//go:build linux

package ironport

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHSessionChannelLimit(t *testing.T) {
	config := newTestConfig("", "", "", map[string]UserInfo{
		"alice": {Password: "pw", Root: t.TempDir(), CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)
	config.SSHMaxChannels = 2
	srv, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test server with an ephemeral key
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		srv.connWG.Wait()
	})

	first, firstRequests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	assertSSHChannelLimit(t, client)
	_ = first.Close()
	for range firstRequests {
	}
	// CLOSE is acknowledged just before the handler releases its slot. Allow
	// that goroutine to finish without assuming an inter-goroutine ordering.
	assertSSHChannelSlotReusable(t, client)
}

func assertSSHChannelLimit(t *testing.T, client *ssh.Client) {
	t.Helper()
	ch, _, err := client.OpenChannel("session", nil)
	if ch != nil {
		_ = ch.Close()
	}
	var rejected *ssh.OpenChannelError
	if !errors.As(err, &rejected) || rejected.Reason != ssh.ResourceShortage {
		t.Fatalf("extra channel error = %v; want resource shortage", err)
	}
}

func assertSSHChannelSlotReusable(t *testing.T, client *ssh.Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ch, _, err := client.OpenChannel("session", nil)
		if err == nil {
			_ = ch.Close()
			return
		}
		var rejected *ssh.OpenChannelError
		if !errors.As(err, &rejected) || rejected.Reason != ssh.ResourceShortage || time.Now().After(deadline) {
			t.Fatalf("closed channel did not release capacity: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

type auditSSHConn struct {
	ssh.Conn
}

func (auditSSHConn) User() string { return "alice" }
func (auditSSHConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func TestSSHCommitRevocationEmitsFailureEvent(t *testing.T) {
	s := NewServer(&Config{Users: map[string]UserInfo{
		"alice": {Password: "pw", Root: t.TempDir()},
	}})
	u, fs, revision, ok := s.authenticateUser("alice", func(u UserInfo) bool {
		return checkPassword(u.Password, "pw")
	})
	if !ok {
		t.Fatal("initial authentication failed")
	}
	authState := &sshAuthState{}
	authState.replace(fs, "alice", revision)
	t.Cleanup(authState.close)
	serverConn, clientConn := net.Pipe()
	if !s.trackConn(serverConn) {
		t.Fatal("trackConn failed")
	}
	t.Cleanup(func() {
		s.untrackConn(serverConn)
		s.connWG.Done()
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	s.RemoveUser("alice")
	sshConn := &ssh.ServerConn{Conn: auditSSHConn{}, Permissions: permissionsFor(u, "alice", fs)}
	jail, _, _, committed := s.takeCommittedSSHJail(serverConn, sshConn, authState, s.authEventsChan())
	if committed || jail != nil {
		t.Fatal("revoked authentication was committed")
	}
	requireAuthEvent(t, s.AuthEvents(), AuthEventLoginFailed, "alice", CompletedUploadProtocolSFTP)
	if _, err := fs.Stat("/"); err == nil {
		t.Fatal("revoked authentication retained an open jail")
	}
	select {
	case ev := <-s.AuthEvents():
		t.Fatalf("unexpected additional authentication event: %+v", ev)
	default:
	}
}

func TestConnectionCancellationSurvivesAuthenticationReset(t *testing.T) {
	s := NewServer(&Config{Users: map[string]UserInfo{
		"alice": {Root: t.TempDir()},
	}})
	nc, peer := net.Pipe()
	if !s.trackConn(nc) {
		t.Fatal("trackConn failed")
	}
	t.Cleanup(func() {
		s.untrackConn(nc)
		s.connWG.Done()
		_ = nc.Close()
		_ = peer.Close()
	})
	canceled := false
	if !s.setConnCancel(nc, func() {
		_, _, _ = s.userSnapshot("alice") // callback must run outside s.mu
		canceled = true
	}) {
		t.Fatal("setConnCancel failed")
	}
	_, revision, _ := s.userSnapshot("alice")
	if !s.commitConnUser(nc, "alice", revision) {
		t.Fatal("initial commit failed")
	}
	s.clearConnUser(nc)
	if !s.commitConnUser(nc, "alice", revision) {
		t.Fatal("commit after reset failed")
	}
	s.RemoveUser("alice")
	if !canceled {
		t.Fatal("authentication reset discarded cancellation callback")
	}
	s.AddUser("alice", UserInfo{Root: t.TempDir()})
	_, revision, _ = s.userSnapshot("alice")
	if s.commitConnUser(nc, "alice", revision) {
		t.Fatal("canceled connection was reauthenticated")
	}
	lateCanceled := false
	if s.setConnCancel(nc, func() { lateCanceled = true }) || !lateCanceled {
		t.Fatal("late cancellation registration missed revocation")
	}
}

func TestRequireTLSWithoutConfigFailsStartup(t *testing.T) {
	s := NewServer(&Config{FtpAddr: "127.0.0.1:0", FtpRequireTLS: true})
	if err := s.prepareForListen(); err == nil {
		t.Fatal("startup accepted required TLS without TLS configuration")
	}
}

func TestDisabledFTPTLSSettingsDoNotBlockSFTPStartup(t *testing.T) {
	signer := testSigner(t)
	for _, tt := range []struct {
		name string
		addr string
	}{
		{name: "empty", addr: ""},
		{name: "whitespace", addr: " \t\n "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, tlsCase := range []struct {
				name   string
				config *tls.Config
			}{
				{name: "required TLS without config"},
				{name: "custom session callback", config: &tls.Config{
					WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) {
						return []byte("unused FTP ticket"), nil
					},
				}},
			} {
				t.Run(tlsCase.name, func(t *testing.T) {
					srv := NewServer(&Config{
						SftpAddr: "127.0.0.1:0", SftpSigner: signer,
						FtpAddr: tt.addr, FtpRequireTLS: true, FtpTLSConfig: tlsCase.config,
					})
					errCh := make(chan error, 1)
					done := make(chan struct{})
					go func() {
						defer close(done)
						errCh <- srv.ListenAndServe()
					}()
					t.Cleanup(func() {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()
						if err := srv.Shutdown(ctx); err != nil {
							t.Errorf("Shutdown: %v", err)
						}
						select {
						case <-done:
						case <-time.After(time.Second):
							t.Error("ListenAndServe did not stop")
						}
						select {
						case err := <-errCh:
							if err != nil {
								t.Errorf("ListenAndServe: %v", err)
							}
						default:
						}
					})
					addr := waitForSFTPListener(t, srv, errCh)
					if srv.FTPListeningAddr() != nil {
						t.Fatal("disabled FTP opened a listener")
					}
					conn, err := net.DialTimeout("tcp", addr, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = conn.Close() }()
					_ = conn.SetReadDeadline(time.Now().Add(time.Second))
					banner, err := bufio.NewReader(conn).ReadString('\n')
					if err != nil || !strings.HasPrefix(banner, "SSH-2.0-") {
						t.Fatalf("SFTP SSH banner = %q, %v", banner, err)
					}
				})
			}
		})
	}
}
