//go:build linux && integration

package ironport

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSSHSessionChannelLimit(t *testing.T) {
	config := newTestConfig("", "", "", map[string]UserInfo{
		"alice": {Password: "pw", Root: t.TempDir(), CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)
	config.ResourceLimits.SSHMaxChannels = 2
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

func resourceSSH(t *testing.T, addr string) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "alice", Auth: []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // local test server
		Timeout:         time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func resourceSFTP(t *testing.T, conn *ssh.Client) *sftp.Client {
	t.Helper()
	c, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSFTPHandleLimitAcrossChannelsAndTeardown(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := newTestConfig("", "", "", map[string]UserInfo{"alice": {Password: "pw", Root: root, CanRead: true}}, testSigner(t), 1)
	cfg.ResourceLimits.SFTPMaxHandlesPerConnection = 2
	cfg.ResourceLimits.SFTPMaxHandlesPerUser = 2
	cfg.ResourceLimits.SFTPMaxHandles = 2
	srv, addr, stop := startTestServerWithConfig(t, cfg)
	defer stop()
	sshConn := resourceSSH(t, addr)
	first := resourceSFTP(t, sshConn)
	second := resourceSFTP(t, sshConn)
	if _, err := first.Open("/file"); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Open("/file"); err != nil {
		t.Fatal(err)
	}
	if f, err := second.Open("/file"); err == nil {
		_ = f.Close()
		t.Fatal("second channel bypassed shared handle budget")
	}
	_ = first.Close() // Deliberately omit file CLOSE; subsystem teardown must release it.
	var reused *sftp.File
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		var err error
		reused, err = second.Open("/file")
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if reused == nil {
		t.Fatal("channel teardown leaked handle permit")
	}
	_ = sshConn.Close() // Abandon both handles; transport teardown must free all budgets.
	waitResourceConnections(t, srv)
	newSSH := resourceSSH(t, addr)
	newSFTP := resourceSFTP(t, newSSH)
	for range 2 {
		if _, err := newSFTP.Open("/file"); err != nil {
			t.Fatalf("transport teardown leaked handle permit: %v", err)
		}
	}
	_ = newSSH.Close()
	waitResourceConnections(t, srv)
}

func waitResourceConnections(t *testing.T, srv *Server) {
	t.Helper()
	// Do not Wait on a reusable WaitGroup while this test's listener remains
	// open: the next accepted connection can race a zero-counter Wait.
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		srv.mu.RLock()
		active := len(srv.activeConns)
		srv.mu.RUnlock()
		if active == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("connection handlers did not finish")
}
