//go:build linux && integration

package ironport

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestConnectionAdmissionOnWire(t *testing.T) {
	cfg := newTestConfig("", "", "", nil, testSigner(t), 1)
	cfg.MaxConnections = 1
	srv, addr, stop := startTestServerWithConfig(t, cfg)
	defer stop()
	first, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(first).ReadString('\n'); err != nil {
		t.Fatalf("first banner: %v", err)
	}
	second, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := second.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("overload connection not rejected: %d, %v", n, err)
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("overload connection left open")
	}
	_ = first.Close()
	waitResourceConnections(t, srv)
	third, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Close() }()
	_ = third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(third).ReadString('\n'); err != nil {
		t.Fatalf("released connection slot unavailable: %v", err)
	}
	_ = third.Close()
	waitResourceConnections(t, srv)
}

func TestFTPPreAuthTimeoutIsAbsolute(t *testing.T) {
	cfg := newTestFTPConfig(t, nil, "", false)
	cfg.FTPAuthTimeout = 150 * time.Millisecond
	cfg.IdleTimeout = time.Second
	srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := fmt.Fprint(c, "NOOP\r\n"); err != nil {
			waitResourceConnections(t, srv)
			return
		}
		if _, err := r.ReadString('\n'); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("client deadline reached before server closed pre-auth session")
			}
			waitResourceConnections(t, srv)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("NOOP kept unauthenticated FTP session alive")
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
	cfg.SFTPMaxHandlesPerSession = 2
	cfg.SFTPMaxHandlesPerUser = 2
	cfg.SFTPMaxHandles = 2
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

func TestSFTPQuotaFailureDoesNotAnnounceCompletion(t *testing.T) {
	root := t.TempDir()
	cfg := newTestConfig("", "", "", map[string]UserInfo{"alice": {Password: "pw", Root: root, CanWrite: true}}, testSigner(t), 4)
	cfg.MaxFileBytes = 4
	cfg.MaxTransferBytes = 8
	cfg.MaxJailBytes = 8
	srv, addr, stop := startTestServerWithConfig(t, cfg)
	defer stop()
	sshConn := resourceSSH(t, addr)
	c := resourceSFTP(t, sshConn)
	f, err := c.Create("/limited")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("ok"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("no"), 4); err == nil {
		t.Fatal("sparse write exceeded file limit")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case evt := <-srv.CompletedUploads():
		t.Fatalf("failed upload announced: %+v", evt)
	default:
	}
	got, err := os.ReadFile(filepath.Join(root, "limited"))
	if err != nil || string(got) != "ok" {
		t.Fatalf("quota failure changed file: %q, %v", got, err)
	}
	_ = sshConn.Close()
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
