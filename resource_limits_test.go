//go:build linux

package ironport

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pkg/sftp"
)

type addressedConn struct {
	net.Conn
	addr net.Addr
}

func (c *addressedConn) RemoteAddr() net.Addr { return c.addr }

func admissionConn(t *testing.T, ip string) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	return &addressedConn{Conn: server, addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 2022}}
}

func TestConnectionAdmissionLimits(t *testing.T) {
	s := NewServer(&Config{MaxConnections: 2, MaxConnectionsPerIP: 1})
	first := admissionConn(t, "192.0.2.1")
	sameIP := admissionConn(t, "::ffff:192.0.2.1")
	second := admissionConn(t, "192.0.2.2")
	third := admissionConn(t, "192.0.2.3")
	if !s.trackConn(first) {
		t.Fatal("first connection rejected")
	}
	if s.trackConn(sameIP) {
		t.Fatal("mapped IPv4 bypassed per-IP cap")
	}
	if !s.trackConn(second) {
		t.Fatal("independent IP rejected")
	}
	if s.trackConn(third) {
		t.Fatal("global cap bypassed")
	}
	s.untrackConn(first)
	s.connWG.Done()
	if !s.trackConn(third) {
		t.Fatal("released global slot not reusable")
	}
	s.untrackConn(second)
	s.connWG.Done()
	s.untrackConn(third)
	s.connWG.Done()
	s.connWG.Wait()
}

func TestConnectionAdmissionConcurrent(t *testing.T) {
	s := NewServer(&Config{MaxConnections: 7, MaxConnectionsPerIP: 3})
	var wg sync.WaitGroup
	accepted := make(chan net.Conn, 30)
	for i := range 30 {
		ip := "192.0.2.1"
		if i%2 == 0 {
			ip = "192.0.2.2"
		}
		c := admissionConn(t, ip)
		wg.Go(func() {
			if s.trackConn(c) {
				accepted <- c
			}
		})
	}
	wg.Wait()
	close(accepted)
	count := 0
	for c := range accepted {
		count++
		s.untrackConn(c)
		s.connWG.Done()
	}
	if count != 6 {
		t.Fatalf("admitted %d concurrent connections; want 6", count)
	}
}

func handleTestJail(t *testing.T, root string, budget *sessionHandleBudget) jail {
	t.Helper()
	fs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return jail{fs: fs, canRead: true, canWrite: true, handles: budget}
}

func closeHandle(t *testing.T, handle any) {
	t.Helper()
	c, ok := handle.(io.Closer)
	if !ok {
		t.Fatalf("handle %T has no Close", handle)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSFTPHandleBudgets(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := &handleBudget{max: 3, maxUser: 2, maxSession: 1}
	first := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	second := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	third := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "bob"})
	fourth := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "carol"})
	if _, err := first.Fileread(sftp.NewRequest("Get", "/missing")); err == nil {
		t.Fatal("missing file opened")
	}
	r, err := first.Fileread(sftp.NewRequest("Get", "/existing"))
	if err != nil {
		t.Fatalf("failed open leaked slot: %v", err)
	}
	defer closeHandle(t, r)
	if _, err := first.Filelist(sftp.NewRequest("List", "/")); err == nil {
		t.Fatal("directory open bypassed session budget")
	}
	d, err := second.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandle(t, d)
	extra := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	if _, err := extra.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("second connection bypassed per-user cap")
	}
	req := sftp.NewRequest("Put", "/new")
	req.Flags = 2 | 8 | 16 // WRITE | CREAT | TRUNC
	w, err := third.Filewrite(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fourth.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("global handle cap bypassed")
	}
	req.Filepath = "/existing"
	if _, err := first.Filewrite(req); err == nil {
		t.Fatal("write open bypassed handle cap")
	}
	if content, err := os.ReadFile(filepath.Join(root, "existing")); err != nil || string(content) != "keep" {
		t.Fatalf("rejected write modified target: %q, %v", content, err)
	}
	closeHandle(t, w)
	closeHandle(t, w) // double CLOSE must not release somebody else's slot
	reused, err := fourth.Fileread(sftp.NewRequest("Get", "/existing"))
	if err != nil {
		t.Fatalf("closed slot not reusable: %v", err)
	}
	defer closeHandle(t, reused)
	if _, err := third.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("double close over-released global budget")
	}
}
