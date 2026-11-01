//go:build linux && integration

package ironport

import (
	"bufio"
	"errors"
	"net"
	"testing"
	"time"
)

func TestConnectionAdmissionSharedByProtocols(t *testing.T) {
	cfg := newTestFTPConfig(t, nil, "", false)
	cfg.ResourceLimits.MaxConnections = 1
	srv, ftpAddr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()
	first, err := net.DialTimeout("tcp", srv.ListeningAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(first).ReadString('\n'); err != nil {
		t.Fatalf("SSH banner: %v", err)
	}
	second, err := net.DialTimeout("tcp", ftpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := second.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("FTP overload not rejected: %d, %v", n, err)
	} else if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		t.Fatal("FTP overload socket left open")
	}
	_ = first.Close()
	waitConnectionHandlers(t, srv)
	third, err := net.DialTimeout("tcp", ftpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = third.Close() }()
	_ = third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(third).ReadString('\n'); err != nil {
		t.Fatalf("released slot unavailable to FTP: %v", err)
	}
	_ = third.Close()
	waitConnectionHandlers(t, srv)
}

func waitConnectionHandlers(t *testing.T, srv *Server) {
	t.Helper()
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
