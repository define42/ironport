//go:build linux

package netconn

import (
	"net"
	"testing"
	"time"
)

// TestApplyTCPKeepAlive verifies that the helper is a no-op for non-TCP
// connections and does not panic for either polarity of period.
func TestApplyTCPKeepAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	srv := <-accepted
	if srv == nil {
		t.Fatal("accept failed")
	}
	defer func() { _ = srv.Close() }()

	// Enabled path: must not panic and must accept a *net.TCPConn.
	ApplyTCPKeepAlive(srv, 30*time.Second)
	// Disabled path: zero/negative disables keepalive.
	ApplyTCPKeepAlive(srv, 0)
	ApplyTCPKeepAlive(srv, -1)

	// Non-TCP connection: pipe(2) endpoints implement net.Conn but are not
	// *net.TCPConn — the helper must silently no-op.
	p1, p2 := net.Pipe()
	defer func() { _ = p1.Close() }()
	defer func() { _ = p2.Close() }()
	ApplyTCPKeepAlive(p1, 30*time.Second)
}

// TestIdleConn_ResetsReadDeadline verifies that the per-Read deadline is
// applied and that subsequent Reads beyond the timeout fail.
func TestIdleConn_ResetsReadDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Hold the connection open without sending anything.
		<-time.After(2 * time.Second)
		_ = c.Close()
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	ic := &IdleConn{Conn: c}
	ic.SetReadTimeout(100 * time.Millisecond)
	buf := make([]byte, 1)
	start := time.Now()
	if _, err := ic.Read(buf); err == nil {
		t.Fatal("expected idle Read to fail with a deadline error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("idle Read took too long: %v", elapsed)
	}
}
