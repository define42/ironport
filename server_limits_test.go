//go:build linux

package ironport

import (
	"net"
	"sync"
	"testing"
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
	s := NewServer(&Config{ResourceLimits: ResourceLimitConfig{MaxConnections: 2, MaxConnectionsPerIP: 1}})
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
	s := NewServer(&Config{ResourceLimits: ResourceLimitConfig{MaxConnections: 7, MaxConnectionsPerIP: 3}})
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

func TestConnectionCancellationRegistration(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cancelFirst bool
		removeAll   bool
	}{
		{name: "registered before removal"},
		{name: "registered after removal", cancelFirst: true},
		{name: "registered before removing all", removeAll: true},
		{name: "registered after removing all", cancelFirst: true, removeAll: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testConnectionCancellation(t, tc.cancelFirst, tc.removeAll)
		})
	}
}

func testConnectionCancellation(t *testing.T, cancelFirst, removeAll bool) {
	t.Helper()
	s := NewServer(&Config{})
	c := admissionConn(t, "192.0.2.1")
	if !s.trackConn(c) {
		t.Fatal("connection rejected")
	}
	defer s.connWG.Done()
	defer s.untrackConn(c)
	s.setConnUser(c, "alice")
	canceled := false
	cancel := func() { canceled = true }
	if !cancelFirst && !s.setConnCancel(c, cancel) {
		t.Fatal("registration rejected")
	}
	if removeAll {
		s.RemoveAllUsers()
	} else {
		s.RemoveUser("alice")
	}
	// FTP authentication reset must not erase connection cancellation state.
	s.setConnUser(c, "")
	if cancelFirst && s.setConnCancel(c, cancel) {
		t.Fatal("revoked connection accepted cleanup registration")
	}
	if !canceled {
		t.Fatal("protocol cleanup was not called")
	}
}

func TestConnectionAdmissionFiniteDefaults(t *testing.T) {
	for _, value := range []int{0, -1} {
		t.Run(map[int]string{0: "zero", -1: "negative"}[value], func(t *testing.T) {
			s := NewServer(&Config{ResourceLimits: ResourceLimitConfig{MaxConnections: value, MaxConnectionsPerIP: value}})
			for i := range defaultMaxConnectionsPerIP + 1 {
				c := admissionConn(t, "192.0.2.1")
				admitted := s.trackConn(c)
				if admitted {
					defer s.connWG.Done()
					defer s.untrackConn(c)
				}
				if admitted != (i < defaultMaxConnectionsPerIP) {
					t.Fatalf("connection %d admitted=%t", i+1, admitted)
				}
			}
		})
	}
}
