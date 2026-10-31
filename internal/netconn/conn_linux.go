//go:build linux

// Package netconn provides connection deadlines, keepalive, and address helpers.
package netconn

import (
	"net"
	"sync/atomic"
	"time"
)

// IdleConn wraps a net.Conn and resets the read and/or write deadlines
// before each Read/Write so that a connection is closed when no data has
// moved in the configured direction within the configured idle timeout.
// A timeout of zero in either direction disables the corresponding
// deadline; the two directions are independent so callers can apply an
// idle deadline only on the side they actually use.
type IdleConn struct {
	net.Conn

	readTimeoutNs  atomic.Int64
	writeTimeoutNs atomic.Int64
}

func (c *IdleConn) Read(b []byte) (int, error) {
	if d := time.Duration(c.readTimeoutNs.Load()); d > 0 {
		_ = c.SetReadDeadline(time.Now().Add(d))
	} else {
		_ = c.SetReadDeadline(time.Time{})
	}
	return c.Conn.Read(b)
}

func (c *IdleConn) Write(b []byte) (int, error) {
	if d := time.Duration(c.writeTimeoutNs.Load()); d > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(d))
	} else {
		_ = c.SetWriteDeadline(time.Time{})
	}
	return c.Conn.Write(b)
}

// SetReadTimeout configures the per-Read idle deadline. A zero or
// negative value disables it.
func (c *IdleConn) SetReadTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.readTimeoutNs.Store(int64(d))
}

// SetWriteTimeout configures the per-Write idle deadline. A zero or
// negative value disables it.
func (c *IdleConn) SetWriteTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.writeTimeoutNs.Store(int64(d))
}

// ApplyTCPKeepAlive enables SO_KEEPALIVE on a freshly accepted control
// connection and sets the idle period before probes begin. A non-positive
// period disables keepalive. Connections that are not *net.TCPConn (e.g. test
// fakes) are left untouched.
func ApplyTCPKeepAlive(nc net.Conn, period time.Duration) {
	tc, ok := nc.(*net.TCPConn)
	if !ok {
		return
	}
	if period <= 0 {
		_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable:   false,
			Idle:     -1,
			Interval: -1,
			Count:    -1,
		})
		return
	}
	_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     period,
		Interval: -1,
		Count:    -1,
	})
}

// RemoteIP extracts the IP portion of a net.Addr. If the address contains a
// host:port pair (as is the case for TCP) only the host is returned; otherwise
// the full string form of the address is returned. Returns "" for a nil addr.
func RemoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return HostFromAddr(addr.String())
}

// HostFromAddr returns the host portion of a "host:port" address string,
// without the port. It returns the input unchanged when it carries no port and
// "" for an empty input. It backs both RemoteIP (net.Addr) and the HTTP
// endpoint's client-IP extraction from http.Request.RemoteAddr.
func HostFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
