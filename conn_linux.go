//go:build linux

package ironport

import (
	"net"
	"sync/atomic"
	"time"
)

// idleConn wraps a net.Conn and resets the read and/or write deadlines
// before each Read/Write so that a connection is closed when no data has
// moved in the configured direction within the configured idle timeout.
// A timeout of zero in either direction disables the corresponding
// deadline; the two directions are independent so callers can apply an
// idle deadline only on the side they actually use.
type idleConn struct {
	net.Conn

	readTimeoutNs  atomic.Int64
	writeTimeoutNs atomic.Int64
}

func (c *idleConn) Read(b []byte) (int, error) {
	if d := time.Duration(c.readTimeoutNs.Load()); d > 0 {
		_ = c.SetReadDeadline(time.Now().Add(d))
	} else {
		_ = c.SetReadDeadline(time.Time{})
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if d := time.Duration(c.writeTimeoutNs.Load()); d > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(d))
	} else {
		_ = c.SetWriteDeadline(time.Time{})
	}
	return c.Conn.Write(b)
}

// setReadTimeout configures the per-Read idle deadline. A zero or
// negative value disables it.
func (c *idleConn) setReadTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.readTimeoutNs.Store(int64(d))
}

// setWriteTimeout configures the per-Write idle deadline. A zero or
// negative value disables it.
func (c *idleConn) setWriteTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.writeTimeoutNs.Store(int64(d))
}

// applyTCPKeepAlive enables SO_KEEPALIVE on a freshly accepted control
// connection and sets the idle period before probes begin. A non-positive
// period disables keepalive. Connections that are not *net.TCPConn (e.g. test
// fakes) are left untouched.
func applyTCPKeepAlive(nc net.Conn, period time.Duration) {
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

// remoteIP extracts the IP portion of a net.Addr. If the address contains a
// host:port pair (as is the case for TCP) only the host is returned; otherwise
// the full string form of the address is returned. Returns "" for a nil addr.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return hostFromAddr(addr.String())
}

// hostFromAddr returns the host portion of a "host:port" address string,
// without the port. It returns the input unchanged when it carries no port and
// "" for an empty input. It backs both remoteIP (net.Addr) and the HTTP
// endpoint's client-IP extraction from http.Request.RemoteAddr.
func hostFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
