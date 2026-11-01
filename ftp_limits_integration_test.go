//go:build linux && integration

package ironport

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestFTPPreAuthTimeoutIsAbsolute(t *testing.T) {
	cfg := newTestFTPConfig(t, nil, "", false)
	cfg.ResourceLimits.FTPAuthTimeout = 100 * time.Millisecond
	cfg.IdleTimeout = time.Second
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	_ = c.conn.SetDeadline(time.Now().Add(time.Second))
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); {
		if err := c.tp.PrintfLine("NOOP"); err != nil {
			return
		}
		if _, _, err := c.tp.ReadResponse(200); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatal("client timed out before server closed the unauthenticated session")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("NOOP extended the login deadline")
}

func TestFTPLoginDeadlineRestartsAfterLogout(t *testing.T) {
	cfg := newTestFTPConfig(t, map[string]UserInfo{"u": {Password: "p", Root: t.TempDir()}}, "", false)
	cfg.ResourceLimits.FTPAuthTimeout = 100 * time.Millisecond
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	c.login("u", "p")
	time.Sleep(150 * time.Millisecond)
	c.command(200, "NOOP")
	c.command(220, "REIN")
	_ = c.conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.tp.ReadResponse(0); err == nil {
		t.Fatal("logged-out control connection remained open")
	} else {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("logout did not start a new login deadline")
		}
	}
}

func TestFTPPassiveReservationExpiresDespiteNOOP(t *testing.T) {
	cfg := newTestFTPConfig(t, map[string]UserInfo{"u": {Password: "p", Root: t.TempDir()}}, "", false)
	cfg.FtpDataAcceptTimeout = 75 * time.Millisecond
	cfg.ResourceLimits.FTPMaxPassiveListeners = 1
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	holder, other := dialFTP(t, addr), dialFTP(t, addr)
	holder.login("u", "p")
	other.login("u", "p")
	holder.command(227, "PASV")
	other.command(425, "PASV")
	for range 8 {
		time.Sleep(15 * time.Millisecond)
		holder.command(200, "NOOP")
	}
	other.command(227, "PASV")
}

func TestFTPPassiveReservationRelease(t *testing.T) {
	for _, action := range []string{"USER", "REIN", "ABOR", "QUIT", "disconnect", "shutdown", "revoke", "replacement"} {
		t.Run(action, func(t *testing.T) {
			cfg := newTestFTPConfig(t, map[string]UserInfo{"u": {Password: "p", Root: t.TempDir()}}, "", false)
			cfg.ResourceLimits.FTPMaxPassiveListeners = 1
			srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
			t.Cleanup(stop)
			c := dialFTP(t, addr)
			c.login("u", "p")
			host, port, err := parseFTPPASVResponse(c.command(227, "PASV"))
			if err != nil {
				t.Fatal(err)
			}
			switch action {
			case "USER":
				c.command(331, "USER u")
			case "REIN":
				c.command(220, "REIN")
			case "ABOR":
				c.command(226, "ABOR")
			case "QUIT":
				c.command(221, "QUIT")
			case "disconnect":
				_ = c.conn.Close()
			case "shutdown":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "revoke":
				srv.RemoveUser("u")
			case "replacement":
				c.command(229, "EPSV")
				c.command(226, "ABOR")
			}
			waitFTPPassiveRelease(t, srv)
			if dc, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Second); err == nil {
				_ = dc.Close()
				t.Fatal("released passive listener remained open")
			}
		})
	}
}

func TestFTPPendingPassiveSetupCancelled(t *testing.T) {
	for _, action := range []string{"disconnect", "shutdown", "revoke"} {
		t.Run(action, func(t *testing.T) {
			cfg := newTestFTPConfig(t, map[string]UserInfo{"u": {Password: "p", Root: t.TempDir(), CanWrite: true}}, "", false)
			cfg.FtpDataAcceptTimeout = time.Minute
			srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
			t.Cleanup(stop)
			c := dialFTP(t, addr)
			c.login("u", "p")
			c.command(227, "PASV")
			c.command(150, "STOR pending")
			switch action {
			case "disconnect":
				_ = c.conn.Close()
			case "shutdown":
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "revoke":
				srv.RemoveUser("u")
			}
			waitFTPPassiveRelease(t, srv)
		})
	}
}

func TestFTPAuthTLSAfterLoginUsesNewDeadline(t *testing.T) {
	cfg, _ := newTestFTPSConfig(t, map[string]UserInfo{"u": {Password: "p", Root: t.TempDir()}}, false)
	cfg.ResourceLimits.FTPAuthTimeout = 150 * time.Millisecond
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	c.login("u", "p")
	c.command(234, "AUTH TLS")
	// AUTH discards the authenticated identity. A stalled ClientHello must
	// observe the new login window, rather than only the 10-second TLS limit.
	_ = c.conn.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := c.conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("stalled TLS upgrade remained open: n=%d, err=%v", n, err)
	} else {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("client deadline reached before the fresh authentication deadline")
		}
	}
}
