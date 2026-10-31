//go:build linux && integration

package ironport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFTPSTORFailedDataSetupPreservesFiles(t *testing.T) {
	for _, tt := range []struct {
		name    string
		passive bool
	}{
		{name: "no endpoint"},
		{name: "passive timeout", passive: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			original := []byte("retain this existing content")
			existing := filepath.Join(root, "existing.txt")
			if err := os.WriteFile(existing, original, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := newTestFTPConfig(t, map[string]UserInfo{
				"u": {Password: "p", Root: root, CanWrite: true},
			}, "", false)
			cfg.FtpDataAcceptTimeout = 50 * time.Millisecond
			_, addr, stop := startTestFTPServerWithConfig(t, cfg)
			t.Cleanup(stop)
			c := dialFTP(t, addr)
			c.login("u", "p")
			for _, name := range []string{"existing.txt", "new.txt"} {
				if tt.passive {
					c.command(227, "PASV")
				}
				c.command(150, "STOR %s", name)
				c.read(425)
			}
			got, err := os.ReadFile(existing)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("existing file after failed setup = %q, %v", got, err)
			}
			if _, err := os.Stat(filepath.Join(root, "new.txt")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("new file created by failed setup: %v", err)
			}
		})
	}
}

func TestFTPSSTORRejectedTicketPreservesFile(t *testing.T) {
	root := t.TempDir()
	original := []byte("data must survive a foreign control-session ticket")
	filename := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(filename, original, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, pool := newTestFTPSConfig(t, map[string]UserInfo{
		"u": {Password: "p", Root: root, CanWrite: true},
	}, true)
	cfg.FtpDataAcceptTimeout = time.Second
	cfg.FtpTLSConfig.MinVersion = tls.VersionTLS12
	cfg.FtpTLSConfig.MaxVersion = tls.VersionTLS12
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	attacker := dialFTPS(t, addr, pool)
	attacker.tlsCfg.MinVersion = tls.VersionTLS12
	attacker.tlsCfg.MaxVersion = tls.VersionTLS12
	attacker.authTLS()
	attacker.command(200, "NOOP")
	victim := dialFTPS(t, addr, pool)
	victim.tlsCfg.MinVersion = tls.VersionTLS12
	victim.tlsCfg.MaxVersion = tls.VersionTLS12
	victim.authTLS()
	victim.login("u", "p")
	victim.command(200, "PBSZ 0")
	victim.command(200, "PROT P")
	dc := victim.passiveDial()
	defer func() { _ = dc.Close() }()
	victim.command(150, "STOR existing.txt")
	_ = dc.SetDeadline(time.Now().Add(2 * time.Second))
	foreignTLS := tls.Client(dc, attacker.tlsCfg)
	if err := foreignTLS.HandshakeContext(context.Background()); err == nil {
		t.Fatal("foreign control-session ticket accepted for STOR")
	}
	got, err := os.ReadFile(filename)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("rejected peer changed file before timeout: %q, %v", got, err)
	}
	victim.read(425)
	got, err = os.ReadFile(filename)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("rejected data setup changed file: %q, %v", got, err)
	}
}

func TestFTPPassiveReservationExpiresDespiteNOOP(t *testing.T) {
	cfg := newTestFTPConfig(t, map[string]UserInfo{
		"u": {Password: "p", Root: t.TempDir(), CanWrite: true},
	}, "", false)
	cfg.FtpDataAcceptTimeout = 100 * time.Millisecond
	cfg.FtpMaxPassiveListeners = 1
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)
	holder := dialFTP(t, addr)
	holder.login("u", "p")
	other := dialFTP(t, addr)
	other.login("u", "p")
	holder.command(227, "PASV")
	other.command(425, "PASV")
	for range 8 {
		time.Sleep(25 * time.Millisecond)
		holder.command(200, "NOOP")
	}
	other.command(227, "PASV")
	holder.command(150, "STOR expired.txt")
	holder.read(425)
}

func TestFTPPassiveReservationRelease(t *testing.T) {
	for _, action := range []string{"REIN", "ABOR", "QUIT", "disconnect", "shutdown", "replacement"} {
		t.Run(action, func(t *testing.T) {
			cfg := newTestFTPConfig(t, map[string]UserInfo{
				"u": {Password: "p", Root: t.TempDir(), CanWrite: true},
			}, "", false)
			cfg.FtpMaxPassiveListeners = 1
			srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
			t.Cleanup(stop)
			c := dialFTP(t, addr)
			c.login("u", "p")
			oldAddress := ftpSecurityPassiveAddress(t, c)
			switch action {
			case "REIN":
				c.command(220, "REIN")
			case "ABOR":
				c.command(226, "ABOR")
			case "QUIT":
				c.command(221, "QUIT")
			case "disconnect":
				_ = c.conn.Close()
			case "shutdown":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "replacement":
				c.command(229, "EPSV")
				c.command(226, "ABOR")
			}
			deadline := time.Now().Add(time.Second)
			for {
				srv.ftpPassiveLimits.mu.Lock()
				active := srv.ftpPassiveLimits.total
				srv.ftpPassiveLimits.mu.Unlock()
				if active == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("reservation permit leaked")
				}
				time.Sleep(time.Millisecond)
			}
			if dc, err := net.DialTimeout("tcp", oldAddress, time.Second); err == nil {
				_ = dc.Close()
				t.Fatal("old passive listener remained open")
			}
		})
	}
}
