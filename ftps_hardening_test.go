//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/define42/ironport/internal/netconn"
)

func TestFTPSPreTLSLogRedactsCommands(t *testing.T) {
	tests := []struct {
		name, line, verb, secret string
	}{
		{"password", "PASS private-password\r\n", "PASS", "private-password"},
		{"username", "USER private-user\r\n", "USER", "private-user"},
		{"other argument", "SITE private-argument\r\n", "SITE", "private-argument"},
		{"mixed case", "\tpass\tprivate-password\r\n", "PASS", "private-password"},
		{"unknown token", "private-token argument\r\n", "UNKNOWN", "private-token"},
		{"malformed verb", "PA\x00SS private-password\r\n", "UNKNOWN", "private-password"},
		{"control bytes", "PASS private-password\x1b[31m\x00\r\n", "PASS", "private-password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&output)
			t.Cleanup(func() { log.SetOutput(previous) })
			f := &ftpSession{conn: &stubConn{}, r: bufio.NewReader(strings.NewReader("")), ctlMsg: make(chan ftpCtlMsg, 1)}
			f.ctlMsg <- ftpCtlMsg{line: tt.line}
			clean := f.preTLSChannelClean()
			log.SetOutput(previous)
			if clean {
				t.Fatal("accepted a plaintext command queued behind AUTH TLS")
			}
			got := ftpsRejectionLogLine(output.String())
			want := fmt.Sprintf("verb=%q bytes=%d", tt.verb, len(tt.line))
			if !strings.Contains(got, want) || strings.Contains(got, tt.secret) {
				t.Fatalf("rejection log = %q; want %q without credentials", got, want)
			}
			if strings.ContainsAny(got, "\r\x00\x1b") || strings.Count(got, "\n") != 1 {
				t.Fatalf("rejection log contains control characters or extra lines: %q", got)
			}
		})
	}
}

func TestFTPSPreTLSLogRedactsBufferedBytes(t *testing.T) {
	const plaintext = "PASS private-buffered-password\r\n"
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	f := &ftpSession{conn: &stubConn{}, r: bufio.NewReader(strings.NewReader(plaintext)), ctlMsg: make(chan ftpCtlMsg)}
	if _, err := f.r.Peek(1); err != nil {
		t.Fatal(err)
	}
	close(f.ctlMsg)
	clean := f.preTLSChannelClean()
	log.SetOutput(previous)
	if clean {
		t.Fatal("accepted plaintext buffered behind AUTH TLS")
	}
	got := ftpsRejectionLogLine(output.String())
	if !strings.Contains(got, fmt.Sprintf("%d bytes buffered", len(plaintext))) || strings.Contains(got, "private-buffered-password") {
		t.Fatalf("buffered-data rejection log = %q; want only byte count", got)
	}
}

func ftpsRejectionLogLine(output string) string {
	for line := range strings.SplitAfterSeq(output, "\n") {
		if strings.Contains(line, "ftp AUTH TLS rejected") {
			return line
		}
	}
	return ""
}

func TestFTPSAuthTLSResetClearsPlaintextState(t *testing.T) {
	f, peer := newFTPSResetTestSession(t)
	oldJail := f.fs
	controlTLS, dataTLS := f.controlTLSConfig, f.dataTLSConfig
	f.resetSessionStateForAuthTLS()

	if f.username != "" || f.authenticated || f.user.Password != "" || f.fs != nil {
		t.Fatalf("AUTH TLS retained plaintext authentication: username=%q authenticated=%t", f.username, f.authenticated)
	}
	if _, err := oldJail.Stat("."); err == nil {
		t.Fatal("AUTH TLS retained the old jail descriptor")
	}
	if f.authFailures != 2 || f.controlTLSConfig != controlTLS || f.dataTLSConfig != dataTLS || f.clientIP != "127.0.0.1" {
		t.Fatal("AUTH TLS changed failure accounting or control-session configuration")
	}
	requireFTPSTransferReset(t, f, peer)
	requireFTPSResetAccounting(t, f)
	requireAuthEvent(t, f.server.AuthEvents(), AuthEventLogout, "user", CompletedUploadProtocolFTP)
	f.resetSessionStateForAuthTLS()
	requireNoAuthEvent(t, f.server.AuthEvents())
}

func requireFTPSTransferReset(t *testing.T, f *ftpSession, peer net.Conn) {
	t.Helper()
	if f.epsvAll || f.pbszSet || f.dataProt != 'C' || f.rnfrPath != "" || f.restartOffset != 0 || f.expectedUploadSize != 0 {
		t.Fatal("AUTH TLS retained plaintext transfer state")
	}
	if f.dataLn != nil || f.dataAddr != nil {
		t.Fatal("AUTH TLS retained a data endpoint")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("reserved endpoint after AUTH TLS: %v; want EOF", err)
	}
}

func newFTPSResetTestSession(t *testing.T) (*ftpSession, net.Conn) {
	t.Helper()
	srv := NewServer(&Config{Users: map[string]UserInfo{"user": {Password: "password", Root: t.TempDir(), CanWrite: true}}})
	raw := &stubConn{}
	if !srv.trackConn(raw) {
		t.Fatal("trackConn rejected test connection")
	}
	t.Cleanup(func() {
		srv.untrackConn(raw)
		srv.connWG.Done()
	})
	f := &ftpSession{
		server: srv, conn: raw, rawConn: raw, username: "user", clientIP: "127.0.0.1", authEvents: srv.authEvents,
		controlTLSConfig: &tls.Config{}, dataTLSConfig: &tls.Config{}, authFailures: 2,
	}
	if !f.authenticate("password") {
		t.Fatal("plaintext authentication failed")
	}
	t.Cleanup(f.closeJail)
	release, err := srv.ftpPassiveLimits.reserve("user", f.clientIP)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	f.dataLn = netconn.NewExpiringListener(&stubListener{conn: endpoint}, time.Hour, release)
	t.Cleanup(f.closeDataEndpoint)
	f.dataAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	f.epsvAll, f.pbszSet, f.dataProt = true, true, 'P'
	f.rnfrPath, f.restartOffset, f.expectedUploadSize = "pending", 10, 20
	return f, peer
}

func requireFTPSResetAccounting(t *testing.T, f *ftpSession) {
	t.Helper()
	limits := &f.server.ftpPassiveLimits
	limits.mu.Lock()
	defer limits.mu.Unlock()
	if limits.total != 0 || len(limits.users) != 0 || len(limits.ips) != 0 {
		t.Fatalf("AUTH TLS leaked passive permits: total=%d users=%v ips=%v", limits.total, limits.users, limits.ips)
	}
	f.server.mu.RLock()
	defer f.server.mu.RUnlock()
	state, tracked := f.server.activeConns[f.rawConn]
	if !tracked || state.authenticated || state.username != "" {
		t.Fatalf("AUTH TLS connection association = %+v, tracked=%t; want tracked anonymous connection", state, tracked)
	}
}

func TestFTPSAuthTLSResetPreservesCancellation(t *testing.T) {
	raw := &stubConn{}
	srv := NewServer(&Config{})
	if !srv.trackConn(raw) {
		t.Fatal("trackConn rejected test connection")
	}
	defer func() {
		srv.untrackConn(raw)
		srv.connWG.Done()
	}()
	srv.mu.Lock()
	_ = srv.cancelConnLocked(raw)
	srv.mu.Unlock()
	f := &ftpSession{server: srv, rawConn: raw, cancelled: true, controlReadClosed: true, authTerminated: true}
	f.resetSessionStateForAuthTLS()
	if !f.cancelled || !f.controlReadClosed || !f.authTerminated || !srv.connCancels[raw].canceled {
		t.Fatal("AUTH TLS revived a canceled or terminated control session")
	}
}
