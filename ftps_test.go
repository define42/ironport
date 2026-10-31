package ironport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/define42/ironport/internal/netconn"
)

func TestBindFTPTLSConfigToSessionHardensSelectedConfig(t *testing.T) {
	verifyCalls := 0
	selected := &tls.Config{
		VerifyConnection: func(tls.ConnectionState) error {
			verifyCalls++
			return nil
		},
	}
	base := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return selected, nil
		},
	}

	bound, err := bindFTPTLSConfigToSession(base, [32]byte{1}, true)
	if err != nil {
		t.Fatalf("bindFTPTLSConfigToSession: %v", err)
	}
	got, err := bound.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if got == selected {
		t.Fatal("GetConfigForClient returned the unhardened caller config")
	}
	if err := got.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("selected config accepted a fresh data TLS session")
	}
	if verifyCalls != 1 {
		t.Fatalf("user VerifyConnection calls after fresh session = %d; want 1", verifyCalls)
	}
	if err := got.VerifyConnection(tls.ConnectionState{DidResume: true}); err != nil {
		t.Fatalf("selected config rejected a resumed data TLS session: %v", err)
	}
	if verifyCalls != 2 {
		t.Fatalf("user VerifyConnection calls after resumed session = %d; want 2", verifyCalls)
	}
}

func TestFTPTLSSessionBindingRejectsCustomSessionCallbacks(t *testing.T) {
	tests := []struct {
		name   string
		config func() *tls.Config
	}{
		{
			name: "WrapSession",
			config: func() *tls.Config {
				return &tls.Config{
					WrapSession: func(tls.ConnectionState, *tls.SessionState) ([]byte, error) {
						return []byte("ticket"), nil
					},
				}
			},
		},
		{
			name: "UnwrapSession",
			config: func() *tls.Config {
				return &tls.Config{
					UnwrapSession: func([]byte, tls.ConnectionState) (*tls.SessionState, error) {
						return nil, nil
					},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewServer(&Config{FtpTLSConfig: tt.config()})
			if err := srv.prepareForListen(); err == nil {
				t.Fatal("prepareForListen accepted a custom TLS session callback")
			} else if !strings.Contains(err.Error(), "custom TLS session wrapping") {
				t.Fatalf("prepareForListen error = %q; want custom-session-callback error", err)
			}

			base := &tls.Config{
				GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
					return tt.config(), nil
				},
			}
			bound, err := bindFTPTLSConfigToSession(base, [32]byte{1}, true)
			if err != nil {
				t.Fatalf("bindFTPTLSConfigToSession(base): %v", err)
			}
			if _, err := bound.GetConfigForClient(&tls.ClientHelloInfo{}); err == nil {
				t.Fatal("GetConfigForClient accepted a selected config with a custom TLS session callback")
			} else if !strings.Contains(err.Error(), "custom TLS session wrapping") {
				t.Fatalf("GetConfigForClient error = %q; want custom-session-callback error", err)
			}
		})
	}
}

//nolint:funlen // one end-to-end dynamic-config ticket attack and legitimate fallback
func TestFTPSGetConfigForClientCannotOverrideControlSessionTicketKey(t *testing.T) {
	root := t.TempDir()
	payload := []byte("victim secret")
	if err := os.WriteFile(filepath.Join(root, "secret.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"victim": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}
	cfg, pool := newTestFTPSConfig(t, users, true)
	cfg.FtpTLSConfig.MinVersion = tls.VersionTLS13
	cfg.FtpTLSConfig.MaxVersion = tls.VersionTLS13

	// Model a dynamic TLS config that would otherwise restore one ticket key
	// shared by every control session and replace the data resumption verifier.
	selected := cfg.FtpTLSConfig.Clone()
	var sharedKey [32]byte
	sharedKey[0] = 1
	selected.SetSessionTicketKeys([][32]byte{sharedKey})
	cfg.FtpTLSConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return selected, nil
	}

	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	t.Cleanup(stop)

	attacker := dialFTPS(t, addr, pool)
	attacker.tlsCfg.MinVersion = tls.VersionTLS13
	attacker.tlsCfg.MaxVersion = tls.VersionTLS13
	attackerSessions := newTrackingTLSSessionCache()
	attacker.sessions = attackerSessions
	attacker.tlsCfg.ClientSessionCache = attackerSessions
	attacker.authTLS()
	attacker.command(200, "NOOP") // consume the TLS 1.3 NewSessionTicket
	if cached, puts, _ := attackerSessions.stats(); cached == 0 || puts == 0 {
		t.Fatal("anonymous AUTH TLS did not cache a resumable session")
	}

	victim := dialFTPS(t, addr, pool)
	victim.tlsCfg.MinVersion = tls.VersionTLS13
	victim.tlsCfg.MaxVersion = tls.VersionTLS13
	victim.authTLS()
	victim.login("victim", "pw")
	victim.command(200, "PBSZ 0")
	victim.command(200, "PROT P")

	attackerData := victim.passiveDial()
	defer func() { _ = attackerData.Close() }()
	victim.send("RETR secret.bin")
	victim.read(150)

	_, _, hitsBefore := attackerSessions.stats()
	_ = attackerData.SetDeadline(time.Now().Add(5 * time.Second))
	attackerTLS := tls.Client(attackerData, attacker.tlsCfg)
	if err := attackerTLS.HandshakeContext(context.Background()); err == nil {
		// In TLS 1.3 the client can finish before it consumes the server's
		// post-handshake rejection alert. A resumed connection would pass the
		// server verifier, so DidResume is an immediate binding failure.
		if attackerTLS.ConnectionState().DidResume {
			t.Fatal("GetConfigForClient restored a server-wide ticket key on the victim data connection")
		}
		got, readErr := io.ReadAll(attackerTLS)
		if len(got) != 0 {
			t.Fatalf("fresh attacker handshake disclosed %q before the server rejection", got)
		}
		if readErr == nil {
			t.Fatal("fresh attacker handshake was not rejected by the selected config's VerifyConnection")
		}
	}
	_, _, hitsAfter := attackerSessions.stats()
	if hitsAfter <= hitsBefore {
		t.Fatal("attacker's cached ticket was not offered on the victim data connection")
	}
	_ = attackerData.Close()
	victim.read(425)
	// Hardening the dynamic config must not disable legitimate resumption.
	victimData := victim.passiveDial()
	defer func() { _ = victimData.Close() }()
	_ = victimData.SetDeadline(time.Now().Add(5 * time.Second))
	victim.send("RETR secret.bin")
	victim.read(150)
	victimTLS := victim.upgradeDataConn(victimData)
	if !victimTLS.ConnectionState().DidResume {
		t.Fatal("victim data handshake did not resume its control session")
	}
	got, err := io.ReadAll(victimTLS)
	if err != nil {
		t.Fatalf("victim RETR: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("victim RETR payload = %q; want %q", got, payload)
	}
	_ = victimTLS.Close()
	victim.read(226)
}

// ---- FTPS (explicit, RFC 4217) integration tests ----

func TestFTPS_AdvertisesFEAT(t *testing.T) {
	users := map[string]UserInfo{"u": {Password: "p", Root: t.TempDir(), CanRead: true, CanWrite: true}}
	cfg, pool := newTestFTPSConfig(t, users, false)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	feat := c.command(211, "FEAT")
	for _, want := range []string{"AUTH TLS", "PBSZ", "PROT"} {
		if !strings.Contains(feat, want) {
			t.Errorf("FEAT response missing %q\ngot:\n%s", want, feat)
		}
	}
}

func TestFTPS_AuthTLSAndLogin(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true}}
	cfg, pool := newTestFTPSConfig(t, users, false)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("alice", "alicepw")
	c.command(257, "PWD")
}

func TestFTPS_MFMTSetsModificationTime(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "file.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true}}
	cfg, pool := newTestFTPSConfig(t, users, true)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("alice", "alicepw")
	if got := c.command(213, "MFMT 20240607080910 file.txt"); got != "20240607080910" {
		t.Fatalf("MFMT response = %q; want 20240607080910", got)
	}
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("os.Stat after MFMT: %v", err)
	}
	want := time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)
	if !info.ModTime().Equal(want) {
		t.Fatalf("mtime after MFMT = %v; want %v", info.ModTime(), want)
	}
}

func TestFTPS_PROTDataConnRoundTrip(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true}}
	cfg, pool := newTestFTPSConfig(t, users, true)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("alice", "alicepw")
	c.command(200, "PBSZ 0")
	c.command(200, "PROT P")
	c.command(200, "TYPE I")

	payload := []byte("encrypted upload payload")

	// STOR over TLS
	raw := c.passiveDial()
	c.send("STOR hello.bin")
	c.read(150)
	tc := c.upgradeDataConn(raw)
	if _, err := tc.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	_ = tc.Close()
	c.read(226)

	got, err := os.ReadFile(filepath.Join(root, "hello.bin")) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("on-disk content = %q; want %q", got, payload)
	}

	// RETR over TLS — also exercises close_notify on the server side.
	raw = c.passiveDial()
	c.send("RETR hello.bin")
	c.read(150)
	tc = c.upgradeDataConn(raw)
	buf, err := io.ReadAll(tc)
	if err != nil {
		t.Fatalf("ReadAll RETR: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("RETR payload = %q; want %q", buf, payload)
	}
	_ = tc.Close()
	c.read(226)
}

// TestFTPS_RetrEOFIsCleanTLSShutdown verifies that a successful RETR ends
// with a TLS close_notify (clean io.EOF from the TLS layer) rather than a
// bare TCP FIN. Without close_notify a malicious party could truncate the
// download and the client could not tell the difference.
func TestFTPS_RetrEOFIsCleanTLSShutdown(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f.bin"), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true}}
	cfg, pool := newTestFTPSConfig(t, users, false)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("alice", "alicepw")
	c.command(200, "PBSZ 0")
	c.command(200, "PROT P")
	c.command(200, "TYPE I")

	raw := c.passiveDial()
	c.send("RETR f.bin")
	c.read(150)
	tc := c.upgradeDataConn(raw)
	// Reading one byte past the payload must surface io.EOF (TLS layer saw
	// close_notify), not io.ErrUnexpectedEOF (raw TCP FIN inside TLS).
	buf := make([]byte, 7)
	if _, err := io.ReadFull(tc, buf); err != nil {
		t.Fatalf("ReadFull(7): %v", err)
	}
	if string(buf) != "payload" {
		t.Fatalf("payload = %q; want %q", buf, "payload")
	}
	one := make([]byte, 1)
	_, err := tc.Read(one)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("post-payload Read err = %v; want io.EOF (close_notify)", err)
	}
	_ = tc.Close()
	c.read(226)
}

func TestFTPS_RequireTLSRejectsCleartextLogin(t *testing.T) {
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true, CanWrite: true}}
	cfg, _ := newTestFTPSConfig(t, users, true)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	tp := textproto.NewConn(conn)
	if _, _, err := tp.ReadResponse(220); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if err := tp.PrintfLine("USER alice"); err != nil {
		t.Fatalf("USER: %v", err)
	}
	code, _, err := tp.ReadResponse(0)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if code != 534 {
		t.Fatalf("USER over plaintext: got %d; want 534", code)
	}
}

//nolint:funlen // one end-to-end policy matrix plus filesystem side-effect checks
func TestFTPS_RequireTLSRejectsUnprotectedDataCommands(t *testing.T) {
	root := t.TempDir()
	existingPath := filepath.Join(root, "existing.txt")
	original := []byte("original content")
	if err := os.WriteFile(existingPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	cfg, pool := newTestFTPSConfig(t, users, true)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("alice", "alicepw")
	// PBSZ alone does not protect the data channel; PROT P is mandatory.
	c.command(200, "PBSZ 0")

	c.expectDataProtectionRequired("LIST")
	c.expectDataProtectionRequired("NLST")
	c.expectDataProtectionRequired("MLSD")
	c.expectDataProtectionRequired("RETR existing.txt")
	c.expectDataProtectionRequired("STOR existing.txt")
	c.expectDataProtectionRequired("STOR created-by-stor.txt")
	c.expectDataProtectionRequired("APPE existing.txt")
	c.expectDataProtectionRequired("APPE created-by-appe.txt")
	// Rejected transfers must consume one-shot REST and ALLO hints.
	c.command(350, "REST 4")
	c.command(200, "ALLO 999")
	c.expectDataProtectionRequired("STOR hinted.txt")
	c.command(200, "NOOP")

	got, err := os.ReadFile(existingPath) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing file changed after rejected transfer: got %q; want %q", got, original)
	}
	if _, err := os.Stat(filepath.Join(root, "created-by-stor.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected STOR created a file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "created-by-appe.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected APPE created a file: %v", err)
	}
	hintedPath := filepath.Join(root, "hinted.txt")
	if _, err := os.Stat(hintedPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("policy-rejected hinted STOR created a file: %v", err)
	}

	// A later protected upload must not inherit the rejected transfer's hints.
	c.command(200, "PROT P")
	protectedPayload := []byte("protected upload")
	c.storeProtected("hinted.txt", protectedPayload)
	got, err = os.ReadFile(hintedPath) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, protectedPayload) {
		t.Fatalf("protected upload inherited stale transfer hints: got %q; want %q", got, protectedPayload)
	}
}

func TestFTPS_RequireTLSRequiresPROTPAfterREIN(t *testing.T) {
	root := t.TempDir()
	existingPath := filepath.Join(root, "existing.txt")
	original := []byte("original content")
	if err := os.WriteFile(existingPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	cfg, pool := newTestFTPSConfig(t, users, true)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("alice", "alicepw")
	c.command(200, "PBSZ 0")
	c.command(200, "PROT P")
	c.command(220, "REIN")
	c.login("alice", "alicepw")

	// REIN keeps the control TLS session but resets PBSZ and PROT.
	c.command(503, "PROT P")
	c.command(200, "PBSZ 0")
	c.expectDataProtectionRequired("STOR existing.txt")

	got, err := os.ReadFile(existingPath) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing file changed after REIN policy rejection: got %q; want %q", got, original)
	}

	// The session can recover by negotiating private data protection again.
	c.command(200, "PROT P")
	protectedPayload := []byte("protected after REIN")
	c.storeProtected("existing.txt", protectedPayload)
	got, err = os.ReadFile(existingPath) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, protectedPayload) {
		t.Fatalf("post-REIN protected upload = %q; want %q", got, protectedPayload)
	}
}

// TestFTPS_BufferedBytesAttackRejected covers the canonical FTPS command-
// injection attack: an attacker on the cleartext segment pipelines an
// extra "USER attacker" behind the legitimate "AUTH TLS\r\n" line. A
// naive server reads both lines into the bufio buffer pre-TLS, replies
// 234, then upgrades and dequeues "USER attacker" — executing
// attacker-controlled commands inside the encrypted session.
//
// The server must detect the pending bytes before sending 234 and close
// the connection without proceeding to the TLS handshake. We assert that
// by writing the pipeline ourselves and verifying the server hangs up.
func TestFTPS_BufferedBytesAttackRejected(t *testing.T) {
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true, CanWrite: true}}
	cfg, _ := newTestFTPSConfig(t, users, false)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	r := bufio.NewReader(conn)
	// Read the 220 greeting.
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	// Pipeline AUTH TLS together with an injected USER line so both arrive
	// in a single read on the server's bufio.Reader.
	if _, err := conn.Write([]byte("AUTH TLS\r\nUSER attacker\r\n")); err != nil {
		t.Fatalf("write pipeline: %v", err)
	}
	// Server must reply 234 only after confirming the channel is clean.
	// Here the injected USER is buffered, so the server detects it before
	// replying and closes the connection. What matters is that subsequent
	// reads return EOF rather than another reply, and crucially that the
	// server never answers the injected USER (which would be a 331 reply).
	deadline := time.Now().Add(5 * time.Second)
	_ = conn.SetReadDeadline(deadline)
	// Drain any responses until EOF or read deadline. The server must NOT
	// have answered the injected USER (which would be a 331 reply).
	saw331 := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "331") {
			saw331 = true
			break
		}
	}
	if saw331 {
		t.Fatal("server processed pre-TLS USER injection (saw 331); expected the connection to be torn down")
	}
}

// TestFTPS_DataConnRequiresResumption verifies the data-channel binding:
// a client that does not present a session ticket issued for the
// current control session is rejected at the data-conn TLS handshake.
//
// We exercise this by stripping the client's session cache between
// control and data handshakes, so the data handshake is necessarily
// fresh (DidResume == false). The server-side VerifyConnection callback
// must fail the handshake.
func TestFTPS_DataConnRequiresResumption(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true}}
	cfg, pool := newTestFTPSConfig(t, users, false)
	_, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("alice", "alicepw")
	c.command(200, "PBSZ 0")
	c.command(200, "PROT P")
	c.command(200, "TYPE I")

	host, port, err := parseFTPPASVResponse(c.command(227, "PASV"))
	if err != nil {
		t.Fatalf("parse PASV: %v", err)
	}
	dc, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("dial data: %v", err)
	}
	defer func() { _ = dc.Close() }()

	// Fresh session cache => no ticket presented => handshake fresh.
	freshCfg := &tls.Config{
		RootCAs:            pool,
		ServerName:         "127.0.0.1",
		ClientSessionCache: tls.NewLRUClientSessionCache(1),
	}
	tc := tls.Client(dc, freshCfg)
	_ = dc.SetDeadline(time.Now().Add(5 * time.Second))
	err = tc.HandshakeContext(context.Background())
	if err == nil {
		t.Fatal("data-conn handshake without session resumption succeeded; want failure")
	}
}

// TestFTPS_DataConnRejectsTicketFromDifferentControlSession covers the
// cross-session ticket attack. An anonymous control connection can obtain a
// valid server ticket with AUTH TLS alone, so DidResume is not sufficient to
// bind a protected data connection to the authenticated control session.
//
//nolint:gocognit,funlen // one end-to-end cross-session attack and legitimate fallback
func TestFTPS_DataConnRejectsTicketFromDifferentControlSession(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
	}{
		{name: "TLS 1.2", version: tls.VersionTLS12},
		{name: "TLS 1.3", version: tls.VersionTLS13},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			payload := []byte("victim secret")
			if err := os.WriteFile(filepath.Join(root, "secret.bin"), payload, 0o600); err != nil {
				t.Fatal(err)
			}

			users := map[string]UserInfo{
				"victim": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
			}
			cfg, pool := newTestFTPSConfig(t, users, true)
			cfg.FtpTLSConfig.MinVersion = tt.version
			cfg.FtpTLSConfig.MaxVersion = tt.version
			_, addr, stop := startTestFTPServerWithConfig(t, cfg)
			defer stop()

			attacker := dialFTPS(t, addr, pool)
			attacker.tlsCfg.MinVersion = tt.version
			attacker.tlsCfg.MaxVersion = tt.version
			attackerSessions := newTrackingTLSSessionCache()
			attacker.sessions = attackerSessions
			attacker.tlsCfg.ClientSessionCache = attackerSessions

			attacker.authTLS()
			// Reading an application-data response also consumes the TLS 1.3
			// NewSessionTicket sent after the handshake.
			attacker.command(200, "NOOP")
			attacker.command(530, "PWD") // prove the ticket holder is anonymous
			cached, puts, _ := attackerSessions.stats()
			if cached == 0 || puts == 0 {
				t.Fatal("anonymous AUTH TLS did not cache a resumable session")
			}

			victim := dialFTPS(t, addr, pool)
			victim.tlsCfg.MinVersion = tt.version
			victim.tlsCfg.MaxVersion = tt.version
			victim.authTLS()
			victim.login("victim", "pw")
			victim.command(200, "PBSZ 0")
			victim.command(200, "PROT P")
			victim.command(200, "TYPE I")

			// The passive-mode source-IP check must not be what rejects this
			// connection: attacker, victim, and raced data socket all share the
			// same loopback IP, modelling clients behind one NAT address.
			victimIP := netconn.RemoteIP(victim.rawConn.LocalAddr())
			if attackerIP := netconn.RemoteIP(attacker.rawConn.LocalAddr()); attackerIP != victimIP {
				t.Fatalf("control source IPs differ: attacker=%s victim=%s", attackerIP, victimIP)
			}

			attackerData := victim.passiveDial()
			defer func() { _ = attackerData.Close() }()
			if attackerDataIP := netconn.RemoteIP(attackerData.LocalAddr()); attackerDataIP != victimIP {
				t.Fatalf("attacker data source IP = %s; want victim IP %s", attackerDataIP, victimIP)
			}
			victim.send("RETR secret.bin")
			victim.read(150)

			_, _, hitsBefore := attackerSessions.stats()
			_ = attackerData.SetDeadline(time.Now().Add(5 * time.Second))
			attackerTLS := tls.Client(attackerData, attacker.tlsCfg)
			handshakeErr := attackerTLS.HandshakeContext(context.Background())
			_, _, hitsAfter := attackerSessions.stats()
			if hitsAfter <= hitsBefore {
				t.Fatal("attacker's cached control-session ticket was not offered on the victim's data connection")
			}
			if handshakeErr == nil {
				// With TLS 1.3 the client may finish its side of a full
				// handshake before the server reports its resumption-only
				// VerifyConnection failure. In that case the rejection is
				// observed by the first application-data read instead.
				if attackerTLS.ConnectionState().DidResume {
					t.Fatal("attacker ticket resumed on the victim's data connection")
				}
				stolen, readErr := io.ReadAll(attackerTLS)
				if len(stolen) != 0 {
					t.Fatalf("attacker ticket resumed on victim data connection and disclosed %q", stolen)
				}
				if readErr == nil {
					t.Fatal("attacker data connection closed cleanly; want TLS rejection")
				}
			}
			_ = attackerData.Close()
			victim.read(425)

			// Rejection must be scoped to the foreign ticket. The ticket from
			// this victim control session still resumes and transfers data.
			victimData := victim.passiveDial()
			defer func() { _ = victimData.Close() }()
			_ = victimData.SetDeadline(time.Now().Add(5 * time.Second))
			victim.send("RETR secret.bin")
			victim.read(150)
			victimTLS := victim.upgradeDataConn(victimData)
			if !victimTLS.ConnectionState().DidResume {
				t.Fatal("victim data handshake did not resume its control session")
			}
			got, err := io.ReadAll(victimTLS)
			if err != nil {
				t.Fatalf("victim RETR: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("victim RETR payload = %q; want %q", got, payload)
			}
			_ = victimTLS.Close()
			victim.read(226)
		})
	}
}

// TestFTPS_AuthTLSDiscardsPlaintextLogin verifies that when a plaintext
// login precedes AUTH TLS, the upgrade runs the real logout path: a
// Logout event is announced and the connection's user association is
// dropped, so revoking the pre-TLS user does not evict the now-anonymous
// encrypted session.
func TestFTPS_AuthTLSDiscardsPlaintextLogin(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"victim": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}
	cfg, pool := newTestFTPSConfig(t, users, false)
	srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.login("victim", "pw")
	requireAuthEvent(t, srv.AuthEvents(), AuthEventLoginSuccess, "victim", CompletedUploadProtocolFTP)

	c.authTLS()
	requireAuthEvent(t, srv.AuthEvents(), AuthEventLogout, "victim", CompletedUploadProtocolFTP)

	srv.RemoveUser("victim")
	c.command(200, "NOOP")
}
