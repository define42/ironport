package ironport

import (
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHServerConfig_AppliesAlgorithmPins(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "pw", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	config := newTestConfig(":0", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.SSHKeyExchanges = []string{ssh.KeyExchangeCurve25519}
	config.SSHCiphers = []string{ssh.CipherAES256CTR}
	config.SSHMACs = []string{ssh.HMACSHA256}
	config.SSHPublicKeyAuthAlgorithms = []string{ssh.KeyAlgoRSASHA256}
	config.TempExtensions = []string{".tmp"}
	srv := NewServer(config)
	config.SSHCiphers[0] = ssh.CipherAES128CTR
	config.TempExtensions[0] = ".writing"

	cfg := srv.sshServerConfig()
	if !slices.Equal(cfg.KeyExchanges, []string{ssh.KeyExchangeCurve25519}) {
		t.Fatalf("KeyExchanges = %v; want %v", cfg.KeyExchanges, []string{ssh.KeyExchangeCurve25519})
	}
	if !slices.Equal(cfg.Ciphers, []string{ssh.CipherAES256CTR}) {
		t.Fatalf("Ciphers = %v; want %v", cfg.Ciphers, []string{ssh.CipherAES256CTR})
	}
	if !slices.Equal(cfg.MACs, []string{ssh.HMACSHA256}) {
		t.Fatalf("MACs = %v; want %v", cfg.MACs, []string{ssh.HMACSHA256})
	}
	if !slices.Equal(cfg.PublicKeyAuthAlgorithms, []string{ssh.KeyAlgoRSASHA256}) {
		t.Fatalf("PublicKeyAuthAlgorithms = %v; want %v", cfg.PublicKeyAuthAlgorithms, []string{ssh.KeyAlgoRSASHA256})
	}

	srv.sshCiphers[0] = ssh.CipherAES128CTR
	if got := cfg.Ciphers[0]; got != ssh.CipherAES256CTR {
		t.Fatalf("sshServerConfig aliased server SSHCiphers; Ciphers[0] = %q", got)
	}
	if got := srv.configuredTempExtensions()[0]; got != ".tmp" {
		t.Fatalf("NewServer aliased config TempExtensions; configuredTempExtensions()[0] = %q", got)
	}
}

func TestSFTPServer_SSHAlgorithmPinning(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.SSHKeyExchanges = []string{ssh.KeyExchangeCurve25519}
	config.SSHCiphers = []string{ssh.CipherAES256CTR}
	config.SSHMACs = []string{ssh.HMACSHA256}
	_, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherAES256CTR},
			MACs:         []string{ssh.HMACSHA256},
		},
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial with matching pinned algorithms: %v", err)
	}
	_ = conn.Close()

	sshCfg.Ciphers = []string{ssh.CipherAES128CTR}
	if conn, err = ssh.Dial("tcp", addr, sshCfg); err == nil {
		_ = conn.Close()
		t.Fatal("expected cipher negotiation failure, got nil")
	}
}

func TestSFTPServer_PublicKeyAuthAlgorithmPinning(t *testing.T) {
	root := t.TempDir()
	clientSigner, clientPubKey := testClientKey(t)
	users := map[string]UserInfo{
		"alice": {AuthorizedKeys: []ssh.PublicKey{clientPubKey}, Root: root, CanRead: true, CanWrite: true},
	}

	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.SSHPublicKeyAuthAlgorithms = []string{ssh.KeyAlgoRSASHA256}
	_, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial with matching public-key auth algorithm: %v", err)
	}
	_ = conn.Close()

	rejectConfig := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	rejectConfig.SSHPublicKeyAuthAlgorithms = []string{ssh.KeyAlgoED25519}
	_, rejectAddr, rejectStop := startTestServerWithConfig(t, rejectConfig)
	t.Cleanup(rejectStop)

	if conn, err = ssh.Dial("tcp", rejectAddr, sshCfg); err == nil {
		_ = conn.Close()
		t.Fatal("expected public-key auth algorithm rejection, got nil")
	}
}

// TestHandleConn_HandshakeTimeout verifies that a raw TCP connection that
// never sends SSH data is dropped well within the 30-second handshake
// deadline (we use a 35-second upper bound to keep the test fast without
// being flaky on slow CI).
func TestHandleConn_HandshakeTimeout(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	signer := testSigner(t)
	srv := newTestServer("127.0.0.1:0", "", "", users, signer, defaultCompletedUploadsSize)
	cfg := srv.sshServerConfig()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConn(nc, cfg, srv.completedUploadsChan(), srv.authEventsChan(), srv.configuredTempExtensions(), srv.effectiveIdleTimeout(), srv.sftpChownAllowed())
		}
	}()

	// Connect but never send any SSH data.
	idle, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer func() { _ = idle.Close() }()

	// The server sends the SSH protocol version banner on connect, so we must
	// drain bytes until the connection is fully closed by the server-side
	// handshake deadline.  Use a 35-second outer deadline so the test does not
	// hang if the fix were ever reverted.
	_ = idle.SetReadDeadline(time.Now().Add(35 * time.Second))
	buf := make([]byte, 256)
	var lastErr error
	for {
		_, lastErr = idle.Read(buf)
		if lastErr != nil {
			break
		}
	}
	// The deadline on our side must NOT have expired – the server must have
	// closed the connection first (EOF or connection-reset).
	var netErr net.Error
	if errors.As(lastErr, &netErr) && netErr.Timeout() {
		t.Error("server did not close the idle connection before the 35 s outer deadline; handshake timeout may not be working")
	}
}

func TestHandleSession_RecoversFromPanic(t *testing.T) {
	ch := &panicReadChannel{closed: make(chan struct{})}
	inReqs := make(chan *ssh.Request, 1)
	inReqs <- &ssh.Request{
		Type:    "subsystem",
		Payload: append([]byte{0, 0, 0, 4}, []byte("sftp")...),
	}
	close(inReqs)

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSession(ch, inReqs, t.TempDir(), "testuser", "127.0.0.1", true, true, make(chan CompletedUpload, 1), nil, false)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleSession did not return after recovered panic")
	}

	select {
	case <-ch.closed:
	default:
		t.Fatal("handleSession did not close the channel after recovered panic")
	}
}

func TestCleanSFTPClientPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/upload.txt", "/upload.txt"},
		{"upload.txt", "/upload.txt"},
		{"foo.txt", "/foo.txt"},
		{"/a/../b.txt", "/b.txt"},
		{"../../etc/passwd", "/etc/passwd"},
		{"/a/b/../c", "/a/c"},
		{"", "/"},
		{".", "/"},
		{"/", "/"},
		{"//double//slash", "/double/slash"},
	}
	for _, c := range cases {
		if got := cleanSFTPClientPath(c.in); got != c.want {
			t.Errorf("cleanSFTPClientPath(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
