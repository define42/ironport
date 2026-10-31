package ironport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// testSigner creates a throwaway RSA host key for tests.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func newTestConfig(addr, ftpAddr, ftpPassivePortRange string, users map[string]UserInfo, signer ssh.Signer, completedUploadsSize int) *Config {
	config := DefaultConfig()
	config.SftpAddr = addr
	config.FtpAddr = ftpAddr
	config.FtpPassivePortRange = ftpPassivePortRange
	config.Users = users
	config.SftpSigner = signer
	config.CompletedUploadSize = completedUploadsSize
	return config
}

func newTestServer(addr, ftpAddr, ftpPassivePortRange string, users map[string]UserInfo, signer ssh.Signer, completedUploadsSize int) *Server {
	return NewServer(newTestConfig(addr, ftpAddr, ftpPassivePortRange, users, signer, completedUploadsSize))
}

func newTestFTPConfig(t *testing.T, users map[string]UserInfo, ftpPassivePortRange string, allowActive bool) *Config {
	t.Helper()
	config := newTestConfig("127.0.0.1:0", "127.0.0.1:0", ftpPassivePortRange, users, testSigner(t), defaultCompletedUploadsSize)
	config.FtpAllowActiveMode = allowActive
	return config
}

// startTestServer launches a server on a random OS-assigned port and returns
// the address and a cancel function that closes the listener.
func startTestServer(t *testing.T, users map[string]UserInfo) (srv *Server, addr string, stop func()) {
	t.Helper()
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	return startTestServerWithConfig(t, config)
}

func startTestServerWithConfig(t *testing.T, config *Config) (srv *Server, addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()

	if config == nil {
		config = DefaultConfig()
	}
	serverConfig := *config
	serverConfig.SftpAddr = addr
	srv = NewServer(&serverConfig)
	cfg := srv.sshServerConfig()

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			if !srv.trackConn(nc) {
				_ = nc.Close()
				continue
			}
			go func() {
				defer srv.connWG.Done()
				defer srv.untrackConn(nc)
				srv.handleConn(nc, cfg, srv.completedUploadsChan(), srv.authEventsChan(), srv.configuredTempExtensions(), srv.effectiveIdleTimeout(), srv.sftpChownAllowed())
			}()
		}
	}()

	stop = func() { _ = ln.Close() }
	return srv, addr, stop
}

// dialSFTP connects an sftp.Client to addr using the given credentials.
func dialSFTP(t *testing.T, addr, user, pass string) *sftp.Client {
	t.Helper()
	sshCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = conn.Close()
	})
	return client
}

func startTestFTPServer(t *testing.T, users map[string]UserInfo, ftpPassivePortRange string) (srv *Server, addr string, stop func()) {
	t.Helper()

	return startTestFTPServerWithConfig(t, newTestFTPConfig(t, users, ftpPassivePortRange, false))
}

func startTestFTPServerWithActive(t *testing.T, users map[string]UserInfo, ftpPassivePortRange string) (srv *Server, addr string, stop func()) {
	t.Helper()

	return startTestFTPServerWithConfig(t, newTestFTPConfig(t, users, ftpPassivePortRange, true))
}

//nolint:gocognit // test harness setup: many optional config knobs to thread through
func startTestFTPServerWithConfig(t *testing.T, config *Config) (srv *Server, addr string, stop func()) {
	t.Helper()

	srv = NewServer(config)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("ListenAndServe: %v", err)
		default:
		}
		if lnAddr := srv.FTPListeningAddr(); lnAddr != nil {
			addr = lnAddr.String()
			stop = func() {
				if err := srv.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
				select {
				case err := <-errCh:
					if err != nil {
						t.Errorf("ListenAndServe returned error: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("timed out waiting for FTP server shutdown")
				}
			}
			return srv, addr, stop
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = srv.Close()
	t.Fatal("timed out waiting for FTP listener")
	return nil, "", nil
}

type ftpTestClient struct {
	t    *testing.T
	conn net.Conn
	tp   *textproto.Conn
}

func dialFTP(t *testing.T, addr string) *ftpTestClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout: %v", err)
	}

	client := &ftpTestClient{
		t:    t,
		conn: conn,
		tp:   textproto.NewConn(conn),
	}
	if got := client.read(220); !strings.Contains(strings.ToLower(got), "ready") {
		t.Fatalf("unexpected FTP greeting: %q", got)
	}
	t.Cleanup(func() {
		_ = client.tp.Close()
	})
	return client
}

func (c *ftpTestClient) send(format string, args ...any) {
	c.t.Helper()
	if err := c.tp.PrintfLine(format, args...); err != nil {
		c.t.Fatalf("PrintfLine(%q): %v", format, err)
	}
}

func (c *ftpTestClient) read(expect int) string {
	c.t.Helper()
	_, msg, err := c.tp.ReadResponse(expect)
	if err != nil {
		c.t.Fatalf("ReadResponse(%d): %v", expect, err)
	}
	return msg
}

func (c *ftpTestClient) command(expect int, format string, args ...any) string {
	c.t.Helper()
	c.send(format, args...)
	return c.read(expect)
}

func (c *ftpTestClient) login(user, pass string) {
	c.t.Helper()
	c.command(331, "USER %s", user)
	c.command(230, "PASS %s", pass)
}

func (c *ftpTestClient) passiveConn() (net.Conn, int) {
	c.t.Helper()

	host, port, err := parseFTPPASVResponse(c.command(227, "PASV"))
	if err != nil {
		c.t.Fatalf("parse PASV response: %v", err)
	}

	dc, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		c.t.Fatalf("net.DialTimeout(data): %v", err)
	}
	return dc, port
}

func listenFTPActiveData(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(active data): %v", err)
	}
	return ln
}

func acceptFTPActiveData(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()

	if tcpLn, ok := ln.(*net.TCPListener); ok {
		_ = tcpLn.SetDeadline(time.Now().Add(5 * time.Second))
	}
	dc, err := ln.Accept()
	if err != nil {
		t.Fatalf("active data Accept: %v", err)
	}
	return dc
}

func (c *ftpTestClient) activePORTListener() net.Listener {
	c.t.Helper()

	ln := listenFTPActiveData(c.t)
	addr := ln.Addr().(*net.TCPAddr)
	ip := addr.IP.To4()
	if ip == nil {
		_ = ln.Close()
		c.t.Fatalf("active listener IP = %v; want IPv4", addr.IP)
	}
	c.command(200, "PORT %d,%d,%d,%d,%d,%d", ip[0], ip[1], ip[2], ip[3], addr.Port/256, addr.Port%256)
	return ln
}

func (c *ftpTestClient) activeEPRTListener() net.Listener {
	c.t.Helper()

	ln := listenFTPActiveData(c.t)
	addr := ln.Addr().(*net.TCPAddr)
	c.command(200, "EPRT |1|%s|%d|", addr.IP.String(), addr.Port)
	return ln
}

func requireAuthEvent(t *testing.T, events <-chan AuthEvent, eventType AuthEventType, username, protocol string) AuthEvent {
	t.Helper()
	select {
	case got := <-events:
		if got.Type != eventType {
			t.Fatalf("AuthEvent Type = %q; want %q (event %+v)", got.Type, eventType, got)
		}
		if got.Username != username {
			t.Fatalf("AuthEvent Username = %q; want %q (event %+v)", got.Username, username, got)
		}
		if got.Protocol != protocol {
			t.Fatalf("AuthEvent Protocol = %q; want %q (event %+v)", got.Protocol, protocol, got)
		}
		return got
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for AuthEvent type=%q user=%q protocol=%q", eventType, username, protocol)
		return AuthEvent{}
	}
}

func requireNoAuthEvent(t *testing.T, events <-chan AuthEvent) {
	t.Helper()
	select {
	case got := <-events:
		t.Fatalf("unexpected AuthEvent: %+v", got)
	default:
	}
}

func parseFTPPASVResponse(msg string) (string, int, error) {
	start := strings.IndexByte(msg, '(')
	end := strings.LastIndexByte(msg, ')')
	if start < 0 || end <= start {
		return "", 0, errors.New("missing passive mode tuple")
	}

	parts := strings.Split(msg[start+1:end], ",")
	if len(parts) != 6 {
		return "", 0, errors.New("invalid passive mode tuple")
	}

	values := make([]int, len(parts))
	for i, part := range parts {
		value, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return "", 0, err
		}
		if value < 0 || value > 255 {
			return "", 0, fmt.Errorf("PASV octet/byte %d out of range: %d", i, value)
		}
		values[i] = value
	}

	host := net.IPv4(byte(values[0]), byte(values[1]), byte(values[2]), byte(values[3])).String() //nolint:gosec // values bounded to [0,255] above
	port := values[4]*256 + values[5]
	return host, port, nil
}

// testClientKey generates a throwaway RSA key pair for use as a client
// authentication key in tests.  It returns both the signer (private key) and
// the corresponding public key.
func testClientKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, signer.PublicKey()
}

// dialSFTPWithPublicKey connects an sftp.Client to addr using public-key auth.
func dialSFTPWithPublicKey(t *testing.T, addr, user string, signer ssh.Signer) *sftp.Client {
	t.Helper()
	sshCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = conn.Close()
	})
	return client
}

type testConnMetadata struct {
	user string
}

func (m testConnMetadata) User() string          { return m.user }
func (m testConnMetadata) SessionID() []byte     { return nil }
func (m testConnMetadata) ClientVersion() []byte { return nil }
func (m testConnMetadata) ServerVersion() []byte { return nil }
func (m testConnMetadata) RemoteAddr() net.Addr  { return &net.TCPAddr{} }
func (m testConnMetadata) LocalAddr() net.Addr   { return &net.TCPAddr{} }

// startListenAndServe boots a server via ListenAndServe on
// 127.0.0.1:0 and returns it once it is accepting. The caller must drain
// errCh and call Shutdown/Close to stop the server.
func startListenAndServe(t *testing.T, users map[string]UserInfo) (srv *Server, addr string, errCh chan error) {
	t.Helper()
	srv = newTestServer("127.0.0.1:0", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	errCh = make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	addr = waitForSFTPListener(t, srv, errCh)
	return srv, addr, errCh
}

func waitForSFTPListener(t *testing.T, srv *Server, errCh <-chan error) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.ListeningAddr(); a != nil {
			return a.String()
		}
		select {
		case err := <-errCh:
			t.Fatalf("ListenAndServe returned early: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = srv.Close()
	t.Fatal("server did not start in time")
	return ""
}

type panicReadChannel struct {
	closeOnce sync.Once
	closed    chan struct{}
	stderr    bytes.Buffer
}

func (c *panicReadChannel) Read([]byte) (int, error) {
	panic("synthetic channel read panic")
}

func (c *panicReadChannel) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c *panicReadChannel) Close() error {
	c.closeOnce.Do(func() {
		if c.closed != nil {
			close(c.closed)
		}
	})
	return nil
}

func (c *panicReadChannel) CloseWrite() error {
	return nil
}

func (c *panicReadChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}

func (c *panicReadChannel) Stderr() io.ReadWriter {
	return &c.stderr
}

func assertWriterCompletedUpload(t *testing.T, uploads <-chan CompletedUpload, finalName, finalFullPath string) {
	t.Helper()
	select {
	case got := <-uploads:
		if got.FilePath != finalName {
			t.Errorf("CompletedUploads FilePath = %q; want %q", got.FilePath, finalName)
		}
		if got.FullFilePath != finalFullPath {
			t.Errorf("CompletedUploads FullFilePath = %q; want final path", got.FullFilePath)
		}
		if got.Protocol != CompletedUploadProtocolSFTP {
			t.Errorf("CompletedUploads Protocol = %q; want %q", got.Protocol, CompletedUploadProtocolSFTP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CompletedUploads for .writer rename")
	}
}

type stubListener struct {
	conn net.Conn
}

func (l *stubListener) Accept() (net.Conn, error) { return l.conn, nil }
func (l *stubListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}
func (l *stubListener) Addr() net.Addr { return &net.TCPAddr{} }

type stubConn struct {
	readErr error
}

func (c *stubConn) Read([]byte) (int, error)         { return 0, c.readErr }
func (c *stubConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *stubConn) Close() error                     { return nil }
func (c *stubConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stubConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *stubConn) SetDeadline(time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

// generateFTPSTestCert mints a single-host self-signed RSA certificate
// suitable for use as the server certificate in FTPS test runs. It also
// returns the CA pool that the client uses to verify it.
func generateFTPSTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ironport-ftps-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)
	return cert, pool
}

func newTestFTPSConfig(t *testing.T, users map[string]UserInfo, requireTLS bool) (*Config, *x509.CertPool) {
	t.Helper()
	cert, pool := generateFTPSTestCert(t)
	cfg := newTestFTPConfig(t, users, "", false)
	cfg.FtpTLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	cfg.FtpRequireTLS = requireTLS
	return cfg, pool
}

// trackingTLSSessionCache makes TLS ticket use observable without inspecting
// opaque ClientSessionState internals. A successful Get records that crypto/tls
// selected a cached session while constructing a ClientHello.
type trackingTLSSessionCache struct {
	mu      sync.Mutex
	entries map[string]*tls.ClientSessionState
	puts    int
	hits    int
}

func newTrackingTLSSessionCache() *trackingTLSSessionCache {
	return &trackingTLSSessionCache{entries: make(map[string]*tls.ClientSessionState)}
}

func (c *trackingTLSSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cs == nil {
		delete(c.entries, sessionKey)
		return
	}
	c.entries[sessionKey] = cs
	c.puts++
}

func (c *trackingTLSSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cs, ok := c.entries[sessionKey]
	if ok {
		c.hits++
	}
	return cs, ok
}

func (c *trackingTLSSessionCache) stats() (cached, puts, hits int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries), c.puts, c.hits
}

// ftpsTestClient drives an FTPS session over a fresh TCP connection. It
// reuses the same textproto plumbing as ftpTestClient but rewraps the
// reader/writer after the AUTH TLS handshake completes.
type ftpsTestClient struct {
	t        *testing.T
	rawConn  net.Conn
	tlsConn  *tls.Conn
	conn     net.Conn
	tp       *textproto.Conn
	tlsCfg   *tls.Config
	sessions tls.ClientSessionCache
}

func dialFTPS(t *testing.T, addr string, pool *x509.CertPool) *ftpsTestClient {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout: %v", err)
	}
	c := &ftpsTestClient{
		t:        t,
		rawConn:  raw,
		conn:     raw,
		tp:       textproto.NewConn(raw),
		sessions: tls.NewLRUClientSessionCache(8),
		tlsCfg: &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
		},
	}
	c.tlsCfg.ClientSessionCache = c.sessions
	if _, msg, err := c.tp.ReadResponse(220); err != nil {
		t.Fatalf("greeting: %v (%s)", err, msg)
	}
	t.Cleanup(func() { _ = c.tp.Close() })
	return c
}

func (c *ftpsTestClient) send(format string, args ...any) {
	c.t.Helper()
	if err := c.tp.PrintfLine(format, args...); err != nil {
		c.t.Fatalf("PrintfLine(%q): %v", format, err)
	}
}

func (c *ftpsTestClient) read(expect int) string {
	c.t.Helper()
	_, msg, err := c.tp.ReadResponse(expect)
	if err != nil {
		c.t.Fatalf("ReadResponse(%d): %v", expect, err)
	}
	return msg
}

func (c *ftpsTestClient) command(expect int, format string, args ...any) string {
	c.t.Helper()
	c.send(format, args...)
	return c.read(expect)
}

func (c *ftpsTestClient) authTLS() {
	c.t.Helper()
	c.command(234, "AUTH TLS")
	tlsConn := tls.Client(c.rawConn, c.tlsCfg)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		c.t.Fatalf("client TLS handshake: %v", err)
	}
	c.tlsConn = tlsConn
	c.conn = tlsConn
	c.tp = textproto.NewConn(tlsConn)
}

func (c *ftpsTestClient) login(user, pass string) {
	c.t.Helper()
	c.command(331, "USER %s", user)
	c.command(230, "PASS %s", pass)
}

// passiveDial opens the data TCP connection after PASV but does not start
// the TLS handshake. Use upgradeDataConn after the server has replied 150
// to the transfer command: server-side TLS handshake on the data conn
// runs only after the transfer command is processed, so starting the
// client-side handshake before that would deadlock.
func (c *ftpsTestClient) passiveDial() net.Conn {
	c.t.Helper()
	host, port, err := parseFTPPASVResponse(c.command(227, "PASV"))
	if err != nil {
		c.t.Fatalf("parse PASV: %v", err)
	}
	dc, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		c.t.Fatalf("dial data: %v", err)
	}
	return dc
}

// expectDataProtectionRequired verifies that a prepared data transfer is
// rejected before the server emits 150 or touches the target file.
func (c *ftpsTestClient) expectDataProtectionRequired(command string) {
	c.t.Helper()
	dc := c.passiveDial()
	defer func() { _ = dc.Close() }()

	if got := c.command(534, "%s", command); got != errFTPDataProtectionRequired.Error() {
		c.t.Fatalf("%s response = %q; want %q", command, got, errFTPDataProtectionRequired)
	}
}

// storeProtected uploads payload over a PROT P data connection.
func (c *ftpsTestClient) storeProtected(filename string, payload []byte) {
	c.t.Helper()
	raw := c.passiveDial()
	defer func() { _ = raw.Close() }()

	c.send("STOR %s", filename)
	c.read(150)
	tc := c.upgradeDataConn(raw)
	if _, err := tc.Write(payload); err != nil {
		c.t.Fatalf("write protected upload: %v", err)
	}
	if err := tc.CloseWrite(); err != nil {
		c.t.Fatalf("close protected upload: %v", err)
	}
	_ = tc.Close()
	c.read(226)
}

// upgradeDataConn drives the client-side TLS handshake on an FTP data
// connection. It must be called only after the server has replied 150 to
// the transfer command.
func (c *ftpsTestClient) upgradeDataConn(dc net.Conn) *tls.Conn {
	c.t.Helper()
	tc := tls.Client(dc, c.tlsCfg)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		_ = dc.Close()
		c.t.Fatalf("data TLS handshake: %v", err)
	}
	return tc
}

// errListener is a net.Listener whose Close returns a configurable error, used
// to exercise the listener-cleanup paths without a real socket.
type errListener struct {
	closeErr error
	closed   bool
}

func (l *errListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *errListener) Close() error {
	l.closed = true
	return l.closeErr
}
func (l *errListener) Addr() net.Addr { return &net.TCPAddr{} }

// timeoutErr is a net.Error that reports a timeout, used to drive the
// net.Error/Timeout() branch of isTransientAcceptError.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// newReplyCaptureSession returns an ftpSession whose control replies are
// captured in buf. flush is required because reply() writes through a
// bufio.Writer.
func newReplyCaptureSession(buf *bytes.Buffer) *ftpSession {
	return &ftpSession{w: bufio.NewWriter(buf)}
}
