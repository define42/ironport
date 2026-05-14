package ironport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ---- cleanRelClientPath / jailFS path-handling tests ----

func TestCleanRelClientPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "."},
		{"/", "."},
		{".", "."},
		{"foo.txt", "foo.txt"},
		{"/foo.txt", "foo.txt"},
		{"/bar/baz.txt", "bar/baz.txt"},
		{"./bar", "bar"},
		{"/a/../b.txt", "b.txt"},
		{"../../etc/passwd", "etc/passwd"},
	}
	for _, tc := range tests {
		got := cleanRelClientPath(tc.in)
		if got != tc.want {
			t.Errorf("cleanRelClientPath(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestJailFS_RejectsSymlinkComponents covers the core hardening guarantee:
// no openat2-backed operation may traverse a symlink, regardless of whether
// the symlink is the final component or an intermediate one, and regardless
// of whether its target lies inside or outside the jail. The same fixture
// exercises read, write, stat, list, chmod, truncate, mkdir, remove, and
// rename, so a regression in any helper is caught here.
func TestJailFS_RejectsSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	// Create a real subdir and a regular file inside the jail so that
	// "innocent" calls succeed and we know the failures below are caused
	// by the symlink, not by a misconfigured fixture.
	if err := os.Mkdir(filepath.Join(root, "real"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real", "file.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Symlink whose target escapes the jail.
	if err := os.Symlink(filepath.Join(outside, "missing.txt"), filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	// Symlink to a directory inside the jail. Even an "internal" symlink is
	// rejected so the policy does not depend on resolving the target.
	if err := os.Symlink("real", filepath.Join(root, "real_link")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatalf("openJailFS: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })

	type op struct {
		name string
		run  func() error
	}
	ops := []op{
		{"OpenRead final", func() error { _, err := jfs.OpenRead("/escape"); return err }},
		{"OpenRead middle", func() error { _, err := jfs.OpenRead("/real_link/file.txt"); return err }},
		{"OpenWrite final", func() error {
			_, err := jfs.OpenWrite("/escape", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			return err
		}},
		{"OpenWrite middle", func() error {
			_, err := jfs.OpenWrite("/real_link/new.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			return err
		}},
		{"Stat final", func() error { _, err := jfs.Stat("/escape"); return err }},
		{"List middle", func() error { _, err := jfs.List("/real_link"); return err }},
		{"Mkdir middle", func() error { return jfs.Mkdir("/real_link/sub", 0o750) }},
		{"Rename src middle", func() error { return jfs.Rename("/real_link/file.txt", "/x") }},
		{"Rename dst middle", func() error { return jfs.Rename("/real/file.txt", "/real_link/x") }},
		{"Chmod final", func() error { return jfs.Chmod("/escape", 0o600) }},
		{"Truncate final", func() error { return jfs.Truncate("/escape", 0) }},
	}
	for _, o := range ops {
		err := o.run()
		if err == nil {
			t.Errorf("%s: expected error for symlink traversal, got nil", o.name)
		}
	}

	// The escaping symlink target must still not exist on disk: none of the
	// rejected operations may have been completed through it. (Note: Remove
	// of a symlink final component is intentionally allowed so users can
	// clean up symlinks; it removes the symlink itself via unlinkat, not
	// its target.)
	if _, err := os.Stat(filepath.Join(outside, "missing.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside target was created or stat failed unexpectedly: %v", err)
	}
}

// TestJailFS_PathTraversalContained verifies RESOLVE_IN_ROOT keeps ".."
// inside the jail. Both the leading ".." and a mid-path ".." are clamped so
// they cannot reach a sibling jail or the real filesystem root.
func TestJailFS_PathTraversalContained(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatalf("openJailFS: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })

	// "../../etc/passwd" → cleaned to "etc/passwd" relative to the jail and
	// resolved against the root fd, so it must fail with ENOENT, not return
	// /etc/passwd from the host.
	if _, err := jfs.OpenRead("../../etc/passwd"); err == nil {
		t.Fatal("OpenRead escape returned nil error")
	}
	// A path that climbs and then re-descends to a real entry inside the jail
	// must succeed via cleaning ("../inside.txt" → "inside.txt").
	f, err := jfs.OpenRead("../inside.txt")
	if err != nil {
		t.Fatalf("OpenRead inside via .. : %v", err)
	}
	_ = f.Close()
}

func TestJailFilewriteRejectsBrokenSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideTarget := filepath.Join(outside, "newfile.txt")
	link := filepath.Join(root, "link")
	if err := os.Symlink(outsideTarget, link); err != nil {
		t.Skipf("creating symlink: %v", err)
	}

	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatalf("openJailFS: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })

	j := jail{
		fs:       jfs,
		username: "testuser",
		clientIP: "127.0.0.1",
		canWrite: true,
		uploads:  make(chan CompletedUpload, 1),
	}
	_, err = j.Filewrite(&sftp.Request{Filepath: "/link"})
	if err == nil {
		t.Fatalf("Filewrite to broken symlink succeeded; want error")
	}
	if _, err := os.Stat(outsideTarget); !os.IsNotExist(err) {
		t.Fatalf("outside target was created or stat failed unexpectedly: %v", err)
	}
}

// ---- integration test: full SFTP upload / download / list ----

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

func newTestServer(addr, ftpAddr, ftpPassivePortRange string, users map[string]UserInfo, signer ssh.Signer, completedUploadsSize int) *server {
	config := DefaultIronportConfig()
	config.Addr = addr
	config.FtpAddr = ftpAddr
	config.FtpPassivePortRange = ftpPassivePortRange
	config.Users = users
	config.Signer = signer
	config.CompletedUploadSize = completedUploadsSize
	return NewServer(config)
}

// startTestServer launches a server on a random OS-assigned port and returns
// the address and a cancel function that closes the listener.
//
// Each optional configure callback runs against the freshly constructed
// *server BEFORE the accept goroutine starts, so tests can safely mutate
// fields like AllowChown or TempExtensions without racing the accept loop.
// Mutating those fields on the returned *server after this function returns
// is unsafe under the race detector.
func startTestServer(t *testing.T, users map[string]UserInfo, configure ...func(*server)) (srv *server, addr string, stop func()) {
	t.Helper()
	signer := testSigner(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()

	srv = newTestServer(addr, "", "", users, signer, defaultCompletedUploadsSize)
	for _, fn := range configure {
		if fn != nil {
			fn(srv)
		}
	}
	cfg := srv.sshServerConfig()

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go handleConn(nc, cfg, srv.completedUploadsChan(), srv.tempExtensions(), srv.idleTimeout(), srv.allowChown())
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

func startTestFTPServer(t *testing.T, users map[string]UserInfo, ftpPassivePortRange string) (srv *server, addr string, stop func()) {
	t.Helper()

	srv = newTestServer("127.0.0.1:0", "127.0.0.1:0", ftpPassivePortRange, users, testSigner(t), defaultCompletedUploadsSize)
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
		values[i] = value
	}

	host := net.IPv4(byte(values[0]), byte(values[1]), byte(values[2]), byte(values[3])).String()
	port := values[4]*256 + values[5]
	return host, port, nil
}

func TestSFTPServer_UploadDownload(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	content := []byte("hello sftp world")
	remote := "/upload.txt"
	f, err := client.Create(remote)
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	_ = f.Close()

	// Download and compare.
	rf, err := client.Open(remote)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

func TestSFTPServer_List(t *testing.T) {
	root := t.TempDir()
	// Pre-create a file so we have something to list.
	if err := os.WriteFile(filepath.Join(root, "listed.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("client.ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "listed.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("ReadDir returned %v; want [listed.txt]", names)
	}
}

func TestSFTPServer_InvalidCredentials(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "rightpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("wrongpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_, err := ssh.Dial("tcp", addr, sshCfg)
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
}

func TestNewServer(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "pw", Root: "/tmp/alice", CanRead: true, CanWrite: true},
	}
	signer := testSigner(t)
	config := DefaultIronportConfig()
	config.Addr = ":0"
	config.FtpAddr = ":0"
	config.FtpPassivePortRange = "5000-5010"
	config.Users = users
	config.Signer = signer
	config.CompletedUploadSize = defaultCompletedUploadsSize
	srv := NewServer(config)
	if srv.Addr != ":0" {
		t.Errorf("Addr = %q; want :0", srv.Addr)
	}
	if srv.FTPAddr != ":0" {
		t.Errorf("FTPAddr = %q; want :0", srv.FTPAddr)
	}
	if srv.FTPPassivePortRange != "5000-5010" {
		t.Errorf("FTPPassivePortRange = %q; want 5000-5010", srv.FTPPassivePortRange)
	}
	if len(srv.users) != 1 {
		t.Errorf("users len = %d; want 1", len(srv.users))
	}
	users["alice"] = UserInfo{Password: "changed", Root: "/tmp/changed"}
	if got := srv.users["alice"].Password; got != "pw" {
		t.Errorf("users map was not cloned; password = %q; want pw", got)
	}
	if srv.signer != signer {
		t.Error("signer not set correctly")
	}
}

func TestDefaultIronportConfig(t *testing.T) {
	config := DefaultIronportConfig()
	if config.Addr != ":2022" {
		t.Errorf("Addr = %q; want :2022", config.Addr)
	}
	if config.FtpAddr != "" {
		t.Errorf("FtpAddr = %q; want empty", config.FtpAddr)
	}
	if config.FtpPassivePortRange != "5000-5010" {
		t.Errorf("FtpPassivePortRange = %q; want 5000-5010", config.FtpPassivePortRange)
	}
	if config.CompletedUploadSize != defaultCompletedUploadsSize {
		t.Errorf("CompletedUploadSize = %d; want %d", config.CompletedUploadSize, defaultCompletedUploadsSize)
	}
	if config.Users != nil {
		t.Error("Users is non-nil; want nil")
	}
	if config.Signer != nil {
		t.Error("Signer is non-nil; want nil")
	}

	other := DefaultIronportConfig()
	if config == other {
		t.Fatal("DefaultIronportConfig returned the same pointer twice")
	}
	config.Addr = ":9999"
	if other.Addr != ":2022" {
		t.Errorf("second config Addr = %q after mutating first; want :2022", other.Addr)
	}
}

func TestSSHServerConfig_AppliesAlgorithmPins(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "pw", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	srv := newTestServer(":0", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	srv.SSHAlgorithms = SSHAlgorithms{
		KeyExchanges:            []string{ssh.KeyExchangeCurve25519},
		Ciphers:                 []string{ssh.CipherAES256CTR},
		MACs:                    []string{ssh.HMACSHA256},
		PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoRSASHA256},
	}

	cfg := srv.sshServerConfig()
	if !reflect.DeepEqual(cfg.KeyExchanges, []string{ssh.KeyExchangeCurve25519}) {
		t.Fatalf("KeyExchanges = %v; want %v", cfg.KeyExchanges, []string{ssh.KeyExchangeCurve25519})
	}
	if !reflect.DeepEqual(cfg.Ciphers, []string{ssh.CipherAES256CTR}) {
		t.Fatalf("Ciphers = %v; want %v", cfg.Ciphers, []string{ssh.CipherAES256CTR})
	}
	if !reflect.DeepEqual(cfg.MACs, []string{ssh.HMACSHA256}) {
		t.Fatalf("MACs = %v; want %v", cfg.MACs, []string{ssh.HMACSHA256})
	}
	if !reflect.DeepEqual(cfg.PublicKeyAuthAlgorithms, []string{ssh.KeyAlgoRSASHA256}) {
		t.Fatalf("PublicKeyAuthAlgorithms = %v; want %v", cfg.PublicKeyAuthAlgorithms, []string{ssh.KeyAlgoRSASHA256})
	}

	srv.SSHAlgorithms.Ciphers[0] = ssh.CipherAES128CTR
	if got := cfg.Ciphers[0]; got != ssh.CipherAES256CTR {
		t.Fatalf("sshServerConfig aliased server SSHAlgorithms; Ciphers[0] = %q", got)
	}
}

func TestSFTPServer_SSHAlgorithmPinning(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users, func(s *server) {
		s.SSHAlgorithms = SSHAlgorithms{
			KeyExchanges: []string{ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherAES256CTR},
			MACs:         []string{ssh.HMACSHA256},
		}
	})
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		Config: ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeCurve25519},
			Ciphers:      []string{ssh.CipherAES256CTR},
			MACs:         []string{ssh.HMACSHA256},
		},
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	_, addr, stop := startTestServer(t, users, func(s *server) {
		s.SSHAlgorithms = SSHAlgorithms{
			PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoRSASHA256},
		}
	})
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial with matching public-key auth algorithm: %v", err)
	}
	_ = conn.Close()

	_, rejectAddr, rejectStop := startTestServer(t, users, func(s *server) {
		s.SSHAlgorithms = SSHAlgorithms{
			PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoED25519},
		}
	})
	t.Cleanup(rejectStop)

	if conn, err = ssh.Dial("tcp", rejectAddr, sshCfg); err == nil {
		_ = conn.Close()
		t.Fatal("expected public-key auth algorithm rejection, got nil")
	}
}

// TestCompletedUploadsBufferSize verifies that NewServer controls the buffer
// capacity of the CompletedUploads channel.
func TestCompletedUploadsBufferSize(t *testing.T) {
	signer := testSigner(t)
	users := map[string]UserInfo{
		"u": {Password: "pw", Root: t.TempDir(), CanWrite: true},
	}

	// Default capacity: a non-positive config value selects defaultCompletedUploadsSize.
	config := DefaultIronportConfig()
	config.Addr = ":0"
	config.FtpPassivePortRange = ""
	config.Users = users
	config.Signer = signer
	config.CompletedUploadSize = 0
	srv := NewServer(config)
	if cap(srv.CompletedUploads()) != defaultCompletedUploadsSize {
		t.Errorf("default cap = %d; want %d", cap(srv.CompletedUploads()), defaultCompletedUploadsSize)
	}

	// Custom capacity via NewServer config.
	config2 := DefaultIronportConfig()
	config2.Addr = ":0"
	config2.FtpPassivePortRange = ""
	config2.Users = users
	config2.Signer = signer
	config2.CompletedUploadSize = 256
	srv2 := NewServer(config2)
	if cap(srv2.CompletedUploads()) != 256 {
		t.Errorf("custom cap via NewServer = %d; want 256", cap(srv2.CompletedUploads()))
	}

	if srv2.completedUploadsChan() != srv2.completedUploads {
		t.Error("completedUploadsChan did not return the server upload channel")
	}
}

func TestFTPSessionAnnounceUploadUsesCapturedCompletedUploads(t *testing.T) {
	serverUploads := make(chan CompletedUpload, 1)
	sessionUploads := make(chan CompletedUpload, 1)
	fs := &ftpSession{
		server: &server{
			completedUploads: serverUploads,
		},
		username: "alice",
		clientIP: "127.0.0.1",
		uploads:  sessionUploads,
	}

	fs.announceUpload("/upload.txt", "/srv/upload.txt")

	select {
	case got := <-sessionUploads:
		if got.Username != "alice" {
			t.Errorf("Username = %q; want alice", got.Username)
		}
		if got.FilePath != "/upload.txt" {
			t.Errorf("FilePath = %q; want /upload.txt", got.FilePath)
		}
		if got.FullFilePath != "/srv/upload.txt" {
			t.Errorf("FullFilePath = %q; want /srv/upload.txt", got.FullFilePath)
		}
	case <-time.After(time.Second):
		t.Fatal("expected CompletedUpload on captured FTP session channel")
	}

	select {
	case got := <-serverUploads:
		t.Fatalf("announceUpload sent to server CompletedUploads after session capture: %+v", got)
	default:
	}
}

func TestParseFTPPassivePortRange(t *testing.T) {
	tests := []struct {
		name      string
		portRange string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{name: "empty", portRange: "", wantStart: 0, wantEnd: 0, wantErr: false},
		{name: "single port", portRange: "5000", wantStart: 5000, wantEnd: 5000},
		{name: "range", portRange: "5000-5010", wantStart: 5000, wantEnd: 5010},
		{name: "range with spaces", portRange: " 5000 - 5010 ", wantStart: 5000, wantEnd: 5010},
		{name: "invalid text", portRange: "abc", wantErr: true},
		{name: "invalid range", portRange: "5000-", wantErr: true},
		{name: "start greater than end", portRange: "5010-5000", wantErr: true},
		{name: "out of range", portRange: "70000", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotStart, gotEnd, err := parseFTPPassivePortRange(tc.portRange)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseFTPPassivePortRange(%q) error = nil; want non-nil", tc.portRange)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFTPPassivePortRange(%q): %v", tc.portRange, err)
			}
			if gotStart != tc.wantStart || gotEnd != tc.wantEnd {
				t.Fatalf("parseFTPPassivePortRange(%q) = (%d, %d); want (%d, %d)", tc.portRange, gotStart, gotEnd, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestServerListenFTPData(t *testing.T) {
	t.Run("os assigned port", func(t *testing.T) {
		srv := &server{}
		ln, err := srv.listenFTPData("127.0.0.1")
		if err != nil {
			t.Fatalf("listenFTPData: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		port := ln.Addr().(*net.TCPAddr).Port
		if port == 0 {
			t.Fatal("listenFTPData returned port 0; want assigned port")
		}
	})

	t.Run("configured port unavailable", func(t *testing.T) {
		busyLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { _ = busyLn.Close() })

		port := busyLn.Addr().(*net.TCPAddr).Port
		srv := &server{FTPPassivePortRange: strconv.Itoa(port)}
		if _, err := srv.listenFTPData("127.0.0.1"); err == nil {
			t.Fatal("listenFTPData error = nil; want non-nil when configured port is already in use")
		}
	})
}

func TestFTPServer_UploadDownloadList(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}

	srv, addr, stop := startTestFTPServer(t, users, "5000-5010")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")
	client.command(200, "TYPE I")

	content := []byte("hello ftp world")

	uploadConn, uploadPort := client.passiveConn()
	if uploadPort < 5000 || uploadPort > 5010 {
		t.Fatalf("PASV port = %d; want within 5000-5010", uploadPort)
	}
	client.send("STOR upload.txt")
	client.read(150)
	if _, err := uploadConn.Write(content); err != nil {
		t.Fatalf("uploadConn.Write: %v", err)
	}
	_ = uploadConn.Close()
	client.read(226)

	if got, err := os.ReadFile(filepath.Join(root, "upload.txt")); err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	} else if !bytes.Equal(got, content) {
		t.Fatalf("uploaded file content = %q; want %q", got, content)
	}

	listConn, listPort := client.passiveConn()
	if listPort < 5000 || listPort > 5010 {
		t.Fatalf("PASV port = %d; want within 5000-5010", listPort)
	}
	client.send("NLST")
	client.read(150)
	listing, err := io.ReadAll(listConn)
	if err != nil {
		t.Fatalf("io.ReadAll(listConn): %v", err)
	}
	_ = listConn.Close()
	client.read(226)
	if !strings.Contains(string(listing), "upload.txt") {
		t.Fatalf("NLST listing = %q; want upload.txt", listing)
	}

	downloadConn, downloadPort := client.passiveConn()
	if downloadPort < 5000 || downloadPort > 5010 {
		t.Fatalf("PASV port = %d; want within 5000-5010", downloadPort)
	}
	client.send("RETR upload.txt")
	client.read(150)
	downloaded, err := io.ReadAll(downloadConn)
	if err != nil {
		t.Fatalf("io.ReadAll(downloadConn): %v", err)
	}
	_ = downloadConn.Close()
	client.read(226)
	if !bytes.Equal(downloaded, content) {
		t.Fatalf("downloaded content = %q; want %q", downloaded, content)
	}

	select {
	case evt := <-srv.CompletedUploads():
		if evt.FilePath != "/upload.txt" {
			t.Fatalf("CompletedUploads FilePath = %q; want /upload.txt", evt.FilePath)
		}
		if evt.FullFilePath != filepath.Join(root, "upload.txt") {
			t.Fatalf("CompletedUploads FullFilePath = %q; want %q", evt.FullFilePath, filepath.Join(root, "upload.txt"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for FTP upload completion event")
	}
}

// TestSFTPServer_ReadOnlyUser verifies that a read-only user can download and
// list files but cannot upload or delete files.
func TestSFTPServer_ReadOnlyUser(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "data.txt"), []byte("read me"), 0644); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"reader": {Password: "readpw", Root: root, CanRead: true, CanWrite: false},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "reader", "readpw")

	// Read/list must succeed.
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "data.txt" {
		t.Errorf("ReadDir returned unexpected entries")
	}

	rf, err := client.Open("/data.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if string(got) != "read me" {
		t.Errorf("downloaded %q; want %q", got, "read me")
	}

	// Write must be denied.
	_, err = client.Create("/upload.txt")
	if err == nil {
		t.Error("expected write to be denied for read-only user, got nil error")
	}
}

// TestSFTPServer_WriteOnlyUser verifies that a write-only user can upload files
// but cannot read/download or list files.
func TestSFTPServer_WriteOnlyUser(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"writer": {Password: "writepw", Root: root, CanRead: false, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "writer", "writepw")

	// Upload must succeed.
	f, err := client.Create("/upload.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("write only")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Read must be denied.
	_, err = client.Open("/upload.txt")
	if err == nil {
		t.Error("expected read to be denied for write-only user, got nil error")
	}

	// List must be denied.
	_, err = client.ReadDir("/")
	if err == nil {
		t.Error("expected list to be denied for write-only user, got nil error")
	}
}

// TestServer_AddRemoveUser verifies that AddUser and RemoveUser take effect for
// new login attempts without restarting the server.
func TestServer_AddRemoveUser(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	// Before AddUser: connection must fail.
	sshCfg := &ssh.ClientConfig{
		User:            "dynamic",
		Auth:            []ssh.AuthMethod{ssh.Password("dynpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure before AddUser, got nil")
	}

	// AddUser: now the user should be able to connect.
	srv.AddUser("dynamic", UserInfo{Password: "dynpw", Root: root, CanRead: true, CanWrite: true})
	_ = dialSFTP(t, addr, "dynamic", "dynpw")

	// RemoveUser: subsequent logins must fail.
	srv.RemoveUser("dynamic")
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure after RemoveUser, got nil")
	}
}

// TestServer_AddUser_Replace verifies that AddUser replaces an existing user's info.
func TestServer_AddUser_Replace(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"user1": {Password: "oldpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	// Old password works.
	_ = dialSFTP(t, addr, "user1", "oldpw")

	// Replace with new password.
	srv.AddUser("user1", UserInfo{Password: "newpw", Root: root, CanRead: true, CanWrite: true})

	// Old password must now fail.
	sshCfg := &ssh.ClientConfig{
		User:            "user1",
		Auth:            []ssh.AuthMethod{ssh.Password("oldpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected old password to fail after AddUser replace, got nil")
	}

	// New password must work.
	_ = dialSFTP(t, addr, "user1", "newpw")
}

func TestServer_AddUser_ClonesAuthorizedKeys(t *testing.T) {
	root := t.TempDir()
	_, pubKey1 := testClientKey(t)
	_, pubKey2 := testClientKey(t)
	keys := make([]ssh.PublicKey, 1, 2)
	keys[0] = pubKey1

	srv := newTestServer(":0", "", "", map[string]UserInfo{}, testSigner(t), defaultCompletedUploadsSize)
	srv.AddUser("alice", UserInfo{
		Password:       "pw",
		AuthorizedKeys: keys,
		Root:           root,
		CanRead:        true,
	})

	keys[0] = pubKey2
	keys[:2][1] = pubKey2

	srv.mu.RLock()
	got := srv.users["alice"]
	srv.mu.RUnlock()

	if len(got.AuthorizedKeys) != 1 {
		t.Fatalf("AuthorizedKeys length = %d; want 1", len(got.AuthorizedKeys))
	}
	if !bytes.Equal(got.AuthorizedKeys[0].Marshal(), pubKey1.Marshal()) {
		t.Fatal("server stored AuthorizedKeys slice aliases caller-owned storage")
	}
}

// TestServer_RemoveAllUsers verifies that RemoveAllUsers blocks future logins
// without deleting any on-disk data in the users' roots.
func TestServer_RemoveAllUsers(t *testing.T) {
	root1 := t.TempDir()
	root2 := t.TempDir()
	file1 := filepath.Join(root1, "keep.txt")
	file2 := filepath.Join(root2, "keep.txt")
	if err := os.WriteFile(file1, []byte("alice data"), 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", file1, err)
	}
	if err := os.WriteFile(file2, []byte("bob data"), 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", file2, err)
	}

	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root1, CanRead: true, CanWrite: true},
		"bob":   {Password: "bobpw", Root: root2, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	_ = dialSFTP(t, addr, "alice", "alicepw")
	_ = dialSFTP(t, addr, "bob", "bobpw")

	srv.RemoveAllUsers()

	srv.mu.RLock()
	n := len(srv.users)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("expected no users after RemoveAllUsers, got %d", n)
	}

	for username, password := range map[string]string{"alice": "alicepw", "bob": "bobpw"} {
		sshCfg := &ssh.ClientConfig{
			User:            username,
			Auth:            []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
			t.Fatalf("expected auth failure for %q after RemoveAllUsers, got nil", username)
		}
	}

	if _, err := os.Stat(file1); err != nil {
		t.Fatalf("Stat(%q): %v", file1, err)
	}
	if _, err := os.Stat(file2); err != nil {
		t.Fatalf("Stat(%q): %v", file2, err)
	}
}

// TestNewSignerFromFile verifies that NewSignerFromFile loads a valid PEM key file
// and returns a usable signer, and that it returns an error for invalid inputs.
func TestNewSignerFromFile(t *testing.T) {
	t.Run("RSA key file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "id_rsa")

		// Generate an RSA key and write it as PEM.
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		der := x509.MarshalPKCS1PrivateKey(priv)
		pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
			t.Fatal(err)
		}

		signer, err := NewSignerFromFile(keyPath)
		if err != nil {
			t.Fatalf("NewSignerFromFile: %v", err)
		}
		if signer == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("ECDSA key file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "id_ecdsa")

		// Generate an ECDSA key and write it as PEM.
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
			t.Fatal(err)
		}

		signer, err := NewSignerFromFile(keyPath)
		if err != nil {
			t.Fatalf("NewSignerFromFile: %v", err)
		}
		if signer == nil {
			t.Fatal("expected non-nil signer")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := NewSignerFromFile("/nonexistent/path/to/key.pem")
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("invalid PEM content", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "bad.pem")
		if err := os.WriteFile(keyPath, []byte("not a valid PEM file"), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := NewSignerFromFile(keyPath)
		if err == nil {
			t.Fatal("expected error for invalid PEM, got nil")
		}
	})
}

// TestSFTPServer_WithFileHostKey verifies that the server works end-to-end when
// started with a host key loaded from a file via NewSignerFromFile.
func TestSFTPServer_WithFileHostKey(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()

	// Write a PEM-encoded RSA key file.
	keyPath := filepath.Join(dir, "host_key")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(priv)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(keyPath, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	signer, err := NewSignerFromFile(keyPath)
	if err != nil {
		t.Fatalf("NewSignerFromFile: %v", err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()

	srv := newTestServer(addr, "", "", users, signer, defaultCompletedUploadsSize)
	cfg := srv.sshServerConfig()

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(nc, cfg, srv.completedUploadsChan(), srv.tempExtensions(), srv.idleTimeout(), srv.allowChown())
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	client := dialSFTP(t, addr, "testuser", "testpw")
	content := []byte("key from file")
	f, err := client.Create("/hello.txt")
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	_ = f.Close()

	rf, err := client.Open("/hello.txt")
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

// TestSFTPServer_JailedWorkingDirectory verifies that a user's working directory
// appears as "/" even though it is backed by a subdirectory on disk.
// This is the jail/chroot behaviour: Alice logs in and sees "/" as her root,
// but on disk that "/" is mounted to her actual home directory.
func TestSFTPServer_JailedWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "alice", "alicepw")

	// The initial working directory must appear as "/" to the client.
	wd, err := client.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if wd != "/" {
		t.Errorf("Getwd() = %q; want / (user must see / as their root, not the on-disk path)", wd)
	}

	// Files in the jail root must be reachable via "/filename", not via the
	// real on-disk path.
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("ReadDir(/) = %v; want [file.txt]", names)
	}

	// The on-disk path must NOT be accessible as an SFTP path; it resolves
	// to a non-existent location inside the jail.
	_, err = client.ReadDir(root)
	if err == nil {
		t.Error("expected error when accessing the real on-disk path via SFTP, got nil")
	}
}

// TestSFTPServer_CompletedUploadsQueue verifies that after a file upload finishes
// the server announces the SFTP path on the CompletedUploads channel.
func TestSFTPServer_CompletedUploadsQueue(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload two files and close each one to trigger the completion signal.
	for _, name := range []string{"/first.txt", "/second.txt"} {
		f, err := client.Create(name)
		if err != nil {
			t.Fatalf("client.Create(%q): %v", name, err)
		}
		if _, err = f.Write([]byte("data")); err != nil {
			t.Fatalf("f.Write: %v", err)
		}
		if err = f.Close(); err != nil {
			t.Fatalf("f.Close: %v", err)
		}

		select {
		case got := <-srv.CompletedUploads():
			if got.FilePath != name {
				t.Errorf("CompletedUploads received FilePath %q; want %q", got.FilePath, name)
			}
			if got.Username != "testuser" {
				t.Errorf("CompletedUploads Username = %q; want %q", got.Username, "testuser")
			}
			wantFull := filepath.Join(root, name)
			if got.FullFilePath != wantFull {
				t.Errorf("CompletedUploads FullFilePath = %q; want %q", got.FullFilePath, wantFull)
			}
			if got.ClientIP == "" {
				t.Errorf("CompletedUploads ClientIP is empty; want non-empty")
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for CompletedUploads signal for %q", name)
		}
	}
}

// TestSFTPServer_MkdirNoParent verifies that creating a directory whose parent
// does not yet exist returns an error instead of silently creating all
// intermediate directories (os.Mkdir semantics, not os.MkdirAll).
func TestSFTPServer_MkdirNoParent(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// "/nonexistent/child" should fail because "/nonexistent" doesn't exist.
	if err := client.Mkdir("/nonexistent/child"); err == nil {
		t.Error("expected error when creating directory with missing parent, got nil")
	}
}

// TestSFTPServer_UploadFilePermissions verifies that files created via SFTP
// are owner-readable/writable only (mode 0600), not group-readable.
func TestSFTPServer_UploadFilePermissions(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.Create("/secret.txt")
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write([]byte("sensitive")); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	_ = f.Close()

	info, err := os.Stat(filepath.Join(root, "secret.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	// Mask to the permission bits only and verify owner-only access (0600).
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("file permissions = %04o; want 0600", got)
	}
}

func TestSFTPServer_OpenFileAppendHonorsAppendFlag(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "append.txt"), []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.OpenFile("/append.txt", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatalf("OpenFile(O_APPEND): %v", err)
	}
	if _, err := f.Write([]byte(" second")); err != nil {
		_ = f.Close()
		t.Fatalf("Write append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close append: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "append.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first second" {
		t.Fatalf("append.txt = %q; want %q", got, "first second")
	}
}

func TestSFTPServer_OpenFileWriteOnlyDoesNotTruncate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "plain.txt"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.OpenFile("/plain.txt", os.O_WRONLY)
	if err != nil {
		t.Fatalf("OpenFile(O_WRONLY): %v", err)
	}
	if _, err := f.Write([]byte("XY")); err != nil {
		_ = f.Close()
		t.Fatalf("Write plain: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close plain: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "plain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "XYiginal" {
		t.Fatalf("plain.txt = %q; want %q", got, "XYiginal")
	}
}

func TestSFTPServer_OpenFileExclusiveCreateHonorsExcl(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "exists.txt"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	if f, err := client.OpenFile("/exists.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL); err == nil {
		_ = f.Close()
		t.Fatal("OpenFile(O_CREATE|O_EXCL) on existing file succeeded; want error")
	}
	got, err := os.ReadFile(filepath.Join(root, "exists.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("exists.txt = %q; want %q", got, "keep")
	}

	f, err := client.OpenFile("/new.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatalf("OpenFile(O_CREATE|O_EXCL) on missing file: %v", err)
	}
	if _, err := f.Write([]byte("new")); err != nil {
		_ = f.Close()
		t.Fatalf("Write new: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close new: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(root, "new.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("new.txt = %q; want %q", got, "new")
	}
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

// TestSFTPServer_PublicKeyAuth verifies that a user configured with an
// AuthorizedKeys entry can authenticate using the matching private key and
// perform full read/write SFTP operations.
func TestSFTPServer_PublicKeyAuth(t *testing.T) {
	root := t.TempDir()
	clientSigner, clientPubKey := testClientKey(t)

	users := map[string]UserInfo{
		"keyuser": {
			AuthorizedKeys: []ssh.PublicKey{clientPubKey},
			Root:           root,
			CanRead:        true,
			CanWrite:       true,
		},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTPWithPublicKey(t, addr, "keyuser", clientSigner)

	// Upload a file to verify write access.
	content := []byte("public key auth test")
	f, err := client.Create("/pubkey.txt")
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	_ = f.Close()

	// Download and verify the content.
	rf, err := client.Open("/pubkey.txt")
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

// TestSFTPServer_PublicKeyAuth_InvalidKey verifies that a key not listed in a
// user's AuthorizedKeys is rejected.
func TestSFTPServer_PublicKeyAuth_InvalidKey(t *testing.T) {
	root := t.TempDir()
	_, authorizedKey := testClientKey(t)
	wrongSigner, _ := testClientKey(t)
	users := map[string]UserInfo{
		"keyuser": {
			AuthorizedKeys: []ssh.PublicKey{authorizedKey},
			Root:           root,
			CanRead:        true,
			CanWrite:       true,
		},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "keyuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(wrongSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected authentication error with wrong key, got nil")
	}
}

func TestCanonicalJailRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	missingPath := filepath.Join(t.TempDir(), "missing")

	tests := []struct {
		name    string
		root    string
		want    string
		wantErr error
	}{
		{name: "empty", root: "", wantErr: os.ErrInvalid},
		{name: "whitespace", root: " \t ", wantErr: os.ErrInvalid},
		{name: "missing", root: missingPath, wantErr: os.ErrNotExist},
		{name: "file", root: filePath, wantErr: syscall.ENOTDIR},
		{name: "symlink", root: link, want: target},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalJailRoot(tc.root)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("canonicalJailRoot(%q) error = %v; want %v", tc.root, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalJailRoot(%q): %v", tc.root, err)
			}
			if got != tc.want {
				t.Fatalf("canonicalJailRoot(%q) = %q; want %q", tc.root, got, tc.want)
			}
		})
	}
}

func TestSFTPServer_PasswordAuth_ValidatesJailRoot(t *testing.T) {
	target := t.TempDir()
	filePath := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	tests := []struct {
		name string
		root string
		want string
	}{
		{name: "empty", root: ""},
		{name: "whitespace", root: "  "},
		{name: "file", root: filePath},
		{name: "missing", root: filepath.Join(t.TempDir(), "missing")},
		{name: "directory", root: target, want: target},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(":0", "", "", map[string]UserInfo{
				"alice": {Password: "alicepw", Root: tc.root, CanRead: true, CanWrite: true},
			}, testSigner(t), defaultCompletedUploadsSize)
			cfg := srv.sshServerConfig()

			perms, err := cfg.PasswordCallback(testConnMetadata{user: "alice"}, []byte("alicepw"))
			if tc.want == "" {
				if err == nil {
					t.Fatalf("PasswordCallback returned nil error with permissions %+v", perms)
				}
				return
			}
			if err != nil {
				t.Fatalf("PasswordCallback: %v", err)
			}
			if actualJailRoot := perms.Extensions["jailRoot"]; actualJailRoot != tc.want {
				t.Fatalf("permissions jailRoot = %q; want %q", actualJailRoot, tc.want)
			}
		})
	}

	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}
	srv := newTestServer(":0", "", "", map[string]UserInfo{
		"alice": {Password: "alicepw", Root: link, CanRead: true, CanWrite: true},
	}, testSigner(t), defaultCompletedUploadsSize)
	cfg := srv.sshServerConfig()
	perms, err := cfg.PasswordCallback(testConnMetadata{user: "alice"}, []byte("alicepw"))
	if err != nil {
		t.Fatalf("PasswordCallback: %v", err)
	}
	if actualJailRoot := perms.Extensions["jailRoot"]; actualJailRoot != target {
		t.Fatalf("permissions jailRoot = %q; want %q", actualJailRoot, target)
	}
}

func TestSFTPServer_PublicKeyAuth_RejectsInvalidJailRoot(t *testing.T) {
	_, clientPubKey := testClientKey(t)
	filePath := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	tests := []struct {
		name string
		root string
	}{
		{name: "empty", root: ""},
		{name: "whitespace", root: "  "},
		{name: "file", root: filePath},
		{name: "missing", root: filepath.Join(t.TempDir(), "missing")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(":0", "", "", map[string]UserInfo{
				"alice": {AuthorizedKeys: []ssh.PublicKey{clientPubKey}, Root: tc.root, CanRead: true, CanWrite: true},
			}, testSigner(t), defaultCompletedUploadsSize)
			cfg := srv.sshServerConfig()

			perms, err := cfg.PublicKeyCallback(testConnMetadata{user: "alice"}, clientPubKey)
			if err == nil {
				t.Fatalf("PublicKeyCallback returned nil error with permissions %+v", perms)
			}
		})
	}
}

func TestNewServer_ClonesUsersMapAndAuthorizedKeys(t *testing.T) {
	root := t.TempDir()
	_, pubKey1 := testClientKey(t)
	_, pubKey2 := testClientKey(t)
	keys := make([]ssh.PublicKey, 1, 2)
	keys[0] = pubKey1
	users := map[string]UserInfo{
		"alice": {
			Password:       "pw1",
			AuthorizedKeys: keys,
			Root:           root,
			CanRead:        true,
		},
	}

	srv := newTestServer(":0", "", "", users, testSigner(t), defaultCompletedUploadsSize)

	users["alice"] = UserInfo{Password: "pw2", Root: root}
	delete(users, "alice")
	keys[0] = pubKey2
	keys[:2][1] = pubKey2

	srv.mu.RLock()
	got, ok := srv.users["alice"]
	srv.mu.RUnlock()

	if !ok {
		t.Fatal("server user map aliases caller-owned map")
	}
	if got.Password != "pw1" {
		t.Fatalf("stored password = %q; want %q", got.Password, "pw1")
	}
	if len(got.AuthorizedKeys) != 1 {
		t.Fatalf("AuthorizedKeys length = %d; want 1", len(got.AuthorizedKeys))
	}
	if !bytes.Equal(got.AuthorizedKeys[0].Marshal(), pubKey1.Marshal()) {
		t.Fatal("server AuthorizedKeys slice aliases caller-owned storage")
	}
}

// TestServer_AddUserKey verifies that AddUserKey grants a new key authentication
// access for an existing user without disturbing the existing password or other
// fields.
func TestServer_AddUserKey(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	// Before AddUserKey: public-key auth must fail (no keys registered).
	newSigner, newPubKey := testClientKey(t)
	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(newSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure before AddUserKey, got nil")
	}

	// AddUserKey: public-key auth must now succeed.
	srv.AddUserKey("alice", newPubKey)
	_ = dialSFTPWithPublicKey(t, addr, "alice", newSigner)

	// Password auth must still work.
	_ = dialSFTP(t, addr, "alice", "alicepw")
}

// TestServer_RemoveUserKey verifies that RemoveUserKey revokes a specific key
// while leaving any other keys (and password auth) intact.
func TestServer_RemoveUserKey(t *testing.T) {
	root := t.TempDir()
	signer1, pubKey1 := testClientKey(t)
	signer2, pubKey2 := testClientKey(t)

	users := map[string]UserInfo{
		"bob": {
			Password:       "bobpw",
			AuthorizedKeys: []ssh.PublicKey{pubKey1, pubKey2},
			Root:           root,
			CanRead:        true,
			CanWrite:       true,
		},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	// Both keys work initially.
	_ = dialSFTPWithPublicKey(t, addr, "bob", signer1)
	_ = dialSFTPWithPublicKey(t, addr, "bob", signer2)

	// Remove key1 only.
	srv.RemoveUserKey("bob", pubKey1)

	// key1 must now be rejected.
	sshCfg := &ssh.ClientConfig{
		User:            "bob",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer1)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure for removed key, got nil")
	}

	// key2 must still work.
	_ = dialSFTPWithPublicKey(t, addr, "bob", signer2)

	// Password auth must still work.
	_ = dialSFTP(t, addr, "bob", "bobpw")
}

// TestServer_AddUserKey_NoDuplicate verifies that AddUserKey does not store the
// same key more than once when called multiple times with identical keys.
func TestServer_AddUserKey_NoDuplicate(t *testing.T) {
	root := t.TempDir()
	_, pubKey := testClientKey(t)

	srv := newTestServer(":0", "", "", map[string]UserInfo{
		"carol": {Root: root, CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)

	srv.AddUserKey("carol", pubKey)
	srv.AddUserKey("carol", pubKey)
	srv.AddUserKey("carol", pubKey)

	srv.mu.RLock()
	n := len(srv.users["carol"].AuthorizedKeys)
	srv.mu.RUnlock()

	if n != 1 {
		t.Errorf("expected 1 authorized key after duplicate adds, got %d", n)
	}
}

// TestServer_AddRemoveUserKey_NonExistentUser verifies that calling AddUserKey
// or RemoveUserKey for a user that does not exist is a safe no-op.
func TestServer_AddRemoveUserKey_NonExistentUser(t *testing.T) {
	srv := newTestServer(":0", "", "", map[string]UserInfo{}, testSigner(t), defaultCompletedUploadsSize)
	_, pub := testClientKey(t)

	// Neither call should panic or create phantom entries.
	srv.AddUserKey("ghost", pub)
	srv.RemoveUserKey("ghost", pub)

	srv.mu.RLock()
	_, exists := srv.users["ghost"]
	srv.mu.RUnlock()

	if exists {
		t.Error("AddUserKey created a user entry for a non-existent user")
	}
}

// TestServer_NilKeyInAuthorizedKeys verifies that the server does not panic
// when AuthorizedKeys contains a nil entry. The nil entry must be skipped, and
// a subsequent valid key in the same slice must still be accepted.
func TestServer_NilKeyInAuthorizedKeys(t *testing.T) {
	root := t.TempDir()
	validSigner, validPubKey := testClientKey(t)

	users := map[string]UserInfo{
		"dave": {
			// AuthorizedKeys intentionally contains a nil entry before the
			// valid key to trigger the panic-prone code path.
			AuthorizedKeys: []ssh.PublicKey{nil, validPubKey},
			Root:           root,
			CanRead:        true,
			CanWrite:       true,
		},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	// Must not panic; valid key after the nil entry must authenticate.
	client := dialSFTPWithPublicKey(t, addr, "dave", validSigner)
	_ = client
}

// TestServer_AddUserKey_NilKey verifies that passing nil to AddUserKey is a
// safe no-op and does not panic or corrupt the AuthorizedKeys slice.
func TestServer_AddUserKey_NilKey(t *testing.T) {
	root := t.TempDir()
	_, pub := testClientKey(t)
	srv := newTestServer(":0", "", "", map[string]UserInfo{
		"eve": {AuthorizedKeys: []ssh.PublicKey{pub}, Root: root, CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)

	srv.AddUserKey("eve", nil) // must not panic

	srv.mu.RLock()
	n := len(srv.users["eve"].AuthorizedKeys)
	srv.mu.RUnlock()

	if n != 1 {
		t.Errorf("AddUserKey(nil) changed AuthorizedKeys length to %d; want 1", n)
	}
}

// TestServer_RemoveUserKey_NilEntry verifies that RemoveUserKey does not panic
// when AuthorizedKeys contains nil entries and correctly removes the target key.
func TestServer_RemoveUserKey_NilEntry(t *testing.T) {
	root := t.TempDir()
	_, pub := testClientKey(t)
	srv := newTestServer(":0", "", "", map[string]UserInfo{
		"frank": {
			// Mix nil entries with a real key.
			AuthorizedKeys: []ssh.PublicKey{nil, pub, nil},
			Root:           root,
			CanRead:        true,
		},
	}, testSigner(t), defaultCompletedUploadsSize)

	srv.RemoveUserKey("frank", pub) // must not panic

	srv.mu.RLock()
	keys := srv.users["frank"].AuthorizedKeys
	srv.mu.RUnlock()

	for _, k := range keys {
		if k == nil {
			continue
		}
		t.Error("RemoveUserKey left the real key in AuthorizedKeys")
	}
}

// TestServer_RemoveUserKey_NilKey verifies that passing nil to RemoveUserKey is
// a safe no-op and does not modify AuthorizedKeys.
func TestServer_RemoveUserKey_NilKey(t *testing.T) {
	root := t.TempDir()
	_, pub := testClientKey(t)
	srv := newTestServer(":0", "", "", map[string]UserInfo{
		"grace": {AuthorizedKeys: []ssh.PublicKey{pub}, Root: root, CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)

	srv.RemoveUserKey("grace", nil) // must not panic

	srv.mu.RLock()
	n := len(srv.users["grace"].AuthorizedKeys)
	srv.mu.RUnlock()

	if n != 1 {
		t.Errorf("RemoveUserKey(nil) changed AuthorizedKeys length to %d; want 1", n)
	}
}

// TestSFTPServer_CreateFolder verifies that a directory can be successfully
// created via SFTP Mkdir, and that it is visible when listing the parent.
func TestSFTPServer_CreateFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	if err := client.Mkdir("/newdir"); err != nil {
		t.Fatalf("Mkdir(/newdir): %v", err)
	}

	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir(/): %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Name() == "newdir" && e.IsDir() {
			found = true
			break
		}
	}
	if !found {
		t.Error("created directory newdir not found in ReadDir(/)")
	}
}

// TestSFTPServer_CreateFileInFolder verifies that a file can be created inside
// a previously created subdirectory.
func TestSFTPServer_CreateFileInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	if err := client.Mkdir("/subdir"); err != nil {
		t.Fatalf("Mkdir(/subdir): %v", err)
	}

	content := []byte("file in subfolder")
	f, err := client.Create("/subdir/file.txt")
	if err != nil {
		t.Fatalf("Create(/subdir/file.txt): %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Verify by downloading.
	rf, err := client.Open("/subdir/file.txt")
	if err != nil {
		t.Fatalf("Open(/subdir/file.txt): %v", err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

// TestSFTPServer_RenameFile verifies that an uploaded file can be renamed via
// the SFTP Rename command, and that the new name is accessible while the old
// name is gone.
func TestSFTPServer_RenameFile(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	content := []byte("rename me")
	f, err := client.Create("/original.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Rename it.
	if err := client.Rename("/original.txt", "/renamed.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	// New name must be readable.
	rf, err := client.Open("/renamed.txt")
	if err != nil {
		t.Fatalf("Open(/renamed.txt): %v", err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}

	// Old name must no longer exist.
	if _, err := client.Stat("/original.txt"); err == nil {
		t.Error("expected error accessing old name after rename, got nil")
	}
}

// TestSFTPServer_MoveFileBetweenFolders verifies that a file can be moved from
// one existing subdirectory to another via Rename.
func TestSFTPServer_MoveFileBetweenFolders(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create source and destination directories.
	if err := client.Mkdir("/src"); err != nil {
		t.Fatalf("Mkdir(/src): %v", err)
	}
	if err := client.Mkdir("/dst"); err != nil {
		t.Fatalf("Mkdir(/dst): %v", err)
	}

	// Upload a file to the source directory.
	content := []byte("moving between folders")
	f, err := client.Create("/src/move.txt")
	if err != nil {
		t.Fatalf("Create(/src/move.txt): %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Move the file to the destination directory.
	if err := client.Rename("/src/move.txt", "/dst/move.txt"); err != nil {
		t.Fatalf("Rename (move between folders): %v", err)
	}

	// Verify the file is now at the destination.
	rf, err := client.Open("/dst/move.txt")
	if err != nil {
		t.Fatalf("Open(/dst/move.txt): %v", err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}

	// Source must no longer exist.
	if _, err := client.Stat("/src/move.txt"); err == nil {
		t.Error("expected error accessing source after move, got nil")
	}
}

// TestSFTPServer_DeleteFileInFolder verifies that a file inside a subdirectory
// can be deleted via SFTP Remove.
func TestSFTPServer_DeleteFileInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a folder and upload a file into it.
	if err := client.Mkdir("/folder"); err != nil {
		t.Fatalf("Mkdir(/folder): %v", err)
	}
	f, err := client.Create("/folder/todelete.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("delete me")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Delete the file.
	if err := client.Remove("/folder/todelete.txt"); err != nil {
		t.Fatalf("Remove(/folder/todelete.txt): %v", err)
	}

	// Verify the file is gone.
	if _, err := client.Stat("/folder/todelete.txt"); err == nil {
		t.Error("expected error accessing deleted file, got nil")
	}
}

// TestSFTPServer_MoveFileToNonExistentFolder verifies that renaming a file into
// a directory that does not exist returns an error.
func TestSFTPServer_MoveFileToNonExistentFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/existing.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("content")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Attempt to rename into a non-existent directory; must fail.
	err = client.Rename("/existing.txt", "/nosuchdir/existing.txt")
	if err == nil {
		t.Error("expected error when moving file to non-existent folder, got nil")
	}
}

// TestSFTPServer_Chmod verifies that a chmod (Setstat with permissions) is
// applied to the file on disk.
func TestSFTPServer_Chmod(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/chmod_test.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("chmod test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Send a chmod request and verify it was applied on disk.
	if err := client.Chmod("/chmod_test.txt", 0644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "chmod_test.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Errorf("file mode = %o; want 0644", got)
	}
}

// TestSFTPServer_Chown verifies that a chown (Setstat with uid/gid) request is
// accepted by the server. We chown to the current uid/gid so the call does
// not require elevated privileges; this exercises the server side without
// actually changing ownership on disk.
func TestSFTPServer_Chown(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users, func(s *server) { s.AllowChown = true })
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/chown_test.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("chown test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Retrieve the current owner so we can use valid uid/gid values.
	info, err := os.Stat(filepath.Join(root, "chown_test.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("cannot read uid/gid on this platform")
	}
	uid := int(stat.Uid)
	gid := int(stat.Gid)

	// Send chown with the same uid/gid; the server applies the chown and it
	// is a no-op on disk because the values are unchanged.
	if err := client.Chown("/chown_test.txt", uid, gid); err != nil {
		t.Fatalf("Chown: %v", err)
	}
}

// TestSFTPServer_Chgrp verifies that a chgrp (Setstat with a new gid) request
// is accepted by the server without error.
func TestSFTPServer_Chgrp(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users, func(s *server) { s.AllowChown = true })
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/chgrp_test.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("chgrp test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Retrieve the current owner/group so we can pass valid identifiers.
	info, err := os.Stat(filepath.Join(root, "chgrp_test.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("cannot read uid/gid on this platform")
	}
	uid := int(stat.Uid)
	gid := int(stat.Gid)

	// Chown with uid unchanged and gid unchanged acts as chgrp; the server
	// applies the change and it is a no-op on disk because the values match.
	if err := client.Chown("/chgrp_test.txt", uid, gid); err != nil {
		t.Fatalf("Chown (chgrp): %v", err)
	}
}

// TestSFTPServer_CreateFolderInFolder verifies that a subdirectory can be
// created inside an existing parent directory, and that it appears correctly
// when listing the parent's contents.
func TestSFTPServer_CreateFolderInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create the parent directory.
	if err := client.Mkdir("/parent"); err != nil {
		t.Fatalf("Mkdir(/parent): %v", err)
	}

	// Create a child directory inside the parent.
	if err := client.Mkdir("/parent/child"); err != nil {
		t.Fatalf("Mkdir(/parent/child): %v", err)
	}

	// Verify the child appears when listing the parent.
	entries, err := client.ReadDir("/parent")
	if err != nil {
		t.Fatalf("ReadDir(/parent): %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Name() == "child" && e.IsDir() {
			found = true
			break
		}
	}
	if !found {
		t.Error("child directory not found in ReadDir(/parent)")
	}
}

// TestSFTPServer_DeleteFolder verifies that an empty directory can be removed
// via SFTP RemoveDirectory and that it disappears from the listing afterwards.
func TestSFTPServer_DeleteFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create an empty directory.
	if err := client.Mkdir("/emptydir"); err != nil {
		t.Fatalf("Mkdir(/emptydir): %v", err)
	}

	// Remove it.
	if err := client.RemoveDirectory("/emptydir"); err != nil {
		t.Fatalf("RemoveDirectory(/emptydir): %v", err)
	}

	// Verify it is gone.
	if _, err := client.Stat("/emptydir"); err == nil {
		t.Error("expected error accessing removed directory, got nil")
	}
}

// TestSFTPServer_DeleteFolderInFolder verifies that a nested empty directory
// can be removed while leaving the parent directory intact.
func TestSFTPServer_DeleteFolderInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create parent and nested child directories.
	if err := client.Mkdir("/outer"); err != nil {
		t.Fatalf("Mkdir(/outer): %v", err)
	}
	if err := client.Mkdir("/outer/inner"); err != nil {
		t.Fatalf("Mkdir(/outer/inner): %v", err)
	}

	// Remove the inner (nested) directory.
	if err := client.RemoveDirectory("/outer/inner"); err != nil {
		t.Fatalf("RemoveDirectory(/outer/inner): %v", err)
	}

	// The inner directory must be gone.
	if _, err := client.Stat("/outer/inner"); err == nil {
		t.Error("expected error accessing removed nested directory, got nil")
	}

	// The outer (parent) directory must still exist.
	if _, err := client.Stat("/outer"); err != nil {
		t.Fatalf("parent directory /outer should still exist: %v", err)
	}
}

// TestSFTPServer_DeleteFolderWithFoldersInside verifies that removing a
// directory that still contains subdirectories returns an error (the server
// uses os.Remove semantics which refuses non-empty directories).
func TestSFTPServer_DeleteFolderWithFoldersInside(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a parent directory with a subdirectory inside.
	if err := client.Mkdir("/nonempty"); err != nil {
		t.Fatalf("Mkdir(/nonempty): %v", err)
	}
	if err := client.Mkdir("/nonempty/subdir"); err != nil {
		t.Fatalf("Mkdir(/nonempty/subdir): %v", err)
	}

	// Attempt to remove the non-empty parent; must fail.
	if err := client.RemoveDirectory("/nonempty"); err == nil {
		t.Error("expected error when removing non-empty directory (contains subdirs), got nil")
	}

	// Parent must still be present.
	if _, err := client.Stat("/nonempty"); err != nil {
		t.Fatalf("non-empty directory /nonempty should still exist after failed removal: %v", err)
	}
}

// TestServer_ListenAndServe_Close verifies that calling Close on a running
// server causes ListenAndServe to return nil, and that a subsequent connection
// attempt fails because the listener is closed.
func TestServer_ListenAndServe_Close(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	signer := testSigner(t)

	srv := newTestServer("127.0.0.1:0", "", "", users, signer, defaultCompletedUploadsSize)

	errc := make(chan error, 1)
	go func() {
		errc <- srv.ListenAndServe()
	}()

	// Wait until the server is accepting connections.
	var addr string
	for i := 0; i < 50; i++ {
		if a := srv.ListeningAddr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not start in time")
	}

	// Verify the server is reachable before Close.
	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial before Close: %v", err)
	}
	_ = conn.Close()

	// Close the server; ListenAndServe must return nil.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Close")
	}

	// Subsequent connection attempts must fail.
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Error("expected error connecting after Close, got nil")
	}
}

// TestServer_Close_BeforeListenAndServe verifies that calling Close before
// ListenAndServe is a safe no-op and does not panic or return an error.
func TestServer_Close_BeforeListenAndServe(t *testing.T) {
	srv := newTestServer(":0", "", "", map[string]UserInfo{}, testSigner(t), defaultCompletedUploadsSize)
	if err := srv.Close(); err != nil {
		t.Errorf("Close before ListenAndServe returned %v; want nil", err)
	}
}

// startListenAndServe boots a server via ListenAndServe on
// 127.0.0.1:0 and returns it once it is accepting. The caller must drain
// errCh and call Shutdown/Close to stop the server.
func startListenAndServe(t *testing.T, users map[string]UserInfo) (srv *server, addr string, errCh chan error) {
	t.Helper()
	srv = newTestServer("127.0.0.1:0", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	errCh = make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.ListeningAddr(); a != nil {
			return srv, a.String(), errCh
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
	return nil, "", nil
}

// TestServer_Shutdown_DrainsInFlight verifies that Shutdown waits for an
// authenticated client session to finish before returning.
func TestServer_Shutdown_DrainsInFlight(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	srv, addr, errCh := startListenAndServe(t, users)

	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()

	// Shutdown must not return while the client is still connected.
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before client closed: err=%v", err)
	case <-time.After(150 * time.Millisecond):
	}

	// New dials must be refused even though Shutdown is still draining.
	if _, dialErr := ssh.Dial("tcp", addr, sshCfg); dialErr == nil {
		t.Error("expected dial to fail after Shutdown closed the listener")
	}

	// Close the active client; Shutdown should finish soon after.
	_ = client.Close()
	_ = conn.Close()

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown returned %v; want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after client closed")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
}

// TestServer_Shutdown_ForceClosesOnContextDeadline verifies that when the
// supplied context expires before in-flight handlers finish, Shutdown
// force-closes the lingering connections and returns ctx.Err().
func TestServer_Shutdown_ForceClosesOnContextDeadline(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	srv, addr, errCh := startListenAndServe(t, users)

	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = srv.Shutdown(ctx)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err = %v; want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Shutdown took %v; expected to return promptly after force-close", elapsed)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown deadline")
	}

	// The forcibly-closed SSH connection's session loop should observe the
	// read error and finish; a subsequent read on the client side fails.
	if _, _, err := conn.SendRequest("noop", true, nil); err == nil {
		t.Error("expected error sending request on force-closed conn, got nil")
	}
}

// TestServer_Shutdown_BeforeListenAndServe is a no-op and must not block.
func TestServer_Shutdown_BeforeListenAndServe(t *testing.T) {
	srv := newTestServer(":0", "", "", map[string]UserInfo{}, testSigner(t), defaultCompletedUploadsSize)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown before ListenAndServe returned %v; want nil", err)
	}
}

// TestServer_ListenAndServe_AfterShutdown verifies that once a server has been
// shut down it cannot be restarted; ListenAndServe returns a sentinel error
// instead of silently spinning a refusing accept loop.
func TestServer_ListenAndServe_AfterShutdown(t *testing.T) {
	srv := newTestServer("127.0.0.1:0", "", "", map[string]UserInfo{}, testSigner(t), defaultCompletedUploadsSize)
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	err := srv.ListenAndServe()
	if err == nil {
		t.Fatal("expected ListenAndServe to fail after Shutdown")
	}
	if want := "ironport: server has been shut down"; err.Error() != want {
		t.Errorf("got %q; want %q", err.Error(), want)
	}
}

// TestServer_ListenAndServe_EmptyAddr verifies that ListenAndServe returns an
// error immediately when Addr is empty or blank without opening any listener.
func TestServer_ListenAndServe_EmptyAddr(t *testing.T) {
	for _, addr := range []string{"", "   ", "\t"} {
		srv := &server{Addr: addr, signer: testSigner(t)}
		err := srv.ListenAndServe()
		if err == nil {
			t.Errorf("addr=%q: expected error, got nil", addr)
			continue
		}
		const want = "ironport: Addr is required"
		if err.Error() != want {
			t.Errorf("addr=%q: got %q; want %q", addr, err.Error(), want)
		}
	}
}

// TestServer_ListenAndServe_NilSigner verifies that ListenAndServe returns an
// error immediately when signer is nil without opening any listener.
func TestServer_ListenAndServe_NilSigner(t *testing.T) {
	srv := &server{Addr: ":0"}
	err := srv.ListenAndServe()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	const want = "ironport: signer is required"
	if err.Error() != want {
		t.Errorf("got %q; want %q", err.Error(), want)
	}
}

// TestSFTPServer_DeleteFolderWithFilesInside verifies that removing a
// directory that still contains files returns an error.
func TestSFTPServer_DeleteFolderWithFilesInside(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a directory and put a file inside.
	if err := client.Mkdir("/hasfiles"); err != nil {
		t.Fatalf("Mkdir(/hasfiles): %v", err)
	}
	f, err := client.Create("/hasfiles/content.txt")
	if err != nil {
		t.Fatalf("Create(/hasfiles/content.txt): %v", err)
	}
	if _, err = f.Write([]byte("data")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Attempt to remove the non-empty directory; must fail.
	if err := client.RemoveDirectory("/hasfiles"); err == nil {
		t.Error("expected error when removing non-empty directory (contains files), got nil")
	}

	// Directory and its contents must still be present.
	if _, err := client.Stat("/hasfiles"); err != nil {
		t.Fatalf("directory /hasfiles should still exist after failed removal: %v", err)
	}
	if _, err := client.Stat("/hasfiles/content.txt"); err != nil {
		t.Fatalf("file /hasfiles/content.txt should still exist after failed removal: %v", err)
	}
}

// TestSFTPServer_PasswordAuth_NonExistentUser verifies that authentication
// with a non-existent username returns an error (the timing side-channel fix
// must not break the rejection path).
func TestSFTPServer_PasswordAuth_NonExistentUser(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "nobody",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure for non-existent user, got nil")
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
			go handleConn(nc, cfg, srv.completedUploadsChan(), srv.tempExtensions(), srv.idleTimeout(), srv.allowChown())
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

func TestJailHandlersRecoverFromPanic(t *testing.T) {
	j := jail{
		username: "testuser",
		clientIP: "127.0.0.1",
		canRead:  true,
		canWrite: true,
		uploads:  make(chan CompletedUpload, 1),
	}

	if _, err := j.Fileread(sftp.NewRequest("Get", "/panic.txt")); !errors.Is(err, errSFTPRequestFailed) {
		t.Fatalf("Fileread panic recovery err = %v; want %v", err, errSFTPRequestFailed)
	}
	if _, err := j.Filelist(sftp.NewRequest("List", "/panic")); !errors.Is(err, errSFTPRequestFailed) {
		t.Fatalf("Filelist panic recovery err = %v; want %v", err, errSFTPRequestFailed)
	}
	if err := j.Filecmd(sftp.NewRequest("Mkdir", "/panic")); !errors.Is(err, errSFTPRequestFailed) {
		t.Fatalf("Filecmd panic recovery err = %v; want %v", err, errSFTPRequestFailed)
	}
}

func TestSFTPReturnedObjectsRecoverFromPanic(t *testing.T) {
	w := &writeLogger{
		filepath: "/panic.txt",
		username: "testuser",
		clientIP: "127.0.0.1",
	}

	if _, err := w.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("WriteAt with nil file returned nil error")
	}
	if err := w.Close(); err == nil {
		t.Fatal("Close with nil file returned nil error")
	}
	if _, err := (fileInfoLister{}).ListAt(make([]os.FileInfo, 1), -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("ListAt negative offset err = %v; want %v", err, os.ErrInvalid)
	}
}

// ---- TempExtensions tests ----

// TestHasTempExt covers the case-insensitive matching of temp extensions.
func TestHasTempExt(t *testing.T) {
	exts := []string{".tmp", ".writing"}
	cases := []struct {
		name string
		want bool
	}{
		{"foo.tmp", true},
		{"foo.TMP", true},
		{"path/to/foo.writing", true},
		{"foo.txt", false},
		{"foo.tmp.bak", false},
		{"", false},
	}
	for _, c := range cases {
		if got := hasTempExt(c.name, exts); got != c.want {
			t.Errorf("hasTempExt(%q) = %v; want %v", c.name, got, c.want)
		}
	}
	// Nil ext list never matches.
	if hasTempExt("foo.tmp", nil) {
		t.Error("hasTempExt with nil exts should return false")
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

// TestServer_TempExtensionsNormalisation verifies that TempExtensions are
// normalised (lower-cased, dot-prefixed, empty entries stripped) before use.
func TestServer_TempExtensionsNormalisation(t *testing.T) {
	srv := &server{TempExtensions: []string{"TMP", ".Writing", "  ", ".part"}}
	got := srv.tempExtensions()
	want := []string{".tmp", ".writing", ".part"}
	if len(got) != len(want) {
		t.Fatalf("tempExtensions() = %v; want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("tempExtensions()[%d] = %q; want %q", i, got[i], w)
		}
	}
}

// TestSFTPServer_TempExtensions_SuppressesUploadAndAnnouncesOnRename verifies
// the end-to-end flow: a file uploaded with a temp extension does NOT produce
// a CompletedUploads notification, and renaming it to its final name does.
func TestSFTPServer_TempExtensions_SuppressesUploadAndAnnouncesOnRename(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users, func(s *server) {
		s.TempExtensions = []string{".tmp", ".writing"}
	})
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file with a temp extension — must NOT be announced.
	tmpName := "/foo.txt.tmp"
	f, err := client.Create(tmpName)
	if err != nil {
		t.Fatalf("client.Create(%q): %v", tmpName, err)
	}
	if _, err = f.Write([]byte("hello")); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("f.Close: %v", err)
	}

	select {
	case got := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received %+v for a temp-extension upload; expected suppression", got)
	case <-time.After(300 * time.Millisecond):
		// expected: nothing
	}

	// Rename to final name — must announce the new path on CompletedUploads.
	finalName := "/foo.txt"
	if err := client.Rename(tmpName, finalName); err != nil {
		t.Fatalf("client.Rename(%q, %q): %v", tmpName, finalName, err)
	}

	select {
	case got := <-srv.CompletedUploads():
		if got.FilePath != finalName {
			t.Errorf("CompletedUploads FilePath = %q; want %q", got.FilePath, finalName)
		}
		if got.Username != "testuser" {
			t.Errorf("CompletedUploads Username = %q; want %q", got.Username, "testuser")
		}
		wantFull := filepath.Join(root, finalName)
		if got.FullFilePath != wantFull {
			t.Errorf("CompletedUploads FullFilePath = %q; want %q", got.FullFilePath, wantFull)
		}
		if got.ClientIP == "" {
			t.Errorf("CompletedUploads ClientIP is empty; want non-empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CompletedUploads signal for renamed file %q", finalName)
	}
}

// TestSFTPServer_TempExtensions_RenameBetweenTempNamesDoesNotAnnounce verifies
// that renaming a temp file to another temp name (e.g. .tmp -> .writing) does
// not produce a CompletedUploads notification.
func TestSFTPServer_TempExtensions_RenameBetweenTempNamesDoesNotAnnounce(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users, func(s *server) {
		s.TempExtensions = []string{".tmp", ".writing"}
	})
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload .tmp file (suppressed).
	if f, err := client.Create("/foo.tmp"); err != nil {
		t.Fatalf("create: %v", err)
	} else {
		_, _ = f.Write([]byte("x"))
		_ = f.Close()
	}
	// Rename .tmp -> .writing (still temp): no notification expected.
	if err := client.Rename("/foo.tmp", "/foo.writing"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	select {
	case got := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received %+v; expected no notification for temp->temp rename", got)
	case <-time.After(300 * time.Millisecond):
		// expected
	}
}

// TestSFTPServer_TempExtensions_PlainUploadStillAnnounced verifies that
// configuring TempExtensions does not break notifications for normal uploads.
func TestSFTPServer_TempExtensions_PlainUploadStillAnnounced(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users, func(s *server) {
		s.TempExtensions = []string{".tmp", ".writing"}
	})
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	name := "/plain.txt"
	f, err := client.Create(name)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, _ = f.Write([]byte("hi"))
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case got := <-srv.CompletedUploads():
		if got.FilePath != name {
			t.Errorf("CompletedUploads FilePath = %q; want %q", got.FilePath, name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CompletedUploads for plain upload")
	}
}

// TestSFTPServer_EmptyStoredPassword_Rejected verifies that a user whose
// stored Password is "" cannot authenticate by sending an empty password.
func TestSFTPServer_EmptyStoredPassword_Rejected(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"nopw": {Password: "", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "nopw",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure when both stored and supplied passwords are empty, got nil")
	}
}

// TestSFTPServer_EmptySuppliedPassword_Rejected verifies that an empty
// password supplied by the client is always rejected, even when the stored
// password is non-empty.
func TestSFTPServer_EmptySuppliedPassword_Rejected(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure for empty supplied password, got nil")
	}
}

// TestFTPServer_EmptyStoredPassword_Rejected verifies that FTP password auth
// rejects users with an empty stored password.
func TestFTPServer_EmptyStoredPassword_Rejected(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"nopw": {Password: "", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	c := dialFTP(t, addr)
	c.command(331, "USER nopw")
	c.command(530, "PASS ")
}

// TestFTPServer_EmptySuppliedPassword_Rejected verifies that FTP rejects an
// empty supplied password even when the stored password is non-empty.
func TestFTPServer_EmptySuppliedPassword_Rejected(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	c := dialFTP(t, addr)
	c.command(331, "USER alice")
	c.command(530, "PASS ")
}

func TestFTPSessionAuthenticate_ValidatesJailRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("os.Symlink: %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	tests := []struct {
		name string
		root string
		want bool
	}{
		{name: "empty", root: "", want: false},
		{name: "whitespace", root: "  ", want: false},
		{name: "file", root: filePath, want: false},
		{name: "missing", root: filepath.Join(t.TempDir(), "missing"), want: false},
		{name: "symlink", root: link, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := &ftpSession{
				server: &server{
					users: map[string]UserInfo{
						"alice": {Password: "alicepw", Root: tc.root, CanRead: true, CanWrite: true},
					},
				},
				username: "alice",
			}

			got := fs.authenticate("alicepw")
			if got != tc.want {
				t.Fatalf("authenticate() = %v; want %v", got, tc.want)
			}
			if tc.want && fs.user.Root != target {
				t.Fatalf("authenticated root = %q; want %q", fs.user.Root, target)
			}
		})
	}
}

// TestFTPServer_ControlLineTooLong verifies that an oversized FTP control
// line is rejected with a 500 reply and the connection is closed, so that a
// malicious client cannot grow per-connection memory without bound.
func TestFTPServer_ControlLineTooLong(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Drain the 220 greeting.
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send a single line larger than ftpMaxControlLineLen.
	huge := make([]byte, ftpMaxControlLineLen+128)
	for i := range huge {
		huge[i] = 'A'
	}
	huge[len(huge)-2] = '\r'
	huge[len(huge)-1] = '\n'
	if _, err := conn.Write(huge); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if !strings.HasPrefix(reply, "500 ") {
		t.Fatalf("expected 500 reply, got %q", reply)
	}
}

// TestFTPServer_ErrorMessagesSanitized verifies that error replies sent over
// the FTP control channel do not leak server-side filesystem paths.
func TestFTPServer_ErrorMessagesSanitized(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	c := dialFTP(t, addr)
	c.login("alice", "alicepw")
	msg := c.command(550, "SIZE /does-not-exist.txt")
	if strings.Contains(msg, root) {
		t.Errorf("error reply leaked server path %q: %q", root, msg)
	}
	if strings.Contains(strings.ToLower(msg), "no such") == false &&
		strings.Contains(strings.ToLower(msg), "request failed") == false {
		t.Errorf("unexpected error reply: %q", msg)
	}
}

// TestSFTPServer_Setstat_TruncateAndTimes verifies that Setstat applies size
// and modification time changes to the underlying file.
func TestSFTPServer_Setstat_TruncateAndTimes(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "alice", "alicepw")

	f, err := client.Create("/setstat.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write(bytes.Repeat([]byte{'x'}, 1024)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Truncate via Setstat.
	if err := client.Truncate("/setstat.txt", 16); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "setstat.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if info.Size() != 16 {
		t.Errorf("size = %d; want 16", info.Size())
	}

	// Chtimes via Setstat is rejected under the hardened "no symlinks /
	// fd-relative-only" policy: setting access/modification times on jailed
	// files is denied wholesale rather than silently succeeding via
	// path-based os.Chtimes.
	want := time.Unix(1_700_000_000, 0)
	if err := client.Chtimes("/setstat.txt", want, want); err == nil {
		t.Fatal("Chtimes succeeded; expected permission error under hardened policy")
	}
}

// TestSFTPServer_Setstat_PermissionDeniedForReadOnly verifies that Setstat is
// rejected when the user lacks write permission, rather than silently
// pretending to succeed.
func TestSFTPServer_Setstat_PermissionDeniedForReadOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ro.txt"), []byte("ro"), 0644); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"reader": {Password: "rpw", Root: root, CanRead: true, CanWrite: false},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "reader", "rpw")
	if err := client.Chmod("/ro.txt", 0600); err == nil {
		t.Fatal("expected permission error for Chmod by a read-only user, got nil")
	}
}

// TestServer_IdleTimeout verifies the resolution rules of server.idleTimeout.
func TestServer_IdleTimeout(t *testing.T) {
	s := &server{}
	if got := s.idleTimeout(); got != defaultSFTPIdleTimeout {
		t.Errorf("default idleTimeout = %v; want %v", got, defaultSFTPIdleTimeout)
	}
	s.IdleTimeout = 7 * time.Second
	if got := s.idleTimeout(); got != 7*time.Second {
		t.Errorf("custom idleTimeout = %v; want 7s", got)
	}
	s.IdleTimeout = -1
	if got := s.idleTimeout(); got != 0 {
		t.Errorf("negative idleTimeout = %v; want 0", got)
	}
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

	ic := &idleConn{Conn: c}
	ic.setReadTimeout(100 * time.Millisecond)
	buf := make([]byte, 1)
	start := time.Now()
	if _, err := ic.Read(buf); err == nil {
		t.Fatal("expected idle Read to fail with a deadline error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("idle Read took too long: %v", elapsed)
	}
}

// TestReadFTPControlLine_Normal verifies a normal CRLF-terminated line is
// returned including the trailing '\n'.
func TestReadFTPControlLine_Normal(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("USER alice\r\nPASS pw\r\n"))
	got, err := readFTPControlLine(r, ftpMaxControlLineLen)
	if err != nil {
		t.Fatalf("readFTPControlLine: %v", err)
	}
	if got != "USER alice\r\n" {
		t.Errorf("got %q; want %q", got, "USER alice\r\n")
	}
}

// TestReadFTPControlLine_TooLong verifies an oversized line returns
// errFTPLineTooLong after discarding the remainder of the line.
func TestReadFTPControlLine_TooLong(t *testing.T) {
	long := strings.Repeat("A", ftpMaxControlLineLen+50) + "\r\nNEXT\r\n"
	r := bufio.NewReader(strings.NewReader(long))
	if _, err := readFTPControlLine(r, ftpMaxControlLineLen); !errors.Is(err, errFTPLineTooLong) {
		t.Fatalf("err = %v; want errFTPLineTooLong", err)
	}
	// The reader should now be positioned at the start of the next line.
	next, err := readFTPControlLine(r, ftpMaxControlLineLen)
	if err != nil {
		t.Fatalf("readFTPControlLine (second): %v", err)
	}
	if next != "NEXT\r\n" {
		t.Errorf("next line = %q; want %q", next, "NEXT\r\n")
	}
}

// TestFTPErrMsg verifies that ftpErrMsg returns generic, path-free messages
// for the well-known error categories.
func TestFTPErrMsg(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "ok"},
		{os.ErrNotExist, "no such file or directory"},
		{os.ErrPermission, "permission denied"},
		{os.ErrExist, "file exists"},
		{syscall.ENOTEMPTY, "directory not empty"},
		{syscall.EISDIR, "is a directory"},
		{syscall.ENOTDIR, "not a directory"},
		{errFTPLineTooLong, "command line too long"},
		{errors.New("something with /etc/passwd in it"), "request failed"},
	}
	for _, tc := range cases {
		if got := ftpErrMsg(tc.err); got != tc.want {
			t.Errorf("ftpErrMsg(%v) = %q; want %q", tc.err, got, tc.want)
		}
	}
}

func TestSanitizeSFTPErr(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantIs  error
		wantMsg string
	}{
		{
			name:    "not exist path error",
			err:     &os.PathError{Op: "open", Path: "/srv/sftp/alice/missing.txt", Err: os.ErrNotExist},
			wantIs:  os.ErrNotExist,
			wantMsg: "file does not exist",
		},
		{
			name:    "permission path error",
			err:     &os.PathError{Op: "stat", Path: "/srv/sftp/alice/secret.txt", Err: os.ErrPermission},
			wantIs:  os.ErrPermission,
			wantMsg: "permission denied",
		},
		{
			name:    "not a directory",
			err:     &os.PathError{Op: "opendir", Path: "/srv/sftp/alice/file", Err: syscall.ENOTDIR},
			wantIs:  syscall.ENOTDIR,
			wantMsg: "not a directory",
		},
		{
			name:    "is a directory",
			err:     &os.PathError{Op: "open", Path: "/srv/sftp/alice/dir", Err: syscall.EISDIR},
			wantIs:  syscall.EISDIR,
			wantMsg: "is a directory",
		},
		{
			name:    "directory not empty",
			err:     &os.PathError{Op: "remove", Path: "/srv/sftp/alice/dir", Err: syscall.ENOTEMPTY},
			wantIs:  syscall.ENOTEMPTY,
			wantMsg: "directory not empty",
		},
		{
			name:    "unknown path error",
			err:     &os.PathError{Op: "open", Path: "/srv/sftp/alice/secret.txt", Err: syscall.EIO},
			wantIs:  errSFTPRequestFailed,
			wantMsg: "request failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeSFTPErr(tc.err)
			if !errors.Is(got, tc.wantIs) {
				t.Fatalf("sanitizeSFTPErr(%v) = %v; want errors.Is(..., %v)", tc.err, got, tc.wantIs)
			}
			if got.Error() != tc.wantMsg {
				t.Fatalf("sanitizeSFTPErr(%v) message = %q; want %q", tc.err, got.Error(), tc.wantMsg)
			}
			if strings.Contains(got.Error(), "/srv/sftp/alice") {
				t.Fatalf("sanitizeSFTPErr(%v) leaked path in message %q", tc.err, got.Error())
			}
		})
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

func TestFTPServer_CmdStorSanitizesCopyErrors(t *testing.T) {
	root := t.TempDir()
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatalf("openJailFS: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	copyErr := errors.New("copy failed while reading /srv/secret.txt")
	var control bytes.Buffer
	controlConn := &stubConn{}
	dataConn := &stubConn{readErr: copyErr}

	fs := &ftpSession{
		server: &server{
			completedUploads: make(chan CompletedUpload, 1),
		},
		conn:   controlConn,
		w:      bufio.NewWriter(&control),
		user:   UserInfo{Root: root, CanWrite: true},
		dataLn: &stubListener{conn: dataConn},
		fs:     jfs,
	}

	fs.cmdStor("upload.txt", false)

	got := control.String()
	if !strings.Contains(got, "426 "+ftpErrMsg(copyErr)+"\r\n") {
		t.Fatalf("cmdStor reply = %q; want sanitized FTP error reply", got)
	}
	if strings.Contains(got, "/srv/secret.txt") {
		t.Fatalf("cmdStor reply leaked internal path: %q", got)
	}
}

// TestNextAcceptBackoff verifies that the accept backoff schedule starts at
// 5ms, doubles, and caps at 1s.
func TestNextAcceptBackoff(t *testing.T) {
	if got := nextAcceptBackoff(0); got != 5*time.Millisecond {
		t.Errorf("nextAcceptBackoff(0) = %v; want 5ms", got)
	}
	if got := nextAcceptBackoff(5 * time.Millisecond); got != 10*time.Millisecond {
		t.Errorf("nextAcceptBackoff(5ms) = %v; want 10ms", got)
	}
	if got := nextAcceptBackoff(900 * time.Millisecond); got != time.Second {
		t.Errorf("nextAcceptBackoff(900ms) = %v; want 1s", got)
	}
	if got := nextAcceptBackoff(time.Second); got != time.Second {
		t.Errorf("nextAcceptBackoff(1s) = %v; want 1s", got)
	}
}

// TestSFTPServer_Chown_DefaultDenied verifies that a chown request is
// rejected with a permission error when server.AllowChown is left at its
// default (false). This is the opt-in flag that hardens deployments where
// the server runs with enough privilege (e.g. as root) to actually change
// ownership: clients must not be able to chown jailed files unless the
// operator has explicitly enabled it.
func TestSFTPServer_Chown_DefaultDenied(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)
	if srv.AllowChown {
		t.Fatalf("AllowChown should default to false")
	}

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.Create("/chown_denied.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	info, err := os.Stat(filepath.Join(root, "chown_denied.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("cannot read uid/gid on this platform")
	}
	// Chown to the current uid/gid: this would succeed on disk (same owner),
	// so the only thing that can fail this call is the server's AllowChown
	// gate. If the gate is wired up correctly we get a permission error
	// regardless of the underlying filesystem semantics.
	err = client.Chown("/chown_denied.txt", int(stat.Uid), int(stat.Gid))
	if err == nil {
		t.Fatalf("Chown succeeded with AllowChown=false; want permission denied")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Errorf("Chown error = %v; want a permission denied error", err)
	}
}

// TestSFTPServer_SymlinkRejected verifies that clients cannot create symlinks
// inside their jail. Allowing symlinks would let a client plant a link
// pointing outside the jail root that a subsequent request could follow,
// bypassing the path-containment checks in jail.resolve.
func TestSFTPServer_SymlinkRejected(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a target file so the symlink would otherwise be valid.
	f, err := client.Create("/target.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = f.Close()

	err = client.Symlink("/target.txt", "/link.txt")
	if err == nil {
		t.Fatalf("Symlink unexpectedly succeeded; want permission denied")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Errorf("Symlink error = %v; want a permission denied error", err)
	}
	// Confirm no link was created on disk.
	if _, err := os.Lstat(filepath.Join(root, "link.txt")); !os.IsNotExist(err) {
		t.Errorf("link.txt exists on disk after rejected Symlink: err=%v", err)
	}
}

// TestWriteLogger_TransferErrorSuppressesNotification verifies that when
// pkg/sftp invokes TransferError on the writer before Close (i.e. the
// in-flight upload was aborted), the subsequent Close does NOT enqueue a
// CompletedUpload event. Without this guarantee, a truncated upload caused
// by a client connection drop would be mis-reported as a complete upload.
func TestWriteLogger_TransferErrorSuppressesNotification(t *testing.T) {
	root := t.TempDir()
	f, err := os.OpenFile(filepath.Join(root, "partial.bin"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	uploads := make(chan CompletedUpload, 1)
	wl := &writeLogger{
		File:         f,
		filepath:     "/partial.bin",
		fullFilepath: filepath.Join(root, "partial.bin"),
		username:     "alice",
		clientIP:     "127.0.0.1",
		uploads:      uploads,
	}
	// Simulate the request server signalling that the transfer was aborted.
	wl.TransferError(io.ErrUnexpectedEOF)
	if err := wl.Close(); err != nil {
		t.Fatalf("Close after TransferError: %v", err)
	}
	select {
	case evt := <-uploads:
		t.Fatalf("CompletedUploads received notification %+v for an interrupted upload; want none", evt)
	case <-time.After(100 * time.Millisecond):
		// expected: no notification.
	}
}

// TestWriteLogger_CleanCloseAnnouncesUpload verifies that the happy path is
// unchanged: a Close with no preceding TransferError still announces the
// upload on the CompletedUploads channel.
func TestWriteLogger_CleanCloseAnnouncesUpload(t *testing.T) {
	root := t.TempDir()
	f, err := os.OpenFile(filepath.Join(root, "ok.bin"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	uploads := make(chan CompletedUpload, 1)
	wl := &writeLogger{
		File:         f,
		filepath:     "/ok.bin",
		fullFilepath: filepath.Join(root, "ok.bin"),
		username:     "alice",
		clientIP:     "127.0.0.1",
		uploads:      uploads,
	}
	if err := wl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case evt := <-uploads:
		if evt.FilePath != "/ok.bin" {
			t.Errorf("FilePath = %q; want /ok.bin", evt.FilePath)
		}
	case <-time.After(time.Second):
		t.Fatal("expected CompletedUpload notification for clean Close")
	}
}

// TestWriteLogger_TransferErrorNilIsNoop verifies that a TransferError(nil)
// call is ignored, so a subsequent clean Close still announces the upload.
func TestWriteLogger_TransferErrorNilIsNoop(t *testing.T) {
	root := t.TempDir()
	f, err := os.OpenFile(filepath.Join(root, "ok2.bin"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	uploads := make(chan CompletedUpload, 1)
	wl := &writeLogger{
		File:         f,
		filepath:     "/ok2.bin",
		fullFilepath: filepath.Join(root, "ok2.bin"),
		username:     "alice",
		uploads:      uploads,
	}
	wl.TransferError(nil)
	if err := wl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-uploads:
		// expected
	case <-time.After(time.Second):
		t.Fatal("expected CompletedUpload notification for clean Close after TransferError(nil)")
	}
}

// TestSFTPServer_InterruptedUploadNotAnnounced exercises the full SFTP
// pipeline: a client opens a file, writes some bytes, then abruptly tears
// down the underlying SSH transport without calling Close on the SFTP
// handle. pkg/sftp's request server drains the in-flight request through
// transferError + Close, and writeLogger must NOT announce the upload.
func TestSFTPServer_InterruptedUploadNotAnnounced(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	const name = "/aborted.bin"
	rf, err := client.Create(name)
	if err != nil {
		_ = client.Close()
		_ = conn.Close()
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = rf.Write([]byte("partial-data")); err != nil {
		_ = client.Close()
		_ = conn.Close()
		t.Fatalf("rf.Write: %v", err)
	}
	// Abruptly tear down the SSH transport WITHOUT closing the SFTP
	// handle. This is what happens on a client crash / network drop:
	// pkg/sftp's RequestServer sees EOF, calls transferError on the
	// in-flight write request, then Close on the writer.
	_ = conn.Close()

	select {
	case evt := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received notification %+v for an interrupted upload; want none", evt)
	case <-time.After(500 * time.Millisecond):
		// expected: no notification for a truncated upload.
	}
}

// ---- CRLF/control-byte sanitization tests ----

func TestSanitizeFTPText(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"normal.txt", "normal.txt"},
		{"with\rCR", "with?CR"},
		{"with\nLF", "with?LF"},
		{"with\r\nboth", "with??both"},
		{"tab\there", "tab?here"},
		{"del\x7Fhere", "del?here"},
		{"null\x00byte", "null?byte"},
		{"", ""},
		{"αβγ", "αβγ"}, // multi-byte UTF-8 (all bytes ≥ 0x80) passes through
	}
	for _, tc := range cases {
		if got := sanitizeFTPText(tc.in); got != tc.want {
			t.Errorf("sanitizeFTPText(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasCRLF(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"normal", false},
		{"with\rCR", true},
		{"with\nLF", true},
		{"with\r\nboth", true},
		{"tab\there", false}, // tab is a control byte but not CR/LF
		{"", false},
	}
	for _, tc := range cases {
		if got := hasCRLF(tc.in); got != tc.want {
			t.Errorf("hasCRLF(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func TestFtpQuotePath_SanitizesControlBytes(t *testing.T) {
	if got, want := ftpQuotePath("/foo\r\nbar"), `"/foo??bar"`; got != want {
		t.Errorf("ftpQuotePath CR/LF = %q; want %q", got, want)
	}
	if got, want := ftpQuotePath(`/has"quote`), `"/has""quote"`; got != want {
		t.Errorf("ftpQuotePath quote escape = %q; want %q", got, want)
	}
	if got, want := ftpQuotePath("/clean"), `"/clean"`; got != want {
		t.Errorf("ftpQuotePath clean = %q; want %q", got, want)
	}
}

func TestFtpListLine_SanitizesName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "stub")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	line := ftpListLine(info, "name\r\nFAKE 200 injected")
	if strings.ContainsAny(line, "\r\n") {
		t.Errorf("ftpListLine output contains raw CR/LF: %q", line)
	}
	if !strings.Contains(line, "name??FAKE 200 injected") {
		t.Errorf("ftpListLine output = %q; want sanitized name substring", line)
	}
}

// TestFTPServer_RejectsCRLFInWriteCommands verifies that STOR, MKD, and RNTO
// reject a bare CR in the client-supplied filename. The CR survives the
// CRLF-framed control read (only the trailing CR is trimmed), so without
// explicit rejection at the write commands a hostile client could create a
// file whose name later forges reply lines when echoed back via PWD/MKD or
// LIST.
func TestFTPServer_RejectsCRLFInWriteCommands(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "renameable.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "5000-5010")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	// STOR
	client.command(553, "STOR foo\rbar")
	// MKD
	client.command(553, "MKD foo\rbar")
	// RNFR + RNTO
	client.command(350, "RNFR renameable.txt")
	client.command(553, "RNTO foo\rbar")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "renameable.txt" {
		t.Fatalf("root contents = %v; want only renameable.txt (no CR-named entries created)", entries)
	}
}

// TestFTPServer_LISTSanitizesEmbeddedCRLF verifies that a filename containing
// raw CR/LF (created out-of-band — pkg/sftp + our write-time guards now
// reject these, but the host filesystem can still hold one) does not let a
// LIST response inject extra reply lines onto the data channel.
func TestFTPServer_LISTSanitizesEmbeddedCRLF(t *testing.T) {
	root := t.TempDir()
	const badName = "good\r\nFAKE 200 injected"
	if err := os.WriteFile(filepath.Join(root, badName), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "5000-5010")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")
	client.command(200, "TYPE I")

	dc, _ := client.passiveConn()
	client.send("LIST")
	client.read(150)
	listing, err := io.ReadAll(dc)
	if err != nil {
		t.Fatalf("io.ReadAll(dc): %v", err)
	}
	_ = dc.Close()
	client.read(226)

	// The data channel is line-oriented ("\r\n" per entry). With sanitization,
	// the single directory entry should produce a single non-empty line; the
	// CR and LF bytes inside the filename must have been replaced with '?'.
	lines := strings.Split(strings.TrimRight(string(listing), "\r\n"), "\r\n")
	if len(lines) != 1 {
		t.Fatalf("LIST emitted %d lines; want 1 (CR/LF injection bypassed sanitization): %q", len(lines), listing)
	}
	if !strings.Contains(lines[0], "good??FAKE 200 injected") {
		t.Errorf("LIST line = %q; want sanitized name substring %q", lines[0], "good??FAKE 200 injected")
	}
}

// TestSFTPServer_RejectsCRLFInFilenames verifies the write-time CR/LF guards
// on the SFTP handler paths (Filewrite, Filecmd Mkdir, Filecmd Rename) so
// that a hostile SFTP client cannot create a name that would later be
// echoed back to an FTP client and forge control-channel replies.
func TestSFTPServer_RejectsCRLFInFilenames(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "src.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "u", "p")

	if _, err := client.Create("/bad\rname.txt"); err == nil {
		t.Errorf("Create with CR in name unexpectedly succeeded")
	}
	if _, err := client.Create("/bad\nname.txt"); err == nil {
		t.Errorf("Create with LF in name unexpectedly succeeded")
	}
	if err := client.Mkdir("/bad\rdir"); err == nil {
		t.Errorf("Mkdir with CR in name unexpectedly succeeded")
	}
	if err := client.Rename("/src.txt", "/bad\nrenamed.txt"); err == nil {
		t.Errorf("Rename to CR/LF target unexpectedly succeeded")
	}

	// The valid source should still exist after the failed rename.
	if _, err := os.Stat(filepath.Join(root, "src.txt")); err != nil {
		t.Errorf("src.txt missing after rejected Rename: %v", err)
	}
	// No bad-named files should have been created on the host.
	for _, n := range []string{"bad\rname.txt", "bad\nname.txt", "bad\rdir", "bad\nrenamed.txt"} {
		if _, err := os.Stat(filepath.Join(root, n)); err == nil {
			t.Errorf("CR/LF-named entry %q exists on disk; write-time guard bypassed", n)
		}
	}
}
