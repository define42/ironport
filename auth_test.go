package ironport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	_, err := ssh.Dial("tcp", addr, sshCfg)
	if err == nil {
		t.Fatal("expected authentication error, got nil")
	}
}

// TestNewSignerFromFile verifies that NewSignerFromFile loads a valid PEM key file
// and returns a usable signer, and that it returns an error for invalid inputs.
//
//nolint:gocognit,funlen // exercises every supported key type and every error branch in one fixture
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
		if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
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
		if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
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
		if err := os.WriteFile(keyPath, []byte("not a valid PEM file"), 0o600); err != nil {
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
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		t.Fatal(err)
	}

	signer, err := NewSignerFromFile(keyPath)
	if err != nil {
		t.Fatalf("NewSignerFromFile: %v", err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}

	config := newTestConfig("", "", "", users, signer, defaultCompletedUploadsSize)
	_, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected authentication error with wrong key, got nil")
	}
}

//nolint:gocognit // covers each jail-root rejection path against a live SSH handshake
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
		{name: "dot-dot", root: target + "/../" + filepath.Base(target)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(":0", "", "", map[string]UserInfo{
				"alice": {Password: "alicepw", Root: tc.root, CanRead: true, CanWrite: true},
			}, testSigner(t), defaultCompletedUploadsSize)
			state := &sshAuthState{}
			t.Cleanup(state.close)
			cfg := state.config(srv.sshServerConfig())

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
	state := &sshAuthState{}
	t.Cleanup(state.close)
	cfg := state.config(srv.sshServerConfig())
	perms, err := cfg.PasswordCallback(testConnMetadata{user: "alice"}, []byte("alicepw"))
	if err == nil {
		t.Fatalf("PasswordCallback accepted symlink root with permissions %+v", perms)
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Fatal("expected auth failure for non-existent user, got nil")
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
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
		{name: "symlink", root: link, want: false},
		{name: "dot-dot", root: target + "/../" + filepath.Base(target), want: false},
		{name: "directory", root: target, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := NewServer(&Config{Users: map[string]UserInfo{
				"alice": {Password: "alicepw", Root: tc.root, CanRead: true, CanWrite: true},
			}})
			conn := &stubConn{}
			if !srv.trackConn(conn) {
				t.Fatal("control connection was not admitted")
			}
			t.Cleanup(func() {
				srv.untrackConn(conn)
				srv.connWG.Done()
			})
			fs := &ftpSession{server: srv, rawConn: conn, username: "alice"}
			t.Cleanup(fs.closeJail)

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
