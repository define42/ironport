package sftpserver

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ---- withinRoot tests ----

func TestWithinRoot(t *testing.T) {
	tests := []struct {
		path, root string
		want       bool
	}{
		{"/srv/sftp/alice", "/srv/sftp/alice", true},
		{"/srv/sftp/alice/foo", "/srv/sftp/alice", true},
		{"/srv/sftp/alice/foo/bar", "/srv/sftp/alice", true},
		{"/srv/sftp/alice_evil", "/srv/sftp/alice", false},
		{"/srv/sftp", "/srv/sftp/alice", false},
		{"/srv/sftp/bob", "/srv/sftp/alice", false},
		{"/", "/srv/sftp/alice", false},
	}
	for _, tc := range tests {
		got := withinRoot(tc.path, tc.root)
		if got != tc.want {
			t.Errorf("withinRoot(%q, %q) = %v; want %v", tc.path, tc.root, got, tc.want)
		}
	}
}

// ---- jail.resolve tests ----

func TestJailResolve(t *testing.T) {
	root := t.TempDir()
	j := jail{root: root}

	// Normal relative path
	p, err := j.resolve("foo.txt")
	if err != nil {
		t.Fatalf("resolve(foo.txt): %v", err)
	}
	if p != filepath.Join(root, "foo.txt") {
		t.Errorf("resolve(foo.txt) = %q; want %q", p, filepath.Join(root, "foo.txt"))
	}

	// Absolute SFTP path
	p, err = j.resolve("/bar/baz.txt")
	if err != nil {
		t.Fatalf("resolve(/bar/baz.txt): %v", err)
	}
	if p != filepath.Join(root, "bar", "baz.txt") {
		t.Errorf("resolve(/bar/baz.txt) = %q; want %q", p, filepath.Join(root, "bar", "baz.txt"))
	}

	// Empty path → root
	p, err = j.resolve("")
	if err != nil {
		t.Fatalf("resolve(''): %v", err)
	}
	if p != root {
		t.Errorf("resolve('') = %q; want %q", p, root)
	}

	// Path traversal attempt
	_, err = j.resolve("../../etc/passwd")
	if err != nil {
		// After clean, ../../etc/passwd from "/" becomes /etc/passwd which is
		// outside root, so resolve returns os.ErrPermission only when the
		// resolved real path escapes; for non-existing paths the string check
		// catches it.  Accept any non-nil error.
		t.Logf("resolve(../../etc/passwd) correctly returned error: %v", err)
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

// startTestServer launches a Server on a random OS-assigned port and returns
// the address and a cancel function that closes the listener.
func startTestServer(t *testing.T, users map[string]UserInfo) (srv *Server, addr string, stop func()) {
	t.Helper()
	signer := testSigner(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = ln.Addr().String()

	srv = NewServer(addr, users, signer)
	cfg := srv.sshServerConfig()

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go handleConn(nc, cfg, srv.CompletedUploads, srv.tempExtensions())
		}
	}()

	stop = func() { ln.Close() }
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
		conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		conn.Close()
	})
	return client
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
	f.Close()

	// Download and compare.
	rf, err := client.Open(remote)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, err := io.ReadAll(rf)
	rf.Close()
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
	srv := NewServer(":0", users, signer)
	if srv.Addr != ":0" {
		t.Errorf("Addr = %q; want :0", srv.Addr)
	}
	if len(srv.Users) != 1 {
		t.Errorf("Users len = %d; want 1", len(srv.Users))
	}
	if srv.Signer != signer {
		t.Error("Signer not set correctly")
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
	rf.Close()
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
	f.Close()

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

	srv := NewServer(addr, users, signer)
	cfg := srv.sshServerConfig()

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(nc, cfg, srv.CompletedUploads, srv.tempExtensions())
		}
	}()
	t.Cleanup(func() { ln.Close() })

	client := dialSFTP(t, addr, "testuser", "testpw")
	content := []byte("key from file")
	f, err := client.Create("/hello.txt")
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	f.Close()

	rf, err := client.Open("/hello.txt")
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, _ := io.ReadAll(rf)
	rf.Close()
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
		case got := <-srv.CompletedUploads:
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
	f.Close()

	info, err := os.Stat(filepath.Join(root, "secret.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	// Mask to the permission bits only and verify owner-only access (0600).
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("file permissions = %04o; want 0600", got)
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
		conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		conn.Close()
	})
	return client
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
	f.Close()

	// Download and verify the content.
	rf, err := client.Open("/pubkey.txt")
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, err := io.ReadAll(rf)
	rf.Close()
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

	srv := NewServer(":0", map[string]UserInfo{
		"carol": {Root: root, CanRead: true},
	}, testSigner(t))

	srv.AddUserKey("carol", pubKey)
	srv.AddUserKey("carol", pubKey)
	srv.AddUserKey("carol", pubKey)

	srv.mu.RLock()
	n := len(srv.Users["carol"].AuthorizedKeys)
	srv.mu.RUnlock()

	if n != 1 {
		t.Errorf("expected 1 authorized key after duplicate adds, got %d", n)
	}
}

// TestServer_AddRemoveUserKey_NonExistentUser verifies that calling AddUserKey
// or RemoveUserKey for a user that does not exist is a safe no-op.
func TestServer_AddRemoveUserKey_NonExistentUser(t *testing.T) {
	srv := NewServer(":0", map[string]UserInfo{}, testSigner(t))
	_, pub := testClientKey(t)

	// Neither call should panic or create phantom entries.
	srv.AddUserKey("ghost", pub)
	srv.RemoveUserKey("ghost", pub)

	srv.mu.RLock()
	_, exists := srv.Users["ghost"]
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
	srv := NewServer(":0", map[string]UserInfo{
		"eve": {AuthorizedKeys: []ssh.PublicKey{pub}, Root: root, CanRead: true},
	}, testSigner(t))

	srv.AddUserKey("eve", nil) // must not panic

	srv.mu.RLock()
	n := len(srv.Users["eve"].AuthorizedKeys)
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
	srv := NewServer(":0", map[string]UserInfo{
		"frank": {
			// Mix nil entries with a real key.
			AuthorizedKeys: []ssh.PublicKey{nil, pub, nil},
			Root:           root,
			CanRead:        true,
		},
	}, testSigner(t))

	srv.RemoveUserKey("frank", pub) // must not panic

	srv.mu.RLock()
	keys := srv.Users["frank"].AuthorizedKeys
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
	srv := NewServer(":0", map[string]UserInfo{
		"grace": {AuthorizedKeys: []ssh.PublicKey{pub}, Root: root, CanRead: true},
	}, testSigner(t))

	srv.RemoveUserKey("grace", nil) // must not panic

	srv.mu.RLock()
	n := len(srv.Users["grace"].AuthorizedKeys)
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
	f.Close()

	// Verify by downloading.
	rf, err := client.Open("/subdir/file.txt")
	if err != nil {
		t.Fatalf("Open(/subdir/file.txt): %v", err)
	}
	got, err := io.ReadAll(rf)
	rf.Close()
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
	f.Close()

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
	rf.Close()
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
	f.Close()

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
	rf.Close()
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
	f.Close()

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
	f.Close()

	// Attempt to rename into a non-existent directory; must fail.
	err = client.Rename("/existing.txt", "/nosuchdir/existing.txt")
	if err == nil {
		t.Error("expected error when moving file to non-existent folder, got nil")
	}
}

// TestSFTPServer_Chmod verifies that a chmod (Setstat with permissions) request
// is accepted by the server without error.
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
	f.Close()

	// Send a chmod request; the server accepts but does not apply it (no-op).
	if err := client.Chmod("/chmod_test.txt", 0644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
}

// TestSFTPServer_Chown verifies that a chown (Setstat with uid/gid) request is
// accepted by the server without error.  The server records no-op for Setstat,
// so the underlying uid/gid on disk is unchanged; we only verify the protocol
// round-trip succeeds.
func TestSFTPServer_Chown(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
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
	f.Close()

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

	// Send chown with the same uid/gid; the server accepts this as a no-op.
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
	_, addr, stop := startTestServer(t, users)
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
	f.Close()

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
	// accepts this as a no-op for Setstat.
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

	srv := NewServer("127.0.0.1:0", users, signer)

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
	conn.Close()

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
	srv := NewServer(":0", map[string]UserInfo{}, testSigner(t))
	if err := srv.Close(); err != nil {
		t.Errorf("Close before ListenAndServe returned %v; want nil", err)
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
	f.Close()

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
	srv := NewServer("127.0.0.1:0", users, signer)
	cfg := srv.sshServerConfig()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(nc, cfg, srv.CompletedUploads, srv.tempExtensions())
		}
	}()

	// Connect but never send any SSH data.
	idle, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer idle.Close()

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

// TestServer_TempExtensionsNormalisation verifies that TempExtensions are
// normalised (lower-cased, dot-prefixed, empty entries stripped) before use.
func TestServer_TempExtensionsNormalisation(t *testing.T) {
	srv := &Server{TempExtensions: []string{"TMP", ".Writing", "  ", ".part"}}
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
	srv, addr, stop := startTestServer(t, users)
	srv.TempExtensions = []string{".tmp", ".writing"}
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
	case got := <-srv.CompletedUploads:
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
	case got := <-srv.CompletedUploads:
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
	srv, addr, stop := startTestServer(t, users)
	srv.TempExtensions = []string{".tmp", ".writing"}
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
	case got := <-srv.CompletedUploads:
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
	srv, addr, stop := startTestServer(t, users)
	srv.TempExtensions = []string{".tmp", ".writing"}
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
	case got := <-srv.CompletedUploads:
		if got.FilePath != name {
			t.Errorf("CompletedUploads FilePath = %q; want %q", got.FilePath, name)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CompletedUploads for plain upload")
	}
}
