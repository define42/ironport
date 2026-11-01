package ironport

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
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

// TestServer_RemoveUser_DisconnectsActiveSFTP verifies that RemoveUser
// force-closes an SFTP session that is currently authenticated as the
// removed user.
func TestServer_RemoveUser_DisconnectsActiveSFTP(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"victim": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "victim", "pw")
	if _, err := client.ReadDir("/"); err != nil {
		t.Fatalf("pre-remove ReadDir: %v", err)
	}

	srv.RemoveUser("victim")

	// After RemoveUser the existing SFTP session must be torn down. Poll
	// briefly because the close races with the server-side handler goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := client.ReadDir("/")
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expected SFTP session to be closed after RemoveUser, but it still serves requests")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestServer_RemoveUser_DisconnectsActiveFTP verifies that RemoveUser
// force-closes an FTP control connection that is currently authenticated as
// the removed user.
func TestServer_RemoveUser_DisconnectsActiveFTP(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"victim": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	c := dialFTP(t, addr)
	c.login("victim", "pw")

	srv.RemoveUser("victim")

	// The control connection should now be closed by the server. A
	// subsequent command read must surface an error.
	c.send("NOOP")
	_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.tp.ReadResponse(0); err == nil {
		t.Fatal("expected FTP control connection to be closed after RemoveUser, got nil error")
	}
}

// TestServer_RemoveAllUsers_DisconnectsActive verifies that RemoveAllUsers
// force-closes every connection currently authenticated as one of the
// removed users.
func TestServer_RemoveAllUsers_DisconnectsActive(t *testing.T) {
	root1 := t.TempDir()
	root2 := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root1, CanRead: true, CanWrite: true},
		"bob":   {Password: "bobpw", Root: root2, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	alice := dialSFTP(t, addr, "alice", "alicepw")
	bob := dialSFTP(t, addr, "bob", "bobpw")

	srv.RemoveAllUsers()

	assertClientClosed := func(name string, client *sftp.Client) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := client.ReadDir("/"); err != nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected SFTP session for %q to be closed after RemoveAllUsers, but it still serves requests", name)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	assertClientClosed("alice", alice)
	assertClientClosed("bob", bob)
}

// TestServer_RemoveAllUsers_LeavesPreAuthAlone verifies that RemoveAllUsers
// does not close TCP connections that have not yet completed authentication.
// Such connections will simply fail to authenticate against the now-empty
// user map; closing them pre-auth could mask client-side error reporting.
func TestServer_RemoveAllUsers_LeavesPreAuthAlone(t *testing.T) {
	srv, addr, stop := startTestServer(t, map[string]UserInfo{})
	t.Cleanup(stop)

	// Open a raw TCP connection but do not start the SSH handshake.
	preAuth, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("net.DialTimeout: %v", err)
	}
	t.Cleanup(func() { _ = preAuth.Close() })

	// Give the server a moment to trackConn the new socket.
	deadline := time.Now().Add(time.Second)
	for {
		srv.mu.RLock()
		n := len(srv.activeConns)
		srv.mu.RUnlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected 1 tracked conn before RemoveAllUsers, got %d", n)
		}
		time.Sleep(10 * time.Millisecond)
	}

	srv.RemoveAllUsers()

	// The pre-auth connection must still be open. A short-deadline Read
	// should either time out (no bytes from the server yet) or return >0
	// bytes (the SSH banner) — both indicate the conn is alive. An EOF or
	// "connection reset" would mean RemoveAllUsers wrongly kicked it.
	_ = preAuth.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 256)
	n, err := preAuth.Read(buf)
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("pre-auth connection was closed by RemoveAllUsers: err=%v n=%d", err, n)
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
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

	// Mutate the caller-owned slice through both its visible length and its
	// extra capacity to verify AddUser cloned the slice (and not just
	// captured a reference). keys has len=1, cap=2 so the cap-2 reslice and
	// index 1 write are in-bounds; gosec G602 does not track cap.
	keys[0] = pubKey2
	keys[:2][1] = pubKey2 //nolint:gosec // cap=2 reslice; intentional aliasing test

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
	if err := os.WriteFile(file1, []byte("alice data"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", file1, err)
	}
	if err := os.WriteFile(file2, []byte("bob data"), 0o600); err != nil {
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
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
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

func TestServer_RemoveAllUsers_ReplacesUserMap(t *testing.T) {
	srv := newTestServer(":0", "", "", map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)

	srv.mu.RLock()
	oldUsers := srv.users
	srv.mu.RUnlock()

	srv.RemoveAllUsers()

	if len(oldUsers) != 1 {
		t.Fatalf("old user map length = %d; want 1", len(oldUsers))
	}
	srv.mu.RLock()
	n := len(srv.users)
	srv.mu.RUnlock()
	if n != 0 {
		t.Fatalf("new user map length = %d; want 0", n)
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
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

func TestServer_AddUserKey_DoesNotMutateExistingAuthorizedKeysSnapshots(t *testing.T) {
	root := t.TempDir()
	_, pubKey1 := testClientKey(t)
	_, pubKey2 := testClientKey(t)
	srv := newTestServer(":0", "", "", map[string]UserInfo{
		"alice": {AuthorizedKeys: []ssh.PublicKey{pubKey1}, Root: root, CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)

	// Simulate a future reader holding a UserInfo copy whose AuthorizedKeys
	// slice has spare capacity. AddUserKey must not append into that backing
	// array after the reader has released the lock.
	keys := make([]ssh.PublicKey, 1, 2)
	keys[0] = pubKey1
	srv.mu.Lock()
	u := srv.users["alice"]
	u.AuthorizedKeys = keys
	srv.users["alice"] = u
	snapshot := srv.users["alice"]
	srv.mu.Unlock()

	srv.AddUserKey("alice", pubKey2)

	if len(snapshot.AuthorizedKeys) != 1 {
		t.Fatalf("snapshot AuthorizedKeys length = %d; want 1", len(snapshot.AuthorizedKeys))
	}
	grownSnapshot := snapshot.AuthorizedKeys[:2]
	if grownSnapshot[1] != nil {
		t.Fatal("AddUserKey appended into an existing snapshot's AuthorizedKeys backing array")
	}

	srv.mu.RLock()
	stored := srv.users["alice"].AuthorizedKeys
	srv.mu.RUnlock()
	if len(stored) != 2 {
		t.Fatalf("stored AuthorizedKeys length = %d; want 2", len(stored))
	}
	if !bytes.Equal(stored[1].Marshal(), pubKey2.Marshal()) {
		t.Fatal("stored AuthorizedKeys missing appended key")
	}
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
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

// TestServer_RemoveUser_DisconnectsActiveFTPS verifies that RemoveUser
// force-closes a control connection that authenticated after an AUTH TLS
// upgrade. Regression test: Server.activeConns is keyed by the conn as
// accepted, but the session's working conn becomes the *tls.Conn after
// AUTH TLS; recording the association against the wrapper silently missed
// the map, so revoked users kept their live FTPS sessions.
func TestServer_RemoveUser_DisconnectsActiveFTPS(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"victim": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}
	cfg, pool := newTestFTPSConfig(t, users, true)
	srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("victim", "pw")

	// White-box: the association must be recorded under the tracked raw
	// conn even though the session now operates on the TLS wrapper.
	srv.mu.RLock()
	associated := false
	for _, u := range srv.activeConns {
		if u.authenticated && u.username == "victim" {
			associated = true
			break
		}
	}
	srv.mu.RUnlock()
	if !associated {
		t.Fatal("no tracked connection is associated with the authenticated FTPS user")
	}

	srv.RemoveUser("victim")

	// The control connection must have been force-closed. The NOOP write
	// may itself fail (already proof of closure); if it goes through, the
	// next read must surface an error instead of a 200 reply.
	if err := c.tp.PrintfLine("NOOP"); err == nil {
		_ = c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := c.tp.ReadResponse(0); err == nil {
			t.Fatal("expected FTPS control connection to be closed after RemoveUser, got nil error")
		}
	}
}

// TestServer_RemoveUser_SparesFTPSSessionAfterREIN verifies that REIN
// clears the user association on the tracked raw conn: revoking the
// previous user must not evict a session that has already returned to
// the pre-login state.
func TestServer_RemoveUser_SparesFTPSSessionAfterREIN(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"victim": {Password: "pw", Root: root, CanRead: true, CanWrite: true},
	}
	cfg, pool := newTestFTPSConfig(t, users, true)
	srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
	defer stop()

	c := dialFTPS(t, addr, pool)
	c.authTLS()
	c.login("victim", "pw")
	c.command(220, "REIN")

	srv.RemoveUser("victim")

	// The now-anonymous session must survive its former user's revocation.
	c.command(200, "NOOP")
}
