//go:build linux

package ironport

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestServerAddUserEquivalentAuthenticationPreservesRevision(t *testing.T) {
	_, first := testClientKey(t)
	_, second := testClientKey(t)
	parsedFirst, err := ssh.ParsePublicKey(first.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	parsedSecond, err := ssh.ParsePublicKey(second.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		oldKeys, newKeys []ssh.PublicKey
	}{
		{name: "identical", oldKeys: []ssh.PublicKey{first, second}, newKeys: []ssh.PublicKey{first, second}},
		{name: "reparsed", oldKeys: []ssh.PublicKey{first, second}, newKeys: []ssh.PublicKey{parsedFirst, parsedSecond}},
		{name: "reordered duplicated and nil keys", oldKeys: []ssh.PublicKey{first, nil, second, first}, newKeys: []ssh.PublicKey{nil, parsedSecond, parsedFirst, nil, parsedSecond}},
		{name: "nil and empty keys", newKeys: []ssh.PublicKey{}},
		{name: "only nil keys", oldKeys: []ssh.PublicKey{nil, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := UserInfo{Password: "pw", Root: t.TempDir(), CanRead: true, CanWrite: true, AuthorizedKeys: tc.oldKeys}
			replacement := original
			replacement.AuthorizedKeys = tc.newKeys
			t.Run("during authentication", func(t *testing.T) {
				assertAddUserDuringAuthentication(t, original, replacement, true)
			})
			t.Run("before connection commit", func(t *testing.T) {
				assertCommitConnUser(t, original, func(s *Server) { s.AddUser("alice", replacement) }, true)
			})
			t.Run("active session", func(t *testing.T) {
				assertAddUserActiveSession(t, original, replacement, false)
			})
		})
	}
}

func assertAddUserDuringAuthentication(t *testing.T, original, replacement UserInfo, want bool) {
	t.Helper()
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": original}})
	_, initialRevision, _ := s.userSnapshot("alice")
	_, fs, revision, ok := s.authenticateUser("alice", func(stored UserInfo) bool {
		// This callback runs after the user/revision snapshot, reproducing the
		// interleaving of an update during authentication without timing waits.
		s.AddUser("alice", replacement)
		return checkPassword(stored.Password, original.Password)
	})
	if fs != nil {
		defer func() { _ = fs.Close() }()
	}
	if ok != want {
		t.Fatalf("authentication succeeded=%t; want %t", ok, want)
	}
	if want && (fs == nil || revision != initialRevision) {
		t.Fatalf("equivalent update changed snapshot: fs=%v revision=%d; initial=%d", fs, revision, initialRevision)
	}
	if !want && (fs != nil || revision != 0) {
		t.Fatalf("changed authentication retained stale snapshot: fs=%v revision=%d", fs, revision)
	}
}

func TestServerAddUserChangedAuthenticationInvalidatesRevision(t *testing.T) {
	_, first := testClientKey(t)
	_, second := testClientKey(t)
	for _, tc := range []struct {
		name   string
		change func(*UserInfo)
	}{
		{name: "password", change: func(u *UserInfo) { u.Password = "changed" }},
		{name: "root", change: func(u *UserInfo) { u.Root = t.TempDir() }},
		{name: "read permission", change: func(u *UserInfo) { u.CanRead = false }},
		{name: "write permission", change: func(u *UserInfo) { u.CanWrite = false }},
		{name: "added key", change: func(u *UserInfo) { u.AuthorizedKeys = []ssh.PublicKey{first, second} }},
		{name: "removed key", change: func(u *UserInfo) { u.AuthorizedKeys = nil }},
		{name: "replaced key", change: func(u *UserInfo) { u.AuthorizedKeys = []ssh.PublicKey{second} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := UserInfo{Password: "pw", Root: t.TempDir(), CanRead: true, CanWrite: true, AuthorizedKeys: []ssh.PublicKey{first}}
			replacement := original
			tc.change(&replacement)
			t.Run("during authentication", func(t *testing.T) {
				assertAddUserDuringAuthentication(t, original, replacement, false)
			})
			t.Run("before connection commit", func(t *testing.T) {
				assertCommitConnUser(t, original, func(s *Server) { s.AddUser("alice", replacement) }, false)
			})
			t.Run("active session", func(t *testing.T) {
				assertAddUserActiveSession(t, original, replacement, true)
			})
		})
	}
}

func assertAddUserActiveSession(t *testing.T, original, replacement UserInfo, wantClosed bool) {
	t.Helper()
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": original}})
	peer := trackAuthenticatedPipe(t, s, "alice")
	s.AddUser("alice", replacement)
	if wantClosed {
		assertPipeClosed(t, peer)
		return
	}
	assertPipeOpen(t, peer)
}

func TestServerKeyUpdatesRevokeOnlyWhenAuthorityRemoved(t *testing.T) {
	_, first := testClientKey(t)
	_, second := testClientKey(t)
	for _, tc := range []struct {
		name                string
		update              func(*Server)
		wantClosed          bool
		wantRevisionChanged bool
	}{
		{
			name:                "removed key",
			update:              func(s *Server) { s.RemoveUserKey("alice", first) },
			wantClosed:          true,
			wantRevisionChanged: true,
		},
		{name: "missing key", update: func(s *Server) { s.RemoveUserKey("alice", second) }},
		{name: "nil key", update: func(s *Server) { s.RemoveUserKey("alice", nil) }},
		{
			name:                "added key",
			update:              func(s *Server) { s.AddUserKey("alice", second) },
			wantRevisionChanged: true,
		},
		{name: "duplicate key", update: func(s *Server) { s.AddUserKey("alice", first) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := UserInfo{
				Password:       "pw",
				Root:           t.TempDir(),
				CanRead:        true,
				AuthorizedKeys: []ssh.PublicKey{nil, first},
			}
			s := NewServer(&Config{Users: map[string]UserInfo{"alice": info}})
			_, before, _ := s.userSnapshot("alice")
			peer := trackAuthenticatedPipe(t, s, "alice")

			tc.update(s)

			_, after, _ := s.userSnapshot("alice")
			if got := after != before; got != tc.wantRevisionChanged {
				t.Fatalf("revision changed = %t; want %t", got, tc.wantRevisionChanged)
			}
			if tc.wantClosed {
				assertPipeClosed(t, peer)
				return
			}
			assertPipeOpen(t, peer)
		})
	}
}

func trackAuthenticatedPipe(t *testing.T, s *Server, username string) net.Conn {
	t.Helper()
	serverConn, peer := net.Pipe()
	if !s.trackConn(serverConn) {
		t.Fatal("trackConn rejected test connection")
	}
	t.Cleanup(func() {
		s.untrackConn(serverConn)
		s.connWG.Done()
		_ = serverConn.Close()
		_ = peer.Close()
	})
	_, revision, ok := s.userSnapshot(username)
	if !ok || !s.commitConnUser(serverConn, username, revision) {
		t.Fatal("commitConnUser rejected current authentication")
	}
	return peer
}

func assertPipeClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		if errors.Is(err, io.ErrClosedPipe) {
			return
		}
		t.Fatal(err)
	}
	_, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("connection remained open after revocation: %v", err)
	}
}

func assertPipeOpen(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("connection closed unexpectedly: %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestServerAddUserConcurrentEquivalentUpdates(t *testing.T) {
	_, key := testClientKey(t)
	info := UserInfo{Password: "pw", Root: t.TempDir(), CanRead: true, AuthorizedKeys: []ssh.PublicKey{key}}
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": info}})
	_, initialRevision, _ := s.userSnapshot("alice")
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 10 {
				s.AddUser("alice", info)
			}
		})
	}
	workers.Wait()
	if _, revision, _ := s.userSnapshot("alice"); revision != initialRevision {
		t.Fatalf("equivalent updates changed revision from %d to %d", initialRevision, revision)
	}
}

type revisionObservedKey struct {
	ssh.PublicKey
	onMarshal func()
}

func (k revisionObservedKey) Marshal() []byte {
	k.onMarshal()
	return k.PublicKey.Marshal()
}

func TestServerAddUserComparesPublicKeysOutsideLock(t *testing.T) {
	_, key := testClientKey(t)
	info := UserInfo{Password: "pw", Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{key}}
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": info}})
	calls := 0
	heldLock := false
	info.AuthorizedKeys = []ssh.PublicKey{revisionObservedKey{PublicKey: key, onMarshal: func() {
		calls++
		if s.mu.TryLock() {
			s.mu.Unlock()
		} else {
			heldLock = true
		}
	}}}
	s.AddUser("alice", info)
	if calls == 0 || heldLock {
		t.Fatalf("key comparison calls=%d held server lock=%t", calls, heldLock)
	}
}

func TestServerAddUserRetriesConcurrentAuthenticationChange(t *testing.T) {
	_, key := testClientKey(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var blocked atomic.Bool
	observed := revisionObservedKey{PublicKey: key, onMarshal: func() {
		if blocked.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
	}}
	info := UserInfo{Password: "pw", Root: t.TempDir(), AuthorizedKeys: []ssh.PublicKey{observed}}
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": info}})
	_, initialRevision, _ := s.userSnapshot("alice")
	info.AuthorizedKeys = []ssh.PublicKey{key}
	go func() {
		s.AddUser("alice", info)
		close(done)
	}()
	select {
	case <-entered:
	case <-done:
		t.Fatal("equivalent update did not compare key bytes")
	case <-time.After(5 * time.Second):
		t.Fatal("key comparison did not start")
	}
	changed := info
	changed.Password = "changed"
	s.AddUser("alice", changed)
	_, changedRevision, _ := s.userSnapshot("alice")
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent update did not finish")
	}
	current, finalRevision, _ := s.userSnapshot("alice")
	if current.Password != info.Password || finalRevision == initialRevision || finalRevision == changedRevision {
		t.Fatalf("update reused stale comparison: password=%q revisions=%d,%d,%d", current.Password, initialRevision, changedRevision, finalRevision)
	}
}
