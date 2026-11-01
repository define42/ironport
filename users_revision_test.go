//go:build linux

package ironport

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestUserRevisionEquivalentUpdates(t *testing.T) {
	_, first := testClientKey(t)
	_, second := testClientKey(t)
	parsed, err := ssh.ParsePublicKey(first.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		oldKeys, newKeys []ssh.PublicKey
	}{
		{name: "identical", oldKeys: []ssh.PublicKey{first, second}, newKeys: []ssh.PublicKey{first, second}},
		{name: "reparsed", oldKeys: []ssh.PublicKey{first}, newKeys: []ssh.PublicKey{parsed}},
		{
			name: "reordered duplicated and nil keys", oldKeys: []ssh.PublicKey{first, nil, second, first},
			newKeys: []ssh.PublicKey{nil, second, parsed, nil, second},
		},
		{name: "nil and empty keys", newKeys: []ssh.PublicKey{}},
		{name: "only nil keys", oldKeys: []ssh.PublicKey{nil, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := revisionUser(t, tc.oldKeys)
			replacement := original
			replacement.AuthorizedKeys = tc.newKeys
			checkRevisionUpdate(t, original, func(s *Server) { s.AddUser("alice", replacement) }, false, false)
		})
	}
}

func TestUserRevisionEffectiveUpdates(t *testing.T) {
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
			original := revisionUser(t, []ssh.PublicKey{first})
			replacement := original
			tc.change(&replacement)
			checkRevisionUpdate(t, original, func(s *Server) { s.AddUser("alice", replacement) }, true, true)
		})
	}
}

func TestUserRevisionKeyUpdates(t *testing.T) {
	_, first := testClientKey(t)
	_, second := testClientKey(t)
	for _, tc := range []struct {
		name                    string
		update                  func(*Server)
		changed, closesExisting bool
	}{
		{name: "add key", update: func(s *Server) { s.AddUserKey("alice", second) }, changed: true},
		{name: "duplicate key", update: func(s *Server) { s.AddUserKey("alice", first) }},
		{name: "add nil key", update: func(s *Server) { s.AddUserKey("alice", nil) }},
		{name: "remove key", update: func(s *Server) { s.RemoveUserKey("alice", first) }, changed: true, closesExisting: true},
		{name: "missing key", update: func(s *Server) { s.RemoveUserKey("alice", second) }},
		{name: "remove nil key", update: func(s *Server) { s.RemoveUserKey("alice", nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := revisionUser(t, []ssh.PublicKey{nil, first, first})
			checkRevisionUpdate(t, original, tc.update, tc.changed, tc.closesExisting)
		})
	}
}

func revisionUser(t *testing.T, keys []ssh.PublicKey) UserInfo {
	t.Helper()
	return UserInfo{Password: "pw", Root: t.TempDir(), CanRead: true, CanWrite: true, AuthorizedKeys: keys}
}

func checkRevisionUpdate(t *testing.T, original UserInfo, update func(*Server), changed, closesExisting bool) {
	t.Helper()
	t.Run("during authentication", func(t *testing.T) {
		checkRevisionAuthentication(t, original, update, changed)
	})
	t.Run("before connection commit", func(t *testing.T) {
		s := NewServer(&Config{Users: map[string]UserInfo{"alice": original}})
		conn := newRevisionConn(t, s)
		_, before, _ := s.userSnapshot("alice")
		update(s)
		if got := s.commitConnUser(conn, "alice", before); got == changed {
			t.Fatalf("stale authentication committed=%t after revision changed=%t", got, changed)
		}
	})
	t.Run("active session", func(t *testing.T) {
		s := NewServer(&Config{Users: map[string]UserInfo{"alice": original}})
		conn := newRevisionConn(t, s)
		before := commitRevisionConn(t, s, conn, "alice")
		update(s)
		_, after, _ := s.userSnapshot("alice")
		if (after != before) != changed {
			t.Fatalf("revision %d -> %d; want changed=%t", before, after, changed)
		}
		if got := conn.closed.Load(); got != closesExisting {
			t.Fatalf("existing session closed=%t; want %t", got, closesExisting)
		}
	})
}

func checkRevisionAuthentication(t *testing.T, original UserInfo, update func(*Server), changed bool) {
	t.Helper()
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": original}})
	_, before, _ := s.userSnapshot("alice")
	beforeFDs := countRetainedJailDescriptors(t, original.Root)
	_, root, revision, ok := s.authenticateUser("alice", func(stored UserInfo) bool {
		update(s)
		return checkPassword(stored.Password, original.Password)
	})
	if root != nil {
		t.Cleanup(func() { _ = root.Close() })
	}
	if ok == changed {
		t.Fatalf("authentication succeeded=%t after revision changed=%t", ok, changed)
	}
	if changed {
		if afterFDs := countRetainedJailDescriptors(t, original.Root); afterFDs != beforeFDs {
			t.Fatalf("rejected authentication leaked jail descriptors: %d -> %d", beforeFDs, afterFDs)
		}
	}
	if changed && (root != nil || revision != 0) {
		t.Fatalf("rejected authentication retained stale metadata: root=%v revision=%d", root, revision)
	}
	if !changed && (root == nil || revision != before) {
		t.Fatalf("equivalent update lost authentication: root=%v revision=%d; want %d", root, revision, before)
	}
}

// revisionConn observes the actual transport close without sleeps or socket I/O.
type revisionConn struct {
	net.Conn

	closed atomic.Bool
}

func (c *revisionConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func newRevisionConn(t *testing.T, s *Server) *revisionConn {
	t.Helper()
	conn := &revisionConn{Conn: admissionConn(t, "192.0.2.1")}
	if !s.trackConn(conn) {
		t.Fatal("test connection rejected")
	}
	t.Cleanup(func() {
		s.untrackConn(conn)
		s.connWG.Done()
		_ = conn.Close()
	})
	return conn
}

func commitRevisionConn(t *testing.T, s *Server, conn net.Conn, username string) uint64 {
	t.Helper()
	_, revision, ok := s.userSnapshot(username)
	if !ok || !s.commitConnUser(conn, username, revision) {
		t.Fatal("current authentication rejected")
	}
	return revision
}

func TestUserRevisionRemovalInvalidatesSnapshots(t *testing.T) {
	for _, tc := range []struct {
		name       string
		all, readd bool
	}{
		{name: "remove user"},
		{name: "remove and readd", readd: true},
		{name: "remove all", all: true},
		{name: "remove all and readd", all: true, readd: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := revisionUser(t, nil)
			update := func(s *Server) {
				if tc.all {
					s.RemoveAllUsers()
				} else {
					s.RemoveUser("alice")
				}
				if tc.readd {
					s.AddUser("alice", original)
				}
			}
			checkRevisionUpdate(t, original, update, true, true)
		})
	}
}

func TestUserRevisionEmptyUsernameIsAuthenticated(t *testing.T) {
	for _, tc := range []struct {
		name        string
		remove      func(*Server)
		closesOther bool
	}{
		{name: "remove empty user", remove: func(s *Server) { s.RemoveUser("") }},
		{name: "remove all users", remove: (*Server).RemoveAllUsers, closesOther: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := revisionUser(t, nil)
			s := NewServer(&Config{Users: map[string]UserInfo{"": info, "alice": info}})
			authenticated := newRevisionConn(t, s)
			other := newRevisionConn(t, s)
			preauth := newRevisionConn(t, s)
			before := commitRevisionConn(t, s, authenticated, "")
			commitRevisionConn(t, s, other, "alice")
			tc.remove(s)
			if !authenticated.closed.Load() || preauth.closed.Load() {
				t.Fatalf("empty username removal: authenticated closed=%t, preauth closed=%t",
					authenticated.closed.Load(), preauth.closed.Load())
			}
			if other.closed.Load() != tc.closesOther {
				t.Fatalf("other user closed=%t; want %t", other.closed.Load(), tc.closesOther)
			}
			if s.commitConnUser(preauth, "", before) {
				t.Fatal("removed empty user snapshot committed")
			}
			s.AddUser("", info)
			if s.commitConnUser(preauth, "", before) {
				t.Fatal("readded empty user accepted its previous revision")
			}
			commitRevisionConn(t, s, preauth, "")
		})
	}
}

func TestUserRevisionCancellationSurvivesReset(t *testing.T) {
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": revisionUser(t, nil)}})
	conn := newRevisionConn(t, s)
	revision := commitRevisionConn(t, s, conn, "alice")
	called, locked := false, false
	if !s.setConnCancel(conn, func() {
		called = true
		if s.mu.TryLock() {
			s.mu.Unlock()
		} else {
			locked = true
		}
	}) {
		t.Fatal("cancellation registration rejected")
	}
	s.clearConnUser(conn)
	if !s.commitConnUser(conn, "alice", revision) {
		t.Fatal("authentication after reset rejected")
	}
	s.RemoveUser("alice")
	if !called || locked {
		t.Fatalf("cancellation callback called=%t while holding server lock=%t", called, locked)
	}
	s.clearConnUser(conn)
	s.AddUser("alice", revisionUser(t, nil))
	_, revision, _ = s.userSnapshot("alice")
	if s.commitConnUser(conn, "alice", revision) {
		t.Fatal("canceled connection reauthenticated after user was readded")
	}
	lateCalled := false
	if s.setConnCancel(conn, func() { lateCalled = true }) || !lateCalled {
		t.Fatal("late callback registration missed prior cancellation")
	}
}

func TestUserRevisionCallbacksOutsideLock(t *testing.T) {
	_, key := testClientKey(t)
	for _, tc := range []struct {
		name   string
		update func(*Server, UserInfo)
	}{
		{name: "replacement", update: func(s *Server, u UserInfo) { u.Password = "changed"; s.AddUser("alice", u) }},
		{name: "key removal", update: func(s *Server, _ UserInfo) { s.RemoveUserKey("alice", key) }},
		{name: "user removal", update: func(s *Server, _ UserInfo) { s.RemoveUser("alice") }},
		{name: "all users removal", update: func(s *Server, _ UserInfo) { s.RemoveAllUsers() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := revisionUser(t, []ssh.PublicKey{key})
			s := NewServer(&Config{Users: map[string]UserInfo{"alice": info}})
			conn := newRevisionConn(t, s)
			commitRevisionConn(t, s, conn, "alice")
			called, locked := false, false
			s.setConnCancel(conn, func() {
				called = true
				if s.mu.TryLock() {
					s.mu.Unlock()
				} else {
					locked = true
				}
			})
			tc.update(s, info)
			if !called || locked {
				t.Fatalf("cancellation callback called=%t while holding server lock=%t", called, locked)
			}
		})
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

func TestUserRevisionKeyMarshalOutsideLock(t *testing.T) {
	_, first := testClientKey(t)
	_, second := testClientKey(t)
	for _, tc := range []struct {
		name   string
		update func(*Server, UserInfo, ssh.PublicKey)
	}{
		{name: "equivalent user", update: func(s *Server, u UserInfo, _ ssh.PublicKey) { s.AddUser("alice", u) }},
		{name: "add key", update: func(s *Server, _ UserInfo, k ssh.PublicKey) { s.AddUserKey("alice", k) }},
		{name: "remove missing key", update: func(s *Server, _ UserInfo, k ssh.PublicKey) { s.RemoveUserKey("alice", k) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(&Config{})
			calls, locked := 0, false
			observe := func() {
				calls++
				if s.mu.TryLock() {
					s.mu.Unlock()
				} else {
					locked = true
				}
			}
			info := revisionUser(t, []ssh.PublicKey{revisionObservedKey{PublicKey: first, onMarshal: observe}})
			s.AddUser("alice", info)
			calls = 0
			tc.update(s, info, revisionObservedKey{PublicKey: second, onMarshal: observe})
			if calls == 0 || locked {
				t.Fatalf("key Marshal calls=%d while holding server lock=%t", calls, locked)
			}
		})
	}
}

func TestUserRevisionConcurrentEquivalentUpdates(t *testing.T) {
	_, key := testClientKey(t)
	info := revisionUser(t, []ssh.PublicKey{key})
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": info}})
	_, before, _ := s.userSnapshot("alice")
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 10 {
				s.AddUser("alice", info)
			}
		})
	}
	workers.Wait()
	if _, after, _ := s.userSnapshot("alice"); after != before {
		t.Fatalf("equivalent concurrent updates changed revision %d -> %d", before, after)
	}
}

func TestUserRevisionRetriesConcurrentChanges(t *testing.T) {
	_, first := testClientKey(t)
	_, second := testClientKey(t)
	for _, tc := range []struct {
		name         string
		update       func(*Server, UserInfo)
		wantOld      bool
		wantSecond   bool
		wantPassword string
	}{
		{name: "replace user", update: func(s *Server, u UserInfo) { s.AddUser("alice", u) }, wantOld: true, wantPassword: "pw"},
		{name: "add key", update: func(s *Server, _ UserInfo) { s.AddUserKey("alice", second) }, wantOld: true, wantSecond: true, wantPassword: "changed"},
		{name: "remove key", update: func(s *Server, _ UserInfo) { s.RemoveUserKey("alice", first) }, wantPassword: "changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkRevisionRetry(t, first, second, tc.update, tc.wantOld, tc.wantSecond, tc.wantPassword)
		})
	}
}

func checkRevisionRetry(t *testing.T, first, second ssh.PublicKey, update func(*Server, UserInfo), wantOld, wantSecond bool, wantPassword string) {
	t.Helper()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var blocked atomic.Bool
	observed := revisionObservedKey{PublicKey: first, onMarshal: func() {
		if blocked.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
	}}
	original := revisionUser(t, []ssh.PublicKey{observed})
	s := NewServer(&Config{Users: map[string]UserInfo{"alice": original}})
	_, before, _ := s.userSnapshot("alice")
	original.AuthorizedKeys = []ssh.PublicKey{first}
	go func() {
		defer close(done)
		update(s, original)
	}()
	waitRevisionSignal(t, entered, "key comparison did not start")
	if !s.mu.TryLock() {
		t.Fatal("key comparison held server lock")
	}
	s.mu.Unlock()
	changed := original
	changed.Password = "changed"
	s.AddUser("alice", changed)
	_, intermediate, _ := s.userSnapshot("alice")
	unblock()
	waitRevisionSignal(t, done, "concurrent update did not finish")
	current, after, _ := s.userSnapshot("alice")
	if after == before || after == intermediate {
		t.Fatalf("update reused stale revision: %d -> %d -> %d", before, intermediate, after)
	}
	if matchAuthorizedKey(current.AuthorizedKeys, first) != wantOld || matchAuthorizedKey(current.AuthorizedKeys, second) != wantSecond {
		t.Fatal("retry applied key update to the wrong snapshot")
	}
	if current.Password != wantPassword {
		t.Fatalf("retry password=%q; want %q", current.Password, wantPassword)
	}
}

func waitRevisionSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}
