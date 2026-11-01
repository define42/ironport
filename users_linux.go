//go:build linux

package ironport

import (
	"crypto/subtle"
	"slices"

	"golang.org/x/crypto/ssh"
)

// UserInfo holds the credentials and jail root for a single SFTP/FTP/HTTP user.
// Root must name an existing directory when authenticating. Symlinks in any
// configured root component and literal ".." components are rejected. Relative
// roots are resolved from the working directory at authentication time.
type UserInfo struct {
	Password       string
	AuthorizedKeys []ssh.PublicKey // public keys allowed for SFTP authentication; nil or empty means public-key auth is disabled for this user
	Root           string          // jail root on disk, e.g. /srv/sftp/alice
	CanRead        bool            // allow read/download/list operations
	CanWrite       bool            // allow write/upload/delete/rename operations
}

func cloneUserInfo(u UserInfo) UserInfo {
	u.AuthorizedKeys = slices.Clone(u.AuthorizedKeys)
	return u
}

// sameUserAuthentication compares effective authentication rather than public
// key object identity or slice layout. Keys are an unordered set of wire-format
// values; duplicates and nil entries do not change which keys may authenticate.
// Call without s.mu: application-provided PublicKey.Marshal methods may block
// or call back into the server.
func sameUserAuthentication(a, b UserInfo) bool {
	if a.Password != b.Password || a.Root != b.Root || a.CanRead != b.CanRead || a.CanWrite != b.CanWrite {
		return false
	}
	return slices.Equal(authorizedKeyValues(a.AuthorizedKeys), authorizedKeyValues(b.AuthorizedKeys))
}

func authorizedKeyValues(keys []ssh.PublicKey) []string {
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if key != nil {
			values = append(values, string(key.Marshal()))
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

// replaceUser publishes a cloned configuration and changes its revision only
// when authentication actually changes. An effective change also marks every
// authenticated connection for that user as canceled at the same
// linearization point. The caller closes those connections after the lock is
// released. The comparison runs outside the lock; retrying after a concurrent
// revision change preserves atomic update/commit semantics, including
// remove-and-readd of an otherwise identical user.
func (s *Server) replaceUser(username string, info UserInfo) []func() {
	info = cloneUserInfo(info)
	for {
		s.mu.RLock()
		previous, existed := s.users[username]
		previous = cloneUserInfo(previous)
		revision := s.userRevisions[username]
		s.mu.RUnlock()
		unchanged := existed && revision != 0 && sameUserAuthentication(previous, info)

		s.mu.Lock()
		_, exists := s.users[username]
		if exists != existed || s.userRevisions[username] != revision {
			s.mu.Unlock()
			continue
		}
		if s.users == nil {
			s.users = make(map[string]UserInfo)
		}
		s.users[username] = info
		var toClose []func()
		if !unchanged {
			s.bumpUserRevisionLocked(username)
			toClose = s.cancelUserConnsLocked(username)
		}
		s.mu.Unlock()
		return toClose
	}
}

func cloneUsers(users map[string]UserInfo) map[string]UserInfo {
	if users == nil {
		return nil
	}
	cloned := make(map[string]UserInfo, len(users))
	for username, info := range users {
		cloned[username] = cloneUserInfo(info)
	}
	return cloned
}

func (s *Server) userSnapshot(username string) (UserInfo, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return UserInfo{}, 0, false
	}
	revision, ok := s.userRevisions[username]
	if !ok {
		return UserInfo{}, 0, false
	}
	return cloneUserInfo(u), revision, true
}

// bumpUserRevisionLocked assigns a server-lifetime-unique revision to the
// current value of username. The caller must hold s.mu for writing unless
// initializing the server before publication.
func (s *Server) bumpUserRevisionLocked(username string) uint64 {
	s.nextUserRevision++
	if s.nextUserRevision == 0 {
		panic("ironport: user revision counter exhausted")
	}
	if s.userRevisions == nil {
		s.userRevisions = make(map[string]uint64)
	}
	s.userRevisions[username] = s.nextUserRevision
	return s.nextUserRevision
}

func (s *Server) userRevisionMatches(username string, revision uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.users[username]
	return exists && revision != 0 && s.userRevisions[username] == revision
}

// AddUser adds or replaces a user entry in the server's user map.
// An effective change to credentials, root, or permissions invalidates pending
// logins and closes the user's established SFTP/FTP sessions. Equivalent
// replacements preserve sessions; authorized keys are compared as sets of
// wire-format values, ignoring order, duplicates, and nil entries.
// It is safe to call concurrently with active connections.
func (s *Server) AddUser(username string, info UserInfo) {
	toClose := s.replaceUser(username, info)
	closeConns(toClose)
}

// RemoveUser removes a user and closes their authenticated SFTP/FTP connections,
// including FTP data operations. Pending logins using the old user are rejected.
// HTTP requests already authorized continue; subsequent authentication fails.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveUser(username string) {
	s.mu.Lock()
	delete(s.users, username)
	delete(s.userRevisions, username)
	toClose := s.cancelUserConnsLocked(username)
	s.mu.Unlock()
	closeConns(toClose)
}

// RemoveAllUsers removes every user and closes their authenticated SFTP/FTP
// connections. Pending logins cannot commit their old authentication snapshots,
// even if the same users are added again. Already-authorized HTTP requests
// continue, and no on-disk user data is removed.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveAllUsers() {
	s.mu.Lock()
	s.users = make(map[string]UserInfo)
	s.userRevisions = make(map[string]uint64)
	var toClose []func()
	for nc, state := range s.activeConns {
		if state.authenticated {
			toClose = append(toClose, s.cancelConnLocked(nc))
		}
	}
	s.mu.Unlock()
	closeConns(toClose)
}

// AddUserKey appends key to the AuthorizedKeys of an existing user.
// If the key is already present (by wire-format equality) it is not added again.
// It is a no-op when username does not exist or key is nil.
// Adding a key does not revoke authority held by an existing session, so active
// sessions are left connected. The revision still changes to linearize the new
// authentication configuration with logins already in flight.
// It is safe to call concurrently with active connections.
func (s *Server) AddUserKey(username string, key ssh.PublicKey) {
	if key == nil {
		return
	}
	keyBytes := key.Marshal()
	for {
		s.mu.RLock()
		u, ok := s.users[username]
		u = cloneUserInfo(u)
		revision := s.userRevisions[username]
		s.mu.RUnlock()
		if !ok {
			return
		}
		if containsAuthorizedKey(u.AuthorizedKeys, keyBytes) {
			if s.userRevisionMatches(username, revision) {
				return
			}
			continue
		}
		u.AuthorizedKeys = append(u.AuthorizedKeys, key)

		s.mu.Lock()
		_, exists := s.users[username]
		if !exists || s.userRevisions[username] != revision {
			s.mu.Unlock()
			continue
		}
		s.users[username] = u
		s.bumpUserRevisionLocked(username)
		s.mu.Unlock()
		return
	}
}

// RemoveUserKey removes key from the AuthorizedKeys of an existing user.
// It is a no-op when username does not exist, the key is not found, or key is nil.
// Removing an effective key disconnects that user's established SFTP/FTP
// sessions so a compromised credential cannot retain access through an old
// session. No-op removals leave existing sessions untouched.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveUserKey(username string, key ssh.PublicKey) {
	if key == nil {
		return
	}
	keyBytes := key.Marshal()
	for {
		s.mu.RLock()
		u, ok := s.users[username]
		u = cloneUserInfo(u)
		revision := s.userRevisions[username]
		s.mu.RUnlock()
		if !ok {
			return
		}

		filtered := withoutAuthorizedKey(u.AuthorizedKeys, keyBytes)
		if len(filtered) == len(u.AuthorizedKeys) {
			if s.userRevisionMatches(username, revision) {
				return
			}
			continue
		}
		u.AuthorizedKeys = filtered

		s.mu.Lock()
		_, exists := s.users[username]
		if !exists || s.userRevisions[username] != revision {
			s.mu.Unlock()
			continue
		}
		s.users[username] = u
		s.bumpUserRevisionLocked(username)
		toClose := s.cancelUserConnsLocked(username)
		s.mu.Unlock()
		closeConns(toClose)
		return
	}
}

// These key comparisons run outside s.mu because Marshal may call application code.
func containsAuthorizedKey(keys []ssh.PublicKey, keyBytes []byte) bool {
	for _, existing := range keys {
		if existing != nil && subtle.ConstantTimeCompare(keyBytes, existing.Marshal()) == 1 {
			return true
		}
	}
	return false
}

func withoutAuthorizedKey(keys []ssh.PublicKey, keyBytes []byte) []ssh.PublicKey {
	filtered := make([]ssh.PublicKey, 0, len(keys))
	for _, existing := range keys {
		if existing != nil && subtle.ConstantTimeCompare(keyBytes, existing.Marshal()) == 1 {
			continue
		}
		filtered = append(filtered, existing)
	}
	return filtered
}
