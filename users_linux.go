//go:build linux

package ironport

import (
	"crypto/subtle"
	"slices"

	"golang.org/x/crypto/ssh"
)

// UserInfo holds the credentials and jail root for a single SFTP/FTP user.
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

func (s *Server) userSnapshot(username string) (UserInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return UserInfo{}, false
	}
	return cloneUserInfo(u), true
}

// AddUser adds or replaces a user entry in the server's user map.
// It is safe to call concurrently with active connections.
func (s *Server) AddUser(username string, info UserInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users == nil {
		s.users = make(map[string]UserInfo)
	}
	s.users[username] = cloneUserInfo(info)
}

// RemoveUser removes a user entry from the server's user map and force-closes
// any connections currently authenticated as that user, so an in-flight
// session cannot keep operating after its credentials have been revoked.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveUser(username string) {
	s.mu.Lock()
	delete(s.users, username)
	var toClose []func()
	for nc, u := range s.activeConns {
		if u == username {
			toClose = append(toClose, s.cancelConnLocked(nc))
		}
	}
	s.mu.Unlock()
	for _, closeConn := range toClose {
		closeConn()
	}
}

// RemoveAllUsers removes every user entry from the server's user map and
// force-closes any connections currently authenticated as one of those users.
// Connections that have not yet completed authentication are left alone so
// they can either finish authenticating against the (now empty) user map or
// be rejected by it. No on-disk user data is removed.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveAllUsers() {
	s.mu.Lock()
	s.users = make(map[string]UserInfo)
	var toClose []func()
	for nc, u := range s.activeConns {
		if u != "" {
			toClose = append(toClose, s.cancelConnLocked(nc))
		}
	}
	s.mu.Unlock()
	for _, closeConn := range toClose {
		closeConn()
	}
}

// AddUserKey appends key to the AuthorizedKeys of an existing user.
// If the key is already present (by wire-format equality) it is not added again.
// It is a no-op when username does not exist or key is nil.
// It is safe to call concurrently with active connections.
func (s *Server) AddUserKey(username string, key ssh.PublicKey) {
	if key == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return
	}
	keys := slices.Clone(u.AuthorizedKeys)
	keyBytes := key.Marshal()
	for _, existing := range keys {
		if existing == nil {
			continue
		}
		if subtle.ConstantTimeCompare(keyBytes, existing.Marshal()) == 1 {
			return // already present
		}
	}
	keys = append(keys, key)
	u.AuthorizedKeys = keys
	s.users[username] = u
}

// RemoveUserKey removes key from the AuthorizedKeys of an existing user.
// It is a no-op when username does not exist, the key is not found, or key is nil.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveUserKey(username string, key ssh.PublicKey) {
	if key == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return
	}
	keyBytes := key.Marshal()
	var filtered []ssh.PublicKey
	for _, existing := range u.AuthorizedKeys {
		if existing == nil {
			continue
		}
		if subtle.ConstantTimeCompare(keyBytes, existing.Marshal()) != 1 {
			filtered = append(filtered, existing)
		}
	}
	u.AuthorizedKeys = filtered
	s.users[username] = u
}
