//go:build linux

package ironport

import (
	"net"

	"github.com/define42/ironport/internal/authlimit"
	"github.com/define42/ironport/internal/jailfs"
	"github.com/define42/ironport/internal/netconn"
	"golang.org/x/crypto/ssh"
)

type sshRevisionKey struct{}

type sshJailFSKey struct{}

type sshAdmissionKey struct{}

// sshAuthState owns a password or verified-key callback's provisional jail
// until the completed handshake commits it. SSH invokes callbacks sequentially,
// before any session starts. Unsigned queries own no jail; subsequent callbacks
// and failed handshakes close any previously retained jail.
type sshAuthState struct {
	fs       *jailfs.FS
	username string
	revision uint64
}

func (a *sshAuthState) close() {
	if a.fs != nil {
		_ = a.fs.Close()
	}
	a.fs, a.username, a.revision = nil, "", 0
}

func (a *sshAuthState) record(username string, permissions *ssh.Permissions, err error) (*ssh.Permissions, error) {
	var fs *jailfs.FS
	var revision uint64
	if permissions != nil {
		fs, _ = permissions.ExtraData[sshJailFSKey{}].(*jailfs.FS)
		revision, _ = permissions.ExtraData[sshRevisionKey{}].(uint64)
	}
	if a.fs != fs {
		a.close()
	}
	a.fs, a.username, a.revision = fs, username, revision
	if err != nil {
		a.close()
	}
	return permissions, err
}

// config keeps ownership local to one handshake while preserving the shared
// server configuration and any callback wrappers installed by the caller.
// Any additional authentication callback must also pass its result to record.
func (a *sshAuthState) config(base *ssh.ServerConfig) *ssh.ServerConfig {
	cfg := *base
	if callback := base.PasswordCallback; callback != nil {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			permissions, err := callback(c, password)
			return a.record(c.User(), permissions, err)
		}
	}
	if callback := base.PublicKeyCallback; callback != nil {
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			permissions, err := callback(c, key)
			return a.record(c.User(), permissions, err)
		}
	}
	if callback := base.VerifiedPublicKeyCallback; callback != nil {
		cfg.VerifiedPublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey, query *ssh.Permissions, algorithm string) (*ssh.Permissions, error) {
			permissions, err := callback(c, key, query, algorithm)
			return a.record(c.User(), permissions, err)
		}
	}
	return &cfg
}

// commitSSHConnection transfers only the exact authentication snapshot and
// opened jail that completed this handshake. Revocation produces no session.
func (s *Server) commitSSHConnection(nc net.Conn, conn *ssh.ServerConn, state *sshAuthState, events chan<- AuthEvent) (*jailfs.FS, bool) {
	var attempt authlimit.Attempt
	if conn.Permissions != nil {
		attempt, _ = conn.Permissions.ExtraData[sshAdmissionKey{}].(authlimit.Attempt)
		fs, _ := conn.Permissions.ExtraData[sshJailFSKey{}].(*jailfs.FS)
		revision, _ := conn.Permissions.ExtraData[sshRevisionKey{}].(uint64)
		user := conn.Permissions.Extensions["user"]
		if fs != nil && fs == state.fs && user == conn.User() && user == state.username && revision == state.revision && s.commitConnUser(nc, user, revision) {
			state.fs = nil
			return fs, true
		}
	}
	s.authFailed(attempt, conn.User(), netconn.RemoteIP(conn.RemoteAddr()), CompletedUploadProtocolSFTP, events, false)
	return nil, false
}
