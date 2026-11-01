//go:build linux

package ironport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"

	"github.com/define42/ironport/internal/jailfs"
	"golang.org/x/crypto/ssh"
)

// errInvalidCredentials is returned by SSH auth callbacks when authentication
// is rejected. Returning a single sentinel keeps the response identical
// regardless of which step failed (unknown user, wrong password/key, or
// jail-root resolution), so a client cannot distinguish the cases by error
// text.
var errInvalidCredentials = errors.New("invalid credentials")

// NewSignerFromFile reads a PEM-encoded private key from the given file path
// and returns an ssh.Signer suitable for use as a server host key.
// It supports any key type accepted by ssh.ParsePrivateKey (RSA, ECDSA, Ed25519).
func NewSignerFromFile(path string) (ssh.Signer, error) {
	// The path is supplied by the caller (operator-controlled), which is the
	// documented contract of this helper.
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied host-key path
	if err != nil {
		return nil, fmt.Errorf("read host key %q: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse host key %q: %w", path, err)
	}
	return signer, nil
}

func generateEphemeralSigner() (ssh.Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, ephemeralHostKeyBits)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

func (s *Server) ensureSigner() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sftpSigner != nil {
		return nil
	}
	signer, err := generateEphemeralSigner()
	if err != nil {
		return fmt.Errorf("generate ephemeral host key: %w", err)
	}
	s.sftpSigner = signer
	return nil
}

// permissionsFor builds the ssh.Permissions for an authenticated user,
// embedding the jail root and access flags as extensions so that the
// connection handler can retrieve them after the handshake.
func permissionsFor(u UserInfo, username, jailRoot string) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			"jailRoot": jailRoot,
			"user":     username,
			"canRead":  fmt.Sprintf("%v", u.CanRead),
			"canWrite": fmt.Sprintf("%v", u.CanWrite),
		},
	}
}

// checkPassword performs a SHA-256-normalized constant-time comparison between
// stored and supplied passwords, and rejects empty stored/supplied credentials.
func checkPassword(storedPw, suppliedPw string) bool {
	storedHash := sha256.Sum256([]byte(storedPw))
	suppliedHash := sha256.Sum256([]byte(suppliedPw))
	match := subtle.ConstantTimeCompare(storedHash[:], suppliedHash[:]) == 1
	return match && len(storedPw) > 0 && len(suppliedPw) > 0
}

// authenticateUser performs the credential check shared by SFTP, FTP, and
// HTTP. It returns a cloned user, canonical jail-root path, and revision.
// The final revision check linearizes HTTP authentication with user updates;
// connection protocols must also commit that revision before starting a session.
// ok is false when credentials, root validation, or the revision check fail;
// callers should not distinguish those cases when replying to clients, to avoid
// leaking which step failed.
//
// keyCheck supplies the matching logic so the SSH PasswordCallback can pass a
// password comparator and the PublicKeyCallback can pass a constant-time-padded
// key comparator. keyCheck receives the zero-value UserInfo when the user is
// unknown, so it MUST be constant-time (independent of stored password length
// and AuthorizedKeys count) to avoid leaking username existence; checkPassword
// and the public-key timing pad already satisfy this.
func (s *Server) authenticateUser(username string, keyCheck func(stored UserInfo) bool) (UserInfo, string, uint64, bool) {
	u, revision, ok := s.userSnapshot(username)
	if !keyCheck(u) || !ok {
		return UserInfo{}, "", 0, false
	}
	jailRoot, err := jailfs.CanonicalRoot(u.Root)
	if err != nil {
		return UserInfo{}, "", 0, false
	}
	if !s.userRevisionMatches(username, revision) {
		return UserInfo{}, "", 0, false
	}
	return u, jailRoot, revision, true
}

// matchAuthorizedKey reports whether the presented SSH public key matches any
// entry in authorizedKeys. The comparison is constant-time on a fixed
// SHA-256 hash, and the total iteration count is padded out to
// authorizedKeyTimingPad so the response time does not leak (a) whether the
// user exists, (b) the position of a matching key, or (c) the number of keys
// the user has configured (up to the pad constant).
func matchAuthorizedKey(authorizedKeys []ssh.PublicKey, presented ssh.PublicKey) bool {
	presentedMarshaled := presented.Marshal()
	keyHash := sha256.Sum256(presentedMarshaled)
	matched := false
	compares := 0
	for _, authorizedKey := range authorizedKeys {
		if authorizedKey == nil {
			continue
		}
		authHash := sha256.Sum256(authorizedKey.Marshal())
		if subtle.ConstantTimeCompare(keyHash[:], authHash[:]) == 1 {
			matched = true
		}
		compares++
	}
	// Pad with dummy iterations until the loop has executed a fixed number
	// of times, independent of len(AuthorizedKeys). Each padding iteration
	// reproduces the full per-key cost of a real iteration — a SHA-256 over
	// a buffer the size of a marshalled key plus a constant-time compare —
	// because that hashing cost dominates and would otherwise let response
	// time scale with the user's key count (including the zero-key case for
	// an unknown user), leaking username existence. The padding hash can
	// never set matched: its result is discarded.
	for ; compares < authorizedKeyTimingPad; compares++ {
		dummyHash := sha256.Sum256(presentedMarshaled)
		_ = subtle.ConstantTimeCompare(keyHash[:], dummyHash[:])
	}
	return matched
}
