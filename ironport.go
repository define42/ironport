//go:build linux

// Package ironport provides an embeddable, security-hardened SFTP and FTP server.
//
// Core features:
//
//   - Per-user jail roots enforced via path resolution and symlink checks.
//   - Password and SSH public-key authentication with constant-time comparisons.
//   - Fine-grained CanRead / CanWrite per-user permission flags.
//   - Runtime user management (AddUser, RemoveUser, RemoveAllUsers, AddUserKey, RemoveUserKey).
//   - Optional SSH algorithm pinning for key exchange, ciphers, MACs, and public-key auth signatures.
//   - Graceful shutdown via Close; upload-completion notifications via CompletedUploads;
//     authentication/session notifications via AuthEvents.
//   - Optional FTP listener sharing the same users, jails, permissions,
//     temp-extension handling, CompletedUploads stream, and AuthEvents stream as SFTP.
//     FTP uses passive mode by default; active mode can be enabled explicitly.
//
// Typical usage:
//
//	cfg := ironport.DefaultConfig()
//	cfg.SftpAddr = ":2022"
//	cfg.FtpAddr = ":2121"
//	cfg.Users = users
//	cfg.SftpSigner = signer
//	srv := ironport.NewServer(cfg)
//	log.Fatal(srv.ListenAndServe())
package ironport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// Default timeouts and limits applied unless callers override them.
const (
	// defaultSFTPIdleTimeout is the default per-connection inactivity timeout
	// applied to SFTP sessions when Config.IdleTimeout is zero. A client that
	// sends no data for this duration has its connection closed.
	defaultSFTPIdleTimeout = 15 * time.Minute
	// sshHandshakeTimeout bounds the time the raw TCP connection has to
	// complete the SSH handshake before being dropped.
	sshHandshakeTimeout = 30 * time.Second
	// ftpMaxControlLineLen caps the size of a single FTP control command in
	// bytes (including the CRLF terminator). Longer commands are rejected to
	// prevent unbounded memory growth from malicious clients.
	ftpMaxControlLineLen = 4096
	// ftpDataIdleTimeout bounds how long an FTP data connection may sit
	// without transferring any bytes before being considered stalled. A
	// stalled transfer surfaces as a read error from io.Copy, which in turn
	// suppresses the CompletedUpload notification for a STOR/APPE that did
	// not finish cleanly.
	ftpDataIdleTimeout = 5 * time.Minute
	// defaultFTPDataAcceptTimeout bounds how long a passive-mode FTP data
	// listener waits after PASV/EPSV and how long an active-mode FTP dial may
	// take after PORT/EPRT.
	defaultFTPDataAcceptTimeout = 30 * time.Second
	// defaultCompletedUploadsSize is the fallback buffer size used for the
	// CompletedUploads channel.
	defaultCompletedUploadsSize = 64
	// defaultAuthEventsSize is the fallback buffer size used for the
	// AuthEvents channel.
	defaultAuthEventsSize = 64
	// ephemeralHostKeyBits is the size of the in-memory RSA host key generated
	// when a server is started without an explicit signer.
	ephemeralHostKeyBits = 3072
	// authorizedKeyTimingPad is the minimum number of constant-time key
	// comparisons performed by the public-key auth callback. Users with
	// fewer AuthorizedKeys are padded with dummy comparisons up to this
	// count so the response time does not leak how many keys a particular
	// user has configured. Users with more than this many keys still take
	// longer; tune upward if a deployment routinely exceeds it.
	authorizedKeyTimingPad = 32
	// defaultTCPKeepAlivePeriod is the SO_KEEPALIVE idle period applied
	// to accepted control connections when Config.TCPKeepAlivePeriod
	// is zero. Keepalive probes prevent stateful firewalls and NAT devices
	// from silently dropping long-idle control connections, and surface
	// half-open connections (e.g. peer reboot, route loss) as read errors
	// instead of leaving handler goroutines blocked indefinitely.
	defaultTCPKeepAlivePeriod = 30 * time.Second
)

const (
	// CompletedUploadProtocolSFTP identifies an upload completed through SFTP.
	CompletedUploadProtocolSFTP = "SFTP"
	// CompletedUploadProtocolFTP identifies an upload completed through FTP.
	CompletedUploadProtocolFTP = "FTP"
)

type AuthEventType string

const (
	// AuthEventLoginSuccess identifies a successful user login.
	AuthEventLoginSuccess AuthEventType = "LoginSuccess"
	// AuthEventLoginFailed identifies a rejected user login attempt.
	AuthEventLoginFailed AuthEventType = "LoginFailed"
	// AuthEventLogout identifies the end of an authenticated session.
	AuthEventLogout AuthEventType = "Logout"
)

// errFTPLineTooLong is returned when an FTP client sends a control-channel
// command that exceeds ftpMaxControlLineLen bytes.
var errFTPLineTooLong = errors.New("ftp control line too long")

// errSFTPRequestFailed is returned to SFTP clients for unknown backend errors
// so internal paths and server details are not exposed.
var errSFTPRequestFailed = errors.New("request failed")

// errInvalidCredentials is returned by SSH auth callbacks when authentication
// is rejected. Returning a single sentinel keeps the response identical
// regardless of which step failed (unknown user, wrong password/key, or
// jail-root resolution), so a client cannot distinguish the cases by error
// text.
var errInvalidCredentials = errors.New("invalid credentials")

// publishUpload sends evt to uploads without blocking the caller. When the
// channel buffer is full the event is dropped and a single line is logged so
// operators can spot a slow consumer.
func publishUpload(uploads chan<- CompletedUpload, evt CompletedUpload) {
	if uploads == nil {
		return
	}
	select {
	case uploads <- evt:
	default:
		log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", evt.FilePath)
	}
}

// maybeAnnounceTempRename publishes a CompletedUpload event when a file is
// renamed from a temp-suffixed name to a non-temp name (matching is
// case-insensitive and the extension list comes from Config.TempExtensions).
// It is a no-op in every other case, so both protocols share the same
// "rename completes an upload" decision and log line.
func maybeAnnounceTempRename(uploads chan<- CompletedUpload, tempExts []string, oldPath string, evt CompletedUpload) {
	if !hasTempExt(oldPath, tempExts) || hasTempExt(evt.FilePath, tempExts) {
		return
	}
	log.Printf("upload complete via rename: %q -> %q", oldPath, evt.FilePath)
	publishUpload(uploads, evt)
}

// resolveDur applies the package-wide "configured duration" rule: zero selects
// defaultV, a negative value disables the deadline (returns 0), any other
// value is honoured as-is.
func resolveDur(configured, defaultV time.Duration) time.Duration {
	switch {
	case configured == 0:
		return defaultV
	case configured < 0:
		return 0
	}
	return configured
}

// idleConn wraps a net.Conn and resets the read and/or write deadlines
// before each Read/Write so that a connection is closed when no data has
// moved in the configured direction within the configured idle timeout.
// A timeout of zero in either direction disables the corresponding
// deadline; the two directions are independent so callers can apply an
// idle deadline only on the side they actually use.
type idleConn struct {
	net.Conn
	readTimeoutNs  atomic.Int64
	writeTimeoutNs atomic.Int64
}

func (c *idleConn) Read(b []byte) (int, error) {
	if d := time.Duration(c.readTimeoutNs.Load()); d > 0 {
		_ = c.SetReadDeadline(time.Now().Add(d))
	} else {
		_ = c.SetReadDeadline(time.Time{})
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if d := time.Duration(c.writeTimeoutNs.Load()); d > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(d))
	} else {
		_ = c.SetWriteDeadline(time.Time{})
	}
	return c.Conn.Write(b)
}

// setReadTimeout configures the per-Read idle deadline. A zero or
// negative value disables it.
func (c *idleConn) setReadTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.readTimeoutNs.Store(int64(d))
}

// setWriteTimeout configures the per-Write idle deadline. A zero or
// negative value disables it.
func (c *idleConn) setWriteTimeout(d time.Duration) {
	if d < 0 {
		d = 0
	}
	c.writeTimeoutNs.Store(int64(d))
}

// ftpErrMsg maps an internal error to a generic, client-safe FTP reply
// message. Raw os/syscall errors are not exposed to clients because they
// often include absolute on-disk paths or other server-side details that
// would leak filesystem layout.
func ftpErrMsg(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, errFTPLineTooLong):
		return "command line too long"
	case errors.Is(err, syscall.ENOTEMPTY):
		return "directory not empty"
	case errors.Is(err, syscall.EISDIR):
		return "is a directory"
	case errors.Is(err, syscall.ENOTDIR):
		return "not a directory"
	case errors.Is(err, syscall.EINVAL):
		return "invalid argument"
	case errors.Is(err, os.ErrNotExist):
		return "no such file or directory"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	case errors.Is(err, os.ErrExist):
		return "file exists"
	}
	return "request failed"
}

// sanitizeSFTPErr maps backend filesystem errors to safe, path-free sentinel
// errors before they are returned to SFTP clients.
func sanitizeSFTPErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ENOTEMPTY):
		return syscall.ENOTEMPTY
	case errors.Is(err, syscall.EISDIR):
		return syscall.EISDIR
	case errors.Is(err, syscall.ENOTDIR):
		return syscall.ENOTDIR
	case errors.Is(err, syscall.EINVAL):
		return syscall.EINVAL
	case errors.Is(err, os.ErrNotExist):
		return os.ErrNotExist
	case errors.Is(err, os.ErrPermission):
		return os.ErrPermission
	case errors.Is(err, os.ErrExist):
		return os.ErrExist
	}
	return errSFTPRequestFailed
}

// hasCRLF reports whether s contains a CR or LF byte. Used to reject
// client-supplied filenames that, if accepted, would let a later listing or
// path-echoing reply inject fake FTP control-channel lines.
func hasCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// sanitizeFTPText returns s with every ASCII control byte (0x00–0x1F, 0x7F)
// replaced by '?'. Defense in depth for filenames that reach the FTP control
// channel (257 replies) or the LIST/NLST data channel: even if a control byte
// slips past the write-time guards (e.g. file created out-of-band), it cannot
// forge reply lines or corrupt line-oriented listing output.
func sanitizeFTPText(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7F {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c == 0x7F {
			b[i] = '?'
		}
	}
	return string(b)
}

// NewSignerFromFile reads a PEM-encoded private key from the given file path
// and returns an ssh.Signer suitable for use as a server host key.
// It supports any key type accepted by ssh.ParsePrivateKey (RSA, ECDSA, Ed25519).
func NewSignerFromFile(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host key %q: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse host key %q: %w", path, err)
	}
	return signer, nil
}

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

func normalizeTempExtensions(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, 0, len(src))
	for _, ext := range src {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		out = append(out, ext)
	}
	return out
}

// CompletedUpload describes a file upload that has finished successfully.
// It is the payload delivered on the server's CompletedUploads stream.
type CompletedUpload struct {
	// Username is the authenticated SFTP/FTP user that performed the upload.
	Username string
	// FullFilePath is the absolute path of the uploaded file on the server's
	// local filesystem (i.e. resolved through the user's jail root).
	FullFilePath string
	// FilePath is the file path as seen by the client, relative to the
	// user's jail root (e.g. "/incoming/foo.txt").
	FilePath string
	// ClientIP is the remote IP address of the client that performed
	// the upload, without the port. It is empty if the address could not
	// be parsed.
	ClientIP string
	// Protocol is the file-transfer protocol used for the upload.
	// It is either CompletedUploadProtocolSFTP or CompletedUploadProtocolFTP.
	Protocol string
}

// AuthEvent describes an authentication or session-lifecycle event.
// It is the payload delivered on the server's AuthEvents stream.
type AuthEvent struct {
	// Type is the authentication event kind.
	Type AuthEventType
	// Username is the username supplied by the client for this event.
	Username string
	// ClientIP is the remote IP address of the client, without the port. It is
	// empty if the address could not be parsed.
	ClientIP string
	// Protocol is the file-transfer protocol used for the event.
	// It is either CompletedUploadProtocolSFTP or CompletedUploadProtocolFTP.
	Protocol string
}

// Server is a self-contained SFTP server with optional FTP support.
type Server struct {
	// addr is the TCP address to listen on for SFTP, e.g. ":2022".
	addr string
	// ftpAddr is the TCP address to listen on for FTP, e.g. ":2121".
	// Set it to "" to disable FTP.
	ftpAddr string
	// ftpPassivePortRange optionally constrains FTP passive-mode data listeners
	// to a single port or inclusive range such as "5000-5010". Leave it empty
	// to let the OS choose any available port.
	ftpPassivePortRange string
	// ftpDataAcceptTimeout bounds how long passive-mode FTP data listeners wait
	// after PASV/EPSV and how long active-mode FTP dials may take after
	// PORT/EPRT. Zero selects the package default; negative disables the deadline.
	ftpDataAcceptTimeout time.Duration
	// ftpAllowActiveMode controls whether FTP PORT/EPRT commands may ask the
	// server to dial an active-mode data connection back to the client IP.
	ftpAllowActiveMode bool
	// users maps usernames to their credentials and jail roots.
	users map[string]UserInfo
	// mu protects users, completedUploads, authEvents, and listeners for concurrent reads and writes.
	mu sync.RWMutex
	// ln is the active SFTP listener; set by ListenAndServe and closed by Close.
	ln net.Listener
	// ftpLn is the active FTP listener; set by ListenAndServe and closed by Close.
	ftpLn net.Listener
	// serveID increments for each ListenAndServe invocation so cleanup from an
	// older run cannot clear listeners published by a restarted run.
	serveID uint64
	// serving is true while a ListenAndServe invocation is starting or has
	// active listeners. Close clears it after closing the current listeners,
	// allowing a new ListenAndServe call while older in-flight sessions drain.
	serving bool
	// sftpSigner is the host key used for the SSH handshake.
	sftpSigner ssh.Signer
	// SSH algorithm allow-lists. Nil slices use golang.org/x/crypto/ssh
	// defaults.
	sshKeyExchanges            []string
	sshCiphers                 []string
	sshMACs                    []string
	sshPublicKeyAuthAlgorithms []string
	// completedUploads receives upload notifications. Use CompletedUploads to
	// access it as a receive-only stream.
	completedUploads chan CompletedUpload
	// authEvents receives authentication/session notifications. Use AuthEvents
	// to access it as a receive-only stream.
	authEvents chan AuthEvent
	// tempExtensions is an optional list of file extensions (each beginning
	// with a leading dot, e.g. ".tmp", ".writing") that mark files as still
	// being written and therefore not yet "complete".
	//
	// When set:
	//   - A successful upload whose filename ends with one of these
	//     extensions is NOT announced on CompletedUploads.
	//   - When a file is renamed from a name ending with one of these
	//     extensions to a name that does NOT end with any of them, the new
	//     path is announced on CompletedUploads, signalling that the upload
	//     is finally complete.
	//
	// Matching is case-insensitive.
	tempExtensions []string
	// idleTimeout bounds how long an authenticated SFTP connection may sit
	// without receiving any data before being closed. A zero value selects
	// the package default (15 minutes); a negative value disables the idle
	// timeout entirely.
	idleTimeout time.Duration
	// tcpKeepAlivePeriod is the SO_KEEPALIVE idle period applied to
	// accepted SFTP and FTP control connections. A zero value selects the
	// package default; a negative value disables keepalive entirely.
	tcpKeepAlivePeriod time.Duration
	// sftpAllowChown controls whether SFTP clients may change the ownership
	// (uid/gid) of files in their jail via Setstat/Fsetstat requests.
	// It defaults to false: chown requests are rejected with a permission
	// error. Enable it only when the server runs with sufficient privilege
	// (typically as root with CAP_CHOWN) AND the deployment trusts
	// authenticated users not to chown their files to other UIDs.
	sftpAllowChown bool
	// connWG tracks in-flight per-connection handler goroutines so that
	// Shutdown can wait for them to finish. Each accepted connection adds
	// one before its goroutine starts and decrements on goroutine exit.
	// connWG.Add is always called under mu so it is serialised with
	// shuttingDown reads/writes; this keeps the Add/Wait pair race-free
	// per the sync.WaitGroup contract.
	connWG sync.WaitGroup
	// activeConns holds every accepted connection that has not yet returned
	// from its handler, mapped to the username currently authenticated on
	// that connection (empty string before authentication, or after FTP REIN).
	// It is consulted by Shutdown to force-close stragglers when the caller's
	// context deadline fires, and by RemoveUser to evict active sessions of
	// a user being deleted.
	activeConns map[net.Conn]string
	// shutdownWaiters counts concurrent Shutdown callers so shuttingDown stays
	// true until the final caller has finished waiting on connWG.
	shutdownWaiters int
	// shuttingDown is set while Shutdown is draining so subsequent trackConn
	// calls refuse new work instead of starting handlers we would have to
	// drain. It is guarded by mu so it serialises with connWG.Add inside
	// trackConn.
	shuttingDown bool
}

// Config holds the values used to construct a server.
type Config struct {
	SftpAddr            string
	FtpAddr             string
	FtpPassivePortRange string
	// FtpDataAcceptTimeout bounds how long passive-mode FTP data listeners wait
	// for the client data connection after PASV/EPSV, and how long active-mode
	// FTP dials may take after PORT/EPRT. Zero selects the package default
	// (30 seconds); negative disables the deadline.
	FtpDataAcceptTimeout time.Duration
	// FtpAllowActiveMode enables FTP active mode (PORT/EPRT). It defaults to
	// false because active mode requires outbound connections from the server.
	// When enabled, this server only dials the same IP as the control connection.
	FtpAllowActiveMode  bool
	Users               map[string]UserInfo
	SftpSigner          ssh.Signer
	CompletedUploadSize int
	AuthEventSize       int
	// SSHKeyExchanges, SSHCiphers, SSHMACs, and
	// SSHPublicKeyAuthAlgorithms optionally pin SSH negotiation and public-key
	// auth signature algorithms. Nil slices use golang.org/x/crypto/ssh
	// defaults.
	SSHKeyExchanges            []string
	SSHCiphers                 []string
	SSHMACs                    []string
	SSHPublicKeyAuthAlgorithms []string
	// TempExtensions marks file extensions that should defer completion
	// notifications until a later rename to a non-temp name. Matching is
	// case-insensitive.
	TempExtensions []string
	// IdleTimeout bounds authenticated SFTP connection inactivity and FTP
	// control-session inactivity between commands. Zero selects the package
	// default; negative disables the idle timeout.
	IdleTimeout time.Duration
	// TCPKeepAlivePeriod controls the SO_KEEPALIVE idle period applied to
	// accepted SFTP and FTP control connections. Zero selects the package
	// default (30 seconds); a negative value disables keepalive entirely.
	// Probes keep idle control connections alive through stateful
	// firewalls/NAT and surface half-open peers as read errors.
	TCPKeepAlivePeriod time.Duration
	// SftpAllowChown controls whether SFTP clients may change file ownership
	// inside their jail. It defaults to false.
	SftpAllowChown bool
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
	var toClose []net.Conn
	for nc, u := range s.activeConns {
		if u == username {
			toClose = append(toClose, nc)
		}
	}
	s.mu.Unlock()
	for _, c := range toClose {
		_ = c.Close()
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
	var toClose []net.Conn
	for nc, u := range s.activeConns {
		if u != "" {
			toClose = append(toClose, nc)
		}
	}
	s.mu.Unlock()
	for _, c := range toClose {
		_ = c.Close()
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
	u.AuthorizedKeys = append(keys, key)
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

// DefaultConfig returns a fresh server configuration with package
// defaults applied. Callers should set Users before starting the server. Set
// SftpSigner to use a stable host key; when SftpSigner is nil, ListenAndServe
// generates an ephemeral in-memory host key.
func DefaultConfig() *Config {
	return &Config{
		SftpAddr:            ":2022",
		FtpAddr:             "",
		FtpPassivePortRange: "5000-5010",
		CompletedUploadSize: defaultCompletedUploadsSize,
		AuthEventSize:       defaultAuthEventsSize,
	}
}

// NewServer creates a new Server from config. Pass FtpAddr as "" to disable
// FTP. Leave FtpPassivePortRange empty to use OS-assigned passive data ports.
//
// CompletedUploadSize sets the buffer capacity of the CompletedUploads channel.
// AuthEventSize sets the buffer capacity of the AuthEvents channel. A
// non-positive value falls back to the package default (64) for either stream:
//
//	cfg := ironport.DefaultConfig()
//	cfg.Users = users
//	cfg.SftpSigner = signer
//	cfg.CompletedUploadSize = 256
//	cfg.AuthEventSize = 256
//	srv := ironport.NewServer(cfg)
func NewServer(config *Config) *Server {
	if config == nil {
		config = DefaultConfig()
	}
	s := &Server{
		addr:                       config.SftpAddr,
		ftpAddr:                    config.FtpAddr,
		ftpPassivePortRange:        config.FtpPassivePortRange,
		ftpDataAcceptTimeout:       config.FtpDataAcceptTimeout,
		ftpAllowActiveMode:         config.FtpAllowActiveMode,
		users:                      cloneUsers(config.Users),
		sftpSigner:                 config.SftpSigner,
		completedUploads:           newCompletedUploadsChannel(config.CompletedUploadSize),
		authEvents:                 newAuthEventsChannel(config.AuthEventSize),
		sshKeyExchanges:            slices.Clone(config.SSHKeyExchanges),
		sshCiphers:                 slices.Clone(config.SSHCiphers),
		sshMACs:                    slices.Clone(config.SSHMACs),
		sshPublicKeyAuthAlgorithms: slices.Clone(config.SSHPublicKeyAuthAlgorithms),
		tempExtensions:             normalizeTempExtensions(config.TempExtensions),
		idleTimeout:                config.IdleTimeout,
		tcpKeepAlivePeriod:         config.TCPKeepAlivePeriod,
		sftpAllowChown:             config.SftpAllowChown,
		activeConns:                make(map[net.Conn]string),
	}
	return s
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

func (s *Server) beginListenAndServe() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shuttingDown {
		return 0, errors.New("ironport: server is shutting down")
	}
	if s.serving {
		return 0, errors.New("ironport: server is already running")
	}
	s.serveID++
	s.serving = true
	return s.serveID, nil
}

func (s *Server) publishListeners(runID uint64, sftpLn, ftpLn net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serveID != runID || !s.serving || s.shuttingDown {
		return false
	}
	s.ln = sftpLn
	s.ftpLn = ftpLn
	return true
}

func (s *Server) finishListenAndServe(runID uint64) {
	s.mu.Lock()
	if s.serveID == runID {
		s.ln = nil
		s.ftpLn = nil
		s.serving = false
	}
	s.mu.Unlock()
}

func (s *Server) beginShutdown() {
	s.mu.Lock()
	s.shuttingDown = true
	s.shutdownWaiters++
	s.mu.Unlock()
}

func (s *Server) endShutdown() {
	s.mu.Lock()
	s.shutdownWaiters--
	if s.shutdownWaiters == 0 {
		s.shuttingDown = false
	}
	s.mu.Unlock()
}

// trackConn records nc as an in-flight handler-owned connection. It returns
// false when the server has already begun shutting down, in which case the
// caller must not spawn a handler for nc and is responsible for closing it.
// On success the caller must call untrackConn(nc) and connWG.Done() exactly
// once before its handler goroutine returns.
func (s *Server) trackConn(nc net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shuttingDown {
		return false
	}
	if s.activeConns == nil {
		s.activeConns = make(map[net.Conn]string)
	}
	s.activeConns[nc] = ""
	s.connWG.Add(1)
	return true
}

// setConnUser records username as the authenticated identity on nc. It is a
// no-op when nc is not currently tracked (e.g., in tests that bypass the
// accept loop). Pass an empty username to clear the association (used after
// FTP REIN so the now-anonymous session is no longer tied to the prior user).
func (s *Server) setConnUser(nc net.Conn, username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.activeConns[nc]; ok {
		s.activeConns[nc] = username
	}
}

// untrackConn removes nc from the in-flight set. The corresponding
// connWG.Done() call is the caller's responsibility so that ordering between
// "stop tracking" and "decrement waitgroup" is explicit at each call site.
func (s *Server) untrackConn(nc net.Conn) {
	s.mu.Lock()
	delete(s.activeConns, nc)
	s.mu.Unlock()
}

// forceCloseActiveConns closes every connection still in the active set.
// Returns the number of connections it closed. Used by Shutdown to evict
// stragglers when the caller's context deadline fires before handlers have
// finished on their own.
func (s *Server) forceCloseActiveConns() int {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.activeConns))
	for c := range s.activeConns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

func newCompletedUploadsChannel(size int) chan CompletedUpload {
	if size <= 0 {
		size = defaultCompletedUploadsSize
	}
	return make(chan CompletedUpload, size)
}

func newAuthEventsChannel(size int) chan AuthEvent {
	if size <= 0 {
		size = defaultAuthEventsSize
	}
	return make(chan AuthEvent, size)
}

func (s *Server) completedUploadsChan() chan CompletedUpload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.completedUploads
}

func (s *Server) authEventsChan() chan AuthEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authEvents
}

// CompletedUploads returns a receive-only stream of successful upload
// notifications. Each CompletedUpload includes the protocol that produced it.
// The channel is buffered; sends are non-blocking so a slow consumer never
// stalls an upload. Callers should drain the stream continuously.
//
// The buffer capacity is set by Config.CompletedUploadSize. A
// non-positive value falls back to the package default (64).
func (s *Server) CompletedUploads() <-chan CompletedUpload {
	return s.completedUploadsChan()
}

// AuthEvents returns a receive-only stream of authentication/session
// notifications. Each AuthEvent includes the protocol that produced it.
// The channel is buffered; sends are non-blocking so a slow consumer never
// stalls authentication or logout handling. Callers should drain the stream
// continuously.
//
// The buffer capacity is set by Config.AuthEventSize. A non-positive
// value falls back to the package default (64).
func (s *Server) AuthEvents() <-chan AuthEvent {
	return s.authEventsChan()
}

func announceAuthEvent(events chan<- AuthEvent, evt AuthEvent) {
	if events == nil {
		return
	}
	select {
	case events <- evt:
	default:
		log.Printf("auth event: AuthEvents queue full, notification type=%q protocol=%q user=%q dropped", evt.Type, evt.Protocol, evt.Username)
	}
}

func parseFTPPassivePortRange(portRange string) (start, end int, err error) {
	portRange = strings.TrimSpace(portRange)
	if portRange == "" {
		return 0, 0, nil
	}

	if !strings.Contains(portRange, "-") {
		port, err := strconv.Atoi(portRange)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid FTP passive port %q", portRange)
		}
		if port < 1 || port > 65535 {
			return 0, 0, fmt.Errorf("FTP passive port %q out of range", portRange)
		}
		return port, port, nil
	}

	startText, endText, _ := strings.Cut(portRange, "-")
	start, err = strconv.Atoi(strings.TrimSpace(startText))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid FTP passive port range %q", portRange)
	}
	end, err = strconv.Atoi(strings.TrimSpace(endText))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid FTP passive port range %q", portRange)
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 || start > end {
		return 0, 0, fmt.Errorf("FTP passive port range %q out of range", portRange)
	}
	return start, end, nil
}

func (s *Server) listenFTPData(host string) (net.Listener, error) {
	portRange := strings.TrimSpace(s.ftpPassivePortRange)
	if portRange == "" {
		return net.Listen("tcp", net.JoinHostPort(host, "0"))
	}

	start, end, err := parseFTPPassivePortRange(portRange)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for port := start; port <= end; port++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all FTP passive ports in range %q are unavailable: %w", portRange, lastErr)
}

// ListenAndServe starts the SFTP server and, when configured, the FTP server
// too. It blocks until Close or Shutdown is called or an unexpected
// listener error occurs. It returns nil when stopped via Close or Shutdown.
//
// A stopped server can be started again by calling ListenAndServe after Close
// or Shutdown returns. Concurrent ListenAndServe calls are rejected.
func (s *Server) ListenAndServe() error {
	if strings.TrimSpace(s.addr) == "" {
		return errors.New("ironport: SftpAddr is required")
	}
	runID, err := s.beginListenAndServe()
	if err != nil {
		return err
	}
	var sftpLn net.Listener
	var ftpLn net.Listener
	defer s.finishListenAndServe(runID)

	if err := s.ensureSigner(); err != nil {
		return fmt.Errorf("ironport: %w", err)
	}
	// Hard requirement: the package's containment guarantee relies on
	// openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS), available since Linux
	// 5.6. Fail fast at startup on older kernels rather than silently
	// degrading the policy at first request.
	if err := ensureOpenat2(); err != nil {
		return fmt.Errorf("ironport: %w", err)
	}
	uploads := s.completedUploadsChan()
	authEvents := s.authEventsChan()
	cfg := s.sshServerConfig()

	sftpLn, err = net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	if strings.TrimSpace(s.ftpAddr) != "" {
		ftpLn, err = net.Listen("tcp", s.ftpAddr)
		if err != nil {
			_ = sftpLn.Close()
			return err
		}
	}

	if !s.publishListeners(runID, sftpLn, ftpLn) {
		return closeListenerPair(sftpLn, ftpLn)
	}

	log.Printf("SFTP listening on %s", sftpLn.Addr())
	workers := 1
	errCh := make(chan error, 2)
	go func() { errCh <- s.serveSFTP(sftpLn, cfg, uploads, authEvents) }()

	if ftpLn != nil {
		workers++
		log.Printf("FTP listening on %s", ftpLn.Addr())
		go func() { errCh <- s.serveFTP(ftpLn, uploads, authEvents) }()
	}

	var ret error
	for i := 0; i < workers; i++ {
		if err := <-errCh; err != nil && ret == nil {
			ret = err
			_ = s.closeRunListeners(runID, sftpLn, ftpLn)
		}
	}
	return ret
}

func (s *Server) serveSFTP(ln net.Listener, cfg *ssh.ServerConfig, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent) error {
	tempExts := s.configuredTempExtensions()
	idleTimeout := s.effectiveIdleTimeout()
	allowChown := s.sftpChownAllowed()
	return s.acceptLoop(ln, "sftp", func(nc net.Conn) {
		s.handleConn(nc, cfg, uploads, authEvents, tempExts, idleTimeout, allowChown)
	})
}

func (s *Server) serveFTP(ln net.Listener, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent) error {
	tempExts := s.configuredTempExtensions()
	return s.acceptLoop(ln, "ftp", func(nc net.Conn) {
		s.handleFTPConn(nc, tempExts, uploads, authEvents)
	})
}

// acceptLoop runs the shared Accept loop used by both protocol listeners:
// it applies the configured TCP keepalive to every new connection, tracks
// the connection for graceful shutdown, recovers from handler panics, and
// applies exponential backoff between 5ms and 1s on transient Accept errors
// so a momentary EMFILE/ENFILE cannot kill the listener. name is used in log
// messages to distinguish the SFTP and FTP loops.
func (s *Server) acceptLoop(ln net.Listener, name string, handler func(net.Conn)) error {
	var backoff time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = nextAcceptBackoff(backoff)
			log.Printf("%s accept: %v; retrying in %s", name, err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		applyTCPKeepAlive(nc, s.effectiveTCPKeepAlivePeriod())
		if !s.trackConn(nc) {
			// Shutdown began between Accept returning and tracking; refuse
			// the connection rather than spawning an untrackable handler.
			_ = nc.Close()
			continue
		}
		go func() {
			defer s.connWG.Done()
			defer s.untrackConn(nc)
			defer func() {
				if r := recover(); r != nil {
					log.Printf("%s handler panic from=%s: %v\n%s", name, nc.RemoteAddr(), r, debug.Stack())
					_ = nc.Close()
				}
			}()
			handler(nc)
		}()
	}
}

// nextAcceptBackoff returns the next exponential backoff duration to sleep
// after a transient Accept error. The schedule starts at 5ms and caps at 1s.
func nextAcceptBackoff(prev time.Duration) time.Duration {
	if prev == 0 {
		return 5 * time.Millisecond
	}
	next := prev * 2
	if next > time.Second {
		next = time.Second
	}
	return next
}

// configuredTempExtensions returns a copy of the normalised temp extensions
// configured at construction.
func (s *Server) configuredTempExtensions() []string {
	return slices.Clone(s.tempExtensions)
}

// effectiveIdleTimeout returns the effective idle timeout for SFTP connections.
// A zero configured timeout selects the package default; a negative timeout
// disables the deadline.
func (s *Server) effectiveIdleTimeout() time.Duration {
	return resolveDur(s.idleTimeout, defaultSFTPIdleTimeout)
}

// effectiveFTPDataAcceptTimeout returns the effective FTP data-connection
// setup timeout. A zero configured timeout selects the package default; a
// negative timeout disables the passive accept or active dial deadline.
func (s *Server) effectiveFTPDataAcceptTimeout() time.Duration {
	return resolveDur(s.ftpDataAcceptTimeout, defaultFTPDataAcceptTimeout)
}

// sftpChownAllowed returns the configured SFTP chown permission.
func (s *Server) sftpChownAllowed() bool {
	return s.sftpAllowChown
}

// effectiveTCPKeepAlivePeriod returns the effective SO_KEEPALIVE idle period for
// accepted control connections. A zero configured value selects the package
// default; a negative value disables keepalive (returns 0).
func (s *Server) effectiveTCPKeepAlivePeriod() time.Duration {
	return resolveDur(s.tcpKeepAlivePeriod, defaultTCPKeepAlivePeriod)
}

// applyTCPKeepAlive enables SO_KEEPALIVE on a freshly accepted control
// connection and sets the idle period before probes begin. A non-positive
// period disables keepalive. Connections that are not *net.TCPConn (e.g. test
// fakes) are left untouched.
func applyTCPKeepAlive(nc net.Conn, period time.Duration) {
	tc, ok := nc.(*net.TCPConn)
	if !ok {
		return
	}
	if period <= 0 {
		_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable:   false,
			Idle:     -1,
			Interval: -1,
			Count:    -1,
		})
		return
	}
	_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     period,
		Interval: -1,
		Count:    -1,
	})
}

// cleanSFTPClientPath normalises a raw SFTP client path into an absolute,
// slash-separated, clean path that starts with "/". This mirrors the
// normalisation that FTP sessions apply via cleanPath so that event consumers
// always receive a consistent FilePath value regardless of how the client
// formatted the request (e.g. "foo.txt", "../../etc/passwd", "/a/../b.txt").
func cleanSFTPClientPath(p string) string {
	p = filepath.ToSlash(p)
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
}

func sftpRequestContext(r *sftp.Request) (method, filepath string) {
	if r == nil {
		return "", ""
	}
	return r.Method, r.Filepath
}

func recoverSFTPSessionPanic(username, clientIP string, recovered any) {
	if recovered == nil {
		return
	}
	log.Printf("sftp session panic user=%q ip=%q: %v\n%s", username, clientIP, recovered, debug.Stack())
}

func recoverSFTPHandlerPanic(username, clientIP, method, filepath string, recovered any, errp *error) bool {
	if recovered == nil {
		return false
	}
	log.Printf("sftp handler panic user=%q ip=%q method=%q path=%q: %v\n%s", username, clientIP, method, filepath, recovered, debug.Stack())
	if errp != nil {
		*errp = errSFTPRequestFailed
	}
	return true
}

// deferRecoverSFTPHandlerPanic returns a deferred panic-recovery function for
// SFTP handler methods. It logs the recovered panic using the request's method
// and path, stores errSFTPRequestFailed in errp, and optionally runs onPanic to
// zero any additional named return values.
func deferRecoverSFTPHandlerPanic(username, clientIP string, r *sftp.Request, errp *error, onPanic func()) func() {
	method, filePath := sftpRequestContext(r)
	return func() {
		if recoverSFTPHandlerPanic(username, clientIP, method, filePath, recover(), errp) && onPanic != nil {
			onPanic()
		}
	}
}

// deferRecoverSFTPPanicf returns a deferred panic-recovery function for helpers that
// do not have an sftp.Request available for deferRecoverSFTPHandlerPanic. format
// must include two trailing verbs for the recovered panic value and stack trace
// after args.
func deferRecoverSFTPPanicf(errp *error, onPanic func(), format string, args ...any) func() {
	return func() {
		if recovered := recover(); recovered != nil {
			allArgs := append(args, recovered, debug.Stack())
			log.Printf(format, allArgs...)
			if onPanic != nil {
				onPanic()
			}
			if errp != nil {
				*errp = errSFTPRequestFailed
			}
		}
	}
}

// hasTempExt reports whether name ends with one of the given (already
// normalised, lower-case, dot-prefixed) extensions. Matching is
// case-insensitive on the filename.
func hasTempExt(name string, tempExts []string) bool {
	if len(tempExts) == 0 {
		return false
	}
	lower := strings.ToLower(name)
	for _, ext := range tempExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// Close stops both listeners, causing ListenAndServe to return nil. It is safe
// to call concurrently with active connections; in-flight connections are not
// terminated, and the server can be started again after Close returns. Calling
// Close before ListenAndServe has been called, or after it has already
// returned, is a no-op.
func (s *Server) Close() error {
	return s.closeListeners()
}

// Shutdown gracefully stops the server. It closes the listeners so no new
// connections are accepted, then waits for every in-flight handler goroutine
// to return.
//
// If ctx is canceled or its deadline passes before all handlers finish,
// Shutdown forcibly closes every remaining tracked connection (which causes
// each handler's network I/O to fail and the handler to return), waits for
// those handlers to exit, and returns ctx.Err(). Passing context.Background()
// blocks until all handlers exit.
//
// Shutdown is safe to call concurrently with Close and with itself. After
// Shutdown returns, ListenAndServe (if it was running) will have returned nil,
// and the server can be started again. Calling Shutdown before ListenAndServe
// has been started, or after it has already returned and all handlers have
// exited, returns immediately with nil.
func (s *Server) Shutdown(ctx context.Context) error {
	// Mark the server as shutting down so any accept that races with the
	// listener close refuses the connection rather than starting a handler
	// we would then have to drain. Setting this under mu serialises with
	// trackConn's connWG.Add so the WaitGroup Add/Wait pair is race-free.
	s.beginShutdown()
	defer s.endShutdown()
	listenerErr := s.closeListeners()

	done := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		return listenerErr
	case <-ctx.Done():
		n := s.forceCloseActiveConns()
		if n > 0 {
			log.Printf("Shutdown: forcing close of %d in-flight connection(s) after deadline", n)
		}
		// Wait for handlers to actually return so the WaitGroup is settled
		// and there are no live goroutines touching server state after
		// Shutdown returns.
		<-done
		return ctx.Err()
	}
}

func closeListenerPair(ln, ftpLn net.Listener) error {
	var ret error
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			ret = err
		}
	}
	if ftpLn != nil {
		if err := ftpLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && ret == nil {
			ret = err
		}
	}
	return ret
}

func (s *Server) closeRunListeners(runID uint64, ln, ftpLn net.Listener) error {
	s.mu.Lock()
	if s.serveID == runID {
		s.ln = nil
		s.ftpLn = nil
		s.serving = false
	}
	s.mu.Unlock()
	return closeListenerPair(ln, ftpLn)
}

func (s *Server) closeListeners() error {
	s.mu.Lock()
	ln := s.ln
	ftpLn := s.ftpLn
	s.ln = nil
	s.ftpLn = nil
	s.serving = false
	s.mu.Unlock()

	return closeListenerPair(ln, ftpLn)
}

// ListeningAddr returns the actual SFTP network address the server is listening
// on, or nil if the SFTP listener is not currently listening. It is useful when
// the server was started with port 0 (OS-assigned port).
func (s *Server) ListeningAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// FTPListeningAddr returns the actual FTP network address the server is
// listening on, or nil if FTP is disabled or not currently listening.
func (s *Server) FTPListeningAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ftpLn == nil {
		return nil
	}
	return s.ftpLn.Addr()
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

func canonicalJailRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", os.ErrInvalid
	}

	abs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", err
	}

	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}

	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", syscall.ENOTDIR
	}

	return real, nil
}

// checkPassword performs a SHA-256-normalized constant-time comparison between
// stored and supplied passwords, and rejects empty stored/supplied credentials.
func checkPassword(storedPw, suppliedPw string) bool {
	storedHash := sha256.Sum256([]byte(storedPw))
	suppliedHash := sha256.Sum256([]byte(suppliedPw))
	match := subtle.ConstantTimeCompare(storedHash[:], suppliedHash[:]) == 1
	return match && len(storedPw) > 0 && len(suppliedPw) > 0
}

// authenticateUser performs the credential check shared by SFTP and FTP
// logins. It returns a cloned UserInfo snapshot and the canonical jail-root
// path on success. ok is false when either the credentials do not match or
// the jail-root cannot be canonicalised; callers should not distinguish those
// cases when replying to clients, to avoid leaking which step failed.
//
// keyCheck supplies the matching logic so the SSH PasswordCallback can pass a
// password comparator and the PublicKeyCallback can pass a constant-time-padded
// key comparator. keyCheck receives the zero-value UserInfo when the user is
// unknown, so it MUST be constant-time (independent of stored password length
// and AuthorizedKeys count) to avoid leaking username existence; checkPassword
// and the public-key timing pad already satisfy this.
func (s *Server) authenticateUser(username string, keyCheck func(stored UserInfo) bool) (UserInfo, string, bool) {
	u, ok := s.userSnapshot(username)
	if !keyCheck(u) || !ok {
		return UserInfo{}, "", false
	}
	jailRoot, err := canonicalJailRoot(u.Root)
	if err != nil {
		return UserInfo{}, "", false
	}
	return u, jailRoot, true
}

// sshServerConfig builds the SSH server configuration with both password-based
// and public-key-based authentication enabled.
//
// Password authentication succeeds when the supplied password matches the
// stored Password (constant-time comparison).
//
// Public-key authentication succeeds when the presented key matches any entry
// in the user's AuthorizedKeys slice (constant-time comparison of wire-format
// bytes).
func (s *Server) sshServerConfig() *ssh.ServerConfig {
	authEvents := s.authEventsChan()
	// completeLogin centralises the failure announcement and the success
	// permissions construction so PasswordCallback and PublicKeyCallback only
	// have to express their own credential-matching logic.
	completeLogin := func(c ssh.ConnMetadata, keyCheck func(UserInfo) bool) (*ssh.Permissions, error) {
		u, jailRoot, ok := s.authenticateUser(c.User(), keyCheck)
		if !ok {
			announceAuthEvent(authEvents, AuthEvent{
				Type:     AuthEventLoginFailed,
				Username: c.User(),
				ClientIP: remoteIP(c.RemoteAddr()),
				Protocol: CompletedUploadProtocolSFTP,
			})
			return nil, errInvalidCredentials
		}
		return permissionsFor(u, c.User(), jailRoot), nil
	}

	cfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: slices.Clone(s.sshKeyExchanges),
			Ciphers:      slices.Clone(s.sshCiphers),
			MACs:         slices.Clone(s.sshMACs),
		},
		PublicKeyAuthAlgorithms: slices.Clone(s.sshPublicKeyAuthAlgorithms),
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return completeLogin(c, func(u UserInfo) bool {
				// checkPassword treats an empty stored password as
				// "no password set" and rejects it. Passing u.Password
				// directly works for both the existing-user and
				// unknown-user (zero-value UserInfo) cases, and the SHA-256
				// length-normalisation inside checkPassword keeps the
				// comparison constant-time regardless.
				return checkPassword(u.Password, string(pass))
			})
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return completeLogin(c, func(u UserInfo) bool {
				keyBytes := key.Marshal()
				// Hash the presented key's wire-format bytes to a fixed 32-byte
				// value so that all comparisons in the loop are the same length
				// regardless of key algorithm. RSA, ECDSA, and Ed25519 wire
				// formats all differ in length; a raw ConstantTimeCompare would
				// short-circuit on any length mismatch, leaking type information.
				keyHash := sha256.Sum256(keyBytes)
				// All comparisons are constant-time on a fixed 32-byte hash and
				// the total iteration count is padded out to authorizedKeyTimingPad
				// below so the response time does not leak (a) whether the user
				// exists, (b) the position of a matching key in AuthorizedKeys, or
				// (c) the number of keys the user has configured (up to the pad
				// constant).
				var zeroHash [sha256.Size]byte
				matched := false
				compares := 0
				for _, authorizedKey := range u.AuthorizedKeys {
					if authorizedKey == nil {
						continue
					}
					authHash := sha256.Sum256(authorizedKey.Marshal())
					if subtle.ConstantTimeCompare(keyHash[:], authHash[:]) == 1 {
						matched = true
					}
					compares++
				}
				// Pad with dummy comparisons against an all-zero hash (which can
				// never match a real key's SHA-256) so that the total number of
				// constant-time compares is independent of len(AuthorizedKeys).
				for ; compares < authorizedKeyTimingPad; compares++ {
					_ = subtle.ConstantTimeCompare(keyHash[:], zeroHash[:])
				}
				return matched
			})
		},
	}
	cfg.AddHostKey(s.sftpSigner)
	return cfg
}

func (s *Server) handleConn(nc net.Conn, cfg *ssh.ServerConfig, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent, tempExts []string, idleTimeout time.Duration, sftpAllowChown bool) {
	defer func() { _ = nc.Close() }()

	// Wrap the raw connection so that every Read resets the read deadline.
	// During the handshake we use sshHandshakeTimeout to prevent malicious
	// clients from holding goroutines open indefinitely without completing
	// the handshake (denial-of-service via resource exhaustion). After the
	// handshake succeeds we switch to the per-session idle timeout so that
	// authenticated but inactive sessions are eventually reaped.
	ic := &idleConn{Conn: nc}
	ic.setReadTimeout(sshHandshakeTimeout)
	sshConn, chans, reqs, err := ssh.NewServerConn(ic, cfg)
	if err != nil {
		log.Println("ssh handshake:", err)
		return
	}
	// Handshake complete – switch to the idle-session deadline. A zero value
	// disables the deadline.
	ic.setReadTimeout(idleTimeout)
	defer func() { _ = sshConn.Close() }()

	jailRoot := sshConn.Permissions.Extensions["jailRoot"]
	user := sshConn.Permissions.Extensions["user"]
	canRead := sshConn.Permissions.Extensions["canRead"] == "true"
	canWrite := sshConn.Permissions.Extensions["canWrite"] == "true"
	clientIP := remoteIP(sshConn.RemoteAddr())
	// Record the authenticated user on this connection so RemoveUser can
	// force-close it if the account is later revoked.
	s.setConnUser(nc, user)
	log.Printf("login protocol=sftp user=%s root=%s from=%s", user, jailRoot, sshConn.RemoteAddr())
	announceAuthEvent(authEvents, AuthEvent{
		Type:     AuthEventLoginSuccess,
		Username: user,
		ClientIP: clientIP,
		Protocol: CompletedUploadProtocolSFTP,
	})
	defer announceAuthEvent(authEvents, AuthEvent{
		Type:     AuthEventLogout,
		Username: user,
		ClientIP: clientIP,
		Protocol: CompletedUploadProtocolSFTP,
	})

	// Discard global requests
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, inReqs, err := newCh.Accept()
		if err != nil {
			log.Println("accept channel:", err)
			continue
		}

		go handleSession(ch, inReqs, jailRoot, user, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown)
	}
}

// remoteIP extracts the IP portion of a net.Addr. If the address contains a
// host:port pair (as is the case for TCP) only the host is returned; otherwise
// the full string form of the address is returned. Returns "" for a nil addr.
func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	s := addr.String()
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

func handleSession(ch ssh.Channel, inReqs <-chan *ssh.Request, jailRoot, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, sftpAllowChown bool) {
	defer func() {
		recoverSFTPSessionPanic(username, clientIP, recover())
		_ = ch.Close()
	}()

	for req := range inReqs {
		switch req.Type {
		case "subsystem":
			// Payload is a wire-format SSH string: uint32 length + bytes.
			// Validate that the payload is large enough and that the encoded
			// length matches the actual remaining bytes before slicing.
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			nameLen := binary.BigEndian.Uint32(req.Payload[:4])
			// Use int64 arithmetic to avoid uint32 overflow when checking bounds.
			if int64(nameLen) > int64(len(req.Payload))-4 || string(req.Payload[4:4+nameLen]) != "sftp" {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)

			// Serving the SFTP subsystem is delegated to a helper so that
			// its cleanup defers (fs.Close, server.Close) run on its own
			// return rather than accumulating inside this for/switch — a
			// defer placed directly in this case would survive across loop
			// iterations if the trailing `return` were ever removed.
			serveSFTPSubsystem(ch, jailRoot, username, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown)
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
}

// serveSFTPSubsystem opens the per-session jail, runs the SFTP request server
// to completion, and tears both down via defer so the cleanup is local to this
// function and not to handleSession's loop body. Callers must already have
// replied to the "subsystem" request before invoking it.
func serveSFTPSubsystem(ch ssh.Channel, jailRoot, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, sftpAllowChown bool) {
	handlers, fs, err := jailedHandlers(jailRoot, username, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown)
	if err != nil {
		log.Printf("open jail root %q: %v", jailRoot, err)
		return
	}
	defer func() { _ = fs.Close() }()

	server := sftp.NewRequestServer(ch, handlers)
	defer func() { _ = server.Close() }()
	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		log.Println("sftp serve:", err)
	}
}

type jail struct {
	// fs is the fd-relative filesystem implementation backing this jail. It
	// is constructed once per session and shared by all handler invocations.
	// Its lifetime is bound to the session: jailedHandlers (SFTP) or
	// ftpSession.openJail (FTP) creates it; the corresponding teardown path
	// calls fs.Close() exactly once.
	fs       *jailFS
	username string
	clientIP string
	canRead  bool
	canWrite bool
	uploads  chan<- CompletedUpload
	// tempExts is the list of "still being written" extensions (lower-case,
	// dot-prefixed). Uploads ending in one of these extensions are not
	// announced on uploads; renaming such a file to a name without any of
	// these extensions announces the final path on uploads instead.
	tempExts []string
	// sftpAllowChown controls whether Setstat/Fsetstat requests carrying a
	// uid/gid attribute are honoured. When false, chown requests are
	// rejected with a permission error so an authenticated user cannot
	// change ownership of jailed files even if the server process has
	// the privilege to do so (for example when running as root).
	sftpAllowChown bool
}

// jail implements the four sftp handler interfaces for a chrooted filesystem.
// Fileread implements sftp.FileReader.
func (j jail) Fileread(r *sftp.Request) (reader io.ReaderAt, err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, func() { reader = nil })()
	if !j.canRead {
		return nil, os.ErrPermission
	}
	f, err := j.fs.OpenRead(r.Filepath)
	if err != nil {
		return nil, sanitizeSFTPErr(err)
	}
	return f, nil
}

// writeLogger wraps an *os.File and logs the filename when the file is closed,
// signalling that the upload is complete. The sftp request server calls Close()
// on the returned io.WriterAt when it detects an io.Closer.
//
// If the uploaded filename ends with one of tempExts (e.g. ".tmp", ".writing"),
// the file is considered still in progress and no notification is sent on
// uploads; the completion notification will instead be emitted when the client
// renames the file to its final name (see jail.Filecmd "Rename").
//
// When pkg/sftp's RequestServer aborts an in-flight transfer (typically
// because the client dropped the connection mid-upload, or sent an explicit
// error packet), it invokes TransferError(err) on the writer before calling
// Close. writeLogger records that error in transferErr so Close knows the
// upload is truncated and must NOT be announced on the CompletedUploads
// channel; otherwise consumers would treat a partial file as complete.
type writeLogger struct {
	*os.File
	filepath     string
	fullFilepath string
	username     string
	clientIP     string
	uploads      chan<- CompletedUpload
	tempExts     []string
	appendMode   bool
	// mu guards transferErr against the race between TransferError (invoked
	// asynchronously from the request-server's drain path when the client
	// connection drops mid-transfer) and Close (invoked from the per-request
	// worker goroutine that handled the SSH_FXP_WRITE packets).
	mu sync.Mutex
	// transferErr records the first error reported via TransferError. Only
	// the first error is retained ("first error wins"); subsequent calls
	// from the drain path are no-ops because the upload is already known
	// to be poisoned and further error detail would not change the
	// "do not announce" decision in Close.
	transferErr error
}

func (w *writeLogger) WriteAt(p []byte, off int64) (n int, err error) {
	defer deferRecoverSFTPPanicf(&err, func() { n = 0 }, "sftp write panic user=%q ip=%q path=%q: %v\n%s", w.username, w.clientIP, w.filepath)()
	if w.appendMode {
		// O_APPEND semantics (open(2)): on every write the kernel
		// atomically re-seeks the file offset to EOF before writing, so
		// the off parameter from the SFTP request is intentionally
		// dropped — honouring it would not change the destination of
		// the bytes and would only confuse the next reader.
		return w.Write(p)
	}
	return w.File.WriteAt(p, off)
}

// TransferError implements pkg/sftp's optional TransferError interface. It is
// invoked by the request server when the in-flight transfer is aborted (for
// example, the client connection dropped or the client sent an SSH_FXP_CLOSE
// after an error packet). Recording the error marks the upload as poisoned so
// the subsequent Close does not announce a CompletedUpload event for what is
// in fact a truncated file.
func (w *writeLogger) TransferError(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	if w.transferErr == nil {
		w.transferErr = err
	}
	w.mu.Unlock()
}

func (w *writeLogger) Close() (err error) {
	defer deferRecoverSFTPPanicf(&err, nil, "sftp write close panic user=%q ip=%q path=%q: %v\n%s", w.username, w.clientIP, w.filepath)()
	err = w.File.Close()
	w.mu.Lock()
	transferErr := w.transferErr
	w.mu.Unlock()
	if transferErr != nil {
		log.Printf("upload interrupted: %q: %v; not announcing on CompletedUploads", w.filepath, transferErr)
		return err
	}
	if err == nil {
		log.Printf("upload complete: %q", w.filepath)
		if hasTempExt(w.filepath, w.tempExts) {
			// File is still considered "in progress"; defer notification
			// until the client renames it to its final (non-temp) name.
			log.Printf("upload complete: %q has temp extension, deferring CompletedUploads notification", w.filepath)
			return nil
		}
		// Announce the completed upload on the queue; non-blocking so a slow
		// consumer never stalls the upload handler.
		publishUpload(w.uploads, CompletedUpload{
			Username:     w.username,
			FullFilePath: w.fullFilepath,
			FilePath:     w.filepath,
			ClientIP:     w.clientIP,
			Protocol:     CompletedUploadProtocolSFTP,
		})
	}
	return err
}

// Filewrite implements sftp.FileWriter.
func (j jail) Filewrite(r *sftp.Request) (writer io.WriterAt, err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, func() { writer = nil })()
	if !j.canWrite {
		return nil, os.ErrPermission
	}
	if hasCRLF(r.Filepath) {
		return nil, syscall.EINVAL
	}
	clientPath := cleanSFTPClientPath(r.Filepath)
	log.Printf("upload: %q", clientPath)
	openFlags, appendMode, err := sftpWriteOpenFlags(r)
	if err != nil {
		return nil, err
	}
	f, err := j.fs.OpenWrite(r.Filepath, openFlags, 0600)
	if err != nil {
		return nil, sanitizeSFTPErr(err)
	}
	return &writeLogger{
		File:         f,
		filepath:     clientPath,
		fullFilepath: j.fs.fullPath(r.Filepath),
		username:     j.username,
		clientIP:     j.clientIP,
		uploads:      j.uploads,
		tempExts:     j.tempExts,
		appendMode:   appendMode,
	}, nil
}

func sftpWriteOpenFlags(r *sftp.Request) (int, bool, error) {
	pflags := r.Pflags()
	if !pflags.Write && !pflags.Append {
		return 0, false, os.ErrInvalid
	}

	openFlags := os.O_WRONLY
	if pflags.Append {
		openFlags |= os.O_APPEND
	}
	if pflags.Creat {
		openFlags |= os.O_CREATE
	}
	if pflags.Trunc {
		openFlags |= os.O_TRUNC
	}
	if pflags.Excl {
		openFlags |= os.O_EXCL
	}
	return openFlags, pflags.Append, nil
}

// Filecmd implements sftp.FileCmder.
func (j jail) Filecmd(r *sftp.Request) (err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, nil)()
	if !j.canWrite {
		return os.ErrPermission
	}
	switch r.Method {
	case "Setstat", "Fsetstat":
		return sanitizeSFTPErr(j.applyAttrs(r))

	case "Rename":
		if hasCRLF(r.Target) {
			return syscall.EINVAL
		}
		if err := j.fs.Rename(r.Filepath, r.Target); err != nil {
			return sanitizeSFTPErr(err)
		}
		// If a file with a "still being written" extension is renamed to a
		// final (non-temp) name, treat the rename as the moment the upload
		// completes and announce the new SFTP path on uploads.
		oldClientPath := cleanSFTPClientPath(r.Filepath)
		newClientPath := cleanSFTPClientPath(r.Target)
		maybeAnnounceTempRename(j.uploads, j.tempExts, oldClientPath, CompletedUpload{
			Username:     j.username,
			FullFilePath: j.fs.fullPath(r.Target),
			FilePath:     newClientPath,
			ClientIP:     j.clientIP,
			Protocol:     CompletedUploadProtocolSFTP,
		})
		return nil

	case "Rmdir":
		return sanitizeSFTPErr(j.fs.Rmdir(r.Filepath))

	case "Remove":
		return sanitizeSFTPErr(j.fs.Remove(r.Filepath))

	case "Mkdir":
		if hasCRLF(r.Filepath) {
			return syscall.EINVAL
		}
		return sanitizeSFTPErr(j.fs.Mkdir(r.Filepath, 0750))

	case "Symlink":
		// Symlinks are disallowed in the jail: a client-created symlink could
		// point outside the jail root and be followed by a subsequent request,
		// bypassing the path-containment checks.
		return os.ErrPermission

	default:
		return fmt.Errorf("unsupported method: %s", r.Method)
	}
}

// Filelist implements sftp.FileLister.
func (j jail) Filelist(r *sftp.Request) (lister sftp.ListerAt, err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, func() { lister = nil })()
	if !j.canRead {
		return nil, os.ErrPermission
	}
	switch r.Method {
	case "List":
		infos, err := j.fs.List(r.Filepath)
		if err != nil {
			return nil, sanitizeSFTPErr(err)
		}
		return listerFromFileInfo(infos), nil
	case "Stat", "Lstat":
		// Under the no-symlink policy Stat and Lstat are equivalent: the
		// kernel rejects any symlink in the path lookup, so the entry being
		// described is never a symlink.
		st, err := j.fs.Stat(r.Filepath)
		if err != nil {
			return nil, sanitizeSFTPErr(err)
		}
		return listerFromFileInfo([]os.FileInfo{st}), nil
	default:
		return nil, fmt.Errorf("unsupported list method: %s", r.Method)
	}
}

// applyAttrs applies SFTP Setstat/Fsetstat attributes to the file referenced
// by r.Filepath, constrained to the operations that can run safely as the
// server process and consistent with the hardened "no symlinks anywhere"
// policy.
//
// Supported flags:
//   - Permissions       → fchmod via openat2-obtained fd
//   - UidGid            → fchownat (only when sftpAllowChown is true; otherwise
//     the request is rejected with os.ErrPermission so an authenticated user
//     cannot change ownership of jailed files even when the server process
//     has the privilege to do so)
//   - Size              → ftruncate via openat2-obtained fd
//   - Acmodtime         → REJECTED with os.ErrPermission. Setting timestamps
//     on jailed files is denied wholesale under the hardened policy; clients
//     get a deterministic permission error rather than a partial success.
//
// Policy-level rejections (Acmodtime, and UidGid when sftpAllowChown is false)
// are evaluated before any mutating operation is performed, so a multi-flag
// request that violates policy fails atomically rather than leaving the
// file partially mutated. Remaining mutating operations are then applied in
// a deterministic order; the first error is returned and subsequent
// attributes are not applied, mirroring how OpenSSH's sftp-server reports
// errors.
func (j jail) applyAttrs(r *sftp.Request) error {
	flags := r.AttrFlags()
	attrs := r.Attributes()
	if attrs == nil {
		return nil
	}
	// Reject policy violations up front so they cannot leave the file
	// half-mutated when combined with Size/Permissions in a single request.
	if flags.Acmodtime {
		return os.ErrPermission
	}
	if flags.UidGid && !j.sftpAllowChown {
		return os.ErrPermission
	}
	if flags.Size {
		if err := j.fs.Truncate(r.Filepath, int64(attrs.Size)); err != nil {
			return err
		}
	}
	if flags.Permissions {
		if err := j.fs.Chmod(r.Filepath, attrs.FileMode().Perm()); err != nil {
			return err
		}
	}
	if flags.UidGid {
		if err := j.fs.Chown(r.Filepath, int(attrs.UID), int(attrs.GID)); err != nil {
			return err
		}
	}
	return nil
}

func jailedHandlers(root, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, sftpAllowChown bool) (sftp.Handlers, *jailFS, error) {
	fs, err := openJailFS(filepath.Clean(root))
	if err != nil {
		return sftp.Handlers{}, nil, err
	}
	j := jail{
		fs:             fs,
		username:       username,
		clientIP:       clientIP,
		canRead:        canRead,
		canWrite:       canWrite,
		uploads:        uploads,
		tempExts:       tempExts,
		sftpAllowChown: sftpAllowChown,
	}
	return sftp.Handlers{
		FileGet:  j,
		FilePut:  j,
		FileCmd:  j,
		FileList: j,
	}, fs, nil
}

type fileInfoLister struct{ infos []os.FileInfo }

func (l fileInfoLister) ListAt(fis []os.FileInfo, offset int64) (n int, err error) {
	defer deferRecoverSFTPPanicf(&err, func() { n = 0 }, "sftp list panic offset=%d: %v\n%s", offset)()
	if offset < 0 {
		return 0, os.ErrInvalid
	}
	if offset >= int64(len(l.infos)) {
		return 0, io.EOF
	}
	n = copy(fis, l.infos[offset:])
	if n < len(fis) {
		return n, io.EOF
	}
	return n, nil
}

func listerFromFileInfo(infos []os.FileInfo) sftp.ListerAt {
	return fileInfoLister{infos: infos}
}

// FTP implementation. Passive mode is the default. Active FTP (PORT / EPRT)
// is opt-in because it is harder to firewall safely and opens outbound
// connections from the server; when enabled, active targets are restricted to
// the control connection's peer IP.

// ftpCtlMsg is one item produced by the control-reader goroutine: either a
// raw control-protocol line (terminator stripped by the receiver) or the
// error that ended the reader. After an error is delivered the reader
// closes its channel, so the main loop and any in-flight transfer helper
// see a single sentinel signalling session end.
type ftpCtlMsg struct {
	line string
	err  error
}

type ftpSession struct {
	server        *Server
	conn          net.Conn
	r             *bufio.Reader
	w             *bufio.Writer
	username      string
	user          UserInfo
	authenticated bool
	cwd           string
	dataLn        net.Listener
	dataAddr      *net.TCPAddr
	epsvAll       bool
	rnfrPath      string
	restartOffset int64
	// expectedUploadSize is the byte count declared by the client via the
	// most recent ALLO command; it is consumed by the next STOR/APPE so
	// an aborted transfer cannot let the hint leak into a later command.
	// When non-zero, STOR rejects transfers whose byte count does not
	// match — the only reliable way to detect a client that truncates by
	// half-closing the data connection in STREAM mode.
	expectedUploadSize int64
	// ctlMsg carries control-protocol lines from the reader goroutine to
	// both the main command loop and any in-flight data transfer. Having
	// a single producer/consumer pair makes ABOR mid-transfer possible:
	// the transfer helper selects on this channel alongside the transfer
	// goroutine's completion signal.
	ctlMsg     chan ftpCtlMsg
	clientIP   string
	tempExts   []string
	uploads    chan<- CompletedUpload
	authEvents chan<- AuthEvent
	// fs is the fd-relative filesystem backing this session's jail. It is
	// constructed by authenticate on successful login and released when the
	// session ends (closeJail). Until login succeeds it is nil.
	fs *jailFS
}

func (s *Server) handleFTPConn(nc net.Conn, tempExts []string, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent) {
	sess := &ftpSession{
		server:     s,
		conn:       nc,
		r:          bufio.NewReader(nc),
		w:          bufio.NewWriter(nc),
		cwd:        "/",
		clientIP:   remoteIP(nc.RemoteAddr()),
		tempExts:   tempExts,
		uploads:    uploads,
		authEvents: authEvents,
		ctlMsg:     make(chan ftpCtlMsg, 1),
	}
	// Close nc first, then drain the reader so its goroutine can exit.
	// LIFO defer order means this runs last — after closeDataListener,
	// closeJail, and logoutIfAuthenticated — so the reader keeps running
	// in case those handlers want to reply on the control connection.
	defer func() {
		_ = nc.Close()
		for range sess.ctlMsg {
		}
	}()
	defer sess.closeDataEndpoint()
	defer sess.closeJail()
	defer sess.logoutIfAuthenticated()

	if err := sess.reply(220, "ready"); err != nil {
		return
	}

	go sess.readControlLines()

	// Capture the configured idle timeout once at session start, matching
	// the SFTP per-session semantics. A zero value disables the deadline.
	// The idle timer below is only armed while the main loop is between
	// commands; an in-flight transfer is not counted as "idle" because
	// runTransfer blocks the main loop until it completes.
	idleTimeout := s.effectiveIdleTimeout()
	var idleTimer *time.Timer
	var idleC <-chan time.Time
	if idleTimeout > 0 {
		idleTimer = time.NewTimer(idleTimeout)
		idleC = idleTimer.C
		defer idleTimer.Stop()
	}
	for {
		if idleTimer != nil {
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleTimeout)
		}
		var msg ftpCtlMsg
		var ok bool
		select {
		case msg, ok = <-sess.ctlMsg:
			if !ok {
				return
			}
		case <-idleC:
			log.Printf("ftp control idle timeout from=%s", nc.RemoteAddr())
			return
		}
		if msg.err != nil {
			if errors.Is(msg.err, errFTPLineTooLong) {
				_ = sess.reply(500, ftpErrMsg(msg.err))
				log.Printf("ftp control read from=%s: line exceeded %d bytes", nc.RemoteAddr(), ftpMaxControlLineLen)
				return
			}
			if !errors.Is(msg.err, io.EOF) {
				log.Printf("ftp control read from=%s: %v", nc.RemoteAddr(), msg.err)
			}
			return
		}

		line := strings.TrimRight(msg.line, "\r\n")
		if line == "" {
			continue
		}
		cmd, arg := parseFTPCommand(line)
		quit := sess.handleFTPCommand(cmd, arg)
		if quit {
			return
		}
	}
}

// readControlLines is the sole reader of the control connection. It runs
// from session start until the connection closes (or an oversized line is
// encountered), delivering each parsed line to ctlMsg and a final error
// message before closing the channel. Centralising reads here is what
// lets a long-running data transfer also observe ABOR in real time.
func (f *ftpSession) readControlLines() {
	defer close(f.ctlMsg)
	for {
		line, err := readFTPControlLine(f.r, ftpMaxControlLineLen)
		f.ctlMsg <- ftpCtlMsg{line: line, err: err}
		if err != nil {
			return
		}
	}
}

// readFTPControlLine reads a single FTP control command terminated by '\n'
// from r, capped at maxLen bytes (including the terminator). When a client
// sends a longer line, the excess is discarded up to the next '\n' (or
// connection close) and errFTPLineTooLong is returned so the caller can
// reject the command and tear the session down.
func readFTPControlLine(r *bufio.Reader, maxLen int) (string, error) {
	buf := make([]byte, 0, 64)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\n' {
			return string(buf) + "\n", nil
		}
		if len(buf)+1 >= maxLen {
			// Drain the rest of the offending line so the protocol stream
			// stays aligned for the caller's error reply.
			for {
				b2, err := r.ReadByte()
				if err != nil {
					return "", errFTPLineTooLong
				}
				if b2 == '\n' {
					return "", errFTPLineTooLong
				}
			}
		}
		buf = append(buf, b)
	}
}

func parseFTPCommand(line string) (string, string) {
	line = strings.TrimLeft(line, " \t")
	if line == "" {
		return "", ""
	}
	cmd := line
	arg := ""
	if i := strings.IndexAny(line, " \t"); i >= 0 {
		cmd = line[:i]
		arg = strings.TrimLeft(line[i+1:], " \t")
	}
	return strings.ToUpper(cmd), arg
}

func (f *ftpSession) handleFTPCommand(cmd, arg string) bool {
	switch cmd {
	case "USER":
		f.logoutIfAuthenticated()
		f.username = arg
		f.authenticated = false
		f.user = UserInfo{}
		_ = f.reply(331, "password required")
		return false

	case "PASS":
		if f.username == "" {
			_ = f.reply(503, "send USER first")
			return false
		}
		if !f.authenticate(arg) {
			f.announceAuthEvent(AuthEventLoginFailed)
			_ = f.reply(530, errInvalidCredentials.Error())
			return false
		}
		log.Printf("login protocol=ftp user=%s root=%s from=%s", f.username, f.user.Root, f.conn.RemoteAddr())
		f.announceAuthEvent(AuthEventLoginSuccess)
		_ = f.reply(230, "login successful")
		return false

	case "QUIT":
		_ = f.reply(221, "goodbye")
		return true

	case "NOOP":
		_ = f.reply(200, "ok")
		return false

	case "SYST":
		_ = f.reply(215, "UNIX Type: L8")
		return false

	case "FEAT":
		features := []string{
			"UTF8",
			"EPSV",
			"PASV",
			"SIZE",
			"MDTM",
			"REST STREAM",
			"MLST type*;size*;modify*;perm*;unique*;",
			"MLSD",
			"TVFS",
			"LANG en-US*",
			"HOST",
		}
		if f.server.ftpAllowActiveMode {
			features = append(features, "EPRT")
		}
		_ = f.multilineReply(211, "Features:", features, "End")
		return false

	case "HELP":
		f.cmdHelp(arg)
		return false

	case "STAT":
		// STAT with no argument is server status and is commonly issued before
		// login; the path form falls through to the authenticated switch by
		// reusing cmdStat's own auth checks.
		f.cmdStat(arg)
		return false

	case "LANG":
		f.cmdLang(arg)
		return false

	case "HOST":
		f.cmdHost(arg)
		return false

	case "REIN":
		f.cmdRein()
		return false

	case "AUTH":
		// This implementation does not provide FTPS. Keep SFTP enabled for
		// encrypted transport; expose FTP only where plaintext FTP is acceptable.
		_ = f.reply(502, "AUTH not supported")
		return false
	}

	if !f.authenticated {
		_ = f.reply(530, "not logged in")
		return false
	}

	switch cmd {
	case "PWD", "XPWD":
		_ = f.reply(257, fmt.Sprintf("%s is the current directory", ftpQuotePath(f.cwd)))

	case "CWD":
		f.cmdCWD(arg)

	case "CDUP":
		f.cmdCWD("..")

	case "TYPE":
		// Transfers are binary-safe. Accept ASCII and binary mode for client
		// compatibility, but do not transform bytes.
		upper := strings.ToUpper(strings.TrimSpace(arg))
		if upper == "A" || upper == "A N" || upper == "I" || upper == "L 8" {
			_ = f.reply(200, "type set")
		} else {
			_ = f.reply(504, "unsupported type")
		}

	case "MODE":
		if strings.EqualFold(strings.TrimSpace(arg), "S") {
			_ = f.reply(200, "mode set")
		} else {
			_ = f.reply(504, "unsupported mode")
		}

	case "STRU":
		if strings.EqualFold(strings.TrimSpace(arg), "F") {
			_ = f.reply(200, "structure set")
		} else {
			_ = f.reply(504, "unsupported structure")
		}

	case "OPTS":
		if strings.EqualFold(strings.TrimSpace(arg), "UTF8 ON") {
			_ = f.reply(200, "UTF8 enabled")
		} else {
			_ = f.reply(501, "unsupported option")
		}

	case "PASV":
		f.enterPassive(false)

	case "EPSV":
		if strings.EqualFold(strings.TrimSpace(arg), "ALL") {
			f.closeDataEndpoint()
			f.epsvAll = true
			_ = f.reply(200, "EPSV ALL ok")
		} else {
			f.enterPassive(true)
		}

	case "PORT":
		f.enterActivePORT(arg)

	case "EPRT":
		f.enterActiveEPRT(arg)

	case "LIST":
		f.cmdList(arg, false)

	case "NLST":
		f.cmdList(arg, true)

	case "RETR":
		f.cmdRetr(arg)

	case "STOR":
		f.cmdStor(arg, false)

	case "APPE":
		f.cmdStor(arg, true)

	case "ALLO":
		f.cmdAllo(arg)

	case "REST":
		f.cmdRest(arg)

	case "SIZE":
		f.cmdSize(arg)

	case "MDTM":
		f.cmdMDTM(arg)

	case "DELE":
		f.cmdDelete(arg)

	case "MKD", "XMKD":
		f.cmdMkdir(arg)

	case "RMD", "XRMD":
		f.cmdRmdir(arg)

	case "RNFR":
		f.cmdRnfr(arg)

	case "RNTO":
		f.cmdRnto(arg)

	case "ABOR":
		f.closeDataListener()
		f.restartOffset = 0
		f.expectedUploadSize = 0
		_ = f.reply(226, "abort successful")

	case "MLST":
		f.cmdMLST(arg)

	case "MLSD":
		f.cmdMLSD(arg)

	case "SITE":
		// SITE has no portable subcommands here; reply cleanly rather than
		// the generic 502 so clients can probe without ambiguity.
		_ = f.reply(502, "SITE command not implemented")

	case "MFMT", "MFCT":
		// Setting modification times on jailed files is denied wholesale by the
		// same policy that rejects SFTP Acmodtime. Reply with the canonical
		// "command not implemented for that parameter" code so MFMT-aware
		// clients (backup/sync tools) get a deterministic, well-formed refusal.
		_ = f.reply(502, cmd+" not supported")

	default:
		_ = f.reply(502, "command not implemented")
	}
	return false
}

func (f *ftpSession) authenticate(pass string) bool {
	u, jailRoot, ok := f.server.authenticateUser(f.username, func(stored UserInfo) bool {
		return checkPassword(stored.Password, pass)
	})
	if !ok {
		return false
	}
	// Open the fd-relative jail filesystem now. If openat2 is not available
	// on the running kernel this fails and the login is rejected, preserving
	// the package's hardened guarantee that all subsequent FTP commands
	// operate via openat2.
	jfs, err := openJailFS(jailRoot)
	if err != nil {
		log.Printf("ftp open jail root %q for user %q: %v", jailRoot, f.username, err)
		return false
	}
	// Release any previous jail from a stale session that re-used USER/PASS.
	f.closeJail()
	f.fs = jfs
	f.user = UserInfo{
		Password:       u.Password,
		Root:           jailRoot,
		CanRead:        u.CanRead,
		CanWrite:       u.CanWrite,
		AuthorizedKeys: slices.Clone(u.AuthorizedKeys),
	}
	f.authenticated = true
	f.cwd = "/"
	f.rnfrPath = ""
	f.restartOffset = 0
	// Tie the connection to the authenticated user so RemoveUser can
	// force-close active FTP sessions if the account is revoked.
	f.server.setConnUser(f.conn, f.username)
	return true
}

func (f *ftpSession) announceAuthEvent(eventType AuthEventType) {
	announceAuthEvent(f.authEvents, AuthEvent{
		Type:     eventType,
		Username: f.username,
		ClientIP: f.clientIP,
		Protocol: CompletedUploadProtocolFTP,
	})
}

func (f *ftpSession) logoutIfAuthenticated() {
	if !f.authenticated {
		return
	}
	f.announceAuthEvent(AuthEventLogout)
	f.authenticated = false
	f.user = UserInfo{}
	f.rnfrPath = ""
	f.restartOffset = 0
	f.closeJail()
}

// closeJail releases the session's jail filesystem fd, if any. It is safe to
// call multiple times.
func (f *ftpSession) closeJail() {
	if f.fs != nil {
		_ = f.fs.Close()
		f.fs = nil
	}
}

func (f *ftpSession) reply(code int, message string) error {
	_, err := fmt.Fprintf(f.w, "%d %s\r\n", code, message)
	if err != nil {
		return err
	}
	return f.w.Flush()
}

func (f *ftpSession) multilineReply(code int, first string, lines []string, last string) error {
	if _, err := fmt.Fprintf(f.w, "%d-%s\r\n", code, first); err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := fmt.Fprintf(f.w, " %s\r\n", line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(f.w, "%d %s\r\n", code, last); err != nil {
		return err
	}
	return f.w.Flush()
}

func (f *ftpSession) cleanPath(p string) string {
	p = strings.TrimSpace(unquoteFTPPath(p))
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" {
		return f.cwd
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(f.cwd, p)
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p == "." {
		return "/"
	}
	return p
}

func unquoteFTPPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		p = p[1 : len(p)-1]
		p = strings.ReplaceAll(p, "\"\"", "\"")
	}
	return p
}

func ftpQuotePath(p string) string {
	p = sanitizeFTPText(p)
	return "\"" + strings.ReplaceAll(p, "\"", "\"\"") + "\""
}

// listPathArg extracts the pathname argument from a LIST/NLST/STAT line,
// discarding any leading ls-style flags. Only the first non-flag token is
// honoured: anything after it is dropped on the floor rather than being
// silently concatenated. FTP has no quoting convention for the LIST
// argument, so an unquoted multi-word path is ambiguous with a series of
// stray arguments — RFC 959 specifies a single optional pathname, so the
// strict interpretation is the safer one.
func listPathArg(arg string) string {
	for _, field := range strings.Fields(arg) {
		if strings.HasPrefix(field, "-") {
			continue
		}
		return field
	}
	return ""
}

func (f *ftpSession) cmdCWD(arg string) {
	if !f.user.CanRead && !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	if !st.IsDir() {
		_ = f.reply(550, "not a directory")
		return
	}
	f.cwd = ftpPath
	_ = f.reply(250, "directory changed")
}

func (f *ftpSession) enterPassive(epsv bool) {
	f.closeDataEndpoint()

	host, _, err := net.SplitHostPort(f.conn.LocalAddr().String())
	if err != nil || host == "" {
		_ = f.reply(425, "cannot determine local address")
		return
	}

	ip := net.ParseIP(host)
	if !epsv && ip.To4() == nil {
		_ = f.reply(522, "network protocol not supported, use EPSV")
		return
	}

	ln, err := f.server.listenFTPData(host)
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	f.dataLn = ln

	port := ln.Addr().(*net.TCPAddr).Port
	if epsv {
		_ = f.reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
		return
	}

	v4 := ip.To4()
	p1 := port / 256
	p2 := port % 256
	_ = f.reply(227, fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", v4[0], v4[1], v4[2], v4[3], p1, p2))
}

func (f *ftpSession) enterActivePORT(arg string) {
	f.closeDataEndpoint()
	if !f.activeModeAllowed() {
		_ = f.reply(502, "active mode is disabled; use PASV or EPSV")
		return
	}

	addr, err := parseFTPPORTArg(arg)
	if err != nil {
		_ = f.reply(501, "invalid PORT")
		return
	}
	f.enterActive(addr)
}

func (f *ftpSession) enterActiveEPRT(arg string) {
	f.closeDataEndpoint()
	if !f.activeModeAllowed() {
		_ = f.reply(502, "active mode is disabled; use PASV or EPSV")
		return
	}

	addr, err := parseFTPEPRTArg(arg)
	if err != nil {
		_ = f.reply(501, "invalid EPRT")
		return
	}
	f.enterActive(addr)
}

func (f *ftpSession) activeModeAllowed() bool {
	return f.server.ftpAllowActiveMode && !f.epsvAll
}

func (f *ftpSession) enterActive(addr *net.TCPAddr) {
	if !f.activeTargetAllowed(addr.IP) {
		_ = f.reply(501, "active target address not allowed")
		return
	}
	f.closeDataEndpoint()
	f.dataAddr = addr
	_ = f.reply(200, "active mode ready")
}

func (f *ftpSession) activeTargetAllowed(ip net.IP) bool {
	clientIP := net.ParseIP(f.clientIP)
	return clientIP != nil && ip != nil && ip.Equal(clientIP)
}

func parseFTPPORTArg(arg string) (*net.TCPAddr, error) {
	parts := strings.Split(strings.TrimSpace(arg), ",")
	if len(parts) != 6 {
		return nil, errors.New("invalid PORT")
	}
	values := make([]int, len(parts))
	for i, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 0 || n > 255 {
			return nil, errors.New("invalid PORT")
		}
		values[i] = n
	}
	port := values[4]*256 + values[5]
	if port <= 0 || port > 65535 {
		return nil, errors.New("invalid PORT")
	}
	return &net.TCPAddr{
		IP:   net.IPv4(byte(values[0]), byte(values[1]), byte(values[2]), byte(values[3])),
		Port: port,
	}, nil
}

func parseFTPEPRTArg(arg string) (*net.TCPAddr, error) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 5 {
		return nil, errors.New("invalid EPRT")
	}
	delim := arg[:1]
	parts := strings.Split(arg[1:], delim)
	if len(parts) != 4 || parts[3] != "" {
		return nil, errors.New("invalid EPRT")
	}
	family, addrText, portText := parts[0], parts[1], parts[2]
	ip := net.ParseIP(addrText)
	if ip == nil {
		return nil, errors.New("invalid EPRT")
	}
	switch family {
	case "1":
		ip = ip.To4()
		if ip == nil {
			return nil, errors.New("invalid EPRT")
		}
	case "2":
		if ip.To4() != nil {
			return nil, errors.New("invalid EPRT")
		}
	default:
		return nil, errors.New("invalid EPRT")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("invalid EPRT")
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

func (f *ftpSession) acceptDataConn() (net.Conn, error) {
	if f.dataLn != nil {
		ln := f.dataLn
		f.dataLn = nil
		defer func() { _ = ln.Close() }()

		if tcpLn, ok := ln.(*net.TCPListener); ok {
			if timeout := f.server.effectiveFTPDataAcceptTimeout(); timeout > 0 {
				_ = tcpLn.SetDeadline(time.Now().Add(timeout))
			}
		}

		dc, err := ln.Accept()
		if err != nil {
			return nil, err
		}

		// Prevent passive data-port stealing by requiring the data connection to
		// originate from the same IP as the control connection.
		if f.clientIP != "" && remoteIP(dc.RemoteAddr()) != f.clientIP {
			_ = dc.Close()
			return nil, fmt.Errorf("data connection from unexpected IP %s", remoteIP(dc.RemoteAddr()))
		}

		return dc, nil
	}

	if f.dataAddr != nil {
		addr := f.dataAddr
		f.dataAddr = nil
		dialer := net.Dialer{}
		if timeout := f.server.effectiveFTPDataAcceptTimeout(); timeout > 0 {
			dialer.Timeout = timeout
		}
		return dialer.Dial("tcp", addr.String())
	}

	return nil, errors.New("data connection not prepared")
}

func (f *ftpSession) closeDataListener() {
	if f.dataLn != nil {
		_ = f.dataLn.Close()
		f.dataLn = nil
	}
}

func (f *ftpSession) closeDataEndpoint() {
	f.closeDataListener()
	f.dataAddr = nil
}

// runTransfer executes work on dc while watching the control connection
// for ABOR. If ABOR arrives mid-transfer it closes dc (forcing work to
// return), drains the worker, and reports aborted=true; the caller is
// then responsible for the RFC 959 reply sequence (426 to the transfer
// command, 226 to the ABOR). Control commands other than ABOR received
// during a transfer are answered with 503 and the transfer continues.
// A control-reader error or close also aborts the transfer so the
// session can shut down cleanly; the main loop will observe the same
// signal on its next receive from ctlMsg.
func (f *ftpSession) runTransfer(dc net.Conn, work func() error) (aborted bool, transferErr error) {
	done := make(chan error, 1)
	go func() {
		done <- work()
	}()

	for {
		select {
		case transferErr = <-done:
			return false, transferErr
		case msg, ok := <-f.ctlMsg:
			if !ok || msg.err != nil {
				_ = dc.Close()
				transferErr = <-done
				return true, transferErr
			}
			cmd, _ := parseFTPCommand(strings.TrimRight(msg.line, "\r\n"))
			if cmd == "ABOR" {
				_ = dc.Close()
				transferErr = <-done
				return true, transferErr
			}
			_ = f.reply(503, "transfer in progress")
		}
	}
}

// replyAborted emits the RFC 959 two-message sequence for a transfer that
// was interrupted by ABOR: 426 closes out the transfer command, then 226
// acknowledges the ABOR itself. Centralising this keeps the wording (and
// the order) consistent across cmdStor/cmdRetr/cmdList/cmdMLSD.
func (f *ftpSession) replyAborted() {
	_ = f.reply(426, "transfer aborted")
	_ = f.reply(226, "abort successful")
}

func (f *ftpSession) cmdList(arg string, namesOnly bool) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(listPathArg(arg))
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer func() { _ = dc.Close() }()

	// Apply a per-Write idle deadline so a client that opens the data
	// connection but refuses to read does not pin this goroutine and FD
	// indefinitely once its TCP receive buffer fills.
	idleDC := &idleConn{Conn: dc}
	idleDC.setWriteTimeout(ftpDataIdleTimeout)
	aborted, copyErr := f.runTransfer(dc, func() error {
		formatLine := func(info os.FileInfo, name string) string {
			if namesOnly {
				return sanitizeFTPText(name)
			}
			return ftpListLine(info, name)
		}
		writeLine := func(line string) error {
			_, err := io.WriteString(idleDC, line+"\r\n")
			return err
		}
		if !st.IsDir() {
			return writeLine(formatLine(st, path.Base(ftpPath)))
		}
		// Stream directory entries straight to the data connection so a
		// directory with millions of entries does not have to be buffered
		// in memory before transmission begins.
		return f.fs.ListStream(ftpPath, func(info os.FileInfo) error {
			return writeLine(formatLine(info, info.Name()))
		})
	})
	if aborted {
		f.replyAborted()
		return
	}
	if copyErr != nil {
		_ = f.reply(426, ftpErrMsg(copyErr))
		return
	}
	_ = f.reply(226, "transfer complete")
}

func ftpListLine(info os.FileInfo, name string) string {
	mtime := info.ModTime()
	now := time.Now()
	timePart := mtime.Format("Jan _2 15:04")
	if mtime.Before(now.Add(-180*24*time.Hour)) || mtime.After(now.Add(24*time.Hour)) {
		timePart = mtime.Format("Jan _2  2006")
	}
	return fmt.Sprintf("%s 1 ftp ftp %12d %s %s", ftpModeString(info.Mode()), info.Size(), timePart, sanitizeFTPText(name))
}

func ftpModeString(mode os.FileMode) string {
	buf := []byte("----------")
	if mode.IsDir() {
		buf[0] = 'd'
	} else if mode&os.ModeSymlink != 0 {
		buf[0] = 'l'
	}
	bits := []struct {
		bit os.FileMode
		idx int
		chr byte
	}{
		{0400, 1, 'r'}, {0200, 2, 'w'}, {0100, 3, 'x'},
		{0040, 4, 'r'}, {0020, 5, 'w'}, {0010, 6, 'x'},
		{0004, 7, 'r'}, {0002, 8, 'w'}, {0001, 9, 'x'},
	}
	for _, b := range bits {
		if mode&b.bit != 0 {
			buf[b.idx] = b.chr
		}
	}
	return string(buf)
}

// consumeTransferHints atomically captures and clears both the REST restart
// offset and the ALLO expected-size hint. Calling it at the top of cmdStor
// (and cmdRetr) ensures that every exit path — error or success — always
// leaves both fields zeroed, with no risk of a stale hint leaking into a
// subsequent transfer command.
func (f *ftpSession) consumeTransferHints() (restartOffset, expectedSize int64) {
	restartOffset, expectedSize = f.restartOffset, f.expectedUploadSize
	f.restartOffset = 0
	f.expectedUploadSize = 0
	return
}

func (f *ftpSession) cmdRetr(arg string) {
	restartOffset, _ := f.consumeTransferHints()
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	file, err := f.fs.OpenRead(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	defer func() { _ = file.Close() }()

	if restartOffset > 0 {
		if _, err := file.Seek(restartOffset, io.SeekStart); err != nil {
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
	}

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer func() { _ = dc.Close() }()

	// Apply a per-Write idle deadline so a client that opens the data
	// connection but refuses to read (filling its TCP receive buffer) does
	// not pin this goroutine and FD indefinitely.
	idleDC := &idleConn{Conn: dc}
	idleDC.setWriteTimeout(ftpDataIdleTimeout)
	aborted, copyErr := f.runTransfer(dc, func() error {
		_, err := io.Copy(idleDC, file)
		return err
	})
	if aborted {
		f.replyAborted()
		return
	}
	if copyErr != nil {
		_ = f.reply(426, ftpErrMsg(copyErr))
		return
	}
	_ = f.reply(226, "transfer complete")
}

func (f *ftpSession) cmdStor(arg string, appendMode bool) {
	restartOffset, expectedSize := f.consumeTransferHints()
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if hasCRLF(arg) {
		_ = f.reply(553, "invalid filename")
		return
	}
	ftpPath := f.cleanPath(arg)

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer func() { _ = dc.Close() }()

	flags := os.O_CREATE | os.O_WRONLY
	switch {
	case appendMode:
		flags |= os.O_APPEND
	case restartOffset > 0:
		// Keep existing bytes and resume at requested offset.
	default:
		flags |= os.O_TRUNC
	}

	file, err := f.fs.OpenWrite(ftpPath, flags, 0600)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}

	if restartOffset > 0 && !appendMode {
		// Reject restart offsets beyond the current end of file. Without
		// this guard, O_CREATE+seek+write would happily produce a sparse
		// file with a hole between the previous EOF and restartOffset —
		// silently corrupting the upload (the hole reads back as NULs,
		// not as the bytes the client thought it had already sent).
		// This also covers the "REST N + STOR newfile" case, where the
		// file is created at size 0 and any positive offset is invalid.
		st, statErr := file.Stat()
		if statErr != nil {
			_ = file.Close()
			_ = f.reply(550, ftpErrMsg(statErr))
			return
		}
		if restartOffset > st.Size() {
			offset, size := restartOffset, st.Size()
			_ = file.Close()
			_ = f.reply(554, fmt.Sprintf("restart offset %d exceeds file size %d", offset, size))
			return
		}
		if _, err := file.Seek(restartOffset, io.SeekStart); err != nil {
			_ = file.Close()
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
	}

	log.Printf("upload protocol=ftp path=%q", ftpPath)
	// Wrap the data connection so that every Read enforces a fresh idle
	// deadline. A stalled client that stops sending bytes but keeps the TCP
	// connection open will surface as a read error from io.Copy below, which
	// in turn skips the CompletedUploads notification — partial uploads must
	// never be announced as complete.
	//
	// FTP STREAM mode signals "end of file" by half-closing the data
	// connection, so a client that uploads N bytes then half-closes is
	// indistinguishable at the protocol level from a client that intended
	// to upload exactly N bytes. The only reliable defense is an explicit
	// size hint from the client (ALLO); when present, the byte count is
	// verified below and a mismatch is rejected. Without ALLO the idle
	// deadline still catches stalls, but a deliberate early half-close
	// will be accepted — that is an inherent limitation of FTP itself,
	// and downstream consumers of CompletedUploads must treat events from
	// no-ALLO transfers as best-effort.
	idleDC := &idleConn{Conn: dc}
	idleDC.setReadTimeout(ftpDataIdleTimeout)
	var written int64
	aborted, copyErr := f.runTransfer(dc, func() error {
		n, err := io.Copy(file, idleDC)
		written = n
		return err
	})
	closeErr := file.Close()
	if aborted {
		log.Printf("upload aborted protocol=ftp path=%q bytes=%d", ftpPath, written)
		f.replyAborted()
		return
	}
	if copyErr != nil {
		log.Printf("upload interrupted protocol=ftp path=%q: %v", ftpPath, copyErr)
		_ = f.reply(426, ftpErrMsg(copyErr))
		return
	}
	if closeErr != nil {
		log.Printf("upload interrupted protocol=ftp path=%q close: %v", ftpPath, closeErr)
		_ = f.reply(451, ftpErrMsg(closeErr))
		return
	}
	if expectedSize > 0 && written != expectedSize {
		log.Printf("upload size mismatch protocol=ftp path=%q expected=%d got=%d", ftpPath, expectedSize, written)
		_ = f.reply(551, fmt.Sprintf("expected %d bytes, received %d", expectedSize, written))
		return
	}

	f.announceUpload(ftpPath, f.fs.fullPath(ftpPath))
	_ = f.reply(226, "transfer complete")
}

// announceUpload publishes the CompletedUpload event for a successful STOR.
//
// Completeness guarantee: when the client preceded STOR with ALLO, cmdStor
// verifies the byte count matches before calling here, so the event is
// authoritative. Without an ALLO hint, FTP STREAM mode cannot distinguish
// "client sent every intended byte then half-closed" from "client truncated
// mid-transfer", so the event is best-effort — its absence is not proof of
// failure and its presence is not proof of byte-level integrity.
func (f *ftpSession) announceUpload(ftpPath, fullPath string) {
	log.Printf("upload complete: %q", ftpPath)
	if hasTempExt(ftpPath, f.tempExts) {
		log.Printf("upload complete: %q has temp extension, deferring CompletedUploads notification", ftpPath)
		return
	}
	publishUpload(f.uploads, CompletedUpload{
		Username:     f.username,
		FullFilePath: fullPath,
		FilePath:     ftpPath,
		ClientIP:     f.clientIP,
		Protocol:     CompletedUploadProtocolFTP,
	})
}

// cmdHelp answers the HELP command. With no argument it returns a multi-line
// reply listing supported commands; with an argument it returns a short
// per-command line. The list deliberately covers only commands this server
// implements — clients that probe for an unlisted command will still get a
// 502 from the command dispatcher itself.
func (f *ftpSession) cmdHelp(arg string) {
	arg = strings.TrimSpace(arg)
	if arg != "" {
		upper := strings.ToUpper(arg)
		if (upper == "PORT" || upper == "EPRT") && !f.server.ftpAllowActiveMode {
			_ = f.reply(502, "active mode is disabled; use PASV or EPSV")
			return
		}
		_ = f.reply(214, fmt.Sprintf("%s command recognized", upper))
		return
	}
	lines := []string{
		"USER PASS QUIT NOOP SYST FEAT HELP STAT",
		"PWD CWD CDUP TYPE MODE STRU OPTS REIN",
		"PASV EPSV LIST NLST MLST MLSD",
		"RETR STOR APPE ALLO REST SIZE MDTM",
		"DELE MKD RMD RNFR RNTO ABOR",
		"LANG HOST",
	}
	if f.server.ftpAllowActiveMode {
		lines = append(lines, "PORT EPRT")
	}
	_ = f.multilineReply(214, "The following commands are recognized:", lines, "End")
}

// cmdLang answers the LANG command (RFC 2640). The server's only output
// language is English; UTF-8 byte semantics are already announced via OPTS
// UTF8. We accept "en", "en-US", or an empty argument as success and reject
// everything else with 504, mirroring how OpenSSH and other minimal servers
// handle language negotiation.
func (f *ftpSession) cmdLang(arg string) {
	tag := strings.TrimSpace(arg)
	if tag == "" {
		_ = f.reply(200, "language set to en-US")
		return
	}
	upper := strings.ToUpper(tag)
	if upper == "EN" || upper == "EN-US" {
		_ = f.reply(200, "language set to en-US")
		return
	}
	_ = f.reply(504, "language not supported")
}

// cmdHost answers the HOST command (RFC 7151). This server does not implement
// per-virtual-host user databases — every listener serves the single user set
// configured on the server. Accept any well-formed host name so HOST-aware
// clients can advance past the handshake; reject only the few cases where the
// argument is clearly malformed.
func (f *ftpSession) cmdHost(arg string) {
	if f.authenticated {
		// RFC 7151 §3.1: HOST must be sent before authentication. Once a user
		// is logged in, refuse to switch virtual hosts.
		_ = f.reply(503, "HOST cannot be issued after login")
		return
	}
	host := strings.TrimSpace(arg)
	if host == "" || hasCRLF(host) || len(host) > 255 {
		_ = f.reply(501, "invalid host name")
		return
	}
	_ = f.reply(220, "host accepted")
}

// cmdRein answers the REIN command. RFC 959 specifies that REIN flushes any
// authentication state and returns the session to the pre-login state without
// closing the control connection. Any pending data transfer is aborted.
func (f *ftpSession) cmdRein() {
	f.closeDataEndpoint()
	f.logoutIfAuthenticated()
	f.username = ""
	f.cwd = "/"
	f.rnfrPath = ""
	f.restartOffset = 0
	f.expectedUploadSize = 0
	f.epsvAll = false
	// The session is no longer tied to the previous user; clear the
	// connection's user association so a RemoveUser for that name does not
	// kick this now-anonymous session.
	f.server.setConnUser(f.conn, "")
	_ = f.reply(220, "ready for new user")
}

// cmdStat answers the STAT command. With no argument it reports server
// status; with a path argument it returns a directory/file listing inline
// over the control connection (no data connection), which clients often
// issue immediately after login as a low-overhead probe.
func (f *ftpSession) cmdStat(arg string) {
	// Use rawPath rather than path here: a local named "path" would shadow
	// the imported "path" package, so any future edit that calls path.Base
	// or path.Clean inside this function would silently become a method
	// call on a string.
	rawPath := strings.TrimSpace(arg)
	if rawPath == "" {
		lines := []string{
			fmt.Sprintf("Connected from %s", sanitizeFTPText(f.clientIP)),
			fmt.Sprintf("Logged in as %s", sanitizeFTPText(f.username)),
			"TYPE: BINARY",
			"No data connection",
		}
		_ = f.multilineReply(211, "Server status:", lines, "End of status")
		return
	}
	if !f.authenticated {
		_ = f.reply(530, "not logged in")
		return
	}
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(listPathArg(rawPath))
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	var lines []string
	if st.IsDir() {
		entries, err := f.fs.List(ftpPath)
		if err != nil {
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
		for _, info := range entries {
			lines = append(lines, ftpListLine(info, info.Name()))
		}
	} else {
		lines = append(lines, ftpListLine(st, ftpPathBase(ftpPath)))
	}
	_ = f.multilineReply(213, "Status of "+ftpQuotePath(ftpPath)+":", lines, "End of status")
}

// cmdMLST answers MLST (RFC 3659). MLST returns machine-readable facts for a
// single path inline on the control connection, never opening a data
// connection. The reply format is "211-Listing\r\n <facts> name\r\n211 End".
func (f *ftpSession) cmdMLST(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	// The MLST fact-line is required to start with a single space, per RFC
	// 3659 §4.8 ("Each fact-set is preceded by a single space"). multilineReply
	// already prefixes intermediate lines with a space, so the payload here is
	// just "facts; name" without leading whitespace.
	line := mlstFactLine(st, ftpPath, f.user.CanWrite)
	_ = f.multilineReply(250, "Listing "+ftpQuotePath(ftpPath), []string{line}, "End")
}

// cmdMLSD answers MLSD (RFC 3659). MLSD returns machine-readable facts for
// every entry in a directory over the data connection, terminating with
// 226 once the listing has been written.
func (f *ftpSession) cmdMLSD(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	if !st.IsDir() {
		_ = f.reply(501, "MLSD requires a directory")
		return
	}

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer func() { _ = dc.Close() }()

	idleDC := &idleConn{Conn: dc}
	idleDC.setWriteTimeout(ftpDataIdleTimeout)
	aborted, copyErr := f.runTransfer(dc, func() error {
		// Stream entries straight to the data connection rather than
		// materialising the whole listing in memory — see cmdList.
		return f.fs.ListStream(ftpPath, func(info os.FileInfo) error {
			line := mlstFactLine(info, info.Name(), f.user.CanWrite)
			_, err := io.WriteString(idleDC, line+"\r\n")
			return err
		})
	})
	if aborted {
		f.replyAborted()
		return
	}
	if copyErr != nil {
		_ = f.reply(426, ftpErrMsg(copyErr))
		return
	}
	_ = f.reply(226, "transfer complete")
}

// mlstFactLine renders a single MLST/MLSD entry: a fact-set followed by a
// space and the entry name. The facts emitted match the FEAT advertisement
// (type, size, modify, perm, unique). For MLST the caller passes the full
// path; for MLSD the basename.
func mlstFactLine(info os.FileInfo, name string, canWrite bool) string {
	var typeFact string
	switch {
	case info.IsDir():
		typeFact = "dir"
	case info.Mode()&os.ModeSymlink != 0:
		typeFact = "OS.unix=symlink"
	default:
		typeFact = "file"
	}
	var b strings.Builder
	b.WriteString("type=")
	b.WriteString(typeFact)
	b.WriteString(";size=")
	b.WriteString(strconv.FormatInt(info.Size(), 10))
	b.WriteString(";modify=")
	b.WriteString(info.ModTime().UTC().Format("20060102150405"))
	b.WriteString(";perm=")
	b.WriteString(mlstPermFact(info, canWrite))
	b.WriteString(";unique=")
	b.WriteString(mlstUniqueFact(info))
	b.WriteString("; ")
	b.WriteString(sanitizeFTPText(name))
	return b.String()
}

// mlstPermFact builds the RFC 3659 "perm" fact for an entry. The flags
// reported are bounded by what this server actually exposes: read implies
// list/retrieve, write implies store/append/delete/rename/mkdir. Symlinks
// are never traversable through the jail and so report no permissions.
func mlstPermFact(info os.FileInfo, canWrite bool) string {
	if info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	var b strings.Builder
	if info.IsDir() {
		b.WriteString("el") // enter / list
		if canWrite {
			b.WriteString("cmp") // create / make-dir / delete contents
		}
	} else {
		b.WriteString("r") // retrieve
		if canWrite {
			b.WriteString("adfw") // append / delete / rename-from / store
		}
	}
	return b.String()
}

// mlstUniqueFact returns a stable per-entry identifier for the "unique"
// fact. Per RFC 3659 the value need only be unique within the server; we
// derive it from dev+ino when available and fall back to mtime+size.
func mlstUniqueFact(info os.FileInfo) string {
	if st, ok := info.Sys().(*unix.Stat_t); ok && st != nil {
		return fmt.Sprintf("%XU%X", st.Dev, st.Ino)
	}
	return fmt.Sprintf("M%XS%X", info.ModTime().UnixNano(), info.Size())
}

// ftpPathBase returns the basename of an FTP path, treating "/" as the root.
func ftpPathBase(p string) string {
	if p == "/" || p == "" {
		return "/"
	}
	return path.Base(p)
}

// cmdAllo answers the ALLO command (RFC 959 §4.1.3). The size argument is
// recorded so the next STOR/APPE can verify the uploaded byte count matches
// — STREAM mode signals end-of-file by half-close, which is otherwise
// indistinguishable from a client that deliberately truncates the upload.
// The "R record-size" form is accepted for compatibility (STRU F is the
// only structure supported, so record size is meaningless here).
func (f *ftpSession) cmdAllo(arg string) {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		_ = f.reply(501, "missing size")
		return
	}
	size, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || size < 0 {
		_ = f.reply(501, "invalid size")
		return
	}
	f.expectedUploadSize = size
	_ = f.reply(200, "allocation noted")
}

func (f *ftpSession) cmdRest(arg string) {
	offset, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
	if err != nil || offset < 0 {
		f.restartOffset = 0
		_ = f.reply(501, "invalid restart offset")
		return
	}
	f.restartOffset = offset
	_ = f.reply(350, "restart position accepted")
}

func (f *ftpSession) cmdSize(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	st, err := f.fs.Stat(f.cleanPath(arg))
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	if st.IsDir() {
		_ = f.reply(550, "not a regular file")
		return
	}
	_ = f.reply(213, strconv.FormatInt(st.Size(), 10))
}

func (f *ftpSession) cmdMDTM(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	st, err := f.fs.Stat(f.cleanPath(arg))
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(213, st.ModTime().UTC().Format("20060102150405"))
}

func (f *ftpSession) cmdDelete(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if err := f.fs.Remove(f.cleanPath(arg)); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(250, "deleted")
}

func (f *ftpSession) cmdMkdir(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if hasCRLF(arg) {
		_ = f.reply(553, "invalid filename")
		return
	}
	ftpPath := f.cleanPath(arg)
	if err := f.fs.Mkdir(ftpPath, 0750); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(257, fmt.Sprintf("%s created", ftpQuotePath(ftpPath)))
}

func (f *ftpSession) cmdRmdir(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if err := f.fs.Rmdir(f.cleanPath(arg)); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(250, "removed")
}

func (f *ftpSession) cmdRnfr(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	if _, err := f.fs.Stat(ftpPath); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	f.rnfrPath = ftpPath
	_ = f.reply(350, "ready for RNTO")
}

func (f *ftpSession) cmdRnto(arg string) {
	if !f.user.CanWrite {
		f.rnfrPath = ""
		_ = f.reply(550, "permission denied")
		return
	}
	if f.rnfrPath == "" {
		_ = f.reply(503, "send RNFR first")
		return
	}
	if hasCRLF(arg) {
		f.rnfrPath = ""
		_ = f.reply(553, "invalid filename")
		return
	}
	oldPath := f.rnfrPath
	f.rnfrPath = ""

	newPath := f.cleanPath(arg)
	if err := f.fs.Rename(oldPath, newPath); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	maybeAnnounceTempRename(f.uploads, f.tempExts, oldPath, CompletedUpload{
		Username:     f.username,
		FullFilePath: f.fs.fullPath(newPath),
		FilePath:     newPath,
		ClientIP:     f.clientIP,
		Protocol:     CompletedUploadProtocolFTP,
	})
	_ = f.reply(250, "renamed")
}
