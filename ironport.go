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
//   - Graceful shutdown via Close; upload-completion notifications via CompletedUploads.
//   - Optional passive-mode FTP listener sharing the same users, jails, permissions,
//     temp-extension handling, and CompletedUploads stream as SFTP.
//
// Typical usage:
//
//	cfg := ironport.DefaultIronportConfig()
//	cfg.Addr = ":2022"
//	cfg.FtpAddr = ":2121"
//	cfg.Users = users
//	cfg.Signer = signer
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Default timeouts and limits applied unless callers override them.
const (
	// defaultSFTPIdleTimeout is the default per-connection inactivity timeout
	// applied to SFTP sessions when server.IdleTimeout is zero. A client that
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
	// defaultCompletedUploadsSize is the fallback buffer size used for the
	// CompletedUploads channel.
	defaultCompletedUploadsSize = 64
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
)

// errFTPLineTooLong is returned when an FTP client sends a control-channel
// command that exceeds ftpMaxControlLineLen bytes.
var errFTPLineTooLong = errors.New("ftp control line too long")

// errSFTPRequestFailed is returned to SFTP clients for unknown backend errors
// so internal paths and server details are not exposed.
var errSFTPRequestFailed = errors.New("request failed")

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
	if u.AuthorizedKeys != nil {
		u.AuthorizedKeys = append([]ssh.PublicKey(nil), u.AuthorizedKeys...)
	}
	return u
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
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
}

// server is a self-contained SFTP server with optional FTP support.
// It is unexported so external callers construct servers through NewServer.
type server struct {
	// addr is the TCP address to listen on for SFTP, e.g. ":2022".
	addr string
	// ftpAddr is the TCP address to listen on for FTP, e.g. ":2121".
	// Set it to "" to disable FTP.
	ftpAddr string
	// ftpPassivePortRange optionally constrains FTP passive-mode data listeners
	// to a single port or inclusive range such as "5000-5010". Leave it empty
	// to let the OS choose any available port.
	ftpPassivePortRange string
	// users maps usernames to their credentials and jail roots.
	users map[string]UserInfo
	// mu protects users, completedUploads, and listeners for concurrent reads and writes.
	mu sync.RWMutex
	// ln is the active SFTP listener; set by ListenAndServe and closed by Close.
	ln net.Listener
	// ftpLn is the active FTP listener; set by ListenAndServe and closed by Close.
	ftpLn net.Listener
	// signer is the host key used for the SSH handshake.
	signer ssh.Signer
	// SSH algorithm allow-lists. Nil slices use golang.org/x/crypto/ssh
	// defaults.
	sshKeyExchanges            []string
	sshCiphers                 []string
	sshMACs                    []string
	sshPublicKeyAuthAlgorithms []string
	// completedUploads receives upload notifications. Use CompletedUploads to
	// access it as a receive-only stream.
	completedUploads chan CompletedUpload
	// TempExtensions is an optional list of file extensions (each beginning
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
	// Matching is case-insensitive. Setting this field after the server has
	// started has effect only on connections accepted afterwards.
	TempExtensions []string
	// IdleTimeout bounds how long an authenticated SFTP connection may sit
	// without receiving any data before being closed. A zero value selects
	// the package default (15 minutes); a negative value disables the idle
	// timeout entirely. Setting this field after the server has started has
	// effect only on connections accepted afterwards.
	IdleTimeout time.Duration
	// AllowChown controls whether SFTP clients may change the ownership
	// (uid/gid) of files in their jail via Setstat/Fsetstat requests.
	// It defaults to false: chown requests are rejected with a permission
	// error. Enable it only when the server runs with sufficient privilege
	// (typically as root with CAP_CHOWN) AND the deployment trusts
	// authenticated users not to chown their files to other UIDs.
	// Setting this field after the server has started has effect only on
	// connections accepted afterwards.
	AllowChown bool
	// connWG tracks in-flight per-connection handler goroutines so that
	// Shutdown can wait for them to finish. Each accepted connection adds
	// one before its goroutine starts and decrements on goroutine exit.
	// connWG.Add is always called under mu so it is serialised with
	// shuttingDown reads/writes; this keeps the Add/Wait pair race-free
	// per the sync.WaitGroup contract.
	connWG sync.WaitGroup
	// activeConns holds every accepted connection that has not yet returned
	// from its handler. It is consulted by Shutdown to force-close
	// stragglers when the caller's context deadline fires.
	activeConns map[net.Conn]struct{}
	// shuttingDown is set by Shutdown so subsequent trackConn calls refuse
	// new work instead of starting handlers we would have to drain. It is
	// guarded by mu so it serialises with connWG.Add inside trackConn.
	// Shutdown is one-shot: once set, ListenAndServe cannot start again.
	shuttingDown bool
}

// ironportConfig holds the values used to construct a server.
type ironportConfig struct {
	Addr                string
	FtpAddr             string
	FtpPassivePortRange string
	Users               map[string]UserInfo
	Signer              ssh.Signer
	CompletedUploadSize int
	// SSHKeyExchanges, SSHCiphers, SSHMACs, and
	// SSHPublicKeyAuthAlgorithms optionally pin SSH negotiation and public-key
	// auth signature algorithms. Nil slices use golang.org/x/crypto/ssh
	// defaults.
	SSHKeyExchanges            []string
	SSHCiphers                 []string
	SSHMACs                    []string
	SSHPublicKeyAuthAlgorithms []string
}

// AddUser adds or replaces a user entry in the server's user map.
// It is safe to call concurrently with active connections.
func (s *server) AddUser(username string, info UserInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users == nil {
		s.users = make(map[string]UserInfo)
	}
	s.users[username] = cloneUserInfo(info)
}

// RemoveUser removes a user entry from the server's user map.
// Active connections for that user are not terminated.
// It is safe to call concurrently with active connections.
func (s *server) RemoveUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, username)
}

// RemoveAllUsers removes every user entry from the server's user map.
// Active connections are not terminated, and no on-disk user data is removed.
// It is safe to call concurrently with active connections.
func (s *server) RemoveAllUsers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.users)
}

// AddUserKey appends key to the AuthorizedKeys of an existing user.
// If the key is already present (by wire-format equality) it is not added again.
// It is a no-op when username does not exist or key is nil.
// It is safe to call concurrently with active connections.
func (s *server) AddUserKey(username string, key ssh.PublicKey) {
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
	for _, existing := range u.AuthorizedKeys {
		if existing == nil {
			continue
		}
		if subtle.ConstantTimeCompare(keyBytes, existing.Marshal()) == 1 {
			return // already present
		}
	}
	u.AuthorizedKeys = append(u.AuthorizedKeys, key)
	s.users[username] = u
}

// RemoveUserKey removes key from the AuthorizedKeys of an existing user.
// It is a no-op when username does not exist, the key is not found, or key is nil.
// It is safe to call concurrently with active connections.
func (s *server) RemoveUserKey(username string, key ssh.PublicKey) {
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

// DefaultIronportConfig returns a fresh server configuration with package
// defaults applied. Callers should set Users before starting the server. Set
// Signer to use a stable host key; when Signer is nil, ListenAndServe generates
// an ephemeral in-memory host key.
func DefaultIronportConfig() *ironportConfig {
	return &ironportConfig{
		Addr:                ":2022",
		FtpAddr:             "",
		FtpPassivePortRange: "5000-5010",
		CompletedUploadSize: defaultCompletedUploadsSize,
	}
}

// NewServer creates a new server from config. Pass FtpAddr as "" to disable
// FTP. Leave FtpPassivePortRange empty to use OS-assigned passive data ports.
//
// CompletedUploadSize sets the buffer capacity of the CompletedUploads channel.
// A non-positive value falls back to the package default (64):
//
//	cfg := ironport.DefaultIronportConfig()
//	cfg.Users = users
//	cfg.Signer = signer
//	cfg.CompletedUploadSize = 256
//	srv := ironport.NewServer(cfg)
func NewServer(config *ironportConfig) *server {
	if config == nil {
		config = DefaultIronportConfig()
	}
	s := &server{
		addr:                       config.Addr,
		ftpAddr:                    config.FtpAddr,
		ftpPassivePortRange:        config.FtpPassivePortRange,
		users:                      cloneUsers(config.Users),
		signer:                     config.Signer,
		completedUploads:           newCompletedUploadsChannel(config.CompletedUploadSize),
		sshKeyExchanges:            cloneStringSlice(config.SSHKeyExchanges),
		sshCiphers:                 cloneStringSlice(config.SSHCiphers),
		sshMACs:                    cloneStringSlice(config.SSHMACs),
		sshPublicKeyAuthAlgorithms: cloneStringSlice(config.SSHPublicKeyAuthAlgorithms),
		activeConns:                make(map[net.Conn]struct{}),
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

func (s *server) ensureSigner() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signer != nil {
		return nil
	}
	signer, err := generateEphemeralSigner()
	if err != nil {
		return fmt.Errorf("generate ephemeral host key: %w", err)
	}
	s.signer = signer
	return nil
}

// trackConn records nc as an in-flight handler-owned connection. It returns
// false when the server has already begun shutting down, in which case the
// caller must not spawn a handler for nc and is responsible for closing it.
// On success the caller must call untrackConn(nc) and connWG.Done() exactly
// once before its handler goroutine returns.
func (s *server) trackConn(nc net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shuttingDown {
		return false
	}
	if s.activeConns == nil {
		s.activeConns = make(map[net.Conn]struct{})
	}
	s.activeConns[nc] = struct{}{}
	s.connWG.Add(1)
	return true
}

// untrackConn removes nc from the in-flight set. The corresponding
// connWG.Done() call is the caller's responsibility so that ordering between
// "stop tracking" and "decrement waitgroup" is explicit at each call site.
func (s *server) untrackConn(nc net.Conn) {
	s.mu.Lock()
	delete(s.activeConns, nc)
	s.mu.Unlock()
}

// forceCloseActiveConns closes every connection still in the active set.
// Returns the number of connections it closed. Used by Shutdown to evict
// stragglers when the caller's context deadline fires before handlers have
// finished on their own.
func (s *server) forceCloseActiveConns() int {
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

func (s *server) completedUploadsChan() chan CompletedUpload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.completedUploads
}

// CompletedUploads returns a receive-only stream of successful upload
// notifications. The channel is buffered; sends are non-blocking so a slow
// consumer never stalls an upload. Callers should drain the stream
// continuously.
//
// The buffer capacity is set by ironportConfig.CompletedUploadSize. A
// non-positive value falls back to the package default (64).
func (s *server) CompletedUploads() <-chan CompletedUpload {
	return s.completedUploadsChan()
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

func (s *server) listenFTPData(host string) (net.Listener, error) {
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
// A server that has been Shutdown cannot be reused; ListenAndServe returns
// an error in that case. Construct a fresh server instead.
func (s *server) ListenAndServe() error {
	if strings.TrimSpace(s.addr) == "" {
		return errors.New("ironport: Addr is required")
	}
	s.mu.RLock()
	closed := s.shuttingDown
	s.mu.RUnlock()
	if closed {
		return errors.New("ironport: server has been shut down")
	}
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
	cfg := s.sshServerConfig()

	sftpLn, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	var ftpLn net.Listener
	if strings.TrimSpace(s.ftpAddr) != "" {
		ftpLn, err = net.Listen("tcp", s.ftpAddr)
		if err != nil {
			_ = sftpLn.Close()
			return err
		}
	}

	s.mu.Lock()
	s.ln = sftpLn
	s.ftpLn = ftpLn
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.ln = nil
		s.ftpLn = nil
		s.mu.Unlock()
	}()

	log.Printf("SFTP listening on %s", sftpLn.Addr())
	workers := 1
	errCh := make(chan error, 2)
	go func() { errCh <- s.serveSFTP(sftpLn, cfg, uploads) }()

	if ftpLn != nil {
		workers++
		log.Printf("FTP listening on %s", ftpLn.Addr())
		go func() { errCh <- s.serveFTP(ftpLn, uploads) }()
	}

	var ret error
	for i := 0; i < workers; i++ {
		if err := <-errCh; err != nil && ret == nil {
			ret = err
			_ = s.closeListeners()
		}
	}
	return ret
}

func (s *server) serveSFTP(ln net.Listener, cfg *ssh.ServerConfig, uploads chan<- CompletedUpload) error {
	var backoff time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Transient accept errors should not tear the server down: a
			// momentary EMFILE/ENFILE or similar would otherwise kill all
			// listeners. Apply exponential backoff between 5ms and 1s.
			backoff = nextAcceptBackoff(backoff)
			log.Printf("sftp accept: %v; retrying in %s", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
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
					log.Printf("sftp handler panic from=%s: %v\n%s", nc.RemoteAddr(), r, debug.Stack())
					_ = nc.Close()
				}
			}()
			handleConn(nc, cfg, uploads, s.tempExtensions(), s.idleTimeout(), s.allowChown())
		}()
	}
}

func (s *server) serveFTP(ln net.Listener, uploads chan<- CompletedUpload) error {
	var backoff time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = nextAcceptBackoff(backoff)
			log.Printf("ftp accept: %v; retrying in %s", err, backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if !s.trackConn(nc) {
			_ = nc.Close()
			continue
		}
		go func() {
			defer s.connWG.Done()
			defer s.untrackConn(nc)
			defer func() {
				if r := recover(); r != nil {
					log.Printf("ftp handler panic from=%s: %v\n%s", nc.RemoteAddr(), r, debug.Stack())
					_ = nc.Close()
				}
			}()
			s.handleFTPConn(nc, s.tempExtensions(), uploads)
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

// tempExtensions returns a normalised copy of s.TempExtensions: each entry is
// lower-cased and guaranteed to start with a single leading dot. Empty entries
// are dropped. The result is safe to use without holding s.mu because it is
// a freshly allocated slice.
func (s *server) tempExtensions() []string {
	s.mu.RLock()
	src := s.TempExtensions
	s.mu.RUnlock()
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

// idleTimeout returns the effective idle timeout for SFTP connections.
// A zero IdleTimeout selects the package default; a negative IdleTimeout
// disables the deadline.
func (s *server) idleTimeout() time.Duration {
	s.mu.RLock()
	d := s.IdleTimeout
	s.mu.RUnlock()
	switch {
	case d == 0:
		return defaultSFTPIdleTimeout
	case d < 0:
		return 0
	}
	return d
}

// allowChown returns the current value of AllowChown under the server lock.
func (s *server) allowChown() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AllowChown
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
// terminated. Calling Close before ListenAndServe has been called, or after it
// has already returned, is a no-op.
func (s *server) Close() error {
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
// Shutdown returns, ListenAndServe (if it was running) will have returned
// nil. Calling Shutdown before ListenAndServe has been started, or after it
// has already returned and all handlers have exited, returns immediately
// with nil.
func (s *server) Shutdown(ctx context.Context) error {
	// Mark the server as shutting down so any accept that races with the
	// listener close refuses the connection rather than starting a handler
	// we would then have to drain. Setting this under mu serialises with
	// trackConn's connWG.Add so the WaitGroup Add/Wait pair is race-free.
	s.mu.Lock()
	s.shuttingDown = true
	s.mu.Unlock()
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

func (s *server) closeListeners() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var ret error
	if s.ln != nil {
		if err := s.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			ret = err
		}
	}
	if s.ftpLn != nil {
		if err := s.ftpLn.Close(); err != nil && !errors.Is(err, net.ErrClosed) && ret == nil {
			ret = err
		}
	}
	return ret
}

// ListeningAddr returns the actual SFTP network address the server is listening
// on, or nil if the SFTP listener is not currently listening. It is useful when
// the server was started with port 0 (OS-assigned port).
func (s *server) ListeningAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// FTPListeningAddr returns the actual FTP network address the server is
// listening on, or nil if FTP is disabled or not currently listening.
func (s *server) FTPListeningAddr() net.Addr {
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

// sshServerConfig builds the SSH server configuration with both password-based
// and public-key-based authentication enabled.
//
// Password authentication succeeds when the supplied password matches the
// stored Password (constant-time comparison).
//
// Public-key authentication succeeds when the presented key matches any entry
// in the user's AuthorizedKeys slice (constant-time comparison of wire-format
// bytes).
func (s *server) sshServerConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: cloneStringSlice(s.sshKeyExchanges),
			Ciphers:      cloneStringSlice(s.sshCiphers),
			MACs:         cloneStringSlice(s.sshMACs),
		},
		PublicKeyAuthAlgorithms: cloneStringSlice(s.sshPublicKeyAuthAlgorithms),
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.mu.RLock()
			u, ok := s.users[c.User()]
			s.mu.RUnlock()
			// Compare SHA-256 hashes of both passwords so that the comparison
			// always operates on the same 32-byte length regardless of whether
			// the username exists or what length the stored password has. A
			// direct subtle.ConstantTimeCompare on the raw strings would return
			// immediately on a length mismatch, leaking username existence via
			// timing side-channel (non-existent users have an empty stored
			// password that differs in length from any real password).
			var storedPw string
			if ok {
				storedPw = u.Password
			}
			storedHash := sha256.Sum256([]byte(storedPw))
			passHash := sha256.Sum256(pass)
			match := subtle.ConstantTimeCompare(storedHash[:], passHash[:]) == 1
			// Reject empty stored or supplied passwords. An empty stored
			// password disables password authentication for that user (or
			// indicates a non-existent user); an empty supplied password is
			// never a valid credential. This guards against accidentally
			// permitting login when a UserInfo is added with Password: "".
			if !ok || !match || len(pass) == 0 || len(storedPw) == 0 {
				return nil, fmt.Errorf("invalid credentials")
			}
			jailRoot, err := canonicalJailRoot(u.Root)
			if err != nil {
				return nil, fmt.Errorf("invalid credentials")
			}
			return permissionsFor(u, c.User(), jailRoot), nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.RLock()
			u, ok := s.users[c.User()]
			s.mu.RUnlock()
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
			if !ok || !matched {
				return nil, fmt.Errorf("invalid credentials")
			}
			jailRoot, err := canonicalJailRoot(u.Root)
			if err != nil {
				return nil, fmt.Errorf("invalid credentials")
			}
			return permissionsFor(u, c.User(), jailRoot), nil
		},
	}
	cfg.AddHostKey(s.signer)
	return cfg
}

func handleConn(nc net.Conn, cfg *ssh.ServerConfig, uploads chan<- CompletedUpload, tempExts []string, idleTimeout time.Duration, allowChown bool) {
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
	log.Printf("login protocol=sftp user=%s root=%s from=%s", user, jailRoot, sshConn.RemoteAddr())

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

		go handleSession(ch, inReqs, jailRoot, user, clientIP, canRead, canWrite, uploads, tempExts, allowChown)
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

func handleSession(ch ssh.Channel, inReqs <-chan *ssh.Request, jailRoot, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, allowChown bool) {
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

			handlers, fs, err := jailedHandlers(jailRoot, username, clientIP, canRead, canWrite, uploads, tempExts, allowChown)
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
			return

		default:
			_ = req.Reply(false, nil)
		}
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
	// allowChown controls whether Setstat/Fsetstat requests carrying a
	// uid/gid attribute are honoured. When false, chown requests are
	// rejected with a permission error so an authenticated user cannot
	// change ownership of jailed files even if the server process has
	// the privilege to do so (for example when running as root).
	allowChown bool
}

// jail implements the four sftp handler interfaces for a chrooted filesystem.
// Fileread implements sftp.FileReader.
func (j jail) Fileread(r *sftp.Request) (reader io.ReaderAt, err error) {
	method, filePath := sftpRequestContext(r)
	defer func() {
		if recoverSFTPHandlerPanic(j.username, j.clientIP, method, filePath, recover(), &err) {
			reader = nil
		}
	}()
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
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("sftp write panic user=%q ip=%q path=%q: %v\n%s", w.username, w.clientIP, w.filepath, recovered, debug.Stack())
			n = 0
			err = errSFTPRequestFailed
		}
	}()
	if w.appendMode {
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
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("sftp write close panic user=%q ip=%q path=%q: %v\n%s", w.username, w.clientIP, w.filepath, recovered, debug.Stack())
			err = errSFTPRequestFailed
		}
	}()
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
		evt := CompletedUpload{
			Username:     w.username,
			FullFilePath: w.fullFilepath,
			FilePath:     w.filepath,
			ClientIP:     w.clientIP,
		}
		select {
		case w.uploads <- evt:
		default:
			log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", w.filepath)
		}
	}
	return err
}

// Filewrite implements sftp.FileWriter.
func (j jail) Filewrite(r *sftp.Request) (writer io.WriterAt, err error) {
	method, filePath := sftpRequestContext(r)
	defer func() {
		if recoverSFTPHandlerPanic(j.username, j.clientIP, method, filePath, recover(), &err) {
			writer = nil
		}
	}()
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
	method, filePath := sftpRequestContext(r)
	defer func() {
		recoverSFTPHandlerPanic(j.username, j.clientIP, method, filePath, recover(), &err)
	}()
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
		if hasTempExt(oldClientPath, j.tempExts) && !hasTempExt(newClientPath, j.tempExts) {
			log.Printf("upload complete via rename: %q -> %q", oldClientPath, newClientPath)
			evt := CompletedUpload{
				Username:     j.username,
				FullFilePath: j.fs.fullPath(r.Target),
				FilePath:     newClientPath,
				ClientIP:     j.clientIP,
			}
			select {
			case j.uploads <- evt:
			default:
				log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", newClientPath)
			}
		}
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
	method, filePath := sftpRequestContext(r)
	defer func() {
		if recoverSFTPHandlerPanic(j.username, j.clientIP, method, filePath, recover(), &err) {
			lister = nil
		}
	}()
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
//   - UidGid            → fchownat (only when allowChown is true; otherwise
//     the request is rejected with os.ErrPermission so an authenticated user
//     cannot change ownership of jailed files even when the server process
//     has the privilege to do so)
//   - Size              → ftruncate via openat2-obtained fd
//   - Acmodtime         → REJECTED with os.ErrPermission. Setting timestamps
//     on jailed files is denied wholesale under the hardened policy; clients
//     get a deterministic permission error rather than a partial success.
//
// Policy-level rejections (Acmodtime, and UidGid when allowChown is false)
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
	if flags.UidGid && !j.allowChown {
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

func jailedHandlers(root, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, allowChown bool) (sftp.Handlers, *jailFS, error) {
	fs, err := openJailFS(filepath.Clean(root))
	if err != nil {
		return sftp.Handlers{}, nil, err
	}
	j := jail{
		fs:         fs,
		username:   username,
		clientIP:   clientIP,
		canRead:    canRead,
		canWrite:   canWrite,
		uploads:    uploads,
		tempExts:   tempExts,
		allowChown: allowChown,
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
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("sftp list panic offset=%d: %v\n%s", offset, recovered, debug.Stack())
			n = 0
			err = errSFTPRequestFailed
		}
	}()
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

// FTP implementation. It is deliberately passive-mode only. Active FTP (PORT / EPRT)
// is disabled because it is harder to firewall safely and opens client-chosen
// outbound connections from the server.

type ftpSession struct {
	server        *server
	conn          net.Conn
	r             *bufio.Reader
	w             *bufio.Writer
	username      string
	user          UserInfo
	authenticated bool
	cwd           string
	dataLn        net.Listener
	rnfrPath      string
	restartOffset int64
	clientIP      string
	tempExts      []string
	uploads       chan<- CompletedUpload
	// fs is the fd-relative filesystem backing this session's jail. It is
	// constructed by authenticate on successful login and released when the
	// session ends (closeJail). Until login succeeds it is nil.
	fs *jailFS
}

func (s *server) handleFTPConn(nc net.Conn, tempExts []string, uploads chan<- CompletedUpload) {
	defer func() { _ = nc.Close() }()

	sess := &ftpSession{
		server:   s,
		conn:     nc,
		r:        bufio.NewReader(nc),
		w:        bufio.NewWriter(nc),
		cwd:      "/",
		clientIP: remoteIP(nc.RemoteAddr()),
		tempExts: tempExts,
		uploads:  uploads,
	}
	defer sess.closeDataListener()
	defer sess.closeJail()

	if err := sess.reply(220, "ready"); err != nil {
		return
	}

	// Capture the configured idle timeout once at session start. Mutating
	// server.IdleTimeout afterwards only affects sessions accepted later,
	// matching the SFTP per-session semantics. A zero value disables the
	// deadline.
	idleTimeout := s.idleTimeout()
	for {
		if idleTimeout > 0 {
			_ = nc.SetReadDeadline(time.Now().Add(idleTimeout))
		} else {
			_ = nc.SetReadDeadline(time.Time{})
		}
		line, err := readFTPControlLine(sess.r, ftpMaxControlLineLen)
		if err != nil {
			if errors.Is(err, errFTPLineTooLong) {
				_ = sess.reply(500, ftpErrMsg(err))
				log.Printf("ftp control read from=%s: line exceeded %d bytes", nc.RemoteAddr(), ftpMaxControlLineLen)
				return
			}
			if !errors.Is(err, io.EOF) {
				log.Printf("ftp control read from=%s: %v", nc.RemoteAddr(), err)
			}
			return
		}
		_ = nc.SetReadDeadline(time.Time{})

		line = strings.TrimRight(line, "\r\n")
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
			_ = f.reply(530, "invalid credentials")
			return false
		}
		log.Printf("login protocol=ftp user=%s root=%s from=%s", f.username, f.user.Root, f.conn.RemoteAddr())
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
		_ = f.multilineReply(211, "Features:", []string{
			"UTF8",
			"EPSV",
			"PASV",
			"SIZE",
			"MDTM",
			"REST STREAM",
		}, "End")
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
		f.enterPassive(true)

	case "PORT", "EPRT":
		_ = f.reply(502, "active mode is disabled; use PASV or EPSV")

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
		_ = f.reply(226, "abort successful")

	default:
		_ = f.reply(502, "command not implemented")
	}
	return false
}

func (f *ftpSession) authenticate(pass string) bool {
	f.server.mu.RLock()
	u, ok := f.server.users[f.username]
	f.server.mu.RUnlock()

	var storedPw string
	if ok {
		storedPw = u.Password
	}
	storedHash := sha256.Sum256([]byte(storedPw))
	passHash := sha256.Sum256([]byte(pass))
	match := subtle.ConstantTimeCompare(storedHash[:], passHash[:]) == 1
	// Reject empty stored or supplied passwords. An empty stored password
	// disables password authentication for the user; an empty supplied
	// password is never a valid credential.
	if !ok || !match || len(pass) == 0 || len(storedPw) == 0 {
		return false
	}
	jailRoot, err := canonicalJailRoot(u.Root)
	if err != nil {
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
		AuthorizedKeys: u.AuthorizedKeys,
	}
	f.authenticated = true
	f.cwd = "/"
	f.rnfrPath = ""
	f.restartOffset = 0
	return true
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

func listPathArg(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return ""
	}
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		return ""
	}
	for i, field := range fields {
		if strings.HasPrefix(field, "-") {
			continue
		}
		return strings.Join(fields[i:], " ")
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
	f.closeDataListener()

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

func (f *ftpSession) acceptDataConn() (net.Conn, error) {
	if f.dataLn == nil {
		return nil, errors.New("passive mode not enabled")
	}
	ln := f.dataLn
	f.dataLn = nil
	defer func() { _ = ln.Close() }()

	if tcpLn, ok := ln.(*net.TCPListener); ok {
		_ = tcpLn.SetDeadline(time.Now().Add(30 * time.Second))
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

func (f *ftpSession) closeDataListener() {
	if f.dataLn != nil {
		_ = f.dataLn.Close()
		f.dataLn = nil
	}
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

	var lines []string
	if st.IsDir() {
		entries, err := f.fs.List(ftpPath)
		if err != nil {
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
		for _, info := range entries {
			if namesOnly {
				lines = append(lines, sanitizeFTPText(info.Name()))
			} else {
				lines = append(lines, ftpListLine(info, info.Name()))
			}
		}
	} else if namesOnly {
		lines = append(lines, sanitizeFTPText(path.Base(ftpPath)))
	} else {
		lines = append(lines, ftpListLine(st, path.Base(ftpPath)))
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
	for _, line := range lines {
		if _, err := io.WriteString(idleDC, line+"\r\n"); err != nil {
			_ = f.reply(426, ftpErrMsg(err))
			return
		}
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

func (f *ftpSession) cmdRetr(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	file, err := f.fs.OpenRead(ftpPath)
	if err != nil {
		f.restartOffset = 0
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	defer func() { _ = file.Close() }()

	if f.restartOffset > 0 {
		if _, err := file.Seek(f.restartOffset, io.SeekStart); err != nil {
			f.restartOffset = 0
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
	}
	f.restartOffset = 0

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
	if _, err := io.Copy(idleDC, file); err != nil {
		_ = f.reply(426, ftpErrMsg(err))
		return
	}
	_ = f.reply(226, "transfer complete")
}

func (f *ftpSession) cmdStor(arg string, appendMode bool) {
	if !f.user.CanWrite {
		f.restartOffset = 0
		_ = f.reply(550, "permission denied")
		return
	}
	if hasCRLF(arg) {
		f.restartOffset = 0
		_ = f.reply(553, "invalid filename")
		return
	}
	ftpPath := f.cleanPath(arg)

	if err := f.reply(150, "opening data connection"); err != nil {
		f.restartOffset = 0
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		f.restartOffset = 0
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer func() { _ = dc.Close() }()

	flags := os.O_CREATE | os.O_WRONLY
	switch {
	case appendMode:
		flags |= os.O_APPEND
	case f.restartOffset > 0:
		// Keep existing bytes and resume at requested offset.
	default:
		flags |= os.O_TRUNC
	}

	file, err := f.fs.OpenWrite(ftpPath, flags, 0600)
	if err != nil {
		f.restartOffset = 0
		_ = f.reply(550, ftpErrMsg(err))
		return
	}

	if f.restartOffset > 0 && !appendMode {
		if _, err := file.Seek(f.restartOffset, io.SeekStart); err != nil {
			f.restartOffset = 0
			_ = file.Close()
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
	}
	f.restartOffset = 0

	log.Printf("upload protocol=ftp path=%q", ftpPath)
	// Wrap the data connection so that every Read enforces a fresh idle
	// deadline. A stalled client that stops sending bytes but keeps the TCP
	// connection open will surface as a read error from io.Copy below, which
	// in turn skips the CompletedUploads notification — partial uploads must
	// never be announced as complete.
	//
	// Note: FTP STREAM mode signals "end of file" by half-closing the data
	// connection, so a client that uploads N bytes then half-closes is
	// indistinguishable at the protocol level from a client that intended
	// to upload exactly N bytes. The idle deadline therefore catches stalled
	// transfers but cannot detect a client that deliberately truncates by
	// half-closing early; that is an inherent limitation of FTP itself.
	idleDC := &idleConn{Conn: dc}
	idleDC.setReadTimeout(ftpDataIdleTimeout)
	_, copyErr := io.Copy(file, idleDC)
	closeErr := file.Close()
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

	f.announceUpload(ftpPath, f.fs.fullPath(ftpPath))
	_ = f.reply(226, "transfer complete")
}

func (f *ftpSession) announceUpload(ftpPath, fullPath string) {
	log.Printf("upload complete: %q", ftpPath)
	if hasTempExt(ftpPath, f.tempExts) {
		log.Printf("upload complete: %q has temp extension, deferring CompletedUploads notification", ftpPath)
		return
	}
	evt := CompletedUpload{
		Username:     f.username,
		FullFilePath: fullPath,
		FilePath:     ftpPath,
		ClientIP:     f.clientIP,
	}
	select {
	case f.uploads <- evt:
	default:
		log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", ftpPath)
	}
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
	if hasTempExt(oldPath, f.tempExts) && !hasTempExt(newPath, f.tempExts) {
		newFull := f.fs.fullPath(newPath)
		log.Printf("upload complete via rename: %q -> %q", oldPath, newPath)
		f.announceUpload(newPath, newFull)
	}
	_ = f.reply(250, "renamed")
}
