// Package sftpserver provides an embeddable, security-hardened SFTP server.
//
// Core features:
//
//   - Per-user jail roots enforced via path resolution and symlink checks.
//   - Password and SSH public-key authentication with constant-time comparisons.
//   - Fine-grained CanRead / CanWrite per-user permission flags.
//   - Runtime user management (AddUser, RemoveUser, AddUserKey, RemoveUserKey).
//   - Graceful shutdown via Close; upload-completion notifications via CompletedUploads.
//
// Typical usage:
//
//	srv := sftpserver.NewServer(":2022", users, signer)
//	log.Fatal(srv.ListenAndServe())
package sftpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

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

// UserInfo holds the credentials and jail root for a single SFTP user.
type UserInfo struct {
	Password       string
	AuthorizedKeys []ssh.PublicKey // public keys allowed for authentication; nil or empty means public-key auth is disabled for this user
	Root           string          // jail root on disk, e.g. /srv/sftp/alice
	CanRead        bool            // allow read/download/list operations
	CanWrite       bool            // allow write/upload/delete/rename operations
}

// Server is a self-contained SFTP server.
type Server struct {
	// Addr is the TCP address to listen on, e.g. ":2022".
	Addr string
	// Users maps usernames to their credentials and jail roots.
	Users map[string]UserInfo
	// mu protects Users and ln for concurrent reads and writes.
	mu sync.RWMutex
	// ln is the active listener; set by ListenAndServe and closed by Close.
	ln net.Listener
	// Signer is the host key used for the SSH handshake.
	Signer ssh.Signer
	// CompletedUploads receives the SFTP path of each file whose write has
	// finished successfully (i.e. the client closed the file without error).
	// The channel is buffered; sends are non-blocking so a slow consumer
	// never stalls an upload.  Callers should drain the channel continuously.
	CompletedUploads chan string
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
	// Matching is case-insensitive.  Setting this field after the server has
	// started has effect only on connections accepted afterwards.
	TempExtensions []string
}

// AddUser adds or replaces a user entry in the server's user map.
// It is safe to call concurrently with active connections.
func (s *Server) AddUser(username string, info UserInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Users == nil {
		s.Users = make(map[string]UserInfo)
	}
	s.Users[username] = info
}

// RemoveUser removes a user entry from the server's user map.
// Active connections for that user are not terminated.
// It is safe to call concurrently with active connections.
func (s *Server) RemoveUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Users, username)
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
	u, ok := s.Users[username]
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
	s.Users[username] = u
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
	u, ok := s.Users[username]
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
	s.Users[username] = u
}

// NewServer creates a new Server with the given address, user map, and host key.
func NewServer(addr string, users map[string]UserInfo, signer ssh.Signer) *Server {
	return &Server{
		Addr:             addr,
		Users:            users,
		Signer:           signer,
		CompletedUploads: make(chan string, 64),
	}
}

// ListenAndServe starts the SFTP server and blocks, accepting connections.
// It returns a non-nil error only if the listener cannot be created or fails
// with an unexpected error.  It returns nil when the server is stopped via
// Close.
func (s *Server) ListenAndServe() error {
	cfg := s.sshServerConfig()

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.ln = nil
		s.mu.Unlock()
	}()

	log.Printf("SFTP listening on %s", ln.Addr())

	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Println("accept:", err)
			return err
		}
		go handleConn(nc, cfg, s.CompletedUploads, s.tempExtensions())
	}
}

// tempExtensions returns a normalised copy of s.TempExtensions: each entry is
// lower-cased and guaranteed to start with a single leading dot.  Empty entries
// are dropped.  The result is safe to use without holding s.mu because it is
// a freshly allocated slice.
func (s *Server) tempExtensions() []string {
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

// hasTempExt reports whether name ends with one of the given (already
// normalised, lower-case, dot-prefixed) extensions.  Matching is
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

// Close stops the server by closing the listener, causing ListenAndServe to
// return nil.  It is safe to call concurrently with active connections; in-
// flight connections are not terminated.  Calling Close before ListenAndServe
// has been called, or after it has already returned, is a no-op.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

// ListeningAddr returns the actual network address the server is listening on,
// or nil if the server is not currently listening.  It is useful when the
// server was started with port 0 (OS-assigned port).
func (s *Server) ListeningAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// permissionsFor builds the ssh.Permissions for an authenticated user,
// embedding the jail root and access flags as extensions so that the
// connection handler can retrieve them after the handshake.
func permissionsFor(u UserInfo, username string) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			"jailRoot": u.Root,
			"user":     username,
			"canRead":  fmt.Sprintf("%v", u.CanRead),
			"canWrite": fmt.Sprintf("%v", u.CanWrite),
		},
	}
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
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.mu.RLock()
			u, ok := s.Users[c.User()]
			s.mu.RUnlock()
			// Compare SHA-256 hashes of both passwords so that the comparison
			// always operates on the same 32-byte length regardless of whether
			// the username exists or what length the stored password has.  A
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
			if !ok || !match {
				return nil, fmt.Errorf("invalid credentials")
			}
			return permissionsFor(u, c.User()), nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.RLock()
			u, ok := s.Users[c.User()]
			s.mu.RUnlock()
			keyBytes := key.Marshal()
			// Hash the presented key's wire-format bytes to a fixed 32-byte
			// value so that all comparisons in the loop are the same length
			// regardless of key algorithm.  RSA, ECDSA, and Ed25519 wire
			// formats all differ in length; a raw ConstantTimeCompare would
			// short-circuit on any length mismatch, leaking type information.
			keyHash := sha256.Sum256(keyBytes)
			// Perform a dummy fixed-length comparison against an all-zero hash
			// before the loop.  When the user does not exist (or has no
			// AuthorizedKeys), the loop is a no-op; without this baseline, such
			// cases would be measurably faster than users who have keys to check.
			// The all-zero value will never match a real key's SHA-256 hash.
			var zeroHash [sha256.Size]byte
			matched := subtle.ConstantTimeCompare(keyHash[:], zeroHash[:]) == 1 // always false
			// Do not return early on the first match: iterate to the end so
			// that the response time does not leak the position of the matching
			// key in the AuthorizedKeys slice.
			for _, authorizedKey := range u.AuthorizedKeys {
				if authorizedKey == nil {
					continue
				}
				authHash := sha256.Sum256(authorizedKey.Marshal())
				if subtle.ConstantTimeCompare(keyHash[:], authHash[:]) == 1 {
					matched = true
				}
			}
			if !ok || !matched {
				return nil, fmt.Errorf("invalid credentials")
			}
			return permissionsFor(u, c.User()), nil
		},
	}
	cfg.AddHostKey(s.Signer)
	return cfg
}

func handleConn(nc net.Conn, cfg *ssh.ServerConfig, uploads chan<- string, tempExts []string) {
	defer nc.Close()

	// Enforce a deadline for the SSH handshake to prevent malicious clients
	// from holding goroutines open indefinitely without completing the
	// handshake (denial-of-service via resource exhaustion).
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	sshConn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Println("ssh handshake:", err)
		return
	}
	// Handshake complete – remove the deadline so session I/O is not
	// artificially limited.
	_ = nc.SetDeadline(time.Time{})
	defer sshConn.Close()

	jailRoot := sshConn.Permissions.Extensions["jailRoot"]
	user := sshConn.Permissions.Extensions["user"]
	canRead := sshConn.Permissions.Extensions["canRead"] == "true"
	canWrite := sshConn.Permissions.Extensions["canWrite"] == "true"
	log.Printf("login user=%s root=%s from=%s", user, jailRoot, sshConn.RemoteAddr())

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

		go handleSession(ch, inReqs, jailRoot, canRead, canWrite, uploads, tempExts)
	}
}

func handleSession(ch ssh.Channel, inReqs <-chan *ssh.Request, jailRoot string, canRead, canWrite bool, uploads chan<- string, tempExts []string) {
	defer ch.Close()

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

			handlers := jailedHandlers(jailRoot, canRead, canWrite, uploads, tempExts)

			server := sftp.NewRequestServer(ch, handlers)
			if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
				log.Println("sftp serve:", err)
			}
			_ = server.Close()
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
}

type jail struct {
	root     string
	canRead  bool
	canWrite bool
	uploads  chan<- string
	// tempExts is the list of "still being written" extensions (lower-case,
	// dot-prefixed).  Uploads ending in one of these extensions are not
	// announced on uploads; renaming such a file to a name without any of
	// these extensions announces the final path on uploads instead.
	tempExts []string
}

// resolve maps an SFTP path (possibly relative) into an absolute on-disk path
// under j.root, rejecting escapes and symlink escapes.
func (j jail) resolve(p string) (string, error) {
	if p == "" {
		p = "/"
	}

	// Force absolute + clean: "/../../etc" => "/etc"
	clean := filepath.Clean("/" + filepath.ToSlash(p))

	// Join to root. clean starts with "/", Join will drop earlier elems,
	// so we strip the leading "/" first.
	full := filepath.Join(j.root, strings.TrimPrefix(clean, "/"))

	// First prefix check (string check)
	if !withinRoot(full, j.root) {
		return "", os.ErrPermission
	}

	// Prevent symlink escapes:
	// EvalSymlinks fails if path doesn't exist; that's OK for create paths.
	// For create paths, check the parent directory's symlinks instead.
	target, err := filepath.EvalSymlinks(full)
	if err == nil {
		if !withinRoot(target, j.root) {
			return "", os.ErrPermission
		}
		return target, nil
	}

	// If full doesn't exist yet, validate parent
	parent := filepath.Dir(full)
	parentReal, perr := filepath.EvalSymlinks(parent)
	if perr == nil && !withinRoot(parentReal, j.root) {
		return "", os.ErrPermission
	}
	return full, nil
}

func withinRoot(path, root string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)

	if path == root {
		return true
	}
	if !strings.HasSuffix(root, string(os.PathSeparator)) {
		root += string(os.PathSeparator)
	}
	return strings.HasPrefix(path, root)
}

// jail implements the four sftp handler interfaces for a chrooted filesystem.
// Fileread implements sftp.FileReader.
func (j jail) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	if !j.canRead {
		return nil, os.ErrPermission
	}
	p, err := j.resolve(r.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

// writeLogger wraps an *os.File and logs the filename when the file is closed,
// signalling that the upload is complete. The sftp request server calls Close()
// on the returned io.WriterAt when it detects an io.Closer.
//
// If the uploaded filename ends with one of tempExts (e.g. ".tmp", ".writing"),
// the file is considered still in progress and no notification is sent on
// uploads; the completion notification will instead be emitted when the client
// renames the file to its final name (see jail.Filecmd "Rename").
type writeLogger struct {
	*os.File
	filepath string
	uploads  chan<- string
	tempExts []string
}

func (w *writeLogger) Close() error {
	err := w.File.Close()
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
		select {
		case w.uploads <- w.filepath:
		default:
			log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", w.filepath)
		}
	}
	return err
}

// Filewrite implements sftp.FileWriter.
func (j jail) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if !j.canWrite {
		return nil, os.ErrPermission
	}
	p, err := j.resolve(r.Filepath)
	if err != nil {
		return nil, err
	}
	log.Printf("upload: %q", r.Filepath)
	// Create/overwrite
	f, err := os.OpenFile(p, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &writeLogger{File: f, filepath: r.Filepath, uploads: j.uploads, tempExts: j.tempExts}, nil
}

// Filecmd implements sftp.FileCmder.
func (j jail) Filecmd(r *sftp.Request) error {
	if !j.canWrite {
		return os.ErrPermission
	}
	switch r.Method {
	case "Setstat", "Fsetstat":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		// Minimal: allow chmod/chown/times only if you want; here we ignore.
		_ = p
		return nil

	case "Rename":
		oldP, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		newP, err := j.resolve(r.Target)
		if err != nil {
			return err
		}
		if err := os.Rename(oldP, newP); err != nil {
			return err
		}
		// If a file with a "still being written" extension is renamed to a
		// final (non-temp) name, treat the rename as the moment the upload
		// completes and announce the new SFTP path on uploads.
		if hasTempExt(r.Filepath, j.tempExts) && !hasTempExt(r.Target, j.tempExts) {
			log.Printf("upload complete via rename: %q -> %q", r.Filepath, r.Target)
			select {
			case j.uploads <- r.Target:
			default:
				log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", r.Target)
			}
		}
		return nil

	case "Rmdir":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		return os.Remove(p)

	case "Remove":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		return os.Remove(p)

	case "Mkdir":
		p, err := j.resolve(r.Filepath)
		if err != nil {
			return err
		}
		return os.Mkdir(p, 0750)

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
func (j jail) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	if !j.canRead {
		return nil, os.ErrPermission
	}
	p, err := j.resolve(r.Filepath)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		return listerFromDirEntries(p, entries), nil
	case "Stat":
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		return listerFromFileInfo([]os.FileInfo{st}), nil
	case "Lstat":
		st, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		return listerFromFileInfo([]os.FileInfo{st}), nil
	default:
		return nil, fmt.Errorf("unsupported list method: %s", r.Method)
	}
}

func jailedHandlers(root string, canRead, canWrite bool, uploads chan<- string, tempExts []string) sftp.Handlers {
	j := jail{root: filepath.Clean(root), canRead: canRead, canWrite: canWrite, uploads: uploads, tempExts: tempExts}
	return sftp.Handlers{
		FileGet:  j,
		FilePut:  j,
		FileCmd:  j,
		FileList: j,
	}
}

type fileInfoLister struct{ infos []os.FileInfo }

func (l fileInfoLister) ListAt(fis []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.infos)) {
		return 0, io.EOF
	}
	n := copy(fis, l.infos[offset:])
	if n < len(fis) {
		return n, io.EOF
	}
	return n, nil
}

func listerFromFileInfo(infos []os.FileInfo) sftp.ListerAt {
	return fileInfoLister{infos: infos}
}

func listerFromDirEntries(dir string, entries []os.DirEntry) sftp.ListerAt {
	infos := make([]os.FileInfo, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			log.Printf("listerFromDirEntries: stat %s/%s: %v", dir, e.Name(), err)
			continue
		}
		infos = append(infos, fi)
	}
	return fileInfoLister{infos: infos}
}
