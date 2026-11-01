//go:build linux

package ironport

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"path"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/define42/ironport/internal/jailfs"
	"github.com/define42/ironport/internal/netconn"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func (s *Server) serveSFTP(ln net.Listener, cfg *ssh.ServerConfig, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent) error {
	tempExts := s.configuredTempExtensions()
	idleTimeout := s.effectiveIdleTimeout()
	allowChown := s.sftpChownAllowed()
	return s.acceptLoop(ln, "sftp", func(nc net.Conn) {
		s.handleConn(nc, cfg, uploads, authEvents, tempExts, idleTimeout, allowChown)
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
			allArgs := make([]any, 0, len(args)+2)
			allArgs = append(allArgs, args...)
			allArgs = append(allArgs, recovered, debug.Stack())
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

// checkSSHKeyQuery checks admission and key eligibility without opening a jail.
// An unsigned query does not prove key ownership, so it must not trigger root
// I/O or root diagnostics. Proof will re-read the user and check the key again.
func (s *Server) checkSSHKeyQuery(c ssh.ConnMetadata, key ssh.PublicKey, authEvents chan<- AuthEvent) error {
	clientIP := netconn.RemoteIP(c.RemoteAddr())
	if s.allowAuth(c.User(), clientIP) > 0 {
		s.authFailed(c.User(), clientIP, CompletedUploadProtocolSFTP, authEvents, true)
		return errInvalidCredentials
	}
	u, revision, exists := s.userSnapshot(c.User())
	// Match even for unknown users to preserve the public-key timing pad.
	if !matchAuthorizedKey(u.AuthorizedKeys, key) || !exists || !s.userRevisionMatches(c.User(), revision) {
		// Clients commonly offer several keys before finding an authorized one.
		// Eligibility is checked before signature verification, even for signed
		// requests, so a rejection must not advance credential-failure backoff.
		s.reportAuthFailure(c.User(), clientIP, CompletedUploadProtocolSFTP, authEvents, false)
		return errInvalidCredentials
	}
	return nil
}

// authenticateSSH checks admission and credentials for a password or verified
// key. A query's first proof reuses its already-consumed token.
// Successful permissions carry an owned jail descriptor. Every new auth callback
// must transfer that ownership through sshAuthState.config or close it itself.
func (s *Server) authenticateSSH(c ssh.ConnMetadata, keyCheck func(UserInfo) bool, useQueryAdmission bool, authEvents chan<- AuthEvent) (*ssh.Permissions, error) {
	clientIP := netconn.RemoteIP(c.RemoteAddr())
	var retry time.Duration
	if useQueryAdmission {
		retry = s.authControl().RetryBackoff(c.User(), clientIP, time.Now())
	} else {
		retry = s.allowAuth(c.User(), clientIP)
	}
	if retry > 0 {
		s.authFailed(c.User(), clientIP, CompletedUploadProtocolSFTP, authEvents, true)
		return nil, errInvalidCredentials
	}
	u, fs, revision, ok := s.authenticateUser(c.User(), keyCheck)
	if !ok {
		s.authFailed(c.User(), clientIP, CompletedUploadProtocolSFTP, authEvents, false)
		return nil, errInvalidCredentials
	}
	permissions := permissionsFor(u, c.User(), u.Root)
	permissions.ExtraData = map[any]any{sshRevisionKey{}: revision, sshJailFSKey{}: fs}
	return permissions, nil
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
	type keyAdmission struct{}

	cfg := &ssh.ServerConfig{
		KeyExchanges:            slices.Clone(s.sshKeyExchanges),
		Ciphers:                 slices.Clone(s.sshCiphers),
		MACs:                    slices.Clone(s.sshMACs),
		PublicKeyAuthAlgorithms: slices.Clone(s.sshPublicKeyAuthAlgorithms),
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			perms, err := s.authenticateSSH(c, func(u UserInfo) bool {
				// checkPassword treats an empty stored password as
				// "no password set" and rejects it. Passing u.Password
				// directly works for both the existing-user and
				// unknown-user (zero-value UserInfo) cases, and the SHA-256
				// length-normalisation inside checkPassword keeps the
				// comparison constant-time regardless.
				return checkPassword(u.Password, string(pass))
			}, false, authEvents)
			if err == nil {
				s.authSucceeded(c.User(), netconn.RemoteIP(c.RemoteAddr()))
			}
			return perms, err
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if err := s.checkSSHKeyQuery(c, key, authEvents); err != nil {
				return nil, err
			}
			// Retain only admission, never the query's user snapshot or a jail.
			return &ssh.Permissions{ExtraData: map[any]any{keyAdmission{}: true}}, nil
		},
		VerifiedPublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey, queryPermissions *ssh.Permissions, _ string) (*ssh.Permissions, error) {
			// x/crypto transfers ownership of the cached query permissions here.
			// Spend its admission once: another proof after a failed callback
			// must obtain a fresh token even when x/crypto reuses that query.
			admitted := false
			if queryPermissions != nil {
				_, admitted = queryPermissions.ExtraData[keyAdmission{}]
				delete(queryPermissions.ExtraData, keyAdmission{})
			}
			// Signature verification has proved key ownership. Re-read current
			// credentials and permissions before opening and retaining the jail.
			permissions, err := s.authenticateSSH(c, func(u UserInfo) bool {
				return matchAuthorizedKey(u.AuthorizedKeys, key)
			}, admitted, authEvents)
			if err == nil {
				s.authSucceeded(c.User(), netconn.RemoteIP(c.RemoteAddr()))
			}
			return permissions, err
		},
	}
	cfg.AddHostKey(s.sftpSigner)
	return cfg
}

// acceptSSHConnection bounds both inactivity and total handshake time, then
// switches successful connections to the authenticated-session idle timeout.
func acceptSSHConnection(nc net.Conn, cfg *ssh.ServerConfig, idleTimeout time.Duration) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	ic := &netconn.IdleConn{Conn: nc}
	ic.SetReadTimeout(sshHandshakeTimeout)
	// Reads refresh the idle deadline, but cannot extend this absolute login
	// window. Closing the transport also interrupts a blocked handshake write.
	handshakeTimer := time.AfterFunc(sshHandshakeTimeout, func() { _ = nc.Close() })
	defer handshakeTimer.Stop()
	sshConn, chans, reqs, err := ssh.NewServerConn(ic, cfg)
	handshakeTimer.Stop()
	if err == nil {
		ic.SetReadTimeout(idleTimeout)
	}
	return sshConn, chans, reqs, err
}

func (s *Server) handleConn(nc net.Conn, cfg *ssh.ServerConfig, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent, tempExts []string, idleTimeout time.Duration, sftpAllowChown bool) {
	defer func() { _ = nc.Close() }()

	var authState sshAuthState
	defer authState.close()
	sshConn, chans, reqs, err := acceptSSHConnection(nc, authState.config(cfg), idleTimeout)
	if err != nil {
		if allowed, suppressed := s.authLogs.allow(time.Now()); allowed {
			log.Printf("ssh handshake: %v (suppressed=%d)", err, suppressed)
		}
		return
	}
	globalRequestsDone := make(chan struct{})
	go func() {
		defer close(globalRequestsDone)
		ssh.DiscardRequests(reqs)
	}()
	defer func() {
		_ = sshConn.Close()
		<-globalRequestsDone
	}()
	fs, committed := s.commitSSHConnection(nc, sshConn, &authState, authEvents)
	if !committed {
		// Closing the transport alone cannot release a mux blocked on its
		// incoming-channel queue. Drain queued opens after revocation too.
		_ = sshConn.Close()
		for newCh := range chans {
			_ = newCh.Reject(ssh.Prohibited, "authentication no longer valid")
		}
		return
	}

	defer func() { _ = fs.Close() }()
	jailRoot := sshConn.Permissions.Extensions["jailRoot"]
	user := sshConn.Permissions.Extensions["user"]
	canRead := sshConn.Permissions.Extensions["canRead"] == "true"
	canWrite := sshConn.Permissions.Extensions["canWrite"] == "true"
	clientIP := netconn.RemoteIP(sshConn.RemoteAddr())
	log.Printf("login protocol=sftp user=%q root=%q from=%s", user, jailRoot, sshConn.RemoteAddr())
	authEvent := AuthEvent{
		Type:     AuthEventLoginSuccess,
		Username: user,
		ClientIP: clientIP,
		Protocol: CompletedUploadProtocolSFTP,
	}
	announceAuthEvent(authEvents, authEvent)
	authEvent.Type = AuthEventLogout
	defer announceAuthEvent(authEvents, authEvent)

	s.serveSSHChannels(chans, fs, user, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown)
}

func (s *Server) serveSSHChannels(chans <-chan ssh.NewChannel, fs *jailfs.FS, user, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, sftpAllowChown bool) {
	// Track the per-channel session goroutines so this function does not
	// return until they have all finished. handleConn returning is what
	// triggers untrackConn/connWG.Done in acceptLoop, which Shutdown waits
	// on; without this wait, Shutdown could return while a jailed file
	// operation is still in flight and jailfs.FS.Close could race with it.
	var sessionWG sync.WaitGroup
	defer sessionWG.Wait()
	sessionSlots := make(chan struct{}, positiveLimit(s.sshMaxChannels, defaultSSHMaxChannels))
	handles := &sessionHandleBudget{owner: &s.sftpHandles, username: user}

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		select {
		case sessionSlots <- struct{}{}:
		default:
			_ = newCh.Reject(ssh.ResourceShortage, "session channel limit reached")
			continue
		}

		ch, inReqs, err := newCh.Accept()
		if err != nil {
			<-sessionSlots
			log.Println("accept channel:", err)
			continue
		}

		sessionWG.Go(func() {
			defer func() { <-sessionSlots }()
			handleSession(ch, inReqs, fs, user, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown, handles)
		})
	}
}

func handleSession(ch ssh.Channel, inReqs <-chan *ssh.Request, fs *jailfs.FS, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, sftpAllowChown bool, handles ...*sessionHandleBudget) {
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
			// its cleanup defer (server.Close) runs on its own
			// return rather than accumulating inside this for/switch — a
			// defer placed directly in this case would survive across loop
			// iterations if the trailing `return` were ever removed.
			serveSFTPSubsystem(ch, fs, username, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown, handles...)
			return

		default:
			_ = req.Reply(false, nil)
		}
	}
}

// serveSFTPSubsystem runs one channel against the connection's authenticated
// jail. The connection retains that jail until every channel has finished.
// Callers must already have replied to the "subsystem" request before invoking it.
func serveSFTPSubsystem(ch ssh.Channel, fs *jailfs.FS, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, sftpAllowChown bool, handles ...*sessionHandleBudget) {
	handlers := jailedHandlers(fs, username, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown, handles...)

	server := sftp.NewRequestServer(ch, handlers)
	defer func() { _ = server.Close() }()
	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		log.Println("sftp serve:", err)
	}
}
