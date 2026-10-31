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
				ClientIP: netconn.RemoteIP(c.RemoteAddr()),
				Protocol: CompletedUploadProtocolSFTP,
			})
			return nil, errInvalidCredentials
		}
		return permissionsFor(u, c.User(), jailRoot), nil
	}

	cfg := &ssh.ServerConfig{
		KeyExchanges:            slices.Clone(s.sshKeyExchanges),
		Ciphers:                 slices.Clone(s.sshCiphers),
		MACs:                    slices.Clone(s.sshMACs),
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
				return matchAuthorizedKey(u.AuthorizedKeys, key)
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
	ic := &netconn.IdleConn{Conn: nc}
	ic.SetReadTimeout(sshHandshakeTimeout)
	sshConn, chans, reqs, err := ssh.NewServerConn(ic, cfg)
	if err != nil {
		log.Println("ssh handshake:", err)
		return
	}
	// Handshake complete – switch to the idle-session deadline. A zero value
	// disables the deadline.
	ic.SetReadTimeout(idleTimeout)
	defer func() { _ = sshConn.Close() }()

	jailRoot := sshConn.Permissions.Extensions["jailRoot"]
	user := sshConn.Permissions.Extensions["user"]
	canRead := sshConn.Permissions.Extensions["canRead"] == "true"
	canWrite := sshConn.Permissions.Extensions["canWrite"] == "true"
	clientIP := netconn.RemoteIP(sshConn.RemoteAddr())
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

	// Track the per-channel session goroutines so this function does not
	// return until they have all finished. handleConn returning is what
	// triggers untrackConn/connWG.Done in acceptLoop, which Shutdown waits
	// on; without this wait, Shutdown could return while a jailed file
	// operation is still in flight and jailfs.FS.Close could race with it.
	var sessionWG sync.WaitGroup
	defer sessionWG.Wait()

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

		sessionWG.Go(func() {
			handleSession(ch, inReqs, jailRoot, user, clientIP, canRead, canWrite, uploads, tempExts, sftpAllowChown)
		})
	}
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
