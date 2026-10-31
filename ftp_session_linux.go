//go:build linux

package ironport

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/define42/ironport/internal/jailfs"
	"github.com/define42/ironport/internal/netconn"
)

var (
	// errFTPLineTooLong is returned when an FTP client sends a control-channel
	// command that exceeds ftpMaxControlLineLen bytes.
	errFTPLineTooLong = errors.New("ftp control line too long")
	// errFTPDataProtectionRequired is returned when a require-TLS session tries
	// to transfer data without first negotiating PBSZ followed by PROT P.
	errFTPDataProtectionRequired = errors.New("PROT P required before data transfer")
)

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

func (s *Server) serveFTP(ln net.Listener, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent) error {
	tempExts := s.configuredTempExtensions()
	return s.acceptLoop(ln, "ftp", func(nc net.Conn) {
		s.handleFTPConn(nc, tempExts, uploads, authEvents)
	})
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
	server *Server
	conn   net.Conn
	// rawConn is the connection exactly as it was accepted and recorded
	// in Server.activeConns. AUTH TLS replaces conn with the *tls.Conn
	// wrapper, but activeConns stays keyed by the accepted conn, so user
	// association updates (setConnUser) must always go through rawConn;
	// keying on conn after the upgrade misses the map and the session
	// escapes RemoveUser / RemoveAllUsers eviction.
	rawConn       net.Conn
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
	ctlMsg chan ftpCtlMsg
	// readerStop, when closed, asks the reader goroutine to exit without
	// reporting the read error that the close triggers. AUTH TLS uses this
	// to suspend the reader, drain bookkeeping, swap the underlying reader
	// for the TLS-wrapped one, and then start a fresh reader.
	readerStop chan struct{}
	// readerDone is closed by the reader goroutine on exit so a caller of
	// stopReader can wait for the goroutine to terminate before touching
	// shared state (f.r, f.conn, f.ctlMsg).
	readerDone chan struct{}
	clientIP   string
	tempExts   []string
	uploads    chan<- CompletedUpload
	authEvents chan<- AuthEvent
	// fs is the fd-relative filesystem backing this session's jail. It is
	// constructed by authenticate on successful login and released when the
	// session ends (closeJail). Until login succeeds it is nil.
	fs *jailfs.FS
	// tlsConn is non-nil once the control connection has been wrapped via
	// AUTH TLS. f.conn is set to the same *tls.Conn value in that case;
	// keeping a typed pointer avoids repeated type assertions in PROT and
	// data-conn setup paths.
	tlsConn *tls.Conn
	// controlTLSConfig and dataTLSConfig form a capability private to this
	// control connection. They share one random ticket key that no other FTP
	// session receives; the data config also requires successful resumption.
	// The pair is retained across REIN because REIN does not replace the
	// current TLS control transport.
	controlTLSConfig, dataTLSConfig *tls.Config
	// pbszSet records that the client has sent PBSZ. PROT may only be
	// accepted after PBSZ per RFC 4217 §9.
	pbszSet bool
	// dataProt is 'C' (clear / default) or 'P' (private / TLS-wrapped). It
	// gates whether acceptDataConn TLS-wraps the data connection.
	dataProt byte
}

func (s *Server) handleFTPConn(nc net.Conn, tempExts []string, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent) {
	sess := &ftpSession{
		server:     s,
		conn:       nc,
		rawConn:    nc,
		r:          bufio.NewReader(nc),
		w:          bufio.NewWriter(nc),
		cwd:        "/",
		dataProt:   'C',
		clientIP:   netconn.RemoteIP(nc.RemoteAddr()),
		tempExts:   tempExts,
		uploads:    uploads,
		authEvents: authEvents,
	}
	// Close nc first, then drain the current reader's ctlMsg so its goroutine
	// can exit. The reader may have been restarted by AUTH TLS; sess.ctlMsg
	// is re-read at defer-execution time so the drain targets whichever
	// channel is current.
	defer func() {
		_ = nc.Close()
		ctl := sess.ctlMsg
		if ctl != nil {
			for range ctl {
			}
		}
	}()
	defer sess.closeDataEndpoint()
	defer sess.closeJail()
	defer sess.logoutIfAuthenticated()

	if err := sess.reply(220, "ready"); err != nil {
		return
	}

	sess.startReader()

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
		resetIdleTimer(idleTimer, idleTimeout)
		msg, done := sess.nextControlMessage(idleC, nc)
		if done {
			return
		}
		line := strings.TrimRight(msg.line, "\r\n")
		if line == "" {
			continue
		}
		cmd, arg := parseFTPCommand(line)
		if sess.handleFTPCommand(cmd, arg) {
			return
		}
	}
}

func resetIdleTimer(t *time.Timer, d time.Duration) {
	if t == nil {
		return
	}
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// nextControlMessage waits for the next control-channel message or for the
// idle timer to fire. Returns done=true when the caller should exit the
// per-session loop (channel closed, idle timeout, or fatal read error); the
// helper has already logged and replied as needed.
func (f *ftpSession) nextControlMessage(idleC <-chan time.Time, nc net.Conn) (ftpCtlMsg, bool) {
	select {
	case msg, ok := <-f.ctlMsg:
		if !ok {
			return ftpCtlMsg{}, true
		}
		if msg.err != nil {
			f.handleControlReadError(msg.err, nc)
			return ftpCtlMsg{}, true
		}
		return msg, false
	case <-idleC:
		log.Printf("ftp control idle timeout from=%s", nc.RemoteAddr())
		// Tell the client why the connection is going away instead of
		// dropping it silently (which clients see as an unexplained hang-up).
		_ = f.reply(421, "idle timeout, closing control connection")
		return ftpCtlMsg{}, true
	}
}

func (f *ftpSession) handleControlReadError(err error, nc net.Conn) {
	if errors.Is(err, errFTPLineTooLong) {
		_ = f.reply(500, ftpErrMsg(err))
		log.Printf("ftp control read from=%s: line exceeded %d bytes", nc.RemoteAddr(), ftpMaxControlLineLen)
		return
	}
	if !errors.Is(err, io.EOF) {
		log.Printf("ftp control read from=%s: %v", nc.RemoteAddr(), err)
	}
}

// startReader spins up a fresh reader goroutine bound to the session's
// current bufio.Reader and a fresh ctlMsg channel. It is called once at
// session start and again after AUTH TLS swaps the underlying transport.
func (f *ftpSession) startReader() {
	f.ctlMsg = make(chan ftpCtlMsg, 1)
	f.readerStop = make(chan struct{})
	f.readerDone = make(chan struct{})
	go f.readControlLines()
}

// stopReader signals the reader goroutine to exit and waits for it to
// terminate. It interrupts an in-flight read by setting a near-past read
// deadline on f.conn; the resulting error is suppressed by the reader
// because readerStop is already closed. After stopReader returns the
// caller owns f.r and f.conn until startReader is invoked again. The read
// deadline is restored to the zero value before returning so subsequent
// reads (on the wrapped or replaced transport) block normally.
func (f *ftpSession) stopReader() {
	if f.readerStop == nil {
		return
	}
	close(f.readerStop)
	// Wake any blocked read in readFTPControlLine without closing the
	// connection. tls.Conn forwards SetReadDeadline to the underlying
	// socket, so the same trick works pre- and post-upgrade.
	_ = f.conn.SetReadDeadline(time.Unix(1, 0))
	<-f.readerDone
	_ = f.conn.SetReadDeadline(time.Time{})
	f.readerStop = nil
	f.readerDone = nil
}

// readControlLines is the sole reader of the control connection. It runs
// from session start until the connection closes (or an oversized line is
// encountered), delivering each parsed line to ctlMsg and a final error
// message before closing the channel. Centralising reads here is what
// lets a long-running data transfer also observe ABOR in real time.
//
// Exit paths:
//   - readerStop closed: return without emitting a final error so the main
//     loop knows the swap (AUTH TLS) is in progress rather than that the
//     peer hung up. ctlMsg is still closed so any drainer terminates.
//   - read error: emit it on ctlMsg and return.
func (f *ftpSession) readControlLines() {
	defer close(f.ctlMsg)
	defer close(f.readerDone)
	for {
		select {
		case <-f.readerStop:
			return
		default:
		}
		line, err := readFTPControlLine(f.r, ftpMaxControlLineLen)
		if err != nil {
			// If stopReader is what unblocked us, swallow the deadline
			// error so the main loop does not treat the AUTH TLS swap
			// as a connection failure.
			select {
			case <-f.readerStop:
				return
			default:
			}
			select {
			case f.ctlMsg <- ftpCtlMsg{err: err}:
			case <-f.readerStop:
			}
			return
		}
		select {
		case f.ctlMsg <- ftpCtlMsg{line: line}:
		case <-f.readerStop:
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
			drainFTPControlLine(r)
			return "", errFTPLineTooLong
		}
		buf = append(buf, b)
	}
}

// drainFTPControlLine consumes bytes from r up to and including the next '\n'
// (or EOF) so the protocol stream stays aligned after an over-length command
// is rejected.
func drainFTPControlLine(r *bufio.Reader) {
	for {
		b, err := r.ReadByte()
		if err != nil || b == '\n' {
			return
		}
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
	jfs, err := jailfs.Open(jailRoot)
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
	// force-close active FTP sessions if the account is revoked. Key on
	// rawConn: after AUTH TLS, f.conn is the *tls.Conn wrapper, which is
	// not the conn the accept loop registered in activeConns.
	f.server.setConnUser(f.rawConn, f.username)
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
