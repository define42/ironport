//go:build linux

package ironport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/define42/ironport/internal/authlimit"
	"github.com/define42/ironport/internal/jailfs"
	"github.com/define42/ironport/internal/netconn"
	"golang.org/x/crypto/ssh"
)

// Server is a self-contained SFTP server with optional FTP support.
type Server struct {
	// configErr retains invalid admission settings so every protocol fails closed.
	configErr error
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
	// PORT/EPRT. Zero selects the package default; negative disables active
	// dial deadlines only. Passive reservations remain finite.
	ftpDataAcceptTimeout time.Duration
	// ftpPassiveAdvertisedIP optionally overrides the IPv4 address sent to
	// clients in the PASV (227) reply, for deployments behind NAT or a
	// port-forward. Empty means advertise the control connection's local IP.
	ftpPassiveAdvertisedIP string
	// ftpAllowActiveMode controls whether FTP PORT/EPRT commands may ask the
	// server to dial an active-mode data connection back to the client IP.
	ftpAllowActiveMode bool
	// ftpTLSConfig is the immutable template used to derive a private pair of
	// control/data TLS configs for each FTP session that issues AUTH TLS. A nil
	// value disables FTPS — the AUTH command will be refused with 502.
	ftpTLSConfig *tls.Config
	// ftpTLSConfigErr records a fatal validation error in the supplied FTP TLS
	// template. It is surfaced at startup by prepareForListen.
	ftpTLSConfigErr error
	// ftpRequireTLS, when true, refuses USER/PASS until the control connection
	// has been wrapped with AUTH TLS and refuses data transfers until the client
	// has negotiated PBSZ followed by PROT P.
	ftpRequireTLS bool
	// users maps usernames to their credentials and jail roots.
	users map[string]UserInfo
	// Revisions distinguish each authentication configuration, including a
	// removed user subsequently recreated with the same credentials.
	userRevisions    map[string]uint64
	nextUserRevision uint64
	// mu protects users, revisions, connection state, event streams, and listeners.
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
	// Admission budgets are shared by all protocol handlers from this server.
	sshMaxChannels            int
	maxConnections            int
	maxConnectionsPerIP       int
	ftpAuthTimeout            time.Duration
	ftpMaxAuthFailures        int
	ftpPassiveLimits          ftpPassiveLimits
	sftpHandles               handleBudget
	authOnce                  sync.Once
	authLimiter               *authlimit.Limiter
	authLogs                  authLogSampler
	httpMaxConcurrentRequests int
	httpMaxAuthorizationBytes int
	httpMaxUsernameBytes      int
	httpMaxPasswordBytes      int
	httpControlLogs           authLogSampler
	httpRequestOnce           sync.Once
	httpRequestSlots          chan struct{}
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
	// activeConns holds every accepted connection until its handler returns.
	// Authentication is separate from username because an empty username is
	// valid and must not be confused with an unauthenticated connection.
	activeConns map[net.Conn]activeConnState
	// connCancels retains cancellation state until the owning handler exits.
	// It lets FTP interrupt data setup as well as the control connection.
	// Both maps are protected by mu.
	connCancels map[net.Conn]connCancelState
	// shutdownWaiters counts concurrent Shutdown callers so shuttingDown stays
	// true until the final caller has finished waiting on connWG.
	shutdownWaiters int
	// shuttingDown is set while Shutdown is draining so subsequent trackConn
	// calls refuse new work instead of starting handlers we would have to
	// drain. It is guarded by mu so it serialises with connWG.Add inside
	// trackConn.
	shuttingDown bool
}

type activeConnState struct {
	username      string
	authenticated bool
}

type connCancelState struct {
	cancel   func()
	canceled bool
}

// NewServer creates a new Server from config. Call Config.Validate to check
// admission settings first. Invalid settings make ListenAndServe return an
// error and HttpIngest reject requests with HTTP 503.
// Pass FtpAddr as "" to disable
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
		configErr:                  config.Validate(),
		addr:                       config.SftpAddr,
		ftpAddr:                    config.FtpAddr,
		ftpPassivePortRange:        config.FtpPassivePortRange,
		ftpDataAcceptTimeout:       config.FtpDataAcceptTimeout,
		ftpAllowActiveMode:         config.FtpAllowActiveMode,
		ftpPassiveAdvertisedIP:     strings.TrimSpace(config.FtpPassiveAdvertisedIP),
		ftpRequireTLS:              config.FtpRequireTLS,
		users:                      cloneUsers(config.Users),
		sftpSigner:                 config.SftpSigner,
		completedUploads:           newCompletedUploadsChannel(config.CompletedUploadSize),
		authEvents:                 newAuthEventsChannel(config.AuthEventSize),
		sshKeyExchanges:            slices.Clone(config.SSHKeyExchanges),
		sshCiphers:                 slices.Clone(config.SSHCiphers),
		sshMACs:                    slices.Clone(config.SSHMACs),
		sshPublicKeyAuthAlgorithms: slices.Clone(config.SSHPublicKeyAuthAlgorithms),
		sshMaxChannels:             positiveLimit(config.ResourceLimits.SSHMaxChannels, defaultSSHMaxChannels),
		maxConnections:             positiveLimit(config.ResourceLimits.MaxConnections, defaultMaxConnections),
		maxConnectionsPerIP:        positiveLimit(config.ResourceLimits.MaxConnectionsPerIP, defaultMaxConnectionsPerIP),
		ftpAuthTimeout:             positiveDuration(config.ResourceLimits.FTPAuthTimeout, defaultFTPAuthTimeout),
		sftpHandles: handleBudget{
			max:        positiveLimit(config.ResourceLimits.SFTPMaxHandles, defaultSFTPMaxHandles),
			maxUser:    positiveLimit(config.ResourceLimits.SFTPMaxHandlesPerUser, defaultSFTPMaxHandlesPerUser),
			maxSession: positiveLimit(config.ResourceLimits.SFTPMaxHandlesPerConnection, defaultSFTPMaxHandlesPerConnection),
		},
		ftpMaxAuthFailures:        positiveLimit(config.ResourceLimits.FTPMaxAuthFailures, 5),
		ftpPassiveLimits:          newFTPPassiveLimits(config),
		authLimiter:               newAuthLimiter(config.AuthLimits),
		httpMaxConcurrentRequests: positiveLimit(config.ResourceLimits.HTTPMaxConcurrentRequests, defaultHTTPMaxConcurrentRequests),
		httpMaxAuthorizationBytes: positiveLimit(config.ResourceLimits.HTTPMaxAuthorizationBytes, defaultHTTPMaxAuthorizationBytes),
		httpMaxUsernameBytes:      positiveLimit(config.ResourceLimits.HTTPMaxUsernameBytes, defaultHTTPMaxUsernameBytes),
		httpMaxPasswordBytes:      positiveLimit(config.ResourceLimits.HTTPMaxPasswordBytes, defaultHTTPMaxPasswordBytes),
		tempExtensions:            normalizeTempExtensions(config.TempExtensions),
		idleTimeout:               config.IdleTimeout,
		tcpKeepAlivePeriod:        config.TCPKeepAlivePeriod,
		sftpAllowChown:            config.SftpAllowChown,
		activeConns:               make(map[net.Conn]activeConnState),
	}
	for username := range s.users {
		s.bumpUserRevisionLocked(username)
	}
	if config.FtpTLSConfig != nil {
		s.ftpTLSConfig = config.FtpTLSConfig.Clone()
		s.ftpTLSConfigErr = validateFTPTLSSessionCallbacks(s.ftpTLSConfig)
	}
	return s
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

// trackConn admits and tracks SFTP/FTP control connections within the shared
// total and per-IP budgets. On overload or shutdown it returns false; the
// caller must close nc without starting a handler.
// On success the caller must call untrackConn(nc) and connWG.Done() exactly
// once before its handler goroutine returns.
func (s *Server) trackConn(nc net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shuttingDown || len(s.activeConns) >= positiveLimit(s.maxConnections, defaultMaxConnections) {
		return false
	}
	if _, tracked := s.activeConns[nc]; tracked {
		return false
	}
	ip := canonicalClientIP(netconn.RemoteIP(nc.RemoteAddr()))
	count := 0
	for conn := range s.activeConns {
		if canonicalClientIP(netconn.RemoteIP(conn.RemoteAddr())) == ip {
			count++
		}
	}
	if count >= positiveLimit(s.maxConnectionsPerIP, defaultMaxConnectionsPerIP) {
		return false
	}
	if s.activeConns == nil {
		s.activeConns = make(map[net.Conn]activeConnState)
	}
	s.activeConns[nc] = activeConnState{}
	s.connWG.Add(1)
	return true
}

// setConnCancel attaches idempotent protocol cleanup to a tracked connection.
// A concurrent revocation or shutdown cannot be missed by late registration.
func (s *Server) setConnCancel(nc net.Conn, cancel func()) bool {
	s.mu.Lock()
	_, tracked := s.activeConns[nc]
	state := s.connCancels[nc]
	if !tracked || state.canceled || s.shuttingDown {
		s.mu.Unlock()
		cancel()
		return false
	}
	if s.connCancels == nil {
		s.connCancels = make(map[net.Conn]connCancelState)
	}
	state.cancel = cancel
	s.connCancels[nc] = state
	s.mu.Unlock()
	return true
}

// cancelConnLocked marks a connection before returning cleanup to run outside
// mu. Keeping the marker until untrackConn prevents late registration races.
func (s *Server) cancelConnLocked(nc net.Conn) func() {
	if s.connCancels == nil {
		s.connCancels = make(map[net.Conn]connCancelState)
	}
	state := s.connCancels[nc]
	state.canceled = true
	s.connCancels[nc] = state
	return func() {
		_ = nc.Close()
		if state.cancel != nil {
			state.cancel()
		}
	}
}

// clearConnUser marks a tracked connection as unauthenticated. It preserves
// cancellation state, so a concurrent revocation cannot be undone by FTP reset.
func (s *Server) clearConnUser(nc net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, tracked := s.activeConns[nc]; tracked {
		s.activeConns[nc] = activeConnState{}
	}
}

// commitConnUser verifies the snapshot and registers its authenticated
// connection under the same lock as user mutations. A concurrent revocation
// either invalidates this revision first or sees the connection and closes it.
func (s *Server) commitConnUser(nc net.Conn, username string, revision uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision == 0 || s.userRevisions[username] != revision {
		return false
	}
	if _, exists := s.users[username]; !exists {
		return false
	}
	if _, tracked := s.activeConns[nc]; !tracked || s.connCancels[nc].canceled {
		return false
	}
	s.activeConns[nc] = activeConnState{username: username, authenticated: true}
	return true
}

// cancelUserConnsLocked marks every authenticated connection belonging to a
// user before returning its cleanup callbacks. Callers run I/O outside mu.
func (s *Server) cancelUserConnsLocked(username string) []func() {
	var toClose []func()
	for nc, state := range s.activeConns {
		if state.authenticated && state.username == username {
			toClose = append(toClose, s.cancelConnLocked(nc))
		}
	}
	return toClose
}

func closeConns(closers []func()) {
	for _, closeConn := range closers {
		closeConn()
	}
}

// untrackConn removes nc from the in-flight set. The corresponding
// connWG.Done() call is the caller's responsibility so that ordering between
// "stop tracking" and "decrement waitgroup" is explicit at each call site.
func (s *Server) untrackConn(nc net.Conn) {
	s.mu.Lock()
	delete(s.activeConns, nc)
	delete(s.connCancels, nc)
	s.mu.Unlock()
}

// forceCloseActiveConns closes every connection still in the active set.
// Returns the number of connections it closed. Used by Shutdown to evict
// stragglers when the caller's context deadline fires before handlers have
// finished on their own.
func (s *Server) forceCloseActiveConns() int {
	s.mu.Lock()
	closers := make([]func(), 0, len(s.activeConns))
	for c := range s.activeConns {
		closers = append(closers, s.cancelConnLocked(c))
	}
	s.mu.Unlock()
	for _, closeConn := range closers {
		closeConn()
	}
	return len(closers)
}

// ListenAndServe starts the SFTP server and, when configured, the FTP server
// too. It blocks until Close or Shutdown is called or an unexpected
// listener error occurs. It returns nil when stopped via Close or Shutdown.
//
// A stopped server can be started again by calling ListenAndServe after Close
// or Shutdown returns. Concurrent ListenAndServe calls are rejected.
func (s *Server) ListenAndServe() error {
	if s.configErr != nil {
		return s.configErr
	}
	if strings.TrimSpace(s.addr) == "" {
		return errors.New("ironport: SftpAddr is required")
	}
	runID, err := s.beginListenAndServe()
	if err != nil {
		return err
	}
	defer s.finishListenAndServe(runID)

	if err := s.prepareForListen(); err != nil {
		return err
	}
	uploads := s.completedUploadsChan()
	authEvents := s.authEventsChan()
	cfg := s.sshServerConfig()

	sftpLn, ftpLn, err := s.openListeners()
	if err != nil {
		return err
	}
	if !s.publishListeners(runID, sftpLn, ftpLn) {
		return closeListenerPair(sftpLn, ftpLn)
	}
	return s.runListenWorkers(runID, sftpLn, ftpLn, cfg, uploads, authEvents)
}

// prepareForListen runs the startup checks that must succeed before any
// listener is opened: the FTPS config is valid, a signer is available, and the
// running kernel supports the openat2 containment primitive.
func (s *Server) prepareForListen() error {
	if s.ftpTLSConfigErr != nil {
		return fmt.Errorf("ironport: %w", s.ftpTLSConfigErr)
	}
	if err := s.ensureSigner(); err != nil {
		return fmt.Errorf("ironport: %w", err)
	}
	// The package's containment guarantee relies on
	// openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS), available since Linux
	// 5.6. Fail fast at startup on older kernels rather than silently
	// degrading the policy at first request.
	if err := jailfs.CheckSupport(); err != nil {
		return fmt.Errorf("ironport: %w", err)
	}
	return nil
}

func (s *Server) openListeners() (net.Listener, net.Listener, error) {
	sftpLn, err := net.Listen("tcp", s.addr)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(s.ftpAddr) == "" {
		return sftpLn, nil, nil
	}
	ftpLn, err := net.Listen("tcp", s.ftpAddr)
	if err != nil {
		_ = sftpLn.Close()
		return nil, nil, err
	}
	return sftpLn, ftpLn, nil
}

func (s *Server) runListenWorkers(runID uint64, sftpLn, ftpLn net.Listener, cfg *ssh.ServerConfig, uploads chan<- CompletedUpload, authEvents chan<- AuthEvent) error {
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

// acceptLoop runs the shared Accept loop used by both protocol listeners:
// it applies the configured TCP keepalive to every new connection, tracks
// the connection for graceful shutdown, recovers from handler panics, and
// applies exponential backoff between 5ms and 1s on transient Accept errors
// so a momentary EMFILE/ENFILE cannot kill the listener. name is used in log
// messages to distinguish the SFTP and FTP loops.
//
// Transient errors (timeouts, EMFILE/ENFILE, ECONNABORTED, EINTR, …) are
// retried indefinitely. A run of non-transient errors — for example a
// poisoned listener fd that returns the same hard error on every Accept —
// is capped: after maxConsecutiveAcceptErrors such errors the loop gives up
// and returns the error rather than spinning and logging forever.
func (s *Server) acceptLoop(ln net.Listener, name string, handler func(net.Conn)) error {
	var backoff time.Duration
	var permanentErrors int
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			newBackoff, retErr := s.handleAcceptError(name, err, backoff, &permanentErrors)
			if retErr != nil {
				return retErr
			}
			backoff = newBackoff
			continue
		}
		backoff = 0
		permanentErrors = 0
		netconn.ApplyTCPKeepAlive(nc, s.effectiveTCPKeepAlivePeriod())
		if !s.trackConn(nc) {
			// Reject overload or shutdown before allocating protocol state
			// or starting a handler goroutine.
			_ = nc.Close()
			continue
		}
		s.spawnConnHandler(name, nc, handler)
	}
}

// handleAcceptError processes a non-ErrClosed Accept error: it updates the
// permanent-error counter, decides whether to give up, logs, and sleeps for
// the next backoff interval. It returns a non-nil error when the loop should
// stop; otherwise it returns the new backoff to carry forward.
func (s *Server) handleAcceptError(name string, err error, backoff time.Duration, permanentErrors *int) (time.Duration, error) {
	if isTransientAcceptError(err) {
		*permanentErrors = 0
	} else {
		*permanentErrors++
		if *permanentErrors >= maxConsecutiveAcceptErrors {
			log.Printf("%s accept: %v; giving up after %d consecutive non-transient errors", name, err, *permanentErrors)
			return 0, fmt.Errorf("%s accept: %w", name, err)
		}
	}
	backoff = nextAcceptBackoff(backoff)
	log.Printf("%s accept: %v; retrying in %s", name, err, backoff)
	time.Sleep(backoff)
	return backoff, nil
}

// spawnConnHandler runs handler for an accepted connection in its own
// goroutine, recovering from handler panics and releasing the connection's
// shutdown tracking when it returns.
func (s *Server) spawnConnHandler(name string, nc net.Conn, handler func(net.Conn)) {
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

// isTransientAcceptError reports whether an Accept error is the kind that
// typically clears on its own (and so is worth retrying indefinitely):
// timeouts and transient syscall conditions such as running out of file
// descriptors. Anything else is treated as potentially permanent.
func isTransientAcceptError(err error) bool {
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		return true
	}
	if se, ok := errors.AsType[syscall.Errno](err); ok {
		return se == syscall.EMFILE || se == syscall.ENFILE ||
			se == syscall.ECONNABORTED || se == syscall.EINTR ||
			se == syscall.ENOBUFS || se == syscall.ENOMEM
	}
	return false
}

// nextAcceptBackoff returns the next exponential backoff duration to sleep
// after a transient Accept error. The schedule starts at 5ms and caps at 1s.
func nextAcceptBackoff(prev time.Duration) time.Duration {
	if prev == 0 {
		return 5 * time.Millisecond
	}
	return min(prev*2, time.Second)
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
