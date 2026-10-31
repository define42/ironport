package ironport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestNewServer(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "pw", Root: "/tmp/alice", CanRead: true, CanWrite: true},
	}
	signer := testSigner(t)
	config := DefaultConfig()
	config.SftpAddr = ":0"
	config.FtpAddr = ":0"
	config.FtpPassivePortRange = "5000-5010"
	config.FtpDataAcceptTimeout = 17 * time.Second
	config.FtpAllowActiveMode = true
	config.Users = users
	config.SftpSigner = signer
	config.CompletedUploadSize = defaultCompletedUploadsSize
	config.AuthEventSize = defaultAuthEventsSize
	srv := NewServer(config)
	if srv.addr != ":0" {
		t.Errorf("addr = %q; want :0", srv.addr)
	}
	if srv.ftpAddr != ":0" {
		t.Errorf("ftpAddr = %q; want :0", srv.ftpAddr)
	}
	if srv.ftpPassivePortRange != "5000-5010" {
		t.Errorf("ftpPassivePortRange = %q; want 5000-5010", srv.ftpPassivePortRange)
	}
	if srv.ftpDataAcceptTimeout != 17*time.Second {
		t.Errorf("ftpDataAcceptTimeout = %v; want 17s", srv.ftpDataAcceptTimeout)
	}
	if !srv.ftpAllowActiveMode {
		t.Error("ftpAllowActiveMode = false; want true")
	}
	if len(srv.users) != 1 {
		t.Errorf("users len = %d; want 1", len(srv.users))
	}
	users["alice"] = UserInfo{Password: "changed", Root: "/tmp/changed"}
	if got := srv.users["alice"].Password; got != "pw" {
		t.Errorf("users map was not cloned; password = %q; want pw", got)
	}
	if srv.sftpSigner != signer {
		t.Error("sftpSigner not set correctly")
	}
	if cap(srv.AuthEvents()) != defaultAuthEventsSize {
		t.Errorf("AuthEvents cap = %d; want %d", cap(srv.AuthEvents()), defaultAuthEventsSize)
	}
}

func TestNewServer_ClonesUsersMapAndAuthorizedKeys(t *testing.T) {
	root := t.TempDir()
	_, pubKey1 := testClientKey(t)
	_, pubKey2 := testClientKey(t)
	keys := make([]ssh.PublicKey, 1, 2)
	keys[0] = pubKey1
	users := map[string]UserInfo{
		"alice": {
			Password:       "pw1",
			AuthorizedKeys: keys,
			Root:           root,
			CanRead:        true,
		},
	}

	srv := newTestServer(":0", "", "", users, testSigner(t), defaultCompletedUploadsSize)

	users["alice"] = UserInfo{Password: "pw2", Root: root}
	delete(users, "alice")
	// keys has len=1, cap=2 so the cap-2 reslice and index 1 write are
	// in-bounds; gosec G602 does not track cap. This verifies NewServer
	// cloned the AuthorizedKeys slice (including the unused capacity).
	keys[0] = pubKey2
	keys[:2][1] = pubKey2 //nolint:gosec // cap=2 reslice; intentional aliasing test

	srv.mu.RLock()
	got, ok := srv.users["alice"]
	srv.mu.RUnlock()

	if !ok {
		t.Fatal("server user map aliases caller-owned map")
	}
	if got.Password != "pw1" {
		t.Fatalf("stored password = %q; want %q", got.Password, "pw1")
	}
	if len(got.AuthorizedKeys) != 1 {
		t.Fatalf("AuthorizedKeys length = %d; want 1", len(got.AuthorizedKeys))
	}
	if !bytes.Equal(got.AuthorizedKeys[0].Marshal(), pubKey1.Marshal()) {
		t.Fatal("server AuthorizedKeys slice aliases caller-owned storage")
	}
}

// TestServer_ListenAndServe_Close verifies that calling Close on a running
// server causes ListenAndServe to return nil, and that a subsequent connection
// attempt fails because the listener is closed.
func TestServer_ListenAndServe_Close(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	signer := testSigner(t)

	srv := newTestServer("127.0.0.1:0", "", "", users, signer, defaultCompletedUploadsSize)

	errc := make(chan error, 1)
	go func() {
		errc <- srv.ListenAndServe()
	}()

	// Wait until the server is accepting connections.
	var addr string
	for range 50 {
		if a := srv.ListeningAddr(); a != nil {
			addr = a.String()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("server did not start in time")
	}

	// Verify the server is reachable before Close.
	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial before Close: %v", err)
	}
	_ = conn.Close()

	// Close the server; ListenAndServe must return nil.
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Close")
	}

	// Subsequent connection attempts must fail.
	if _, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		t.Error("expected error connecting after Close, got nil")
	}
}

// TestServer_ListenAndServe_RestartAfterClose verifies that Close stops the
// current listeners cleanly enough for the same Server to be started again,
// even while an older accepted connection is still draining.
func TestServer_ListenAndServe_RestartAfterClose(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv := newTestServer("127.0.0.1:0", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}

	errc1 := make(chan error, 1)
	go func() { errc1 <- srv.ListenAndServe() }()
	addr1 := waitForSFTPListener(t, srv, errc1)

	conn1, err := ssh.Dial("tcp", addr1, sshCfg)
	if err != nil {
		t.Fatalf("first ssh.Dial: %v", err)
	}
	defer func() { _ = conn1.Close() }()

	if err := srv.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Start again immediately, before the first ListenAndServe goroutine has
	// necessarily finished its cleanup.
	errc2 := make(chan error, 1)
	go func() { errc2 <- srv.ListenAndServe() }()
	addr2 := waitForSFTPListener(t, srv, errc2)

	conn2, err := ssh.Dial("tcp", addr2, sshCfg)
	if err != nil {
		t.Fatalf("second ssh.Dial: %v", err)
	}
	_ = conn2.Close()

	if err := srv.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	_ = conn1.Close()

	for name, errc := range map[string]chan error{"first": errc1, "second": errc2} {
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("%s ListenAndServe returned %v; want nil", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s ListenAndServe did not return after Close", name)
		}
	}
}

// TestServer_Close_BeforeListenAndServe verifies that calling Close before
// ListenAndServe is a safe no-op and does not panic or return an error.
func TestServer_Close_BeforeListenAndServe(t *testing.T) {
	srv := newTestServer(":0", "", "", map[string]UserInfo{}, testSigner(t), defaultCompletedUploadsSize)
	if err := srv.Close(); err != nil {
		t.Errorf("Close before ListenAndServe returned %v; want nil", err)
	}
}

// TestServer_Shutdown_DrainsInFlight verifies that Shutdown waits for an
// authenticated client session to finish before returning.
func TestServer_Shutdown_DrainsInFlight(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	srv, addr, errCh := startListenAndServe(t, users)

	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()

	// Shutdown must not return while the client is still connected.
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown returned before client closed: err=%v", err)
	case <-time.After(150 * time.Millisecond):
	}

	// New dials must be refused even though Shutdown is still draining.
	if _, dialErr := ssh.Dial("tcp", addr, sshCfg); dialErr == nil {
		t.Error("expected dial to fail after Shutdown closed the listener")
	}

	// Close the active client; Shutdown should finish soon after.
	_ = client.Close()
	_ = conn.Close()

	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("Shutdown returned %v; want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not return after client closed")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
}

// TestServer_Shutdown_ForceClosesOnContextDeadline verifies that when the
// supplied context expires before in-flight handlers finish, Shutdown
// force-closes the lingering connections and returns ctx.Err().
func TestServer_Shutdown_ForceClosesOnContextDeadline(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	srv, addr, errCh := startListenAndServe(t, users)

	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = srv.Shutdown(ctx)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown err = %v; want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Shutdown took %v; expected to return promptly after force-close", elapsed)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown deadline")
	}

	// The forcibly-closed SSH connection's session loop should observe the
	// read error and finish; a subsequent request on the client side fails.
	// SendRequest(wantReply=true) blocks waiting for a reply, so bound it with
	// a timeout: if the mux never delivers a reply because the connection was
	// force-closed, treat that as the expected failure instead of hanging.
	// The channel is buffered so the goroutine can always complete its send.
	reqDone := make(chan error, 1)
	go func() {
		_, _, err := conn.SendRequest("noop", true, nil)
		reqDone <- err
	}()
	select {
	case err := <-reqDone:
		if err == nil {
			t.Error("expected error sending request on force-closed conn, got nil")
		}
	case <-time.After(2 * time.Second):
		// No reply arrived because the connection is force-closed, which is the
		// behavior under test.
	}
}

// TestServer_Shutdown_BeforeListenAndServe is a no-op and must not block.
func TestServer_Shutdown_BeforeListenAndServe(t *testing.T) {
	srv := newTestServer(":0", "", "", map[string]UserInfo{}, testSigner(t), defaultCompletedUploadsSize)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown before ListenAndServe returned %v; want nil", err)
	}
}

// TestServer_ListenAndServe_AfterShutdown verifies that Shutdown drains the
// current run but does not permanently poison the Server; it can be started
// again once Shutdown returns.
func TestServer_ListenAndServe_AfterShutdown(t *testing.T) {
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanRead: true, CanWrite: true},
	}
	srv, _, errc1 := startListenAndServe(t, users)
	if err := srv.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-errc1:
		if err != nil {
			t.Fatalf("first ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first ListenAndServe did not return after Shutdown")
	}

	errc2 := make(chan error, 1)
	go func() { errc2 <- srv.ListenAndServe() }()
	addr := waitForSFTPListener(t, srv, errc2)
	sshCfg := &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.Password("alicepw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial after restart: %v", err)
	}
	_ = conn.Close()

	if err := srv.Close(); err != nil {
		t.Fatalf("Close after restart: %v", err)
	}
	select {
	case err := <-errc2:
		if err != nil {
			t.Errorf("second ListenAndServe returned %v; want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second ListenAndServe did not return after Close")
	}
}

// TestServer_ListenAndServe_EmptySftpAddr verifies that ListenAndServe returns an
// error immediately when SftpAddr is empty or blank without opening any listener.
func TestServer_ListenAndServe_EmptySftpAddr(t *testing.T) {
	for _, addr := range []string{"", "   ", "\t"} {
		srv := &Server{addr: addr, sftpSigner: testSigner(t)}
		err := srv.ListenAndServe()
		if err == nil {
			t.Errorf("addr=%q: expected error, got nil", addr)
			continue
		}
		const want = "ironport: SftpAddr is required"
		if err.Error() != want {
			t.Errorf("addr=%q: got %q; want %q", addr, err.Error(), want)
		}
	}
}

// TestServer_ListenAndServe_NilSignerGeneratesHostKey verifies that
// ListenAndServe generates an ephemeral host key when sftpSigner is nil.
//
//nolint:gocognit // boots a real listener and verifies the generated host key is usable
func TestServer_ListenAndServe_NilSignerGeneratesHostKey(t *testing.T) {
	config := DefaultConfig()
	config.SftpAddr = "127.0.0.1:0"
	config.FtpPassivePortRange = ""
	srv := NewServer(config)
	if srv.sftpSigner != nil {
		t.Fatal("expected nil sftpSigner before ListenAndServe")
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.ListeningAddr(); a != nil {
			if srv.sftpSigner == nil {
				t.Fatal("sftpSigner was not generated")
			}
			if err := srv.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("ListenAndServe returned %v; want nil", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ListenAndServe did not return after Close")
			}
			return
		}
		select {
		case err := <-errCh:
			t.Fatalf("ListenAndServe returned early: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = srv.Close()
	t.Fatal("server did not start in time")
}

// TestNextAcceptBackoff verifies that the accept backoff schedule starts at
// 5ms, doubles, and caps at 1s.
func TestNextAcceptBackoff(t *testing.T) {
	if got := nextAcceptBackoff(0); got != 5*time.Millisecond {
		t.Errorf("nextAcceptBackoff(0) = %v; want 5ms", got)
	}
	if got := nextAcceptBackoff(5 * time.Millisecond); got != 10*time.Millisecond {
		t.Errorf("nextAcceptBackoff(5ms) = %v; want 10ms", got)
	}
	if got := nextAcceptBackoff(900 * time.Millisecond); got != time.Second {
		t.Errorf("nextAcceptBackoff(900ms) = %v; want 1s", got)
	}
	if got := nextAcceptBackoff(time.Second); got != time.Second {
		t.Errorf("nextAcceptBackoff(1s) = %v; want 1s", got)
	}
}

// ---- isTransientAcceptError ----

// TestIsTransientAcceptError verifies that timeout and the recognised transient
// syscall errors are classified as transient, while a plain or non-transient
// error is not.
func TestIsTransientAcceptError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "plain", err: errors.New("boom"), want: false},
		{name: "timeout", err: timeoutErr{}, want: true},
		{name: "EMFILE", err: syscall.EMFILE, want: true},
		{name: "ENFILE", err: syscall.ENFILE, want: true},
		{name: "ECONNABORTED", err: syscall.ECONNABORTED, want: true},
		{name: "EINTR", err: syscall.EINTR, want: true},
		{name: "ENOBUFS", err: syscall.ENOBUFS, want: true},
		{name: "ENOMEM", err: syscall.ENOMEM, want: true},
		{name: "EACCES", err: syscall.EACCES, want: false},
		{name: "wrapped EMFILE", err: fmt.Errorf("accept: %w", syscall.EMFILE), want: true},
		{name: "OpError timeout", err: &net.OpError{Op: "accept", Err: timeoutErr{}}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientAcceptError(tc.err); got != tc.want {
				t.Fatalf("isTransientAcceptError(%v) = %v; want %v", tc.err, got, tc.want)
			}
		})
	}
}

// ---- handleAcceptError ----

// TestHandleAcceptError_TransientResetsCounter verifies that a transient error
// resets the permanent-error counter, advances the backoff, and never asks the
// loop to stop.
func TestHandleAcceptError_TransientResetsCounter(t *testing.T) {
	s := &Server{}
	permanent := 5
	backoff, err := s.handleAcceptError("sftp", syscall.EMFILE, 0, &permanent)
	if err != nil {
		t.Fatalf("handleAcceptError returned err = %v; want nil for transient error", err)
	}
	if permanent != 0 {
		t.Fatalf("permanentErrors = %d; want 0 after transient error", permanent)
	}
	if backoff != 5*time.Millisecond {
		t.Fatalf("backoff = %v; want 5ms (first step)", backoff)
	}
}

// TestHandleAcceptError_NonTransientIncrements verifies that a non-transient
// error increments the counter and keeps the loop running while under the cap.
func TestHandleAcceptError_NonTransientIncrements(t *testing.T) {
	s := &Server{}
	permanent := 0
	backoff, err := s.handleAcceptError("ftp", errors.New("nope"), 10*time.Millisecond, &permanent)
	if err != nil {
		t.Fatalf("handleAcceptError returned err = %v; want nil while under the cap", err)
	}
	if permanent != 1 {
		t.Fatalf("permanentErrors = %d; want 1 after one non-transient error", permanent)
	}
	if backoff != 20*time.Millisecond {
		t.Fatalf("backoff = %v; want 20ms (doubled)", backoff)
	}
}

// TestHandleAcceptError_GivesUpAtCap verifies that reaching
// maxConsecutiveAcceptErrors consecutive non-transient errors makes the helper
// return a non-nil error wrapping the underlying cause, signalling the accept
// loop to stop.
func TestHandleAcceptError_GivesUpAtCap(t *testing.T) {
	s := &Server{}
	cause := errors.New("listener wedged")
	permanent := maxConsecutiveAcceptErrors - 1
	backoff, err := s.handleAcceptError("sftp", cause, time.Millisecond, &permanent)
	if err == nil {
		t.Fatalf("handleAcceptError returned nil err; want a give-up error at the cap")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("give-up error = %v; want it to wrap the underlying cause", err)
	}
	if permanent != maxConsecutiveAcceptErrors {
		t.Fatalf("permanentErrors = %d; want %d", permanent, maxConsecutiveAcceptErrors)
	}
	if backoff != 0 {
		t.Fatalf("backoff = %v; want 0 on give-up", backoff)
	}
}

// ---- closeRunListeners ----

// TestCloseRunListeners_ClearsStateForMatchingRun verifies that when the run ID
// matches the server's current serveID, the listener fields are cleared and
// serving is reset, and both listeners are closed.
func TestCloseRunListeners_ClearsStateForMatchingRun(t *testing.T) {
	ln := &errListener{}
	ftpLn := &errListener{}
	s := &Server{serveID: 7, serving: true, ln: ln, ftpLn: ftpLn}

	if err := s.closeRunListeners(7, ln, ftpLn); err != nil {
		t.Fatalf("closeRunListeners returned err = %v; want nil", err)
	}
	if s.ln != nil || s.ftpLn != nil {
		t.Fatalf("listener fields not cleared: ln=%v ftpLn=%v", s.ln, s.ftpLn)
	}
	if s.serving {
		t.Fatalf("serving = true; want false after closing the active run")
	}
	if !ln.closed || !ftpLn.closed {
		t.Fatalf("listeners not closed: sftp=%v ftp=%v", ln.closed, ftpLn.closed)
	}
}

// TestCloseRunListeners_LeavesStateForStaleRun verifies that a cleanup from a
// superseded run (its runID no longer matches serveID) still closes the
// listeners it was handed but does not disturb the current run's server state.
func TestCloseRunListeners_LeavesStateForStaleRun(t *testing.T) {
	staleLn := &errListener{}
	staleFtpLn := &errListener{}
	currentLn := &errListener{}
	s := &Server{serveID: 8, serving: true, ln: currentLn, ftpLn: currentLn}

	if err := s.closeRunListeners(7, staleLn, staleFtpLn); err != nil {
		t.Fatalf("closeRunListeners returned err = %v; want nil", err)
	}
	if s.ln != currentLn || s.ftpLn != currentLn {
		t.Fatalf("stale cleanup clobbered current run's listeners")
	}
	if !s.serving {
		t.Fatalf("serving = false; stale cleanup must not stop the current run")
	}
	if !staleLn.closed || !staleFtpLn.closed {
		t.Fatalf("stale listeners not closed: sftp=%v ftp=%v", staleLn.closed, staleFtpLn.closed)
	}
}

// TestCloseRunListeners_NilFTPListener verifies the FTP-disabled case (ftpLn is
// nil) closes only the SFTP listener without panicking.
func TestCloseRunListeners_NilFTPListener(t *testing.T) {
	ln := &errListener{}
	s := &Server{serveID: 1, serving: true, ln: ln}

	if err := s.closeRunListeners(1, ln, nil); err != nil {
		t.Fatalf("closeRunListeners returned err = %v; want nil", err)
	}
	if !ln.closed {
		t.Fatalf("sftp listener not closed")
	}
}

// TestCloseRunListeners_PropagatesCloseError verifies that a real Close error
// (not net.ErrClosed) is surfaced to the caller.
func TestCloseRunListeners_PropagatesCloseError(t *testing.T) {
	closeErr := errors.New("close failed")
	ln := &errListener{closeErr: closeErr}
	s := &Server{serveID: 1, ln: ln}

	if err := s.closeRunListeners(1, ln, nil); !errors.Is(err, closeErr) {
		t.Fatalf("closeRunListeners err = %v; want it to wrap %v", err, closeErr)
	}
}

// TestCloseRunListeners_IgnoresErrClosed verifies that a net.ErrClosed from
// Close (the listener was already closed) is treated as success.
func TestCloseRunListeners_IgnoresErrClosed(t *testing.T) {
	ln := &errListener{closeErr: net.ErrClosed}
	s := &Server{serveID: 1, ln: ln}

	if err := s.closeRunListeners(1, ln, nil); err != nil {
		t.Fatalf("closeRunListeners err = %v; want nil for net.ErrClosed", err)
	}
}
