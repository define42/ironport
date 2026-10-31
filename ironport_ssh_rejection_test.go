//go:build linux && integration

package ironport

import (
	"bytes"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const sshRejectionTestTimeout = 10 * time.Second

// postAuthWriteGateConn pauses the first server write after arm is called. The
// password callback arms it immediately before sending the authentication
// request, so the gated write is the server's authentication-success packet.
// The bytes reach the loopback socket before the gate blocks: the client can
// finish its handshake while the server remains inside ssh.NewServerConn.
type postAuthWriteGateConn struct {
	net.Conn

	armed       atomic.Bool
	blocked     chan struct{}
	release     chan struct{}
	blockedOnce sync.Once
	releaseOnce sync.Once
}

func newPostAuthWriteGateConn(conn net.Conn) *postAuthWriteGateConn {
	return &postAuthWriteGateConn{
		Conn:    conn,
		blocked: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (c *postAuthWriteGateConn) arm() {
	c.armed.Store(true)
}

func (c *postAuthWriteGateConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if err == nil && c.armed.CompareAndSwap(true, false) {
		c.blockedOnce.Do(func() { close(c.blocked) })
		<-c.release
	}
	return n, err
}

func (c *postAuthWriteGateConn) releaseWrite() {
	c.releaseOnce.Do(func() { close(c.release) })
}

func (c *postAuthWriteGateConn) Close() error {
	c.releaseWrite()
	return c.Conn.Close()
}

type sshRevisionRejectionHarness struct {
	t              *testing.T
	server         *Server
	serverConn     *postAuthWriteGateConn
	clientConn     net.Conn
	client         ssh.Conn
	handlerDone    <-chan struct{}
	baselineMuxes  int
	commitMuLocked bool
}

func newSSHRevisionRejectionHarness(t *testing.T) *sshRevisionRejectionHarness {
	t.Helper()
	baselineMuxes := countSSHMuxLoops()

	root := t.TempDir()
	config := newTestConfig("", "", "", map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanRead: true},
	}, testSigner(t), defaultCompletedUploadsSize)
	server := NewServer(config)

	serverRaw, clientRaw := tcpConnPair(t)
	serverConn := newPostAuthWriteGateConn(serverRaw)
	if !server.trackConn(serverConn) {
		t.Fatal("trackConn rejected test connection")
	}
	handlerDone := make(chan struct{})
	uploads := server.completedUploadsChan()
	authEvents := server.authEventsChan()
	tempExts := server.configuredTempExtensions()
	idleTimeout := server.effectiveIdleTimeout()
	allowChown := server.sftpChownAllowed()
	go func() {
		defer close(handlerDone)
		defer server.connWG.Done()
		defer server.untrackConn(serverConn)
		server.handleConn(serverConn, uploads, authEvents, tempExts, idleTimeout, allowChown)
	}()
	// This cleanup is registered before the handshake can fail. In particular,
	// releasing the write gate prevents an early test failure from stranding the
	// server inside the authentication-success write.
	t.Cleanup(func() {
		serverConn.releaseWrite()
		_ = clientRaw.Close()
		_ = serverConn.Close()
	})

	clientResult := make(chan sshClientConnResult, 1)
	go func() {
		conn, _, _, err := ssh.NewClientConn(clientRaw, "loopback", &ssh.ClientConfig{
			User: "alice",
			Auth: []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
				serverConn.arm()
				return "pw", nil
			})},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test connection with an ephemeral key
		})
		clientResult <- sshClientConnResult{conn: conn, err: err}
	}()

	var result sshClientConnResult
	select {
	case result = <-clientResult:
	case <-time.After(sshRejectionTestTimeout):
		t.Fatal("client SSH handshake did not finish at the post-authentication gate")
	}
	if result.err != nil {
		t.Fatalf("client SSH handshake: %v", result.err)
	}
	select {
	case <-serverConn.blocked:
	case <-time.After(sshRejectionTestTimeout):
		t.Fatal("server authentication-success write did not reach the gate")
	}

	h := &sshRevisionRejectionHarness{
		t:             t,
		server:        server,
		serverConn:    serverConn,
		clientConn:    clientRaw,
		client:        result.conn,
		handlerDone:   handlerDone,
		baselineMuxes: baselineMuxes,
	}
	t.Cleanup(func() {
		if h.commitMuLocked {
			h.server.mu.Unlock()
			h.commitMuLocked = false
		}
		h.serverConn.releaseWrite()
		_ = h.client.Close()
		_ = h.clientConn.Close()
		_ = h.serverConn.Close()
	})

	// Invalidate the snapshot captured by the successful password callback.
	// The connection is not committed yet, so RemoveUser deliberately leaves it
	// open for takeCommittedSSHJail to reject after NewServerConn returns.
	server.RemoveUser("alice")

	// Hold commitConnUser after NewServerConn returns. This gives the SSH mux a
	// deterministic window to receive traffic while final revision validation
	// is pending.
	server.mu.Lock()
	h.commitMuLocked = true
	serverConn.releaseWrite()
	return h
}

func (h *sshRevisionRejectionHarness) releaseCommit() {
	h.t.Helper()
	if !h.commitMuLocked {
		h.t.Fatal("SSH revision commit gate already released")
	}
	h.server.mu.Unlock()
	h.commitMuLocked = false
}

func (h *sshRevisionRejectionHarness) finish() {
	h.t.Helper()
	h.releaseCommit()
	select {
	case <-h.handlerDone:
	case <-time.After(sshRejectionTestTimeout):
		h.t.Fatal("post-handshake revision rejection did not finish SSH teardown")
	}
	_ = h.client.Close()
	waitForSSHMuxCountAtMost(h.t, h.baselineMuxes)
	requireAuthEvent(h.t, h.server.AuthEvents(), AuthEventLoginFailed, "alice", CompletedUploadProtocolSFTP)
	requireNoAuthEvent(h.t, h.server.AuthEvents())
}

func TestSSHRevisionRejectionDrainsGlobalRequests(t *testing.T) {
	h := newSSHRevisionRejectionHarness(t)

	// x/crypto/ssh's incoming request queue has 16 entries. The reply-required
	// barrier can complete only if handleConn started consuming the 40 earlier
	// requests before blocking in final revision validation.
	for range 40 {
		if _, _, err := h.client.SendRequest("ironport-rejection-test", false, nil); err != nil {
			t.Fatalf("send queued global request: %v", err)
		}
	}
	barrierDone := make(chan error, 1)
	go func() {
		_, _, err := h.client.SendRequest("ironport-rejection-barrier", true, nil)
		barrierDone <- err
	}()
	select {
	case err := <-barrierDone:
		if err != nil {
			t.Fatalf("global request drain barrier: %v", err)
		}
	case <-time.After(sshRejectionTestTimeout):
		t.Fatal("global requests were not drained during final revision validation")
	}

	h.finish()
}

func TestSSHRevisionRejectionDrainsChannelOpens(t *testing.T) {
	h := newSSHRevisionRejectionHarness(t)

	// Fill the 16-entry incoming-channel queue and wait until the server mux is
	// blocked attempting to enqueue another open. Closing only the raw socket
	// cannot release this send; handleConn must consume and reject the opens.
	const channelOpens = 40
	channelErrors := make(chan error, channelOpens)
	var channelWG sync.WaitGroup
	channelWG.Add(channelOpens)
	for range channelOpens {
		go func() {
			defer channelWG.Done()
			ch, _, err := h.client.OpenChannel("session", nil)
			if ch != nil {
				_ = ch.Close()
			}
			channelErrors <- err
		}()
	}
	waitForSSHMuxFrame(t, "golang.org/x/crypto/ssh.(*mux).handleChannelOpen")

	h.finish()

	channelDone := make(chan struct{})
	go func() {
		channelWG.Wait()
		close(channelDone)
	}()
	select {
	case <-channelDone:
	case <-time.After(sshRejectionTestTimeout):
		t.Fatal("queued client channel opens did not unblock during rejection")
	}
	close(channelErrors)
	for err := range channelErrors {
		if err == nil {
			t.Error("channel open succeeded after authentication revision was invalidated")
		}
	}
}

type sshClientConnResult struct {
	conn ssh.Conn
	err  error
}

func tcpConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SSH test connection: %v", err)
	}
	defer func() { _ = listener.Close() }()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- acceptResult{conn: conn, err: err}
	}()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), sshRejectionTestTimeout)
	if err != nil {
		t.Fatalf("dial SSH test connection: %v", err)
	}
	result := <-accepted
	if result.err != nil {
		_ = client.Close()
		t.Fatalf("accept SSH test connection: %v", result.err)
	}
	return result.conn, client
}

func sshGoroutineStacks() []byte {
	for size := 64 << 10; ; size *= 2 {
		stacks := make([]byte, size)
		n := runtime.Stack(stacks, true)
		if n < len(stacks) || size >= 8<<20 {
			return stacks[:n]
		}
	}
}

func countSSHMuxLoops() int {
	return bytes.Count(sshGoroutineStacks(), []byte("golang.org/x/crypto/ssh.(*mux).loop"))
}

func waitForSSHMuxFrame(t *testing.T, frame string) {
	t.Helper()
	deadline := time.Now().Add(sshRejectionTestTimeout)
	for {
		stacks := sshGoroutineStacks()
		if bytes.Contains(stacks, []byte(frame)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("SSH mux did not block in %s\n%s", frame, sshMuxStackDump(stacks))
		}
		runtime.Gosched()
	}
}

func waitForSSHMuxCountAtMost(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(sshRejectionTestTimeout)
	for {
		stacks := sshGoroutineStacks()
		if got := bytes.Count(stacks, []byte("golang.org/x/crypto/ssh.(*mux).loop")); got <= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("SSH mux goroutines did not exit; want at most %d\n%s", want, sshMuxStackDump(stacks))
		}
		runtime.Gosched()
	}
}

func sshMuxStackDump(stacks []byte) []byte {
	var dump []byte
	for _, stack := range bytes.Split(stacks, []byte("\n\n")) {
		if bytes.Contains(stack, []byte("golang.org/x/crypto/ssh.(*mux)")) {
			dump = append(dump, stack...)
			dump = append(dump, '\n', '\n')
		}
	}
	return dump
}
