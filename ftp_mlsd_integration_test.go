//go:build linux && integration

package ironport

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/define42/ironport/internal/jailfs"
)

func TestFTPMLSDTCPInterruptionAndRecovery(t *testing.T) {
	for _, interruption := range []string{"ABOR", "peer reset"} {
		t.Run(interruption, func(t *testing.T) {
			client, data, gated := newFTPMLSDTCPFixture(t)
			client.command(150, "MLSD /")
			select {
			case <-gated.writing:
			case <-time.After(5 * time.Second):
				t.Fatal("MLSD did not reach its data write")
			}
			client.command(503, "NOOP")
			if interruption == "ABOR" {
				abortFTPMLSDPeer(t, client, data)
			} else {
				resetFTPMLSDPeer(t, data, gated)
				client.read(426)
			}
			// This response also detects a stray transfer-success 226 and waits
			// until the interrupted handler has completed its deferred cleanup.
			client.command(200, "NOOP")
			select {
			case <-gated.closed:
			default:
				t.Fatal("interrupted listing retained its data connection")
			}
			checkFTPMLSDTCPRecovery(t, client)
		})
	}
}

// Gate the first listing write so interruption does not depend on the TCP
// send buffer filling, a directory's size, or the client's scheduling speed.
type ftpMLSDGatedTCPConn struct {
	net.Conn

	writing chan struct{}
	release chan struct{}
	closed  chan struct{}
	wrote   sync.Once
	close   sync.Once
}

func (c *ftpMLSDGatedTCPConn) Write(p []byte) (int, error) {
	c.wrote.Do(func() { close(c.writing) })
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-c.release:
		return c.Conn.Write(p)
	}
}

func (c *ftpMLSDGatedTCPConn) Close() error {
	c.close.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func newFTPMLSDTCPFixture(t *testing.T) (*ftpTestClient, net.Conn, *ftpMLSDGatedTCPConn) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry.txt"), []byte("entry"), 0o600); err != nil {
		t.Fatal(err)
	}
	jfs, err := jailfs.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	control, peer := tcpConnPair(t)
	t.Cleanup(func() { _ = control.Close() })
	t.Cleanup(func() { _ = peer.Close() })
	data, dataPeer := tcpConnPair(t)
	t.Cleanup(func() { _ = data.Close() })
	t.Cleanup(func() { _ = dataPeer.Close() })
	for _, conn := range []net.Conn{control, peer, data, dataPeer} {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	gated := &ftpMLSDGatedTCPConn{
		Conn: data, writing: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}),
	}
	f := &ftpSession{
		server: NewServer(&Config{}), conn: control, rawConn: control,
		r: bufio.NewReader(control), w: bufio.NewWriter(control), fs: jfs,
		user: UserInfo{CanRead: true}, authenticated: true, cwd: "/", clientIP: "127.0.0.1",
		dataLn: newFTPRetryListener(gated), dataProt: 'C',
	}
	startFTPMLSDTCPCommands(t, f)
	client := &ftpTestClient{t: t, conn: peer, tp: textproto.NewConn(peer)}
	return client, dataPeer, gated
}

func startFTPMLSDTCPCommands(t *testing.T, f *ftpSession) {
	t.Helper()
	f.startReader()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer f.closeControlConn()
		defer f.cancelDataOperations()
		for msg := range f.ctlMsg {
			if msg.err != nil {
				return
			}
			cmd, arg := parseFTPCommand(strings.TrimRight(msg.line, "\r\n"))
			if f.handleFTPCommand(cmd, arg) {
				return
			}
		}
	}()
	t.Cleanup(func() {
		f.cancelDataOperations()
		_ = f.conn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("MLSD control handler did not stop")
		}
	})
}

func abortFTPMLSDPeer(t *testing.T, client *ftpTestClient, peer net.Conn) {
	t.Helper()
	if reply := client.command(426, "ABOR"); reply != "transfer aborted" {
		t.Fatalf("MLSD abort reply = %q; want transfer aborted", reply)
	}
	// The 226 acknowledges ABOR; it must not claim the listing completed.
	if reply := client.read(226); reply != "abort successful" {
		t.Fatalf("ABOR acknowledgement = %q; want abort successful", reply)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("aborted data connection read = %v; want EOF", err)
	}
}

func resetFTPMLSDPeer(t *testing.T, peer net.Conn, gated *ftpMLSDGatedTCPConn) {
	t.Helper()
	if err := peer.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	// Observe the kernel reset before allowing the listing's real TCP Write.
	// Otherwise a tiny listing can be buffered before the reset arrives.
	if _, err := gated.Conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("data reset read = %v; want ECONNRESET", err)
	}
	close(gated.release)
}

func checkFTPMLSDTCPRecovery(t *testing.T, client *ftpTestClient) {
	t.Helper()
	data, _ := client.passiveConn()
	defer func() { _ = data.Close() }()
	if err := data.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client.command(150, "MLSD /")
	listing, err := io.ReadAll(data)
	if err != nil {
		t.Fatalf("read recovered listing: %v", err)
	}
	client.read(226)
	if !strings.HasPrefix(string(listing), "type=file;") || !strings.HasSuffix(string(listing), "; entry.txt\r\n") ||
		strings.Count(string(listing), "\r\n") != 1 {
		t.Fatalf("recovered listing = %q; want one complete entry.txt fact line", listing)
	}
	client.command(200, "NOOP")
}
