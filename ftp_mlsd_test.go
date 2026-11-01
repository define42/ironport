//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/ironport/internal/jailfs"
	"github.com/define42/ironport/internal/netconn"
)

func TestFTPMLSDWriteFailureCleansUp(t *testing.T) {
	for _, tt := range []struct {
		name      string
		failAfter int
	}{
		{name: "first write", failAfter: 0},
		{name: "partial listing", failAfter: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkFTPMLSDWriteFailure(t, tt.failAfter)
		})
	}
}

func checkFTPMLSDWriteFailure(t *testing.T, failAfter int) {
	t.Helper()
	f, control, data, listener := newFTPMLSDWriteFailureSession(t, failAfter)
	beforeFDs := countRetainedJailDescriptors(t, f.user.Root)
	f.cmdMLSD("/")
	// Internal paths and injected reply text in a write error must
	// never reach the control channel or turn failure into success.
	const want = "150 opening data connection\r\n426 request failed\r\n"
	if got := control.String(); got != want {
		t.Fatalf("failed MLSD replies = %q; want %q", got, want)
	}
	if data.writes != failAfter+1 || strings.Count(data.output.String(), "\r\n") != failAfter {
		t.Fatalf("MLSD continued after write failure: writes=%d output=%q", data.writes, data.output.String())
	}
	if !data.closed || !listener.closed.Load() {
		t.Fatal("failed MLSD retained its data socket or passive listener")
	}
	if got := countRetainedJailDescriptors(t, f.user.Root); got != beforeFDs {
		t.Fatalf("directory descriptors after failure = %d; before = %d", got, beforeFDs)
	}
	requireFTPMLSDSetupReleased(t, f)
	if f.handleFTPCommand("NOOP", "") || control.String() != want+"200 ok\r\n" {
		t.Fatalf("control connection unusable after MLSD failure: %q", control.String())
	}
}

func newFTPMLSDWriteFailureSession(t *testing.T, failAfter int) (*ftpSession, *bytes.Buffer, *ftpMLSDWriteFailureConn, *ftpMLSDWriteListener) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"entry-a", "entry-b", "entry-c"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fs, err := jailfs.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	server := &Server{ftpPassiveLimits: ftpPassiveLimits{maxTotal: 1}}
	release, err := server.ftpPassiveLimits.reserve("reader", "")
	if err != nil {
		t.Fatal(err)
	}
	data := &ftpMLSDWriteFailureConn{failAfter: failAfter}
	listener := &ftpMLSDWriteListener{conn: data}
	reserved := netconn.NewExpiringListener(listener, time.Minute, release)
	t.Cleanup(func() { _ = reserved.Close() })
	t.Cleanup(func() { _ = data.Close() })
	control := &bytes.Buffer{}
	f := &ftpSession{
		server: server, conn: &stubConn{}, w: bufio.NewWriter(control), fs: fs,
		username: "reader", authenticated: true, user: UserInfo{Root: root, CanRead: true},
		cwd: "/", dataProt: 'C', dataLn: reserved,
	}
	return f, control, data, listener
}

func requireFTPMLSDSetupReleased(t *testing.T, f *ftpSession) {
	t.Helper()
	if f.dataLn != nil || f.dataAddr != nil || f.dataCancel != nil {
		t.Fatal("MLSD retained data setup state")
	}
	release, err := f.server.ftpPassiveLimits.reserve(f.username, f.clientIP)
	if err != nil {
		t.Fatalf("MLSD retained the sole passive-listener permit: %v", err)
	}
	release()
}

type ftpMLSDWriteFailureConn struct {
	stubConn

	output    bytes.Buffer
	failAfter int
	writes    int
	closed    bool
}

func (c *ftpMLSDWriteFailureConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes > c.failAfter {
		return 0, errors.New("write failed: /srv/private-root\r\n226 forged completion")
	}
	return c.output.Write(p)
}

func (c *ftpMLSDWriteFailureConn) Close() error {
	c.closed = true
	return nil
}

type ftpMLSDWriteListener struct {
	stubListener

	closed atomic.Bool
}

func (l *ftpMLSDWriteListener) Close() error {
	// Closing the listening socket must not close the accepted data socket.
	l.closed.Store(true)
	return nil
}
