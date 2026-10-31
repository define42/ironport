//go:build linux && integration

package ironport

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Queue the whole input before dispatch so the reader reaching EOF cannot
// race the test: both rename commands must remain executable afterward.
func TestFTPControlReadErrorPreservesQueuedCommands(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "EOF", err: io.EOF},
		{name: "read error", err: io.ErrUnexpectedEOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			fs, err := openJailFS(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fs.Close() }()
			var replies bytes.Buffer
			f := &ftpSession{
				fs: fs, authenticated: true, user: UserInfo{CanWrite: true}, cwd: "/",
				r: bufio.NewReader(io.MultiReader(
					strings.NewReader("RNFR source.txt\r\nRNTO target.txt\r\n"),
					ftpTerminalErrorReader{err: tt.err},
				)),
				w: bufio.NewWriter(&replies), ctlMsg: make(chan ftpCtlMsg, 3),
				readerStop: make(chan struct{}), readerDone: make(chan struct{}),
			}
			f.readControlLines()
			commands := 0
			for msg := range f.ctlMsg {
				if msg.err != nil {
					if commands != 2 || !errors.Is(msg.err, tt.err) {
						t.Fatalf("terminal message after %d commands: %v", commands, msg.err)
					}
					continue
				}
				cmd, arg := parseFTPCommand(strings.TrimRight(msg.line, "\r\n"))
				if f.handleFTPCommand(cmd, arg) {
					t.Fatalf("reader error discarded queued %s", cmd)
				}
				commands++
			}
			got, err := os.ReadFile(filepath.Join(root, "target.txt"))
			if err != nil || string(got) != "keep" {
				t.Fatalf("queued rename did not complete: %q, %v", got, err)
			}
			if !strings.HasPrefix(replies.String(), "350 ") || !strings.Contains(replies.String(), "\r\n250 ") {
				t.Fatalf("rename replies out of order: %q", replies.String())
			}
		})
	}
}

type ftpTerminalErrorReader struct{ err error }

func (r ftpTerminalErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestFTPControlEOFBeforeQueuedDataSetupDoesNotBlock(t *testing.T) {
	ln := &ftpLimitsListener{closed: make(chan struct{})}
	f := &ftpSession{
		server: &Server{ftpDataAcceptTimeout: -1}, dataLn: ln,
		r: bufio.NewReader(strings.NewReader("")), ctlMsg: make(chan ftpCtlMsg, 1),
		readerStop: make(chan struct{}), readerDone: make(chan struct{}),
	}
	defer f.cancelDataOperations()
	// The reader can finish before the main loop starts a queued transfer.
	// The transfer must still terminate promptly with the timeout disabled.
	f.readControlLines()
	done := make(chan error, 1)
	go func() {
		dc, err := f.acceptDataConn()
		if dc != nil {
			_ = dc.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("data setup after EOF = %v; want closed", err)
		}
	case <-time.After(time.Second):
		f.cancelDataOperations()
		<-done
		t.Fatal("queued data setup remained blocked after control EOF")
	}
}

func TestFTPControlHalfCloseCompletesQueuedRename(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"u": {Password: "p", Root: root, CanWrite: true},
	}, "")
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	c.login("u", "p")
	if err := c.conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c.conn, "RNFR source.txt\r\nRNTO target.txt\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := c.conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.read(350)
	c.read(250)
	if _, err := c.tp.ReadLine(); !errors.Is(err, io.EOF) {
		t.Fatalf("terminal control read = %v; want EOF after replies", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "target.txt"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("half-close lost queued rename: %q, %v", got, err)
	}
}

func TestFTPControlHalfCloseAbortsEstablishedTransfer(t *testing.T) {
	root := t.TempDir()
	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"u": {Password: "p", Root: root, CanWrite: true},
	}, "")
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	c.login("u", "p")
	dc, _ := c.passiveConn()
	defer func() { _ = dc.Close() }()
	c.command(150, "STOR pending.txt")
	if _, err := dc.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(3 * time.Second); ; {
		st, err := os.Stat(filepath.Join(root, "pending.txt"))
		if err == nil && st.Size() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upload did not reach active transfer state")
		}
		time.Sleep(time.Millisecond)
	}
	_ = c.conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := c.conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.read(426)
	c.read(226)
	_ = dc.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := dc.Read(make([]byte, 1)); err == nil {
		t.Fatal("data connection remained readable after control EOF")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("active data transfer remained blocked after control EOF")
	}
}
