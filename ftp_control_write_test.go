//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type ftpControlRecordingConn struct {
	stubConn

	deadlines []time.Time
	output    bytes.Buffer
	setErr    error
	clearErr  error
	closed    bool
}

func (c *ftpControlRecordingConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	if deadline.IsZero() {
		return c.clearErr
	}
	return c.setErr
}

func (c *ftpControlRecordingConn) Write(p []byte) (int, error) {
	if len(c.deadlines) == 0 || c.deadlines[len(c.deadlines)-1].IsZero() {
		return 0, errors.New("control write started without a deadline")
	}
	return c.output.Write(p)
}

func (c *ftpControlRecordingConn) Close() error {
	c.closed = true
	return nil
}

func TestFTPControlWriteDeadlineCoversCompleteReply(t *testing.T) {
	for _, multiline := range []bool{false, true} {
		name := "single"
		if multiline {
			name = "multiline"
		}
		t.Run(name, func(t *testing.T) {
			checkFTPCompleteControlReply(t, multiline)
		})
	}
}

func checkFTPCompleteControlReply(t *testing.T, multiline bool) {
	t.Helper()
	conn := &ftpControlRecordingConn{}
	f := &ftpSession{conn: conn, w: bufio.NewWriter(conn)}
	before := time.Now()
	// Larger than bufio's buffer: the first write can occur before Flush.
	payload := strings.Repeat("x", 8192)
	for range 2 {
		if err := sendFTPControlTestReply(f, payload, multiline); err != nil {
			t.Fatal(err)
		}
	}
	if len(conn.deadlines) != 4 {
		t.Fatalf("deadline calls = %d; want arm and clear for each complete reply", len(conn.deadlines))
	}
	for i := 0; i < len(conn.deadlines); i += 2 {
		assertFTPControlDeadline(t, conn.deadlines[i], before, time.Now())
		if !conn.deadlines[i+1].IsZero() {
			t.Fatal("completed reply left a deadline on later TLS protocol writes")
		}
	}
	want := "200 " + payload + "\r\n"
	if multiline {
		want = "211-status\r\n " + payload + "\r\n211 end\r\n"
	}
	if got := conn.output.String(); got != want+want || conn.closed {
		t.Fatalf("successful reply changed or connection closed: bytes=%d closed=%t", len(got), conn.closed)
	}
}

func sendFTPControlTestReply(f *ftpSession, payload string, multiline bool) error {
	if multiline {
		return f.multilineReply(211, "status", []string{payload}, "end")
	}
	return f.reply(200, payload)
}

func assertFTPControlDeadline(t *testing.T, deadline, before, after time.Time) {
	t.Helper()
	if deadline.Before(before.Add(5*time.Minute)) || deadline.After(after.Add(5*time.Minute)) {
		t.Fatalf("control deadline %v is not five minutes after reply start", deadline)
	}
}

type ftpShortControlDeadlineConn struct {
	net.Conn

	requested chan time.Time
}

func (c *ftpShortControlDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	c.requested <- deadline
	// Exercise the real blocked-write timeout without a five-minute test.
	return c.Conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
}

func TestFTPControlWriteDeadlineClosesStalledSession(t *testing.T) {
	for _, multiline := range []bool{false, true} {
		name := "single"
		if multiline {
			name = "multiline"
		}
		t.Run(name, func(t *testing.T) {
			checkFTPStalledControlReply(t, multiline)
		})
	}
}

func checkFTPStalledControlReply(t *testing.T, multiline bool) {
	t.Helper()
	server, peer := net.Pipe()
	conn := &ftpShortControlDeadlineConn{Conn: server, requested: make(chan time.Time, 1)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &ftpSession{conn: conn, w: bufio.NewWriter(conn), dataCancel: cancel}
	done := make(chan error, 1)
	finished := make(chan struct{})
	t.Cleanup(func() {
		_ = server.Close()
		_ = peer.Close()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("control writer did not exit after closing transport")
		}
	})
	before := time.Now()
	go func() {
		defer close(finished)
		done <- sendFTPControlTestReply(f, strings.Repeat("x", 8192), multiline)
	}()
	select {
	case err := <-done:
		if netErr, ok := errors.AsType[net.Error](err); !ok || !netErr.Timeout() {
			t.Fatalf("blocked control write = %v; want timeout", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled control write ignored its deadline")
	}
	assertFTPControlDeadline(t, <-conn.requested, before, time.Now())
	if ctx.Err() != context.Canceled || !f.handleFTPCommand("DELE", "queued.txt") {
		t.Fatal("failed reply left data operations or queued commands active")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("control connection after timeout = %v; want EOF", err)
	}
}

func TestFTPControlWriteDeadlineFailureStopsBeforeWrite(t *testing.T) {
	failure := errors.New("deadline unavailable")
	conn := &ftpControlRecordingConn{setErr: failure}
	f := &ftpSession{conn: conn, w: bufio.NewWriter(conn)}
	if err := f.reply(200, "ok"); !errors.Is(err, failure) {
		t.Fatalf("reply = %v; want deadline error", err)
	}
	if conn.output.Len() != 0 || !conn.closed || !f.cancelled {
		t.Fatal("deadline failure wrote an unbounded reply or left session active")
	}
}

func TestFTPControlWriteDeadlineClearFailureClosesSession(t *testing.T) {
	failure := errors.New("cannot clear deadline")
	conn := &ftpControlRecordingConn{clearErr: failure}
	f := &ftpSession{conn: conn, w: bufio.NewWriter(conn)}
	if err := f.reply(200, "ok"); !errors.Is(err, failure) {
		t.Fatalf("reply = %v; want deadline clear error", err)
	}
	if conn.output.String() != "200 ok\r\n" || !conn.closed || !f.cancelled {
		t.Fatal("deadline clear failure left the session active or changed the reply")
	}
}
