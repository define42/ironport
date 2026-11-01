//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type ftpStatStreamConn struct {
	stubConn

	output    bytes.Buffer
	deadlines []time.Time
	onWrite   func()
	writeErr  error
	closed    bool
}

func (c *ftpStatStreamConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

func (c *ftpStatStreamConn) Write(p []byte) (int, error) {
	if c.onWrite != nil {
		c.onWrite()
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.output.Write(p)
}

func (c *ftpStatStreamConn) Close() error {
	c.closed = true
	return nil
}

func newFTPStatStreamSession() (*ftpSession, *ftpStatStreamConn) {
	conn := &ftpStatStreamConn{}
	return &ftpSession{conn: conn, w: bufio.NewWriter(conn)}, conn
}

func ftpStatStreamInfo(t *testing.T) os.FileInfo {
	t.Helper()
	info, err := (fstest.MapFS{"entry\r\n213 forged": &fstest.MapFile{Mode: 0o600}}).Stat("entry\r\n213 forged")
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestFTPStatStreamsBeforeEnumerationCompletes(t *testing.T) {
	f, conn := newFTPStatStreamSession()
	info := ftpStatStreamInfo(t)
	const entryCount = 8193
	produced, firstWrite := 0, 0
	conn.onWrite = func() {
		if firstWrite == 0 {
			firstWrite = produced
		}
	}
	f.replyStatDirectory("/large", func(_ string, yield func(os.FileInfo) error) error {
		for range entryCount {
			produced++
			if err := yield(info); err != nil {
				return err
			}
		}
		return nil
	})
	if firstWrite == 0 || firstWrite > 128 {
		t.Fatalf("first output after %d entries; listing was not streamed in bounded space", firstWrite)
	}
	output := conn.output.String()
	if got := strings.Count(output, "entry??213 forged\r\n"); got != entryCount {
		t.Fatalf("listing entries = %d; want %d", got, entryCount)
	}
	if !strings.HasPrefix(output, "213-Status of \"/large\":\r\n") || !strings.HasSuffix(output, "213 End of status\r\n") {
		t.Fatalf("invalid listing framing: prefix=%q suffix=%q", output[:40], output[len(output)-40:])
	}
	assertFTPStatReplyFinished(t, f, conn)
}

func assertFTPStatReplyFinished(t *testing.T, f *ftpSession, conn *ftpStatStreamConn) {
	t.Helper()
	if conn.closed || f.cancelled {
		t.Fatal("successful listing closed the session")
	}
	if len(conn.deadlines) != 2 || conn.deadlines[0].IsZero() || !conn.deadlines[1].IsZero() {
		t.Fatalf("listing deadlines = %v; want one deadline around the entire response", conn.deadlines)
	}
}

func TestFTPStatEmptyDirectory(t *testing.T) {
	f, conn := newFTPStatStreamSession()
	f.replyStatDirectory("/empty", func(string, func(os.FileInfo) error) error { return nil })
	if got, want := conn.output.String(), "213-Status of \"/empty\":\r\n213 End of status\r\n"; got != want {
		t.Fatalf("empty listing = %q; want %q", got, want)
	}
	assertFTPStatReplyFinished(t, f, conn)
}

func TestFTPStatInitialListingFailureKeepsSession(t *testing.T) {
	f, conn := newFTPStatStreamSession()
	f.replyStatDirectory("/denied", func(string, func(os.FileInfo) error) error { return os.ErrPermission })
	if got := conn.output.String(); got != "550 permission denied\r\n" {
		t.Fatalf("initial listing failure = %q; want standalone 550", got)
	}
	if conn.closed || f.cancelled {
		t.Fatal("initial listing error closed the session")
	}
	if err := f.reply(200, "ok"); err != nil {
		t.Fatalf("session unusable after listing error: %v", err)
	}
}

func TestFTPStatMidstreamListingFailureClosesSession(t *testing.T) {
	f, conn := newFTPStatStreamSession()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.dataCancel = cancel
	info := ftpStatStreamInfo(t)
	failure := errors.New("private filesystem error")
	f.replyStatDirectory("/partial", func(_ string, yield func(os.FileInfo) error) error {
		for range 100 {
			if err := yield(info); err != nil {
				return err
			}
		}
		return failure
	})
	if conn.output.Len() == 0 {
		t.Fatal("fixture did not send a partial listing")
	}
	assertFTPStatFailedStream(ctx, t, f, conn)
}

func TestFTPStatWriteFailureStopsEnumeration(t *testing.T) {
	f, conn := newFTPStatStreamSession()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.dataCancel = cancel
	conn.writeErr = io.ErrClosedPipe
	info := ftpStatStreamInfo(t)
	produced := 0
	f.replyStatDirectory("/large", func(_ string, yield func(os.FileInfo) error) error {
		for range 8193 {
			produced++
			if err := yield(info); err != nil {
				return err
			}
		}
		return nil
	})
	if produced > 128 {
		t.Fatalf("failed control write consumed %d entries instead of stopping enumeration", produced)
	}
	assertFTPStatFailedStream(ctx, t, f, conn)
}

func assertFTPStatFailedStream(ctx context.Context, t *testing.T, f *ftpSession, conn *ftpStatStreamConn) {
	t.Helper()
	if !conn.closed || ctx.Err() != context.Canceled || !f.handleFTPCommand("DELE", "queued") {
		t.Fatal("failed listing left the session, data operations, or queued commands active")
	}
	output := conn.output.String()
	for _, forbidden := range []string{"213 End", "550 ", "private filesystem error"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("partial listing contains %q", forbidden)
		}
	}
}
