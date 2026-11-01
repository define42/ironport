//go:build linux

package ironport

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
)

func TestFTPSDataTransportPreservesFinalBytesBeforeEOF(t *testing.T) {
	const records = "final TLS records"
	conn := &ftpsDataTransport{Conn: &ftpsDataReaderConn{
		reader: iotest.DataErrReader(strings.NewReader(records)),
	}}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != records {
		t.Fatalf("final records = %q, err = %v; want %q and no error", buf[:n], err, records)
	}
	// Deferring transport EOF gives TLS a chance to process close_notify
	// from those final records. Otherwise it must see an error distinct from
	// the EOF/ErrUnexpectedEOF values it treats as a clean record boundary.
	n, err = conn.Read(buf)
	if n != 0 || !errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.Unwrap(err) == nil {
		t.Fatalf("transport EOF = (%d, %v); want a wrapped unexpected EOF", n, err)
	}
}

type ftpsDataReaderConn struct {
	net.Conn

	reader io.Reader
}

func (c *ftpsDataReaderConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
