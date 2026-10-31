package ironport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestFTPServer_IdleTimeoutSends421 verifies that an idle FTP control
// connection receives an explicit 421 reply before being dropped, rather
// than seeing an unexplained hang-up.
func TestFTPServer_IdleTimeoutSends421(t *testing.T) {
	root := t.TempDir()
	config := newTestFTPConfig(t, map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}, "", false)
	config.IdleTimeout = 250 * time.Millisecond
	_, addr, stop := startTestFTPServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")

	// Send nothing further; the idle timer must fire and produce a 421.
	client.read(421)
}

// TestFTPServer_ControlLineTooLong verifies that an oversized FTP control
// line is rejected with a 500 reply and the connection is closed, so that a
// malicious client cannot grow per-connection memory without bound.
func TestFTPServer_ControlLineTooLong(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Drain the 220 greeting.
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read greeting: %v", err)
	}

	// Send a single line larger than ftpMaxControlLineLen.
	huge := make([]byte, ftpMaxControlLineLen+128)
	for i := range huge {
		huge[i] = 'A'
	}
	huge[len(huge)-2] = '\r'
	huge[len(huge)-1] = '\n'
	if _, err := conn.Write(huge); err != nil {
		t.Fatalf("write: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if !strings.HasPrefix(reply, "500 ") {
		t.Fatalf("expected 500 reply, got %q", reply)
	}
}

// TestFTPServer_ErrorMessagesSanitized verifies that error replies sent over
// the FTP control channel do not leak server-side filesystem paths.
func TestFTPServer_ErrorMessagesSanitized(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	c := dialFTP(t, addr)
	c.login("alice", "alicepw")
	msg := c.command(550, "SIZE /does-not-exist.txt")
	if strings.Contains(msg, root) {
		t.Errorf("error reply leaked server path %q: %q", root, msg)
	}
	if strings.Contains(strings.ToLower(msg), "no such") == false &&
		strings.Contains(strings.ToLower(msg), "request failed") == false {
		t.Errorf("unexpected error reply: %q", msg)
	}
}

// TestReadFTPControlLine_Normal verifies a normal CRLF-terminated line is
// returned including the trailing '\n'.
func TestReadFTPControlLine_Normal(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("USER alice\r\nPASS pw\r\n"))
	got, err := readFTPControlLine(r, ftpMaxControlLineLen)
	if err != nil {
		t.Fatalf("readFTPControlLine: %v", err)
	}
	if got != "USER alice\r\n" {
		t.Errorf("got %q; want %q", got, "USER alice\r\n")
	}
}

// TestReadFTPControlLine_TooLong verifies an oversized line returns
// errFTPLineTooLong after discarding the remainder of the line.
func TestReadFTPControlLine_TooLong(t *testing.T) {
	long := strings.Repeat("A", ftpMaxControlLineLen+50) + "\r\nNEXT\r\n"
	r := bufio.NewReader(strings.NewReader(long))
	if _, err := readFTPControlLine(r, ftpMaxControlLineLen); !errors.Is(err, errFTPLineTooLong) {
		t.Fatalf("err = %v; want errFTPLineTooLong", err)
	}
	// The reader should now be positioned at the start of the next line.
	next, err := readFTPControlLine(r, ftpMaxControlLineLen)
	if err != nil {
		t.Fatalf("readFTPControlLine (second): %v", err)
	}
	if next != "NEXT\r\n" {
		t.Errorf("next line = %q; want %q", next, "NEXT\r\n")
	}
}

// TestFTPErrMsg verifies that ftpErrMsg returns generic, path-free messages
// for the well-known error categories.
func TestFTPErrMsg(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "ok"},
		{os.ErrNotExist, "no such file or directory"},
		{os.ErrPermission, "permission denied"},
		{os.ErrExist, "file exists"},
		{syscall.ENOTEMPTY, "directory not empty"},
		{syscall.EISDIR, "is a directory"},
		{syscall.ENOTDIR, "not a directory"},
		{errFTPLineTooLong, "command line too long"},
		{errors.New("something with /etc/passwd in it"), "request failed"},
	}
	for _, tc := range cases {
		if got := ftpErrMsg(tc.err); got != tc.want {
			t.Errorf("ftpErrMsg(%v) = %q; want %q", tc.err, got, tc.want)
		}
	}
}

// FuzzReadFTPControlLine exercises the control-line reader with arbitrary
// byte streams to confirm it never panics and that the line cap is honored
// regardless of how the input is framed.
func FuzzReadFTPControlLine(f *testing.F) {
	f.Add([]byte("USER alice\r\n"))
	f.Add([]byte("\r\n"))
	f.Add([]byte("\n"))
	f.Add([]byte(""))
	f.Add([]byte("partial without terminator"))
	f.Add([]byte("\x00\x01\x02\n"))
	f.Add(append(bytes.Repeat([]byte("A"), ftpMaxControlLineLen+10), '\n'))
	f.Add([]byte("USER a\r\nPASS b\r\nNOOP\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		for range 16 {
			line, err := readFTPControlLine(r, ftpMaxControlLineLen)
			if err != nil {
				return
			}
			if len(line) > ftpMaxControlLineLen {
				t.Fatalf("readFTPControlLine returned line of length %d > cap %d", len(line), ftpMaxControlLineLen)
			}
		}
	})
}

// FuzzParseFTPCommand verifies that parseFTPCommand never panics on
// arbitrary input and always preserves its documented invariants: the
// returned command is uppercased and never carries leading whitespace.
func FuzzParseFTPCommand(f *testing.F) {
	f.Add("USER alice")
	f.Add("noop")
	f.Add("   STOR   /path with spaces  ")
	f.Add("")
	f.Add("\t\t\tcmd\targ")
	f.Add("PASS \x00secret")
	f.Add("\r\n")
	f.Add(" \t ")

	f.Fuzz(func(t *testing.T, line string) {
		cmd, _ := parseFTPCommand(line)
		if cmd != strings.ToUpper(cmd) {
			t.Fatalf("parseFTPCommand(%q) cmd=%q not uppercased", line, cmd)
		}
		if strings.HasPrefix(cmd, " ") || strings.HasPrefix(cmd, "\t") {
			t.Fatalf("parseFTPCommand(%q) cmd=%q has leading whitespace", line, cmd)
		}
	})
}

// TestFTPServer_PipelinedCommands writes five commands in a single Write
// before reading any reply and verifies the server processes them in order
// without losing or merging any of them. Pipelining is not allowed by RFC
// 959 but is harmless when commands are framed correctly, so the server
// should still answer each one.
//
//nolint:gocognit // pipelined-command race needs the full I/O sequence in one function
func TestFTPServer_PipelinedCommands(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	readCode := func(want int) {
		t.Helper()
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(line) >= 4 && line[3] == '-' {
			code := line[:3]
			for {
				next, err := br.ReadString('\n')
				if err != nil {
					t.Fatalf("read continuation: %v", err)
				}
				if strings.HasPrefix(next, code+" ") {
					break
				}
			}
		}
		if !strings.HasPrefix(line, fmt.Sprintf("%d ", want)) && !strings.HasPrefix(line, fmt.Sprintf("%d-", want)) {
			t.Fatalf("got %q; want reply with code %d", line, want)
		}
	}

	readCode(220)

	if _, err := conn.Write([]byte("USER u\r\nPASS p\r\nNOOP\r\nSYST\r\nQUIT\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	readCode(331)
	readCode(230)
	readCode(200)
	readCode(215)
	readCode(221)
}

// TestFTPServer_BareCRDoesNotSmuggleCommands verifies that a bare CR in the
// middle of a control line is not treated as a line terminator: it becomes
// part of the command token after the trailing CRLF is trimmed, the
// resulting token matches no known command, and the session stays alive.
// If CR were ever treated as a terminator, an attacker could smuggle a
// QUIT (or any other command) through a single "logged" line.
func TestFTPServer_BareCRDoesNotSmuggleCommands(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	readPrefix := func(want string) string {
		t.Helper()
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !strings.HasPrefix(line, want) {
			t.Fatalf("got %q; want reply starting with %q", line, want)
		}
		return line
	}

	readPrefix("220")
	if _, err := conn.Write([]byte("USER u\r\nPASS p\r\n")); err != nil {
		t.Fatalf("login write: %v", err)
	}
	readPrefix("331")
	readPrefix("230")

	if _, err := conn.Write([]byte("NOOP\rQUIT\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Authenticated session: unknown commands return 502, not 530. If CR
	// were treated as a terminator, this would have been answered as two
	// commands (200 NOOP, then 221 QUIT and connection close).
	readPrefix("502")

	if _, err := conn.Write([]byte("NOOP\r\n")); err != nil {
		t.Fatalf("write NOOP: %v", err)
	}
	readPrefix("200")
}
