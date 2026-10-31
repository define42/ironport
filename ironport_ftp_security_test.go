//go:build linux

package ironport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFTPRevocationCancelsPassiveAccept(t *testing.T) {
	for _, action := range []string{"remove user", "remove all users", "shutdown", "disconnect"} {
		t.Run(action, func(t *testing.T) {
			users := map[string]UserInfo{"u": {Password: "p", Root: t.TempDir(), CanRead: true}}
			cfg := newTestFTPConfig(t, users, "", false)
			cfg.FtpDataAcceptTimeout = -1
			srv, addr, stop := startTestFTPServerWithConfig(t, cfg)
			t.Cleanup(stop)
			c := dialFTP(t, addr)
			c.login("u", "p")
			dataAddr := ftpSecurityPassiveAddress(t, c)
			c.send("LIST")
			c.read(150)
			done := make(chan error, 1)
			go func() {
				if err := ftpSecurityCancelSession(srv, c, action); err != nil {
					done <- err
					return
				}
				srv.connWG.Wait()
				done <- nil
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("FTP handler remained blocked after cancellation")
			}
			if dc, err := net.DialTimeout("tcp", dataAddr, time.Second); err == nil {
				_ = dc.Close()
				t.Fatal("passive listener survived session cancellation")
			}
		})
	}
}

func ftpSecurityCancelSession(srv *Server, c *ftpTestClient, action string) error {
	switch action {
	case "remove user":
		srv.RemoveUser("u")
	case "remove all users":
		srv.RemoveAllUsers()
	case "shutdown":
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	case "disconnect":
		return c.conn.Close()
	}
	return nil
}

func ftpSecurityPassiveAddress(t *testing.T, c *ftpTestClient) string {
	t.Helper()
	host, port, err := parseFTPPASVResponse(c.command(227, "PASV"))
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func TestFTPRevocationClosesEstablishedDataConnection(t *testing.T) {
	users := map[string]UserInfo{"u": {Password: "p", Root: t.TempDir(), CanWrite: true}}
	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	c.login("u", "p")
	dc, _ := c.passiveConn()
	defer func() { _ = dc.Close() }()
	c.send("STOR pending.bin")
	c.read(150)
	srv.RemoveUser("u")
	_ = dc.SetReadDeadline(time.Now().Add(time.Second))
	_, err := dc.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("revoked data socket Read = %v; want connection closed", err)
	}
}

func TestFTPRevocationSkipsQueuedControlCommands(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "retained.txt")
	if err := os.WriteFile(filename, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jfs.Close() }()
	var output bytes.Buffer
	f := &ftpSession{fs: jfs, authenticated: true, user: UserInfo{CanWrite: true}, w: bufio.NewWriter(&output)}
	f.cancelDataOperations()
	if !f.handleFTPCommand("DELE", "/retained.txt") {
		t.Fatal("revoked session did not stop before the queued command")
	}
	if _, err := os.Stat(filename); err != nil {
		t.Fatalf("revoked session executed queued DELE: %v", err)
	}
}

func TestFTPPassiveRejectsForeignPeerWithoutConsumingListener(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{"u": {Password: "p", Root: root, CanRead: true}}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	c.login("u", "p")
	dataAddr := ftpSecurityPassiveAddress(t, c)
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}
	foreign, err := dialer.DialContext(context.Background(), "tcp", dataAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()
	c.send("LIST")
	c.read(150)
	_ = foreign.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := foreign.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("foreign socket Read = %v; want EOF", err)
	}
	legitimate, err := net.DialTimeout("tcp", dataAddr, time.Second)
	if err != nil {
		t.Fatalf("legitimate data connection after rejection: %v", err)
	}
	defer func() { _ = legitimate.Close() }()
	_ = legitimate.SetReadDeadline(time.Now().Add(time.Second))
	listing, err := io.ReadAll(legitimate)
	if err != nil || !strings.Contains(string(listing), "visible.txt") {
		t.Fatalf("LIST after rejected peer = %q, %v", listing, err)
	}
	c.read(226)
}

func TestFTPPassAfterLoginIsRejectedWithoutAuthEvents(t *testing.T) {
	users := map[string]UserInfo{"u": {Password: "p", Root: t.TempDir(), CanRead: true}}
	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)
	c := dialFTP(t, addr)
	c.login("u", "p")
	requireAuthEvent(t, srv.AuthEvents(), AuthEventLoginSuccess, "u", CompletedUploadProtocolFTP)
	c.command(503, "PASS wrong")
	c.command(503, "PASS p")
	c.command(257, "PWD")
	select {
	case event := <-srv.AuthEvents():
		t.Fatalf("rejected duplicate PASS emitted auth event: %+v", event)
	default:
	}
}

func TestFTPAuthTLSResetClosesDataEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	f := &ftpSession{
		server: &Server{}, dataLn: ln, dataAddr: &net.TCPAddr{},
		epsvAll: true, pbszSet: true, dataProt: 'P',
	}
	f.resetSessionStateForAuthTLS()
	if f.dataLn != nil || f.dataAddr != nil || f.epsvAll || f.pbszSet || f.dataProt != 'C' {
		t.Fatal("AUTH TLS retained pre-upgrade data state")
	}
	if dc, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		_ = dc.Close()
		t.Fatal("AUTH TLS retained the pre-upgrade passive listener")
	}
}

func TestFTPPreTLSChannelCleanRedactsBufferedCommandArguments(t *testing.T) {
	const secret = "pipelined-password-must-not-be-logged"
	line := "PASS " + secret + "\r\n"
	ctlMsg := make(chan ftpCtlMsg, 1)
	ctlMsg <- ftpCtlMsg{line: line}
	f := &ftpSession{
		conn:   &stubConn{},
		r:      bufio.NewReader(strings.NewReader("")),
		ctlMsg: ctlMsg,
	}

	previousOutput := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	if f.preTLSChannelClean() {
		t.Fatal("preTLSChannelClean accepted a pipelined PASS command")
	}
	got := logs.String()
	if strings.Contains(got, secret) {
		t.Fatalf("pre-TLS rejection log disclosed password: %q", got)
	}
	if !strings.Contains(got, `verb="PASS"`) || !strings.Contains(got, fmt.Sprintf("bytes=%d", len(line))) {
		t.Fatalf("pre-TLS rejection log = %q; want sanitized verb and byte count", got)
	}
}

type ftpDeadlineRecorder struct {
	stubConn

	writeDeadline time.Time
}

func (c *ftpDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return nil
}

func TestFTPStatStreamsDirectoryWithWriteDeadline(t *testing.T) {
	root := t.TempDir()
	const count = 600 // more than one ListStream batch
	for i := range count {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("entry-%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jfs.Close() }()
	var output bytes.Buffer
	conn := &ftpDeadlineRecorder{}
	f := &ftpSession{conn: conn, w: bufio.NewWriter(&output), fs: jfs, authenticated: true, user: UserInfo{CanRead: true}}
	f.cmdStat("/")
	if got := strings.Count(output.String(), "entry-"); got != count {
		t.Fatalf("STAT returned %d directory entries; want %d", got, count)
	}
	if !strings.HasSuffix(output.String(), "213 End of status\r\n") || !conn.writeDeadline.After(time.Now()) {
		t.Fatal("STAT did not complete with a bounded control write deadline")
	}
}

type ftpStatConn struct {
	stubConn
	closed bool
}

func (c *ftpStatConn) Close() error {
	c.closed = true
	return nil
}

func TestFTPStatDirectoryOpenFailureKeepsSession(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can open a directory without read permission")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "unreadable")
	if err := os.Mkdir(dir, 0o311); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jfs.Close() }()
	if _, err := jfs.Stat("/unreadable"); err != nil {
		t.Fatalf("directory must be stat-able: %v", err)
	}
	var output bytes.Buffer
	conn := &ftpStatConn{}
	f := &ftpSession{conn: conn, w: bufio.NewWriter(&output), fs: jfs, authenticated: true, user: UserInfo{CanRead: true}}
	f.cmdStat("/unreadable")
	if conn.closed {
		t.Fatal("STAT directory-open failure closed the control connection")
	}
	if got := output.String(); !strings.HasPrefix(got, "550 ") || strings.Contains(got, "213-") {
		t.Fatalf("STAT reply = %q; want standalone 550", got)
	}
	if quit := f.handleFTPCommand("NOOP", ""); quit || !strings.HasSuffix(output.String(), "200 ok\r\n") {
		t.Fatalf("session unusable after STAT: quit=%v, replies=%q", quit, output.String())
	}
}

func TestFTPStatDirectoryRemovedBeforeOpen(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "removed")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jfs.Close() }()
	st, err := jfs.Stat("/removed")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	f := &ftpSession{conn: &ftpStatConn{}, w: bufio.NewWriter(&output), fs: jfs}
	if err := f.writeStatListing("/removed", st); err != nil {
		t.Fatalf("directory-open failure should be handled with 550: %v", err)
	}
	if got := output.String(); !strings.HasPrefix(got, "550 ") || strings.Contains(got, "213-") {
		t.Fatalf("STAT reply = %q; want standalone 550", got)
	}
}
