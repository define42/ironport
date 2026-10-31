package ironport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseFTPPassivePortRange(t *testing.T) {
	tests := []struct {
		name      string
		portRange string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{name: "empty", portRange: "", wantStart: 0, wantEnd: 0, wantErr: false},
		{name: "single port", portRange: "5000", wantStart: 5000, wantEnd: 5000},
		{name: "range", portRange: "5000-5010", wantStart: 5000, wantEnd: 5010},
		{name: "range with spaces", portRange: " 5000 - 5010 ", wantStart: 5000, wantEnd: 5010},
		{name: "invalid text", portRange: "abc", wantErr: true},
		{name: "invalid range", portRange: "5000-", wantErr: true},
		{name: "start greater than end", portRange: "5010-5000", wantErr: true},
		{name: "out of range", portRange: "70000", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotStart, gotEnd, err := parseFTPPassivePortRange(tc.portRange)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseFTPPassivePortRange(%q) error = nil; want non-nil", tc.portRange)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFTPPassivePortRange(%q): %v", tc.portRange, err)
			}
			if gotStart != tc.wantStart || gotEnd != tc.wantEnd {
				t.Fatalf("parseFTPPassivePortRange(%q) = (%d, %d); want (%d, %d)", tc.portRange, gotStart, gotEnd, tc.wantStart, tc.wantEnd)
			}
		})
	}
}

func TestServerListenFTPData(t *testing.T) {
	t.Run("os assigned port", func(t *testing.T) {
		srv := &Server{}
		ln, err := srv.listenFTPData("127.0.0.1")
		if err != nil {
			t.Fatalf("listenFTPData: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })

		port := ln.Addr().(*net.TCPAddr).Port
		if port == 0 {
			t.Fatal("listenFTPData returned port 0; want assigned port")
		}
	})

	t.Run("configured port unavailable", func(t *testing.T) {
		busyLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		t.Cleanup(func() { _ = busyLn.Close() })

		port := busyLn.Addr().(*net.TCPAddr).Port
		srv := &Server{ftpPassivePortRange: strconv.Itoa(port)}
		if _, err := srv.listenFTPData("127.0.0.1"); err == nil {
			t.Fatal("listenFTPData error = nil; want non-nil when configured port is already in use")
		}
	})
}

// TestFTPServer_PassiveAdvertisedIP verifies that FtpPassiveAdvertisedIP
// overrides the address echoed in the PASV (227) reply, which is required
// for deployments behind NAT where the control connection's local IP is the
// internal address.
func TestFTPServer_PassiveAdvertisedIP(t *testing.T) {
	root := t.TempDir()
	config := newTestFTPConfig(t, map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}, "", false)
	config.FtpPassiveAdvertisedIP = "203.0.113.7"
	_, addr, stop := startTestFTPServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")

	host, _, err := parseFTPPASVResponse(client.command(227, "PASV"))
	if err != nil {
		t.Fatalf("parse PASV response: %v", err)
	}
	if host != "203.0.113.7" {
		t.Fatalf("PASV advertised host = %q; want %q", host, "203.0.113.7")
	}
}

func TestFTPSession_AcceptDataConnRequiresPrivateProtection(t *testing.T) {
	fs := &ftpSession{
		server:   &Server{ftpRequireTLS: true},
		dataProt: 'C',
	}
	dc, err := fs.acceptDataConn()
	if dc != nil {
		_ = dc.Close()
		t.Fatal("acceptDataConn returned a connection without PROT P")
	}
	if !errors.Is(err, errFTPDataProtectionRequired) {
		t.Fatalf("acceptDataConn error = %v; want %v", err, errFTPDataProtectionRequired)
	}
}

func TestFTPSession_AcceptDataConnUsesConfiguredTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := &ftpSession{
		server: &Server{
			ftpDataAcceptTimeout: 20 * time.Millisecond,
		},
		dataLn: ln,
	}

	start := time.Now()
	errCh := make(chan error, 1)
	go func() {
		dc, err := fs.acceptDataConn()
		if dc != nil {
			_ = dc.Close()
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("acceptDataConn returned nil error; want timeout")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("acceptDataConn error = %v; want timeout", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("acceptDataConn took %v; expected configured timeout", elapsed)
		}
	case <-time.After(time.Second):
		_ = ln.Close()
		t.Fatal("acceptDataConn did not return after configured timeout")
	}
}

// TestFTPServer_PASVExhaustsPortRange verifies that when every port in the
// configured passive range is already held by another in-flight session,
// a new PASV request fails fast with 425 rather than hanging or silently
// drifting outside the range — and that the session pool recovers when a
// holder releases its listener.
func TestFTPServer_PASVExhaustsPortRange(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "5500-5502")
	t.Cleanup(stop)

	holders := make([]*ftpTestClient, 0, 3)
	seen := make(map[int]struct{}, 3)
	for i := range 3 {
		c := dialFTP(t, addr)
		c.login("u", "p")
		_, port, err := parseFTPPASVResponse(c.command(227, "PASV"))
		if err != nil {
			t.Fatalf("session %d parse PASV: %v", i, err)
		}
		if port < 5500 || port > 5502 {
			t.Fatalf("session %d PASV port = %d; want within 5500-5502", i, port)
		}
		if _, dup := seen[port]; dup {
			t.Fatalf("session %d reused port %d", i, port)
		}
		seen[port] = struct{}{}
		holders = append(holders, c)
	}

	extra := dialFTP(t, addr)
	extra.login("u", "p")
	extra.command(425, "PASV")

	// Release one port and confirm PASV recovers. Closing the textproto
	// connection EOFs the server's control reader, which unwinds the session
	// and triggers the deferred closeDataListener.
	_ = holders[0].tp.Close()
	holders = holders[1:]

	requireFTPPASVRecovery(t, extra, 5500, 5502)

	for _, c := range holders {
		_ = c.tp.Close()
	}
	_ = extra.tp.Close()
}

// TestFTPServer_PASVConcurrentTransfers runs many simultaneous STOR transfers
// through a constrained passive port range. The intent is twofold:
//
//   - Stress the port allocator and acceptDataConn paths under contention so
//     -race can catch any data race in listenFTPData / handleFTPConn.
//   - Confirm that when transfer count exceeds the port range, the server
//     fails late dialers cleanly with 425 instead of hanging or producing a
//     port collision, and that every accepted upload writes the full body.
//
// Each goroutine drives a full session: login, PASV, STOR, write payload,
// close, read 226. Any goroutine that runs while the range is full gets 425
// on PASV and retries — the test only requires that every goroutine
// eventually completes successfully and that the on-disk file matches.
//
//nolint:gocognit,cyclop,funlen // concurrency test orchestrating multiple workers across passive transfers
func TestFTPServer_PASVConcurrentTransfers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent PASV stress in -short mode")
	}
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	// Range of 4 ports vs. 12 concurrent workers guarantees the allocator
	// is repeatedly exhausted and forced to fail-fast some PASV calls.
	srv, addr, stop := startTestFTPServer(t, users, "5600-5603")
	t.Cleanup(stop)

	const workers = 12
	payload := bytes.Repeat([]byte("payload-"), 256) // 2 KiB

	drainUploads := func() {
		for {
			select {
			case <-srv.CompletedUploads():
			case <-time.After(50 * time.Millisecond):
				return
			}
		}
	}
	t.Cleanup(drainUploads)

	doOne := func(t *testing.T, id int) error {
		t.Helper()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			return fmt.Errorf("worker %d dial: %w", id, err)
		}
		defer func() { _ = conn.Close() }()
		tp := textproto.NewConn(conn)
		defer func() { _ = tp.Close() }()

		if _, _, err := tp.ReadResponse(220); err != nil {
			return fmt.Errorf("worker %d greeting: %w", id, err)
		}
		if err := tp.PrintfLine("USER u"); err != nil {
			return fmt.Errorf("worker %d USER: %w", id, err)
		}
		if _, _, err := tp.ReadResponse(331); err != nil {
			return fmt.Errorf("worker %d USER reply: %w", id, err)
		}
		if err := tp.PrintfLine("PASS p"); err != nil {
			return fmt.Errorf("worker %d PASS: %w", id, err)
		}
		if _, _, err := tp.ReadResponse(230); err != nil {
			return fmt.Errorf("worker %d PASS reply: %w", id, err)
		}
		if err := tp.PrintfLine("TYPE I"); err != nil {
			return fmt.Errorf("worker %d TYPE: %w", id, err)
		}
		if _, _, err := tp.ReadResponse(200); err != nil {
			return fmt.Errorf("worker %d TYPE reply: %w", id, err)
		}

		// Retry PASV until the allocator hands us a port — a 425 only means
		// every range slot was busy at that moment; another worker will free
		// one shortly. Cap the loop so a real regression (425 forever) fails.
		deadline := time.Now().Add(10 * time.Second)
		var host string
		var port int
		for {
			if err := tp.PrintfLine("PASV"); err != nil {
				return fmt.Errorf("worker %d PASV: %w", id, err)
			}
			code, msg, err := tp.ReadResponse(0)
			if err != nil {
				return fmt.Errorf("worker %d PASV reply: %w", id, err)
			}
			if code == 227 {
				host, port, err = parseFTPPASVResponse(msg)
				if err != nil {
					return fmt.Errorf("worker %d parse PASV: %w", id, err)
				}
				if port < 5600 || port > 5603 {
					return fmt.Errorf("worker %d PASV port %d outside configured range", id, port)
				}
				break
			}
			if code != 425 {
				return fmt.Errorf("worker %d PASV got code %d: %s", id, code, msg)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("worker %d PASV stuck at 425 past deadline", id)
			}
			time.Sleep(10 * time.Millisecond)
		}

		dc, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 5*time.Second)
		if err != nil {
			return fmt.Errorf("worker %d dial data: %w", id, err)
		}
		name := fmt.Sprintf("file-%02d.bin", id)
		if err := tp.PrintfLine("STOR %s", name); err != nil {
			_ = dc.Close()
			return fmt.Errorf("worker %d STOR: %w", id, err)
		}
		if _, _, err := tp.ReadResponse(150); err != nil {
			_ = dc.Close()
			return fmt.Errorf("worker %d STOR 150: %w", id, err)
		}
		if _, err := dc.Write(payload); err != nil {
			_ = dc.Close()
			return fmt.Errorf("worker %d write: %w", id, err)
		}
		_ = dc.Close()
		if _, _, err := tp.ReadResponse(226); err != nil {
			return fmt.Errorf("worker %d STOR 226: %w", id, err)
		}
		if err := tp.PrintfLine("QUIT"); err != nil {
			return fmt.Errorf("worker %d QUIT: %w", id, err)
		}
		_, _, _ = tp.ReadResponse(221)
		return nil
	}

	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func(id int) {
			defer wg.Done()
			errCh <- doOne(t, id)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	for i := range workers {
		name := fmt.Sprintf("file-%02d.bin", i)
		got, err := os.ReadFile(filepath.Join(root, name)) //nolint:gosec // path under t.TempDir()
		if err != nil {
			t.Fatalf("os.ReadFile(%s): %v", name, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s body mismatch: got %d bytes, want %d", name, len(got), len(payload))
		}
	}
}

func TestFTPServer_ActiveModeDisabledByDefault(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	features := client.command(211, "FEAT")
	if strings.Contains(features, "EPRT") {
		t.Fatalf("FEAT response = %q; active EPRT must not be advertised by default", features)
	}
	help := client.command(214, "HELP")
	if strings.Contains(help, "PORT EPRT") {
		t.Fatalf("HELP response = %q; active commands must not be advertised by default", help)
	}
	client.command(502, "HELP PORT")
	client.command(502, "HELP EPRT")
	client.command(502, "PORT 127,0,0,1,4,210")
	client.command(502, "EPRT |1|127.0.0.1|1234|")
}

//nolint:cyclop,funlen // sequential RETR/STOR/abort transitions; splitting would obscure the protocol flow
func TestFTPServer_ActiveModeTransfers(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "download.txt"), []byte("retr-data"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(download): %v", err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestFTPServerWithActive(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	features := client.command(211, "FEAT")
	if !strings.Contains(features, "EPRT") {
		t.Fatalf("FEAT response = %q; want EPRT advertised when active mode is enabled", features)
	}
	help := client.command(214, "HELP")
	if !strings.Contains(help, "PORT EPRT") {
		t.Fatalf("HELP response = %q; want PORT/EPRT advertised when active mode is enabled", help)
	}
	client.command(214, "HELP PORT")
	client.command(214, "HELP EPRT")

	listLn := client.activePORTListener()
	client.send("LIST")
	client.read(150)
	listDC := acceptFTPActiveData(t, listLn)
	listData, err := io.ReadAll(listDC)
	if err != nil {
		t.Fatalf("active LIST read: %v", err)
	}
	_ = listDC.Close()
	_ = listLn.Close()
	client.read(226)
	if !bytes.Contains(listData, []byte("download.txt")) {
		t.Fatalf("active LIST data = %q; want download.txt", listData)
	}

	retrLn := client.activeEPRTListener()
	client.send("RETR download.txt")
	client.read(150)
	retrDC := acceptFTPActiveData(t, retrLn)
	retrData, err := io.ReadAll(retrDC)
	if err != nil {
		t.Fatalf("active RETR read: %v", err)
	}
	_ = retrDC.Close()
	_ = retrLn.Close()
	client.read(226)
	if !bytes.Equal(retrData, []byte("retr-data")) {
		t.Fatalf("active RETR data = %q; want retr-data", retrData)
	}

	storLn := client.activePORTListener()
	client.send("STOR upload.txt")
	client.read(150)
	storDC := acceptFTPActiveData(t, storLn)
	if _, err := storDC.Write([]byte("stor-data")); err != nil {
		t.Fatalf("active STOR write: %v", err)
	}
	_ = storDC.Close()
	_ = storLn.Close()
	client.read(226)
	if got, err := os.ReadFile(filepath.Join(root, "upload.txt")); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("os.ReadFile(upload): %v", err)
	} else if !bytes.Equal(got, []byte("stor-data")) {
		t.Fatalf("upload.txt = %q; want stor-data", got)
	}
	select {
	case got := <-srv.CompletedUploads():
		if got.Protocol != CompletedUploadProtocolFTP || got.FilePath != "/upload.txt" || got.ClientIP != "127.0.0.1" {
			t.Fatalf("CompletedUpload = %+v; want FTP /upload.txt from 127.0.0.1", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for active STOR CompletedUpload")
	}
}

func TestFTPServer_ActiveModeRejectsInvalidCommands(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServerWithActive(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	client.command(501, "PORT 127,0,0,1,4")
	client.command(501, "PORT 127,0,0,1,999,1")
	client.command(501, "PORT 127,0,0,1,0,0")
	client.command(501, "EPRT |1|127.0.0.1|")
	client.command(501, "EPRT |3|127.0.0.1|1234|")
	client.command(501, "EPRT |1|::1|1234|")
	client.command(501, "EPRT |2|127.0.0.1|1234|")
}

func TestFTPServer_ActiveModeRejectsDifferentTargetIP(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServerWithActive(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	client.command(501, "PORT 127,0,0,2,4,210")
	client.command(501, "EPRT |1|127.0.0.2|1234|")
}

// TestFTPServer_EPSVAllRejectsActiveMode documents the EPSV ALL contract
// from RFC 2428: once a client sends EPSV ALL, the server must refuse
// active-mode commands for the rest of the session. EPSV must still work afterward.
func TestFTPServer_EPSVAllRejectsActiveMode(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServerWithActive(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	client.command(200, "EPSV ALL")

	client.command(502, "PORT 127,0,0,1,4,210")
	client.command(502, "EPRT |1|127.0.0.1|4000|")

	client.command(229, "EPSV")
}

// TestFTPServer_ActiveModeDialTimeoutReplies425 verifies that when the
// server's outbound active-mode dial cannot complete within
// effectiveFTPDataAcceptTimeout, the transfer command is answered with
// 150 followed by 425 — never a spurious 226. A 1ns timeout forces the
// deadline to fire before any connect attempt can succeed.
func TestFTPServer_ActiveModeDialTimeoutReplies425(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestFTPConfig(t, users, "", true)
	config.FtpDataAcceptTimeout = time.Nanosecond
	_, addr, stop := startTestFTPServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	// Reserve and immediately release a local port so the PORT target
	// is well-formed. The dial would never complete in 1ns anyway, so
	// whether the port is bound or not is incidental.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(probe): %v", err)
	}
	target := probe.Addr().(*net.TCPAddr)
	_ = probe.Close()
	ip := target.IP.To4()
	if ip == nil {
		t.Fatalf("probe listener IP = %v; want IPv4", target.IP)
	}
	client.command(200, "PORT %d,%d,%d,%d,%d,%d", ip[0], ip[1], ip[2], ip[3], target.Port/256, target.Port%256)

	client.send("LIST")
	client.read(150)
	client.read(425)
}

// TestFTPServer_STORWithoutPassiveModeFails verifies that data-transfer
// commands fail cleanly (150 then 425) when the client never opened a
// passive listener. The control session must remain usable after each
// failure so a confused client can recover by issuing PASV.
func TestFTPServer_STORWithoutPassiveModeFails(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "exists.txt"), []byte("y"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")
	client.command(200, "TYPE I")

	client.send("STOR new.txt")
	client.read(150)
	client.read(425)

	client.send("RETR exists.txt")
	client.read(150)
	client.read(425)

	client.send("LIST")
	client.read(150)
	client.read(425)

	// Session still works for a legitimate transfer after the failed ones.
	dc, _ := client.passiveConn()
	client.send("STOR after.txt")
	client.read(150)
	if _, err := dc.Write([]byte("ok")); err != nil {
		t.Fatalf("dc.Write: %v", err)
	}
	_ = dc.Close()
	client.read(226)

	if got, err := os.ReadFile(filepath.Join(root, "after.txt")); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("os.ReadFile(after.txt): %v", err)
	} else if !bytes.Equal(got, []byte("ok")) {
		t.Fatalf("after.txt = %q; want %q", got, "ok")
	}
}
