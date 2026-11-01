package ironport

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/ironport/internal/jailfs"
)

//nolint:gocognit,cyclop,funlen // single end-to-end FTP scenario: upload, download, list, verify
func TestFTPServer_UploadDownloadList(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}

	srv, addr, stop := startTestFTPServer(t, users, "5000-5010")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")
	client.command(200, "TYPE I")

	content := []byte("hello ftp world")

	uploadConn, uploadPort := client.passiveConn()
	if uploadPort < 5000 || uploadPort > 5010 {
		t.Fatalf("PASV port = %d; want within 5000-5010", uploadPort)
	}
	client.send("STOR upload.txt")
	client.read(150)
	if _, err := uploadConn.Write(content); err != nil {
		t.Fatalf("uploadConn.Write: %v", err)
	}
	_ = uploadConn.Close()
	client.read(226)

	if got, err := os.ReadFile(filepath.Join(root, "upload.txt")); err != nil { //nolint:gosec // path joined under t.TempDir()
		t.Fatalf("os.ReadFile: %v", err)
	} else if !bytes.Equal(got, content) {
		t.Fatalf("uploaded file content = %q; want %q", got, content)
	}

	listConn, listPort := client.passiveConn()
	if listPort < 5000 || listPort > 5010 {
		t.Fatalf("PASV port = %d; want within 5000-5010", listPort)
	}
	client.send("NLST")
	client.read(150)
	listing, err := io.ReadAll(listConn)
	if err != nil {
		t.Fatalf("io.ReadAll(listConn): %v", err)
	}
	_ = listConn.Close()
	client.read(226)
	if !strings.Contains(string(listing), "upload.txt") {
		t.Fatalf("NLST listing = %q; want upload.txt", listing)
	}

	downloadConn, downloadPort := client.passiveConn()
	if downloadPort < 5000 || downloadPort > 5010 {
		t.Fatalf("PASV port = %d; want within 5000-5010", downloadPort)
	}
	client.send("RETR upload.txt")
	client.read(150)
	downloaded, err := io.ReadAll(downloadConn)
	if err != nil {
		t.Fatalf("io.ReadAll(downloadConn): %v", err)
	}
	_ = downloadConn.Close()
	client.read(226)
	if !bytes.Equal(downloaded, content) {
		t.Fatalf("downloaded content = %q; want %q", downloaded, content)
	}

	select {
	case evt := <-srv.CompletedUploads():
		if evt.FilePath != "/upload.txt" {
			t.Fatalf("CompletedUploads FilePath = %q; want /upload.txt", evt.FilePath)
		}
		if evt.FullFilePath != filepath.Join(root, "upload.txt") {
			t.Fatalf("CompletedUploads FullFilePath = %q; want %q", evt.FullFilePath, filepath.Join(root, "upload.txt"))
		}
		if evt.Protocol != CompletedUploadProtocolFTP {
			t.Fatalf("CompletedUploads Protocol = %q; want %q", evt.Protocol, CompletedUploadProtocolFTP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for FTP upload completion event")
	}
}

// TestFTPServer_AlloSizeVerification covers the ALLO size hint contract:
// when a client declares an upload size via ALLO, STOR must verify the
// uploaded byte count and reject mismatches rather than announce a
// truncated upload as complete. This is the only way to detect a client
// that half-closes early in STREAM mode (see cmdStor for the discussion).
//
//nolint:funlen // multi-case ALLO/STOR verification flow; splitting would duplicate setup
func TestFTPServer_AlloSizeVerification(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")
	client.command(200, "TYPE I")

	// Bad ALLO arguments are rejected without touching session state.
	client.command(501, "ALLO")
	client.command(501, "ALLO not-a-number")
	client.command(501, "ALLO -1")

	content := []byte("hello allo world") // 16 bytes

	// Matching size: ALLO N + STOR with exactly N bytes succeeds and
	// publishes a CompletedUploads event.
	client.command(200, "ALLO %d", len(content))
	uploadConn, _ := client.passiveConn()
	client.send("STOR ok.txt")
	client.read(150)
	if _, err := uploadConn.Write(content); err != nil {
		t.Fatalf("uploadConn.Write: %v", err)
	}
	_ = uploadConn.Close()
	client.read(226)

	select {
	case evt := <-srv.CompletedUploads():
		if evt.FilePath != "/ok.txt" {
			t.Fatalf("CompletedUploads FilePath = %q; want /ok.txt", evt.FilePath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for matched-size upload event")
	}

	// Mismatched size: ALLO N + STOR of fewer bytes is rejected with 551
	// and must NOT publish a CompletedUploads event.
	client.command(200, "ALLO %d", len(content))
	truncConn, _ := client.passiveConn()
	client.send("STOR short.txt")
	client.read(150)
	if _, err := truncConn.Write(content[:len(content)/2]); err != nil {
		t.Fatalf("truncConn.Write: %v", err)
	}
	_ = truncConn.Close()
	client.read(551)

	select {
	case evt := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads fired for truncated upload: %+v", evt)
	case <-time.After(200 * time.Millisecond):
	}

	// The ALLO hint must not carry over: a follow-up STOR without ALLO
	// is judged on the no-hint best-effort path again.
	plainConn, _ := client.passiveConn()
	client.send("STOR plain.txt")
	client.read(150)
	if _, err := plainConn.Write(content); err != nil {
		t.Fatalf("plainConn.Write: %v", err)
	}
	_ = plainConn.Close()
	client.read(226)

	select {
	case evt := <-srv.CompletedUploads():
		if evt.FilePath != "/plain.txt" {
			t.Fatalf("CompletedUploads FilePath = %q; want /plain.txt", evt.FilePath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for follow-up upload event")
	}
}

// TestFTPServer_ListStreamsLargeDirectory verifies that LIST against a
// large directory returns every entry by exercising the batched-readdir
// path. The historical implementation called Readdirnames(-1) and would
// have buffered the entire listing in memory — fine for unit tests but an
// OOM hazard for real million-entry directories.
func TestFTPServer_ListStreamsLargeDirectory(t *testing.T) {
	root := t.TempDir()
	const entryCount = 1543 // exercise listing across multiple batches
	expected := make(map[string]struct{}, entryCount)
	for i := range entryCount {
		name := fmt.Sprintf("entry-%05d", i)
		if err := os.WriteFile(filepath.Join(root, name), []byte{}, 0o600); err != nil {
			t.Fatalf("os.WriteFile(%s): %v", name, err)
		}
		expected[name] = struct{}{}
	}

	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true},
	}, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")

	listConn, _ := client.passiveConn()
	client.send("NLST")
	client.read(150)
	data, err := io.ReadAll(listConn)
	if err != nil {
		t.Fatalf("io.ReadAll(listConn): %v", err)
	}
	_ = listConn.Close()
	client.read(226)

	got := map[string]struct{}{}
	for name := range strings.SplitSeq(strings.TrimRight(string(data), "\r\n"), "\r\n") {
		if name == "" {
			continue
		}
		got[name] = struct{}{}
	}
	if len(got) != len(expected) {
		t.Fatalf("NLST returned %d entries; want %d", len(got), len(expected))
	}
	for name := range expected {
		if _, ok := got[name]; !ok {
			t.Fatalf("NLST missing entry %q", name)
		}
	}
}

// TestFTPServer_AborMidTransfer verifies the RFC 959 ABOR handshake when
// the data transfer is already in flight: the server must close the data
// connection, reply 426 to the transfer command, and follow with 226 to
// acknowledge the ABOR. It also checks that a no-transfer ABOR still
// produces just a 226 (the historical behavior), that a half-written
// upload is NOT announced as complete, and that commands other than ABOR
// arriving during a transfer are politely deferred with 503.
func TestFTPServer_AborMidTransfer(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")
	client.command(200, "TYPE I")

	// ABOR with no active transfer remains a simple 226.
	client.command(226, "ABOR")

	// Mid-transfer ABOR: open STOR, write a partial chunk, send ABOR.
	// The server should reply 426 then 226 and not publish the partial
	// upload via CompletedUploads.
	uploadConn, _ := client.passiveConn()
	client.send("STOR aborted.txt")
	client.read(150)
	if _, err := uploadConn.Write([]byte("partial-")); err != nil {
		t.Fatalf("uploadConn.Write: %v", err)
	}

	// A command that isn't ABOR while the transfer is open should be
	// answered with 503 and must not terminate the transfer.
	client.command(503, "NOOP")

	client.send("ABOR")
	client.read(426)
	client.read(226)
	_ = uploadConn.Close()

	select {
	case evt := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads fired for aborted upload: %+v", evt)
	case <-time.After(200 * time.Millisecond):
	}

	// The session must remain usable after an abort: a follow-up upload
	// should succeed and publish normally.
	plainConn, _ := client.passiveConn()
	client.send("STOR after.txt")
	client.read(150)
	body := []byte("after-abort")
	if _, err := plainConn.Write(body); err != nil {
		t.Fatalf("plainConn.Write: %v", err)
	}
	_ = plainConn.Close()
	client.read(226)

	select {
	case evt := <-srv.CompletedUploads():
		if evt.FilePath != "/after.txt" {
			t.Fatalf("CompletedUploads FilePath = %q; want /after.txt", evt.FilePath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for post-abort upload event")
	}

	if got, err := os.ReadFile(filepath.Join(root, "after.txt")); err != nil { //nolint:gosec // path joined under t.TempDir()
		t.Fatalf("os.ReadFile(after.txt): %v", err)
	} else if !bytes.Equal(got, body) {
		t.Fatalf("after.txt = %q; want %q", got, body)
	}
}

// TestFTPServer_RestBeyondFileSizeRejected verifies that REST N followed by
// STOR (without APPE) is rejected when N is past the current end of file.
// The naive implementation would seek past EOF and write, producing a
// sparse file with a NUL hole between the prior tail and the new bytes —
// silent corruption from the client's perspective.
func TestFTPServer_RestBeyondFileSizeRejected(t *testing.T) {
	root := t.TempDir()
	existing := []byte("abcde") // 5 bytes
	existingPath := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(existingPath, existing, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")
	client.command(200, "TYPE I")

	// REST past EOF of an existing file: STOR must fail with 554 and the
	// existing bytes must remain untouched. Destination validation follows
	// the 150 reply and data setup, but no upload bytes are written.
	client.command(350, "REST 99")
	rejectConn, _ := client.passiveConn()
	client.command(150, "STOR existing.txt")
	client.read(554)
	_ = rejectConn.Close()

	if got, err := os.ReadFile(existingPath); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("os.ReadFile(existing) after rejected REST: %v", err)
	} else if !bytes.Equal(got, existing) {
		t.Fatalf("existing.txt after rejected REST = %q; want %q (untouched)", got, existing)
	}

	// REST > 0 against a brand-new path is also invalid: the file would
	// be created at size 0 and writing at offset N would leave a hole.
	client.command(350, "REST 10")
	newConn, _ := client.passiveConn()
	client.command(150, "STOR new.txt")
	client.read(554)
	_ = newConn.Close()

	// REST at exactly EOF is still allowed (equivalent to APPE-style
	// continuation) — guard against an off-by-one in the size check.
	client.command(350, "REST %d", len(existing))
	tailConn, _ := client.passiveConn()
	client.send("STOR existing.txt")
	client.read(150)
	if _, err := tailConn.Write([]byte("FGH")); err != nil {
		t.Fatalf("tailConn.Write: %v", err)
	}
	_ = tailConn.Close()
	client.read(226)

	want := append(append([]byte{}, existing...), 'F', 'G', 'H')
	if got, err := os.ReadFile(existingPath); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("os.ReadFile(existing) after REST=size: %v", err)
	} else if !bytes.Equal(got, want) {
		t.Fatalf("existing.txt after REST=size = %q; want %q", got, want)
	}
}

// TestFTPServer_StorOpenFailureAfterDataSetup verifies that an invalid
// destination produces 550 after 150 and validated data setup, closes the data
// connection, and leaves the control session usable without announcing success.
func TestFTPServer_StorOpenFailureAfterDataSetup(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "adir"), 0o700); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}

	srv, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")
	client.command(200, "TYPE I")

	dataConn, _ := client.passiveConn()
	defer func() { _ = dataConn.Close() }()
	client.command(150, "STOR adir")
	client.read(550)
	_ = dataConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := dataConn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("data connection after destination failure: %v; want EOF", err)
	}
	select {
	case event := <-srv.CompletedUploads():
		t.Fatalf("failed upload announced success: %+v", event)
	default:
	}
	client.command(200, "NOOP")
}

func TestFTPServer_CmdStorSanitizesCopyErrors(t *testing.T) {
	root := t.TempDir()
	jfs, err := jailfs.Open(root)
	if err != nil {
		t.Fatalf("jailfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	copyErr := errors.New("copy failed while reading /srv/secret.txt")
	var control bytes.Buffer
	controlConn := &stubConn{}
	dataConn := &stubConn{readErr: copyErr}

	fs := &ftpSession{
		server: &Server{
			completedUploads: make(chan CompletedUpload, 1),
		},
		conn:   controlConn,
		w:      bufio.NewWriter(&control),
		user:   UserInfo{Root: root, CanWrite: true},
		dataLn: &stubListener{conn: dataConn},
		fs:     jfs,
	}

	fs.cmdStor("upload.txt", false)

	got := control.String()
	if !strings.Contains(got, "426 "+ftpErrMsg(copyErr)+"\r\n") {
		t.Fatalf("cmdStor reply = %q; want sanitized FTP error reply", got)
	}
	if strings.Contains(got, "/srv/secret.txt") {
		t.Fatalf("cmdStor reply leaked internal path: %q", got)
	}
}

func TestFtpListLine_SanitizesName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "stub")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	line := ftpListLine(info, "name\r\nFAKE 200 injected")
	if strings.ContainsAny(line, "\r\n") {
		t.Errorf("ftpListLine output contains raw CR/LF: %q", line)
	}
	if !strings.Contains(line, "name??FAKE 200 injected") {
		t.Errorf("ftpListLine output = %q; want sanitized name substring", line)
	}
}

// TestFTPServer_LISTSanitizesEmbeddedCRLF verifies that a filename containing
// raw CR/LF (created out-of-band — pkg/sftp + our write-time guards now
// reject these, but the host filesystem can still hold one) does not let a
// LIST response inject extra reply lines onto the data channel.
func TestFTPServer_LISTSanitizesEmbeddedCRLF(t *testing.T) {
	root := t.TempDir()
	const badName = "good\r\nFAKE 200 injected"
	if err := os.WriteFile(filepath.Join(root, badName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "5000-5010")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")
	client.command(200, "TYPE I")

	dc, _ := client.passiveConn()
	client.send("LIST")
	client.read(150)
	listing, err := io.ReadAll(dc)
	if err != nil {
		t.Fatalf("io.ReadAll(dc): %v", err)
	}
	_ = dc.Close()
	client.read(226)

	// The data channel is line-oriented ("\r\n" per entry). With sanitization,
	// the single directory entry should produce a single non-empty line; the
	// CR and LF bytes inside the filename must have been replaced with '?'.
	lines := strings.Split(strings.TrimRight(string(listing), "\r\n"), "\r\n")
	if len(lines) != 1 {
		t.Fatalf("LIST emitted %d lines; want 1 (CR/LF injection bypassed sanitization): %q", len(lines), listing)
	}
	if !strings.Contains(lines[0], "good??FAKE 200 injected") {
		t.Errorf("LIST line = %q; want sanitized name substring %q", lines[0], "good??FAKE 200 injected")
	}
}

// FuzzFtpListLine confirms that ftpListLine never emits raw CR or LF bytes
// regardless of the supplied filename, so the formatter cannot be used to
// inject extra control lines into the LIST data channel.
func FuzzFtpListLine(f *testing.F) {
	dir := f.TempDir()
	stub := filepath.Join(dir, "stub")
	if err := os.WriteFile(stub, []byte("x"), 0o600); err != nil {
		f.Fatal(err)
	}
	info, err := os.Stat(stub)
	if err != nil {
		f.Fatal(err)
	}

	f.Add("plain.txt")
	f.Add("name\r\nFAKE 200 injected")
	f.Add("")
	f.Add("\x00\x01\x02")
	f.Add(strings.Repeat("A", 8192))
	f.Add("name\twith\ttabs")

	f.Fuzz(func(t *testing.T, name string) {
		line := ftpListLine(info, name)
		if strings.ContainsAny(line, "\r\n") {
			t.Fatalf("ftpListLine(%q) emitted raw CR/LF: %q", name, line)
		}
	})
}

// TestFTPServer_ActiveModeAborMidTransfer verifies that the RFC 959 ABOR
// handshake (426 to the transfer command, 226 to the ABOR) works for an
// active-mode upload. Active and passive transfers share runTransfer, so
// this guards against a regression if acceptDataConn is ever split per
// mode and the abort path diverges.
func TestFTPServer_ActiveModeAborMidTransfer(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestFTPServerWithActive(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")
	client.command(200, "TYPE I")

	ln := client.activePORTListener()
	client.send("STOR aborted.txt")
	client.read(150)
	dc := acceptFTPActiveData(t, ln)
	if _, err := dc.Write([]byte("partial-")); err != nil {
		t.Fatalf("active data Write: %v", err)
	}

	client.send("ABOR")
	client.read(426)
	client.read(226)
	_ = dc.Close()
	_ = ln.Close()

	select {
	case evt := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads fired for aborted active upload: %+v", evt)
	case <-time.After(200 * time.Millisecond):
	}

	// Session must remain usable after an active-mode abort: a fresh
	// EPRT transfer should complete normally.
	ln2 := client.activeEPRTListener()
	client.send("STOR after.txt")
	client.read(150)
	dc2 := acceptFTPActiveData(t, ln2)
	body := []byte("after-abort")
	if _, err := dc2.Write(body); err != nil {
		t.Fatalf("active data Write (after): %v", err)
	}
	_ = dc2.Close()
	_ = ln2.Close()
	client.read(226)

	select {
	case evt := <-srv.CompletedUploads():
		if evt.FilePath != "/after.txt" {
			t.Fatalf("CompletedUploads FilePath = %q; want /after.txt", evt.FilePath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for post-abort active upload event")
	}

	if got, err := os.ReadFile(filepath.Join(root, "after.txt")); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("os.ReadFile(after.txt): %v", err)
	} else if !bytes.Equal(got, body) {
		t.Fatalf("after.txt = %q; want %q", got, body)
	}
}

// TestFTPServer_RestPastEOFThenRETR pins the current behavior of REST N
// followed by RETR when N is past the end of file: the seek succeeds, the
// io.Copy returns zero bytes, and the server replies 226 with an empty
// data stream. STOR rejects the same situation with 554 (covered by
// TestFTPServer_RestBeyondFileSizeRejected) — this asymmetry is
// documented here, and the test will fail loudly if RETR's handling
// changes (for example, to 554) so the surrounding contract can be
// updated in one place.
func TestFTPServer_RestPastEOFThenRETR(t *testing.T) {
	root := t.TempDir()
	existing := []byte("abcde")
	if err := os.WriteFile(filepath.Join(root, "existing.txt"), existing, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")
	client.command(200, "TYPE I")

	client.command(350, "REST 99")
	dc, _ := client.passiveConn()
	client.send("RETR existing.txt")
	client.read(150)
	body, err := io.ReadAll(dc)
	if err != nil {
		t.Fatalf("io.ReadAll(RETR): %v", err)
	}
	_ = dc.Close()
	client.read(226)
	if len(body) != 0 {
		t.Fatalf("REST past EOF + RETR returned %d bytes; want 0 (current behavior)", len(body))
	}

	// The restart offset must be cleared after use: a follow-up RETR with
	// no preceding REST should return the full file.
	dc2, _ := client.passiveConn()
	client.send("RETR existing.txt")
	client.read(150)
	got, err := io.ReadAll(dc2)
	if err != nil {
		t.Fatalf("io.ReadAll(post-REST RETR): %v", err)
	}
	_ = dc2.Close()
	client.read(226)
	if !bytes.Equal(got, existing) {
		t.Fatalf("follow-up RETR = %q; want %q (restart offset leaked between commands)", got, existing)
	}
}

// TestFTPServer_AborMidTransferRace exercises the runTransfer select
// window with many ABOR/transfer interleavings so the race detector
// (go test -race) can catch a regression in the abort handshake. Two
// orderings are tried per iteration: ABOR-before-client-close and
// client-close-before-ABOR. The first produces a 426/226 sequence; the
// second usually produces 226/226 because io.Copy finishes before the
// ABOR control message is observed. Either is acceptable — the test
// just requires that two well-formed replies arrive and that the
// session survives.
//
//nolint:gocognit,cyclop,funlen // ABOR-during-transfer race; splitting would break the timing relationship
func TestFTPServer_AborMidTransferRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping race iterations in -short mode")
	}
	root := t.TempDir()
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")
	client.command(200, "TYPE I")

	chunk := bytes.Repeat([]byte("abcdefgh"), 1024) // 8 KiB
	const iterations = 30

	drainUploads := func() {
		for {
			select {
			case <-srv.CompletedUploads():
				continue
			default:
				return
			}
		}
	}

	for i := range iterations {
		dc, _ := client.passiveConn()
		client.send("STOR race.txt")
		client.read(150)

		writes := 1 + (i % 8)
		for range writes {
			if _, err := dc.Write(chunk); err != nil {
				break
			}
		}

		if i%2 == 0 {
			client.send("ABOR")
			_ = dc.Close()
		} else {
			_ = dc.Close()
			client.send("ABOR")
		}

		first, _, err := client.tp.ReadResponse(0)
		if err != nil {
			t.Fatalf("iter %d: read first response: %v", i, err)
		}
		second, _, err := client.tp.ReadResponse(0)
		if err != nil {
			t.Fatalf("iter %d: read second response: %v", i, err)
		}
		switch {
		case first == 426 && second == 226:
		case first == 226 && second == 226:
		default:
			t.Fatalf("iter %d: responses %d then %d; want 426/226 (aborted) or 226/226 (transfer raced ABOR)", i, first, second)
		}

		drainUploads()
	}

	// Session is still usable after the storm.
	dc, _ := client.passiveConn()
	client.send("STOR final.txt")
	client.read(150)
	if _, err := dc.Write([]byte("done")); err != nil {
		t.Fatalf("final write: %v", err)
	}
	_ = dc.Close()
	client.read(226)
}

// ---- ftpPathBase ----

// TestFTPPathBase verifies that ftpPathBase returns "/" for the root and empty
// string and the basename otherwise, including trailing-slash and nested cases.
func TestFTPPathBase(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{in: "/", want: "/"},
		{in: "", want: "/"},
		{in: "/file.txt", want: "file.txt"},
		{in: "/dir/sub/file.txt", want: "file.txt"},
		{in: "file.txt", want: "file.txt"},
		{in: "/dir/", want: "dir"},
		{in: "/dir/sub/", want: "sub"},
		{in: "/a/b/c", want: "c"},
	}
	for _, tc := range tests {
		if got := ftpPathBase(tc.in); got != tc.want {
			t.Errorf("ftpPathBase(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
