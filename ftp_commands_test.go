package ironport

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFTPPathHelpers(t *testing.T) {
	listCases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", "   "},
		{"-la", ""},
		{"-la /incoming", "/incoming"},
		{"-la -- almost", "almost"},
		{"-la /a /b", "/a /b"},
		{"file name.txt", "file name.txt"},
		{"file name.txt ", "file name.txt "},
		{" file name.txt ", " file name.txt "},
		{"-la  file name.txt ", " file name.txt "},
		{"-la\tfile name.txt\t", "file name.txt\t"},
		{"-- -file name.txt ", "-file name.txt "},
		{"--", ""},
		{"--  name ", " name "},
		{"-la -- -- name ", "-- name "},
		{"-la  ", " "},
		{" -file name.txt", " -file name.txt"},
	}
	for _, tc := range listCases {
		if got := listPathArg(tc.in); got != tc.want {
			t.Errorf("listPathArg(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}

	unquoteCases := []struct {
		in   string
		want string
	}{
		{`plain.txt`, "plain.txt"},
		{`"space dir"`, "space dir"},
		{` "space dir" `, ` "space dir" `},
		{`" space dir "`, " space dir "},
		{" plain.txt\t", " plain.txt\t"},
		{`"a""quote.txt"`, `a"quote.txt`},
		{`"unterminated`, `"unterminated`},
	}
	for _, tc := range unquoteCases {
		if got := unquoteFTPPath(tc.in); got != tc.want {
			t.Errorf("unquoteFTPPath(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestFTPPathnameWhitespace(t *testing.T) {
	for _, name := range []string{"report ", " report", "report detail", " ", "\treport\t"} {
		t.Run(name, func(t *testing.T) {
			cmd, arg := parseFTPCommand("DELE " + name)
			if cmd != "DELE" || arg != name {
				t.Fatalf("command parser changed pathname: cmd=%q arg=%q; want %q", cmd, arg, name)
			}
			session := &ftpSession{cwd: "/"}
			if got := session.cleanPath(arg); got != "/"+name {
				t.Fatalf("cleanPath(%q)=%q; want %q", name, got, "/"+name)
			}
			_, got, ok := parseMFMTArg("20240102030405 " + name)
			if !ok || got != name {
				t.Fatalf("MFMT parser changed pathname: path=%q ok=%t; want %q", got, ok, name)
			}
		})
	}
}

//nolint:gocognit,cyclop,funlen // covers DELE/MKD/RMD/RNFR/RNTO/MDTM/SIZE in one walking scenario
func TestFTPServer_FileManagementCommands(t *testing.T) {
	root := t.TempDir()
	content := []byte("hello ftp commands")
	filePath := filepath.Join(root, "file.txt")
	if err := os.WriteFile(filePath, content, 0o600); err != nil {
		t.Fatalf("os.WriteFile(file): %v", err)
	}
	mtime := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(filePath, mtime, mtime); err != nil {
		t.Fatalf("os.Chtimes(file): %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "space dir"), 0o750); err != nil {
		t.Fatalf("os.Mkdir(space dir): %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "rename-src.txt"), []byte("rename me"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(rename-src): %v", err)
	}

	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")

	features := client.command(211, "FEAT")
	if !strings.Contains(features, "UTF8") || !strings.Contains(features, "EPSV") {
		t.Fatalf("FEAT response = %q; want advertised UTF8 and EPSV", features)
	}
	client.command(229, "EPSV")

	if got := client.command(213, "SIZE file.txt"); got != strconv.Itoa(len(content)) {
		t.Fatalf("SIZE response = %q; want %d", got, len(content))
	}
	client.command(550, "SIZE space dir")
	if got := client.command(213, "MDTM file.txt"); got != "20240102030405" {
		t.Fatalf("MDTM response = %q; want 20240102030405", got)
	}
	wantMFMT := time.Date(2024, 1, 3, 4, 5, 6, 0, time.UTC)
	if got := client.command(213, "MFMT 20240103040506 file.txt"); got != "20240103040506" {
		t.Fatalf("MFMT response = %q; want 20240103040506", got)
	}
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("os.Stat after MFMT: %v", err)
	}
	if !info.ModTime().Equal(wantMFMT) {
		t.Fatalf("mtime after MFMT = %v; want %v", info.ModTime(), wantMFMT)
	}

	client.command(250, `CWD "space dir"`)
	if got := client.command(257, "PWD"); !strings.Contains(got, `"/space dir"`) {
		t.Fatalf("PWD after CWD = %q; want /space dir", got)
	}
	client.command(250, "CDUP")
	client.command(550, "CWD file.txt")
	client.command(550, "CWD missing")

	listConn, _ := client.passiveConn()
	client.send("NLST -a file.txt")
	client.read(150)
	listing, err := io.ReadAll(listConn)
	if err != nil {
		t.Fatalf("io.ReadAll(NLST): %v", err)
	}
	_ = listConn.Close()
	client.read(226)
	if strings.TrimSpace(string(listing)) != "file.txt" {
		t.Fatalf("NLST file listing = %q; want file.txt", listing)
	}

	listFileConn, _ := client.passiveConn()
	client.send("LIST -l file.txt")
	client.read(150)
	listFile, err := io.ReadAll(listFileConn)
	if err != nil {
		t.Fatalf("io.ReadAll(LIST file): %v", err)
	}
	_ = listFileConn.Close()
	client.read(226)
	if !strings.Contains(string(listFile), "file.txt") || !strings.Contains(string(listFile), strconv.Itoa(len(content))) {
		t.Fatalf("LIST file response = %q; want filename and size", listFile)
	}

	client.command(501, "REST -1")
	client.command(350, "REST 6")
	downloadConn, _ := client.passiveConn()
	client.send("RETR file.txt")
	client.read(150)
	downloaded, err := io.ReadAll(downloadConn)
	if err != nil {
		t.Fatalf("io.ReadAll(RETR): %v", err)
	}
	_ = downloadConn.Close()
	client.read(226)
	if !bytes.Equal(downloaded, content[6:]) {
		t.Fatalf("resumed RETR returned %q; want %q", downloaded, content[6:])
	}

	appendConn, _ := client.passiveConn()
	client.send("APPE file.txt")
	client.read(150)
	if _, err := appendConn.Write([]byte("!")); err != nil {
		t.Fatalf("APPE write: %v", err)
	}
	_ = appendConn.Close()
	client.read(226)
	appended := append(append([]byte{}, content...), '!')
	if got, err := os.ReadFile(filePath); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("os.ReadFile after APPE: %v", err)
	} else if !bytes.Equal(got, appended) {
		t.Fatalf("file after APPE = %q; want %q", got, appended)
	}

	client.command(350, "REST 5")
	resumeStorConn, _ := client.passiveConn()
	client.send("STOR file.txt")
	client.read(150)
	if _, err := resumeStorConn.Write([]byte("++")); err != nil {
		t.Fatalf("resumed STOR write: %v", err)
	}
	_ = resumeStorConn.Close()
	client.read(226)
	resumed := append([]byte{}, appended...)
	copy(resumed[5:], []byte("++"))
	if got, err := os.ReadFile(filePath); err != nil { //nolint:gosec // path under t.TempDir()
		t.Fatalf("os.ReadFile after resumed STOR: %v", err)
	} else if !bytes.Equal(got, resumed) {
		t.Fatalf("file after resumed STOR = %q; want %q", got, resumed)
	}

	client.command(550, "MDTM missing.txt")

	mkdirMsg := client.command(257, "MKD made")
	if !strings.Contains(mkdirMsg, `"/made"`) {
		t.Fatalf("MKD response = %q; want created /made path", mkdirMsg)
	}
	client.command(550, "MKD made")
	client.command(250, "RMD made")
	client.command(550, "RMD made")

	client.command(503, "RNTO renamed.txt")
	client.command(550, "RNFR missing.txt")
	client.command(350, "RNFR rename-src.txt")
	client.command(250, "RNTO renamed.txt")
	if _, err := os.Stat(filepath.Join(root, "renamed.txt")); err != nil {
		t.Fatalf("renamed file stat: %v", err)
	}
	client.command(250, "DELE renamed.txt")
	client.command(550, "DELE renamed.txt")
}

func TestFTPServer_CommandPermissionDenials(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("contents"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o750); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}

	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"blocked": {Password: "blockedpw", Root: root},
	}, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("blocked", "blockedpw")

	client.command(550, "CWD dir")
	client.command(550, "LIST")
	client.command(550, "RETR file.txt")
	client.command(550, "STOR upload.txt")
	client.command(550, "SIZE file.txt")
	client.command(550, "MDTM file.txt")
	client.command(550, "MFMT 20240103040506 file.txt")
	client.command(550, "DELE file.txt")
	client.command(550, "MKD made")
	client.command(550, "RMD dir")
	client.command(550, "RNFR file.txt")
	client.command(550, "RNTO renamed.txt")
}

//nolint:gocognit,cyclop,funlen // covers EPSV/EPRT/MLST/MLSD/LANG/HOST in one walking scenario
func TestFTPServer_ExtendedCommands(t *testing.T) {
	root := t.TempDir()
	content := []byte("hello mlsd world")
	if err := os.WriteFile(filepath.Join(root, "file.txt"), content, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	mtime := time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(root, "file.txt"), mtime, mtime); err != nil {
		t.Fatalf("os.Chtimes: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o750); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}

	_, addr, stop := startTestFTPServer(t, map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)

	// HELP / STAT / HOST / LANG work before login.
	helpMsg := client.command(214, "HELP")
	if !strings.Contains(helpMsg, "MLSD") || !strings.Contains(helpMsg, "STAT") {
		t.Fatalf("HELP response = %q; want MLSD and STAT advertised", helpMsg)
	}
	client.command(214, "HELP RETR")
	preLoginStat := client.command(211, "STAT")
	if !strings.Contains(preLoginStat, "Connected from") {
		t.Fatalf("STAT pre-login response = %q; want connection status", preLoginStat)
	}
	client.command(220, "HOST example.com")
	client.command(501, "HOST ")
	client.command(200, "LANG")
	client.command(200, "LANG en-US")
	client.command(504, "LANG fr")

	// FEAT must advertise the new capabilities.
	features := client.command(211, "FEAT")
	for _, want := range []string{"MLST", "MLSD", "TVFS", "LANG", "HOST"} {
		if !strings.Contains(features, want) {
			t.Fatalf("FEAT response = %q; want %s advertised", features, want)
		}
	}

	client.login("ftpuser", "ftppw")

	// HOST after login is rejected.
	client.command(503, "HOST other.example.com")

	// SITE refuses cleanly with 502.
	client.command(502, "SITE CHMOD 600 file.txt")

	// MFMT validates timestamp/path syntax; MFCT remains unsupported.
	client.command(501, "MFMT 20240101000000")
	client.command(501, "MFMT not-a-time file.txt")
	client.command(501, "MFMT 00010101000000 file.txt")
	client.command(501, "MFMT 99990101000000 file.txt")
	client.command(502, "MFCT 20240101000000 file.txt")

	// MLST returns a single-entry multi-line 250 reply.
	mlstResp := client.command(250, "MLST file.txt")
	if !strings.Contains(mlstResp, "type=file") {
		t.Fatalf("MLST response = %q; want type=file", mlstResp)
	}
	if !strings.Contains(mlstResp, "size="+strconv.Itoa(len(content))) {
		t.Fatalf("MLST response = %q; want size=%d", mlstResp, len(content))
	}
	if !strings.Contains(mlstResp, "modify=20240607080910") {
		t.Fatalf("MLST response = %q; want modify=20240607080910", mlstResp)
	}
	if !strings.Contains(mlstResp, "perm=") {
		t.Fatalf("MLST response = %q; want perm fact", mlstResp)
	}

	// MLSD opens a data connection and lists directory entries with facts.
	mlsdConn, _ := client.passiveConn()
	client.send("MLSD /")
	client.read(150)
	mlsdData, err := io.ReadAll(mlsdConn)
	if err != nil {
		t.Fatalf("io.ReadAll(MLSD): %v", err)
	}
	_ = mlsdConn.Close()
	client.read(226)
	mlsd := string(mlsdData)
	if !strings.Contains(mlsd, "type=file") || !strings.Contains(mlsd, "file.txt") {
		t.Fatalf("MLSD listing = %q; want file.txt with type=file", mlsd)
	}
	if !strings.Contains(mlsd, "type=dir") || !strings.Contains(mlsd, "sub") {
		t.Fatalf("MLSD listing = %q; want sub with type=dir", mlsd)
	}

	// MLSD on a regular file is rejected.
	client.command(501, "MLSD file.txt")

	// STAT with a path returns an inline listing without a data connection.
	statListing := client.command(213, "STAT /")
	if !strings.Contains(statListing, "file.txt") {
		t.Fatalf("STAT path response = %q; want file.txt", statListing)
	}

	// REIN returns to the unauthenticated state; commands that need auth
	// should then be rejected until a new login.
	client.command(220, "REIN")
	client.command(530, "PWD")
	client.login("ftpuser", "ftppw")
	client.command(257, "PWD")

	// Unknown commands still get the generic 502.
	client.command(502, "FOOBAR")
}

// ---- CRLF/control-byte sanitization tests ----

func TestSanitizeFTPText(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"normal.txt", "normal.txt"},
		{"with\rCR", "with?CR"},
		{"with\nLF", "with?LF"},
		{"with\r\nboth", "with??both"},
		{"tab\there", "tab?here"},
		{"del\x7Fhere", "del?here"},
		{"null\x00byte", "null?byte"},
		{"", ""},
		{"αβγ", "αβγ"}, // multi-byte UTF-8 (all bytes ≥ 0x80) passes through
	}
	for _, tc := range cases {
		if got := sanitizeFTPText(tc.in); got != tc.want {
			t.Errorf("sanitizeFTPText(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestHasCRLF(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"normal", false},
		{"with\rCR", true},
		{"with\nLF", true},
		{"with\r\nboth", true},
		{"tab\there", false}, // tab is a control byte but not CR/LF
		{"", false},
	}
	for _, tc := range cases {
		if got := hasCRLF(tc.in); got != tc.want {
			t.Errorf("hasCRLF(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func TestFtpQuotePath_SanitizesControlBytes(t *testing.T) {
	if got, want := ftpQuotePath("/foo\r\nbar"), `"/foo??bar"`; got != want {
		t.Errorf("ftpQuotePath CR/LF = %q; want %q", got, want)
	}
	if got, want := ftpQuotePath(`/has"quote`), `"/has""quote"`; got != want {
		t.Errorf("ftpQuotePath quote escape = %q; want %q", got, want)
	}
	if got, want := ftpQuotePath("/clean"), `"/clean"`; got != want {
		t.Errorf("ftpQuotePath clean = %q; want %q", got, want)
	}
}

// TestFTPServer_RejectsCRLFInWriteCommands verifies that STOR, MKD, and RNTO
// reject a bare CR in the client-supplied filename. The CR survives the
// CRLF-framed control read (only the trailing CR is trimmed), so without
// explicit rejection at the write commands a hostile client could create a
// file whose name later forges reply lines when echoed back via PWD/MKD or
// LIST.
func TestFTPServer_RejectsCRLFInWriteCommands(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "renameable.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestFTPServer(t, users, "5000-5010")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("u", "p")

	// STOR
	client.command(553, "STOR foo\rbar")
	// MKD
	client.command(553, "MKD foo\rbar")
	// RNFR + RNTO
	client.command(350, "RNFR renameable.txt")
	client.command(553, "RNTO foo\rbar")

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("os.ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "renameable.txt" {
		t.Fatalf("root contents = %v; want only renameable.txt (no CR-named entries created)", entries)
	}
}

// FuzzUnquoteFTPPath confirms the path-unquoter is panic-safe across
// arbitrary inputs (well-formed, unterminated, embedded quotes).
func FuzzUnquoteFTPPath(f *testing.F) {
	f.Add(`plain.txt`)
	f.Add(`"quoted"`)
	f.Add(`"with""quote"`)
	f.Add(`"unterminated`)
	f.Add(`""`)
	f.Add(``)
	f.Add(` "leading space" `)
	f.Add("\"\r\n\"")

	f.Fuzz(func(_ *testing.T, p string) {
		_ = unquoteFTPPath(p)
	})
}

// FuzzListPathArg confirms that option parsing only removes a prefix and that
// a pathname without options is preserved byte for byte.
func FuzzListPathArg(f *testing.F) {
	f.Add("-la /tmp")
	f.Add("")
	f.Add("---")
	f.Add("-")
	f.Add("file with spaces")
	f.Add("-x -y -z")
	f.Add("\t-la\t/incoming\t")
	f.Add("-- -file with spaces ")

	f.Fuzz(func(t *testing.T, arg string) {
		got := listPathArg(arg)
		if !strings.HasSuffix(arg, got) {
			t.Fatalf("listPathArg(%q) = %q; result must be an unchanged suffix", arg, got)
		}
		if !strings.HasPrefix(arg, "-") && got != arg {
			t.Fatalf("listPathArg(%q) = %q; pathname was changed", arg, got)
		}
	})
}

// TestFTPServer_REINClearsEpsvAll verifies that REIN flushes the
// EPSV-ALL latch so a re-authenticated session may use PORT/EPRT again.
// Without the reset, a long-lived control connection that ever issued
// EPSV ALL would be locked into passive mode forever.
func TestFTPServer_REINClearsEpsvAll(t *testing.T) {
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

	client.command(220, "REIN")
	client.login("u", "p")

	ln := client.activePORTListener()
	_ = ln.Close()
	ln2 := client.activeEPRTListener()
	_ = ln2.Close()
}

// ---- cmdMode / cmdStru / cmdOpts ----

// TestFTPSession_CmdMode verifies that only STREAM mode ("S", case-insensitive,
// surrounding whitespace ignored) is accepted; anything else is refused with
// 504.
func TestFTPSession_CmdMode(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "stream", arg: "S", want: "200 mode set\r\n"},
		{name: "stream lowercase", arg: "s", want: "200 mode set\r\n"},
		{name: "stream padded", arg: "  S  ", want: "200 mode set\r\n"},
		{name: "block", arg: "B", want: "504 unsupported mode\r\n"},
		{name: "compressed", arg: "C", want: "504 unsupported mode\r\n"},
		{name: "empty", arg: "", want: "504 unsupported mode\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			newReplyCaptureSession(&buf).cmdMode(tc.arg)
			if got := buf.String(); got != tc.want {
				t.Fatalf("cmdMode(%q) reply = %q; want %q", tc.arg, got, tc.want)
			}
		})
	}
}

// TestFTPSession_CmdStru verifies that only FILE structure ("F",
// case-insensitive, whitespace ignored) is accepted; anything else is refused
// with 504.
func TestFTPSession_CmdStru(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "file", arg: "F", want: "200 structure set\r\n"},
		{name: "file lowercase", arg: "f", want: "200 structure set\r\n"},
		{name: "file padded", arg: " F ", want: "200 structure set\r\n"},
		{name: "record", arg: "R", want: "504 unsupported structure\r\n"},
		{name: "page", arg: "P", want: "504 unsupported structure\r\n"},
		{name: "empty", arg: "", want: "504 unsupported structure\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			newReplyCaptureSession(&buf).cmdStru(tc.arg)
			if got := buf.String(); got != tc.want {
				t.Fatalf("cmdStru(%q) reply = %q; want %q", tc.arg, got, tc.want)
			}
		})
	}
}

// TestFTPSession_CmdOpts verifies that only "UTF8 ON" (case-insensitive,
// whitespace ignored) is accepted; any other option string is refused with 501.
func TestFTPSession_CmdOpts(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "utf8 on", arg: "UTF8 ON", want: "200 UTF8 enabled\r\n"},
		{name: "utf8 on lowercase", arg: "utf8 on", want: "200 UTF8 enabled\r\n"},
		{name: "utf8 on padded", arg: "  UTF8 ON  ", want: "200 UTF8 enabled\r\n"},
		{name: "utf8 off", arg: "UTF8 OFF", want: "501 unsupported option\r\n"},
		{name: "other", arg: "MLST", want: "501 unsupported option\r\n"},
		{name: "empty", arg: "", want: "501 unsupported option\r\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			newReplyCaptureSession(&buf).cmdOpts(tc.arg)
			if got := buf.String(); got != tc.want {
				t.Fatalf("cmdOpts(%q) reply = %q; want %q", tc.arg, got, tc.want)
			}
		})
	}
}
