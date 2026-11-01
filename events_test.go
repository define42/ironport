package ironport

import (
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSFTPServer_AuthEventsLoginSuccessAndLogout(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "rightpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("rightpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}

	login := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginSuccess, "testuser", CompletedUploadProtocolSFTP, "")
	if login.ClientIP == "" {
		t.Fatal("LoginSuccess ClientIP is empty; want non-empty")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("ssh client Close: %v", err)
	}
	logout := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLogout, "testuser", CompletedUploadProtocolSFTP, "")
	if logout.ClientIP == "" {
		t.Fatal("Logout ClientIP is empty; want non-empty")
	}
}

func TestSFTPServer_AuthEventsPasswordLoginFailed(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "rightpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("wrongpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	if conn, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		_ = conn.Close()
		t.Fatal("expected authentication error, got nil")
	}

	failed := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginFailed, "testuser", CompletedUploadProtocolSFTP, AuthFailureCredentials)
	if failed.ClientIP == "" {
		t.Fatal("LoginFailed ClientIP is empty; want non-empty")
	}
}

func TestSFTPServer_AuthEventsPublicKeyLoginFailed(t *testing.T) {
	root := t.TempDir()
	_, authorizedPubKey := testClientKey(t)
	wrongSigner, _ := testClientKey(t)
	users := map[string]UserInfo{
		"keyuser": {AuthorizedKeys: []ssh.PublicKey{authorizedPubKey}, Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "keyuser",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(wrongSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	if conn, err := ssh.Dial("tcp", addr, sshCfg); err == nil {
		_ = conn.Close()
		t.Fatal("expected public-key authentication error, got nil")
	}

	failed := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginFailed, "keyuser", CompletedUploadProtocolSFTP, AuthFailureCredentials)
	if failed.ClientIP == "" {
		t.Fatal("LoginFailed ClientIP is empty; want non-empty")
	}
}

// TestCompletedUploadsBufferSize verifies that NewServer controls the buffer
// capacity of the CompletedUploads channel.
func TestCompletedUploadsBufferSize(t *testing.T) {
	signer := testSigner(t)
	users := map[string]UserInfo{
		"u": {Password: "pw", Root: t.TempDir(), CanWrite: true},
	}

	// Default capacity: a non-positive config value selects defaultCompletedUploadsSize.
	config := DefaultConfig()
	config.SftpAddr = ":0"
	config.FtpPassivePortRange = ""
	config.Users = users
	config.SftpSigner = signer
	config.CompletedUploadSize = 0
	srv := NewServer(config)
	if cap(srv.CompletedUploads()) != defaultCompletedUploadsSize {
		t.Errorf("default cap = %d; want %d", cap(srv.CompletedUploads()), defaultCompletedUploadsSize)
	}

	// Custom capacity via NewServer config.
	config2 := DefaultConfig()
	config2.SftpAddr = ":0"
	config2.FtpPassivePortRange = ""
	config2.Users = users
	config2.SftpSigner = signer
	config2.CompletedUploadSize = 256
	srv2 := NewServer(config2)
	if cap(srv2.CompletedUploads()) != 256 {
		t.Errorf("custom cap via NewServer = %d; want 256", cap(srv2.CompletedUploads()))
	}

	if srv2.completedUploadsChan() != srv2.completedUploads {
		t.Error("completedUploadsChan did not return the server upload channel")
	}
}

// TestAuthEventsBufferSize verifies that NewServer controls the buffer
// capacity of the AuthEvents channel.
func TestAuthEventsBufferSize(t *testing.T) {
	signer := testSigner(t)
	users := map[string]UserInfo{
		"u": {Password: "pw", Root: t.TempDir(), CanWrite: true},
	}

	// Default capacity: a non-positive config value selects defaultAuthEventsSize.
	config := DefaultConfig()
	config.SftpAddr = ":0"
	config.FtpPassivePortRange = ""
	config.Users = users
	config.SftpSigner = signer
	config.AuthEventSize = 0
	srv := NewServer(config)
	if cap(srv.AuthEvents()) != defaultAuthEventsSize {
		t.Errorf("default cap = %d; want %d", cap(srv.AuthEvents()), defaultAuthEventsSize)
	}

	// Custom capacity via NewServer config.
	config2 := DefaultConfig()
	config2.SftpAddr = ":0"
	config2.FtpPassivePortRange = ""
	config2.Users = users
	config2.SftpSigner = signer
	config2.AuthEventSize = 256
	srv2 := NewServer(config2)
	if cap(srv2.AuthEvents()) != 256 {
		t.Errorf("custom cap via NewServer = %d; want 256", cap(srv2.AuthEvents()))
	}

	if srv2.authEventsChan() != srv2.authEvents {
		t.Error("authEventsChan did not return the server auth event channel")
	}
}

func TestFTPSessionAnnounceUploadUsesCapturedCompletedUploads(t *testing.T) {
	serverUploads := make(chan CompletedUpload, 1)
	sessionUploads := make(chan CompletedUpload, 1)
	fs := &ftpSession{
		server: &Server{
			completedUploads: serverUploads,
		},
		username: "alice",
		clientIP: "127.0.0.1",
		uploads:  sessionUploads,
	}

	fs.announceUpload("/upload.txt", "/srv/upload.txt")

	select {
	case got := <-sessionUploads:
		if got.Username != "alice" {
			t.Errorf("Username = %q; want alice", got.Username)
		}
		if got.FilePath != "/upload.txt" {
			t.Errorf("FilePath = %q; want /upload.txt", got.FilePath)
		}
		if got.FullFilePath != "/srv/upload.txt" {
			t.Errorf("FullFilePath = %q; want /srv/upload.txt", got.FullFilePath)
		}
		if got.Protocol != CompletedUploadProtocolFTP {
			t.Errorf("Protocol = %q; want %q", got.Protocol, CompletedUploadProtocolFTP)
		}
	case <-time.After(time.Second):
		t.Fatal("expected CompletedUpload on captured FTP session channel")
	}

	select {
	case got := <-serverUploads:
		t.Fatalf("announceUpload sent to server CompletedUploads after session capture: %+v", got)
	default:
	}
}

func TestFTPSessionAnnounceAuthEventUsesCapturedAuthEvents(t *testing.T) {
	serverEvents := make(chan AuthEvent, 1)
	sessionEvents := make(chan AuthEvent, 1)
	fs := &ftpSession{
		server: &Server{
			authEvents: serverEvents,
		},
		username:   "alice",
		clientIP:   "127.0.0.1",
		authEvents: sessionEvents,
	}

	fs.announceAuthEvent(AuthEventLoginSuccess)

	select {
	case got := <-sessionEvents:
		if got.Type != AuthEventLoginSuccess {
			t.Errorf("Type = %q; want %q", got.Type, AuthEventLoginSuccess)
		}
		if got.Username != "alice" {
			t.Errorf("Username = %q; want alice", got.Username)
		}
		if got.ClientIP != "127.0.0.1" {
			t.Errorf("ClientIP = %q; want 127.0.0.1", got.ClientIP)
		}
		if got.Protocol != CompletedUploadProtocolFTP {
			t.Errorf("Protocol = %q; want %q", got.Protocol, CompletedUploadProtocolFTP)
		}
	case <-time.After(time.Second):
		t.Fatal("expected AuthEvent on captured FTP session channel")
	}

	requireNoAuthEvent(t, serverEvents)
}

func TestAnnounceAuthEventDropsWhenQueueFull(t *testing.T) {
	events := make(chan AuthEvent, 1)
	first := AuthEvent{Type: AuthEventLoginSuccess, Username: "first", Protocol: CompletedUploadProtocolSFTP}
	events <- first

	announceAuthEvent(events, AuthEvent{Type: AuthEventLoginFailed, Username: "second", Protocol: CompletedUploadProtocolSFTP})

	select {
	case got := <-events:
		if got != first {
			t.Fatalf("queued event = %+v; want original %+v", got, first)
		}
	default:
		t.Fatal("expected original event to remain queued")
	}
	requireNoAuthEvent(t, events)
}

func TestFTPSessionAnnounceUploadDefersTempAndDropsWhenQueueFull(t *testing.T) {
	uploads := make(chan CompletedUpload, 1)
	first := CompletedUpload{Username: "first", FilePath: "/first.txt", Protocol: CompletedUploadProtocolFTP}
	uploads <- first
	fs := &ftpSession{
		username: "alice",
		clientIP: "127.0.0.1",
		tempExts: []string{".tmp"},
		uploads:  uploads,
	}

	fs.announceUpload("/deferred.tmp", "/srv/deferred.tmp")
	fs.announceUpload("/dropped.txt", "/srv/dropped.txt")

	select {
	case got := <-uploads:
		if got != first {
			t.Fatalf("queued upload = %+v; want original %+v", got, first)
		}
	default:
		t.Fatal("expected original upload to remain queued")
	}
	select {
	case got := <-uploads:
		t.Fatalf("unexpected additional upload event: %+v", got)
	default:
	}
}

func TestFTPServer_AuthEventsLoginSuccess(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}

	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("ftpuser", "ftppw")

	login := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginSuccess, "ftpuser", CompletedUploadProtocolFTP, "")
	if login.ClientIP == "" {
		t.Fatal("LoginSuccess ClientIP is empty; want non-empty")
	}
}

func TestFTPServer_AuthEventsLoginFailed(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
	}

	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.command(331, "USER ftpuser")
	client.command(530, "PASS wrongpw")

	failed := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginFailed, "ftpuser", CompletedUploadProtocolFTP, AuthFailureCredentials)
	if failed.ClientIP == "" {
		t.Fatal("LoginFailed ClientIP is empty; want non-empty")
	}
}

func TestFTPServer_AuthEventsLogoutOnQuitAndDisconnect(t *testing.T) {
	t.Run("quit", func(t *testing.T) {
		root := t.TempDir()
		users := map[string]UserInfo{
			"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
		}

		srv, addr, stop := startTestFTPServer(t, users, "")
		t.Cleanup(stop)

		client := dialFTP(t, addr)
		client.login("ftpuser", "ftppw")
		requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginSuccess, "ftpuser", CompletedUploadProtocolFTP, "")

		client.command(221, "QUIT")
		logout := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLogout, "ftpuser", CompletedUploadProtocolFTP, "")
		if logout.ClientIP == "" {
			t.Fatal("Logout ClientIP is empty; want non-empty")
		}
	})

	t.Run("disconnect", func(t *testing.T) {
		root := t.TempDir()
		users := map[string]UserInfo{
			"ftpuser": {Password: "ftppw", Root: root, CanRead: true, CanWrite: true},
		}

		srv, addr, stop := startTestFTPServer(t, users, "")
		t.Cleanup(stop)

		client := dialFTP(t, addr)
		client.login("ftpuser", "ftppw")
		requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginSuccess, "ftpuser", CompletedUploadProtocolFTP, "")

		_ = client.tp.Close()
		logout := requireAuthEventReason(t, srv.AuthEvents(), AuthEventLogout, "ftpuser", CompletedUploadProtocolFTP, "")
		if logout.ClientIP == "" {
			t.Fatal("Logout ClientIP is empty; want non-empty")
		}
	})
}

func TestFTPServer_AuthEventsUserLogsOutPreviousSession(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
		"bob":   {Password: "bobpw", Root: root, CanRead: true, CanWrite: true},
	}

	srv, addr, stop := startTestFTPServer(t, users, "")
	t.Cleanup(stop)

	client := dialFTP(t, addr)
	client.login("alice", "alicepw")
	requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginSuccess, "alice", CompletedUploadProtocolFTP, "")

	client.command(331, "USER bob")
	requireAuthEventReason(t, srv.AuthEvents(), AuthEventLogout, "alice", CompletedUploadProtocolFTP, "")

	client.command(230, "PASS bobpw")
	requireAuthEventReason(t, srv.AuthEvents(), AuthEventLoginSuccess, "bob", CompletedUploadProtocolFTP, "")
	client.command(221, "QUIT")
	requireAuthEventReason(t, srv.AuthEvents(), AuthEventLogout, "bob", CompletedUploadProtocolFTP, "")
}

// TestSFTPServer_CompletedUploadsQueue verifies that after a file upload finishes
// the server announces the SFTP path on the CompletedUploads channel.
//
//nolint:gocognit // verifies queue semantics under back-pressure across multiple uploads
func TestSFTPServer_CompletedUploadsQueue(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload two files and close each one to trigger the completion signal.
	for _, name := range []string{"/first.txt", "/second.txt"} {
		f, err := client.Create(name)
		if err != nil {
			t.Fatalf("client.Create(%q): %v", name, err)
		}
		if _, err = f.Write([]byte("data")); err != nil {
			t.Fatalf("f.Write: %v", err)
		}
		if err = f.Close(); err != nil {
			t.Fatalf("f.Close: %v", err)
		}

		select {
		case got := <-srv.CompletedUploads():
			if got.FilePath != name {
				t.Errorf("CompletedUploads received FilePath %q; want %q", got.FilePath, name)
			}
			if got.Username != "testuser" {
				t.Errorf("CompletedUploads Username = %q; want %q", got.Username, "testuser")
			}
			wantFull := filepath.Join(root, name)
			if got.FullFilePath != wantFull {
				t.Errorf("CompletedUploads FullFilePath = %q; want %q", got.FullFilePath, wantFull)
			}
			if got.ClientIP == "" {
				t.Errorf("CompletedUploads ClientIP is empty; want non-empty")
			}
			if got.Protocol != CompletedUploadProtocolSFTP {
				t.Errorf("CompletedUploads Protocol = %q; want %q", got.Protocol, CompletedUploadProtocolSFTP)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for CompletedUploads signal for %q", name)
		}
	}
}

// ---- TempExtensions tests ----

// TestHasTempExt covers the case-insensitive matching of temp extensions.
func TestHasTempExt(t *testing.T) {
	exts := []string{".tmp", ".writing"}
	cases := []struct {
		name string
		want bool
	}{
		{"foo.tmp", true},
		{"foo.TMP", true},
		{"path/to/foo.writing", true},
		{"foo.txt", false},
		{"foo.tmp.bak", false},
		{"", false},
	}
	for _, c := range cases {
		if got := hasTempExt(c.name, exts); got != c.want {
			t.Errorf("hasTempExt(%q) = %v; want %v", c.name, got, c.want)
		}
	}
	// Nil ext list never matches.
	if hasTempExt("foo.tmp", nil) {
		t.Error("hasTempExt with nil exts should return false")
	}
}

// TestHasDotPrefix covers detection of dotfiles (names whose final path
// element begins with ".").
func TestHasDotPrefix(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{".hidden", true},
		{"/.hidden", true},
		{"/path/to/.hidden", true},
		{".foo.txt", true},
		{"foo.txt", false},
		{"/path/to/foo.txt", false},
		{"/", false},
		{"", false},
	}
	for _, c := range cases {
		if got := hasDotPrefix(c.name); got != c.want {
			t.Errorf("hasDotPrefix(%q) = %v; want %v", c.name, got, c.want)
		}
	}
}

// TestShouldDeferCompletion verifies that completion is deferred for both temp
// extensions and dotfiles, including when no temp extensions are configured.
func TestShouldDeferCompletion(t *testing.T) {
	exts := []string{".tmp"}
	cases := []struct {
		name string
		exts []string
		want bool
	}{
		{"foo.tmp", exts, true},
		{"/path/.hidden", exts, true},
		{"/path/.hidden", nil, true},
		{"foo.txt", exts, false},
		{"foo.txt", nil, false},
	}
	for _, c := range cases {
		if got := shouldDeferCompletion(c.name, c.exts); got != c.want {
			t.Errorf("shouldDeferCompletion(%q, %v) = %v; want %v", c.name, c.exts, got, c.want)
		}
	}
}

// TestSFTPServer_Dotfile_SuppressesUploadAndAnnouncesOnRename verifies that a
// file uploaded with a leading-dot name is not announced on CompletedUploads,
// and that renaming it to a non-dot name produces the notification. No temp
// extensions are configured, proving dotfile handling is independent.
func TestSFTPServer_Dotfile_SuppressesUploadAndAnnouncesOnRename(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	srv, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a dotfile — must NOT be announced.
	dotName := "/.foo.txt"
	f, err := client.Create(dotName)
	if err != nil {
		t.Fatalf("client.Create(%q): %v", dotName, err)
	}
	if _, err = f.Write([]byte("hello")); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("f.Close: %v", err)
	}

	select {
	case got := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received %+v for a dotfile upload; expected suppression", got)
	case <-time.After(300 * time.Millisecond):
		// expected: nothing
	}

	// Rename to non-dot name — must announce the new path.
	finalName := "/foo.txt"
	if err := client.Rename(dotName, finalName); err != nil {
		t.Fatalf("client.Rename(%q, %q): %v", dotName, finalName, err)
	}

	select {
	case got := <-srv.CompletedUploads():
		if got.FilePath != finalName {
			t.Errorf("CompletedUploads FilePath = %q; want %q", got.FilePath, finalName)
		}
		if got.Protocol != CompletedUploadProtocolSFTP {
			t.Errorf("CompletedUploads Protocol = %q; want %q", got.Protocol, CompletedUploadProtocolSFTP)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CompletedUploads signal for renamed file %q", finalName)
	}
}

// TestSFTPServer_DotDirectoryRename_NotAnnounced verifies that renaming a
// hidden directory (for example /.staging -> /staging) is NOT announced on
// CompletedUploads. jailfs.FS.Rename permits directory renames, and the leading
// dot would otherwise mark the source as deferred; the destination being a
// directory rather than a regular file must suppress the upload event.
func TestSFTPServer_DotDirectoryRename_NotAnnounced(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	srv, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	dotDir := "/.staging"
	if err := client.Mkdir(dotDir); err != nil {
		t.Fatalf("client.Mkdir(%q): %v", dotDir, err)
	}

	finalDir := "/staging"
	if err := client.Rename(dotDir, finalDir); err != nil {
		t.Fatalf("client.Rename(%q, %q): %v", dotDir, finalDir, err)
	}

	select {
	case got := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received %+v for a directory rename; expected suppression", got)
	case <-time.After(300 * time.Millisecond):
		// expected: nothing
	}
}

// TestSFTPServer_TempExtensions_SuppressesUploadAndAnnouncesOnRename verifies
// the end-to-end flow: a file uploaded with a temp extension does NOT produce
// a CompletedUploads notification, and renaming it to its final name does.
//
//nolint:gocognit // upload-then-rename flow with event-channel assertions in a single scenario
func TestSFTPServer_TempExtensions_SuppressesUploadAndAnnouncesOnRename(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.TempExtensions = []string{".tmp", ".writing"}
	srv, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file with a temp extension — must NOT be announced.
	tmpName := "/foo.txt.tmp"
	f, err := client.Create(tmpName)
	if err != nil {
		t.Fatalf("client.Create(%q): %v", tmpName, err)
	}
	if _, err = f.Write([]byte("hello")); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("f.Close: %v", err)
	}

	select {
	case got := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received %+v for a temp-extension upload; expected suppression", got)
	case <-time.After(300 * time.Millisecond):
		// expected: nothing
	}

	// Rename to final name — must announce the new path on CompletedUploads.
	finalName := "/foo.txt"
	if err := client.Rename(tmpName, finalName); err != nil {
		t.Fatalf("client.Rename(%q, %q): %v", tmpName, finalName, err)
	}

	select {
	case got := <-srv.CompletedUploads():
		if got.FilePath != finalName {
			t.Errorf("CompletedUploads FilePath = %q; want %q", got.FilePath, finalName)
		}
		if got.Username != "testuser" {
			t.Errorf("CompletedUploads Username = %q; want %q", got.Username, "testuser")
		}
		wantFull := filepath.Join(root, finalName)
		if got.FullFilePath != wantFull {
			t.Errorf("CompletedUploads FullFilePath = %q; want %q", got.FullFilePath, wantFull)
		}
		if got.ClientIP == "" {
			t.Errorf("CompletedUploads ClientIP is empty; want non-empty")
		}
		if got.Protocol != CompletedUploadProtocolSFTP {
			t.Errorf("CompletedUploads Protocol = %q; want %q", got.Protocol, CompletedUploadProtocolSFTP)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CompletedUploads signal for renamed file %q", finalName)
	}
}

// TestSFTPServer_TempExtensions_RenameBetweenTempNamesDoesNotAnnounce verifies
// that renaming a temp file to another temp name (e.g. .tmp -> .writing) does
// not produce a CompletedUploads notification.
func TestSFTPServer_TempExtensions_RenameBetweenTempNamesDoesNotAnnounce(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.TempExtensions = []string{".tmp", ".writing"}
	srv, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload .tmp file (suppressed).
	if f, err := client.Create("/foo.tmp"); err != nil {
		t.Fatalf("create: %v", err)
	} else {
		_, _ = f.Write([]byte("x"))
		_ = f.Close()
	}
	// Rename .tmp -> .writing (still temp): no notification expected.
	if err := client.Rename("/foo.tmp", "/foo.writing"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	select {
	case got := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received %+v; expected no notification for temp->temp rename", got)
	case <-time.After(300 * time.Millisecond):
		// expected
	}
}

// TestSFTPServer_TempExtensions_PlainUploadStillAnnounced verifies that
// configuring TempExtensions does not break notifications for normal uploads.
func TestSFTPServer_TempExtensions_PlainUploadStillAnnounced(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.TempExtensions = []string{".tmp", ".writing"}
	srv, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	name := "/plain.txt"
	f, err := client.Create(name)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, _ = f.Write([]byte("hi"))
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case got := <-srv.CompletedUploads():
		if got.FilePath != name {
			t.Errorf("CompletedUploads FilePath = %q; want %q", got.FilePath, name)
		}
		if got.Protocol != CompletedUploadProtocolSFTP {
			t.Errorf("CompletedUploads Protocol = %q; want %q", got.Protocol, CompletedUploadProtocolSFTP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CompletedUploads for plain upload")
	}
}

// TestSFTPServer_WriterUploadChtimesAndRename verifies the common workflow of
// uploading to a .writer temp name, setting the final modification time, then
// renaming away the .writer suffix to announce completion.
func TestSFTPServer_WriterUploadChtimesAndRename(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.TempExtensions = []string{".writer"}
	srv, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	tempName := "/report.csv.writer"
	finalName := "/report.csv"
	content := []byte("id,name\n1,alice\n")
	f, err := client.Create(tempName)
	if err != nil {
		t.Fatalf("Create(%s): %v", tempName, err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case got := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received %+v for a .writer upload; expected suppression", got)
	case <-time.After(300 * time.Millisecond):
		// expected
	}

	wantTime := time.Unix(1_700_000_123, 0)
	if err := client.Chtimes(tempName, wantTime, wantTime); err != nil {
		t.Fatalf("Chtimes(%s): %v", tempName, err)
	}
	if err := client.Rename(tempName, finalName); err != nil {
		t.Fatalf("Rename(%s, %s): %v", tempName, finalName, err)
	}

	finalFullPath := filepath.Join(root, "report.csv")
	info, err := os.Stat(finalFullPath)
	if err != nil {
		t.Fatalf("os.Stat(final): %v", err)
	}
	if !info.ModTime().Equal(wantTime) {
		t.Fatalf("final ModTime = %v; want %v", info.ModTime(), wantTime)
	}

	casePath := filepath.Join(root, "report.csv.writer")
	if _, err := os.Stat(casePath); !os.IsNotExist(err) {
		t.Fatalf(".writer temp path still exists or stat failed unexpectedly: %v", err)
	}

	assertWriterCompletedUpload(t, srv.CompletedUploads(), finalName, finalFullPath)
}

// TestSFTPServer_InterruptedUploadNotAnnounced exercises the full SFTP
// pipeline: a client opens a file, writes some bytes, then abruptly tears
// down the underlying SSH transport without calling Close on the SFTP
// handle. pkg/sftp's request server drains the in-flight request through
// transferError + Close, and writeLogger must NOT announce the upload.
func TestSFTPServer_InterruptedUploadNotAnnounced(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	sshCfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test client against in-process test server; no MITM threat
	}
	conn, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("sftp.NewClient: %v", err)
	}

	const name = "/aborted.bin"
	rf, err := client.Create(name)
	if err != nil {
		_ = client.Close()
		_ = conn.Close()
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = rf.Write([]byte("partial-data")); err != nil {
		_ = client.Close()
		_ = conn.Close()
		t.Fatalf("rf.Write: %v", err)
	}
	// Abruptly tear down the SSH transport WITHOUT closing the SFTP
	// handle. This is what happens on a client crash / network drop:
	// pkg/sftp's RequestServer sees EOF, calls transferError on the
	// in-flight write request, then Close on the writer.
	_ = conn.Close()

	select {
	case evt := <-srv.CompletedUploads():
		t.Fatalf("CompletedUploads received notification %+v for an interrupted upload; want none", evt)
	case <-time.After(500 * time.Millisecond):
		// expected: no notification for a truncated upload.
	}
}

func requireAuthEventReason(t *testing.T, events <-chan AuthEvent, eventType AuthEventType, username, protocol string, reason AuthFailureReason) AuthEvent {
	t.Helper()
	event := requireAuthEvent(t, events, eventType, username, protocol)
	if event.Reason != reason {
		t.Fatalf("AuthEvent Reason = %q; want %q (event %+v)", event.Reason, reason, event)
	}
	return event
}

func TestAuthFailureReasons(t *testing.T) {
	for _, protocol := range []string{CompletedUploadProtocolSFTP, CompletedUploadProtocolFTP, CompletedUploadProtocolHTTP} {
		t.Run(protocol, func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				throttled bool
				reason    AuthFailureReason
			}{
				{name: "credentials", reason: AuthFailureCredentials},
				{name: "throttled", throttled: true, reason: AuthFailureThrottled},
			} {
				t.Run(tc.name, func(t *testing.T) {
					server := NewServer(&Config{})
					server.authFailed(requireAuthAdmission(t, server, "alice", "192.0.2.1"), "alice", "192.0.2.1", protocol, server.authEventsChan(), tc.throttled)
					requireAuthEventReason(t, server.AuthEvents(), AuthEventLoginFailed, "alice", protocol, tc.reason)
				})
			}
		})
	}
}

func TestAuthFailureEventSampling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := NewServer(&Config{AuthEventSize: 8})
		events := server.authEventsChan()
		server.authFailed(requireAuthAdmission(t, server, "alice", "192.0.2.1"), "alice", "192.0.2.1", CompletedUploadProtocolHTTP, events, true)
		requireAuthEventReason(t, events, AuthEventLoginFailed, "alice", CompletedUploadProtocolHTTP, AuthFailureThrottled)
		// The queue is empty, but another throttled failure is still sampled out.
		server.authFailed(requireAuthAdmission(t, server, "alice", "192.0.2.1"), "alice", "192.0.2.1", CompletedUploadProtocolHTTP, events, true)
		requireNoAuthEvent(t, events)
		// Credential failures remain observable while diagnostic logs are sampled.
		server.authFailed(requireAuthAdmission(t, server, "alice", "192.0.2.1"), "alice", "192.0.2.1", CompletedUploadProtocolHTTP, events, false)
		requireAuthEventReason(t, events, AuthEventLoginFailed, "alice", CompletedUploadProtocolHTTP, AuthFailureCredentials)
		time.Sleep(time.Second)
		server.authFailed(requireAuthAdmission(t, server, "alice", "192.0.2.1"), "alice", "192.0.2.1", CompletedUploadProtocolHTTP, events, true)
		requireAuthEventReason(t, events, AuthEventLoginFailed, "alice", CompletedUploadProtocolHTTP, AuthFailureThrottled)
	})
}

func TestHTTPAuthEventsReasons(t *testing.T) {
	server := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "rightpw", Root: t.TempDir(), CanWrite: true},
	})
	doHTTPUpload(t, server, "alice", "wrongpw", "file", "failed.txt", []byte("data"))
	requireAuthEventReason(t, server.AuthEvents(), AuthEventLoginFailed, "alice", CompletedUploadProtocolHTTP, AuthFailureCredentials)
	doHTTPUpload(t, server, "alice", "rightpw", "file", "success.txt", []byte("data"))
	requireAuthEventReason(t, server.AuthEvents(), AuthEventLoginSuccess, "alice", CompletedUploadProtocolHTTP, "")
}
