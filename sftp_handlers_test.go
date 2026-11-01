package ironport

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/define42/ironport/internal/jailfs"
	"github.com/pkg/sftp"
)

func TestJailFilewriteRejectsBrokenSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideTarget := filepath.Join(outside, "newfile.txt")
	link := filepath.Join(root, "link")
	if err := os.Symlink(outsideTarget, link); err != nil {
		t.Skipf("creating symlink: %v", err)
	}

	jfs, err := jailfs.Open(root)
	if err != nil {
		t.Fatalf("jailfs.Open: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })

	j := jail{
		fs:       jfs,
		username: "testuser",
		clientIP: "127.0.0.1",
		canWrite: true,
		uploads:  make(chan CompletedUpload, 1),
	}
	_, err = j.Filewrite(&sftp.Request{Filepath: "/link"})
	if err == nil {
		t.Fatalf("Filewrite to broken symlink succeeded; want error")
	}
	if _, err := os.Stat(outsideTarget); !os.IsNotExist(err) {
		t.Fatalf("outside target was created or stat failed unexpectedly: %v", err)
	}
}

// ---- integration test: full SFTP upload / download / list ----

func TestSFTPServer_UploadDownload(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	content := []byte("hello sftp world")
	remote := "/upload.txt"
	f, err := client.Create(remote)
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	_ = f.Close()

	// Download and compare.
	rf, err := client.Open(remote)
	if err != nil {
		t.Fatalf("client.Open: %v", err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

func TestSFTPServer_List(t *testing.T) {
	root := t.TempDir()
	// Pre-create a file so we have something to list.
	if err := os.WriteFile(filepath.Join(root, "listed.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("client.ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "listed.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("ReadDir returned %v; want [listed.txt]", names)
	}
}

// TestSFTPServer_ReadOnlyUser verifies that a read-only user can download and
// list files but cannot upload or delete files.
func TestSFTPServer_ReadOnlyUser(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "data.txt"), []byte("read me"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"reader": {Password: "readpw", Root: root, CanRead: true, CanWrite: false},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "reader", "readpw")

	// Read/list must succeed.
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "data.txt" {
		t.Errorf("ReadDir returned unexpected entries")
	}

	rf, err := client.Open("/data.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if string(got) != "read me" {
		t.Errorf("downloaded %q; want %q", got, "read me")
	}

	// Write must be denied.
	_, err = client.Create("/upload.txt")
	if err == nil {
		t.Error("expected write to be denied for read-only user, got nil error")
	}

	// A denied mixed handle must not apply its truncation flag.
	if f, err := client.OpenFile("/data.txt", os.O_RDWR|os.O_TRUNC); err == nil {
		_ = f.Close()
		t.Error("expected O_RDWR open to be denied for read-only user, got nil error")
	}
	got, err = os.ReadFile(filepath.Join(root, "data.txt")) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "read me" {
		t.Fatalf("data.txt = %q after denied O_RDWR open; want %q", got, "read me")
	}
}

// TestSFTPServer_WriteOnlyUser verifies that a write-only user can upload files
// but cannot read/download or list files.
func TestSFTPServer_WriteOnlyUser(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"writer": {Password: "writepw", Root: root, CanRead: false, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "writer", "writepw")

	// Upload must succeed.
	f, err := client.Create("/upload.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("write only")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len("write only"))
	if n, err := f.ReadAt(buf, 0); !errors.Is(err, os.ErrPermission) || n != 0 {
		t.Errorf("ReadAt on write-only upload handle = %d, %v; want 0 and %v",
			n, err, os.ErrPermission)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "upload.txt")) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "write only" {
		t.Fatalf("upload.txt = %q after denied read; want %q", got, "write only")
	}

	// Read must be denied.
	_, err = client.Open("/upload.txt")
	if err == nil {
		t.Error("expected read to be denied for write-only user, got nil error")
	}

	// List must be denied.
	_, err = client.ReadDir("/")
	if err == nil {
		t.Error("expected list to be denied for write-only user, got nil error")
	}
}

// TestSFTPServer_JailedWorkingDirectory verifies that a user's working directory
// appears as "/" even though it is backed by a subdirectory on disk.
// This is the jail/chroot behaviour: Alice logs in and sees "/" as her root,
// but on disk that "/" is mounted to her actual home directory.
func TestSFTPServer_JailedWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "alice", "alicepw")

	// The initial working directory must appear as "/" to the client.
	wd, err := client.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if wd != "/" {
		t.Errorf("Getwd() = %q; want / (user must see / as their root, not the on-disk path)", wd)
	}

	// Files in the jail root must be reachable via "/filename", not via the
	// real on-disk path.
	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir(/): %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.txt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("ReadDir(/) = %v; want [file.txt]", names)
	}

	// The on-disk path must NOT be accessible as an SFTP path; it resolves
	// to a non-existent location inside the jail.
	_, err = client.ReadDir(root)
	if err == nil {
		t.Error("expected error when accessing the real on-disk path via SFTP, got nil")
	}
}

// TestSFTPServer_MkdirNoParent verifies that creating a directory whose parent
// does not yet exist returns an error instead of silently creating all
// intermediate directories (os.Mkdir semantics, not os.MkdirAll).
func TestSFTPServer_MkdirNoParent(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// "/nonexistent/child" should fail because "/nonexistent" doesn't exist.
	if err := client.Mkdir("/nonexistent/child"); err == nil {
		t.Error("expected error when creating directory with missing parent, got nil")
	}
}

// TestSFTPServer_UploadFilePermissions verifies that files created via SFTP
// are owner-readable/writable only (mode 0600), not group-readable.
func TestSFTPServer_UploadFilePermissions(t *testing.T) {
	root := t.TempDir()

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.Create("/secret.txt")
	if err != nil {
		t.Fatalf("client.Create: %v", err)
	}
	if _, err = f.Write([]byte("sensitive")); err != nil {
		t.Fatalf("f.Write: %v", err)
	}
	_ = f.Close()

	info, err := os.Stat(filepath.Join(root, "secret.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	// Mask to the permission bits only and verify owner-only access (0600).
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file permissions = %04o; want 0600", got)
	}
}

func TestSFTPServer_OpenFileAppendHonorsAppendFlag(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "append.txt"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.OpenFile("/append.txt", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatalf("OpenFile(O_APPEND): %v", err)
	}
	if _, err := f.Write([]byte(" second")); err != nil {
		_ = f.Close()
		t.Fatalf("Write append: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close append: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "append.txt")) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first second" {
		t.Fatalf("append.txt = %q; want %q", got, "first second")
	}
}

//nolint:cyclop // one end-to-end handle lifecycle verifies data, close, and event behavior
func TestSFTPServer_OpenFileReadWritePreservesData(t *testing.T) {
	root := t.TempDir()
	fullPath := filepath.Join(root, "readwrite.txt")
	if err := os.WriteFile(fullPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")
	f, err := client.OpenFile("/readwrite.txt", os.O_RDWR)
	if err != nil {
		t.Fatalf("OpenFile(O_RDWR): %v", err)
	}
	if _, err := f.WriteAt([]byte("hello"), 0); err != nil {
		_ = f.Close()
		t.Fatalf("WriteAt: %v", err)
	}

	buf := make([]byte, len("original"))
	n, readErr := f.ReadAt(buf, 0)
	if readErr != nil || n != len(buf) {
		t.Errorf("ReadAt = %d, %v; want %d, nil", n, readErr, len(buf))
	}
	if got := string(buf); got != "hellonal" {
		t.Errorf("ReadAt data = %q; want %q", got, "hellonal")
	}
	select {
	case event := <-srv.CompletedUploads():
		_ = f.Close()
		t.Fatalf("upload announced before CLOSE: %+v", event)
	default:
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(fullPath) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hellonal" {
		t.Errorf("readwrite.txt = %q; want %q", got, "hellonal")
	}
	select {
	case event := <-srv.CompletedUploads():
		if event.FilePath != "/readwrite.txt" || event.FullFilePath != fullPath ||
			event.Username != "testuser" || event.ClientIP == "" || event.Protocol != CompletedUploadProtocolSFTP {
			t.Fatalf("unexpected upload notification: %+v", event)
		}
	default:
		t.Fatal("successful CLOSE did not announce the read/write upload")
	}
	select {
	case event := <-srv.CompletedUploads():
		t.Fatalf("read/write upload announced more than once: %+v", event)
	default:
	}
}

func TestSFTPServer_OpenFileReadWriteAppend(t *testing.T) {
	root := t.TempDir()
	fullPath := filepath.Join(root, "append-readwrite.txt")
	if err := os.WriteFile(fullPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")
	f, err := client.OpenFile("/append-readwrite.txt", os.O_RDWR|os.O_APPEND)
	if err != nil {
		t.Fatalf("OpenFile(O_RDWR|O_APPEND): %v", err)
	}
	if _, err := f.WriteAt([]byte(" second"), 0); err != nil {
		_ = f.Close()
		t.Fatalf("WriteAt append: %v", err)
	}

	buf := make([]byte, len("first second"))
	if n, err := f.ReadAt(buf, 0); err != nil || n != len(buf) {
		_ = f.Close()
		t.Fatalf("ReadAt = %d, %v; want %d, nil", n, err, len(buf))
	}
	if got := string(buf); got != "first second" {
		_ = f.Close()
		t.Fatalf("ReadAt data = %q; want %q", got, "first second")
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(fullPath) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first second" {
		t.Fatalf("append-readwrite.txt = %q; want %q", got, "first second")
	}
}

func TestSFTPServer_OpenFileWriteOnlyDoesNotTruncate(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "plain.txt"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.OpenFile("/plain.txt", os.O_WRONLY)
	if err != nil {
		t.Fatalf("OpenFile(O_WRONLY): %v", err)
	}
	if _, err := f.Write([]byte("XY")); err != nil {
		_ = f.Close()
		t.Fatalf("Write plain: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close plain: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "plain.txt")) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "XYiginal" {
		t.Fatalf("plain.txt = %q; want %q", got, "XYiginal")
	}
}

func TestSFTPServer_OpenFileExclusiveCreateHonorsExcl(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "exists.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	if f, err := client.OpenFile("/exists.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL); err == nil {
		_ = f.Close()
		t.Fatal("OpenFile(O_CREATE|O_EXCL) on existing file succeeded; want error")
	}
	got, err := os.ReadFile(filepath.Join(root, "exists.txt")) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep" {
		t.Fatalf("exists.txt = %q; want %q", got, "keep")
	}

	f, err := client.OpenFile("/new.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatalf("OpenFile(O_CREATE|O_EXCL) on missing file: %v", err)
	}
	if _, err := f.Write([]byte("new")); err != nil {
		_ = f.Close()
		t.Fatalf("Write new: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close new: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(root, "new.txt")) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("new.txt = %q; want %q", got, "new")
	}
}

// TestSFTPServer_CreateFolder verifies that a directory can be successfully
// created via SFTP Mkdir, and that it is visible when listing the parent.
func TestSFTPServer_CreateFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	if err := client.Mkdir("/newdir"); err != nil {
		t.Fatalf("Mkdir(/newdir): %v", err)
	}

	entries, err := client.ReadDir("/")
	if err != nil {
		t.Fatalf("ReadDir(/): %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Name() == "newdir" && e.IsDir() {
			found = true
			break
		}
	}
	if !found {
		t.Error("created directory newdir not found in ReadDir(/)")
	}
}

// TestSFTPServer_CreateFileInFolder verifies that a file can be created inside
// a previously created subdirectory.
func TestSFTPServer_CreateFileInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	if err := client.Mkdir("/subdir"); err != nil {
		t.Fatalf("Mkdir(/subdir): %v", err)
	}

	content := []byte("file in subfolder")
	f, err := client.Create("/subdir/file.txt")
	if err != nil {
		t.Fatalf("Create(/subdir/file.txt): %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Verify by downloading.
	rf, err := client.Open("/subdir/file.txt")
	if err != nil {
		t.Fatalf("Open(/subdir/file.txt): %v", err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}
}

// TestSFTPServer_RenameFile verifies that an uploaded file can be renamed via
// the SFTP Rename command, and that the new name is accessible while the old
// name is gone.
func TestSFTPServer_RenameFile(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	content := []byte("rename me")
	f, err := client.Create("/original.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Rename it.
	if err := client.Rename("/original.txt", "/renamed.txt"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	// New name must be readable.
	rf, err := client.Open("/renamed.txt")
	if err != nil {
		t.Fatalf("Open(/renamed.txt): %v", err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}

	// Old name must no longer exist.
	if _, err := client.Stat("/original.txt"); err == nil {
		t.Error("expected error accessing old name after rename, got nil")
	}
}

// TestSFTPServer_MoveFileBetweenFolders verifies that a file can be moved from
// one existing subdirectory to another via Rename.
func TestSFTPServer_MoveFileBetweenFolders(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create source and destination directories.
	if err := client.Mkdir("/src"); err != nil {
		t.Fatalf("Mkdir(/src): %v", err)
	}
	if err := client.Mkdir("/dst"); err != nil {
		t.Fatalf("Mkdir(/dst): %v", err)
	}

	// Upload a file to the source directory.
	content := []byte("moving between folders")
	f, err := client.Create("/src/move.txt")
	if err != nil {
		t.Fatalf("Create(/src/move.txt): %v", err)
	}
	if _, err = f.Write(content); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Move the file to the destination directory.
	if err := client.Rename("/src/move.txt", "/dst/move.txt"); err != nil {
		t.Fatalf("Rename (move between folders): %v", err)
	}

	// Verify the file is now at the destination.
	rf, err := client.Open("/dst/move.txt")
	if err != nil {
		t.Fatalf("Open(/dst/move.txt): %v", err)
	}
	got, _ := io.ReadAll(rf)
	_ = rf.Close()
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded %q; want %q", got, content)
	}

	// Source must no longer exist.
	if _, err := client.Stat("/src/move.txt"); err == nil {
		t.Error("expected error accessing source after move, got nil")
	}
}

// TestSFTPServer_DeleteFileInFolder verifies that a file inside a subdirectory
// can be deleted via SFTP Remove.
func TestSFTPServer_DeleteFileInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a folder and upload a file into it.
	if err := client.Mkdir("/folder"); err != nil {
		t.Fatalf("Mkdir(/folder): %v", err)
	}
	f, err := client.Create("/folder/todelete.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("delete me")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Delete the file.
	if err := client.Remove("/folder/todelete.txt"); err != nil {
		t.Fatalf("Remove(/folder/todelete.txt): %v", err)
	}

	// Verify the file is gone.
	if _, err := client.Stat("/folder/todelete.txt"); err == nil {
		t.Error("expected error accessing deleted file, got nil")
	}
}

// TestSFTPServer_MoveFileToNonExistentFolder verifies that renaming a file into
// a directory that does not exist returns an error.
func TestSFTPServer_MoveFileToNonExistentFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/existing.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("content")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Attempt to rename into a non-existent directory; must fail.
	err = client.Rename("/existing.txt", "/nosuchdir/existing.txt")
	if err == nil {
		t.Error("expected error when moving file to non-existent folder, got nil")
	}
}

// TestSFTPServer_Chmod verifies that a chmod (Setstat with permissions) is
// applied to the file on disk.
func TestSFTPServer_Chmod(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/chmod_test.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("chmod test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Send a chmod request and verify it was applied on disk.
	if err := client.Chmod("/chmod_test.txt", 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "chmod_test.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("file mode = %o; want 0644", got)
	}
}

// TestSFTPServer_Chown verifies that a chown (Setstat with uid/gid) request is
// accepted by the server. We chown to the current uid/gid so the call does
// not require elevated privileges; this exercises the server side without
// actually changing ownership on disk.
func TestSFTPServer_Chown(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.SftpAllowChown = true
	_, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/chown_test.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("chown test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Retrieve the current owner so we can use valid uid/gid values.
	info, err := os.Stat(filepath.Join(root, "chown_test.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("cannot read uid/gid on this platform")
	}
	uid := int(stat.Uid)
	gid := int(stat.Gid)

	// Send chown with the same uid/gid; the server applies the chown and it
	// is a no-op on disk because the values are unchanged.
	if err := client.Chown("/chown_test.txt", uid, gid); err != nil {
		t.Fatalf("Chown: %v", err)
	}
}

// TestSFTPServer_Chgrp verifies that a chgrp (Setstat with a new gid) request
// is accepted by the server without error.
func TestSFTPServer_Chgrp(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	config := newTestConfig("", "", "", users, testSigner(t), defaultCompletedUploadsSize)
	config.SftpAllowChown = true
	_, addr, stop := startTestServerWithConfig(t, config)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Upload a file.
	f, err := client.Create("/chgrp_test.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write([]byte("chgrp test")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Retrieve the current owner/group so we can pass valid identifiers.
	info, err := os.Stat(filepath.Join(root, "chgrp_test.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("cannot read uid/gid on this platform")
	}
	uid := int(stat.Uid)
	gid := int(stat.Gid)

	// Chown with uid unchanged and gid unchanged acts as chgrp; the server
	// applies the change and it is a no-op on disk because the values match.
	if err := client.Chown("/chgrp_test.txt", uid, gid); err != nil {
		t.Fatalf("Chown (chgrp): %v", err)
	}
}

// TestSFTPServer_CreateFolderInFolder verifies that a subdirectory can be
// created inside an existing parent directory, and that it appears correctly
// when listing the parent's contents.
func TestSFTPServer_CreateFolderInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create the parent directory.
	if err := client.Mkdir("/parent"); err != nil {
		t.Fatalf("Mkdir(/parent): %v", err)
	}

	// Create a child directory inside the parent.
	if err := client.Mkdir("/parent/child"); err != nil {
		t.Fatalf("Mkdir(/parent/child): %v", err)
	}

	// Verify the child appears when listing the parent.
	entries, err := client.ReadDir("/parent")
	if err != nil {
		t.Fatalf("ReadDir(/parent): %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Name() == "child" && e.IsDir() {
			found = true
			break
		}
	}
	if !found {
		t.Error("child directory not found in ReadDir(/parent)")
	}
}

// TestSFTPServer_DeleteFolder verifies that an empty directory can be removed
// via SFTP RemoveDirectory and that it disappears from the listing afterwards.
func TestSFTPServer_DeleteFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create an empty directory.
	if err := client.Mkdir("/emptydir"); err != nil {
		t.Fatalf("Mkdir(/emptydir): %v", err)
	}

	// Remove it.
	if err := client.RemoveDirectory("/emptydir"); err != nil {
		t.Fatalf("RemoveDirectory(/emptydir): %v", err)
	}

	// Verify it is gone.
	if _, err := client.Stat("/emptydir"); err == nil {
		t.Error("expected error accessing removed directory, got nil")
	}
}

// TestSFTPServer_DeleteFolderInFolder verifies that a nested empty directory
// can be removed while leaving the parent directory intact.
func TestSFTPServer_DeleteFolderInFolder(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create parent and nested child directories.
	if err := client.Mkdir("/outer"); err != nil {
		t.Fatalf("Mkdir(/outer): %v", err)
	}
	if err := client.Mkdir("/outer/inner"); err != nil {
		t.Fatalf("Mkdir(/outer/inner): %v", err)
	}

	// Remove the inner (nested) directory.
	if err := client.RemoveDirectory("/outer/inner"); err != nil {
		t.Fatalf("RemoveDirectory(/outer/inner): %v", err)
	}

	// The inner directory must be gone.
	if _, err := client.Stat("/outer/inner"); err == nil {
		t.Error("expected error accessing removed nested directory, got nil")
	}

	// The outer (parent) directory must still exist.
	if _, err := client.Stat("/outer"); err != nil {
		t.Fatalf("parent directory /outer should still exist: %v", err)
	}
}

// TestSFTPServer_DeleteFolderWithFoldersInside verifies that removing a
// directory that still contains subdirectories returns an error (the server
// uses os.Remove semantics which refuses non-empty directories).
func TestSFTPServer_DeleteFolderWithFoldersInside(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a parent directory with a subdirectory inside.
	if err := client.Mkdir("/nonempty"); err != nil {
		t.Fatalf("Mkdir(/nonempty): %v", err)
	}
	if err := client.Mkdir("/nonempty/subdir"); err != nil {
		t.Fatalf("Mkdir(/nonempty/subdir): %v", err)
	}

	// Attempt to remove the non-empty parent; must fail.
	if err := client.RemoveDirectory("/nonempty"); err == nil {
		t.Error("expected error when removing non-empty directory (contains subdirs), got nil")
	}

	// Parent must still be present.
	if _, err := client.Stat("/nonempty"); err != nil {
		t.Fatalf("non-empty directory /nonempty should still exist after failed removal: %v", err)
	}
}

// TestSFTPServer_DeleteFolderWithFilesInside verifies that removing a
// directory that still contains files returns an error.
func TestSFTPServer_DeleteFolderWithFilesInside(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a directory and put a file inside.
	if err := client.Mkdir("/hasfiles"); err != nil {
		t.Fatalf("Mkdir(/hasfiles): %v", err)
	}
	f, err := client.Create("/hasfiles/content.txt")
	if err != nil {
		t.Fatalf("Create(/hasfiles/content.txt): %v", err)
	}
	if _, err = f.Write([]byte("data")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	// Attempt to remove the non-empty directory; must fail.
	if err := client.RemoveDirectory("/hasfiles"); err == nil {
		t.Error("expected error when removing non-empty directory (contains files), got nil")
	}

	// Directory and its contents must still be present.
	if _, err := client.Stat("/hasfiles"); err != nil {
		t.Fatalf("directory /hasfiles should still exist after failed removal: %v", err)
	}
	if _, err := client.Stat("/hasfiles/content.txt"); err != nil {
		t.Fatalf("file /hasfiles/content.txt should still exist after failed removal: %v", err)
	}
}

func TestJailHandlersRecoverFromPanic(t *testing.T) {
	j := jail{
		username: "testuser",
		clientIP: "127.0.0.1",
		canRead:  true,
		canWrite: true,
		uploads:  make(chan CompletedUpload, 1),
	}

	if _, err := j.Fileread(sftp.NewRequest("Get", "/panic.txt")); !errors.Is(err, errSFTPRequestFailed) {
		t.Fatalf("Fileread panic recovery err = %v; want %v", err, errSFTPRequestFailed)
	}
	if _, err := j.Filelist(sftp.NewRequest("List", "/panic")); !errors.Is(err, errSFTPRequestFailed) {
		t.Fatalf("Filelist panic recovery err = %v; want %v", err, errSFTPRequestFailed)
	}
	if err := j.Filecmd(sftp.NewRequest("Mkdir", "/panic")); !errors.Is(err, errSFTPRequestFailed) {
		t.Fatalf("Filecmd panic recovery err = %v; want %v", err, errSFTPRequestFailed)
	}
}

func TestSFTPReturnedObjectsRecoverFromPanic(t *testing.T) {
	w := &writeLogger{
		filepath: "/panic.txt",
		username: "testuser",
		clientIP: "127.0.0.1",
	}

	if _, err := w.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("WriteAt with nil file returned nil error")
	}
	if err := w.Close(); err == nil {
		t.Fatal("Close with nil file returned nil error")
	}
	if _, err := (fileInfoLister{}).ListAt(make([]os.FileInfo, 1), -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("ListAt negative offset err = %v; want %v", err, os.ErrInvalid)
	}
}

// TestSFTPServer_Setstat_TruncateAndTimes verifies that Setstat applies size
// and modification time changes to the underlying file.
func TestSFTPServer_Setstat_TruncateAndTimes(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "alice", "alicepw")

	f, err := client.Create("/setstat.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err = f.Write(bytes.Repeat([]byte{'x'}, 1024)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Truncate via Setstat.
	if err := client.Truncate("/setstat.txt", 16); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "setstat.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if info.Size() != 16 {
		t.Errorf("size = %d; want 16", info.Size())
	}

	want := time.Unix(1_700_000_000, 0)
	if err := client.Chtimes("/setstat.txt", want, want); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	info, err = os.Stat(filepath.Join(root, "setstat.txt"))
	if err != nil {
		t.Fatalf("os.Stat after Chtimes: %v", err)
	}
	if !info.ModTime().Equal(want) {
		t.Errorf("mtime = %v; want %v", info.ModTime(), want)
	}
}

// TestSFTPServer_Setstat_PermissionDeniedForReadOnly verifies that Setstat is
// rejected when the user lacks write permission, rather than silently
// pretending to succeed.
func TestSFTPServer_Setstat_PermissionDeniedForReadOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ro.txt"), []byte("ro"), 0o600); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"reader": {Password: "rpw", Root: root, CanRead: true, CanWrite: false},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "reader", "rpw")
	if err := client.Chmod("/ro.txt", 0o600); err == nil {
		t.Fatal("expected permission error for Chmod by a read-only user, got nil")
	}
}

func TestSanitizeSFTPErr(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantIs  error
		wantMsg string
	}{
		{
			name:    "not exist path error",
			err:     &os.PathError{Op: "open", Path: "/srv/sftp/alice/missing.txt", Err: os.ErrNotExist},
			wantIs:  os.ErrNotExist,
			wantMsg: "file does not exist",
		},
		{
			name:    "permission path error",
			err:     &os.PathError{Op: "stat", Path: "/srv/sftp/alice/secret.txt", Err: os.ErrPermission},
			wantIs:  os.ErrPermission,
			wantMsg: "permission denied",
		},
		{
			name:    "not a directory",
			err:     &os.PathError{Op: "opendir", Path: "/srv/sftp/alice/file", Err: syscall.ENOTDIR},
			wantIs:  syscall.ENOTDIR,
			wantMsg: "not a directory",
		},
		{
			name:    "is a directory",
			err:     &os.PathError{Op: "open", Path: "/srv/sftp/alice/dir", Err: syscall.EISDIR},
			wantIs:  syscall.EISDIR,
			wantMsg: "is a directory",
		},
		{
			name:    "directory not empty",
			err:     &os.PathError{Op: "remove", Path: "/srv/sftp/alice/dir", Err: syscall.ENOTEMPTY},
			wantIs:  syscall.ENOTEMPTY,
			wantMsg: "directory not empty",
		},
		{
			name:    "unknown path error",
			err:     &os.PathError{Op: "open", Path: "/srv/sftp/alice/secret.txt", Err: syscall.EIO},
			wantIs:  errSFTPRequestFailed,
			wantMsg: "request failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeSFTPErr(tc.err)
			if !errors.Is(got, tc.wantIs) {
				t.Fatalf("sanitizeSFTPErr(%v) = %v; want errors.Is(..., %v)", tc.err, got, tc.wantIs)
			}
			if got.Error() != tc.wantMsg {
				t.Fatalf("sanitizeSFTPErr(%v) message = %q; want %q", tc.err, got.Error(), tc.wantMsg)
			}
			if strings.Contains(got.Error(), "/srv/sftp/alice") {
				t.Fatalf("sanitizeSFTPErr(%v) leaked path in message %q", tc.err, got.Error())
			}
		})
	}
}

// TestSFTPServer_Chown_DefaultDenied verifies that a chown request is
// rejected with a permission error when config.SftpAllowChown is left at its
// default (false). This is the opt-in flag that hardens deployments where
// the server runs with enough privilege (e.g. as root) to actually change
// ownership: clients must not be able to chown jailed files unless the
// operator has explicitly enabled it.
func TestSFTPServer_Chown_DefaultDenied(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	srv, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)
	if srv.sftpChownAllowed() {
		t.Fatalf("SftpAllowChown should default to false")
	}

	client := dialSFTP(t, addr, "testuser", "testpw")

	f, err := client.Create("/chown_denied.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = f.Close()

	info, err := os.Stat(filepath.Join(root, "chown_denied.txt"))
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("cannot read uid/gid on this platform")
	}
	// Chown to the current uid/gid: this would succeed on disk (same owner),
	// so the only thing that can fail this call is the configured SftpAllowChown
	// gate. If the gate is wired up correctly we get a permission error
	// regardless of the underlying filesystem semantics.
	err = client.Chown("/chown_denied.txt", int(stat.Uid), int(stat.Gid))
	if err == nil {
		t.Fatalf("Chown succeeded with SftpAllowChown=false; want permission denied")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Errorf("Chown error = %v; want a permission denied error", err)
	}
}

// TestSFTPServer_SymlinkRejected verifies that clients cannot create symlinks
// inside their jail. Allowing symlinks would let a client plant a link
// pointing outside the jail root that a subsequent request could follow,
// bypassing the path-containment checks in jail.resolve.
func TestSFTPServer_SymlinkRejected(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"testuser": {Password: "testpw", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "testuser", "testpw")

	// Create a target file so the symlink would otherwise be valid.
	f, err := client.Create("/target.txt")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = f.Close()

	err = client.Symlink("/target.txt", "/link.txt")
	if err == nil {
		t.Fatalf("Symlink unexpectedly succeeded; want permission denied")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Errorf("Symlink error = %v; want a permission denied error", err)
	}
	// Confirm no link was created on disk.
	if _, err := os.Lstat(filepath.Join(root, "link.txt")); !os.IsNotExist(err) {
		t.Errorf("link.txt exists on disk after rejected Symlink: err=%v", err)
	}
}

func TestWriteLogger_WriteFailureSuppressesNotification(t *testing.T) {
	for _, tc := range []struct {
		name       string
		appendMode bool
	}{
		{"ordinary", false},
		{"append", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := os.O_RDONLY
			if tc.appendMode {
				flags |= os.O_APPEND
			}
			wl, uploads, _ := newWriteLoggerFailureFixture(t, flags, tc.appendMode)
			n, firstErr := wl.WriteAt([]byte("first"), 0)
			if n != 0 || !errors.Is(firstErr, syscall.EBADF) {
				t.Fatalf("read-only WriteAt = %d, %v; want 0, EBADF", n, firstErr)
			}
			if n, err := wl.WriteAt([]byte("second"), 9); n != 0 || !errors.Is(err, syscall.EBADF) {
				t.Fatalf("second read-only WriteAt = %d, %v; want 0, EBADF", n, err)
			}
			assertWriteLoggerFirstError(t, wl, firstErr)
			closeWriteLoggerWithoutNotification(t, wl, uploads)
		})
	}
}

func TestWriteLogger_LaterWriteSuccessPreservesFailure(t *testing.T) {
	wl, uploads, disk := newWriteLoggerFailureFixture(t, os.O_RDWR, false)
	n, firstErr := wl.WriteAt([]byte("bad"), -1)
	if n != 0 || firstErr == nil {
		t.Fatalf("negative-offset WriteAt = %d, %v; want 0 and an error", n, firstErr)
	}
	if n, err := wl.WriteAt([]byte("ok"), 0); n != 2 || err != nil {
		t.Fatalf("subsequent WriteAt = %d, %v; want 2, nil", n, err)
	}
	assertWriteLoggerFirstError(t, wl, firstErr)
	closeWriteLoggerWithoutNotification(t, wl, uploads)
	contents, err := disk.ReadFile("upload.bin")
	if err != nil || string(contents) != "okiginal" {
		t.Fatalf("contents after successful later write = %q, %v; want okiginal", contents, err)
	}
}

func TestWriteLogger_RecoveredWritePanicRecordsFailure(t *testing.T) {
	for _, tc := range []struct {
		name       string
		appendMode bool
	}{
		{"ordinary", false},
		{"append", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A zero-value os.File has no internal descriptor state. Its write
			// panics without owning any resource that needs Close or cleanup.
			wl := &writeLogger{File: new(os.File), appendMode: tc.appendMode}
			n, err := wl.WriteAt([]byte("x"), 0)
			if n != 0 || !errors.Is(err, errSFTPRequestFailed) {
				t.Fatalf("recovered WriteAt = %d, %v; want 0 and request failure", n, err)
			}
			assertWriteLoggerFirstError(t, wl, err)
		})
	}
}

func newWriteLoggerFailureFixture(t *testing.T, flags int, appendMode bool) (*writeLogger, <-chan CompletedUpload, *os.Root) {
	t.Helper()
	root := t.TempDir()
	disk, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	if err := disk.WriteFile("upload.bin", []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := disk.OpenFile("upload.bin", flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	uploads := make(chan CompletedUpload, 1)
	return &writeLogger{
		File:         file,
		filepath:     "/upload.bin",
		fullFilepath: filepath.Join(root, "upload.bin"),
		username:     "alice",
		clientIP:     "127.0.0.1",
		uploads:      uploads,
		appendMode:   appendMode,
	}, uploads, disk
}

func assertWriteLoggerFirstError(t *testing.T, wl *writeLogger, firstErr error) {
	t.Helper()
	wl.mu.Lock()
	got := wl.transferErr
	wl.mu.Unlock()
	if !errors.Is(got, firstErr) {
		t.Errorf("recorded write failure = %v; want original error %v", got, firstErr)
	}
}

func closeWriteLoggerWithoutNotification(t *testing.T, wl *writeLogger, uploads <-chan CompletedUpload) {
	t.Helper()
	// Keep Close successful: a close-before-write fixture would suppress
	// completion for the wrong reason and hide the missing write-error state.
	if err := wl.Close(); err != nil {
		t.Fatalf("Close after failed WriteAt = %v; want nil", err)
	}
	select {
	case evt := <-uploads:
		t.Errorf("failed write emitted CompletedUpload: %+v", evt)
	default:
	}
}

// TestWriteLogger_TransferErrorSuppressesNotification verifies that when
// pkg/sftp invokes TransferError on the writer before Close (i.e. the
// in-flight upload was aborted), the subsequent Close does NOT enqueue a
// CompletedUpload event. Without this guarantee, a truncated upload caused
// by a client connection drop would be mis-reported as a complete upload.
func TestWriteLogger_TransferErrorSuppressesNotification(t *testing.T) {
	root := t.TempDir()
	f, err := os.OpenFile(filepath.Join(root, "partial.bin"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	uploads := make(chan CompletedUpload, 1)
	wl := &writeLogger{
		File:         f,
		filepath:     "/partial.bin",
		fullFilepath: filepath.Join(root, "partial.bin"),
		username:     "alice",
		clientIP:     "127.0.0.1",
		uploads:      uploads,
	}
	// Simulate the request server signalling that the transfer was aborted.
	wl.TransferError(io.ErrUnexpectedEOF)
	if err := wl.Close(); err != nil {
		t.Fatalf("Close after TransferError: %v", err)
	}
	select {
	case evt := <-uploads:
		t.Fatalf("CompletedUploads received notification %+v for an interrupted upload; want none", evt)
	case <-time.After(100 * time.Millisecond):
		// expected: no notification.
	}
}

// TestWriteLogger_CleanCloseAnnouncesUpload verifies that the happy path is
// unchanged: a Close with no preceding TransferError still announces the
// upload on the CompletedUploads channel.
func TestWriteLogger_CleanCloseAnnouncesUpload(t *testing.T) {
	root := t.TempDir()
	f, err := os.OpenFile(filepath.Join(root, "ok.bin"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	uploads := make(chan CompletedUpload, 1)
	wl := &writeLogger{
		File:         f,
		filepath:     "/ok.bin",
		fullFilepath: filepath.Join(root, "ok.bin"),
		username:     "alice",
		clientIP:     "127.0.0.1",
		uploads:      uploads,
	}
	if err := wl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case evt := <-uploads:
		if evt.FilePath != "/ok.bin" {
			t.Errorf("FilePath = %q; want /ok.bin", evt.FilePath)
		}
		if evt.Protocol != CompletedUploadProtocolSFTP {
			t.Errorf("Protocol = %q; want %q", evt.Protocol, CompletedUploadProtocolSFTP)
		}
	case <-time.After(time.Second):
		t.Fatal("expected CompletedUpload notification for clean Close")
	}
}

// TestWriteLogger_TransferErrorNilIsNoop verifies that a TransferError(nil)
// call is ignored, so a subsequent clean Close still announces the upload.
func TestWriteLogger_TransferErrorNilIsNoop(t *testing.T) {
	root := t.TempDir()
	f, err := os.OpenFile(filepath.Join(root, "ok2.bin"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	uploads := make(chan CompletedUpload, 1)
	wl := &writeLogger{
		File:         f,
		filepath:     "/ok2.bin",
		fullFilepath: filepath.Join(root, "ok2.bin"),
		username:     "alice",
		uploads:      uploads,
	}
	wl.TransferError(nil)
	if err := wl.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case evt := <-uploads:
		if evt.Protocol != CompletedUploadProtocolSFTP {
			t.Errorf("Protocol = %q; want %q", evt.Protocol, CompletedUploadProtocolSFTP)
		}
	case <-time.After(time.Second):
		t.Fatal("expected CompletedUpload notification for clean Close after TransferError(nil)")
	}
}

// TestSFTPServer_RejectsCRLFInFilenames verifies the write-time CR/LF guards
// on the SFTP handler paths (Filewrite, Filecmd Mkdir, Filecmd Rename) so
// that a hostile SFTP client cannot create a name that would later be
// echoed back to an FTP client and forge control-channel replies.
func TestSFTPServer_RejectsCRLFInFilenames(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "src.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	users := map[string]UserInfo{
		"u": {Password: "p", Root: root, CanRead: true, CanWrite: true},
	}
	_, addr, stop := startTestServer(t, users)
	t.Cleanup(stop)

	client := dialSFTP(t, addr, "u", "p")

	if _, err := client.Create("/bad\rname.txt"); err == nil {
		t.Errorf("Create with CR in name unexpectedly succeeded")
	}
	if _, err := client.Create("/bad\nname.txt"); err == nil {
		t.Errorf("Create with LF in name unexpectedly succeeded")
	}
	if err := client.Mkdir("/bad\rdir"); err == nil {
		t.Errorf("Mkdir with CR in name unexpectedly succeeded")
	}
	if err := client.Rename("/src.txt", "/bad\nrenamed.txt"); err == nil {
		t.Errorf("Rename to CR/LF target unexpectedly succeeded")
	}

	// The valid source should still exist after the failed rename.
	if _, err := os.Stat(filepath.Join(root, "src.txt")); err != nil {
		t.Errorf("src.txt missing after rejected Rename: %v", err)
	}
	// No bad-named files should have been created on the host.
	for _, n := range []string{"bad\rname.txt", "bad\nname.txt", "bad\rdir", "bad\nrenamed.txt"} {
		if _, err := os.Stat(filepath.Join(root, n)); err == nil {
			t.Errorf("CR/LF-named entry %q exists on disk; write-time guard bypassed", n)
		}
	}
}
