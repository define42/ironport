package jailfs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ---- CleanPath / FS path-handling tests ----

func TestCleanRelClientPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "."},
		{"/", "."},
		{".", "."},
		{"foo.txt", "foo.txt"},
		{"/foo.txt", "foo.txt"},
		{"/bar/baz.txt", "bar/baz.txt"},
		{"./bar", "bar"},
		{"/a/../b.txt", "b.txt"},
		{"../../etc/passwd", "etc/passwd"},
	}
	for _, tc := range tests {
		got := CleanPath(tc.in)
		if got != tc.want {
			t.Errorf("CleanPath(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

// TestJailFS_RejectsSymlinkComponents covers the core hardening guarantee:
// no openat2-backed operation may traverse a symlink, regardless of whether
// the symlink is the final component or an intermediate one, and regardless
// of whether its target lies inside or outside the jail. The same fixture
// exercises read, write, stat, list, chmod, truncate, mkdir, remove, and
// rename, so a regression in any helper is caught here.
// symlinkRejectFixture builds a jail containing a real subdir+file, an
// escaping symlink ("escape" → outside the jail) and an internal directory
// symlink ("real_link" → "real"). It returns the opened FS and the
// outside directory whose target must never be created. The symlink creation
// is best-effort: on filesystems that forbid symlinks the test is skipped.
func symlinkRejectFixture(t *testing.T) (*FS, string) {
	t.Helper()
	root := t.TempDir()
	outside := t.TempDir()

	if err := os.Mkdir(filepath.Join(root, "real"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real", "file.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "missing.txt"), filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Symlink("real", filepath.Join(root, "real_link")); err != nil {
		t.Skipf("symlink: %v", err)
	}

	jfs, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	return jfs, outside
}

func TestJailFS_RejectsSymlinkComponents(t *testing.T) {
	jfs, outside := symlinkRejectFixture(t)

	type op struct {
		name string
		run  func() error
	}
	ops := []op{
		{"OpenRead final", func() error { _, err := jfs.OpenRead("/escape"); return err }},
		{"OpenRead middle", func() error { _, err := jfs.OpenRead("/real_link/file.txt"); return err }},
		{"OpenWrite final", func() error {
			_, err := jfs.OpenWrite("/escape", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			return err
		}},
		{"OpenWrite middle", func() error {
			_, err := jfs.OpenWrite("/real_link/new.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			return err
		}},
		{"Stat final", func() error { _, err := jfs.Stat("/escape"); return err }},
		{"List middle", func() error { _, err := jfs.List("/real_link"); return err }},
		{"Mkdir middle", func() error { return jfs.Mkdir("/real_link/sub", 0o750) }},
		{"Rename src middle", func() error { return jfs.Rename("/real_link/file.txt", "/x") }},
		{"Rename dst middle", func() error { return jfs.Rename("/real/file.txt", "/real_link/x") }},
		{"Chmod final", func() error { return jfs.Chmod("/escape", 0o600) }},
		{"Truncate final", func() error { return jfs.Truncate("/escape", 0) }},
		{"Chown final", func() error { return jfs.Chown("/escape", -1, -1) }},
		{"Chown middle", func() error { return jfs.Chown("/real_link/file.txt", -1, -1) }},
		{"Chtimes final", func() error { return jfs.Chtimes("/escape", time.Now(), time.Now()) }},
		{"Chtimes middle", func() error { return jfs.Chtimes("/real_link/file.txt", time.Now(), time.Now()) }},
		{"SetModTime final", func() error { return jfs.SetModTime("/escape", time.Now()) }},
		{"SetModTime middle", func() error { return jfs.SetModTime("/real_link/file.txt", time.Now()) }},
	}
	for _, o := range ops {
		err := o.run()
		if err == nil {
			t.Errorf("%s: expected error for symlink traversal, got nil", o.name)
		}
	}

	// The escaping symlink target must still not exist on disk: none of the
	// rejected operations may have been completed through it. (Note: Remove
	// of a symlink final component is intentionally allowed so users can
	// clean up symlinks; it removes the symlink itself via unlinkat, not
	// its target.)
	if _, err := os.Stat(filepath.Join(outside, "missing.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside target was created or stat failed unexpectedly: %v", err)
	}
}

// TestJailFS_PathTraversalContained verifies RESOLVE_IN_ROOT keeps ".."
// inside the jail. Both the leading ".." and a mid-path ".." are clamped so
// they cannot reach a sibling jail or the real filesystem root.
func TestJailFS_PathTraversalContained(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	jfs, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })

	// "../../etc/passwd" → cleaned to "etc/passwd" relative to the jail and
	// resolved against the root fd, so it must fail with ENOENT, not return
	// /etc/passwd from the host.
	if _, err := jfs.OpenRead("../../etc/passwd"); err == nil {
		t.Fatal("OpenRead escape returned nil error")
	}
	// A path that climbs and then re-descends to a real entry inside the jail
	// must succeed via cleaning ("../inside.txt" → "inside.txt").
	f, err := jfs.OpenRead("../inside.txt")
	if err != nil {
		t.Fatalf("OpenRead inside via .. : %v", err)
	}
	_ = f.Close()
}

func TestJailFS_MkdirAll(t *testing.T) {
	root := t.TempDir()
	jfs, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })

	if err := jfs.MkdirAll("a/b/c", 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if info, err := os.Stat(filepath.Join(root, "a", "b", "c")); err != nil || !info.IsDir() {
		t.Fatalf("expected dir a/b/c; info=%v err=%v", info, err)
	}
	// Idempotent: existing directories are not an error.
	if err := jfs.MkdirAll("a/b/c", 0o700); err != nil {
		t.Fatalf("MkdirAll (repeat): %v", err)
	}
	// The jail root is a no-op.
	if err := jfs.MkdirAll("/", 0o700); err != nil {
		t.Fatalf("MkdirAll(/): %v", err)
	}
	// A component that exists as a regular file is rejected (ENOTDIR).
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := jfs.MkdirAll("file/sub", 0o700); err == nil {
		t.Fatal("MkdirAll under a regular file should fail")
	}
	// A symlinked component is rejected: openat2 refuses symlink traversal, so
	// directories cannot be created through a symlink that points outside.
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if err := jfs.MkdirAll("link/sub", 0o700); err == nil {
		t.Fatal("MkdirAll through a symlink component should fail")
	}
	if _, err := os.Stat(filepath.Join(root, "link", "sub")); err == nil {
		t.Fatal("MkdirAll created a directory through a symlink")
	}
}

func TestStatFileInfoMode(t *testing.T) {
	tests := []struct {
		name string
		mode uint32
		want os.FileMode
	}{
		{name: "regular", mode: syscall.S_IFREG | 0o644, want: 0o644},
		{name: "directory", mode: syscall.S_IFDIR | 0o755, want: os.ModeDir | 0o755},
		{name: "symlink", mode: syscall.S_IFLNK | 0o777, want: os.ModeSymlink | 0o777},
		{name: "fifo", mode: syscall.S_IFIFO | 0o600, want: os.ModeNamedPipe | 0o600},
		{name: "socket", mode: syscall.S_IFSOCK | 0o600, want: os.ModeSocket | 0o600},
		{name: "block device", mode: syscall.S_IFBLK | 0o600, want: os.ModeDevice | 0o600},
		{name: "char device", mode: syscall.S_IFCHR | 0o600, want: os.ModeDevice | os.ModeCharDevice | 0o600},
		{name: "special bits", mode: syscall.S_IFREG | syscall.S_ISUID | syscall.S_ISGID | syscall.S_ISVTX | 0o700, want: os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0o700},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := &statFileInfo{st: unix.Stat_t{Mode: tc.mode}}
			if got := info.Mode(); got != tc.want {
				t.Fatalf("Mode() = %v; want %v", got, tc.want)
			}
		})
	}
}
