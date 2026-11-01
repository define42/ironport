//go:build linux

package jailfs

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRegularRejectsFIFOWithoutPeer(t *testing.T) {
	const childRoot = "IRONPORT_REGULAR_FIFO_TEST_ROOT"
	if root := os.Getenv(childRoot); root != "" {
		assertRegularOperationsRejected(t, openRegularTestFS(t, root), "pipe")
		return
	}
	root := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A regressed blocking FIFO open cannot be canceled through its not-yet
	// returned descriptor. Isolate it so the timeout kills and reaps every
	// worker and descriptor before the parent removes the fixture.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	//nolint:gosec // G204: only this test binary is executed, with a fixed test filter
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRegularRejectsFIFOWithoutPeer$", "-test.count=1")
	cmd.Env = append(os.Environ(), childRoot+"="+root)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("operation blocked waiting for a FIFO peer: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("FIFO rejection checks failed: %v\n%s", err, output)
	}
}

func TestRegularRejectsFIFOTypeBeforePermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission check that distinguishes a premature open")
	}
	jfs, root := newDirectoryTestFS(t)
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0); err != nil {
		t.Fatal(err)
	}
	// A normal I/O open would fail with EACCES. EINVAL proves the pinned
	// inode's type was checked before attempting that open.
	assertRegularOperationsRejected(t, jfs, "pipe")
}

func TestRegularRejectsSocketBeforeIO(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	ln, err := net.Listen("unix", filepath.Join(root, "socket"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	assertRegularOperationsRejected(t, jfs, "socket")
}

func TestRegularRejectsCharacterDevice(t *testing.T) {
	jfs := openRegularTestFS(t, "/dev")
	info, err := jfs.Stat("null")
	if err != nil {
		t.Skipf("/dev/null unavailable: %v", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		t.Skip("/dev/null is not a character device")
	}
	// Only a read open is attempted: even the old implementation cannot
	// mutate this host device while demonstrating the missing type check.
	err = closeRegularTestOpen(jfs.OpenRead("null"))
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("character-device read = %v; want EINVAL before I/O open", err)
	}
}

func assertRegularOperationsRejected(t *testing.T, jfs *FS, name string) {
	t.Helper()
	operations := []struct {
		name string
		run  func() error
	}{
		{"read", func() error { return closeRegularTestOpen(jfs.OpenRead(name)) }},
		{"write", func() error { return closeRegularTestOpen(jfs.OpenWrite(name, os.O_WRONLY|os.O_TRUNC, 0)) }},
		{"create", func() error {
			return closeRegularTestOpen(jfs.OpenWrite(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600))
		}},
		{"read_write", func() error { return closeRegularTestOpen(jfs.OpenWrite(name, os.O_RDWR, 0)) }},
		{"truncate", func() error { return jfs.Truncate(name, 0) }},
		{"chmod", func() error { return jfs.Chmod(name, 0o600) }},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if err := operation.run(); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("special-file operation = %v; want EINVAL before I/O open", err)
			}
		})
	}
	assertNoRegularTestDescriptors(t, jfs.FullPath(name))
}

func assertNoRegularTestDescriptors(t *testing.T, name string) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue // ReadDir's own descriptor has already been closed.
		}
		if err != nil {
			t.Fatal(err)
		}
		if target == name {
			t.Fatalf("rejected operation retained descriptor %s for %q", entry.Name(), name)
		}
	}
}

func closeRegularTestOpen(file *os.File, err error) error {
	if file != nil {
		_ = file.Close()
	}
	return err
}

func openRegularTestFS(t *testing.T, root string) *FS {
	t.Helper()
	jfs, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	return jfs
}

func TestRegularOpenModes(t *testing.T) {
	tests := []struct {
		name, initial string
		flags         int
		want          string
	}{
		{"create", "", os.O_CREATE | os.O_WRONLY, "new"},
		{"exclusive_create", "", os.O_CREATE | os.O_EXCL | os.O_WRONLY, "new"},
		{"truncate_existing", "original", os.O_WRONLY | os.O_TRUNC, "new"},
		{"create_truncate_existing", "original", os.O_CREATE | os.O_WRONLY | os.O_TRUNC, "new"},
		{"append_existing", "original", os.O_CREATE | os.O_WRONLY | os.O_APPEND, "originalnew"},
		{"append_new", "", os.O_CREATE | os.O_WRONLY | os.O_APPEND, "new"},
		{"read_write", "original", os.O_RDWR, "newginal"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jfs, root := newDirectoryTestFS(t)
			if tc.initial != "" {
				writeDirectoryTestFile(t, root, "file", tc.initial)
			}
			file := openRegularTestFile(t, jfs, "file", tc.flags, 0o600)
			if _, err := file.WriteString("new"); err != nil {
				t.Fatal(err)
			}
			if tc.flags&os.O_RDWR != 0 {
				assertRegularDescriptorContents(t, file, tc.want)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			assertRegularPathContents(t, jfs, "file", tc.want)
		})
	}
}

func TestRegularExclusiveCreatePreservesExistingFile(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	writeDirectoryTestFile(t, root, "file", "original")
	err := closeRegularTestOpen(jfs.OpenWrite("file", os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_TRUNC, 0o600))
	if !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("exclusive create = %v; want EEXIST", err)
	}
	assertRegularPathContents(t, jfs, "file", "original")
}

func TestRegularCreationKeepsWritableDescriptor(t *testing.T) {
	jfs, _ := newDirectoryTestFS(t)
	file := openRegularTestFile(t, jfs, "file", os.O_CREATE|os.O_WRONLY, 0)
	// Reopening a freshly created mode-000 file would fail for an ordinary
	// user. The creation descriptor must remain usable for its initial upload.
	if _, err := file.WriteString("created"); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	assertRegularPathContents(t, jfs, "file", "created")
}

func TestRegularFailedReopenPreservesContents(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the write-permission failure used to reject reopening")
	}
	jfs, root := newDirectoryTestFS(t)
	writeDirectoryTestFile(t, root, "file", "original")
	if err := os.Chmod(filepath.Join(root, "file"), 0o400); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		flags int
	}{
		{"truncate", os.O_WRONLY | os.O_TRUNC},
		{"create_truncate", os.O_CREATE | os.O_WRONLY | os.O_TRUNC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := closeRegularTestOpen(jfs.OpenWrite("file", tc.flags, 0o600))
			if !errors.Is(err, syscall.EACCES) {
				t.Fatalf("read-only file open = %v; want EACCES", err)
			}
			assertRegularPathContents(t, jfs, "file", "original")
			assertNoRegularTestDescriptors(t, filepath.Join(root, "file"))
		})
	}
}

func TestRegularTruncateAndDirectoryChmod(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	writeDirectoryTestFile(t, root, "file", "original")
	if err := jfs.Truncate("file", 3); err != nil {
		t.Fatal(err)
	}
	assertRegularPathContents(t, jfs, "file", "ori")
	if err := jfs.Mkdir("directory", 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/", "directory"} {
		t.Run(name, func(t *testing.T) {
			if err := closeRegularTestOpen(jfs.OpenRead(name)); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("directory read = %v; want EINVAL", err)
			}
			if err := jfs.Chmod(name, 0o750); err != nil {
				t.Fatal(err)
			}
			info, err := jfs.Stat(name)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0o750 {
				t.Fatalf("directory after Chmod = %v, %v; want mode 0750", info, err)
			}
		})
	}
}

func TestRegularReopenKeepsPinnedInode(t *testing.T) {
	for _, replacement := range []string{"regular", "fifo", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			jfs, root := newDirectoryTestFS(t)
			writeDirectoryTestFile(t, root, "file", "original")
			pin, err := jfs.openat("file", unix.O_PATH, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(pin) })
			if err := os.Remove(filepath.Join(root, "file")); err != nil {
				t.Fatal(err)
			}
			checkReplacement := replaceRegularTestPath(t, jfs, root, replacement)
			file := reopenRegularTestFile(t, pin)
			if _, err := file.WriteString(" appended"); err != nil {
				t.Fatal(err)
			}
			assertRegularDescriptorContents(t, file, "original appended")
			checkReplacement()
		})
	}
}

func reopenRegularTestFile(t *testing.T, pin int) *os.File {
	t.Helper()
	flags := os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_EXCL | os.O_TRUNC | unix.O_NOFOLLOW
	fd, err := reopenCheckedFile(pin, flags, false)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "pinned file")
	t.Cleanup(func() { _ = file.Close() })
	fdFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("reopened descriptor flags = %d, %v; want close-on-exec", fdFlags, err)
	}
	return file
}

func replaceRegularTestPath(t *testing.T, jfs *FS, root, replacement string) func() {
	t.Helper()
	switch replacement {
	case "regular":
		writeDirectoryTestFile(t, root, "file", "replacement")
		return func() { assertRegularPathContents(t, jfs, "file", "replacement") }
	case "fifo":
		if err := unix.Mkfifo(filepath.Join(root, "file"), 0o600); err != nil {
			t.Fatal(err)
		}
		return func() {
			info, err := jfs.Stat("file")
			if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
				t.Fatalf("replacement FIFO changed: %v, %v", info, err)
			}
		}
	case "symlink":
		outsideFS, outside := newDirectoryTestFS(t)
		writeDirectoryTestFile(t, outside, "target", "outside")
		if err := os.Symlink(filepath.Join(outside, "target"), filepath.Join(root, "file")); err != nil {
			t.Fatal(err)
		}
		return func() { assertRegularPathContents(t, outsideFS, "target", "outside") }
	default:
		t.Fatalf("unknown replacement %q", replacement)
		return nil
	}
}

func openRegularTestFile(t *testing.T, jfs *FS, name string, flags int, perm os.FileMode) *os.File {
	t.Helper()
	file, err := jfs.OpenWrite(name, flags, perm)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func assertRegularPathContents(t *testing.T, jfs *FS, name, want string) {
	t.Helper()
	file, err := jfs.OpenRead(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	assertRegularDescriptorContents(t, file, want)
}

func assertRegularDescriptorContents(t *testing.T, file *os.File, want string) {
	t.Helper()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(file)
	if err != nil || string(contents) != want {
		t.Fatalf("file contents = %q, %v; want %q", contents, err, want)
	}
}
