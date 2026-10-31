package ironport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestJailFS_RejectsSpecialFilesWithoutWaitingForFIFOPeer(t *testing.T) {
	root := t.TempDir()
	fifoPath := filepath.Join(root, "pipe")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	closeOpenedFile := func(f *managedFile, err error) error {
		if f != nil {
			_ = f.Close()
		}
		return err
	}
	tests := []struct {
		name string
		open func() error
	}{
		{name: "read", open: func() error { return closeOpenedFile(jfs.OpenRead("pipe")) }},
		{name: "write", open: func() error {
			return closeOpenedFile(jfs.OpenWrite("pipe", os.O_WRONLY|os.O_TRUNC, 0))
		}},
		{name: "read-write", open: func() error {
			return closeOpenedFile(jfs.OpenWrite("pipe", os.O_RDWR, 0))
		}},
		{name: "truncate", open: func() error { return jfs.Truncate("pipe", 0) }},
		{name: "chmod", open: func() error { return jfs.Chmod("pipe", 0o600) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFIFOOperationRejected(t, fifoPath, tc.open)
		})
	}
}

func assertFIFOOperationRejected(t *testing.T, fifoPath string, operation func() error) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- operation() }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("special file accepted")
		}
	case <-time.After(time.Second):
		// Unblock a regressed FIFO open before reporting failure, so the
		// failing test does not leave a stuck goroutine or open jail fd.
		peer, openErr := unix.Open(fifoPath, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr == nil {
			<-result
			_ = unix.Close(peer)
		}
		t.Fatal("operation blocked waiting for a FIFO peer")
	}
}

func TestJailFS_OpenRegularPreservesFileSemantics(t *testing.T) {
	root := t.TempDir()
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	if f, err := jfs.OpenRead("/"); err == nil {
		_ = f.Close()
		t.Fatal("OpenRead accepted a directory")
	}
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := jfs.OpenWrite("file", os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err == nil {
		_ = f.Close()
		t.Fatal("exclusive create accepted an existing file")
	}
	if data := readJailTestFile(t, jfs, "file"); data != "original" {
		t.Fatalf("exclusive create changed file: data=%q", data)
	}
	f, err = jfs.OpenWrite("file", os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("replacement"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if data := readJailTestFile(t, jfs, "file"); data != "replacement" {
		t.Fatalf("truncate/write: data=%q", data)
	}
}

func TestJailFS_RejectsSpecialFilesBeforeOpening(t *testing.T) {
	// O_PATH can inspect the type without read/write permission. A normal
	// open would fail with EACCES before validation (and could run a device
	// driver's open handler when permitted).
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission check used to detect a premature open")
	}
	root := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0); err != nil {
		t.Fatal(err)
	}
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{name: "read", run: func() error {
			f, err := jfs.OpenRead("pipe")
			if f != nil {
				_ = f.Close()
			}
			return err
		}},
		{name: "create write", run: func() error {
			f, err := jfs.OpenWrite("pipe", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if f != nil {
				_ = f.Close()
			}
			return err
		}},
		{name: "chmod", run: func() error { return jfs.Chmod("pipe", 0o600) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("special file type must be rejected before open: got %v, want EINVAL", err)
			}
		})
	}
}

func TestJailFS_ReopenUsesPinnedInodeAfterReplacement(t *testing.T) {
	for _, replacement := range []string{"regular", "fifo", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			name := filepath.Join(root, "file")
			if err := os.WriteFile(name, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			jfs, err := openJailFS(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = jfs.Close() })
			pin, err := jfs.openat("file", unix.O_PATH, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(pin) }()
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			switch replacement {
			case "regular":
				err = os.WriteFile(name, []byte("replacement"), 0o600)
			case "fifo":
				err = unix.Mkfifo(name, 0o600)
			case "symlink":
				outside := filepath.Join(t.TempDir(), "outside")
				if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(outside, name)
			}
			if err != nil {
				t.Fatal(err)
			}
			flags := os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_EXCL | os.O_TRUNC | unix.O_NOFOLLOW
			fd, err := reopenCheckedFile(pin, flags, false)
			if err != nil {
				t.Fatal(err)
			}
			file := os.NewFile(uintptr(fd), "pinned file")
			defer func() { _ = file.Close() }()
			if _, err := file.WriteString(" appended"); err != nil {
				t.Fatal(err)
			}
			// Append advances the offset; rewind before checking the contents.
			if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
				t.Fatal(seekErr)
			}
			data, err := io.ReadAll(file)
			if err != nil || string(data) != "original appended" {
				t.Fatalf("reopened inode contents = %q, %v", data, err)
			}
			fdFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
				t.Fatalf("reopened descriptor lacks close-on-exec: flags=%d err=%v", fdFlags, err)
			}
			if replacement != "fifo" {
				data, err := os.ReadFile(name)
				want := "replacement"
				if replacement == "symlink" {
					want = "outside"
				}
				if err != nil || string(data) != want {
					t.Fatalf("replacement changed: contents=%q err=%v", data, err)
				}
			}
		})
	}
}

func TestJailFS_CreateAndAppendSemantics(t *testing.T) {
	jfs, err := openJailFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	// A newly created file can be written through its creation descriptor
	// even when its mode would deny any subsequent reopen.
	f, err := jfs.OpenWrite("created", os.O_WRONLY|os.O_CREATE, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("created"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = jfs.OpenWrite("created", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(" appended"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readJailTestFile(t, jfs, "created"); got != "created appended" {
		t.Fatalf("create/append contents = %q", got)
	}
}

func readJailTestFile(t *testing.T, jfs *jailFS, name string) string {
	t.Helper()
	f, err := jfs.OpenRead(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestJailFS_OpenListReadsIncrementally(t *testing.T) {
	root := t.TempDir()
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	lister, err := jfs.OpenList("/")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lister.Close() })
	// Entries created after OpenList must be visible on its first read: the
	// directory is opened at OPENDIR, but is not materialized in memory there.
	const total = 1037
	for i := range total {
		name := fmt.Sprintf("entry-%04d", i)
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	listed := readJailListing(t, lister, 37)
	if len(listed) != total {
		t.Fatalf("listed %d entries, want %d", len(listed), total)
	}
	seen := make(map[string]bool, total)
	for _, name := range listed {
		if seen[name] {
			t.Fatalf("duplicate entry %q", name)
		}
		seen[name] = true
	}
	assertJailListingOffsets(t, lister, listed)
}

func assertJailListingOffsets(t *testing.T, lister *jailDirLister, listed []string) {
	t.Helper()
	var batch [5]os.FileInfo
	if n, err := lister.ListAt(batch[:], 11); err != nil || n != len(batch) {
		t.Fatalf("rewind ListAt: n=%d err=%v", n, err)
	}
	for i, info := range batch {
		if info.Name() != listed[11+i] {
			t.Fatalf("rewound entry %d = %q, want %q", i, info.Name(), listed[11+i])
		}
	}
	if n, err := lister.ListAt(batch[:], int64(len(listed)+1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("past end: n=%d err=%v", n, err)
	}
	if _, err := lister.ListAt(batch[:], -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("negative offset: %v", err)
	}
	if err := lister.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lister.ListAt(batch[:], 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("read after close: %v", err)
	}
}

func readJailListing(t *testing.T, lister *jailDirLister, batchSize int) []string {
	t.Helper()
	var names []string
	batch := make([]os.FileInfo, batchSize)
	for {
		n, err := lister.ListAt(batch, int64(len(names)))
		for _, info := range batch[:n] {
			names = append(names, info.Name())
		}
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Fatal("ListAt made no progress")
		}
	}
}

func TestJailFS_MkdirAllRejectsExistingFinalNonDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dir", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	for _, name := range []string{"file", "link"} {
		t.Run(name, func(t *testing.T) {
			if err := jfs.MkdirAll(name, 0o700); err == nil {
				t.Fatal("MkdirAll accepted a non-directory final component")
			}
		})
	}
}

func TestOpenat2ProbeCachesOnlyDefinitiveResults(t *testing.T) {
	transientErrors := []error{
		syscall.EINTR,
		syscall.EMFILE,
		syscall.ENFILE,
		syscall.ENOMEM,
	}
	for _, transientErr := range transientErrors {
		t.Run(transientErr.Error(), func(t *testing.T) {
			assertOpenat2ProbeSequence(t, func(call int) error {
				if call == 1 {
					return transientErr
				}
				return nil
			}, []error{transientErr, nil, nil}, 2)
		})
	}

	t.Run("unsupported is cached", func(t *testing.T) {
		assertOpenat2ProbeSequence(t, func(int) error {
			return syscall.ENOSYS
		}, []error{errOpenat2Unsupported, errOpenat2Unsupported}, 1)
	})

	t.Run("success is cached", func(t *testing.T) {
		assertOpenat2ProbeSequence(t, func(int) error {
			return nil
		}, []error{nil, nil}, 1)
	})
}

func assertOpenat2ProbeSequence(t *testing.T, run func(int) error, wantErrors []error, wantCalls int) {
	t.Helper()
	calls := 0
	probe := openat2Probe{run: func() error {
		calls++
		return run(calls)
	}}
	for i, wantErr := range wantErrors {
		if err := probe.check(); !errors.Is(err, wantErr) {
			t.Fatalf("check %d error = %v; want %v", i+1, err, wantErr)
		}
	}
	if calls != wantCalls {
		t.Fatalf("probe calls = %d; want %d", calls, wantCalls)
	}
}

func TestOpenJailFS_RejectsSymlinkedRootPath(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real-parent")
	realRoot := filepath.Join(realParent, "root")
	if err := os.MkdirAll(realRoot, 0o750); err != nil {
		t.Fatalf("os.MkdirAll(real root): %v", err)
	}

	finalLink := filepath.Join(base, "final-link")
	if err := os.Symlink(realRoot, finalLink); err != nil {
		t.Fatalf("os.Symlink(final root): %v", err)
	}
	ancestorLink := filepath.Join(base, "ancestor-link")
	if err := os.Symlink(realParent, ancestorLink); err != nil {
		t.Fatalf("os.Symlink(root ancestor): %v", err)
	}

	tests := []struct {
		name string
		root string
	}{
		{name: "final component", root: finalLink},
		{name: "ancestor component", root: filepath.Join(ancestorLink, "root")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jfs, err := openJailFS(tc.root)
			if jfs != nil {
				_ = jfs.Close()
				t.Fatalf("openJailFS(%q) returned a jail for a symlinked root", tc.root)
			}
			if !errors.Is(err, syscall.ELOOP) {
				t.Fatalf("openJailFS(%q) error = %v; want ELOOP", tc.root, err)
			}
		})
	}
}

func TestOpenJailFS_RejectsParentTraversalInRoot(t *testing.T) {
	base := t.TempDir()
	workingDir := filepath.Join(base, "working")
	for _, dir := range []string{
		filepath.Join(base, "jail"),
		filepath.Join(workingDir, "parent"),
		filepath.Join(workingDir, "jail"),
		filepath.Join(workingDir, "jail..name"),
	} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("os.MkdirAll(%q): %v", dir, err)
		}
	}
	t.Chdir(workingDir)

	separator := string(os.PathSeparator)
	absoluteRoot := workingDir + separator + "parent" + separator + ".." + separator + "jail"
	tests := []string{
		"../jail",
		"parent/../jail",
		"parent//..//jail",
		absoluteRoot,
	}

	for _, root := range tests {
		t.Run(root, func(t *testing.T) {
			jfs, err := openJailFS(root)
			if jfs != nil {
				_ = jfs.Close()
				t.Fatalf("openJailFS(%q) returned a jail for a root containing ..", root)
			}
			if !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("openJailFS(%q) error = %v; want os.ErrInvalid", root, err)
			}
		})
	}

	allowed, err := openJailFS("jail..name")
	if err != nil {
		t.Fatalf("openJailFS(lookalike component): %v", err)
	}
	if err := allowed.Close(); err != nil {
		t.Fatalf("close lookalike jail: %v", err)
	}
}

func TestOpenJailFS_RejectsNonDirectoryRoot(t *testing.T) {
	rootFile := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(rootFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(root file): %v", err)
	}

	jfs, err := openJailFS(rootFile)
	if jfs != nil {
		_ = jfs.Close()
		t.Fatalf("openJailFS(%q) returned a jail for a regular file", rootFile)
	}
	if !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("openJailFS(%q) error = %v; want ENOTDIR", rootFile, err)
	}
}

func TestOpenJailFS_RetainsRelativeRootAfterParentReplacement(t *testing.T) {
	originalCWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	base := t.TempDir()
	workingDir := filepath.Join(base, "working")
	configuredRoot := filepath.Join(workingDir, "root")
	if err := os.MkdirAll(configuredRoot, 0o750); err != nil {
		t.Fatalf("os.MkdirAll(configured root): %v", err)
	}
	if err := os.WriteFile(filepath.Join(configuredRoot, "marker.txt"), []byte("original"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(marker): %v", err)
	}
	t.Chdir(workingDir)

	jfs, err := openJailFS("root")
	if err != nil {
		t.Fatalf("openJailFS(relative root): %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	if jfs.root != configuredRoot {
		t.Fatalf("reported root = %q; want %q", jfs.root, configuredRoot)
	}
	if err := os.Chdir(originalCWD); err != nil {
		t.Fatalf("restore cwd: %v", err)
	}

	openedWorkingDir := filepath.Join(base, "opened-working")
	if err := os.Rename(workingDir, openedWorkingDir); err != nil {
		t.Fatalf("os.Rename(working dir): %v", err)
	}
	replacementRoot := filepath.Join(workingDir, "root")
	if err := os.MkdirAll(replacementRoot, 0o750); err != nil {
		t.Fatalf("os.MkdirAll(replacement root): %v", err)
	}
	if err := os.WriteFile(filepath.Join(replacementRoot, "marker.txt"), []byte("replacement"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(replacement marker): %v", err)
	}

	marker, err := jfs.OpenRead("/marker.txt")
	if err != nil {
		t.Fatalf("OpenRead(marker): %v", err)
	}
	got, readErr := io.ReadAll(marker)
	closeErr := marker.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read marker: read error=%v close error=%v", readErr, closeErr)
	}
	if string(got) != "original" {
		t.Fatalf("marker contents = %q; want original", got)
	}
}

//nolint:gocognit,cyclop,funlen // security regression independently verifies inode retention plus read/write confinement
func TestJailFS_RetainsRootFDAfterPathReplacement(t *testing.T) {
	base := t.TempDir()
	configuredRoot := filepath.Join(base, "root")
	replacementRoot := filepath.Join(base, "replacement")
	if err := os.Mkdir(configuredRoot, 0o750); err != nil {
		t.Fatalf("os.Mkdir(configured root): %v", err)
	}
	if err := os.Mkdir(replacementRoot, 0o750); err != nil {
		t.Fatalf("os.Mkdir(replacement root): %v", err)
	}
	if err := os.WriteFile(filepath.Join(configuredRoot, "marker.txt"), []byte("original"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(original marker): %v", err)
	}
	if err := os.WriteFile(filepath.Join(replacementRoot, "marker.txt"), []byte("replacement"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(replacement marker): %v", err)
	}

	jfs, err := openJailFS(configuredRoot)
	if err != nil {
		t.Fatalf("openJailFS: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })

	var openedStat unix.Stat_t
	if err := unix.Fstat(jfs.rootFd, &openedStat); err != nil {
		t.Fatalf("unix.Fstat(opened root): %v", err)
	}

	openedRoot := filepath.Join(base, "opened-root")
	if err := os.Rename(configuredRoot, openedRoot); err != nil {
		t.Fatalf("os.Rename(configured root): %v", err)
	}
	if err := os.Rename(replacementRoot, configuredRoot); err != nil {
		t.Fatalf("os.Rename(replacement root): %v", err)
	}

	var retainedStat unix.Stat_t
	if err := unix.Fstat(jfs.rootFd, &retainedStat); err != nil {
		t.Fatalf("unix.Fstat(retained root): %v", err)
	}
	if retainedStat.Dev != openedStat.Dev || retainedStat.Ino != openedStat.Ino {
		t.Fatalf(
			"retained root fd changed inode: got dev=%d ino=%d; want dev=%d ino=%d",
			retainedStat.Dev,
			retainedStat.Ino,
			openedStat.Dev,
			openedStat.Ino,
		)
	}
	var movedStat unix.Stat_t
	if err := unix.Stat(openedRoot, &movedStat); err != nil {
		t.Fatalf("unix.Stat(opened root): %v", err)
	}
	if retainedStat.Dev != movedStat.Dev || retainedStat.Ino != movedStat.Ino {
		t.Fatalf(
			"retained root fd points elsewhere: got dev=%d ino=%d; opened root has dev=%d ino=%d",
			retainedStat.Dev,
			retainedStat.Ino,
			movedStat.Dev,
			movedStat.Ino,
		)
	}

	marker, err := jfs.OpenRead("/marker.txt")
	if err != nil {
		t.Fatalf("OpenRead(marker): %v", err)
	}
	gotMarker, readErr := io.ReadAll(marker)
	closeErr := marker.Close()
	if readErr != nil {
		t.Fatalf("io.ReadAll(marker): %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("marker.Close: %v", closeErr)
	}
	if string(gotMarker) != "original" {
		t.Fatalf("marker contents = %q; want %q", gotMarker, "original")
	}

	created, err := jfs.OpenWrite("/created.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenWrite(created): %v", err)
	}
	payload := []byte("written through retained root")
	written, writeErr := created.Write(payload)
	closeErr = created.Close()
	if writeErr != nil {
		t.Fatalf("created.Write: %v", writeErr)
	}
	if written != len(payload) {
		t.Fatalf("created.Write wrote %d bytes; want %d", written, len(payload))
	}
	if closeErr != nil {
		t.Fatalf("created.Close: %v", closeErr)
	}

	gotPayload, err := os.ReadFile(filepath.Join(openedRoot, "created.txt")) //nolint:gosec // path is confined to t.TempDir
	if err != nil {
		t.Fatalf("os.ReadFile(opened root): %v", err)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("opened-root payload = %q; want %q", gotPayload, payload)
	}
	if _, err := os.Stat(filepath.Join(configuredRoot, "created.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement root received created.txt; stat error = %v", err)
	}
}

func TestJailFS_CloseReleasesRootFD(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "marker.txt"), []byte("marker"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(marker): %v", err)
	}

	jfs, err := openJailFS(root)
	if err != nil {
		t.Fatalf("openJailFS: %v", err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	rootFD := jfs.rootFd

	var openStat unix.Stat_t
	if err := unix.Fstat(rootFD, &openStat); err != nil {
		t.Fatalf("unix.Fstat(before Close): %v", err)
	}
	if err := jfs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if jfs.rootFd != -1 {
		t.Fatalf("rootFd after Close = %d; want -1", jfs.rootFd)
	}

	var closedStat unix.Stat_t
	if err := unix.Fstat(rootFD, &closedStat); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("unix.Fstat(after Close) error = %v; want EBADF", err)
	}
	if _, err := jfs.OpenRead("/marker.txt"); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("OpenRead after Close error = %v; want EBADF", err)
	}
	if err := jfs.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestUnopenableJailRootIsLoggedAtAddUserAndLogin(t *testing.T) {
	var logs bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	base := t.TempDir()
	realRoot := filepath.Join(base, "real")
	if err := os.Mkdir(realRoot, 0o750); err != nil {
		t.Fatalf("os.Mkdir(real root): %v", err)
	}
	linkRoot := filepath.Join(base, "link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatalf("os.Symlink(root): %v", err)
	}

	s := &Server{}
	s.AddUser("good", UserInfo{Password: "pw", Root: realRoot})
	if logs.Len() != 0 {
		t.Fatalf("AddUser logged for a valid root: %q", logs.String())
	}

	s.AddUser("alice", UserInfo{Password: "pw", Root: linkRoot})
	if got := logs.String(); !strings.Contains(got, "warning: jail-root check failed") || !strings.Contains(got, `"alice"`) {
		t.Fatalf("AddUser log = %q; want a jail-root warning naming alice", got)
	}
	logs.Reset()

	_, jfs, _, ok := s.authenticateUser("alice", func(stored UserInfo) bool {
		return checkPassword(stored.Password, "pw")
	})
	if ok || jfs != nil {
		if jfs != nil {
			_ = jfs.Close()
		}
		t.Fatal("authenticateUser succeeded for a symlinked jail root")
	}
	if got := logs.String(); !strings.Contains(got, "could not be opened") || !strings.Contains(got, `"alice"`) {
		t.Fatalf("login log = %q; want the jail-root open failure naming alice", got)
	}

	injectedRoot := filepath.Join(base, "missing\nFORGED")
	logs.Reset()
	// Give the independent escaping case its own failure-log sampling window;
	// the preceding login has already consumed this server's first sample.
	s = &Server{}
	s.AddUser("mallory", UserInfo{Password: "pw", Root: injectedRoot})
	assertEscapedSingleLogLine(t, logs.String())

	logs.Reset()
	_, jfs, _, ok = s.authenticateUser("mallory", func(stored UserInfo) bool {
		return checkPassword(stored.Password, "pw")
	})
	if ok || jfs != nil {
		if jfs != nil {
			_ = jfs.Close()
		}
		t.Fatal("authenticateUser succeeded for a missing jail root")
	}
	assertEscapedSingleLogLine(t, logs.String())
}

func assertEscapedSingleLogLine(t *testing.T, got string) {
	t.Helper()
	if strings.Count(got, "\n") != 1 {
		t.Fatalf("log contains %d physical lines; want 1: %q", strings.Count(got, "\n"), got)
	}
	if !strings.Contains(got, `\nFORGED`) {
		t.Fatalf("log did not retain escaped newline: %q", got)
	}
	if strings.Contains(got, "\nFORGED") {
		t.Fatalf("log contains an injected physical line: %q", got)
	}
}

func TestUnopenableJailRootWarningSuppressesSupersededRoot(t *testing.T) {
	var logs bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	s := &Server{}
	oldRoot := filepath.Join(t.TempDir(), "missing")
	currentRoot := t.TempDir()
	s.AddUser("alice", UserInfo{Password: "pw", Root: oldRoot})
	_, oldRevision, _ := s.userSnapshot("alice")
	logs.Reset()
	s.AddUser("alice", UserInfo{Password: "pw", Root: currentRoot})
	logs.Reset()

	s.logUnusableJailRootIfCurrent(
		"alice",
		oldRoot,
		oldRevision,
		&os.PathError{Op: "openat2", Path: oldRoot, Err: syscall.ENOENT},
	)
	if logs.Len() != 0 {
		t.Fatalf("superseded root produced a stale warning: %q", logs.String())
	}
}

type blockingLogWriter struct {
	entered chan struct{}
	release chan struct{}
	match   string
	once    sync.Once
}

func (w *blockingLogWriter) Write(p []byte) (int, error) {
	if !bytes.Contains(p, []byte(w.match)) {
		return len(p), nil
	}
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func waitForJailTestSignal(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestAddUserPublishesCredentialsBeforeDiagnosticIO(t *testing.T) {
	badRoot := filepath.Join(t.TempDir(), "missing")
	writer := &blockingLogWriter{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		match:   badRoot,
	}
	previousOutput := log.Writer()
	log.SetOutput(writer)

	var releaseOnce sync.Once
	unblockLog := func() { releaseOnce.Do(func() { close(writer.release) }) }
	s := NewServer(&Config{Users: map[string]UserInfo{
		"alice": {Password: "old", Root: t.TempDir()},
	}})
	badDone := make(chan struct{})
	go func() {
		s.AddUser("alice", UserInfo{Password: "bad", Root: badRoot})
		close(badDone)
	}()
	t.Cleanup(func() {
		defer log.SetOutput(previousOutput)
		unblockLog()
		waitForJailTestSignal(t, badDone, "blocked AddUser cleanup")
	})

	waitForJailTestSignal(t, writer.entered, "jail-root warning")
	if user, _, ok := s.userSnapshot("alice"); !ok || user.Password != "bad" {
		t.Fatal("blocked diagnostic kept old credentials active")
	}

	goodRoot := t.TempDir()
	goodDone := make(chan struct{})
	go func() {
		s.AddUser("alice", UserInfo{Password: "good", Root: goodRoot})
		close(goodDone)
	}()
	waitForJailTestSignal(t, goodDone, "concurrent AddUser")
	goodUser, _, ok := s.userSnapshot("alice")
	if !ok || goodUser.Root != goodRoot {
		t.Fatalf("concurrent AddUser published %+v; want root %q", goodUser, goodRoot)
	}

	unblockLog()
	waitForJailTestSignal(t, badDone, "warned AddUser")
	finalUser, _, ok := s.userSnapshot("alice")
	if !ok || finalUser.Root != goodRoot || finalUser.Password != "good" {
		t.Fatalf("delayed diagnostic overwrote the newer user: %+v", finalUser)
	}
}

func TestServerPrepareForListenWarnsAboutInitialJailRoots(t *testing.T) {
	var logs bytes.Buffer
	previousOutput, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previousOutput)
		log.SetFlags(previousFlags)
	})

	base := t.TempDir()
	realRoot := filepath.Join(base, "real")
	if err := os.Mkdir(realRoot, 0o750); err != nil {
		t.Fatalf("os.Mkdir(real root): %v", err)
	}
	linkRoot := filepath.Join(base, "link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatalf("os.Symlink(root): %v", err)
	}

	config := DefaultConfig()
	config.SftpSigner = testSigner(t)
	config.Users = map[string]UserInfo{
		"good": {Password: "pw", Root: realRoot},
		"bad":  {Password: "pw", Root: linkRoot},
	}
	s := NewServer(config)
	if logs.Len() != 0 {
		t.Fatalf("NewServer logged before startup validation: %q", logs.String())
	}
	if err := s.prepareForListen(); err != nil {
		t.Fatalf("prepareForListen: %v", err)
	}
	got := logs.String()
	if !strings.Contains(got, `user "bad"`) {
		t.Fatalf("startup log = %q; want warning for bad user", got)
	}
	if strings.Contains(got, `user "good"`) {
		t.Fatalf("startup log warned for valid root: %q", got)
	}
}
