package jailfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestOpenDirValidatesPathImmediately(t *testing.T) {
	jfs, _ := symlinkRejectFixture(t)
	for _, name := range []string{"missing", "real/file.txt", "escape", "real_link", "real_link/sub"} {
		t.Run(name, func(t *testing.T) {
			dir, err := jfs.OpenDir(name)
			if err == nil {
				_ = dir.Close()
				t.Fatal("OpenDir accepted an invalid directory")
			}
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) || pathErr.Path != name || pathErr.Op != "open" {
				t.Fatalf("OpenDir error = %v; want open PathError for %q", err, name)
			}
		})
	}
}

func TestOpenDirDoesNotReadAhead(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	writeDirectoryTestFile(t, root, "initial", "first")
	dir := openDirectoryTestCursor(t, jfs, ".")
	if n, err := dir.ReadInto(nil); n != 0 || err != nil {
		t.Fatalf("empty read = %d, %v", n, err)
	}
	writeDirectoryTestFile(t, root, "later", "second")
	entries := readDirectoryTestEntries(t, dir, 3)
	if len(entries) != 2 || entries["initial"] == nil || entries["later"] == nil {
		t.Fatalf("entries = %v; want both files created before first nonempty read", entries)
	}
}

func TestDirReadsCurrentMetadataAndSkipsVanishedEntries(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	for _, name := range []string{"one", "two", "three"} {
		writeDirectoryTestFile(t, root, name, "old")
	}
	dir := openDirectoryTestCursor(t, jfs, ".")
	first := make([]os.FileInfo, 1)
	if n, err := dir.ReadInto(first); n != 1 || err != nil {
		t.Fatalf("first read = %d, %v", n, err)
	}
	var remaining []string
	for _, name := range []string{"one", "two", "three"} {
		if name != first[0].Name() {
			remaining = append(remaining, name)
		}
	}
	if err := os.Remove(filepath.Join(root, remaining[0])); err != nil {
		t.Fatal(err)
	}
	writeDirectoryTestFile(t, root, remaining[1], "new contents")
	entries := readDirectoryTestEntries(t, dir, 3)
	info := entries[remaining[1]]
	if len(entries) != 1 || info == nil || info.Size() != int64(len("new contents")) {
		t.Fatalf("entries = %v; want only the changed file with fresh metadata", entries)
	}
}

func TestDirListsSymlinkMetadataWithoutFollowingTarget(t *testing.T) {
	jfs, _ := symlinkRejectFixture(t)
	dir := openDirectoryTestCursor(t, jfs, ".")
	entries := readDirectoryTestEntries(t, dir, 1)
	for _, name := range []string{"escape", "real_link"} {
		info := entries[name]
		if info == nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("entry %q = %v; want symlink metadata", name, info)
		}
	}
}

func TestDirRewindKeepsRenamedDirectoryPinned(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	if err := os.Mkdir(filepath.Join(root, "original"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDirectoryTestFile(t, root, "original/kept", "contents")
	dir := openDirectoryTestCursor(t, jfs, "original")
	readDirectoryTestEntries(t, dir, 2)
	if err := os.Rename(filepath.Join(root, "original"), filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "original"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeDirectoryTestFile(t, root, "original/replacement", "wrong directory")
	if err := jfs.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dir.Rewind(); err != nil {
		t.Fatal(err)
	}
	entries := readDirectoryTestEntries(t, dir, 2)
	if len(entries) != 1 || entries["kept"] == nil {
		t.Fatalf("rewound entries = %v; want original directory after rename and FS close", entries)
	}
}

func TestDirReadsAcrossBatchBoundaries(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	const count = 1300
	for i := range count {
		writeDirectoryTestFile(t, root, fmt.Sprintf("entry-%04d", i), "")
	}
	dir := openDirectoryTestCursor(t, jfs, ".")
	entries := readDirectoryTestEntries(t, dir, 1025)
	if len(entries) != count {
		t.Fatalf("read %d entries; want %d", len(entries), count)
	}
}

func TestDirEOFAndClose(t *testing.T) {
	jfs, _ := newDirectoryTestFS(t)
	dir := openDirectoryTestCursor(t, jfs, ".")
	buffer := make([]os.FileInfo, 1)
	for range 2 {
		if n, err := dir.ReadInto(buffer); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("empty directory read = %d, %v; want EOF", n, err)
		}
	}
	for range 2 {
		if err := dir.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	for _, buffer := range [][]os.FileInfo{nil, buffer} {
		if n, err := dir.ReadInto(buffer); n != 0 || !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed read = %d, %v; want ErrClosed", n, err)
		}
	}
	if err := dir.Rewind(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed Rewind = %v; want ErrClosed", err)
	}
}

func TestDirReturnsReadErrors(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	writeDirectoryTestFile(t, root, "file", "not a directory")
	file, err := jfs.OpenRead("file")
	if err != nil {
		t.Fatal(err)
	}
	// Construct an invalid cursor to exercise the underlying directory-read
	// error, which cannot normally occur after OpenDir's O_DIRECTORY check.
	dir := &Dir{file: file}
	t.Cleanup(func() { _ = dir.Close() })
	for range 2 {
		if n, err := dir.ReadInto(make([]os.FileInfo, 1)); n != 0 || !errors.Is(err, syscall.ENOTDIR) {
			t.Fatalf("invalid directory read = %d, %v; want ENOTDIR", n, err)
		}
	}
}

func TestDirConcurrentReadsAndClose(t *testing.T) {
	jfs, root := newDirectoryTestFS(t)
	for i := range 100 {
		writeDirectoryTestFile(t, root, fmt.Sprintf("entry-%03d", i), "")
	}
	dir := openDirectoryTestCursor(t, jfs, ".")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { readDirectoryUntilClosed(t, dir) })
	}
	for range 8 {
		wg.Go(func() {
			if err := dir.Close(); err != nil {
				t.Errorf("concurrent Close: %v", err)
			}
		})
	}
	wg.Wait()
}

func readDirectoryUntilClosed(t *testing.T, dir *Dir) {
	t.Helper()
	buffer := make([]os.FileInfo, 7)
	for {
		_, err := dir.ReadInto(buffer)
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrClosed) {
			t.Errorf("concurrent ReadInto: %v", err)
		}
		return
	}
}

func newDirectoryTestFS(t *testing.T) (*FS, string) {
	t.Helper()
	root := t.TempDir()
	jfs, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = jfs.Close() })
	return jfs, root
}

func openDirectoryTestCursor(t *testing.T, jfs *FS, name string) *Dir {
	t.Helper()
	dir, err := jfs.OpenDir(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	return dir
}

func writeDirectoryTestFile(t *testing.T, root, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readDirectoryTestEntries(t *testing.T, dir *Dir, bufferSize int) map[string]os.FileInfo {
	t.Helper()
	entries := make(map[string]os.FileInfo)
	buffer := make([]os.FileInfo, bufferSize)
	for {
		n, err := dir.ReadInto(buffer)
		for _, info := range buffer[:n] {
			if entries[info.Name()] != nil {
				t.Fatalf("duplicate entry %q", info.Name())
			}
			entries[info.Name()] = info
		}
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		if n != len(buffer) {
			t.Fatalf("read %d entries without an error; want full buffer of %d", n, len(buffer))
		}
	}
}
