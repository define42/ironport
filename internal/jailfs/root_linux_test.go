//go:build linux

package jailfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenRootRejectsInvalidPaths(t *testing.T) {
	base := t.TempDir()
	root := makeRootTestDirectory(t, base, "real/root")
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	finalLink := filepath.Join(base, "final-link")
	parentLink := filepath.Join(base, "parent-link")
	makeRootTestSymlink(t, root, finalLink)
	makeRootTestSymlink(t, filepath.Dir(root), parentLink)
	for _, tt := range []struct {
		name string
		root string
		want error
	}{
		{"empty", "", os.ErrInvalid},
		{"whitespace", " \t ", os.ErrInvalid},
		{"missing", filepath.Join(base, "missing"), os.ErrNotExist},
		{"file", file, syscall.ENOTDIR},
		{"final symlink", finalLink, syscall.ELOOP},
		{"final symlink trailing slash", finalLink + "/", syscall.ELOOP},
		{"parent symlink", filepath.Join(parentLink, "root"), syscall.ELOOP},
		{"parent symlink dot", parentLink + "/./root", syscall.ELOOP},
		{"absolute parent traversal", root + "/../root", os.ErrInvalid},
		{"relative parent traversal", "../root", os.ErrInvalid},
		{"relative internal traversal", "parent//..//root", os.ErrInvalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fs, err := Open(tt.root)
			if fs != nil {
				_ = fs.Close()
				t.Fatalf("Open(%q) returned a filesystem", tt.root)
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("Open(%q) = %v; want %v", tt.root, err, tt.want)
			}
		})
	}
}

func TestOpenRootRelativePaths(t *testing.T) {
	base := t.TempDir()
	makeRootTestDirectory(t, base, "jail")
	makeRootTestDirectory(t, base, "jail..name")
	t.Chdir(base)
	for _, name := range []string{"jail", "./jail", "./jail/.", "jail..name", "."} {
		t.Run(name, func(t *testing.T) {
			fs := openRootTestFS(t, name)
			if got, want := fs.FullPath("."), filepath.Join(base, name); got != want {
				t.Fatalf("reported root = %q; want %q", got, want)
			}
		})
	}
}

func TestOpenRelativeRootReportingIgnoresLogicalPWD(t *testing.T) {
	base := t.TempDir()
	physical := makeRootTestDirectory(t, base, "real/parent")
	root := makeRootTestDirectory(t, physical, "root")
	leaf := makeRootTestDirectory(t, physical, "leaf")
	alias := makeRootTestDirectory(t, base, "alias")
	otherRoot := makeRootTestDirectory(t, alias, "root")
	writeDirectoryTestFile(t, root, "marker", root)
	writeDirectoryTestFile(t, otherRoot, "marker", otherRoot)
	link := filepath.Join(alias, "link")
	makeRootTestSymlink(t, leaf, link)

	t.Chdir(physical)
	// The kernel resolves this to physical, but filepath.Join would clean it
	// lexically to alias and produce the wrong reporting path for its root.
	logical := link + "/.."
	t.Setenv("PWD", logical)
	if got, err := os.Getwd(); err != nil || got != logical {
		t.Fatalf("logical working directory = %q, %v; want %q", got, err, logical)
	}
	fs := openRootTestFS(t, "root")
	if got := fs.FullPath("."); got != root {
		t.Fatalf("reported root = %q; want physical path %q", got, root)
	}
	assertRootTestReporting(t, fs)
	if _, err := os.Stat(filepath.Join(otherRoot, "created")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("logical alias directory received the upload: %v", err)
	}
}

func TestOpenRelativeRootReportingDuringChdir(t *testing.T) {
	base := t.TempDir()
	parents := []string{filepath.Join(base, "a"), filepath.Join(base, "b")}
	for _, parent := range parents {
		root := makeRootTestDirectory(t, parent, "root")
		writeDirectoryTestFile(t, root, "marker", root)
	}
	t.Chdir(parents[0])
	stop := churnRootTestCWD(t, parents)
	for range 3000 {
		fs, err := Open("root")
		if errors.Is(err, syscall.EAGAIN) {
			// A bounded snapshot retry may lose every race during cwd churn.
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		assertRootTestReporting(t, fs)
	}
	stop()
	// Require successful opens too, even if every racing snapshot was rejected.
	for _, parent := range parents {
		t.Chdir(parent)
		fs, err := Open("root")
		if err != nil {
			t.Fatal(err)
		}
		assertRootTestReporting(t, fs)
	}
}

func churnRootTestCWD(t *testing.T, parents []string) func() {
	t.Helper()
	stop := make(chan struct{})
	stopped := make(chan error, 1)
	go func() {
		for {
			for _, parent := range parents {
				select {
				case <-stop:
					stopped <- nil
					return
				default:
				}
				if err := os.Chdir(parent); err != nil {
					stopped <- err
					return
				}
			}
		}
	}()
	join := sync.OnceFunc(func() {
		close(stop)
		if err := <-stopped; err != nil {
			t.Error(err)
		}
	})
	// Registered after t.Chdir, so the writer exits before cwd is restored.
	t.Cleanup(join)
	return join
}

func assertRootTestReporting(t *testing.T, fs *FS) {
	t.Helper()
	defer func() { _ = fs.Close() }()
	reportedPath := fs.FullPath(".")
	reported, err := os.OpenRoot(reportedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reported.Close() }()
	var heldInfo, reportedInfo unix.Stat_t
	heldErr := unix.Fstat(fs.rootFd, &heldInfo)
	reportedErr := unix.Stat(reportedPath, &reportedInfo)
	if heldErr != nil || reportedErr != nil {
		t.Fatalf("retained root stat = %v; reported root stat = %v", heldErr, reportedErr)
	}
	if heldInfo.Dev != reportedInfo.Dev || heldInfo.Ino != reportedInfo.Ino {
		t.Fatalf("retained root device/inode %d/%d differs from reported %q (%d/%d); no path was renamed",
			heldInfo.Dev, heldInfo.Ino, reportedPath, reportedInfo.Dev, reportedInfo.Ino)
	}
	marker, err := fs.OpenRead("marker")
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(marker)
	closeErr := marker.Close()
	if readErr != nil || closeErr != nil || string(data) != reportedPath {
		t.Fatalf("retained marker = %q, read %v, close %v; want %q", data, readErr, closeErr, reportedPath)
	}
	assertRootTestReportedWrite(t, fs, reported, reportedPath)
}

func assertRootTestReportedWrite(t *testing.T, fs *FS, reported *os.Root, contents string) {
	t.Helper()
	file, err := fs.OpenWrite("created", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(contents)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("write to retained jail = %v; close = %v", writeErr, closeErr)
	}
	if data, err := reported.ReadFile("created"); err != nil || string(data) != contents {
		t.Fatalf("reported directory received %q, %v; want %q", data, err, contents)
	}
}

func TestOpenRootRetainsDescriptorAfterPathReplacement(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			base := t.TempDir()
			configured := makeRootTestDirectory(t, base, "root")
			other := makeRootTestDirectory(t, base, "other")
			writeDirectoryTestFile(t, configured, "marker", "original")
			writeDirectoryTestFile(t, other, "marker", "replacement")
			fs := openRootTestFS(t, configured)
			moved := filepath.Join(base, "moved")
			if err := os.Rename(configured, moved); err != nil {
				t.Fatal(err)
			}
			replaceRootTestPath(t, configured, other, replacement)
			assertRetainedRoot(t, fs, moved, configured)
		})
	}
}

func TestOpenRootRetainsRelativeRootAfterParentReplacement(t *testing.T) {
	base := t.TempDir()
	working := makeRootTestDirectory(t, base, "working")
	configured := makeRootTestDirectory(t, working, "root")
	writeDirectoryTestFile(t, configured, "marker", "original")
	t.Chdir(working)
	fs := openRootTestFS(t, "root")
	if got := fs.FullPath("."); got != configured {
		t.Fatalf("reported root = %q; want %q", got, configured)
	}
	moved := filepath.Join(base, "moved")
	if err := os.Rename(working, moved); err != nil {
		t.Fatal(err)
	}
	makeRootTestDirectory(t, base, "working/root")
	writeDirectoryTestFile(t, configured, "marker", "replacement")
	assertRetainedRoot(t, fs, filepath.Join(moved, "root"), configured)
}

func TestOpenRootCloseReleasesDescriptor(t *testing.T) {
	fs := openRootTestFS(t, t.TempDir())
	fd := fs.rootFd
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("closed descriptor stat = %v; want EBADF", err)
	}
	if _, err := fs.Stat("."); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("closed filesystem Stat = %v; want EBADF", err)
	}
	if err := fs.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func makeRootTestDirectory(t *testing.T, base, name string) string {
	t.Helper()
	fullPath := filepath.Join(base, name)
	if err := os.MkdirAll(fullPath, 0o700); err != nil {
		t.Fatal(err)
	}
	return fullPath
}

func makeRootTestSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func openRootTestFS(t *testing.T, root string) *FS {
	t.Helper()
	fs, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

func replaceRootTestPath(t *testing.T, configured, other, replacement string) {
	t.Helper()
	if replacement == "symlink" {
		makeRootTestSymlink(t, other, configured)
		return
	}
	if err := os.Rename(other, configured); err != nil {
		t.Fatal(err)
	}
}

func assertRetainedRoot(t *testing.T, fs *FS, moved, configured string) {
	t.Helper()
	file, err := fs.OpenRead("marker")
	if err != nil {
		t.Fatal(err)
	}
	contents, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || string(contents) != "original" {
		t.Fatalf("retained marker = %q, read %v, close %v", contents, readErr, closeErr)
	}
	created, err := fs.OpenWrite("created", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "created")); err != nil {
		t.Fatalf("retained directory did not receive created file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configured, "created")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received created file: %v", err)
	}
}
