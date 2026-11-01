//go:build linux

package jailfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Open opens a configured jail root without following symlinks in any path
// component. Blank roots and literal ".." components are rejected before
// path normalization. Relative roots use a cwd descriptor held until the
// jail-root descriptor has been opened.
//
// The returned FS keeps that directory open for its lifetime, so renaming or
// replacing the configured path cannot redirect subsequent filesystem access.
// openat2 support (Linux 5.6+) is checked before opening the root.
func Open(root string) (*FS, error) {
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	if err := probeOpenat2(); err != nil {
		return nil, err
	}
	fd, displayRoot, err := openRootFD(root)
	if err != nil {
		return nil, err
	}
	return &FS{root: displayRoot, rootFd: fd}, nil
}

func validateRoot(root string) error {
	if strings.TrimSpace(root) == "" {
		return os.ErrInvalid
	}
	// A rename during lookup can change where ".." leads. Do not erase those
	// components with filepath.Clean and accidentally accept the changed path.
	for component := range strings.SplitSeq(root, string(os.PathSeparator)) {
		if component == ".." {
			return &os.PathError{Op: "validate root", Path: root, Err: os.ErrInvalid}
		}
	}
	return nil
}

func openRootFD(root string) (int, string, error) {
	dirFD := unix.AT_FDCWD
	displayRoot := filepath.Clean(root)
	if !filepath.IsAbs(root) {
		cwdFD, cwd, err := openRootCWD()
		if err != nil {
			return -1, "", err
		}
		dirFD = cwdFD
		displayRoot = filepath.Join(cwd, root)
		defer func() { _ = unix.Close(cwdFD) }()
	}
	fd, err := openRootPath(dirFD, root)
	return fd, displayRoot, err
}

func openRootPath(dirFD int, root string) (int, error) {
	fd, err := unix.Openat2(dirFD, root, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return -1, &os.PathError{Op: "openat2", Path: root, Err: err}
	}
	return fd, nil
}

// openRootCWD binds a reporting path to its directory descriptor. A process-wide
// Chdir may race with Getwd, so accept a snapshot only when its path still names
// the pinned cwd inode. Keep the descriptor opened through that path, including
// its mount, so relative lookup and reporting use the same directory tree.
func openRootCWD() (int, string, error) {
	const maxAttempts = 8
	for range maxAttempts {
		fd, cwd, err := snapshotRootCWD()
		if !errors.Is(err, unix.EAGAIN) {
			return fd, cwd, err
		}
	}
	return -1, "", &os.PathError{Op: "open", Path: ".", Err: unix.EAGAIN}
}

func snapshotRootCWD() (int, string, error) {
	currentFD, err := unix.Open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", &os.PathError{Op: "open", Path: ".", Err: err}
	}
	defer func() { _ = unix.Close(currentFD) }()
	// Use the physical kernel path: os.Getwd may return a logical $PWD alias
	// whose meaning changes when filepath.Join cleans its components.
	cwd, err := unix.Getwd()
	if err != nil {
		return -1, "", &os.PathError{Op: "getwd", Path: ".", Err: err}
	}
	pathFD, err := openRootPath(unix.AT_FDCWD, cwd)
	if err != nil {
		return -1, "", err
	}
	matches, err := sameRootDirectory(currentFD, pathFD)
	if err != nil || !matches {
		_ = unix.Close(pathFD)
		if err != nil {
			return -1, "", &os.PathError{Op: "fstat", Path: ".", Err: err}
		}
		return -1, "", unix.EAGAIN
	}
	return pathFD, cwd, nil
}

func sameRootDirectory(first, second int) (bool, error) {
	var firstStat, secondStat unix.Stat_t
	if err := unix.Fstat(first, &firstStat); err != nil {
		return false, err
	}
	if err := unix.Fstat(second, &secondStat); err != nil {
		return false, err
	}
	return firstStat.Dev == secondStat.Dev && firstStat.Ino == secondStat.Ino, nil
}
