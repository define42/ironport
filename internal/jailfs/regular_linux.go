//go:build linux

package jailfs

import (
	"errors"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// openRegular validates a pinned inode before opening it for I/O. This avoids
// both FIFO/device open side effects and O_NONBLOCK's rejection of file leases.
// Truncation happens only after the normal (possibly lease-blocked) open.
func (j *FS) openRegular(clientPath string, flags int, perm os.FileMode) (*os.File, error) {
	rel := CleanPath(clientPath)
	fd, err := j.openRegularFD(rel, flags, perm)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: clientPath, Err: err}
	}
	if err := prepareRegularFile(fd, flags&os.O_TRUNC != 0); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "open", Path: clientPath, Err: err}
	}
	return os.NewFile(uintptr(fd), rel), nil
}

func (j *FS) openRegularFD(rel string, flags int, perm os.FileMode) (int, error) {
	if flags&os.O_CREATE == 0 {
		return j.openExistingRegular(rel, flags)
	}
	// O_PATH cannot create files. Exclusive creation is safe without a type
	// check first: it either creates a new regular inode or fails without
	// opening any existing inode. Never drop the caller's exclusive intent.
	const maxCreateAttempts = 8
	for range maxCreateAttempts {
		fd, err := j.openat(rel, (flags&^os.O_TRUNC)|os.O_EXCL|unix.O_NOCTTY, perm)
		if err == nil || !errors.Is(err, syscall.EEXIST) || flags&os.O_EXCL != 0 {
			return fd, err
		}
		fd, err = j.openExistingRegular(rel, flags)
		if !errors.Is(err, syscall.ENOENT) {
			return fd, err
		}
		// The existing entry disappeared before it could be pinned. Retry
		// creation, but bound work if another process keeps replacing it.
	}
	return -1, syscall.EAGAIN
}

func (j *FS) openExistingRegular(rel string, flags int) (int, error) {
	pathFD, err := j.openat(rel, unix.O_PATH, 0)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(pathFD) }()
	return reopenCheckedFile(pathFD, flags, false)
}

// reopenCheckedFile opens the inode held by an O_PATH descriptor, never the
// original pathname. Keep pathFD alive until this call returns: /proc/self/fd
// is a trusted kernel descriptor reference, not a client-controlled symlink.
// A missing procfs fails closed; re-resolving the pathname would race validation.
func reopenCheckedFile(pathFD int, flags int, allowDirectory bool) (int, error) {
	var st unix.Stat_t
	if err := unix.Fstat(pathFD, &st); err != nil {
		return -1, err
	}
	kind := st.Mode & unix.S_IFMT
	if kind != unix.S_IFREG && !(allowDirectory && kind == unix.S_IFDIR) {
		return -1, syscall.EINVAL
	}
	// The original openat2 lookup enforced the jail and no-symlink policy.
	// Here the procfs magic link must be followed to reopen that exact inode.
	// Preserve access/append flags, but defer truncation to the caller.
	flags &^= os.O_CREATE | os.O_EXCL | os.O_TRUNC | unix.O_NOFOLLOW
	return unix.Open("/proc/self/fd/"+strconv.Itoa(pathFD), flags|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
}

func prepareRegularFile(fd int, truncate bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return syscall.EINVAL
	}
	if truncate {
		return unix.Ftruncate(fd, 0)
	}
	return nil
}
