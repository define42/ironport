// Package ironport: jail filesystem backend built on Linux openat2.
//
// This file implements the "no symlinks anywhere" filesystem policy by
// performing every per-request filesystem operation through file descriptors
// rooted at the jail. Every path lookup uses openat2 with
// RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS so that:
//
//   - The supplied directory fd is treated as the filesystem root.
//   - No symlink is followed during path resolution; if any component is a
//     symlink the call fails with -ELOOP.
//   - ".." cannot escape the jail.
//
// Operations that traditionally take a path (chmod, chown, truncate, mkdir,
// unlink, rename) are implemented as openat2 + f*at syscalls so the kernel —
// not a string pre-check — enforces containment, eliminating the TOCTOU
// window between the pre-check and the action.
//
// Setting access/modification times (SFTP Acmodtime) is rejected outright per
// the hardened policy.

package ironport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// errOpenat2Unsupported is returned when the running kernel lacks the
// openat2 syscall (added in Linux 5.6). The package requires openat2 for
// its symlink-safety guarantee; falling back to older syscalls would be
// race-prone and would silently weaken the policy.
var errOpenat2Unsupported = errors.New("kernel does not support openat2 (Linux 5.6+ required)")

// One-time probe state for openat2. These are package-level globals so the
// probe result is cached across all jail instances in the process; openat2
// availability is a kernel property and cannot change at runtime.
//
//nolint:gochecknoglobals // process-wide cache of kernel capability probe
var (
	openat2ProbeOnce sync.Once
	openat2ProbeErr  error
)

// probeOpenat2 verifies that openat2 is available by issuing a harmless call
// against /. The result is cached after the first successful probe. Callers
// that need this guarantee at startup (e.g. before reporting a configured
// jail root) can invoke it directly; it is also invoked transparently by
// openJailFS on every jail creation.
func probeOpenat2() error {
	openat2ProbeOnce.Do(func() {
		fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: 0,
		})
		if err != nil {
			if errors.Is(err, syscall.ENOSYS) {
				openat2ProbeErr = errOpenat2Unsupported
				return
			}
			openat2ProbeErr = fmt.Errorf("openat2 probe: %w", err)
			return
		}
		_ = unix.Close(fd)
	})
	return openat2ProbeErr
}

// ensureOpenat2 is exposed for callers that want to fail at startup rather
// than at first request when openat2 is unavailable.
func ensureOpenat2() error { return probeOpenat2() }

// cleanRelClientPath normalises a client-supplied path into a slash-separated,
// jail-relative path suitable for openat2(rootFd, ...). The result never
// starts with "/" and never contains "." or ".." segments after cleaning.
// The jail root itself is represented as ".".
func cleanRelClientPath(p string) string {
	p = filepath.ToSlash(p)
	p = path.Clean("/" + p)
	if p == "/" {
		return "."
	}
	return strings.TrimPrefix(p, "/")
}

// splitParent splits a cleaned jail-relative path into (parentDir, base).
// For a top-level entry "foo" the parent is ".". For the root itself ("."),
// it returns ("", "") so callers can reject operations on the jail root.
func splitParent(rel string) (string, string) {
	if rel == "." || rel == "" {
		return "", ""
	}
	dir, base := path.Split(rel)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		dir = "."
	}
	return dir, base
}

// jailFS encapsulates a fd-relative, no-symlink filesystem rooted at a single
// directory. Every method validates the path through the kernel using
// openat2; no string-level resolution or pre-check is performed.
//
// Methods are safe for concurrent use; the only mutable state is the root fd
// which is set at construction and closed at teardown.
type jailFS struct {
	root   string // textual jail root, for constructing client-visible full paths
	rootFd int    // O_PATH fd to the jail root; closed by Close
}

// openJailFS opens a jail root at the given on-disk path and returns a
// jailFS whose root fd refers to that directory. The path is opened with
// O_PATH|O_DIRECTORY|O_NOFOLLOW so the root itself cannot be substituted by
// a symlink at construction time.
//
// openat2 availability is verified on first use; if the running kernel does
// not support it the call returns errOpenat2Unsupported.
func openJailFS(root string) (*jailFS, error) {
	if err := probeOpenat2(); err != nil {
		return nil, err
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: root, Err: err}
	}
	return &jailFS{root: root, rootFd: fd}, nil
}

// Close releases the jail root fd. After Close, further calls return EBADF.
func (j *jailFS) Close() error {
	if j == nil || j.rootFd < 0 {
		return nil
	}
	err := unix.Close(j.rootFd)
	j.rootFd = -1
	return err
}

// resolveFlags is the resolve mask applied to every openat2 inside the jail.
// RESOLVE_IN_ROOT pins the search to rootFd; RESOLVE_NO_SYMLINKS forbids any
// symlink traversal (including a symlinked final component).
const resolveFlags = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS

// openat opens a path relative to the jail root with the given flags and
// permission. Symlinks in any component cause the call to fail.
func (j *jailFS) openat(rel string, flags int, perm os.FileMode) (int, error) {
	// flags is a set of unix open(2) bit constants, never negative; the
	// conversion to uint64 cannot overflow.
	fd, err := unix.Openat2(j.rootFd, rel, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC), //nolint:gosec // bitmask, not a signed quantity
		Mode:    uint64(perm),
		Resolve: resolveFlags,
	})
	if err != nil {
		return -1, err
	}
	return fd, nil
}

// fullPath returns the on-disk path that corresponds to a client-supplied
// path. The argument is cleaned and confined to the jail relative form
// before being joined to the textual root, so callers may pass raw client
// input. Because openat2 with RESOLVE_NO_SYMLINKS guarantees that no
// symlink is traversed when this path is actually used, simple string
// concatenation here yields the actual on-disk path. This is used purely
// for reporting (e.g. CompletedUpload.FullFilePath).
func (j *jailFS) fullPath(clientPath string) string {
	rel := cleanRelClientPath(clientPath)
	if rel == "." || rel == "" {
		return filepath.Clean(j.root)
	}
	return filepath.Join(j.root, filepath.FromSlash(rel))
}

// OpenRead opens a regular file for reading. Symlinks anywhere in the path
// (including the final component) cause the call to fail with EACCES/ELOOP.
func (j *jailFS) OpenRead(clientPath string) (*os.File, error) {
	rel := cleanRelClientPath(clientPath)
	fd, err := j.openat(rel, os.O_RDONLY, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: clientPath, Err: err}
	}
	return os.NewFile(uintptr(fd), rel), nil
}

// OpenWrite opens a file for writing using the given flags and mode. Callers
// pass the standard os.O_* flags (typically O_CREATE|O_WRONLY|O_TRUNC for
// uploads, or |O_APPEND for FTP APPE). The file is opened through openat2 so
// the kernel rejects symlink traversal at all components.
func (j *jailFS) OpenWrite(clientPath string, flags int, perm os.FileMode) (*os.File, error) {
	rel := cleanRelClientPath(clientPath)
	if flags&os.O_CREATE == 0 {
		perm = 0
	}
	fd, err := j.openat(rel, flags, perm)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: clientPath, Err: err}
	}
	return os.NewFile(uintptr(fd), rel), nil
}

// Stat returns os.FileInfo for the given client path. Because openat2 with
// RESOLVE_NO_SYMLINKS rejects symlink components, the result is always the
// stat of a non-symlink. (Lstat is redundant under this policy and is mapped
// to the same call.)
func (j *jailFS) Stat(clientPath string) (os.FileInfo, error) {
	rel := cleanRelClientPath(clientPath)
	fd, err := j.openat(rel, unix.O_PATH, 0)
	if err != nil {
		return nil, &os.PathError{Op: "stat", Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: clientPath, Err: err}
	}
	return &statFileInfo{name: path.Base(rel), st: st}, nil
}

// List opens the directory at clientPath and returns its entries as
// []os.FileInfo. The directory itself must not be a symlink (enforced by
// openat2). Individual entries are returned as the kernel reports them; per
// policy, symlinks among the entries can never be followed by subsequent
// operations, so listing them is harmless.
//
// Entries are stat'd via fstatat against the directory fd so the per-entry
// metadata lookup also goes through the openat2-rooted directory and never
// follows a symlink.
func (j *jailFS) List(clientPath string) ([]os.FileInfo, error) {
	var out []os.FileInfo
	if err := j.ListStream(clientPath, func(info os.FileInfo) error {
		out = append(out, info)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// listStreamBatch is the dirent batch size for ListStream. Small enough
// to keep peak memory bounded on enormous directories, large enough to
// amortise getdents and the per-batch goroutine context switch.
const listStreamBatch = 512

// ListStream invokes yield once per directory entry, pulling dirents in
// fixed-size batches so a directory with millions of entries does not
// have to be materialised in memory before being transmitted. Entries
// that vanish between readdir and fstatat (race with a concurrent
// unlink) are silently skipped — same tolerance as List. yield may
// return a non-nil error to terminate the walk early; that error is
// propagated to the caller unchanged.
func (j *jailFS) ListStream(clientPath string, yield func(os.FileInfo) error) error {
	rel := cleanRelClientPath(clientPath)
	fd, err := j.openat(rel, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: clientPath, Err: err}
	}
	f := os.NewFile(uintptr(fd), j.fullPath(rel))
	defer func() { _ = f.Close() }()
	for {
		names, readErr := f.Readdirnames(listStreamBatch)
		for _, name := range names {
			var st unix.Stat_t
			if statErr := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
				continue
			}
			if yieldErr := yield(&statFileInfo{name: name, st: st}); yieldErr != nil {
				return yieldErr
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

// Mkdir creates a new directory at clientPath with the given permission.
// The parent directory must already exist and must not be reached through a
// symlink. The new directory is created with mkdirat against an openat2 fd of
// the parent, so a TOCTOU race between path check and mkdir is impossible.
func (j *jailFS) Mkdir(clientPath string, perm os.FileMode) error {
	rel := cleanRelClientPath(clientPath)
	parent, base := splitParent(rel)
	if base == "" {
		return &os.PathError{Op: "mkdir", Path: clientPath, Err: syscall.EEXIST}
	}
	pfd, err := j.openat(parent, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(pfd) }()
	if err := unix.Mkdirat(pfd, base, uint32(perm.Perm())); err != nil {
		return &os.PathError{Op: "mkdir", Path: clientPath, Err: err}
	}
	return nil
}

// removeAt is the shared implementation of Remove and Rmdir; flags is either
// 0 (file unlink) or unix.AT_REMOVEDIR (directory unlink).
func (j *jailFS) removeAt(clientPath string, flags int, op string) error {
	rel := cleanRelClientPath(clientPath)
	parent, base := splitParent(rel)
	if base == "" {
		return &os.PathError{Op: op, Path: clientPath, Err: syscall.EBUSY}
	}
	pfd, err := j.openat(parent, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: op, Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(pfd) }()
	if err := unix.Unlinkat(pfd, base, flags); err != nil {
		return &os.PathError{Op: op, Path: clientPath, Err: err}
	}
	return nil
}

// Remove removes a non-directory entry. Because the parent is reached through
// an openat2 with RESOLVE_NO_SYMLINKS, no symlink traversal is possible. The
// final component is not followed by unlinkat, so a symlink at that position
// is removed as a symlink (not its target) — consistent with os.Remove.
func (j *jailFS) Remove(clientPath string) error {
	return j.removeAt(clientPath, 0, "remove")
}

// Rmdir removes an empty directory.
func (j *jailFS) Rmdir(clientPath string) error {
	return j.removeAt(clientPath, unix.AT_REMOVEDIR, "rmdir")
}

// Rename renames oldPath to newPath. Both paths are resolved through openat2
// with RESOLVE_NO_SYMLINKS, so neither side may traverse a symlink. The
// rename itself uses renameat2 with flags=0, preserving the os.Rename
// semantics of overwriting an existing destination.
func (j *jailFS) Rename(oldPath, newPath string) error {
	oldRel := cleanRelClientPath(oldPath)
	newRel := cleanRelClientPath(newPath)
	oldParent, oldBase := splitParent(oldRel)
	newParent, newBase := splitParent(newRel)
	if oldBase == "" || newBase == "" {
		return &os.PathError{Op: "rename", Path: oldPath, Err: syscall.EBUSY}
	}
	oldFd, err := j.openat(oldParent, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: "rename", Path: oldPath, Err: err}
	}
	defer func() { _ = unix.Close(oldFd) }()
	newFd, err := j.openat(newParent, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return &os.PathError{Op: "rename", Path: newPath, Err: err}
	}
	defer func() { _ = unix.Close(newFd) }()
	if err := unix.Renameat2(oldFd, oldBase, newFd, newBase, 0); err != nil {
		return &os.PathError{Op: "rename", Path: oldPath, Err: err}
	}
	return nil
}

// Chmod changes the permission bits of the entry at clientPath via fchmod on
// an openat2-obtained fd. Symlinks anywhere in the path cause failure.
func (j *jailFS) Chmod(clientPath string, perm os.FileMode) error {
	rel := cleanRelClientPath(clientPath)
	// Open read-only; fchmod requires a non-O_PATH fd on Linux.
	fd, err := j.openat(rel, os.O_RDONLY, 0)
	if err != nil {
		// Fall back to read-write if the file is write-only; failing that,
		// surface the original O_RDONLY error. The O_WRONLY error is
		// intentionally discarded: the O_RDONLY result is the one the
		// caller actually asked about (it covers the common cases —
		// ENOENT, EACCES on the path, jail escape) whereas an O_WRONLY
		// failure on the fallback only tells us that "the second guess
		// didn't work either", which would be more confusing than
		// helpful.
		fd2, err2 := j.openat(rel, os.O_WRONLY, 0)
		if err2 != nil {
			return &os.PathError{Op: "chmod", Path: clientPath, Err: err}
		}
		fd = fd2
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchmod(fd, uint32(perm.Perm())); err != nil {
		return &os.PathError{Op: "chmod", Path: clientPath, Err: err}
	}
	return nil
}

// Chown changes the owner/group of clientPath. The lookup goes through the
// jail root with RESOLVE_NO_SYMLINKS, then fchownat with AT_EMPTY_PATH on a
// fd opened with O_PATH operates atomically on the target.
func (j *jailFS) Chown(clientPath string, uid, gid int) error {
	rel := cleanRelClientPath(clientPath)
	fd, err := j.openat(rel, unix.O_PATH, 0)
	if err != nil {
		return &os.PathError{Op: "chown", Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "chown", Path: clientPath, Err: err}
	}
	return nil
}

// Truncate sets the file size at clientPath. The fd is obtained through
// openat2 so symlink traversal is impossible.
func (j *jailFS) Truncate(clientPath string, size int64) error {
	rel := cleanRelClientPath(clientPath)
	fd, err := j.openat(rel, os.O_WRONLY, 0)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Ftruncate(fd, size); err != nil {
		return &os.PathError{Op: "truncate", Path: clientPath, Err: err}
	}
	return nil
}

// statFileInfo adapts a unix.Stat_t into the os.FileInfo interface so that
// callers (especially the SFTP listing helpers) can consume it without an
// extra stat round-trip.
type statFileInfo struct {
	name string
	st   unix.Stat_t
}

func (s *statFileInfo) Name() string { return s.name }
func (s *statFileInfo) Size() int64  { return s.st.Size }
func (s *statFileInfo) Mode() os.FileMode {
	m := os.FileMode(s.st.Mode & 0o777)
	switch s.st.Mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		m |= os.ModeDir
	case syscall.S_IFLNK:
		m |= os.ModeSymlink
	case syscall.S_IFIFO:
		m |= os.ModeNamedPipe
	case syscall.S_IFSOCK:
		m |= os.ModeSocket
	case syscall.S_IFBLK:
		m |= os.ModeDevice
	case syscall.S_IFCHR:
		m |= os.ModeDevice | os.ModeCharDevice
	}
	if s.st.Mode&syscall.S_ISUID != 0 {
		m |= os.ModeSetuid
	}
	if s.st.Mode&syscall.S_ISGID != 0 {
		m |= os.ModeSetgid
	}
	if s.st.Mode&syscall.S_ISVTX != 0 {
		m |= os.ModeSticky
	}
	return m
}

func (s *statFileInfo) ModTime() time.Time {
	return time.Unix(s.st.Mtim.Sec, s.st.Mtim.Nsec)
}
func (s *statFileInfo) IsDir() bool      { return s.Mode().IsDir() }
func (s *statFileInfo) Sys() interface{} { return &s.st }
