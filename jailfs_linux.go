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
// Setting access/modification times (SFTP Acmodtime) is performed through an
// openat2-obtained fd, so timestamp updates follow the same containment policy.

package ironport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
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

const (
	openat2Unknown uint8 = iota
	openat2Available
	openat2Unavailable
)

// openat2Probe caches only definitive capability results. Resource pressure
// and interrupted syscalls are deliberately left uncached so a later jail
// open can recover without requiring a process restart.
type openat2Probe struct {
	mu    sync.Mutex
	state uint8
	run   func() error
}

// check serializes the harmless capability probe. Holding this private mutex
// across the syscall prevents a thundering herd on first use; it does not
// block any server or user-state lock.
func (p *openat2Probe) check() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch p.state {
	case openat2Available:
		return nil
	case openat2Unavailable:
		return errOpenat2Unsupported
	}

	err := p.run()
	if err == nil {
		p.state = openat2Available
		return nil
	}
	if errors.Is(err, syscall.ENOSYS) {
		p.state = openat2Unavailable
		return errOpenat2Unsupported
	}
	return fmt.Errorf("openat2 probe: %w", err)
}

func runOpenat2Probe() error {
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return err
	}
	_ = unix.Close(fd)
	return nil
}

//nolint:gochecknoglobals // process-wide cache of a process-wide kernel capability
var openat2Availability = openat2Probe{run: runOpenat2Probe}

// probeOpenat2 verifies that openat2 is available by issuing a harmless call
// against /. Success and the definitive ENOSYS result are cached; transient
// failures are retried. Callers that need this guarantee at startup (e.g.
// before reporting a configured jail root) can invoke it directly; it is also
// invoked transparently by openJailFS on every jail creation.
func probeOpenat2() error {
	return openat2Availability.check()
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
// Filesystem methods are safe for concurrent use. The root descriptor and
// shared budget are bound before publication; Close runs after request work.
type jailFS struct {
	root    string         // textual jail root, for constructing client-visible full paths
	rootFd  int            // O_PATH fd to the jail root; closed by Close
	storage *storageBudget // shared by all sessions using the same root inode
}

func validateJailRootPath(root string) error {
	if strings.TrimSpace(root) == "" {
		return os.ErrInvalid
	}
	// A concurrent rename can change what ".." resolves to during either an
	// absolute or relative path walk. Reject it before entering the kernel
	// lookup so reparenting cannot redirect the selected directory.
	for _, component := range strings.Split(root, string(os.PathSeparator)) {
		if component == ".." {
			return &os.PathError{Op: "openat2", Path: root, Err: os.ErrInvalid}
		}
	}
	return nil
}

// openJailFS opens a jail root at the given on-disk path and returns a
// jailFS whose root fd refers to that directory. openat2 with
// RESOLVE_NO_SYMLINKS rejects symlinks in every component of the configured
// root path, not only its final component. The returned fd is retained for the
// jail lifetime so later path replacement cannot redirect filesystem access.
//
// openat2 availability is verified on first use; if the running kernel does
// not support it the call returns errOpenat2Unsupported.
func openJailFS(root string) (*jailFS, error) {
	if err := validateJailRootPath(root); err != nil {
		return nil, err
	}
	relativeRoot := !filepath.IsAbs(root)

	if err := probeOpenat2(); err != nil {
		return nil, err
	}

	// Keep the raw, validated components for the kernel lookup rather than
	// normalizing the security-sensitive path. Resolve a relative root from a
	// retained cwd fd so a concurrent rename or replacement of the cwd pathname
	// cannot redirect the target open.
	dirFD := unix.AT_FDCWD
	if relativeRoot {
		cwdFD, err := unix.Open(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: ".", Err: err}
		}
		dirFD = cwdFD
		defer func() { _ = unix.Close(cwdFD) }()
	}

	fd, err := unix.Openat2(dirFD, root, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, &os.PathError{Op: "openat2", Path: root, Err: err}
	}

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: root, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "openat2", Path: root, Err: syscall.ENOTDIR}
	}

	displayRoot := filepath.Clean(root)
	if relativeRoot {
		// The absolute path is reporting-only; filesystem operations remain
		// rooted exclusively at fd. It may become stale after a rename, as
		// documented for CompletedUpload.FullFilePath.
		displayRoot, err = filepath.Abs(root)
		if err != nil {
			_ = unix.Close(fd)
			return nil, &os.PathError{Op: "abs", Path: root, Err: err}
		}
	}
	return &jailFS{root: displayRoot, rootFd: fd}, nil
}

// Close releases the jail root fd. After Close, further calls return EBADF.
func (j *jailFS) Close() error {
	if j == nil || j.rootFd < 0 {
		return nil
	}
	err := unix.Close(j.rootFd)
	j.rootFd = -1
	if j.storage != nil {
		j.storage.mu.Lock()
		j.storage.jails--
		j.storage.mu.Unlock()
		j.storage.forgetIdle()
	}
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
func (j *jailFS) OpenRead(clientPath string) (*managedFile, error) {
	return j.openManaged(clientPath, os.O_RDONLY, 0)
}

// OpenWrite opens a file for writing using the given flags and mode. Callers
// pass the standard os.O_* flags (typically O_CREATE|O_WRONLY|O_TRUNC for
// uploads, or |O_APPEND for FTP APPE). The file is opened through openat2 so
// the kernel rejects symlink traversal at all components.
func (j *jailFS) OpenWrite(clientPath string, flags int, perm os.FileMode) (*managedFile, error) {
	return j.openManaged(clientPath, flags, perm)
}

// openRegular validates a pinned inode before opening it for I/O. This avoids
// both FIFO/device open side effects and O_NONBLOCK's rejection of file leases.
// Truncation happens only after the normal (possibly lease-blocked) open.
func (j *jailFS) openRegular(clientPath string, flags int, perm os.FileMode) (*os.File, error) {
	rel := cleanRelClientPath(clientPath)
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

func (j *jailFS) openRegularFD(rel string, flags int, perm os.FileMode) (int, error) {
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

func (j *jailFS) openExistingRegular(rel string, flags int) (int, error) {
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

// OpenList keeps an open directory handle for incremental SFTP READDIR
// requests. The caller must Close it; pkg/sftp does so on CLOSE or session
// teardown because jailDirLister implements io.Closer.
func (j *jailFS) OpenList(clientPath string) (*jailDirLister, error) {
	f, err := j.openManagedDirectory(clientPath)
	if err != nil {
		return nil, err
	}
	return &jailDirLister{dir: f}, nil
}

// jailDirLister uses bounded batches rather than retaining a directory-wide
// snapshot. Normal SFTP reads are sequential. A non-sequential ListAt call
// rewinds and skips entries as needed, preserving the ListerAt contract without
// retaining every earlier entry. As with filesystem readdir, concurrent
// directory modifications need not produce a stable snapshot.
type jailDirLister struct {
	mu     sync.Mutex
	dir    *managedFile
	offset int64
}

func (l *jailDirLister) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dir == nil {
		return nil
	}
	err := l.dir.Close()
	l.dir = nil
	return err
}

func (l *jailDirLister) ListAt(dst []os.FileInfo, offset int64) (n int, err error) {
	defer deferRecoverSFTPPanicf(&err, func() { n = 0 }, "sftp list panic offset=%d: %v\n%s", offset)()
	l.mu.Lock()
	defer l.mu.Unlock()
	if offset < 0 {
		return 0, os.ErrInvalid
	}
	if l.dir == nil {
		return 0, os.ErrClosed
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if err := l.seekEntry(offset); err != nil {
		return 0, err
	}
	return l.readEntries(dst)
}

// seekEntry and readEntries require l.mu. Entry offsets count successfully
// stat'd entries, matching the count returned to pkg/sftp's request state.
func (l *jailDirLister) seekEntry(offset int64) error {
	if offset < l.offset {
		if _, err := l.dir.Seek(0, io.SeekStart); err != nil {
			return sanitizeSFTPErr(err)
		}
		l.offset = 0
	}
	var discarded [listStreamBatch]os.FileInfo
	for l.offset < offset {
		count := int(min(offset-l.offset, int64(len(discarded))))
		if _, err := l.readEntries(discarded[:count]); err != nil {
			return err
		}
	}
	return nil
}

func (l *jailDirLister) readEntries(dst []os.FileInfo) (int, error) {
	n := 0
	for n < len(dst) {
		names, readErr := l.dir.Readdirnames(min(len(dst)-n, listStreamBatch))
		for _, name := range names {
			var st unix.Stat_t
			if err := unix.Fstatat(int(l.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				continue
			}
			dst[n] = &statFileInfo{name: name, st: st}
			n++
			l.offset++
		}
		if errors.Is(readErr, io.EOF) {
			return n, io.EOF
		}
		if readErr != nil {
			return n, sanitizeSFTPErr(readErr)
		}
	}
	return n, nil
}

// ListStream invokes yield once per directory entry, pulling dirents in
// fixed-size batches so a directory with millions of entries does not
// have to be materialised in memory before being transmitted. Entries
// that vanish between readdir and fstatat (race with a concurrent
// unlink) are silently skipped — same tolerance as List. yield may
// return a non-nil error to terminate the walk early; that error is
// propagated to the caller unchanged.
func (j *jailFS) ListStream(clientPath string, yield func(os.FileInfo) error) error {
	f, err := j.openManagedDirectory(clientPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return streamDirectory(f, yield)
}

// streamDirectory lists an already-open directory without taking ownership of
// its handle. This lets protocol handlers open it before sending a success reply.
func streamDirectory(f *managedFile, yield func(os.FileInfo) error) error {
	fd := int(f.Fd())
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
	b := j.storage
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
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
	if b != nil {
		var st unix.Stat_t
		if err := unix.Fstatat(pfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			return &os.PathError{Op: "mkdir", Path: clientPath, Err: syscall.EEXIST}
		} else if !errors.Is(err, syscall.ENOENT) {
			return &os.PathError{Op: "mkdir", Path: clientPath, Err: err}
		}
		if b.entries >= b.limits.entries {
			return &os.PathError{Op: "mkdir", Path: clientPath, Err: ErrStorageLimit}
		}
	}
	if err := unix.Mkdirat(pfd, base, uint32(perm.Perm())); err != nil {
		return &os.PathError{Op: "mkdir", Path: clientPath, Err: err}
	}
	if b != nil {
		var st unix.Stat_t
		if err := unix.Fstatat(pfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			b.entries++ // retain a conservative charge if external mutation raced
			return err
		}
		if _, err := b.addEntry(&st, true); err != nil {
			return err
		}
	}
	return nil
}

// MkdirAll creates clientPath together with any missing parent directories,
// like os.MkdirAll, but confined to the jail: every level is created with
// Mkdir, which resolves the parent through openat2 with RESOLVE_NO_SYMLINKS, so
// no component may be reached through a symlink and the path cannot escape the
// jail. Directories that already exist are left untouched; it is an error if a
// component along the path exists as a non-directory. Passing the jail root
// (".", "" or "/") is a no-op.
func (j *jailFS) MkdirAll(clientPath string, perm os.FileMode) error {
	rel := cleanRelClientPath(clientPath)
	if rel == "." || rel == "" {
		return nil
	}
	prefix := ""
	for _, segment := range strings.Split(rel, "/") {
		if prefix == "" {
			prefix = segment
		} else {
			prefix += "/" + segment
		}
		// A pre-existing directory yields EEXIST, which is not an error for
		// MkdirAll; any other failure (ENOTDIR on a file component, ELOOP on a
		// symlink, EACCES) is fatal and returned to the caller.
		if err := j.Mkdir(prefix, perm); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
		// EEXIST also describes regular files and symlinks. Open the actual
		// component with O_DIRECTORY and the jail's no-symlink policy before
		// accepting it as a directory, including the final component.
		fd, err := j.openat(prefix, unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			return &os.PathError{Op: "mkdir", Path: clientPath, Err: err}
		}
		_ = unix.Close(fd)
	}
	return nil
}

// removeAt is the shared implementation of Remove and Rmdir; flags is either
// 0 (file unlink) or unix.AT_REMOVEDIR (directory unlink).
func (j *jailFS) removeAt(clientPath string, flags int, op string) error {
	b := j.storage
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
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
	var st unix.Stat_t
	if b != nil {
		if err := unix.Fstatat(pfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return &os.PathError{Op: op, Path: clientPath, Err: err}
		}
		if _, err := b.addEntry(&st, false); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(pfd, base, flags); err != nil {
		return &os.PathError{Op: op, Path: clientPath, Err: err}
	}
	if b != nil {
		b.removeLink(&st)
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
	b := j.storage
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
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
	var oldStat, newStat unix.Stat_t
	replaced := false
	if b != nil {
		if err := unix.Fstatat(oldFd, oldBase, &oldStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return &os.PathError{Op: "rename", Path: oldPath, Err: err}
		}
		if _, err := b.addEntry(&oldStat, false); err != nil {
			return err
		}
		if err := unix.Fstatat(newFd, newBase, &newStat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			if _, err := b.addEntry(&newStat, false); err != nil {
				return err
			}
			replaced = identifyFile(&oldStat) != identifyFile(&newStat)
		} else if !errors.Is(err, syscall.ENOENT) {
			return &os.PathError{Op: "rename", Path: newPath, Err: err}
		}
	}
	if err := unix.Renameat2(oldFd, oldBase, newFd, newBase, 0); err != nil {
		return &os.PathError{Op: "rename", Path: oldPath, Err: err}
	}
	if replaced {
		b.removeLink(&newStat)
	}
	return nil
}

// Chmod changes the permission bits of the entry at clientPath via fchmod on
// an openat2-obtained fd. Symlinks anywhere in the path cause failure.
func (j *jailFS) Chmod(clientPath string, perm os.FileMode) error {
	rel := cleanRelClientPath(clientPath)
	pathFD, err := j.openat(rel, unix.O_PATH, 0)
	if err != nil {
		return &os.PathError{Op: "chmod", Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(pathFD) }()
	// Open read-only after checking the pinned inode's type; fchmod requires
	// a non-O_PATH fd on supported kernels. Both attempts use the same pin.
	fd, err := reopenCheckedFile(pathFD, os.O_RDONLY, true)
	if err != nil {
		// Fall back to write-only if the file is write-only; failing that,
		// surface the original O_RDONLY error. The O_WRONLY error is
		// intentionally discarded: the O_RDONLY result is the one the
		// caller actually asked about (it covers the common cases —
		// ENOENT, EACCES on the path, jail escape) whereas an O_WRONLY
		// failure on the fallback only tells us that "the second guess
		// didn't work either", which would be more confusing than
		// helpful.
		fd2, err2 := reopenCheckedFile(pathFD, os.O_WRONLY, true)
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
	f, err := j.OpenWrite(clientPath, os.O_WRONLY, 0)
	if err != nil {
		return &os.PathError{Op: "truncate", Path: clientPath, Err: err}
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(size); err != nil {
		return &os.PathError{Op: "truncate", Path: clientPath, Err: err}
	}
	return nil
}

// Chtimes changes the access and modification timestamps of clientPath. The
// lookup goes through openat2 with RESOLVE_NO_SYMLINKS, then utimensat with
// AT_EMPTY_PATH applies the timestamps to that fd without reopening by path.
func (j *jailFS) Chtimes(clientPath string, atime, mtime time.Time) error {
	rel := cleanRelClientPath(clientPath)
	fd, err := j.openat(rel, unix.O_PATH, 0)
	if err != nil {
		return &os.PathError{Op: "chtimes", Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	times := []unix.Timespec{
		unix.NsecToTimespec(atime.UnixNano()),
		unix.NsecToTimespec(mtime.UnixNano()),
	}
	if err := unix.UtimesNanoAt(fd, "", times, unix.AT_EMPTY_PATH); err != nil {
		return &os.PathError{Op: "chtimes", Path: clientPath, Err: err}
	}
	return nil
}

// SetModTime changes only the modification timestamp of clientPath. The
// access timestamp is left unchanged by passing UTIME_OMIT to utimensat.
func (j *jailFS) SetModTime(clientPath string, mtime time.Time) error {
	rel := cleanRelClientPath(clientPath)
	fd, err := j.openat(rel, unix.O_PATH, 0)
	if err != nil {
		return &os.PathError{Op: "setmodtime", Path: clientPath, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	times := []unix.Timespec{
		{Nsec: unix.UTIME_OMIT},
		unix.NsecToTimespec(mtime.UnixNano()),
	}
	if err := unix.UtimesNanoAt(fd, "", times, unix.AT_EMPTY_PATH); err != nil {
		return &os.PathError{Op: "setmodtime", Path: clientPath, Err: err}
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
	// Timespec.Unix() returns (sec, nsec) as int64 on every platform; using
	// the raw .Sec/.Nsec fields would fail to compile on 32-bit Linux (arm,
	// 386) where those fields are int32.
	return time.Unix(s.st.Mtim.Unix())
}
func (s *statFileInfo) IsDir() bool      { return s.Mode().IsDir() }
func (s *statFileInfo) Sys() interface{} { return &s.st }
