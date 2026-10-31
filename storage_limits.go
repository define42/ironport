//go:build linux

package ironport

import (
	"errors"
	"io"
	"math"
	"os"
	"path"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	defaultMaxFileBytes     int64 = 200 << 30
	defaultMaxTransferBytes int64 = 200 << 30
	defaultMaxJailBytes     int64 = 1 << 40
	defaultMaxJailEntries   int64 = 1_000_000
)

// ErrStorageLimit means an application storage or transfer budget was exhausted.
// Filesystem quotas are still required: these limits cover mutations through
// one Server, not other processes, overlapping jails, or physical allocation.
var ErrStorageLimit = syscall.EDQUOT

type storageLimits struct {
	fileBytes     int64
	transferBytes int64
	jailBytes     int64
	entries       int64
}

func newStorageManager(config *Config) *storageManager {
	limits := storageLimits{
		fileBytes: config.MaxFileBytes, transferBytes: config.MaxTransferBytes,
		jailBytes: config.MaxJailBytes, entries: config.MaxJailEntries,
	}
	if limits.fileBytes <= 0 {
		limits.fileBytes = defaultMaxFileBytes
	}
	if limits.transferBytes <= 0 {
		limits.transferBytes = defaultMaxTransferBytes
	}
	if limits.jailBytes <= 0 {
		limits.jailBytes = defaultMaxJailBytes
	}
	if limits.entries <= 0 {
		limits.entries = defaultMaxJailEntries
	}
	return &storageManager{limits: limits, roots: make(map[fileIdentity]*storageBudget)}
}

type fileIdentity struct {
	device uint64
	inode  uint64
}

func identifyFile(st *unix.Stat_t) fileIdentity {
	return fileIdentity{device: uint64(st.Dev), inode: uint64(st.Ino)}
}

type storageManager struct {
	mu     sync.Mutex
	limits storageLimits
	roots  map[fileIdentity]*storageBudget
}

// storageBudget serializes filesystem mutations for a root across protocols
// and users. The lock covers short filesystem calls, never a network read.
// Counters include unlinked inodes until their last managed handle is closed.
type storageBudget struct {
	mu      sync.Mutex
	limits  storageLimits
	bytes   int64
	entries int64
	files   map[fileIdentity]*storageEntry
	jails   int64
	handles int64
	manager *storageManager
	rootID  fileIdentity
	pending int // attachment references, guarded by manager.mu
}

type storageEntry struct {
	size    int64
	links   int64 // directory entries inside this jail, not st.Nlink
	handles int64
}

func (s *Server) attachStorageBudget(j *jailFS) error {
	s.mu.Lock()
	if s.storage == nil {
		s.storage = newStorageManager(&Config{})
	}
	m := s.storage
	s.mu.Unlock()
	var st unix.Stat_t
	if err := unix.Fstat(j.rootFd, &st); err != nil {
		return err
	}
	id := identifyFile(&st)
	m.mu.Lock()
	b := m.roots[id]
	if b == nil {
		b = &storageBudget{limits: m.limits, manager: m, rootID: id}
		m.roots[id] = b
	}
	b.pending++
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		b.pending--
		m.mu.Unlock()
		b.forgetIdle()
	}()
	b.mu.Lock()
	defer b.mu.Unlock()
	// Rescan between lifetimes, including reconnects after all handles close.
	// This also avoids reusing stale accounting if a removed root inode is
	// recycled by the filesystem. A failed scan never publishes a budget.
	if b.jails == 0 && b.handles == 0 {
		fresh := &storageBudget{limits: m.limits, files: make(map[fileIdentity]*storageEntry)}
		if err := fresh.scan(j, ".", 0, make(map[fileIdentity]bool)); err != nil {
			return err
		}
		b.bytes, b.entries, b.files = fresh.bytes, fresh.entries, fresh.files
	}
	b.jails++
	j.storage = b
	return nil
}

// forgetIdle releases cached scan metadata when the last session and managed
// handle leave. A new session then reconstructs usage from disk. Lock ordering
// is always manager before budget, including concurrent attachment/teardown.
func (b *storageBudget) forgetIdle() {
	m := b.manager
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// An in-progress attachment may be scanning under b.mu. Its pending
	// reference already keeps the cache alive; do not block other roots on it.
	if b.pending != 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.jails == 0 && b.handles == 0 && m.roots[b.rootID] == b {
		delete(m.roots, b.rootID)
	}
}

func (b *storageBudget) scan(j *jailFS, rel string, depth int, visited map[fileIdentity]bool) error {
	// Bound scan stack and metadata, including roots already over quota. Such
	// roots require administrator cleanup if they exceed this scan allowance.
	if depth > 256 {
		return ErrStorageLimit
	}
	fd, err := j.openat(rel, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), rel)
	defer func() { _ = f.Close() }()
	var dirStat unix.Stat_t
	if err := unix.Fstat(fd, &dirStat); err != nil {
		return err
	}
	id := identifyFile(&dirStat)
	if visited[id] {
		return syscall.ELOOP
	}
	visited[id] = true
	allowance := min(b.limits.entries, int64(10000))
	scanLimit := b.limits.entries
	if scanLimit <= math.MaxInt64-allowance {
		scanLimit += allowance
	}
	for {
		names, readErr := f.Readdirnames(listStreamBatch)
		for _, name := range names {
			if b.entries >= scanLimit {
				return ErrStorageLimit
			}
			var st unix.Stat_t
			if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err // incomplete scans must never undercount
			}
			if _, err := b.addEntry(&st, true); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				if err := b.scan(j, path.Join(rel, name), depth+1, visited); err != nil {
					return err
				}
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

// addEntry registers an inode; anotherLink is true only for a newly observed
// directory entry. Existing hardlinks share bytes but each consumes an entry.
func (b *storageBudget) addEntry(st *unix.Stat_t, anotherLink bool) (*storageEntry, error) {
	id := identifyFile(st)
	e := b.files[id]
	if e == nil {
		size := int64(0)
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			size = st.Size
		}
		if size < 0 || size > math.MaxInt64-b.bytes {
			return nil, ErrStorageLimit
		}
		e = &storageEntry{size: size, links: 1}
		b.files[id] = e
		b.bytes += size
		b.entries++
	} else if anotherLink {
		e.links++
		b.entries++
	}
	return e, nil
}

func (b *storageBudget) removeLink(st *unix.Stat_t) {
	id := identifyFile(st)
	e := b.files[id]
	if e == nil || e.links == 0 {
		return
	}
	e.links--
	if e.links > 0 || e.handles == 0 {
		b.entries--
	}
	if e.links == 0 && e.handles == 0 {
		b.bytes -= e.size
		delete(b.files, id)
	}
}

func (b *storageBudget) canGrow(e *storageEntry, size int64) error {
	if size < 0 || size > b.limits.fileBytes {
		return ErrStorageLimit
	}
	if size > e.size && (b.bytes >= b.limits.jailBytes || size-e.size > b.limits.jailBytes-b.bytes) {
		return ErrStorageLimit
	}
	return nil
}

func (b *storageBudget) setSize(e *storageEntry, size int64) {
	b.bytes += size - e.size
	e.size = size
}

func (j *jailFS) openManaged(clientPath string, flags int, perm os.FileMode) (*managedFile, error) {
	b := j.storage
	if b == nil {
		f, err := j.openRegular(clientPath, flags, perm)
		if err != nil {
			return nil, err
		}
		return &managedFile{File: f, appendMode: flags&os.O_APPEND != 0}, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Open without O_TRUNC, validate/account the inode, then truncate under
	// the same lock as every writer. Exclusive creation prevents a pathname
	// race from silently replacing the existence check.
	openFlags := flags &^ os.O_TRUNC
	var f *os.File
	var err error
	if flags&os.O_CREATE != 0 {
		if flags&os.O_EXCL == 0 {
			f, err = j.openRegular(clientPath, openFlags&^os.O_CREATE, 0)
		}
		if flags&os.O_EXCL != 0 || errors.Is(err, os.ErrNotExist) {
			if b.entries >= b.limits.entries {
				return nil, &os.PathError{Op: "open", Path: clientPath, Err: ErrStorageLimit}
			}
			f, err = j.openRegular(clientPath, openFlags|os.O_EXCL, perm)
		}
	} else {
		f, err = j.openRegular(clientPath, openFlags, perm)
	}
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	e, err := b.addEntry(&st, false)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if flags&os.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			_ = f.Close()
			return nil, err
		}
		b.setSize(e, 0)
	}
	e.handles++
	b.handles++
	return &managedFile{File: f, budget: b, entry: e, id: identifyFile(&st), appendMode: flags&os.O_APPEND != 0}, nil
}

func (j *jailFS) openManagedDirectory(clientPath string) (*managedFile, error) {
	rel := cleanRelClientPath(clientPath)
	b := j.storage
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
	fd, err := j.openat(rel, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: clientPath, Err: err}
	}
	f := os.NewFile(uintptr(fd), rel)
	// The jail root is excluded from entry limits and cannot be removed by a
	// client. Other open directories retain an entry charge after rmdir.
	if b == nil || rel == "." {
		return &managedFile{File: f}, nil
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, err
	}
	e, err := b.addEntry(&st, false)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	e.handles++
	b.handles++
	return &managedFile{File: f, budget: b, entry: e, id: identifyFile(&st)}, nil
}

// managedFile must be passed as a whole to io.Copy and protocol adapters.
// Accessing its embedded File for writes bypasses accounting. The type is
// internal so callers of the public server API cannot do that accidentally.
type managedFile struct {
	*os.File
	mu         sync.Mutex
	budget     *storageBudget
	entry      *storageEntry
	id         fileIdentity
	appendMode bool
	written    int64
	closed     bool
}

func (f *managedFile) Write(p []byte) (int, error) {
	return f.write(p, 0, false)
}

func (f *managedFile) WriteAt(p []byte, offset int64) (int, error) {
	return f.write(p, offset, true)
}

func (f *managedFile) WriteString(s string) (int, error) { return f.Write([]byte(s)) }

func (f *managedFile) ReadFrom(r io.Reader) (int64, error) {
	// Hide ReaderFrom so io.Copy cannot select os.File's zero-copy path.
	return io.Copy(struct{ io.Writer }{f}, r)
}

func (f *managedFile) write(p []byte, offset int64, at bool) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	b := f.budget
	if b == nil {
		if at {
			return f.File.WriteAt(p, offset)
		}
		return f.File.Write(p)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if int64(len(p)) > b.limits.transferBytes-f.written {
		return 0, ErrStorageLimit
	}
	if at && f.appendMode {
		return 0, os.ErrInvalid
	}
	if !at {
		if f.appendMode {
			offset = f.entry.size
		} else {
			var err error
			offset, err = f.File.Seek(0, io.SeekCurrent)
			if err != nil {
				return 0, err
			}
		}
	}
	if offset < 0 || offset > math.MaxInt64-int64(len(p)) {
		return 0, ErrStorageLimit
	}
	end := offset + int64(len(p))
	if err := b.canGrow(f.entry, max(f.entry.size, end)); err != nil {
		return 0, err
	}
	var n int
	var err error
	if at {
		n, err = f.File.WriteAt(p, offset)
	} else {
		n, err = f.File.Write(p)
	}
	f.written += int64(n)
	if n > 0 {
		b.setSize(f.entry, max(f.entry.size, offset+int64(n)))
	}
	return n, err
}

func (f *managedFile) Truncate(size int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return os.ErrClosed
	}
	b := f.budget
	if b == nil {
		return f.File.Truncate(size)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Always permit shrinking an existing over-limit file to recover space.
	if size < 0 {
		return os.ErrInvalid
	}
	if size > f.entry.size {
		if err := b.canGrow(f.entry, size); err != nil {
			return err
		}
	}
	if err := f.File.Truncate(size); err != nil {
		return err
	}
	b.setSize(f.entry, size)
	return nil
}

func (f *managedFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, os.ErrClosed
	}
	return f.File.Seek(offset, whence)
}

func (f *managedFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	if b := f.budget; b != nil {
		b.mu.Lock()
		// Closing the final descriptor may permit immediate inode reuse.
		// Keep it serialized with creates until its accounting is released.
		err := f.File.Close()
		f.entry.handles--
		b.handles--
		if f.entry.handles == 0 && f.entry.links == 0 {
			b.bytes -= f.entry.size
			b.entries--
			delete(b.files, f.id)
		}
		b.mu.Unlock()
		b.forgetIdle()
		return err
	}
	return f.File.Close()
}
