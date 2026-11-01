package jailfs

import (
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Dir is a directory cursor pinned to the directory opened by OpenDir.
// Reads, rewinds, and Close are safe to call concurrently. They serialize
// access to the cursor and its descriptor, including entry metadata lookups.
// A Dir must not be copied after first use.
type Dir struct {
	mu      sync.Mutex
	file    *os.File
	readErr error
}

// OpenDir opens a directory without following symlinks in any component.
// It validates the path immediately but reads no entries. The returned
// cursor keeps referring to the same directory if its path is renamed or
// replaced, and remains usable after the FS is closed.
func (j *FS) OpenDir(clientPath string) (*Dir, error) {
	rel := CleanPath(clientPath)
	fd, err := j.openat(rel, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: clientPath, Err: err}
	}
	return &Dir{file: os.NewFile(uintptr(fd), j.FullPath(rel))}, nil
}

// ReadInto fills entries with successive directory entries, reading names
// in batches of at most 512. Metadata is read relative to the open directory
// without following symlinks; entries whose metadata cannot be read are
// skipped, matching ListStream. Directory changes are not snapshotted.
//
// It returns io.EOF when it reaches the end, possibly with entries. An empty
// buffer does not advance the cursor. Reads after Close return os.ErrClosed.
func (d *Dir) ReadInto(entries []os.FileInfo) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return 0, os.ErrClosed
	}
	n := 0
	for n < len(entries) {
		if d.readErr != nil {
			return n, d.readErr
		}
		names, err := d.file.Readdirnames(min(len(entries)-n, listStreamBatch))
		d.readErr = err
		for _, name := range names {
			var st unix.Stat_t
			if statErr := unix.Fstatat(int(d.file.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); statErr != nil {
				continue
			}
			entries[n] = &statFileInfo{name: name, st: st}
			n++
		}
	}
	return n, nil
}

// Rewind restarts iteration at the beginning of the same open directory.
// It does not resolve the original path again. Rewinding a closed cursor
// returns os.ErrClosed.
func (d *Dir) Rewind() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return os.ErrClosed
	}
	if _, err := d.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	d.readErr = nil
	return nil
}

// Close releases the directory descriptor. Repeated calls return nil.
func (d *Dir) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil
	}
	err := d.file.Close()
	d.file = nil
	return err
}
