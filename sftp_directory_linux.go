//go:build linux

package ironport

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/define42/ironport/internal/jailfs"
)

// directoryLister keeps only a directory cursor between READDIR requests.
// pkg/sftp supplies sequential offsets; rewinding and skipping also supports
// other ListAt callers without caching the entries already returned. Directory
// changes during enumeration follow filesystem readdir semantics, not a snapshot.
type directoryLister struct {
	mu     sync.Mutex
	dir    *jailfs.Dir
	offset int64
}

func (l *directoryLister) ListAt(dst []os.FileInfo, offset int64) (n int, err error) {
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

// seekEntry and readEntries require mu. Offsets count entries whose metadata
// was read successfully, matching the count returned to pkg/sftp.
func (l *directoryLister) seekEntry(offset int64) error {
	if offset < l.offset {
		if err := l.dir.Rewind(); err != nil {
			return sanitizeSFTPErr(err)
		}
		l.offset = 0
	}
	var discarded [512]os.FileInfo
	for l.offset < offset {
		count := int(min(offset-l.offset, int64(len(discarded))))
		if _, err := l.readEntries(discarded[:count]); err != nil {
			return err
		}
	}
	return nil
}

func (l *directoryLister) readEntries(dst []os.FileInfo) (int, error) {
	n, err := l.dir.ReadInto(dst)
	l.offset += int64(n)
	if errors.Is(err, io.EOF) {
		return n, io.EOF
	}
	return n, sanitizeSFTPErr(err)
}

func (l *directoryLister) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dir == nil {
		return nil
	}
	err := l.dir.Close()
	l.dir = nil
	return sanitizeSFTPErr(err)
}
