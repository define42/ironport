//go:build linux

package ironport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pkg/sftp"
)

func TestSFTPDirectoryOpenUsesBoundedAllocations(t *testing.T) {
	small := newSFTPDirectoryTestJail(t, 1)
	large := newSFTPDirectoryTestJail(t, 2048)
	// OPENDIR must allocate only a cursor, independent of directory size.
	// Leave generous fixed headroom for runtime or filesystem differences.
	smallAllocs := sftpDirectoryOpenAllocs(t, small)
	largeAllocs := sftpDirectoryOpenAllocs(t, large)
	if largeAllocs > smallAllocs+64 {
		t.Fatalf("OPENDIR allocations scale with directory size: small=%.0f large=%.0f", smallAllocs, largeAllocs)
	}
}

func sftpDirectoryOpenAllocs(t *testing.T, j jail) float64 {
	t.Helper()
	return testing.AllocsPerRun(3, func() {
		lister, err := j.Filelist(sftp.NewRequest("List", "/"))
		if err != nil {
			t.Fatal(err)
		}
		closeHandle(t, lister)
	})
}

func newSFTPDirectoryTestJail(t *testing.T, count int) jail {
	t.Helper()
	root := t.TempDir()
	files, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = files.Close() }()
	for i := range count {
		if err := files.WriteFile(fmt.Sprintf("entry-%05d", i), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return handleTestJail(t, root, nil)
}

func TestSFTPDirectoryListOffsets(t *testing.T) {
	j := newSFTPDirectoryTestJail(t, 1051)
	// The independent reference is only for this test. Production never
	// materializes this complete listing for an SFTP directory handle.
	want, err := j.fs.List("/")
	if err != nil {
		t.Fatal(err)
	}
	lister, err := j.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandle(t, lister)
	for _, tt := range []struct {
		name   string
		offset int64
	}{
		{"start", 0},
		{"sequential", 7},
		{"forward skip", 1048},
		{"rewind", 3},
		{"end", 1051},
		{"beyond end", 5000},
		{"rewind after EOF", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			requireSFTPDirectoryChunk(t, lister, want, tt.offset)
		})
	}
	if n, err := lister.ListAt(make([]os.FileInfo, 1), -1); n != 0 || !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("negative offset = %d, %v; want invalid argument", n, err)
	}
	if n, err := lister.ListAt(nil, 0); n != 0 || err != nil {
		t.Fatalf("empty buffer = %d, %v", n, err)
	}
	closeHandle(t, lister)
	if n, err := lister.ListAt(make([]os.FileInfo, 1), 0); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed directory = %d, %v; want closed", n, err)
	}
}

func requireSFTPDirectoryChunk(t *testing.T, lister sftp.ListerAt, want []os.FileInfo, offset int64) {
	t.Helper()
	var got [7]os.FileInfo
	n, err := lister.ListAt(got[:], offset)
	wantN := int(min(int64(len(got)), max(0, int64(len(want))-offset)))
	if n != wantN {
		t.Fatalf("ListAt(%d) count = %d; want %d", offset, n, wantN)
	}
	if (n < len(got) && !errors.Is(err, io.EOF)) || (n == len(got) && err != nil) {
		t.Fatalf("ListAt(%d) error = %v with %d entries", offset, err, n)
	}
	for i := range n {
		if got[i].Name() != want[int(offset)+i].Name() {
			t.Fatalf("entry %d = %q; want %q", i, got[i].Name(), want[int(offset)+i].Name())
		}
	}
}

func TestSFTPDirectoryEOFStillConsumesHandleBudget(t *testing.T) {
	owner := &handleBudget{max: 1, maxUser: 1, maxSession: 1}
	j := handleTestJail(t, t.TempDir(), &sessionHandleBudget{owner: owner, username: "alice"})
	lister, err := j.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandle(t, lister)
	if n, err := lister.ListAt(make([]os.FileInfo, 1), 0); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty directory = %d, %v", n, err)
	}
	if extra, err := j.Filelist(sftp.NewRequest("List", "/")); err == nil {
		closeHandle(t, extra)
		t.Fatal("EOF released the permit while the protocol handle was still open")
	}
	closeHandle(t, lister)
	reused, err := j.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatalf("CLOSE failed to release the permit: %v", err)
	}
	closeHandle(t, reused)
}

func TestSFTPDirectoryConcurrentReadAndClose(t *testing.T) {
	j := newSFTPDirectoryTestJail(t, 32)
	lister, err := j.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandle(t, lister)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			var entries [7]os.FileInfo
			for range 10 {
				if _, err := lister.ListAt(entries[:], 0); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Errorf("concurrent ListAt: %v", err)
				}
			}
		})
	}
	closeHandle(t, lister)
	wg.Wait()
}

type sftpClosingTestLister struct {
	closeCalls atomic.Int32
	closeErr   error
}

func (*sftpClosingTestLister) ListAt([]os.FileInfo, int64) (int, error) { return 0, io.EOF }

func (l *sftpClosingTestLister) Close() error {
	l.closeCalls.Add(1)
	return l.closeErr
}

func TestSFTPDirectoryBudgetForwardsCloseOnce(t *testing.T) {
	underlying := &sftpClosingTestLister{closeErr: &os.PathError{Op: "close", Path: "/private/root", Err: errors.New("private backend error")}}
	var releases atomic.Int32
	lister := &budgetLister{ListerAt: underlying, release: func() { releases.Add(1) }}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := lister.Close(); !errors.Is(err, errSFTPRequestFailed) {
				t.Errorf("Close = %v; want sanitized backend error", err)
			}
		})
	}
	wg.Wait()
	if underlying.closeCalls.Load() != 1 || releases.Load() != 1 {
		t.Fatalf("close calls=%d releases=%d; want exactly one each", underlying.closeCalls.Load(), releases.Load())
	}
}
