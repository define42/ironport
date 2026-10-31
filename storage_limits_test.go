//go:build linux

package ironport

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func storageTestServer(t *testing.T, root string, config *Config) (*Server, *jailFS) {
	t.Helper()
	s := NewServer(config)
	j := storageTestJail(t, s, root)
	return s, j
}

func storageTestJail(t *testing.T, s *Server, root string) *jailFS {
	t.Helper()
	j, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	if err := s.attachStorageBudget(j); err != nil {
		t.Fatal(err)
	}
	return j
}

func storageTestWrite(t *testing.T, j *jailFS, name, content string) {
	t.Helper()
	f, err := j.OpenWrite(name, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
}

func TestStorageLimitsExistingFilesRestartAndCleanup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), []byte("12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := &Config{MaxJailBytes: 8, MaxFileBytes: 8, MaxJailEntries: 2}
	_, j := storageTestServer(t, root, config)
	f, err := j.OpenWrite("new", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("existing bytes ignored: %v", err)
	}
	_ = f.Close()
	if err := j.Truncate("existing", 4); err != nil {
		t.Fatal(err)
	}
	storageTestWrite(t, j, "new", "abcd")
	_ = j.Close()
	// A new Server must derive usage from disk, not reset the account to zero.
	_, reopened := storageTestServer(t, root, config)
	f, err = reopened.OpenWrite("new", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("!"); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("restart discarded usage: %v", err)
	}
	if err := reopened.Remove("existing"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("!"); err != nil {
		t.Fatalf("delete did not release bytes: %v", err)
	}
}

func TestStorageLimitsSparseOffsetsTruncateAndTransfer(t *testing.T) {
	t.Parallel()
	_, j := storageTestServer(t, t.TempDir(), &Config{MaxFileBytes: 8, MaxTransferBytes: 4, MaxJailBytes: 16})
	f, err := j.OpenWrite("file", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, offset := range []int64{-1, 8, math.MaxInt64} {
		if _, err := f.WriteAt([]byte("a"), offset); !errors.Is(err, ErrStorageLimit) {
			t.Errorf("offset %d: %v", offset, err)
		}
	}
	if err := f.Truncate(9); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("oversized truncate accepted: %v", err)
	}
	if err := f.Truncate(8); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if _, err := f.WriteAt([]byte("x"), 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.WriteAt([]byte("x"), 0); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("repeated offsets bypassed transfer cap: %v", err)
	}
	info, err := f.Stat()
	if err != nil || info.Size() != 8 {
		t.Fatalf("size changed after rejection: info=%v err=%v", info, err)
	}
}

func TestStorageLimitsCopyAndWriteStringCannotBypass(t *testing.T) {
	t.Parallel()
	_, j := storageTestServer(t, t.TempDir(), &Config{MaxFileBytes: 4})
	f, err := j.OpenWrite("file", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, strings.NewReader("12345")); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("io.Copy bypassed quota: %v", err)
	}
	if _, err := f.WriteString("12345"); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("WriteString bypassed quota: %v", err)
	}
	// Force destination ReaderFrom (the other io.Copy fast path).
	if _, err := io.Copy(f, struct{ io.Reader }{strings.NewReader("12345")}); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("ReaderFrom bypassed quota: %v", err)
	}
	info, _ := f.Stat()
	if info.Size() != 0 {
		t.Fatalf("quota rejection mutated file: size=%d", info.Size())
	}
}

func TestStorageLimitsSharedRootConcurrentAppend(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	s, first := storageTestServer(t, root, &Config{MaxJailBytes: 64, MaxFileBytes: 64})
	second := storageTestJail(t, s, root)
	var writes atomic.Int64
	var wg sync.WaitGroup
	for i := range 8 {
		j := first
		if i%2 == 1 {
			j = second
		}
		f, err := j.OpenWrite("shared", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			defer func() { _ = f.Close() }()
			for range 64 {
				if _, err := f.Write([]byte("x")); err == nil {
					writes.Add(1)
				} else if !errors.Is(err, ErrStorageLimit) {
					t.Errorf("append: %v", err)
				}
			}
		})
	}
	wg.Wait()
	info, err := first.Stat("shared")
	if err != nil || info.Size() != 64 || writes.Load() != 64 {
		t.Fatalf("concurrent append exceeded quota: info=%v writes=%d err=%v", info, writes.Load(), err)
	}
}

func TestStorageLimitsUnlinkedHandlesRetainBytesAndEntries(t *testing.T) {
	t.Parallel()
	_, j := storageTestServer(t, t.TempDir(), &Config{MaxJailBytes: 4, MaxJailEntries: 1})
	storageTestWrite(t, j, "file", "1234")
	reader, err := j.OpenRead("file")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	writer, err := j.OpenWrite("file", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	if err := j.Remove("file"); err != nil {
		t.Fatal(err)
	}
	if f, err := j.OpenWrite("new", os.O_CREATE|os.O_WRONLY, 0o600); !errors.Is(err, ErrStorageLimit) {
		if f != nil {
			_ = f.Close()
		}
		t.Fatalf("unlinked open file released entry: %v", err)
	}
	_ = writer.Close()
	_ = writer.Close() // release must be exactly once
	if err := j.Mkdir("dir", 0o700); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("remaining reader did not retain entry: %v", err)
	}
	_ = reader.Close()
	storageTestWrite(t, j, "new", "1234")
}

func TestStorageLimitsUnlinkedOpenDirectoryRetainsEntry(t *testing.T) {
	t.Parallel()
	_, j := storageTestServer(t, t.TempDir(), &Config{MaxJailEntries: 1})
	if err := j.Mkdir("dir", 0o700); err != nil {
		t.Fatal(err)
	}
	lister, err := j.OpenList("dir")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lister.Close() }()
	if err := j.Rmdir("dir"); err != nil {
		t.Fatal(err)
	}
	if err := j.Mkdir("next", 0o700); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("unlinked open directory released entry: %v", err)
	}
	_ = lister.Close()
	if err := j.Mkdir("next", 0o700); err != nil {
		t.Fatalf("close did not release directory entry: %v", err)
	}
}

func TestStorageLimitsReconnectRetainsUnlinkedHandle(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	s, j := storageTestServer(t, root, &Config{MaxJailBytes: 4})
	storageTestWrite(t, j, "file", "1234")
	reader, err := j.OpenRead("file")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if err := j.Remove("file"); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	reconnected := storageTestJail(t, s, root)
	f, err := reconnected.OpenWrite("new", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("1234"); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("reconnect lost an unlinked handle's charge: %v", err)
	}
	_ = reader.Close()
	if _, err := f.WriteString("1234"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_ = reconnected.Close()
	s.storage.mu.Lock()
	retained := len(s.storage.roots)
	s.storage.mu.Unlock()
	if retained != 0 {
		t.Fatalf("closed sessions retained %d budget cache entries", retained)
	}
}

func TestStorageLimitsConcurrentReconnect(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	s := NewServer(&Config{MaxJailBytes: 64})
	var writes atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 16 {
				j, err := openJailFS(root)
				if err != nil {
					t.Error(err)
					return
				}
				if err := s.attachStorageBudget(j); err != nil {
					_ = j.Close()
					t.Error(err)
					return
				}
				f, err := j.OpenWrite("shared", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					_ = j.Close()
					t.Error(err)
					return
				}
				if _, err := f.WriteString("x"); err == nil {
					writes.Add(1)
				} else if !errors.Is(err, ErrStorageLimit) {
					t.Error(err)
				}
				_ = f.Close()
				_ = j.Close()
			}
		})
	}
	wg.Wait()
	info, err := os.Stat(filepath.Join(root, "shared"))
	if err != nil || info.Size() != 64 || writes.Load() != 64 {
		t.Fatalf("reconnect lost shared usage: info=%v writes=%d err=%v", info, writes.Load(), err)
	}
}

func TestStorageLimitsHardlinksRenameAndDirectories(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "first"), []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "first"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	_, j := storageTestServer(t, root, &Config{MaxJailBytes: 8, MaxJailEntries: 3})
	// Both names consume entries but their shared inode consumes bytes once.
	storageTestWrite(t, j, "second", "5678")
	if err := j.Rename("first", "alias"); err != nil {
		t.Fatal(err)
	}
	if err := j.Mkdir("dir", 0o700); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("same-inode rename released an entry: %v", err)
	}
	if err := j.Remove("first"); err != nil {
		t.Fatal(err)
	}
	f, err := j.OpenWrite("second", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("!"); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("removing one hardlink released bytes: %v", err)
	}
	_ = f.Close()
	if err := j.Rename("second", "alias"); err != nil {
		t.Fatal(err)
	}
	if err := j.MkdirAll("dir/child", 0o700); err != nil {
		t.Fatalf("overwrite did not release entries: %v", err)
	}
	if err := j.MkdirAll("dir/child/grandchild", 0o700); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("mkdirall bypassed entry cap: %v", err)
	}
	if err := j.Rmdir("dir/child"); err != nil {
		t.Fatal(err)
	}
	storageTestWrite(t, j, "new", "1234")
}

func TestStorageLimitsRenameReplacementRetainsOpenInode(t *testing.T) {
	t.Parallel()
	_, j := storageTestServer(t, t.TempDir(), &Config{MaxJailBytes: 8})
	storageTestWrite(t, j, "first", "1234")
	storageTestWrite(t, j, "second", "5678")
	reader, err := j.OpenRead("second")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if err := j.Rename("first", "second"); err != nil {
		t.Fatal(err)
	}
	f, err := j.OpenWrite("new", os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString("1234"); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("rename released a pinned inode: %v", err)
	}
	_ = reader.Close()
	if _, err := f.WriteString("1234"); err != nil {
		t.Fatalf("close did not release replaced inode bytes: %v", err)
	}
}

func TestStorageLimitsOverQuotaAllowsCleanup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), []byte("12345678"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, j := storageTestServer(t, root, &Config{MaxJailBytes: 4, MaxFileBytes: 4})
	if err := j.Truncate("existing", 5); err != nil {
		t.Fatalf("shrinking existing over-limit file blocked: %v", err)
	}
	if err := j.Truncate("existing", 6); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("over-limit file growth accepted: %v", err)
	}
	if err := j.Remove("existing"); err != nil {
		t.Fatal(err)
	}
	storageTestWrite(t, j, "new", "1234")
}

func TestStorageLimitsScanFailsClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for i := range 3 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprint(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := NewServer(&Config{MaxJailEntries: 1})
	j, err := openJailFS(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	if err := s.attachStorageBudget(j); !errors.Is(err, ErrStorageLimit) {
		t.Fatalf("unbounded initial scan accepted: %v", err)
	}
	if j.storage != nil {
		t.Fatal("failed scan attached incomplete accounting")
	}
}
