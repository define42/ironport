//go:build linux

package ironport

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/define42/ironport/internal/jailfs"
	"github.com/pkg/sftp"
)

func handleTestJail(t *testing.T, root string, budget *sessionHandleBudget) jail {
	t.Helper()
	fs, err := jailfs.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return jail{fs: fs, canRead: true, canWrite: true, handles: budget}
}

func closeHandle(t *testing.T, handle any) {
	t.Helper()
	c, ok := handle.(io.Closer)
	if !ok {
		t.Fatalf("handle %T has no Close", handle)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func openHandleForTest(t *testing.T, j jail, method string, r *sftp.Request) error {
	t.Helper()
	switch method {
	case "Get":
		_, err := j.Fileread(r)
		return err
	case "Put":
		_, err := j.Filewrite(r)
		return err
	case "Open":
		_, err := j.OpenFile(r)
		return err
	case "List":
		_, err := j.Filelist(r)
		return err
	default:
		t.Fatalf("unknown handle method %q", method)
		return nil
	}
}

//nolint:funlen // one lifecycle verifies interacting session/user/global caps and safe slot reuse
func TestSFTPHandleBudgets(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := &handleBudget{max: 3, maxUser: 2, maxSession: 1}
	first := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	second := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	third := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "bob"})
	fourth := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "carol"})
	if _, err := first.Fileread(sftp.NewRequest("Get", "/missing")); err == nil {
		t.Fatal("missing file opened")
	}
	r, err := first.Fileread(sftp.NewRequest("Get", "/existing"))
	if err != nil {
		t.Fatalf("failed open leaked slot: %v", err)
	}
	defer closeHandle(t, r)
	if _, err := first.Filelist(sftp.NewRequest("List", "/")); err == nil {
		t.Fatal("directory open bypassed session budget")
	}
	d, err := second.Filelist(sftp.NewRequest("List", "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandle(t, d)
	extra := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	if _, err := extra.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("second connection bypassed per-user cap")
	}
	req := sftp.NewRequest("Put", "/new")
	req.Flags = 2 | 8 | 16 // WRITE | CREAT | TRUNC
	w, err := third.Filewrite(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fourth.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("global handle cap bypassed")
	}
	req.Filepath = "/existing"
	if _, err := first.Filewrite(req); err == nil {
		t.Fatal("write open bypassed handle cap")
	}
	//nolint:gosec // G304: the path is a fixed filename inside this test's temporary directory
	if content, err := os.ReadFile(filepath.Join(root, "existing")); err != nil || string(content) != "keep" {
		t.Fatalf("rejected write modified target: %q, %v", content, err)
	}
	closeHandle(t, w)
	closeHandle(t, w) // double CLOSE must not release somebody else's slot
	reused, err := fourth.Fileread(sftp.NewRequest("Get", "/existing"))
	if err != nil {
		t.Fatalf("closed slot not reusable: %v", err)
	}
	defer closeHandle(t, reused)
	if _, err := third.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("double close over-released global budget")
	}
}

func TestSFTPHandleOpenFailuresReleaseSlots(t *testing.T) {
	for _, method := range []string{"Get", "Put", "Open", "List"} {
		t.Run(method, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "existing"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			owner := &handleBudget{max: 1, maxUser: 1, maxSession: 1}
			j := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
			r := sftp.NewRequest(method, "/missing/child")
			r.Flags = 2 | 8 | 16 // WRITE | CREAT | TRUNC
			if method == "Open" {
				r.Flags |= 1 // READ
			}
			err := openHandleForTest(t, j, method, r)
			if err == nil {
				t.Fatal("missing path unexpectedly opened")
			}
			handle, err := j.Fileread(sftp.NewRequest("Get", "/existing"))
			if err != nil {
				t.Fatalf("failed open leaked its slot: %v", err)
			}
			closeHandle(t, handle)
		})
	}
}

func TestSFTPReadWriteHandleUsesOneBudgetSlot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := &handleBudget{max: 1, maxUser: 1, maxSession: 1}
	j := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	req := sftp.NewRequest("Open", "/existing")
	req.Flags = 1 | 2 // READ | WRITE
	handle, err := j.OpenFile(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("read/write handle used more than one slot or bypassed the budget")
	}
	closeHandle(t, handle)
	closeHandle(t, handle) // double CLOSE must not release an extra slot

	reused, err := j.Fileread(sftp.NewRequest("Get", "/existing"))
	if err != nil {
		t.Fatalf("closed read/write slot not reusable: %v", err)
	}
	defer closeHandle(t, reused)
	if _, err := j.Fileread(sftp.NewRequest("Get", "/existing")); err == nil {
		t.Fatal("double close over-released the read/write handle budget")
	}
}

func TestSFTPHandleBudgetsConcurrent(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	owner := &handleBudget{max: 3, maxUser: 2, maxSession: 2}
	first := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "alice"})
	second := handleTestJail(t, root, &sessionHandleBudget{owner: owner, username: "bob"})
	accepted := make(chan io.ReaderAt, 30)
	var wg sync.WaitGroup
	for i := range 30 {
		j := first
		if i%2 == 0 {
			j = second
		}
		wg.Go(func() {
			handle, err := j.Fileread(sftp.NewRequest("Get", "/existing"))
			if err == nil {
				accepted <- handle
			} else if !errors.Is(err, sftp.ErrSSHFxFailure) {
				t.Errorf("unexpected open error: %v", err)
			}
		})
	}
	wg.Wait()
	close(accepted)
	count := 0
	for handle := range accepted {
		count++
		closeHandle(t, handle)
	}
	if count != 3 {
		t.Fatalf("admitted %d concurrent handles; want 3", count)
	}
	for range 2 {
		handle, err := first.Fileread(sftp.NewRequest("Get", "/existing"))
		if err != nil {
			t.Fatalf("closed slots not reusable: %v", err)
		}
		defer closeHandle(t, handle)
	}
}
