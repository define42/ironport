//go:build linux

package ironport

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Swap the pathname synchronously from the success log: authentication has
// returned its jail, but the handler has not yet started storing the body.
func TestHTTPIngestRetainsAuthenticatedJail(t *testing.T) {
	base, configuredRoot := newRetainedJailFixture(t)
	srv := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: configuredRoot, CanWrite: true},
	})
	var swapErr error
	logger := &retainedJailLogWriter{
		previous: log.Writer(),
		match:    fmt.Sprintf("login protocol=http user=%q root=%q", "alice", configuredRoot),
		onMatch:  func() { swapErr = replaceRetainedJailPath(base) },
	}
	log.SetOutput(logger)
	t.Cleanup(func() { log.SetOutput(logger.previous) })

	payload := []byte("authenticated HTTP jail")
	rec := doHTTPUpload(t, srv, "alice", "pw", "file", "retained.txt", payload)
	if !logger.matched || swapErr != nil {
		t.Fatalf("authenticated root replacement: matched=%t err=%v", logger.matched, swapErr)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%q; want successful upload", rec.Code, rec.Body.String())
	}
	got, err := base.ReadFile("opened/retained.txt")
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("retained jail upload = %q, %v; want %q", got, err, payload)
	}
	if _, err := base.Stat("root/retained.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement jail received upload: %v", err)
	}
}

type retainedJailLogWriter struct {
	previous io.Writer
	match    string
	onMatch  func()
	once     sync.Once
	matched  bool
}

func (w *retainedJailLogWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.match) {
		w.once.Do(func() {
			w.matched = true
			w.onMatch()
		})
	}
	return w.previous.Write(p)
}

func newRetainedJailFixture(t *testing.T) (*os.Root, string) {
	t.Helper()
	basePath := t.TempDir()
	base, err := os.OpenRoot(basePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = base.Close() })
	if err := base.Mkdir("root", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := base.WriteFile("root/marker", []byte("original jail"), 0o600); err != nil {
		t.Fatal(err)
	}
	return base, filepath.Join(basePath, "root")
}

func replaceRetainedJailPath(base *os.Root) error {
	if err := base.Rename("root", "opened"); err != nil {
		return err
	}
	if err := base.Mkdir("root", 0o700); err != nil {
		return err
	}
	return base.WriteFile("root/marker", []byte("replacement jail"), 0o600)
}

func TestHTTPIngestClosesAuthenticatedJailOnEveryReturn(t *testing.T) {
	cases := []struct {
		name       string
		canWrite   bool
		validBody  bool
		wantStatus int
	}{
		{name: "stored", canWrite: true, validBody: true, wantStatus: http.StatusCreated},
		{name: "permission denied", validBody: true, wantStatus: http.StatusForbidden},
		{name: "bad body", canWrite: true, wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			srv := newHTTPTestServer(t, map[string]UserInfo{
				"alice": {Password: "pw", Root: root, CanWrite: tc.canWrite},
			})
			body, contentType := buildMultipartUpload(t, "file", "upload.txt", []byte("contents"))
			if !tc.validBody {
				contentType = "text/plain"
			}
			req := httptest.NewRequest(http.MethodPost, "/upload", body)
			req.Header.Set("Content-Type", contentType)
			req.SetBasicAuth("alice", "pw")
			rec := httptest.NewRecorder()
			before := countRetainedJailDescriptors(t, root)
			srv.HttpIngest()(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d; want %d", rec.Code, tc.wantStatus)
			}
			if after := countRetainedJailDescriptors(t, root); after != before {
				t.Fatalf("jail descriptors after request=%d; before=%d", after, before)
			}
		})
	}
}

func countRetainedJailDescriptors(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && target == root {
			count++
		}
	}
	return count
}

func TestHTTPAuthenticationPanicClosesJailBeforeTransfer(t *testing.T) {
	root := t.TempDir()
	srv := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanWrite: true},
	})
	logger := &retainedJailLogWriter{
		previous: log.Writer(),
		match:    fmt.Sprintf("login protocol=http user=%q root=%q", "alice", root),
		onMatch:  func() { panic("log writer failure") },
	}
	log.SetOutput(logger)
	t.Cleanup(func() { log.SetOutput(logger.previous) })
	before := countRetainedJailDescriptors(t, root)
	var caught any
	func() {
		defer func() { caught = recover() }()
		doHTTPUpload(t, srv, "alice", "pw", "file", "upload.txt", []byte("contents"))
	}()
	if caught != "log writer failure" {
		t.Fatalf("panic=%v; want application log-writer failure", caught)
	}
	if after := countRetainedJailDescriptors(t, root); after != before {
		t.Fatalf("jail descriptors after panic=%d; before=%d", after, before)
	}
}
