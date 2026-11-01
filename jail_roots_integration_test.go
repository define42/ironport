//go:build linux && integration

package ironport

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJailRootWarningAllowsStartupAndLateProvisioning(t *testing.T) {
	root := filepath.Join(t.TempDir(), "provision-later")
	logs := captureJailLifecycleLogs(t, "", nil)
	srv, addr, stopped := startListenAndServe(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanRead: true},
	})
	t.Cleanup(func() { stopJailRootLifecycleServer(t, srv, stopped) })
	assertJailLifecycleWarning(t, logs.String(), root)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	conn := resourceSSH(t, addr)
	timer := time.AfterFunc(5*time.Second, func() { _ = conn.Close() })
	t.Cleanup(func() { timer.Stop() })
	client := resourceSFTP(t, conn)
	info, err := client.Stat(".")
	if err != nil || !info.IsDir() {
		t.Fatalf("SFTP root after late provisioning: info=%v err=%v", info, err)
	}
}

func stopJailRootLifecycleServer(t *testing.T, srv *Server, stopped <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("ListenAndServe: %v", err)
		}
	case <-ctx.Done():
		t.Error("ListenAndServe did not stop")
	}
}

func TestJailRootWarningAllowsHTTPOnlyLateProvisioning(t *testing.T) {
	root := filepath.Join(t.TempDir(), "provision-later")
	srv := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "pw", Root: root, CanWrite: true},
	})
	logs := captureJailLifecycleLogs(t, "", nil)
	handler := srv.HttpIngest()
	assertJailLifecycleWarning(t, logs.String(), root)
	badRoot := invokeJailRootHTTPUpload(t, handler, "pw")
	badPassword := invokeJailRootHTTPUpload(t, handler, "wrong")
	if badRoot.Code != http.StatusUnauthorized || badPassword.Code != http.StatusUnauthorized ||
		badRoot.Body.String() != badPassword.Body.String() ||
		badRoot.Header().Get("WWW-Authenticate") != badPassword.Header().Get("WWW-Authenticate") {
		t.Fatalf("root failure response=%d %q, bad password response=%d %q; want identical unauthorized responses",
			badRoot.Code, badRoot.Body.String(), badPassword.Code, badPassword.Body.String())
	}
	if strings.Contains(badRoot.Body.String(), root) {
		t.Fatal("authentication response exposed the configured jail root")
	}
	if !strings.Contains(logs.String(), "authentication jail-root check failed") {
		t.Fatalf("root authentication failure omitted server diagnostic: %s", logs.String())
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	response := invokeJailRootHTTPUpload(t, handler, "pw")
	if response.Code != http.StatusCreated {
		t.Fatalf("same handler after provisioning: status=%d body=%q", response.Code, response.Body.String())
	}
	assertJailLifecycleUpload(t, root)
}

func invokeJailRootHTTPUpload(t *testing.T, handler http.Handler, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, contentType := buildMultipartUpload(t, "file", "late.txt", []byte("late root upload"))
	request := httptest.NewRequest(http.MethodPost, "/upload", body)
	request.Header.Set("Content-Type", contentType)
	request.SetBasicAuth("alice", password)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func assertJailLifecycleUpload(t *testing.T, root string) {
	t.Helper()
	base, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = base.Close() }()
	contents, err := base.ReadFile("late.txt")
	if err != nil || string(contents) != "late root upload" {
		t.Fatalf("late-provisioned upload = %q, %v", contents, err)
	}
}

func TestAddUserWarningFollowsPublicationAndRevocation(t *testing.T) {
	srv := NewServer(&Config{Users: map[string]UserInfo{
		"alice": {Password: "pw", Root: t.TempDir(), CanRead: true},
	}})
	conn := newRevisionConn(t, srv)
	before := commitRevisionConn(t, srv, conn, "alice")
	replacement := UserInfo{Password: "new", Root: filepath.Join(t.TempDir(), "missing")}
	var callbackErr error
	matched := false
	captureJailLifecycleLogs(t, replacement.Root, func() {
		matched = true
		callbackErr = observeJailRootWarningUpdate(srv, conn, replacement, before)
	})
	srv.AddUser("alice", replacement)
	if !matched || callbackErr != nil {
		t.Fatalf("warning callback: called=%t err=%v", matched, callbackErr)
	}
	if _, _, exists := srv.userSnapshot("alice"); exists {
		t.Fatal("AddUser restored a user removed reentrantly by the warning logger")
	}
}

func observeJailRootWarningUpdate(srv *Server, conn *revisionConn, replacement UserInfo, before uint64) error {
	// TryLock makes a lock-order regression fail without deadlocking the logger.
	if !srv.mu.TryLock() {
		return fmt.Errorf("root warning emitted while holding the server lock")
	}
	user, exists := srv.users["alice"]
	revision := srv.userRevisions["alice"]
	srv.mu.Unlock()
	if !exists || user.Root != replacement.Root || user.Password != replacement.Password || revision == before {
		return fmt.Errorf("warning preceded publication: exists=%t root=%q revision=%d (previous %d)",
			exists, user.Root, revision, before)
	}
	if !conn.closed.Load() {
		return fmt.Errorf("warning preceded closure of the revoked connection")
	}
	// The application's logger can call user management without lock recursion.
	srv.RemoveUser("alice")
	return nil
}

type jailLifecycleLogWriter struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	match   string
	onMatch func()
	once    sync.Once
}

func captureJailLifecycleLogs(t *testing.T, match string, onMatch func()) *jailLifecycleLogWriter {
	t.Helper()
	writer := &jailLifecycleLogWriter{match: match, onMatch: onMatch}
	previous := log.Writer()
	log.SetOutput(writer)
	t.Cleanup(func() { log.SetOutput(previous) })
	return writer
}

func (w *jailLifecycleLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buffer.Write(p)
	w.mu.Unlock()
	if w.onMatch != nil && strings.Contains(string(p), w.match) {
		w.once.Do(w.onMatch)
	}
	return n, err
}

func (w *jailLifecycleLogWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

func assertJailLifecycleWarning(t *testing.T, output, root string) {
	t.Helper()
	if !strings.Contains(output, "warning: jail-root check failed") || !strings.Contains(output, root) {
		t.Fatalf("missing advisory root warning for %q: %s", root, output)
	}
}
