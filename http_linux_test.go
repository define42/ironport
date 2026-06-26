package ironport

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newHTTPTestServer builds a server for HTTP-ingest tests. The HTTP endpoint
// needs no listener and no host key, so it is constructed directly from
// NewServer without starting any of the SFTP/FTP machinery.
func newHTTPTestServer(t *testing.T, users map[string]UserInfo) *Server {
	t.Helper()
	config := DefaultConfig()
	config.Users = users
	return NewServer(config)
}

// buildMultipartUpload returns a multipart/form-data body carrying content
// under the given form field and filename, along with the matching
// Content-Type header value.
func buildMultipartUpload(t *testing.T, field, filename string, content []byte) (body *bytes.Buffer, contentType string) {
	t.Helper()
	body = &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write multipart content: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return body, mw.FormDataContentType()
}

// doHTTPUpload drives one POST upload through srv.HttpIngest and returns the
// recorder. When user and pass are both empty no Authorization header is sent,
// which exercises the unauthenticated path.
func doHTTPUpload(t *testing.T, srv *Server, user, pass, field, filename string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, contentType := buildMultipartUpload(t, field, filename, content)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", contentType)
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	req.RemoteAddr = "192.0.2.10:4444"
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)
	return rec
}

// uploadPart is one multipart part for a multi-file upload request.
type uploadPart struct {
	field    string
	filename string
	content  []byte
}

// doMultiUpload POSTs a request carrying several multipart parts and returns
// the recorder, exercising the multi-file path of HttpIngest.
func doMultiUpload(t *testing.T, srv *Server, user, pass string, parts []uploadPart) *httptest.ResponseRecorder {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	for _, p := range parts {
		fw, err := mw.CreateFormFile(p.field, p.filename)
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := fw.Write(p.content); err != nil {
			t.Fatalf("write multipart content: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth(user, pass)
	req.RemoteAddr = "192.0.2.10:4444"
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)
	return rec
}

func TestHTTPIngest_UploadSuccess(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanRead: true, CanWrite: true},
	}
	srv := newHTTPTestServer(t, users)

	content := []byte("hello http world")
	rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", "upload.txt", content)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(root, "upload.txt")) //nolint:gosec // path joined under t.TempDir()
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("stored content = %q; want %q", got, content)
	}

	select {
	case evt := <-srv.CompletedUploads():
		if evt.FilePath != "/upload.txt" {
			t.Errorf("FilePath = %q; want /upload.txt", evt.FilePath)
		}
		if evt.FullFilePath != filepath.Join(root, "upload.txt") {
			t.Errorf("FullFilePath = %q; want %q", evt.FullFilePath, filepath.Join(root, "upload.txt"))
		}
		if evt.Protocol != CompletedUploadProtocolHTTP {
			t.Errorf("Protocol = %q; want %q", evt.Protocol, CompletedUploadProtocolHTTP)
		}
		if evt.Username != "alice" {
			t.Errorf("Username = %q; want alice", evt.Username)
		}
		if evt.ClientIP != "192.0.2.10" {
			t.Errorf("ClientIP = %q; want 192.0.2.10", evt.ClientIP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP upload completion event")
	}
}

func TestHTTPIngest_AuthEventLoginSuccess(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", "ok.txt", []byte("data"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusCreated)
	}
	expectAuthEvent(t, srv, AuthEventLoginSuccess, "alice")
}

func TestHTTPIngest_RequiresAuth(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	rec := doHTTPUpload(t, srv, "", "", "file", "upload.txt", []byte("data"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("WWW-Authenticate = %q; want a Basic challenge", got)
	}
	if _, err := os.Stat(filepath.Join(root, "upload.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected no file written; stat err = %v", err)
	}
	// A bare unauthenticated request must not emit a LoginFailed event, so
	// challenge/response probes do not flood the AuthEvents stream.
	select {
	case evt := <-srv.AuthEvents():
		t.Fatalf("unexpected AuthEvent for unauthenticated probe: %+v", evt)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHTTPIngest_RejectsBadCredentials(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}

	for _, tc := range []struct {
		name string
		user string
		pass string
	}{
		{"wrong password", "alice", "wrongpw"},
		{"unknown user", "mallory", "whatever"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newHTTPTestServer(t, users)
			rec := doHTTPUpload(t, srv, tc.user, tc.pass, "file", "upload.txt", []byte("data"))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d; want %d", rec.Code, http.StatusUnauthorized)
			}
			if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
				t.Errorf("WWW-Authenticate = %q; want a Basic challenge", got)
			}
			expectAuthEvent(t, srv, AuthEventLoginFailed, tc.user)
			if _, err := os.Stat(filepath.Join(root, "upload.txt")); !os.IsNotExist(err) {
				t.Errorf("file written despite bad credentials; stat err = %v", err)
			}
		})
	}
}

func TestHTTPIngest_MethodNotAllowed(t *testing.T) {
	srv := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanWrite: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/upload", nil)
	req.SetBasicAuth("alice", "alicepw")
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q; want %q", got, http.MethodPost)
	}
}

func TestHTTPIngest_PermissionDenied(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{
		"bob": {Password: "bobpw", Root: root, CanRead: true, CanWrite: false},
	}
	srv := newHTTPTestServer(t, users)

	rec := doHTTPUpload(t, srv, "bob", "bobpw", "file", "upload.txt", []byte("data"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusForbidden)
	}
	if _, err := os.Stat(filepath.Join(root, "upload.txt")); !os.IsNotExist(err) {
		t.Fatalf("file written despite missing CanWrite; stat err = %v", err)
	}
}

func TestHTTPIngest_TraversalFilenameContained(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	content := []byte("contained")
	rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", "../../escape.txt", content)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	// The directory traversal is stripped to a base name: the file lands at the
	// jail root, never above it.
	got, err := os.ReadFile(filepath.Join(root, "escape.txt")) //nolint:gosec // path joined under t.TempDir()
	if err != nil {
		t.Fatalf("os.ReadFile(jail/escape.txt): %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("stored content = %q; want %q", got, content)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("file escaped one level above the jail root; stat err = %v", err)
	}

	if evt := receiveUpload(t, srv); evt.FilePath != "/escape.txt" {
		t.Fatalf("CompletedUpload FilePath = %q; want /escape.txt", evt.FilePath)
	}
}

func TestHTTPIngest_UploadCreatesSubfolders(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	// Both a relative and a leading-slash nested name land at the same place,
	// with the parent directories created on demand.
	for _, name := range []string{"test/hello.png", "/reports/2026/q2.csv"} {
		t.Run(name, func(t *testing.T) {
			uploadAndAssertStored(t, srv, root, name, []byte("body of "+name))
		})
	}
}

// uploadAndAssertStored uploads content under name and asserts it was stored at
// the matching jail-relative path on disk and announced with the expected
// CompletedUpload paths.
func uploadAndAssertStored(t *testing.T, srv *Server, root, name string, content []byte) {
	t.Helper()
	rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", name, content)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	rel := strings.TrimPrefix(path.Clean("/"+name), "/")
	onDisk := filepath.Join(root, filepath.FromSlash(rel))
	got, err := os.ReadFile(onDisk) //nolint:gosec // path joined under t.TempDir()
	if err != nil {
		t.Fatalf("os.ReadFile(%q): %v", onDisk, err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("stored content = %q; want %q", got, content)
	}

	evt := receiveUpload(t, srv)
	if want := "/" + rel; evt.FilePath != want {
		t.Errorf("CompletedUpload FilePath = %q; want %q", evt.FilePath, want)
	}
	if evt.FullFilePath != onDisk {
		t.Errorf("CompletedUpload FullFilePath = %q; want %q", evt.FullFilePath, onDisk)
	}
}

func TestHTTPIngest_SubfolderTraversalContained(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	content := []byte("contained")
	rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", "../../../etc/shadow", content)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	// The ".." segments are collapsed and contained: the file lands inside the
	// jail at <root>/etc/shadow, never at the real /etc/shadow.
	got, err := os.ReadFile(filepath.Join(root, "etc", "shadow")) //nolint:gosec // path joined under t.TempDir()
	if err != nil {
		t.Fatalf("expected contained file <root>/etc/shadow: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("stored content = %q; want %q", got, content)
	}
	if evt := receiveUpload(t, srv); evt.FilePath != "/etc/shadow" {
		t.Fatalf("CompletedUpload FilePath = %q; want /etc/shadow", evt.FilePath)
	}
}

func TestHTTPIngest_MultipleFiles(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	parts := []uploadPart{
		{"file", "a.txt", []byte("aaa")},
		{"file", "sub/b.txt", []byte("bbb")},
		{"file", "c.txt", []byte("ccc")},
	}
	rec := doMultiUpload(t, srv, "alice", "alicepw", parts)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	for _, p := range parts {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p.filename))) //nolint:gosec // path joined under t.TempDir()
		if err != nil {
			t.Fatalf("os.ReadFile(%q): %v", p.filename, err)
		}
		if !bytes.Equal(got, p.content) {
			t.Errorf("file %q = %q; want %q", p.filename, got, p.content)
		}
	}

	// One CompletedUpload event per stored file (order not asserted).
	gotPaths := map[string]bool{}
	for range parts {
		gotPaths[receiveUpload(t, srv).FilePath] = true
	}
	for _, want := range []string{"/a.txt", "/sub/b.txt", "/c.txt"} {
		if !gotPaths[want] {
			t.Errorf("missing CompletedUpload for %q; got %v", want, gotPaths)
		}
	}
}

func TestHTTPIngest_IgnoresNonFileParts(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	// A non-"file" field is skipped; only the "file" part is stored.
	parts := []uploadPart{
		{"description", "meta.txt", []byte("ignore me")},
		{"file", "real.txt", []byte("real")},
	}
	rec := doMultiUpload(t, srv, "alice", "alicepw", parts)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(root, "real.txt")) //nolint:gosec // path joined under t.TempDir()
	if err != nil || !bytes.Equal(got, []byte("real")) {
		t.Fatalf("real.txt = %q, err=%v; want \"real\"", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, "meta.txt")); !os.IsNotExist(err) {
		t.Fatalf("non-file part was written; stat err=%v", err)
	}
	receiveUpload(t, srv)
}

func TestHTTPIngest_MultipleFilesPartialInvalidName(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	parts := []uploadPart{
		{"file", "good.txt", []byte("good")},
		{"file", "..", []byte("bad")}, // invalid name → per-file client error
	}
	rec := doMultiUpload(t, srv, "alice", "alicepw", parts)
	// A client-side per-file error (and no server error) yields 400.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	// Best-effort: the valid file is still stored and announced.
	good, err := os.ReadFile(filepath.Join(root, "good.txt")) //nolint:gosec // path joined under t.TempDir()
	if err != nil || !bytes.Equal(good, []byte("good")) {
		t.Fatalf("good.txt = %q, err=%v; want \"good\"", good, err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "stored /good.txt") {
		t.Errorf("body missing stored line: %q", body)
	}
	if !strings.Contains(body, "failed") {
		t.Errorf("body missing failed line: %q", body)
	}
	if evt := receiveUpload(t, srv); evt.FilePath != "/good.txt" {
		t.Errorf("CompletedUpload = %q; want /good.txt", evt.FilePath)
	}
}

func TestHTTPIngest_MultipleFilesPartialServerError(t *testing.T) {
	root := t.TempDir()
	// "collision" exists as a directory, so writing a file with that name fails
	// server-side (EISDIR).
	if err := os.Mkdir(filepath.Join(root, "collision"), 0o750); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	parts := []uploadPart{
		{"file", "ok.txt", []byte("ok")},
		{"file", "collision", []byte("nope")},
	}
	rec := doMultiUpload(t, srv, "alice", "alicepw", parts)
	// A server-side failure dominates the batch status.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	okContent, err := os.ReadFile(filepath.Join(root, "ok.txt")) //nolint:gosec // path joined under t.TempDir()
	if err != nil || !bytes.Equal(okContent, []byte("ok")) {
		t.Fatalf("ok.txt = %q, err=%v; want \"ok\"", okContent, err)
	}
	if strings.Contains(rec.Body.String(), root) {
		t.Fatalf("response body leaked the on-disk path: %q", rec.Body.String())
	}
	if evt := receiveUpload(t, srv); evt.FilePath != "/ok.txt" {
		t.Errorf("CompletedUpload = %q; want /ok.txt", evt.FilePath)
	}
}

func TestHTTPIngest_RejectsInvalidFilename(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}

	// Names that resolve to the jail root or name a directory rather than a
	// file are rejected with 400 and never touch the filesystem.
	for _, tc := range []struct {
		name     string
		filename string
	}{
		{"dotdot", ".."},
		{"dot", "."},
		{"root slash", "/"},
		{"double slash", "//"},
		{"triple slash", "///"},
		{"absolute trailing slash", "/hello/"},
		{"relative trailing slash", "dir/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newHTTPTestServer(t, users)
			rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", tc.filename, []byte("data"))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("filename %q: status = %d; want %d", tc.filename, rec.Code, http.StatusBadRequest)
			}
			if entries, _ := os.ReadDir(root); len(entries) != 0 {
				t.Fatalf("filename %q created %d entries in the jail; want none", tc.filename, len(entries))
			}
		})
	}
}

func TestHTTPIngest_MissingFileField(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	rec := doHTTPUpload(t, srv, "alice", "alicepw", "notfile", "upload.txt", []byte("data"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusBadRequest)
	}
	if _, err := os.Stat(filepath.Join(root, "upload.txt")); !os.IsNotExist(err) {
		t.Fatalf("file written despite missing %q field; stat err = %v", "file", err)
	}
}

func TestHTTPIngest_NonMultipartBody(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "text/plain")
	req.SetBasicAuth("alice", "alicepw")
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHTTPIngest_DefersDeferredNames(t *testing.T) {
	for _, tc := range []struct {
		name     string
		filename string
	}{
		{"temp extension", "data.tmp"},
		{"dotfile", ".hidden"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			config := DefaultConfig()
			config.Users = map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
			config.TempExtensions = []string{".tmp"}
			srv := NewServer(config)

			content := []byte("deferred")
			rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", tc.filename, content)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d; want %d", rec.Code, http.StatusCreated)
			}
			// The file is written to disk even though completion is deferred.
			got, err := os.ReadFile(filepath.Join(root, tc.filename)) //nolint:gosec // path joined under t.TempDir()
			if err != nil {
				t.Fatalf("os.ReadFile: %v", err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("stored content = %q; want %q", got, content)
			}
			// A deferred name (temp extension or dotfile) is intentionally not
			// announced: HTTP has no rename step to finalize it.
			select {
			case evt := <-srv.CompletedUploads():
				t.Fatalf("unexpected CompletedUpload for deferred name %q: %+v", tc.filename, evt)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

func TestHTTPIngest_OverwritesExistingFile(t *testing.T) {
	root := t.TempDir()
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	if rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", "dup.txt", []byte("first-and-longer")); rec.Code != http.StatusCreated {
		t.Fatalf("first upload status = %d; want %d", rec.Code, http.StatusCreated)
	}
	receiveUpload(t, srv)

	if rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", "dup.txt", []byte("second")); rec.Code != http.StatusCreated {
		t.Fatalf("second upload status = %d; want %d", rec.Code, http.StatusCreated)
	}
	receiveUpload(t, srv)

	got, err := os.ReadFile(filepath.Join(root, "dup.txt")) //nolint:gosec // path joined under t.TempDir()
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}
	if want := []byte("second"); !bytes.Equal(got, want) {
		t.Fatalf("content after overwrite = %q; want %q (truncation failed)", got, want)
	}
}

func TestHTTPIngest_WriteFailureReturns500(t *testing.T) {
	root := t.TempDir()
	// Pre-create a directory; an upload whose name collides with it cannot be
	// opened for writing (EISDIR) and must surface as a generic 500 that does
	// not echo the on-disk path or filesystem error to the client.
	if err := os.Mkdir(filepath.Join(root, "collision"), 0o750); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}
	users := map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	srv := newHTTPTestServer(t, users)

	rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", "collision", []byte("data"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusInternalServerError)
	}
	if strings.Contains(rec.Body.String(), root) {
		t.Fatalf("response body leaked the on-disk path: %q", rec.Body.String())
	}
	select {
	case evt := <-srv.CompletedUploads():
		t.Fatalf("unexpected CompletedUpload for a failed write: %+v", evt)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSanitizeUploadPath(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantPath string
		wantOK   bool
	}{
		{"report.csv", "/report.csv", true},
		{"test/hello.png", "/test/hello.png", true},
		{"/test/hello.png", "/test/hello.png", true},
		{"a/b/c/deep.txt", "/a/b/c/deep.txt", true},
		{"./sub/./x.txt", "/sub/x.txt", true},
		{"name with spaces.txt", "/name with spaces.txt", true},
		// Redundant slashes inside a path collapse to a single separator.
		{"a//b/c.txt", "/a/b/c.txt", true},
		{"//leading.txt", "/leading.txt", true},
		// ".." segments are collapsed and contained inside the jail, never
		// stripped to a bare base name and never escaping upward.
		{"../../etc/passwd", "/etc/passwd", true},
		{"", "", false},
		{".", "", false},
		{"..", "", false},
		{"/", "", false},
		{"//", "", false},
		{"///", "", false},
		{"test/", "", false},
		{"/hello/", "", false},
		{"bad\nname", "", false},
		{"bad\rname", "", false},
		{"bad\x00name", "", false},
	} {
		got, ok := sanitizeUploadPath(tc.in)
		if ok != tc.wantOK {
			t.Errorf("sanitizeUploadPath(%q) ok = %v; want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && got != tc.wantPath {
			t.Errorf("sanitizeUploadPath(%q) = %q; want %q", tc.in, got, tc.wantPath)
		}
	}
}

// expectAuthEvent waits for the next AuthEvent and asserts its kind, username,
// protocol (always HTTP), and client IP (every HTTP test request originates
// from the fixed RemoteAddr set by doHTTPUpload).
func expectAuthEvent(t *testing.T, srv *Server, wantType AuthEventType, wantUser string) {
	t.Helper()
	select {
	case evt := <-srv.AuthEvents():
		if evt.Type != wantType {
			t.Errorf("AuthEvent Type = %q; want %q", evt.Type, wantType)
		}
		if evt.Protocol != CompletedUploadProtocolHTTP {
			t.Errorf("AuthEvent Protocol = %q; want %q", evt.Protocol, CompletedUploadProtocolHTTP)
		}
		if evt.Username != wantUser {
			t.Errorf("AuthEvent Username = %q; want %q", evt.Username, wantUser)
		}
		if evt.ClientIP != "192.0.2.10" {
			t.Errorf("AuthEvent ClientIP = %q; want 192.0.2.10", evt.ClientIP)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for AuthEvent")
	}
}

// receiveUpload waits for and returns the next CompletedUpload, failing the
// test if none arrives.
func receiveUpload(t *testing.T, srv *Server) CompletedUpload {
	t.Helper()
	select {
	case evt := <-srv.CompletedUploads():
		return evt
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CompletedUpload event")
		return CompletedUpload{}
	}
}
