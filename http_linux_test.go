package ironport

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
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

func writeAndClosePipe(t *testing.T, writer *io.PipeWriter, payload []byte) {
	t.Helper()
	type writeResult struct {
		n        int
		writeErr error
		closeErr error
	}
	result := make(chan writeResult, 1)
	go func() {
		n, writeErr := writer.Write(payload)
		result <- writeResult{n: n, writeErr: writeErr, closeErr: writer.Close()}
	}()

	select {
	case got := <-result:
		if got.writeErr != nil {
			t.Fatalf("pipe Write: %v", got.writeErr)
		}
		if got.n != len(payload) {
			t.Fatalf("pipe Write wrote %d bytes; want %d", got.n, len(payload))
		}
		if got.closeErr != nil {
			t.Fatalf("pipe Close: %v", got.closeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out writing HTTP request body")
	}
}

// doHTTPUpload drives one POST upload through srv.HttpIngest and returns the
// recorder. When user and pass are both empty no Authorization header is sent,
// which exercises the unauthenticated path.
func doHTTPUpload(t *testing.T, srv *Server, user, pass, field, filename string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, contentType := buildMultipartUpload(t, field, filename, content)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("X-Ironport-Upload", "1")
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
	req.Header.Set("X-Ironport-Upload", "1")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth(user, pass)
	req.RemoteAddr = "192.0.2.10:4444"
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)
	return rec
}

//nolint:funlen // the held request and rejection form one concurrency regression scenario
func TestHTTPIngest_ConcurrentRequestLimitSharedAcrossHandlers(t *testing.T) {
	config := DefaultConfig()
	config.Users = map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanWrite: true},
	}
	config.HTTPMaxConcurrentRequests = 1
	server := NewServer(config)
	firstHandler := server.HttpIngest()
	secondHandler := server.HttpIngest()

	bodyReader, bodyWriter := io.Pipe()
	t.Cleanup(func() {
		_ = bodyReader.Close()
		_ = bodyWriter.Close()
	})
	firstRequest := httptest.NewRequest(http.MethodPost, "/upload", bodyReader)
	firstRequest.Header.Set("X-Ironport-Upload", "1")
	firstRequest.Header.Set("Content-Type", "multipart/form-data; boundary=held-open")
	firstRequest.SetBasicAuth("alice", "alicepw")
	firstRequest.RemoteAddr = "192.0.2.10:4444"
	firstRecorder := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		firstHandler(firstRecorder, firstRequest)
		close(firstDone)
	}()

	select {
	case event := <-server.AuthEvents():
		if event.Type != AuthEventLoginSuccess {
			t.Fatalf("first request auth event = %q; want %q", event.Type, AuthEventLoginSuccess)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first request to hold its admission slot")
	}

	probe := &httpBodyReadProbe{Reader: strings.NewReader("must not be read")}
	secondRequest := httptest.NewRequest(http.MethodPost, "/upload", probe)
	secondRequest.Header.Set("X-Ironport-Upload", "1")
	secondRequest.Header.Set("Content-Type", "multipart/form-data; boundary=rejected")
	secondRequest.SetBasicAuth("alice", "alicepw")
	secondRequest.RemoteAddr = "192.0.2.11:5555"
	secondRecorder := httptest.NewRecorder()
	secondHandler(secondRecorder, secondRequest)

	if secondRecorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated status = %d; want %d", secondRecorder.Code, http.StatusServiceUnavailable)
	}
	if got := secondRecorder.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q; want 1", got)
	}
	if got := secondRecorder.Header().Get("Connection"); got != "close" {
		t.Fatalf("Connection = %q; want close", got)
	}
	if probe.read {
		t.Fatal("saturated request body was read")
	}
	select {
	case event := <-server.AuthEvents():
		t.Fatalf("saturated request authenticated: %+v", event)
	default:
	}

	if err := bodyWriter.Close(); err != nil {
		t.Fatalf("close held request body: %v", err)
	}
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out releasing first request admission slot")
	}
}

func TestHTTPIngest_RejectedSlowBodiesCloseAfterAdmissionRelease(t *testing.T) {
	const requestCount = 6
	config := DefaultConfig()
	config.HTTPMaxConcurrentRequests = 1
	server := NewServer(config)

	closed := make(chan struct{}, requestCount)
	testServer := httptest.NewUnstartedServer(server.HttpIngest())
	testServer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	testServer.Start()

	var clients []net.Conn
	t.Cleanup(func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
		testServer.Close()
	})

	address := testServer.Listener.Addr().String()
	for i := range requestCount {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatalf("request %d dial: %v", i, err)
		}
		clients = append(clients, conn)
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("request %d deadline: %v", i, err)
		}
		if _, err := fmt.Fprintf(
			conn,
			"POST /upload HTTP/1.1\r\nHost: %s\r\nX-Ironport-Upload: 1\r\nContent-Length: 1\r\n\r\n",
			address,
		); err != nil {
			t.Fatalf("request %d write headers: %v", i, err)
		}

		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("request %d read response: %v", i, err)
		}
		responseBody, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			t.Fatalf("request %d read response body: %v", i, readErr)
		}
		if closeErr != nil {
			t.Fatalf("request %d close response body: %v", i, closeErr)
		}
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("request %d status = %d; want %d", i, response.StatusCode, http.StatusUnauthorized)
		}
		if !response.Close {
			t.Fatalf("request %d did not ask the client to close the connection", i)
		}
		if got := string(responseBody); got != http.StatusText(http.StatusUnauthorized)+"\n" {
			t.Fatalf("request %d body = %q; want generic unauthorized body", i, got)
		}
	}

	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for closedCount := 0; closedCount < requestCount; closedCount++ {
		select {
		case <-closed:
		case <-deadline.C:
			t.Fatalf("only %d of %d rejected slow-body connections closed", closedCount, requestCount)
		}
	}
}

//nolint:funlen // synchronized authentication, path swap, and upload are one regression scenario
func TestHTTPIngest_RetainsJailRootAfterPathReplacement(t *testing.T) {
	base := t.TempDir()
	configuredRoot := filepath.Join(base, "root")
	if err := os.Mkdir(configuredRoot, 0o750); err != nil {
		t.Fatalf("os.Mkdir(configured root): %v", err)
	}
	srv := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "alicepw", Root: configuredRoot, CanWrite: true},
	})

	body, contentType := buildMultipartUpload(t, "file", "retained.txt", []byte("retained HTTP jail"))
	bodyReader, bodyWriter := io.Pipe()
	t.Cleanup(func() {
		_ = bodyReader.Close()
		_ = bodyWriter.Close()
	})
	req := httptest.NewRequest(http.MethodPost, "/upload", bodyReader)
	req.Header.Set("X-Ironport-Upload", "1")
	req.Header.Set("Content-Type", contentType)
	req.SetBasicAuth("alice", "alicepw")
	req.RemoteAddr = "192.0.2.10:4444"
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		srv.HttpIngest()(rec, req)
		close(done)
	}()

	select {
	case event := <-srv.AuthEvents():
		if event.Type != AuthEventLoginSuccess {
			t.Fatalf("auth event type = %q; want %q", event.Type, AuthEventLoginSuccess)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP authentication")
	}

	openedRoot := filepath.Join(base, "opened-root")
	if err := os.Rename(configuredRoot, openedRoot); err != nil {
		t.Fatalf("os.Rename(configured root): %v", err)
	}
	if err := os.Mkdir(configuredRoot, 0o750); err != nil {
		t.Fatalf("os.Mkdir(replacement root): %v", err)
	}

	writeAndClosePipe(t, bodyWriter, body.Bytes())
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP upload")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; want %d (body=%q)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	got, err := os.ReadFile(filepath.Join(openedRoot, "retained.txt")) //nolint:gosec // path is confined to t.TempDir
	if err != nil {
		t.Fatalf("os.ReadFile(opened root): %v", err)
	}
	if !bytes.Equal(got, []byte("retained HTTP jail")) {
		t.Fatalf("retained file contents = %q", got)
	}
	if _, err := os.Stat(filepath.Join(configuredRoot, "retained.txt")); !os.IsNotExist(err) {
		t.Fatalf("replacement root received retained.txt; stat error = %v", err)
	}
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

//nolint:funlen // one table verifies all pre-auth rejection classes and side effects
func TestHTTPIngest_RejectsInvalidCredentialHeadersWithoutSideEffects(t *testing.T) {
	tests := []struct {
		name          string
		authorization []string
		username      string
		password      string
		wantStatus    int
		wantChallenge bool
	}{
		{
			name:          "duplicate authorization headers",
			authorization: []string{"Basic YTpi", "Basic Yzpk"},
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
		},
		{
			name:          "oversized raw authorization",
			authorization: []string{strings.Repeat("x", 33)},
			wantStatus:    http.StatusRequestHeaderFieldsTooLarge,
		},
		{
			name:          "malformed basic authorization",
			authorization: []string{"Basic !!!"},
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
		},
		{
			name:          "oversized decoded username",
			username:      "abcde",
			password:      "pw",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
		},
		{
			name:          "oversized decoded password",
			username:      "usr",
			password:      "abcde",
			wantStatus:    http.StatusUnauthorized,
			wantChallenge: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig()
			config.HTTPMaxAuthorizationBytes = 32
			config.HTTPMaxUsernameBytes = 4
			config.HTTPMaxPasswordBytes = 4
			server := NewServer(config)
			probe := &httpBodyReadProbe{Reader: strings.NewReader("must not be read")}
			request := httptest.NewRequest(http.MethodPost, "/upload", probe)
			request.Header.Set("X-Ironport-Upload", "1")
			request.RemoteAddr = "192.0.2.10:4444"
			if test.authorization != nil {
				request.Header["Authorization"] = append([]string(nil), test.authorization...)
			} else {
				request.SetBasicAuth(test.username, test.password)
			}
			recorder := httptest.NewRecorder()
			server.HttpIngest()(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d; want %d", recorder.Code, test.wantStatus)
			}
			if got := recorder.Body.String(); got != http.StatusText(test.wantStatus)+"\n" {
				t.Fatalf("response body = %q; want generic status text", got)
			}
			gotChallenge := recorder.Header().Get("WWW-Authenticate") != ""
			if gotChallenge != test.wantChallenge {
				t.Fatalf("WWW-Authenticate present = %t; want %t", gotChallenge, test.wantChallenge)
			}
			if got := recorder.Header().Get("Connection"); got != "close" {
				t.Fatalf("Connection = %q; want close", got)
			}
			if probe.read {
				t.Fatal("rejected credential request body was read")
			}
			select {
			case event := <-server.AuthEvents():
				t.Fatalf("invalid credential header emitted AuthEvent: %+v", event)
			default:
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

//nolint:funlen // one rejection matrix verifies authentication, body reads, and filesystem effects
func TestHTTPIngest_CSRFRejectedBeforeAuthenticationOrWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  []string
		origins []string
		fetch   []string
	}{
		{name: "missing header"},
		{name: "wrong header", header: []string{"true"}},
		{name: "multiple headers", header: []string{"1", "1"}},
		{name: "cross-site form", header: []string{"1"}, origins: []string{"https://attacker.example"}},
		{name: "opaque origin", header: []string{"1"}, origins: []string{"null"}},
		{name: "multiple origins", header: []string{"1"}, origins: []string{"https://uploads.example", "https://attacker.example"}},
		{name: "space-separated origins", header: []string{"1"}, origins: []string{"https://uploads.example https://attacker.example"}},
		{name: "origin path", header: []string{"1"}, origins: []string{"https://uploads.example/"}},
		{name: "origin credentials", header: []string{"1"}, origins: []string{"https://attacker@uploads.example"}},
		{name: "fetch cross-site", header: []string{"1"}, fetch: []string{"cross-site"}},
		{name: "multiple fetch metadata", header: []string{"1"}, fetch: []string{"same-origin", "cross-site"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			destination := filepath.Join(root, "existing.txt")
			if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			server := newHTTPTestServer(t, map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}})
			body, contentType := buildMultipartUpload(t, "file", "existing.txt", []byte("attacker"))
			probe := &httpBodyReadProbe{Reader: body}
			request := httptest.NewRequest(http.MethodPost, "https://uploads.example/upload", probe)
			request.SetBasicAuth("alice", "alicepw")
			request.Header.Set("Content-Type", contentType)
			request.Header["X-Ironport-Upload"] = tc.header
			request.Header["Origin"] = tc.origins
			request.Header["Sec-Fetch-Site"] = tc.fetch
			recorder := httptest.NewRecorder()
			server.handleHTTPIngest(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d", recorder.Code)
			}
			if probe.read {
				t.Fatal("rejected request body was read")
			}
			content, err := os.ReadFile(destination)
			if err != nil || string(content) != "original" {
				t.Fatalf("destination=%q err=%v", content, err)
			}
			select {
			case event := <-server.AuthEvents():
				t.Fatalf("CSRF rejection authenticated: %+v", event)
			default:
			}
		})
	}
}

type httpBodyReadProbe struct {
	io.Reader
	read bool
}

func (p *httpBodyReadProbe) Read(buffer []byte) (int, error) {
	p.read = true
	return p.Reader.Read(buffer)
}

//nolint:funlen // table covers direct TLS, cleartext, proxy, and invalid allowlist contracts
func TestHTTPIngest_OriginPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		url       string
		origin    string
		allowed   []string
		forwarded string
		want      int
	}{
		{name: "machine client", url: "https://uploads.example/upload", want: http.StatusCreated},
		{name: "direct TLS same origin", url: "https://uploads.example/upload", origin: "https://uploads.example", want: http.StatusCreated},
		{name: "direct HTTP same origin", url: "http://uploads.example/upload", origin: "http://uploads.example", want: http.StatusCreated},
		{name: "explicit proxy origin", url: "http://internal/upload", origin: "https://uploads.example", allowed: []string{"https://uploads.example"}, want: http.StatusCreated},
		{name: "forwarded headers ignored", url: "http://internal/upload", origin: "https://uploads.example", forwarded: "https", want: http.StatusForbidden},
		{name: "nonallowlisted origin", url: "https://uploads.example/upload", origin: "https://uploads.example", allowed: []string{"https://other.example"}, want: http.StatusForbidden},
		{name: "invalid allowlist", url: "https://uploads.example/upload", origin: "https://uploads.example", allowed: []string{"https://uploads.example/"}, want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{Users: map[string]UserInfo{"alice": {Password: "alicepw", Root: t.TempDir(), CanWrite: true}}, HTTPAllowedOrigins: tc.allowed}
			server := NewServer(config)
			body, contentType := buildMultipartUpload(t, "file", "allowed.txt", []byte("allowed"))
			request := httptest.NewRequest(http.MethodPost, tc.url, body)
			if strings.HasPrefix(tc.url, "https://") {
				request.TLS = &tls.ConnectionState{}
			}
			request.Header.Set("Content-Type", contentType)
			request.Header.Set("X-Ironport-Upload", "1")
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.forwarded != "" {
				request.Header.Set("X-Forwarded-Proto", tc.forwarded)
				request.Header.Set("X-Forwarded-Host", "uploads.example")
			}
			request.SetBasicAuth("alice", "alicepw")
			recorder := httptest.NewRecorder()
			server.handleHTTPIngest(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("status=%d body=%q; want %d", recorder.Code, recorder.Body.String(), tc.want)
			}
		})
	}
}

func TestHTTPIngest_AuthenticationThrottlesTransportIP(t *testing.T) {
	server := NewServer(&Config{AuthLimits: AuthLimitConfig{IPBurst: 2, IPInterval: time.Hour}})
	for i := range 3 {
		request := httptest.NewRequest(http.MethodPost, "/upload", nil)
		request.RemoteAddr = "192.0.2.1:4000"
		request.Header.Set("X-Ironport-Upload", "1")
		request.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", i+1))
		request.SetBasicAuth(fmt.Sprintf("unknown%d", i), "bad")
		recorder := httptest.NewRecorder()
		server.handleHTTPIngest(recorder, request)
		want := http.StatusUnauthorized
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if recorder.Code != want {
			t.Fatalf("attempt %d status=%d want=%d", i+1, recorder.Code, want)
		}
		if i == 2 && recorder.Header().Get("Retry-After") == "" {
			t.Fatal("missing Retry-After")
		}
	}
}

func TestHTTPIngest_StorageBudgetFailureDoesNotAnnounce(t *testing.T) {
	server := NewServer(&Config{Users: map[string]UserInfo{"alice": {Password: "alicepw", Root: t.TempDir(), CanWrite: true}}, MaxFileBytes: 4})
	response := doHTTPUpload(t, server, "alice", "alicepw", "file", "too-large.txt", []byte("exceeds budget"))
	if response.Code != http.StatusInsufficientStorage {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if response.Header().Get("Connection") != "close" {
		t.Fatal("quota-exceeding request left reusable connection")
	}
	select {
	case event := <-server.CompletedUploads():
		t.Fatalf("failed upload announced: %+v", event)
	default:
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
	req.Header.Set("X-Ironport-Upload", "1")
	req.Header.Set("Content-Type", "text/plain")
	req.SetBasicAuth("alice", "alicepw")
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHTTPIngest_ValidatesRootsBeforeFirstRequest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing-root")
	srv := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "alicepw", Root: root, CanWrite: true},
	})
	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })
	_ = srv.HttpIngest()
	if output := logs.String(); !strings.Contains(output, "jail-root check failed") || !strings.Contains(output, root) {
		t.Fatalf("handler creation did not warn about initial root: %q", output)
	}
}

type countedUploadBody struct {
	reader io.Reader
	read   int
}

func (b *countedUploadBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *countedUploadBody) Close() error { return nil }

func requireHTTPUploadLimited(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d; want 413 (body=%q)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Connection") != "close" {
		t.Error("over-limit connection was left reusable")
	}
}

func requireNoHTTPUploadEvent(t *testing.T, srv *Server) {
	t.Helper()
	select {
	case event := <-srv.CompletedUploads():
		t.Fatalf("unexpected upload completion: %+v", event)
	default:
	}
}

func TestHTTPIngest_ZeroValueServerUploadLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		unknown bool
	}{
		{name: "known length"},
		{name: "unknown length", unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			srv := &Server{}
			srv.AddUser("alice", UserInfo{Password: "pw", Root: root, CanWrite: true})
			body, contentType := buildMultipartUpload(t, "file", "upload.txt", []byte("uploaded"))
			req := httptest.NewRequest(http.MethodPost, "/upload", body)
			if tc.unknown {
				req.ContentLength = -1
			}
			req.Header.Set("X-Ironport-Upload", "1")
			req.Header.Set("Content-Type", contentType)
			req.SetBasicAuth("alice", "pw")
			rec := httptest.NewRecorder()
			srv.HttpIngest()(rec, req)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d; want 201 (body=%q)", rec.Code, rec.Body.String())
			}
			content, err := os.ReadFile(filepath.Join(root, "upload.txt"))
			if err != nil || string(content) != "uploaded" {
				t.Fatalf("stored content = %q, error = %v", content, err)
			}
		})
	}
}

func TestHTTPIngest_ZeroValueServerConcurrentUploads(t *testing.T) {
	root := t.TempDir()
	srv := &Server{}
	srv.AddUser("alice", UserInfo{Password: "pw", Root: root, CanWrite: true})
	for i := range 4 {
		t.Run(fmt.Sprintf("upload-%d", i), func(t *testing.T) {
			t.Parallel()
			filename := fmt.Sprintf("upload-%d.txt", i)
			rec := doHTTPUpload(t, srv, "alice", "pw", "file", filename, []byte(filename))
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d; want 201 (body=%q)", rec.Code, rec.Body.String())
			}
			content, err := os.ReadFile(filepath.Join(root, filename))
			if err != nil || string(content) != filename {
				t.Fatalf("stored content = %q, error = %v", content, err)
			}
		})
	}
}

func TestHTTPIngest_ZeroValueServerDefaultsEnforced(t *testing.T) {
	for _, limit := range []string{"bytes", "parts"} {
		t.Run(limit, func(t *testing.T) {
			root := t.TempDir()
			srv := &Server{}
			srv.AddUser("alice", UserInfo{Password: "pw", Root: root, CanWrite: true})
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			if limit == "parts" {
				for range defaultHTTPMaxUploadParts {
					if err := mw.WriteField("ignored", "value"); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := mw.CreateFormFile("file", "excess.txt"); err != nil {
				t.Fatal(err)
			}
			if err := mw.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/upload", &body)
			if limit == "bytes" {
				req.ContentLength = defaultHTTPMaxUploadBytes + 1
			}
			req.Header.Set("X-Ironport-Upload", "1")
			req.Header.Set("Content-Type", mw.FormDataContentType())
			req.SetBasicAuth("alice", "pw")
			rec := httptest.NewRecorder()
			srv.HttpIngest()(rec, req)
			requireHTTPUploadLimited(t, rec)
			if _, err := os.Stat(filepath.Join(root, "excess.txt")); !os.IsNotExist(err) {
				t.Fatalf("over-limit upload created a file: %v", err)
			}
		})
	}
}

func TestHTTPIngest_ByteLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		known bool
		field string
		file  string
	}{
		{name: "known length", known: true, field: "file", file: "large.txt"},
		{name: "chunked file", field: "file", file: "large.txt"},
		{name: "chunked skipped field", field: "ignored", file: "large.txt"},
		{name: "chunked rejected filename", field: "file", file: ".."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			cfg := DefaultConfig()
			cfg.Users = map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
			cfg.HTTPMaxUploadBytes = 1024
			srv := NewServer(cfg)
			body, contentType := buildMultipartUpload(t, tc.field, tc.file, bytes.Repeat([]byte("x"), 64<<10))
			bodyLen := body.Len()
			reader := &countedUploadBody{reader: body}
			req := httptest.NewRequest(http.MethodPost, "/upload", reader)
			req.Header.Set("X-Ironport-Upload", "1")
			req.ContentLength = -1
			if tc.known {
				req.ContentLength = int64(bodyLen)
			}
			req.Header.Set("Content-Type", contentType)
			req.SetBasicAuth("alice", "alicepw")
			rec := httptest.NewRecorder()
			srv.HttpIngest()(rec, req)
			requireHTTPUploadLimited(t, rec)
			if reader.read > int(cfg.HTTPMaxUploadBytes)+1 || (tc.known && reader.read != 0) {
				t.Fatalf("read %d bytes after limit %d, known length=%v", reader.read, cfg.HTTPMaxUploadBytes, tc.known)
			}
			requireNoHTTPUploadEvent(t, srv)
		})
	}
}

func TestHTTPIngest_ByteLimitIncludesMultipartEpilogue(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.Users = map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	cfg.HTTPMaxUploadBytes = 1024
	srv := NewServer(cfg)
	body, contentType := buildMultipartUpload(t, "file", "complete.txt", []byte("complete"))
	body.Write(bytes.Repeat([]byte("x"), 64<<10))
	reader := &countedUploadBody{reader: body}
	req := httptest.NewRequest(http.MethodPost, "/upload", reader)
	req.Header.Set("X-Ironport-Upload", "1")
	req.ContentLength = -1
	req.Header.Set("Content-Type", contentType)
	req.SetBasicAuth("alice", "alicepw")
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)
	requireHTTPUploadLimited(t, rec)
	if reader.read > int(cfg.HTTPMaxUploadBytes)+1 {
		t.Fatalf("read %d bytes after body limit %d", reader.read, cfg.HTTPMaxUploadBytes)
	}
	if !strings.Contains(rec.Body.String(), "stored /complete.txt") {
		t.Fatalf("response omitted file completed before epilogue: %q", rec.Body.String())
	}
	receiveUpload(t, srv)
	requireNoHTTPUploadEvent(t, srv)
}

func TestHTTPIngest_ExactLimitsAccepted(t *testing.T) {
	root := t.TempDir()
	body, contentType := buildMultipartUpload(t, "file", "exact.txt", []byte("exact"))
	cfg := DefaultConfig()
	cfg.Users = map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	cfg.HTTPMaxUploadBytes = int64(body.Len())
	cfg.HTTPMaxUploadParts = 1
	srv := NewServer(cfg)
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("X-Ironport-Upload", "1")
	req.ContentLength = -1
	req.Header.Set("Content-Type", contentType)
	req.SetBasicAuth("alice", "alicepw")
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("exact-limit status = %d; want 201 (body=%q)", rec.Code, rec.Body.String())
	}
	if event := receiveUpload(t, srv); event.FilePath != "/exact.txt" {
		t.Fatalf("completion = %+v; want exact.txt", event)
	}
}

func TestHTTPIngest_PartLimitCountsAllParts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		first  uploadPart
		stored bool
	}{
		{name: "file", first: uploadPart{"file", "first.txt", []byte("first")}, stored: true},
		{name: "ignored field", first: uploadPart{"ignored", "first.txt", []byte("ignored")}},
		{name: "invalid filename", first: uploadPart{"file", "..", []byte("invalid")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			cfg := DefaultConfig()
			cfg.Users = map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
			cfg.HTTPMaxUploadParts = 1
			srv := NewServer(cfg)
			rec := doMultiUpload(t, srv, "alice", "alicepw", []uploadPart{
				tc.first, {"file", "excess.txt", []byte("excess")},
			})
			requireHTTPUploadLimited(t, rec)
			if _, err := os.Stat(filepath.Join(root, "excess.txt")); !os.IsNotExist(err) {
				t.Fatalf("excess part was written: %v", err)
			}
			if tc.stored {
				if !strings.Contains(rec.Body.String(), "stored /first.txt") {
					t.Fatalf("response omitted earlier stored file: %q", rec.Body.String())
				}
				receiveUpload(t, srv)
			}
			requireNoHTTPUploadEvent(t, srv)
		})
	}
}

type unreadUploadTail struct{ read bool }

func (r *unreadUploadTail) Read([]byte) (int, error) {
	r.read = true
	return 0, io.ErrNoProgress
}

func TestHTTPIngest_PartLimitDoesNotDrainExcessPart(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.Users = map[string]UserInfo{"alice": {Password: "alicepw", Root: root, CanWrite: true}}
	cfg.HTTPMaxUploadParts = 1
	srv := NewServer(cfg)
	var prefix bytes.Buffer
	mw := multipart.NewWriter(&prefix)
	if err := mw.WriteField("ignored", "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := mw.CreateFormFile("file", "excess.txt"); err != nil {
		t.Fatal(err)
	}
	// Leave the rejected second part unfinished. Reading its body would hang
	// with a live slow client; this reader records any attempt to drain it.
	tail := &unreadUploadTail{}
	req := httptest.NewRequest(http.MethodPost, "/upload", io.MultiReader(&prefix, tail))
	req.Header.Set("X-Ironport-Upload", "1")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.SetBasicAuth("alice", "alicepw")
	rec := httptest.NewRecorder()
	srv.HttpIngest()(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || tail.read {
		t.Fatalf("status=%d, read rejected body=%v; want 413 without reading", rec.Code, tail.read)
	}
}

func TestHTTPIngest_OversizedFilenameResponseBounded(t *testing.T) {
	srv := newHTTPTestServer(t, map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanWrite: true},
	})
	rec := doHTTPUpload(t, srv, "alice", "alicepw", "file", strings.Repeat("x", 64<<10), nil)
	if rec.Code != http.StatusBadRequest || rec.Body.Len() > 2*httpUploadMaxPathBytes {
		t.Fatalf("status=%d, response bytes=%d; want bounded 400 response", rec.Code, rec.Body.Len())
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
