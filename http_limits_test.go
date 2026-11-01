//go:build linux

package ironport

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

//nolint:funlen // the held request, rejection, and permit release form one concurrency regression
func TestHTTPIngest_ConcurrentRequestLimitSharedAcrossHandlers(t *testing.T) {
	config := DefaultConfig()
	config.Users = map[string]UserInfo{
		"alice": {Password: "alicepw", Root: t.TempDir(), CanWrite: true},
	}
	config.ResourceLimits.HTTPMaxConcurrentRequests = 1
	server := NewServer(config)
	firstHandler := server.HttpIngest()
	secondHandler := server.HttpIngest()

	bodyReader, bodyWriter := io.Pipe()
	t.Cleanup(func() {
		_ = bodyReader.Close()
		_ = bodyWriter.Close()
	})
	firstRequest := httptest.NewRequest(http.MethodPost, "/upload", bodyReader)
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
	const credentials = "Authorization: Basic YWxpY2U6cHc=\r\n" // alice:pw
	for _, test := range []struct {
		name, headers, initialBody string
		wantStatus                 int
	}{
		{name: "missing authentication", wantStatus: http.StatusUnauthorized},
		{
			name: "invalid content type", headers: credentials + "Content-Type: invalid\r\n",
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "malformed multipart headers", headers: credentials + "Content-Type: multipart/form-data; boundary=held-open\r\n",
			initialBody: "--held-open\r\ninvalid-header\r\n\r\n", wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			testHTTPRejectedSlowBodies(t, test.headers, test.initialBody, test.wantStatus)
		})
	}
}

func testHTTPRejectedSlowBodies(t *testing.T, headers, initialBody string, wantStatus int) {
	t.Helper()
	const requestCount = 6
	config := DefaultConfig()
	config.Users = map[string]UserInfo{"alice": {Password: "pw", Root: t.TempDir(), CanWrite: true}}
	config.ResourceLimits.HTTPMaxConcurrentRequests = 1
	server := NewServer(config)

	closed := make(chan struct{}, requestCount)
	testServer := httptest.NewUnstartedServer(server.HttpIngest())
	testServer.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	testServer.Start()
	t.Cleanup(testServer.Close)

	for range requestCount {
		testHTTPRejectedSlowBodyRequest(t, testServer.Listener.Addr().String(), headers, initialBody, wantStatus)
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for closedCount := range requestCount {
		select {
		case <-closed:
		case <-deadline.C:
			t.Fatalf("only %d of %d rejected slow-body connections closed", closedCount, requestCount)
		}
	}
}

func testHTTPRejectedSlowBodyRequest(t *testing.T, address, headers, initialBody string, wantStatus int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	// Withhold the final body byte so automatic draining would hang without
	// the handler's explicit read deadline and connection-close response.
	if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\n%sContent-Length: %d\r\n\r\n%s", address, headers, len(initialBody)+1, initialBody); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil {
		t.Fatalf("read response body: %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("close response body: %v", closeErr)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d; want %d", response.StatusCode, wantStatus)
	}
	if !response.Close {
		t.Fatal("response did not ask the client to close the connection")
	}
	if got := string(responseBody); got != http.StatusText(wantStatus)+"\n" {
		t.Fatalf("body = %q; want generic status body", got)
	}
}

//nolint:funlen,gocognit // each credential rejection must check the same response, body-read, and event guarantees
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
			config.ResourceLimits.HTTPMaxAuthorizationBytes = 32
			config.ResourceLimits.HTTPMaxUsernameBytes = 4
			config.ResourceLimits.HTTPMaxPasswordBytes = 4
			server := NewServer(config)
			probe := &httpBodyReadProbe{Reader: strings.NewReader("must not be read")}
			request := httptest.NewRequest(http.MethodPost, "/upload", probe)
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

type httpBodyReadProbe struct {
	io.Reader

	read bool
}

func (p *httpBodyReadProbe) Read(buffer []byte) (int, error) {
	p.read = true
	return p.Reader.Read(buffer)
}

func TestHTTPIngest_AuthenticationThrottlesTransportIP(t *testing.T) {
	server := NewServer(&Config{AuthLimits: AuthLimitConfig{IPBurst: 2, IPInterval: time.Hour}})
	for i := range 3 {
		request := httptest.NewRequest(http.MethodPost, "/upload", nil)
		request.RemoteAddr = "192.0.2.1:4000"
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
			content, err := os.ReadFile(filepath.Join(root, filename)) //nolint:gosec // G304: generated filename under t.TempDir()
			if err != nil || string(content) != filename {
				t.Fatalf("stored content = %q, error = %v", content, err)
			}
		})
	}
}

func TestHTTPIngest_InvalidConfigRejectsBeforeAuthentication(t *testing.T) {
	server := NewServer(&Config{AuthLimits: AuthLimitConfig{MaxEntries: 1}})
	probe := &httpBodyReadProbe{Reader: strings.NewReader("must not be read")}
	request := httptest.NewRequest(http.MethodPost, "/upload", probe)
	request.Header.Set("Authorization", strings.Repeat("x", defaultHTTPMaxAuthorizationBytes+1))
	recorder := httptest.NewRecorder()
	server.HttpIngest()(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d; want 503 for invalid configuration", recorder.Code)
	}
	if got := recorder.Body.String(); got != http.StatusText(http.StatusServiceUnavailable)+"\n" {
		t.Fatalf("response=%q; want generic service-unavailable response", got)
	}
	if recorder.Header().Get("Connection") != "close" || probe.read {
		t.Fatal("invalid configuration did not reject the body without reading it")
	}
	select {
	case event := <-server.AuthEvents():
		t.Fatalf("invalid configuration triggered authentication: %+v", event)
	default:
	}
}
