//go:build linux && integration

package ironport

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPIngest_MultipartEpilogueRetainsAdmission(t *testing.T) {
	for _, body := range []struct {
		name       string
		content    string
		wantStatus int
	}{
		{"empty", "--boundary--\r\n", http.StatusBadRequest},
		{"uploaded", "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n\r\nx\r\n--boundary--\r\n", http.StatusCreated},
	} {
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chunked=%t", body.name, chunked), func(t *testing.T) {
				testHTTPEpilogueAdmission(t, body.content, body.wantStatus, chunked, nil)
			})
		}
	}
}

func testHTTPEpilogueAdmission(t *testing.T, body string, wantStatus int, chunked bool, wrap func(http.Handler) http.Handler) {
	t.Helper()
	srv, ts, reading, returned := newHTTPEpilogueTestServer(t, len(body), wrap)
	conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	sendHTTPEpilogueRequest(t, conn, body, chunked)
	select {
	case <-reading:
	case <-returned:
		t.Fatal("multipart completion released admission before the HTTP body ended")
	case <-time.After(time.Second):
		t.Fatal("handler did not read the HTTP epilogue")
	}
	requireHTTPEpilogueOverload(t, ts)
	if len(srv.httpRequestSlots) != 1 {
		t.Fatal("stalled epilogue did not retain its admission permit")
	}
	tail := "e"
	if chunked {
		tail = "1\r\ne\r\n0\r\n\r\n"
	}
	if _, err := io.WriteString(conn, tail); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	requireHTTPEpilogueResponse(t, reader, wantStatus)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("completed HTTP body did not release admission")
	}
	if len(srv.httpRequestSlots) != 0 {
		t.Fatal("completed HTTP body leaked its admission permit")
	}
	// A completed request preserves keepalive and admits the next upload.
	if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6cHc=\r\nContent-Type: multipart/form-data; boundary=boundary\r\nContent-Length: %d\r\n\r\n%s", len(body), body); err != nil {
		t.Fatal(err)
	}
	requireHTTPEpilogueResponse(t, reader, wantStatus)
}

func newHTTPEpilogueTestServer(t *testing.T, bodyBytes int, wrap func(http.Handler) http.Handler) (*Server, *httptest.Server, <-chan struct{}, <-chan struct{}) {
	t.Helper()
	config := DefaultConfig()
	config.Users = map[string]UserInfo{"alice": {Password: "pw", Root: t.TempDir(), CanWrite: true}}
	config.ResourceLimits.HTTPMaxConcurrentRequests = 1
	srv := NewServer(config)
	reading, returned := make(chan struct{}), make(chan struct{})
	var handler http.Handler = srv.HttpIngest()
	if wrap != nil {
		handler = wrap(handler)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Held-Epilogue") == "1" {
			r.Body = &httpEpilogueBody{ReadCloser: r.Body, remaining: bodyBytes, reading: reading}
			defer close(returned)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return srv, ts, reading, returned
}

func sendHTTPEpilogueRequest(t *testing.T, conn net.Conn, body string, chunked bool) {
	t.Helper()
	framing := fmt.Sprintf("Content-Length: %d\r\n", len(body)+1)
	wireBody := body
	if chunked {
		framing = "Transfer-Encoding: chunked\r\n"
		wireBody = fmt.Sprintf("%x\r\n%s\r\n", len(body), body)
	}
	if _, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6cHc=\r\nX-Test-Held-Epilogue: 1\r\nContent-Type: multipart/form-data; boundary=boundary\r\n%s\r\n%s", framing, wireBody); err != nil {
		t.Fatal(err)
	}
}

func requireHTTPEpilogueOverload(t *testing.T, ts *httptest.Server) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL, strings.NewReader("ignored"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("concurrent request status=%d Retry-After=%q; want 503 and 1", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func requireHTTPEpilogueResponse(t *testing.T, reader *bufio.Reader, wantStatus int) {
	t.Helper()
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus || resp.Close {
		t.Fatalf("response status=%d close=%t; want %d and keepalive", resp.StatusCode, resp.Close, wantStatus)
	}
}

type httpEpilogueBody struct {
	io.ReadCloser

	remaining int
	reading   chan struct{}
	once      sync.Once
}

func (b *httpEpilogueBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		b.once.Do(func() { close(b.reading) })
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= n
	return n, err
}

func TestHTTPIngest_MultipartEpilogueDisconnectReleasesAdmission(t *testing.T) {
	testHTTPEpilogueDisconnect(t, "--boundary--\r\n", nil)
}

func testHTTPEpilogueDisconnect(t *testing.T, body string, wrap func(http.Handler) http.Handler) {
	t.Helper()
	srv, ts, reading, returned := newHTTPEpilogueTestServer(t, len(body), wrap)
	conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	sendHTTPEpilogueRequest(t, conn, body, false)
	select {
	case <-reading:
	case <-returned:
		t.Fatal("handler returned without waiting for the epilogue")
	case <-time.After(time.Second):
		t.Fatal("handler did not enter the epilogue read")
	}
	_ = conn.Close()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not interrupt the epilogue read")
	}
	if len(srv.httpRequestSlots) != 0 {
		t.Fatal("disconnected epilogue reader leaked its admission permit")
	}
}
