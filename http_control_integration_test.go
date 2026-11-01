//go:build linux && integration

package ironport

import (
	"bufio"
	"errors"
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

func TestHTTPControl_RejectedSlowBodiesThroughMiddleware(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(http.Handler) http.Handler
	}{
		{"captured opaque writer", func(next http.Handler) http.Handler {
			return WithHTTPControl(httpOpaqueControlMiddleware(next))
		}},
		{"outer capture survives nested opaque capture", func(next http.Handler) http.Handler {
			return WithHTTPControl(httpOpaqueControlMiddleware(WithHTTPControl(next)))
		}},
		{"unwrapping writer", func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(httpUnwrappingControlWriter{w}, r)
			})
		}},
		{"unwrapping writer replaced unread body", func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.NoBody
				next.ServeHTTP(httpUnwrappingControlWriter{w}, r)
			})
		}},
		{"captured writer replaced unread body", func(next http.Handler) http.Handler {
			return WithHTTPControl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Body = http.NoBody
				next.ServeHTTP(httpOpaqueControlWriter{w}, r)
			}))
		}},
	} {
		for _, saturated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/saturated=%t", test.name, saturated), func(t *testing.T) {
				t.Parallel()
				testHTTPControlRejectedBodies(t, test.wrap, saturated)
			})
		}
	}
}

func testHTTPControlRejectedBodies(t *testing.T, wrap func(http.Handler) http.Handler, saturated bool) {
	t.Helper()
	const requests = 3
	config := DefaultConfig()
	config.ResourceLimits.HTTPMaxConcurrentRequests = 1
	srv := NewServer(config)
	wantStatus, wantSlots := http.StatusUnauthorized, 0
	if saturated {
		// Reserve the sole slot to isolate the rejection path, which has no
		// admission permit of its own to retain during request-body cleanup.
		srv.httpRequestSemaphore() <- struct{}{}
		t.Cleanup(func() { <-srv.httpRequestSlots })
		wantStatus, wantSlots = http.StatusServiceUnavailable, 1
	}
	closed := make(chan struct{}, requests)
	ts := httptest.NewUnstartedServer(wrap(srv.HttpIngest()))
	ts.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	ts.Start()
	t.Cleanup(ts.Close)
	for range requests {
		testHTTPRejectedSlowBodyRequest(t, ts.Listener.Addr().String(), "", "", wantStatus)
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for count := range requests {
		select {
		case <-closed:
		case <-deadline.C:
			t.Fatalf("only %d of %d rejected connections closed through middleware", count, requests)
		}
	}
	if got := len(srv.httpRequestSlots); got != wantSlots {
		t.Fatalf("admission permits held = %d; want %d", got, wantSlots)
	}
}

func TestHTTPControl_AlteredBodyRetainsAdmission(t *testing.T) {
	const body = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n\r\nx\r\n--boundary--\r\n"
	for _, mode := range []string{"replacement", "limited"} {
		wrap := func(next http.Handler) http.Handler {
			return WithHTTPControl(httpOpaqueControlMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Test-Held-Epilogue") == "1" {
					if mode == "limited" {
						r.Body = io.NopCloser(io.LimitReader(r.Body, int64(len(body))))
					} else {
						r.Body = io.NopCloser(strings.NewReader(body))
					}
				}
				next.ServeHTTP(w, r)
			})))
		}
		for _, chunked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/chunked=%t", mode, chunked), func(t *testing.T) {
				t.Parallel()
				testHTTPEpilogueAdmission(t, body, http.StatusCreated, chunked, wrap)
			})
		}
		t.Run(mode+"/disconnect", func(t *testing.T) {
			t.Parallel()
			testHTTPEpilogueDisconnect(t, body, wrap)
		})
	}
}

func TestHTTPControl_TimeoutDuringOriginalBodyDrain(t *testing.T) {
	t.Parallel()
	const body = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n\r\nx\r\n--boundary--\r\n"
	ingestReturned := make(chan struct{})
	wrap := func(next http.Handler) http.Handler {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(ingestReturned)
			r.Body = io.NopCloser(strings.NewReader(body))
			next.ServeHTTP(w, r)
		})
		return WithHTTPControl(http.TimeoutHandler(inner, 30*time.Millisecond, "timed out"))
	}
	srv, ts, reading, returned := newHTTPEpilogueTestServer(t, len(body), wrap)
	conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	sendHTTPEpilogueRequest(t, conn, body, false)
	waitHTTPControlSignal(t, reading, "handler did not start draining the original body")
	// The outer timeout must return freely while the inner handler retains
	// admission for its blocked read. A controller lock held during that read
	// would prevent WithHTTPControl from returning and invalidating itself.
	waitHTTPControlSignal(t, returned, "original-body drain blocked the outer timeout")
	if len(srv.httpRequestSlots) != 1 {
		t.Fatal("timeout released admission while the original body was unread")
	}
	_ = conn.Close()
	waitHTTPControlSignal(t, ingestReturned, "disconnect did not release the timed-out upload")
	if len(srv.httpRequestSlots) != 0 {
		t.Fatal("timed-out upload leaked its admission permit after disconnect")
	}
}

func TestHTTPControl_HTTP2RejectionPreservesResponse(t *testing.T) {
	srv := NewServer(nil)
	ts := httptest.NewUnstartedServer(WithHTTPControl(httpOpaqueControlMiddleware(srv.HttpIngest())))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	reader, writer := io.Pipe()
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL, reader)
	if err != nil {
		t.Fatal(err)
	}
	// Send headers but withhold the entire body. Rejecting this stream must
	// interrupt its body read while still delivering the authentication reply.
	req.ContentLength = 1
	client := ts.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusUnauthorized || string(body) != "Unauthorized\n" {
		t.Fatalf("response = %s %d %q; want HTTP/2 401 Unauthorized", resp.Proto, resp.StatusCode, body)
	}
	if len(srv.httpRequestSlots) != 0 {
		t.Fatal("rejected HTTP/2 request retained an admission permit")
	}
}

func TestHTTPControl_HijackerFallbackClosesSlowBodies(t *testing.T) {
	for _, saturated := range []bool{false, true} {
		t.Run(fmt.Sprintf("saturated=%t", saturated), func(t *testing.T) {
			t.Parallel()
			testHTTPControlHijackerFallback(t, saturated)
		})
	}
}

func testHTTPControlHijackerFallback(t *testing.T, saturated bool) {
	t.Helper()
	config := DefaultConfig()
	config.ResourceLimits.HTTPMaxConcurrentRequests = 1
	srv := NewServer(config)
	wantSlots := 0
	if saturated {
		srv.httpRequestSemaphore() <- struct{}{}
		t.Cleanup(func() { <-srv.httpRequestSlots })
		wantSlots = 1
	}
	returned := make(chan struct{})
	handler := srv.HttpIngest()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(returned)
		handler(httpHijackingControlWriter{w}, r)
	}))
	t.Cleanup(ts.Close)
	conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := conn.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("hijacked connection read = %d, %v; want EOF without a response", n, err)
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("hijacked rejection did not return")
	}
	if got := len(srv.httpRequestSlots); got != wantSlots {
		t.Fatalf("admission permits held = %d; want %d", got, wantSlots)
	}
}

func TestHTTPControl_TimeoutDoesNotControlNextRequest(t *testing.T) {
	lateDone, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	handler := NewServer(nil).HttpIngest()
	mux := http.NewServeMux()
	mux.Handle("/upload", http.TimeoutHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		defer close(lateDone)
		handler(w, r)
	}), 30*time.Millisecond, "timed out"))
	holding, holdReturned := make(chan struct{}), make(chan struct{})
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		defer close(holdReturned)
		close(holding)
		var b [1]byte
		if _, err := io.ReadFull(r.Body, b[:]); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	ts := httptest.NewServer(WithHTTPControl(mux))
	t.Cleanup(ts.Close)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		waitHTTPControlSignal(t, lateDone, "late handler did not finish")
	})
	conn, err := net.DialTimeout("tcp", ts.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	requireHTTPEpilogueResponse(t, reader, http.StatusServiceUnavailable)
	if _, err := io.WriteString(conn, "POST /hold HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	waitHTTPControlSignal(t, holding, "next request did not start on the reused connection")
	// The old handler now rejects after TimeoutHandler has already returned.
	// Its captured controller must not expire the new request's read deadline.
	releaseOnce.Do(func() { close(release) })
	waitHTTPControlSignal(t, lateDone, "late rejection did not finish")
	select {
	case <-holdReturned:
		t.Fatal("late rejection interrupted the next request before its body arrived")
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := io.WriteString(conn, "x"); err != nil {
		t.Fatal(err)
	}
	requireHTTPEpilogueResponse(t, reader, http.StatusOK)
}

func TestHTTPControl_CompletedBodyPreservesTimeoutResponse(t *testing.T) {
	for _, test := range []struct {
		name, method, bodyMode string
		chunked                bool
		wantStatus             int
	}{
		{"bodyless challenge", http.MethodPost, "empty", false, http.StatusUnauthorized},
		{"bodyless method", http.MethodGet, "empty", false, http.StatusMethodNotAllowed},
		{"consumed body", http.MethodPost, "read", false, http.StatusUnauthorized},
		{"consumed chunked body", http.MethodPost, "read", true, http.StatusUnauthorized},
		{"closed body", http.MethodPost, "close", false, http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testHTTPControlCompletedBody(t, test.method, test.bodyMode, test.chunked, test.wantStatus)
		})
	}
}

func testHTTPControlCompletedBody(t *testing.T, method, bodyMode string, chunked bool, wantStatus int) {
	t.Helper()
	ingest := NewServer(nil).HttpIngest()
	middlewareDone := make(chan error, 1)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := consumeHTTPControlTestBody(r, bodyMode); err != nil {
			middlewareDone <- err
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ingest(w, r)
		// Middleware can do work after its inner handler returns. A body-read
		// deadline must not cancel that work after the body has already ended.
		select {
		case <-r.Context().Done():
			middlewareDone <- r.Context().Err()
		case <-time.After(20 * time.Millisecond):
			middlewareDone <- nil
		}
	})
	ts := httptest.NewServer(WithHTTPControl(http.TimeoutHandler(inner, time.Second, "timed out")))
	t.Cleanup(ts.Close)
	req, err := http.NewRequestWithContext(t.Context(), method, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bodyMode != "empty" {
		req.Body = io.NopCloser(strings.NewReader("x"))
		req.ContentLength = 1
		if chunked {
			req.ContentLength = -1
		}
	}
	client := ts.Client()
	client.Timeout = 2 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status = %d; want %d", resp.StatusCode, wantStatus)
	}
	if wantStatus == http.StatusUnauthorized && resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("authentication challenge was lost")
	}
	select {
	case err := <-middlewareDone:
		if err != nil {
			t.Fatalf("completed-body rejection canceled middleware: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("middleware did not finish")
	}
}

func consumeHTTPControlTestBody(r *http.Request, mode string) error {
	switch mode {
	case "read":
		_, err := io.Copy(io.Discard, r.Body)
		return err
	case "close":
		return r.Body.Close()
	default:
		return nil
	}
}

func waitHTTPControlSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(failure)
	}
}

func httpOpaqueControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(httpOpaqueControlWriter{w}, r)
	})
}

type httpOpaqueControlWriter struct {
	http.ResponseWriter
}

type httpUnwrappingControlWriter struct {
	http.ResponseWriter
}

func (w httpUnwrappingControlWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Some middleware forwards the older Hijacker interface but does not expose
// newer ResponseController methods or an Unwrap method.
type httpHijackingControlWriter struct {
	http.ResponseWriter
}

func (w httpHijackingControlWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}
