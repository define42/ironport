//go:build linux

package ironport

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type httpControlContextKey struct{}

// A timeout middleware may return while its inner handler is still running.
// Serialize transport operations with invalidation so a late handler cannot
// change deadlines on a connection already reused for another request.
type httpControl struct {
	mu         sync.Mutex
	controller *http.ResponseController
	body       io.Reader
	active     bool
	bodyDone   atomic.Bool
}

func (c *httpControl) disable() {
	c.mu.Lock()
	c.active = false
	c.mu.Unlock()
}

// Observe the original body before middleware can consume or replace it. EOF
// means it was consumed; a completed Close prevents further body reads or
// cleanup draining even when unread bytes remain. Expiring the transport read
// deadline afterward could interrupt net/http's background connection read and
// cancel the request context, including any enclosing timeout middleware.
type httpControlBody struct {
	io.ReadCloser

	done *atomic.Bool
}

func (b *httpControlBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		b.done.Store(true)
	}
	return n, err
}

func (b *httpControlBody) Close() error {
	err := b.ReadCloser.Close()
	b.done.Store(true)
	return err
}

// WithHTTPControl preserves the HTTP transport controls needed to terminate
// rejected upload bodies, even when downstream middleware hides optional
// ResponseWriter interfaces. It also keeps original-body cleanup under the
// upload admission limit when middleware replaces or limits the body. Install
// it outside the entire middleware chain:
//
//	server := &http.Server{Handler: ironport.WithHTTPControl(middleware(mux))}
//
// Middleware must preserve the request context. Nested calls retain the
// outermost controller, which is invalidated when this wrapper returns so late
// handlers cannot affect a reused connection. This changes neither routing nor admission
// limits. It is optional when middleware preserves the complete request body
// and every ResponseWriter wrapper implements Unwrap() http.ResponseWriter,
// as required by http.ResponseController.
func WithHTTPControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(httpControlContextKey{}).(*httpControl); !ok {
			control := &httpControl{controller: http.NewResponseController(w), active: true}
			defer control.disable()
			ctx := context.WithValue(r.Context(), httpControlContextKey{}, control)
			r = r.WithContext(ctx)
			if r.Body == nil || r.Body == http.NoBody {
				control.bodyDone.Store(true)
			} else {
				r.Body = &httpControlBody{ReadCloser: r.Body, done: &control.bodyDone}
				control.body = r.Body
			}
		}
		next.ServeHTTP(w, r)
	})
}

// drainHTTPUploadBody consumes both the current body and any remainder of the
// original transport body while the upload still holds its admission permit.
// Middleware can report EOF before the transport body ends, for example when
// limiting or replacing it. Do not hold the controller mutex across reads:
// timeout middleware must remain free to return and invalidate its controller.
func drainHTTPUploadBody(r *http.Request) error {
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		return err
	}
	if control, ok := r.Context().Value(httpControlContextKey{}).(*httpControl); ok && !control.bodyDone.Load() {
		_, err := io.Copy(io.Discard, control.body)
		return err
	}
	return nil
}

func (s *Server) rejectHTTPUpload(w http.ResponseWriter, r *http.Request, status int) {
	if !s.stopHTTPUpload(w, r) {
		return
	}
	if status == http.StatusUnauthorized {
		writeHTTPAuthChallenge(w)
		return
	}
	writeHTTPStatus(w, status)
}

// stopHTTPUpload stops body reads before admission capacity is returned. A
// false result means no response may be written: the connection was hijacked
// and closed, or the outer handler has already returned. HTTP/2 deadlines
// affect only this stream, without sending GOAWAY.
func (s *Server) stopHTTPUpload(w http.ResponseWriter, r *http.Request) bool {
	controller := http.NewResponseController(w)
	// Without an outer capture, middleware may have replaced an unread body.
	// Only skip cleanup when the request framing also says there was no body.
	hasNoBody := r.Body == nil || r.Body == http.NoBody
	bodyDone := r.ContentLength == 0 && len(r.TransferEncoding) == 0 && hasNoBody
	if control, ok := r.Context().Value(httpControlContextKey{}).(*httpControl); ok {
		control.mu.Lock()
		defer control.mu.Unlock()
		if !control.active {
			return false
		}
		controller = control.controller
		bodyDone = control.bodyDone.Load()
	}
	if r.ProtoMajor < 2 {
		w.Header().Set("Connection", "close")
	}
	if bodyDone {
		return true
	}
	if err := controller.SetReadDeadline(time.Now()); err == nil {
		return true
	}
	// Some older middleware forwards Hijacker but not deadline control.
	// Closing a hijacked connection avoids net/http's automatic body drain.
	if conn, _, err := controller.Hijack(); err == nil {
		_ = conn.Close()
		return false
	}
	// In-memory ResponseWriters have no transport to stop. On a real server,
	// make the integration error visible instead of silently claiming cleanup
	// was bounded. Arbitrary opaque writers cannot expose their connection:
	// callers must use WithHTTPControl or forward Unwrap to enable that path.
	if r.Context().Value(http.ServerContextKey) != nil {
		if sample, suppressed := s.httpControlLogs.allow(time.Now()); sample {
			log.Printf("http ingest: transport controls unavailable; install WithHTTPControl outside middleware or forward ResponseWriter.Unwrap; body cleanup depends on server read timeout (suppressed=%d)", suppressed)
		}
	}
	return true
}
