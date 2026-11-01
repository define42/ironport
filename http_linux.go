// Package ironport: HTTP file-ingest endpoint.
//
// This file adds an HTTP upload endpoint that shares the same user database,
// jails, permission flags, and CompletedUploads/AuthEvents streams as the SFTP
// and FTP servers. Unlike SFTP/FTP, the HTTP endpoint does not run its own
// listener: HttpIngest returns an http.HandlerFunc that the caller mounts on
// their own *http.ServeMux (or any router), so the upload path lives inside the
// caller's existing HTTP application:
//
//	srv := ironport.NewServer(config)
//	mux := http.NewServeMux()
//	mux.HandleFunc("/upload", srv.HttpIngest())
//
// Authentication uses HTTP Basic auth with exactly the same username/password
// credentials (and the same constant-time comparison) as SFTP/FTP/FTPS, so a
// user does not need a separate credential for HTTP uploads.

package ironport

import (
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/define42/ironport/internal/jailfs"
	"github.com/define42/ironport/internal/netconn"
)

const (
	defaultHTTPMaxConcurrentRequests = 32
	defaultHTTPMaxAuthorizationBytes = 4096
	defaultHTTPMaxUsernameBytes      = 256
	defaultHTTPMaxPasswordBytes      = 1024

	// CompletedUploadProtocolHTTP identifies an upload completed through the
	// HTTP ingest endpoint (HttpIngest).
	CompletedUploadProtocolHTTP = "HTTP"

	// httpUploadFormField is the multipart/form-data field name the HTTP ingest
	// endpoint reads the uploaded file from. The endpoint is documented as a
	// "key=file" upload, so this is fixed at "file".
	httpUploadFormField = "file"

	// httpUploadFilePerm is the mode of the stored file; httpUploadDirPerm is
	// the mode of any parent directories the endpoint auto-creates for a nested
	// upload path. They mirror the SFTP/FTP upload file mode (0600) with
	// owner-only directories.
	httpUploadFilePerm os.FileMode = 0o600
	httpUploadDirPerm  os.FileMode = 0o700
)

// HttpIngest returns an http.HandlerFunc that accepts a file upload over HTTP
// and stores it in the authenticated user's jail, exactly as an SFTP or FTP
// STOR would. The handler is meant to be registered by the caller on their own
// HTTP server, so the endpoint URL is chosen by the application:
//
//	srv := ironport.NewServer(config)
//	mux := http.NewServeMux()
//	mux.HandleFunc("/upload", srv.HttpIngest())
//
// Request contract:
//
//   - Method must be POST; anything else gets 405 with an Allow header.
//   - HTTP Basic authentication is required. The username and password are the
//     same credentials used for SFTP/FTP/FTPS and are checked with the same
//     constant-time password comparison. A missing or invalid credential gets
//     401 with a WWW-Authenticate challenge; only an attempt that supplied a
//     wrong credential (not a bare unauthenticated probe) emits a LoginFailed
//     AuthEvent. Oversized raw Authorization headers get 431 before decoding;
//     oversized decoded credentials get 401 without logging or events.
//     Throttled attempts get 429 with Retry-After.
//   - HTTPMaxConcurrentRequests bounds in-flight work across every handler
//     created from this Server; saturation gets 503 with Retry-After.
//   - The authenticated user must have CanWrite; otherwise the request gets 403.
//   - The body must be multipart/form-data carrying one or more parts under the
//     form field "file" (key=file). Each part's filename becomes the
//     destination path, relative to the user's jail root. A nested name such as
//     "reports/2026/q2.csv" (or "/reports/2026/q2.csv") is stored at that path
//     and any missing parent directories are created. The path is resolved
//     through the same openat2, no-symlink jail used by SFTP/FTP, so ".."
//     segments are collapsed and contained, and a crafted name can neither
//     traverse out of the jail nor follow a symlink.
//
// Multiple "file" parts in one request are each stored independently (a
// standard multi-file form, e.g. curl -F file=@a -F file=@b), and each stored
// file is announced separately on the CompletedUploads stream (Protocol
// CompletedUploadProtocolHTTP) — honouring TempExtensions and dotfile deferral
// the same way SFTP/FTP do, so a ".tmp"/dotfile upload is intentionally not
// announced until a later rename. The handler replies 201 Created when at least
// one file was stored and none failed; if any file failed it replies with an
// error status (400 for client errors such as an invalid filename or no "file"
// part, 500 for a server-side write error) and a plain-text body listing each
// file's outcome, so a partial failure is never silent.
//
// Like the other protocols, the handler never blocks on the notification
// streams: a slow CompletedUploads/AuthEvents consumer drops events rather
// than stalling an upload. The handler streams the body straight into the
// destination file without buffering the whole upload in memory or staging it
// in a temp directory. It imposes no size limit of its own (matching SFTP/FTP);
// callers that want one can wrap the handler with http.MaxBytesReader or bound
// the body at a reverse proxy.
//
// Middleware must preserve ResponseController access via Unwrap, or callers
// must install WithHTTPControl outside the complete middleware chain. This
// allows early rejections to stop body reads before returning request capacity.
// Middleware that replaces or limits the request body also needs WithHTTPControl
// so the original body is consumed before successful uploads return capacity.
// Without transport control, HTTP/1 cleanup depends on the caller's read timeout.
//
// Creating the handler checks kernel support and warns about unusable jail roots,
// including in HTTP-only deployments. A failed capability check makes requests
// return 503 until a later probe succeeds; root warnings remain advisory.
func (s *Server) HttpIngest() http.HandlerFunc { //nolint:revive // exported name HttpIngest is the documented API (mirrors this package's Ftp/Sftp naming and the caller example)
	handler := http.HandlerFunc(s.handleHTTPIngest)
	if err := s.ValidateJailRoots(); err != nil {
		// Quote error text to escape control characters.
		log.Printf("HTTP ingest jail validation failed: %q", err.Error())
		handler = func(w http.ResponseWriter, r *http.Request) {
			// Transient resource pressure during handler creation must not
			// permanently disable uploads. CheckSupport caches definitive results.
			if jailfs.CheckSupport() != nil {
				s.rejectHTTPUpload(w, r, http.StatusServiceUnavailable)
				return
			}
			s.handleHTTPIngest(w, r)
		}
	}
	return s.limitHTTPRequests(handler)
}

// limitHTTPRequests rejects excess work before inspecting credentials or bodies.
func (s *Server) limitHTTPRequests(next http.HandlerFunc) http.HandlerFunc {
	slots := s.httpRequestSemaphore()
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			s.rejectHTTPUpload(w, r, http.StatusServiceUnavailable)
			return
		}
		next(w, r)
	}
}

func (s *Server) httpRequestSemaphore() chan struct{} {
	s.httpRequestOnce.Do(func() {
		s.httpRequestSlots = make(chan struct{}, positiveLimit(s.httpMaxConcurrentRequests, defaultHTTPMaxConcurrentRequests))
	})
	return s.httpRequestSlots
}

func (s *Server) httpAuthorizationByteLimit() int {
	return positiveLimit(s.httpMaxAuthorizationBytes, defaultHTTPMaxAuthorizationBytes)
}

func (s *Server) httpUsernameByteLimit() int {
	return positiveLimit(s.httpMaxUsernameBytes, defaultHTTPMaxUsernameBytes)
}

func (s *Server) httpPasswordByteLimit() int {
	return positiveLimit(s.httpMaxPasswordBytes, defaultHTTPMaxPasswordBytes)
}

func (s *Server) handleHTTPIngest(w http.ResponseWriter, r *http.Request) {
	if s.configErr != nil {
		s.rejectHTTPUpload(w, r, http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.rejectHTTPUpload(w, r, http.StatusMethodNotAllowed)
		return
	}
	username, user, jfs, ok := s.httpAuthenticate(w, r)
	if !ok {
		return
	}
	// Own the authenticated descriptor before any permission/body rejection.
	// All request filesystem operations use this same retained jail.
	defer func() { _ = jfs.Close() }()
	if !user.CanWrite {
		s.rejectHTTPUpload(w, r, http.StatusForbidden)
		return
	}
	s.httpStoreUpload(w, r, username, jfs)
}

// httpAuthenticate validates HTTP Basic credentials against the shared user
// database. On success it returns the username, the user's snapshot, and the
// open jail, which the caller must close. On failure it returns ok=false after
// rejecting the upload with 401, 429, or 431, or closing the connection when only
// Hijacker is available. A bare request with no Authorization header is answered
// with a challenge but does not emit a LoginFailed event, so unauthenticated
// probes (and the first leg of a browser's challenge/response) do not flood the
// AuthEvents stream.
func (s *Server) httpAuthenticate(w http.ResponseWriter, r *http.Request) (username string, user UserInfo, jfs *jailfs.FS, ok bool) {
	authorizationValues := r.Header.Values("Authorization")
	if len(authorizationValues) == 0 {
		s.rejectHTTPUpload(w, r, http.StatusUnauthorized)
		return "", UserInfo{}, nil, false
	}
	rawLimit := s.httpAuthorizationByteLimit()
	rawBytes := 0
	for _, value := range authorizationValues {
		if len(value) > rawLimit-rawBytes {
			s.rejectHTTPUpload(w, r, http.StatusRequestHeaderFieldsTooLarge)
			return "", UserInfo{}, nil, false
		}
		rawBytes += len(value)
	}
	if len(authorizationValues) != 1 {
		s.rejectHTTPUpload(w, r, http.StatusUnauthorized)
		return "", UserInfo{}, nil, false
	}
	reqUser, reqPass, hasAuth := r.BasicAuth()
	if !hasAuth || len(reqUser) > s.httpUsernameByteLimit() || len(reqPass) > s.httpPasswordByteLimit() {
		s.rejectHTTPUpload(w, r, http.StatusUnauthorized)
		return "", UserInfo{}, nil, false
	}
	clientIP := netconn.HostFromAddr(r.RemoteAddr)
	if retry := s.allowAuth(reqUser, clientIP); retry > 0 {
		s.authFailed(reqUser, clientIP, CompletedUploadProtocolHTTP, s.authEventsChan(), true)
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry-1)/time.Second+1), 10))
		s.rejectHTTPUpload(w, r, http.StatusTooManyRequests)
		return "", UserInfo{}, nil, false
	}
	u, jail, _, authOK := s.authenticateUser(reqUser, func(stored UserInfo) bool {
		return checkPassword(stored.Password, reqPass)
	})
	if !authOK {
		s.authFailed(reqUser, clientIP, CompletedUploadProtocolHTTP, s.authEventsChan(), false)
		s.rejectHTTPUpload(w, r, http.StatusUnauthorized)
		return "", UserInfo{}, nil, false
	}
	// Retain ownership until the successful return, including calls into an
	// application-supplied log writer that may panic before the handler can defer Close.
	defer func() {
		if !ok {
			_ = jail.Close()
		}
	}()
	s.authSucceeded(reqUser, clientIP)
	//nolint:gosec // G706: username/IP are logged with %q, which escapes CR/LF and so neutralises log-line injection from the client-supplied Authorization header
	log.Printf("login protocol=http user=%q root=%q from=%q", reqUser, u.Root, clientIP)
	s.announceHTTPAuthEvent(AuthEventLoginSuccess, reqUser, clientIP)
	return reqUser, u, jail, true
}

// httpStoreUpload reads every multipart part named "file" and stores each into
// the user's jail. It is best-effort across files: each file is validated and
// written independently, gets its own CompletedUpload announcement, and one
// file's failure does not abort the others. The reply is 201 Created when at
// least one file was stored and none failed; otherwise it is an error status
// (400 for client errors / no "file" part, 500 when any file hit a server-side
// error) whose body lists every file's outcome. All filesystem detail is logged
// server-side, never echoed to the client. The caller retains ownership of jfs.
func (s *Server) httpStoreUpload(w http.ResponseWriter, r *http.Request, username string, jfs *jailfs.FS) {
	mr, err := r.MultipartReader()
	if err != nil {
		s.rejectHTTPUpload(w, r, http.StatusBadRequest)
		return
	}
	results, bodyOK := s.storeUploadParts(mr, jfs, username, netconn.HostFromAddr(r.RemoteAddr))
	if bodyOK {
		// The closing multipart boundary can precede the HTTP body's EOF.
		// Consume its epilogue under this request's admission permit, rather
		// than leaving net/http to drain a possibly stalled body after return.
		bodyOK = drainHTTPUploadBody(r) == nil
	}
	if !bodyOK && !s.stopHTTPUpload(w, r) {
		return
	}
	writeUploadResponse(w, results, bodyOK)
}

// uploadResult records the outcome of storing one multipart "file" part. path
// is the jail-relative destination (e.g. "/dir/f.txt") on success or when the
// write failed after a valid name; for a name that failed validation it is the
// quoted raw filename. serverErr distinguishes a server-side failure (→ 500)
// from a client error such as an invalid filename (→ 400).
type uploadResult struct {
	path      string
	stored    bool
	serverErr bool
}

// storeUploadParts walks the multipart body, storing each part named
// httpUploadFormField ("file") via storeUploadPart and skipping all others. It
// returns one uploadResult per "file" part in request order. bodyOK is false
// when the multipart stream itself was malformed (a client error); any parts
// already stored before that point are still reported.
func (s *Server) storeUploadParts(mr *multipart.Reader, jfs *jailfs.FS, username, clientIP string) (results []uploadResult, bodyOK bool) {
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return results, true
		}
		if err != nil {
			return results, false
		}
		if p.FormName() != httpUploadFormField {
			_ = p.Close()
			continue
		}
		results = append(results, s.storeUploadPart(jfs, p, username, clientIP))
		_ = p.Close()
	}
}

// storeUploadPart validates one "file" part's name, creates any missing parent
// directories, streams it into the jail, and announces the completed upload.
func (s *Server) storeUploadPart(jfs *jailfs.FS, p *multipart.Part, username, clientIP string) uploadResult {
	raw := uploadPartFilename(p)
	clientPath, ok := sanitizeUploadPath(raw)
	if !ok {
		return uploadResult{path: fmt.Sprintf("%q", raw)}
	}
	log.Printf("upload protocol=http user=%q path=%q", username, clientPath)
	if err := jfs.MkdirAll(path.Dir(clientPath), httpUploadDirPerm); err != nil {
		log.Printf("upload failed protocol=http user=%q path=%q: create parent dirs: %q", username, clientPath, err.Error())
		return uploadResult{path: clientPath, serverErr: true}
	}
	if err := streamToJailFile(jfs, clientPath, p); err != nil {
		log.Printf("upload interrupted protocol=http user=%q path=%q: %q", username, clientPath, err.Error())
		return uploadResult{path: clientPath, serverErr: true}
	}
	s.announceHTTPUpload(username, clientIP, clientPath, jfs.FullPath(clientPath))
	return uploadResult{path: clientPath, stored: true}
}

// writeUploadResponse writes the HTTP reply for a (possibly multi-file) upload.
// When at least one "file" part was seen, the body lists every file's outcome
// ("stored <path>" / "failed <path> (<reason>)") so the client can tell exactly
// what was and was not stored, even on a partial failure.
func writeUploadResponse(w http.ResponseWriter, results []uploadResult, bodyOK bool) {
	if len(results) == 0 {
		writeHTTPStatus(w, http.StatusBadRequest) // no "file" part in the body
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(uploadResponseStatus(results, bodyOK))
	for _, res := range results {
		if res.stored {
			_, _ = fmt.Fprintf(w, "stored %s\n", res.path)
			continue
		}
		reason := "invalid name"
		if res.serverErr {
			reason = "server error"
		}
		_, _ = fmt.Fprintf(w, "failed %s (%s)\n", res.path, reason)
	}
}

// uploadResponseStatus selects the status code for a batch of upload results:
// 201 when every file stored and the body was well-formed, 500 when any file
// failed server-side, and 400 otherwise (client errors or a malformed body).
func uploadResponseStatus(results []uploadResult, bodyOK bool) int {
	failed, serverErr := 0, 0
	for _, res := range results {
		if res.stored {
			continue
		}
		failed++
		if res.serverErr {
			serverErr++
		}
	}
	switch {
	case failed == 0 && bodyOK:
		return http.StatusCreated
	case serverErr > 0:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// uploadPartFilename returns the raw filename from the part's Content-Disposition
// header. It deliberately does not use multipart.Part.FileName, which strips
// directory components via filepath.Base (RFC 7578 §4.2) and so would discard
// any folder path in the upload name. Returns "" when the header is absent or
// unparseable.
func uploadPartFilename(p *multipart.Part) string {
	_, params, err := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
	if err != nil {
		return ""
	}
	return params["filename"]
}

// sanitizeUploadPath turns a client-supplied multipart filename into a clean,
// jail-relative destination path (always beginning with "/", e.g.
// "/reports/q2.csv"). It rejects names that carry CR/LF or a NUL, name a
// directory rather than a file (a trailing "/"), or resolve to the jail root
// itself (".", "..", "/"). ".." segments are collapsed by jailfs.CleanPath
// and the jail's openat2 resolution is the actual containment guarantee; this
// check only turns obviously bad names into a clean 400 rather than a
// surprising filesystem error.
func sanitizeUploadPath(rawFilename string) (clientPath string, ok bool) {
	if rawFilename == "" || hasCRLF(rawFilename) || strings.ContainsRune(rawFilename, 0) {
		return "", false
	}
	if strings.HasSuffix(rawFilename, "/") {
		return "", false // names a directory, not a file
	}
	rel := jailfs.CleanPath(rawFilename)
	if rel == "." {
		return "", false // resolves to the jail root; no file name
	}
	return "/" + rel, true
}

// streamToJailFile copies src into a freshly truncated file at clientPath,
// overwriting any existing file (the same create/truncate semantics as an
// SFTP/FTP STOR). The destination is opened through the jail's openat2 path so
// symlink components and traversal are rejected by the kernel.
func streamToJailFile(jfs *jailfs.FS, clientPath string, src io.Reader) error {
	f, err := jfs.OpenWrite(clientPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, httpUploadFilePerm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// announceHTTPUpload publishes the CompletedUpload event for a successful HTTP
// upload, applying the same TempExtensions/dotfile deferral as SFTP and FTP.
// Because an HTTP upload has no later rename step, a deferred name (a dotfile or
// a configured temp extension) is intentionally never announced over HTTP
// alone; it is announced if and when the file is renamed to a final name via
// SFTP/FTP.
func (s *Server) announceHTTPUpload(username, clientIP, clientPath, fullPath string) {
	log.Printf("upload complete protocol=http user=%q path=%q", username, clientPath)
	if shouldDeferCompletion(clientPath, s.configuredTempExtensions()) {
		log.Printf("upload complete: %q is a deferred name (temp extension or dotfile), deferring CompletedUploads notification", clientPath)
		return
	}
	publishUpload(s.completedUploadsChan(), CompletedUpload{
		Username:     username,
		FullFilePath: fullPath,
		FilePath:     clientPath,
		ClientIP:     clientIP,
		Protocol:     CompletedUploadProtocolHTTP,
	})
}

func (s *Server) announceHTTPAuthEvent(eventType AuthEventType, username, clientIP string) {
	announceAuthEvent(s.authEventsChan(), AuthEvent{
		Type:     eventType,
		Username: username,
		ClientIP: clientIP,
		Protocol: CompletedUploadProtocolHTTP,
	})
}

// writeHTTPAuthChallenge sends a 401 with a Basic auth challenge. The realm is
// fixed; clients prompt for the same username/password they use for SFTP/FTP.
func writeHTTPAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="ironport"`)
	writeHTTPStatus(w, http.StatusUnauthorized)
}

// writeHTTPStatus replies with the canonical status text for code and nothing
// else, so no internal detail (paths, filesystem errors) leaks to the client.
func writeHTTPStatus(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}
