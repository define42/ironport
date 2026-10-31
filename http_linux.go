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
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
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
	// Bound the per-part names retained in the response, including rejected
	// names. Linux paths cannot exceed this length in filesystem operations.
	httpUploadMaxPathBytes                  = 4096
	errUploadPartLimit     uploadLimitError = "too many multipart parts"
)

type uploadLimitError string

func (e uploadLimitError) Error() string { return string(e) }

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
//   - X-Ironport-Upload: 1 is required on every upload, including machine
//     clients. Cross-site Fetch Metadata and untrusted Origin headers are
//     rejected with 403 before authentication or filesystem access. Browser
//     origins must match the direct request origin or HTTPAllowedOrigins.
//   - HTTP Basic authentication is required. The username and password are the
//     same credentials used for SFTP/FTP/FTPS and are checked with the same
//     constant-time password comparison. A missing or invalid credential gets
//     401 with a WWW-Authenticate challenge; only an attempt that supplied a
//     wrong credential (not a bare unauthenticated probe) emits a LoginFailed
//     AuthEvent. Oversized decoded credentials are rejected the same way but
//     without logging or an event; an oversized raw Authorization header gets
//     431 before Basic-auth decoding.
//     Throttled credentials receive 429 with Retry-After instead of 401.
//   - HTTPMaxConcurrentRequests bounds in-flight handler work across all
//     handlers from this Server; saturation gets 503 with Retry-After.
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
// part, 413 for an HTTP upload limit, 507 for a storage budget, 500 for a
// server-side write error) and a
// plain-text body listing each file's outcome, so a partial failure is never silent.
//
// Like the other protocols, the handler never blocks on the notification
// streams: a slow CompletedUploads/AuthEvents consumer drops events rather
// than stalling an upload. The handler streams the body straight into the
// destination file without buffering the whole upload in memory or staging it
// in a temp directory. HTTPMaxUploadBytes limits the whole multipart body,
// including headers and skipped fields, and HTTPMaxUploadParts limits all
// parts. Their defaults are 200 GiB (200 * 2^30 bytes) and 1000 parts. Exceeding either limit stops
// reading immediately and returns 413; earlier completed files remain stored,
// and an interrupted file may remain partially written without a completion
// event. Callers should also configure HTTP server timeouts and MaxHeaderBytes;
// the demo command provides bounded examples.
// Creating the handler validates configured jail roots and logs unusable roots
// before the first request, including in deployments with no SFTP/FTP listener.
func (s *Server) HttpIngest() http.HandlerFunc { //nolint:revive // exported name HttpIngest is the documented API (mirrors this package's Ftp/Sftp naming and the caller example)
	handler := http.HandlerFunc(s.handleHTTPIngest)
	if err := s.ValidateJailRoots(); err != nil {
		log.Printf("HTTP ingest jail validation failed: %q", err.Error())
		handler = func(w http.ResponseWriter, r *http.Request) {
			// Resource pressure during handler creation must not permanently
			// poison the endpoint; only definitive probe results are cached.
			if ensureOpenat2() != nil {
				stopHTTPUpload(w)
				writeHTTPStatus(w, http.StatusServiceUnavailable)
				return
			}
			s.handleHTTPIngest(w, r)
		}
	}
	return s.limitHTTPRequests(handler)
}

func (s *Server) limitHTTPRequests(next http.HandlerFunc) http.HandlerFunc {
	slots := s.httpRequestSemaphore()
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			stopHTTPUpload(w)
			writeHTTPStatus(w, http.StatusServiceUnavailable)
			return
		}
		next(w, r)
	}
}

func (s *Server) httpRequestSemaphore() chan struct{} {
	s.httpRequestOnce.Do(func() {
		s.httpRequestSlots = make(chan struct{}, s.httpConcurrentRequestLimit())
	})
	return s.httpRequestSlots
}

func (s *Server) httpConcurrentRequestLimit() int {
	if s.httpMaxConcurrentRequests <= 0 {
		return defaultHTTPMaxConcurrentRequests
	}
	return s.httpMaxConcurrentRequests
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
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		stopHTTPUpload(w)
		writeHTTPStatus(w, http.StatusMethodNotAllowed)
		return
	}
	if !s.httpUploadOriginAllowed(r) {
		stopHTTPUpload(w)
		writeHTTPStatus(w, http.StatusForbidden)
		return
	}
	username, user, jfs, ok := s.httpAuthenticate(w, r)
	if !ok {
		return
	}
	// Authentication transfers ownership of the retained jail-root fd to this
	// request. Keep the defer here, before any permission or body-validation
	// return, so every successful-authentication path releases it.
	defer func() { _ = jfs.Close() }()
	if !user.CanWrite {
		stopHTTPUpload(w)
		writeHTTPStatus(w, http.StatusForbidden)
		return
	}
	s.httpStoreUpload(w, r, username, jfs)
}

// The custom header cannot be supplied by a cross-site HTML form. A browser
// needs a successful CORS preflight to send it, and this handler never grants
// CORS. Origin/Fetch Metadata checks also protect callers with CORS middleware.
func (s *Server) httpUploadOriginAllowed(r *http.Request) bool {
	if !validHTTPUploadHeaders(r) {
		return false
	}
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	origin, ok := canonicalHTTPOrigin(values[0])
	if !ok {
		return false
	}
	if len(s.httpAllowedOrigins) != 0 {
		for _, allowed := range s.httpAllowedOrigins {
			if candidate, valid := canonicalHTTPOrigin(allowed); valid && candidate == origin {
				return true
			}
		}
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	expected, valid := canonicalHTTPOrigin(scheme + "://" + r.Host)
	return valid && origin == expected
}

func validHTTPUploadHeaders(r *http.Request) bool {
	if values := r.Header.Values("X-Ironport-Upload"); len(values) != 1 || values[0] != "1" {
		return false
	}
	if values := r.Header.Values("Sec-Fetch-Site"); len(values) > 0 {
		if len(values) != 1 {
			return false
		}
		switch values[0] {
		case "same-origin", "same-site", "none":
		default:
			return false
		}
	}
	return true
}

func canonicalHTTPOrigin(value string) (string, bool) {
	u, err := url.Parse(value)
	if err != nil || !validHTTPOriginURL(u) || strings.ContainsAny(value, " \t\r\n,#") {
		return "", false
	}
	if u.Hostname() == "" {
		return "", false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n <= 0 || n > 65535 {
			return "", false
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), true
}

func validHTTPOriginURL(u *url.URL) bool {
	return (u.Scheme == "http" || u.Scheme == "https") &&
		u.Host != "" && !strings.HasSuffix(u.Host, ":") && u.User == nil &&
		u.Opaque == "" && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

// httpAuthenticate validates HTTP Basic credentials against the shared user
// database. On success it returns the username, the user's snapshot, and an
// open jail whose retained root fd is owned by the caller. On failure it has
// already written the 401 or 429 response and returns ok=false. A bare request with no
// Authorization header is answered with a challenge but does not emit a
// LoginFailed event, so unauthenticated probes (and the first leg of a
// browser's challenge/response) do not flood the AuthEvents stream.
func (s *Server) httpAuthenticate(w http.ResponseWriter, r *http.Request) (username string, user UserInfo, jfs *jailFS, ok bool) {
	authorizationValues := r.Header.Values("Authorization")
	if len(authorizationValues) == 0 {
		stopHTTPUpload(w)
		writeHTTPAuthChallenge(w)
		return "", UserInfo{}, nil, false
	}
	rawLimit := s.httpAuthorizationByteLimit()
	rawBytes := 0
	for _, value := range authorizationValues {
		if len(value) > rawLimit-rawBytes {
			stopHTTPUpload(w)
			writeHTTPStatus(w, http.StatusRequestHeaderFieldsTooLarge)
			return "", UserInfo{}, nil, false
		}
		rawBytes += len(value)
	}
	if len(authorizationValues) != 1 {
		stopHTTPUpload(w)
		writeHTTPAuthChallenge(w)
		return "", UserInfo{}, nil, false
	}
	reqUser, reqPass, hasAuth := r.BasicAuth()
	if !hasAuth || len(reqUser) > s.httpUsernameByteLimit() || len(reqPass) > s.httpPasswordByteLimit() {
		stopHTTPUpload(w)
		writeHTTPAuthChallenge(w)
		return "", UserInfo{}, nil, false
	}
	clientIP := hostFromAddr(r.RemoteAddr)
	if retry := s.allowAuth(reqUser, clientIP); retry > 0 {
		s.authFailed(reqUser, clientIP, CompletedUploadProtocolHTTP, s.authEventsChan(), true)
		w.Header().Set("Retry-After", strconv.FormatInt(int64((retry-1)/time.Second+1), 10))
		stopHTTPUpload(w)
		writeHTTPStatus(w, http.StatusTooManyRequests)
		return "", UserInfo{}, nil, false
	}
	u, jail, _, authOK := s.authenticateUser(reqUser, func(stored UserInfo) bool {
		return checkPassword(stored.Password, reqPass)
	})
	if !authOK || jail == nil {
		s.authFailed(reqUser, clientIP, CompletedUploadProtocolHTTP, s.authEventsChan(), false)
		stopHTTPUpload(w)
		writeHTTPAuthChallenge(w)
		return "", UserInfo{}, nil, false
	}
	s.authSucceeded(reqUser, clientIP)
	//nolint:gosec // G706: username/IP are logged with %q, which escapes CR/LF and so neutralises log-line injection from the client-supplied Authorization header
	log.Printf("login protocol=http user=%q root=%q from=%q", reqUser, jail.root, clientIP)
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
// server-side, never echoed to the client.
func (s *Server) httpStoreUpload(w http.ResponseWriter, r *http.Request, username string, jfs *jailFS) {
	byteLimit := s.httpUploadByteLimit()
	if r.ContentLength > byteLimit {
		stopHTTPUpload(w)
		writeHTTPStatus(w, http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, byteLimit)
	mr, err := r.MultipartReader()
	if err != nil {
		stopHTTPUpload(w)
		writeHTTPStatus(w, http.StatusBadRequest)
		return
	}
	results, bodyErr := s.storeUploadParts(mr, jfs, username, hostFromAddr(r.RemoteAddr))
	if bodyErr == nil {
		// Multipart EOF can precede HTTP EOF (the MIME epilogue). Count the
		// remaining bytes as well so chunked bodies cannot bypass the cap.
		_, bodyErr = io.Copy(io.Discard, r.Body)
	}
	if bodyErr != nil {
		stopHTTPUpload(w)
	}
	writeUploadResponse(w, results, bodyErr)
}

// Read defaults without mutating the server so a zero-value Server also works
// when multiple HTTP requests arrive concurrently.
func (s *Server) httpUploadByteLimit() int64 {
	if s.httpMaxUploadBytes <= 0 {
		return defaultHTTPMaxUploadBytes
	}
	return s.httpMaxUploadBytes
}

func (s *Server) httpUploadPartLimit() int {
	if s.httpMaxUploadParts <= 0 {
		return defaultHTTPMaxUploadParts
	}
	return s.httpMaxUploadParts
}

// stopHTTPUpload prevents connection reuse and bounds net/http's automatic
// request-body cleanup. In particular, multipart.Part.Close must not be used
// after a part limit: it drains the rejected part, which may never end.
func stopHTTPUpload(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
}

func isUploadLimitError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.Is(err, ErrStorageLimit) || errors.Is(err, errUploadPartLimit) || errors.As(err, &maxBytesErr)
}

func uploadLimitHTTPStatus(err error) int {
	if errors.Is(err, ErrStorageLimit) {
		return http.StatusInsufficientStorage
	}
	return http.StatusRequestEntityTooLarge
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
	limited   bool
}

// storeUploadParts walks the multipart body, storing each part named
// httpUploadFormField ("file") via storeUploadPart and skipping all others. It
// returns one uploadResult per accepted "file" part in request order. bodyErr
// describes a malformed stream or exceeded upload limit; any parts
// already stored before that point are still reported.
func (s *Server) storeUploadParts(mr *multipart.Reader, jfs *jailFS, username, clientIP string) (results []uploadResult, bodyErr error) {
	partLimit := s.httpUploadPartLimit()
	for count := 0; ; count++ {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return results, nil
		}
		if err != nil {
			return results, err
		}
		if count >= partLimit {
			return results, errUploadPartLimit
		}
		if p.FormName() == httpUploadFormField {
			result, storeErr := s.storeUploadPart(jfs, p, username, clientIP)
			results = append(results, result)
			if isUploadLimitError(storeErr) {
				return results, storeErr
			}
		}
		// Explicitly drain accepted/skipped parts so read errors, including the
		// byte limit, are observed. Part.Close discards those errors.
		if _, err := io.Copy(io.Discard, p); err != nil {
			return results, err
		}
	}
}

// storeUploadPart validates one "file" part's name, creates any missing parent
// directories, streams it into the jail, and announces the completed upload.
func (s *Server) storeUploadPart(jfs *jailFS, p *multipart.Part, username, clientIP string) (uploadResult, error) {
	raw := uploadPartFilename(p)
	clientPath, ok := sanitizeUploadPath(raw)
	if !ok {
		if len(raw) > httpUploadMaxPathBytes {
			raw = raw[:httpUploadMaxPathBytes] + "..."
		}
		return uploadResult{path: fmt.Sprintf("%q", raw)}, nil
	}
	log.Printf("upload protocol=http user=%q path=%q", username, clientPath)
	if err := jfs.MkdirAll(path.Dir(clientPath), httpUploadDirPerm); err != nil {
		log.Printf("upload failed protocol=http user=%q path=%q: create parent dirs: %q", username, clientPath, err.Error())
		limited := isUploadLimitError(err)
		return uploadResult{path: clientPath, serverErr: !limited, limited: limited}, err
	}
	if err := streamToJailFile(jfs, clientPath, p); err != nil {
		log.Printf("upload interrupted protocol=http user=%q path=%q: %q", username, clientPath, err.Error())
		limited := isUploadLimitError(err)
		return uploadResult{path: clientPath, serverErr: !limited, limited: limited}, err
	}
	s.announceHTTPUpload(username, clientIP, clientPath, jfs.fullPath(clientPath))
	return uploadResult{path: clientPath, stored: true}, nil
}

// writeUploadResponse writes the HTTP reply for a (possibly multi-file) upload.
// When at least one "file" part was seen, the body lists every file's outcome
// ("stored <path>" / "failed <path> (<reason>)") so the client can tell exactly
// what was and was not stored, even on a partial failure.
func writeUploadResponse(w http.ResponseWriter, results []uploadResult, bodyErr error) {
	if len(results) == 0 {
		status := http.StatusBadRequest // no "file" part in the body
		if isUploadLimitError(bodyErr) {
			status = uploadLimitHTTPStatus(bodyErr)
		}
		writeHTTPStatus(w, status)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(uploadResponseStatus(results, bodyErr))
	for _, res := range results {
		if res.stored {
			_, _ = fmt.Fprintf(w, "stored %s\n", res.path)
			continue
		}
		reason := "invalid name"
		if res.serverErr {
			reason = "server error"
		} else if res.limited {
			reason = "upload limit exceeded"
		}
		_, _ = fmt.Fprintf(w, "failed %s (%s)\n", res.path, reason)
	}
	if isUploadLimitError(bodyErr) {
		_, _ = fmt.Fprintln(w, "request upload limit exceeded")
	}
}

// uploadResponseStatus selects the status code for a batch of upload results:
// 413 for an HTTP limit, 507 for a storage budget, 201 when every file stored and the body was
// well-formed, 500 when any file failed server-side, and 400 otherwise.
func uploadResponseStatus(results []uploadResult, bodyErr error) int {
	if isUploadLimitError(bodyErr) {
		return uploadLimitHTTPStatus(bodyErr)
	}
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
	case failed == 0 && bodyErr == nil:
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
// itself (".", "..", "/"). ".." segments are collapsed by cleanRelClientPath
// and the jail's openat2 resolution is the actual containment guarantee; this
// check only turns obviously bad names into a clean 400 rather than a
// surprising filesystem error.
func sanitizeUploadPath(rawFilename string) (clientPath string, ok bool) {
	if rawFilename == "" || len(rawFilename) > httpUploadMaxPathBytes || hasCRLF(rawFilename) || strings.ContainsRune(rawFilename, 0) {
		return "", false
	}
	if strings.HasSuffix(rawFilename, "/") {
		return "", false // names a directory, not a file
	}
	rel := cleanRelClientPath(rawFilename)
	if rel == "." {
		return "", false // resolves to the jail root; no file name
	}
	return "/" + rel, true
}

// streamToJailFile copies src into a freshly truncated file at clientPath,
// overwriting any existing file (the same create/truncate semantics as an
// SFTP/FTP STOR). The destination is opened through the jail's openat2 path so
// symlink components and traversal are rejected by the kernel.
func streamToJailFile(jfs *jailFS, clientPath string, src io.Reader) error {
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
