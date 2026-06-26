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
	"strings"
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
//     AuthEvent.
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
func (s *Server) HttpIngest() http.HandlerFunc { //nolint:revive // exported name HttpIngest is the documented API (mirrors this package's Ftp/Sftp naming and the caller example)
	return s.handleHTTPIngest
}

func (s *Server) handleHTTPIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeHTTPStatus(w, http.StatusMethodNotAllowed)
		return
	}
	username, user, jailRoot, ok := s.httpAuthenticate(w, r)
	if !ok {
		return
	}
	if !user.CanWrite {
		writeHTTPStatus(w, http.StatusForbidden)
		return
	}
	s.httpStoreUpload(w, r, username, jailRoot)
}

// httpAuthenticate validates HTTP Basic credentials against the shared user
// database. On success it returns the username, the user's snapshot, and the
// canonical jail root. On failure it has already written the 401 response and
// returns ok=false. A bare request with no Authorization header is answered
// with a challenge but does not emit a LoginFailed event, so unauthenticated
// probes (and the first leg of a browser's challenge/response) do not flood the
// AuthEvents stream.
func (s *Server) httpAuthenticate(w http.ResponseWriter, r *http.Request) (username string, user UserInfo, jailRoot string, ok bool) {
	clientIP := hostFromAddr(r.RemoteAddr)
	reqUser, reqPass, hasAuth := r.BasicAuth()
	if !hasAuth {
		writeHTTPAuthChallenge(w)
		return "", UserInfo{}, "", false
	}
	u, root, authOK := s.authenticateUser(reqUser, func(stored UserInfo) bool {
		return checkPassword(stored.Password, reqPass)
	})
	if !authOK {
		//nolint:gosec // G706: username/IP are logged with %q, which escapes CR/LF and so neutralises log-line injection from the client-supplied Authorization header
		log.Printf("login failed protocol=http user=%q from=%q", reqUser, clientIP)
		s.announceHTTPAuthEvent(AuthEventLoginFailed, reqUser, clientIP)
		writeHTTPAuthChallenge(w)
		return "", UserInfo{}, "", false
	}
	//nolint:gosec // G706: username/IP are logged with %q, which escapes CR/LF and so neutralises log-line injection from the client-supplied Authorization header
	log.Printf("login protocol=http user=%q root=%q from=%q", reqUser, root, clientIP)
	s.announceHTTPAuthEvent(AuthEventLoginSuccess, reqUser, clientIP)
	return reqUser, u, root, true
}

// httpStoreUpload reads every multipart part named "file" and stores each into
// the user's jail. It is best-effort across files: each file is validated and
// written independently, gets its own CompletedUpload announcement, and one
// file's failure does not abort the others. The reply is 201 Created when at
// least one file was stored and none failed; otherwise it is an error status
// (400 for client errors / no "file" part, 500 when any file hit a server-side
// error) whose body lists every file's outcome. All filesystem detail is logged
// server-side, never echoed to the client.
func (s *Server) httpStoreUpload(w http.ResponseWriter, r *http.Request, username, jailRoot string) {
	mr, err := r.MultipartReader()
	if err != nil {
		writeHTTPStatus(w, http.StatusBadRequest)
		return
	}
	jfs, err := openJailFS(jailRoot)
	if err != nil {
		log.Printf("http open jail root %q for user %q: %v", jailRoot, username, err)
		writeHTTPStatus(w, http.StatusInternalServerError)
		return
	}
	defer func() { _ = jfs.Close() }()

	results, bodyOK := s.storeUploadParts(mr, jfs, username, hostFromAddr(r.RemoteAddr))
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
func (s *Server) storeUploadParts(mr *multipart.Reader, jfs *jailFS, username, clientIP string) (results []uploadResult, bodyOK bool) {
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
func (s *Server) storeUploadPart(jfs *jailFS, p *multipart.Part, username, clientIP string) uploadResult {
	raw := uploadPartFilename(p)
	clientPath, ok := sanitizeUploadPath(raw)
	if !ok {
		return uploadResult{path: fmt.Sprintf("%q", raw)}
	}
	log.Printf("upload protocol=http user=%q path=%q", username, clientPath)
	if err := jfs.MkdirAll(path.Dir(clientPath), httpUploadDirPerm); err != nil {
		log.Printf("upload failed protocol=http user=%q path=%q: create parent dirs: %v", username, clientPath, err)
		return uploadResult{path: clientPath, serverErr: true}
	}
	if err := streamToJailFile(jfs, clientPath, p); err != nil {
		log.Printf("upload interrupted protocol=http user=%q path=%q: %v", username, clientPath, err)
		return uploadResult{path: clientPath, serverErr: true}
	}
	s.announceHTTPUpload(username, clientIP, clientPath, jfs.fullPath(clientPath))
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
// itself (".", "..", "/"). ".." segments are collapsed by cleanRelClientPath
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
