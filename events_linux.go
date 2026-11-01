//go:build linux

package ironport

import (
	"log"
	"os"
	"path"
	"strings"
	"time"
)

const (
	// CompletedUploadProtocolSFTP identifies an upload completed through SFTP.
	CompletedUploadProtocolSFTP = "SFTP"
	// CompletedUploadProtocolFTP identifies an upload completed through FTP.
	CompletedUploadProtocolFTP = "FTP"
)

// AuthEventType identifies the kind of authentication event delivered on the
// AuthEvents channel (login success, login failure, or logout).
type AuthEventType string

const (
	// AuthEventLoginSuccess identifies a successful user login.
	AuthEventLoginSuccess AuthEventType = "LoginSuccess"
	// AuthEventLoginFailed identifies a rejected user login attempt.
	AuthEventLoginFailed AuthEventType = "LoginFailed"
	// AuthEventLogout identifies the end of an authenticated session.
	AuthEventLogout AuthEventType = "Logout"
)

// AuthFailureReason identifies why a login attempt was rejected. It is empty
// for successful login and logout events.
type AuthFailureReason string

const (
	// AuthFailureCredentials identifies a login rejected during credential validation.
	AuthFailureCredentials AuthFailureReason = "Credentials"
	// AuthFailureThrottled identifies a login rejected by authentication limits.
	AuthFailureThrottled AuthFailureReason = "Throttled"
)

// publishUpload sends evt to uploads without blocking the caller. When the
// channel buffer is full the event is dropped and a single line is logged so
// operators can spot a slow consumer.
func publishUpload(uploads chan<- CompletedUpload, evt CompletedUpload) {
	if uploads == nil {
		return
	}
	select {
	case uploads <- evt:
	default:
		log.Printf("upload complete: CompletedUploads queue full, notification for %q dropped", evt.FilePath)
	}
}

// maybeAnnounceTempRename publishes a CompletedUpload event when a file is
// renamed from a deferred (temp-suffixed or dotfile) name to a final name that
// is neither (matching is case-insensitive and the extension list comes from
// Config.TempExtensions). The rename is only treated as a completed upload when
// the destination is a regular file: jailfs.FS.Rename also permits directory
// renames (for example /.staging -> /staging), and announcing those as uploads
// would deliver a false CompletedUpload event for a directory. destInfo is the
// stat of the destination after the rename (nil if it could not be stat'd). It
// is a no-op in every other case, so both protocols share the same "rename
// completes an upload" decision and log line.
func maybeAnnounceTempRename(uploads chan<- CompletedUpload, tempExts []string, oldPath string, destInfo os.FileInfo, evt CompletedUpload) {
	if !shouldDeferCompletion(oldPath, tempExts) || shouldDeferCompletion(evt.FilePath, tempExts) {
		return
	}
	if destInfo == nil || !destInfo.Mode().IsRegular() {
		return
	}
	log.Printf("upload complete via rename: %q -> %q", oldPath, evt.FilePath)
	publishUpload(uploads, evt)
}

// CompletedUpload describes a file upload that has finished successfully.
// It is the payload delivered on the server's CompletedUploads stream.
type CompletedUpload struct {
	// Username is the authenticated SFTP, FTP, or HTTP user that performed the upload.
	Username string
	// FullFilePath is the absolute path of the uploaded file on the server's
	// local filesystem (i.e. resolved through the user's jail root).
	FullFilePath string
	// FilePath is the file path as seen by the client, relative to the
	// user's jail root (e.g. "/incoming/foo.txt").
	FilePath string
	// ClientIP is the remote IP address of the client that performed
	// the upload, without the port. It is empty if the address could not
	// be parsed.
	ClientIP string
	// Protocol is the file-transfer protocol used for the upload.
	// It is CompletedUploadProtocolSFTP, CompletedUploadProtocolFTP, or CompletedUploadProtocolHTTP.
	Protocol string
}

// AuthEvent describes an authentication or session-lifecycle event.
// It is the payload delivered on the server's AuthEvents stream.
type AuthEvent struct {
	// Type is the authentication event kind.
	Type AuthEventType
	// Reason distinguishes credential rejection from authentication throttling
	// for AuthEventLoginFailed. It is empty for successful login and logout.
	Reason AuthFailureReason
	// Username is the username supplied by the client for this event.
	Username string
	// ClientIP is the remote IP address of the client, without the port. It is
	// empty if the address could not be parsed.
	ClientIP string
	// Protocol is the file-transfer protocol used for the event.
	// It is CompletedUploadProtocolSFTP, CompletedUploadProtocolFTP, or CompletedUploadProtocolHTTP.
	Protocol string
}

func newCompletedUploadsChannel(size int) chan CompletedUpload {
	if size <= 0 {
		size = defaultCompletedUploadsSize
	}
	return make(chan CompletedUpload, size)
}

func newAuthEventsChannel(size int) chan AuthEvent {
	if size <= 0 {
		size = defaultAuthEventsSize
	}
	return make(chan AuthEvent, size)
}

func (s *Server) completedUploadsChan() chan CompletedUpload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.completedUploads
}

func (s *Server) authEventsChan() chan AuthEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authEvents
}

// CompletedUploads returns a receive-only stream of successful upload
// notifications. Each CompletedUpload includes the protocol that produced it.
// The channel is buffered; sends are non-blocking so a slow consumer never
// stalls an upload. Callers should drain the stream continuously.
//
// The buffer capacity is set by Config.CompletedUploadSize. A
// non-positive value falls back to the package default (64).
func (s *Server) CompletedUploads() <-chan CompletedUpload {
	return s.completedUploadsChan()
}

// AuthEvents returns a receive-only stream of authentication/session
// notifications. Each AuthEvent includes the protocol that produced it.
// The channel is buffered; sends are non-blocking so a slow consumer never
// stalls authentication or logout handling. Callers should drain the stream
// continuously. A full channel drops events. Throttled login failures are
// sampled even when the channel has capacity, so this stream is not a complete
// audit trail or an exact count of rejected attempts. Credential failures,
// successful logins, and logouts are not sampled.
//
// The buffer capacity is set by Config.AuthEventSize. A non-positive
// value falls back to the package default (64).
func (s *Server) AuthEvents() <-chan AuthEvent {
	return s.authEventsChan()
}

func announceAuthEvent(events chan<- AuthEvent, evt AuthEvent) {
	if events == nil {
		return
	}
	select {
	case events <- evt:
	default:
		if sample, suppressed := authEventDropLogs.allow(time.Now()); sample {
			log.Printf("auth event: AuthEvents queue full, notification type=%q protocol=%q user=%q dropped (suppressed=%d)", evt.Type, evt.Protocol, evt.Username, suppressed)
		}
	}
}

// hasTempExt reports whether name ends with one of the given (already
// normalised, lower-case, dot-prefixed) extensions. Matching is
// case-insensitive on the filename.
func hasTempExt(name string, tempExts []string) bool {
	if len(tempExts) == 0 {
		return false
	}
	lower := strings.ToLower(name)
	for _, ext := range tempExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// hasDotPrefix reports whether the final path element of name begins with a
// dot (a "dotfile"). Such names are treated as still-in-progress uploads, the
// same way temp extensions are, so their completion notification is deferred
// until the client renames them to a final, non-dot name.
func hasDotPrefix(name string) bool {
	if name == "" {
		return false
	}
	return strings.HasPrefix(path.Base(name), ".")
}

// shouldDeferCompletion reports whether an upload to name should have its
// CompletedUploads notification deferred until a later rename. This holds for
// names ending in a configured temp extension and for dotfiles (names whose
// final path element begins with "."). Temp-extension matching is
// case-insensitive.
func shouldDeferCompletion(name string, tempExts []string) bool {
	return hasDotPrefix(name) || hasTempExt(name, tempExts)
}
