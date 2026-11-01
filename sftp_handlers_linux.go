//go:build linux

package ironport

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sync"
	"syscall"

	"github.com/define42/ironport/internal/jailfs"
	"github.com/pkg/sftp"
)

// errSFTPRequestFailed is returned to SFTP clients for unknown backend errors
// so internal paths and server details are not exposed.
var errSFTPRequestFailed = errors.New("request failed")

// sanitizeSFTPErr maps backend filesystem errors to safe, path-free sentinel
// errors before they are returned to SFTP clients.
func sanitizeSFTPErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ENOTEMPTY):
		return syscall.ENOTEMPTY
	case errors.Is(err, syscall.EISDIR):
		return syscall.EISDIR
	case errors.Is(err, syscall.ENOTDIR):
		return syscall.ENOTDIR
	case errors.Is(err, syscall.EINVAL):
		return syscall.EINVAL
	case errors.Is(err, os.ErrNotExist):
		return os.ErrNotExist
	case errors.Is(err, os.ErrPermission):
		return os.ErrPermission
	case errors.Is(err, os.ErrExist):
		return os.ErrExist
	}
	return errSFTPRequestFailed
}

type jail struct {
	handles *sessionHandleBudget
	// fs is opened during authentication. The SSH connection shares it across
	// all SFTP channels and closes it after every channel finishes. FTP sessions
	// likewise own their authenticated filesystem until session teardown.
	fs       *jailfs.FS
	username string
	clientIP string
	canRead  bool
	canWrite bool
	uploads  chan<- CompletedUpload
	// tempExts is the list of "still being written" extensions (lower-case,
	// dot-prefixed). Uploads ending in one of these extensions are not
	// announced on uploads; renaming such a file to a name without any of
	// these extensions announces the final path on uploads instead.
	tempExts []string
	// sftpAllowChown controls whether pathname Setstat requests carrying a
	// uid/gid attribute are honoured. When false, chown requests are
	// rejected with a permission error so an authenticated user cannot
	// change ownership of jailed files even if the server process has
	// the privilege to do so (for example when running as root).
	sftpAllowChown bool
}

var _ sftp.OpenFileWriter = jail{}

// jail implements pkg/sftp's handler interfaces for a chrooted filesystem.
// Fileread implements sftp.FileReader.
func (j jail) Fileread(r *sftp.Request) (reader io.ReaderAt, err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, func() { reader = nil })()
	if !j.canRead {
		return nil, os.ErrPermission
	}
	release, err := j.handles.acquire()
	if err != nil {
		return nil, err
	}
	defer func() {
		if reader == nil {
			release()
		}
	}()
	f, err := j.fs.OpenRead(r.Filepath)
	if err != nil {
		return nil, sanitizeSFTPErr(err)
	}
	return &budgetReader{File: f, release: release}, nil
}

// writeLogger wraps an *os.File and logs the filename when the file is closed,
// signalling that the upload is complete. The sftp request server calls Close()
// on the returned io.WriterAt when it detects an io.Closer.
//
// If the uploaded filename ends with one of tempExts (e.g. ".tmp", ".writing"),
// the file is considered still in progress and no notification is sent on
// uploads; the completion notification will instead be emitted when the client
// renames the file to its final name (see jail.Filecmd "Rename").
//
// Write errors and transfer aborts are recorded through TransferError so Close
// does not announce a failed upload on CompletedUploads. pkg/sftp invokes
// TransferError when aborting a transfer, but WriteAt must record its own
// errors: a failed WRITE can be followed by a normal, successful CLOSE.
type writeLogger struct {
	*os.File

	filepath     string
	fullFilepath string
	username     string
	clientIP     string
	uploads      chan<- CompletedUpload
	tempExts     []string
	appendMode   bool
	// mu guards transferErr across writes, transfer-abort callbacks, and Close.
	mu sync.Mutex
	// transferErr retains the first write or transfer error. Later successful
	// writes cannot restore completion notification for this handle.
	transferErr error
}

func (w *writeLogger) WriteAt(p []byte, off int64) (n int, err error) {
	// Run after panic recovery so every returned write error marks the upload.
	defer func() { w.TransferError(err) }()
	defer deferRecoverSFTPPanicf(&err, func() { n = 0 }, "sftp write panic user=%q ip=%q path=%q: %v\n%s", w.username, w.clientIP, w.filepath)()
	if w.appendMode {
		// O_APPEND semantics (open(2)): on every write the kernel
		// atomically re-seeks the file offset to EOF before writing, so
		// the off parameter from the SFTP request is intentionally
		// dropped — honouring it would not change the destination of
		// the bytes and would only confuse the next reader.
		return w.Write(p)
	}
	return w.File.WriteAt(p, off)
}

// TransferError implements pkg/sftp's optional TransferError interface for
// aborted transfers. WriteAt also calls it for write failures. Recording the
// first error suppresses CompletedUpload notification when the handle closes.
func (w *writeLogger) TransferError(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	if w.transferErr == nil {
		w.transferErr = err
	}
	w.mu.Unlock()
}

func (w *writeLogger) Close() (err error) {
	defer deferRecoverSFTPPanicf(&err, nil, "sftp write close panic user=%q ip=%q path=%q: %v\n%s", w.username, w.clientIP, w.filepath)()
	err = w.File.Close()
	w.mu.Lock()
	transferErr := w.transferErr
	w.mu.Unlock()
	if transferErr != nil {
		log.Printf("upload interrupted: %q: %v; not announcing on CompletedUploads", w.filepath, transferErr)
		return err
	}
	if err == nil {
		log.Printf("upload complete: %q", w.filepath)
		if shouldDeferCompletion(w.filepath, w.tempExts) {
			// File is still considered "in progress"; defer notification
			// until the client renames it to its final (non-temp) name.
			log.Printf("upload complete: %q is a deferred name (temp extension or dotfile), deferring CompletedUploads notification", w.filepath)
			return nil
		}
		// Announce the completed upload on the queue; non-blocking so a slow
		// consumer never stalls the upload handler.
		publishUpload(w.uploads, CompletedUpload{
			Username:     w.username,
			FullFilePath: w.fullFilepath,
			FilePath:     w.filepath,
			ClientIP:     w.clientIP,
			Protocol:     CompletedUploadProtocolSFTP,
		})
	}
	return err
}

// Filewrite implements sftp.FileWriter.
func (j jail) Filewrite(r *sftp.Request) (writer io.WriterAt, err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, func() { writer = nil })()
	if !j.canWrite {
		return nil, os.ErrPermission
	}
	w, err := j.openWriter(r, os.O_WRONLY)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// readWriteHandle keeps pkg/sftp's combined read/write dispatch on one file
// descriptor and one handle permit. Write-only users still need a combined
// handle because pkg/sftp's Client.Create requests O_RDWR; their reads are
// rejected explicitly instead of reaching an O_RDWR descriptor.
type readWriteHandle struct {
	*budgetWriter

	canRead bool
}

func (h *readWriteHandle) ReadAt(p []byte, off int64) (int, error) {
	if !h.canRead {
		return 0, sftp.ErrSSHFxPermissionDenied
	}
	return h.writeLogger.File.ReadAt(p, off)
}

// OpenFile implements sftp.OpenFileWriter. pkg/sftp requires this optional
// interface to route reads and writes on an O_RDWR handle to the corresponding
// ReaderAt and WriterAt methods.
func (j jail) OpenFile(r *sftp.Request) (file sftp.WriterAtReaderAt, err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, func() { file = nil })()
	if !j.canWrite {
		return nil, os.ErrPermission
	}
	if !r.Pflags().Read {
		return nil, os.ErrInvalid
	}

	accessMode := os.O_WRONLY
	if j.canRead {
		accessMode = os.O_RDWR
	}
	w, err := j.openWriter(r, accessMode)
	if err != nil {
		return nil, err
	}
	return &readWriteHandle{budgetWriter: w, canRead: j.canRead}, nil
}

func (j jail) openWriter(r *sftp.Request, accessMode int) (writer *budgetWriter, err error) {
	if hasCRLF(r.Filepath) {
		return nil, syscall.EINVAL
	}
	clientPath := cleanSFTPClientPath(r.Filepath)
	log.Printf("upload: %q", clientPath)
	openFlags, appendMode, err := sftpWriteOpenFlags(r, accessMode)
	if err != nil {
		return nil, err
	}
	release, err := j.handles.acquire()
	if err != nil {
		return nil, err
	}
	var f *os.File
	defer func() {
		if writer == nil {
			if f != nil {
				_ = f.Close()
			}
			release()
		}
	}()
	f, err = j.fs.OpenWrite(r.Filepath, openFlags, 0o600)
	if err != nil {
		return nil, sanitizeSFTPErr(err)
	}
	return &budgetWriter{writeLogger: &writeLogger{
		File:         f,
		filepath:     clientPath,
		fullFilepath: j.fs.FullPath(r.Filepath),
		username:     j.username,
		clientIP:     j.clientIP,
		uploads:      j.uploads,
		tempExts:     j.tempExts,
		appendMode:   appendMode,
	}, release: release}, nil
}

func sftpWriteOpenFlags(r *sftp.Request, accessMode int) (int, bool, error) {
	pflags := r.Pflags()
	if !pflags.Write && !pflags.Append {
		return 0, false, os.ErrInvalid
	}
	if accessMode != os.O_WRONLY && accessMode != os.O_RDWR {
		return 0, false, os.ErrInvalid
	}

	openFlags := accessMode
	if pflags.Append {
		openFlags |= os.O_APPEND
	}
	if pflags.Creat {
		openFlags |= os.O_CREATE
	}
	if pflags.Trunc {
		openFlags |= os.O_TRUNC
	}
	if pflags.Excl {
		openFlags |= os.O_EXCL
	}
	return openFlags, pflags.Append, nil
}

// Filecmd implements sftp.FileCmder.
func (j jail) Filecmd(r *sftp.Request) (err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, nil)()
	if !j.canWrite {
		return os.ErrPermission
	}
	switch r.Method {
	case "Setstat":
		// pkg/sftp v1.13.12 dispatches FSETSTAT as a fresh Setstat request
		// containing only the handle's original pathname, without a context.
		// Pathname SETSTAT requests have a cancellable context. Fail closed
		// when that context is absent: reopening the saved path could mutate
		// a replacement after the opened file was renamed or removed. Keep
		// the protocol regression tests when updating pkg/sftp; safely
		// supporting FSETSTAT requires access to its retained file handle.
		if r.Context().Done() == nil {
			return sftp.ErrSSHFxOpUnsupported
		}
		return sanitizeSFTPErr(j.applyAttrs(r))
	case "Fsetstat":
		return sftp.ErrSSHFxOpUnsupported

	case "Rename":
		if hasCRLF(r.Target) {
			return syscall.EINVAL
		}
		if err := j.fs.Rename(r.Filepath, r.Target); err != nil {
			return sanitizeSFTPErr(err)
		}
		// If a file with a "still being written" extension is renamed to a
		// final (non-temp) name, treat the rename as the moment the upload
		// completes and announce the new SFTP path on uploads.
		oldClientPath := cleanSFTPClientPath(r.Filepath)
		newClientPath := cleanSFTPClientPath(r.Target)
		destInfo, _ := j.fs.Stat(r.Target)
		maybeAnnounceTempRename(j.uploads, j.tempExts, oldClientPath, destInfo, CompletedUpload{
			Username:     j.username,
			FullFilePath: j.fs.FullPath(r.Target),
			FilePath:     newClientPath,
			ClientIP:     j.clientIP,
			Protocol:     CompletedUploadProtocolSFTP,
		})
		return nil

	case "Rmdir":
		return sanitizeSFTPErr(j.fs.Rmdir(r.Filepath))

	case "Remove":
		return sanitizeSFTPErr(j.fs.Remove(r.Filepath))

	case "Mkdir":
		if hasCRLF(r.Filepath) {
			return syscall.EINVAL
		}
		return sanitizeSFTPErr(j.fs.Mkdir(r.Filepath, 0o750))

	case "Symlink":
		// Symlinks are disallowed in the jail: a client-created symlink could
		// point outside the jail root and be followed by a subsequent request,
		// bypassing the path-containment checks.
		return os.ErrPermission

	default:
		return fmt.Errorf("unsupported method: %s", r.Method)
	}
}

// Filelist implements sftp.FileLister.
func (j jail) Filelist(r *sftp.Request) (lister sftp.ListerAt, err error) {
	defer deferRecoverSFTPHandlerPanic(j.username, j.clientIP, r, &err, func() { lister = nil })()
	if !j.canRead {
		return nil, os.ErrPermission
	}
	switch r.Method {
	case "List":
		release, err := j.handles.acquire()
		if err != nil {
			return nil, err
		}
		defer func() {
			if lister == nil {
				release()
			}
		}()
		dir, err := j.fs.OpenDir(r.Filepath)
		if err != nil {
			return nil, sanitizeSFTPErr(err)
		}
		return &budgetLister{ListerAt: &directoryLister{dir: dir}, release: release}, nil
	case "Stat", "Lstat":
		// Under the no-symlink policy Stat and Lstat are equivalent: the
		// kernel rejects any symlink in the path lookup, so the entry being
		// described is never a symlink.
		st, err := j.fs.Stat(r.Filepath)
		if err != nil {
			return nil, sanitizeSFTPErr(err)
		}
		return listerFromFileInfo([]os.FileInfo{st}), nil
	default:
		return nil, fmt.Errorf("unsupported list method: %s", r.Method)
	}
}

// applyAttrs applies SFTP pathname Setstat attributes to the file referenced
// by r.Filepath, constrained to the operations that can run safely as the
// server process and consistent with the hardened "no symlinks anywhere"
// policy.
//
// Supported flags:
//   - Permissions       → fchmod via openat2-obtained fd
//   - UidGid            → fchownat (only when sftpAllowChown is true; otherwise
//     the request is rejected with os.ErrPermission so an authenticated user
//     cannot change ownership of jailed files even when the server process
//     has the privilege to do so)
//   - Size              → ftruncate via openat2-obtained fd
//   - Acmodtime         → utimensat via openat2-obtained fd
//
// Policy-level rejections (UidGid when sftpAllowChown is false) are evaluated
// before any mutating operation is performed, so a multi-flag request that
// violates policy fails atomically rather than leaving the file partially
// mutated. Remaining mutating operations are then applied in a deterministic
// order; the first error is returned and subsequent attributes are not applied,
// mirroring how OpenSSH's sftp-server reports errors.
func (j jail) applyAttrs(r *sftp.Request) error {
	flags := r.AttrFlags()
	attrs := r.Attributes()
	if attrs == nil {
		return nil
	}
	// Reject policy violations up front so they cannot leave the file
	// half-mutated when combined with Size/Permissions in a single request.
	if flags.UidGid && !j.sftpAllowChown {
		return os.ErrPermission
	}
	if flags.Size {
		// attrs.Size is a uint64 from the SFTP protocol but the underlying
		// fs API expects int64. Reject sizes that would overflow rather than
		// silently wrapping into a negative truncation length.
		if attrs.Size > math.MaxInt64 {
			return os.ErrInvalid
		}
		if err := j.fs.Truncate(r.Filepath, int64(attrs.Size)); err != nil {
			return err
		}
	}
	if flags.Permissions {
		if err := j.fs.Chmod(r.Filepath, attrs.FileMode().Perm()); err != nil {
			return err
		}
	}
	if flags.UidGid {
		if err := j.fs.Chown(r.Filepath, int(attrs.UID), int(attrs.GID)); err != nil {
			return err
		}
	}
	return j.applyTimes(r, flags, attrs)
}

func (j jail) applyTimes(r *sftp.Request, flags sftp.FileAttrFlags, attrs *sftp.FileStat) error {
	if flags.Acmodtime {
		if err := j.fs.Chtimes(r.Filepath, attrs.AccessTime(), attrs.ModTime()); err != nil {
			return err
		}
	}
	return nil
}

func jailedHandlers(fs *jailfs.FS, username, clientIP string, canRead, canWrite bool, uploads chan<- CompletedUpload, tempExts []string, sftpAllowChown bool, handles ...*sessionHandleBudget) sftp.Handlers {
	j := jail{
		fs:             fs,
		username:       username,
		clientIP:       clientIP,
		canRead:        canRead,
		canWrite:       canWrite,
		uploads:        uploads,
		tempExts:       tempExts,
		sftpAllowChown: sftpAllowChown,
	}
	if len(handles) > 0 {
		j.handles = handles[0]
	}
	return sftp.Handlers{
		FileGet:  j,
		FilePut:  j,
		FileCmd:  j,
		FileList: j,
	}
}

type fileInfoLister struct{ infos []os.FileInfo }

func (l fileInfoLister) ListAt(fis []os.FileInfo, offset int64) (n int, err error) {
	defer deferRecoverSFTPPanicf(&err, func() { n = 0 }, "sftp list panic offset=%d: %v\n%s", offset)()
	if offset < 0 {
		return 0, os.ErrInvalid
	}
	if offset >= int64(len(l.infos)) {
		return 0, io.EOF
	}
	n = copy(fis, l.infos[offset:])
	if n < len(fis) {
		return n, io.EOF
	}
	return n, nil
}

func listerFromFileInfo(infos []os.FileInfo) sftp.ListerAt {
	return fileInfoLister{infos: infos}
}
