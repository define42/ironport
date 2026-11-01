//go:build linux

package ironport

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/define42/ironport/internal/netconn"
	"golang.org/x/sys/unix"
)

// runTransfer executes work on dc while watching the control connection
// for ABOR. If ABOR arrives mid-transfer it closes dc (forcing work to
// return), drains the worker, and reports aborted=true; the caller is
// then responsible for the RFC 959 reply sequence (426 to the transfer
// command, 226 to the ABOR). Control commands other than ABOR received
// during a transfer are answered with 503 and the transfer continues.
// A control-reader error or close also aborts the transfer so the
// session can shut down cleanly; the main loop will observe the same
// signal on its next receive from ctlMsg.
func (f *ftpSession) runTransfer(dc net.Conn, work func() error) (aborted bool, transferErr error) {
	done := make(chan error, 1)
	go func() {
		done <- work()
	}()

	for {
		select {
		case transferErr = <-done:
			return false, transferErr
		case msg, ok := <-f.ctlMsg:
			if !ok || msg.err != nil {
				_ = dc.Close()
				transferErr = <-done
				return true, transferErr
			}
			cmd, _ := parseFTPCommand(strings.TrimRight(msg.line, "\r\n"))
			if cmd == "ABOR" {
				_ = dc.Close()
				transferErr = <-done
				return true, transferErr
			}
			_ = f.reply(503, "transfer in progress")
		}
	}
}

// replyAborted emits the RFC 959 two-message sequence for a transfer that
// was interrupted by ABOR: 426 closes out the transfer command, then 226
// acknowledges the ABOR itself. Centralising this keeps the wording (and
// the order) consistent across cmdStor/cmdRetr/cmdList/cmdMLSD.
func (f *ftpSession) replyAborted() {
	_ = f.reply(426, "transfer aborted")
	_ = f.reply(226, "abort successful")
}

func (f *ftpSession) cmdList(arg string, namesOnly bool) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(listPathArg(arg))
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer closeDataConn(dc)

	// Apply a per-Write idle deadline so a client that opens the data
	// connection but refuses to read does not pin this goroutine and FD
	// indefinitely once its TCP receive buffer fills.
	idleDC := &netconn.IdleConn{Conn: dc}
	idleDC.SetWriteTimeout(ftpDataIdleTimeout)
	aborted, copyErr := f.runTransfer(dc, func() error {
		formatLine := func(info os.FileInfo, name string) string {
			if namesOnly {
				return sanitizeFTPText(name)
			}
			return ftpListLine(info, name)
		}
		writeLine := func(line string) error {
			_, err := io.WriteString(idleDC, line+"\r\n")
			return err
		}
		if !st.IsDir() {
			return writeLine(formatLine(st, path.Base(ftpPath)))
		}
		// Stream directory entries straight to the data connection so a
		// directory with millions of entries does not have to be buffered
		// in memory before transmission begins.
		return f.fs.ListStream(ftpPath, func(info os.FileInfo) error {
			return writeLine(formatLine(info, info.Name()))
		})
	})
	if aborted {
		f.replyAborted()
		return
	}
	if copyErr != nil {
		_ = f.reply(426, ftpErrMsg(copyErr))
		return
	}
	_ = f.reply(226, "transfer complete")
}

func ftpListLine(info os.FileInfo, name string) string {
	mtime := info.ModTime()
	now := time.Now()
	timePart := mtime.Format("Jan _2 15:04")
	if mtime.Before(now.Add(-180*24*time.Hour)) || mtime.After(now.Add(24*time.Hour)) {
		timePart = mtime.Format("Jan _2  2006")
	}
	return fmt.Sprintf("%s 1 ftp ftp %12d %s %s", ftpModeString(info.Mode()), info.Size(), timePart, sanitizeFTPText(name))
}

func ftpModeString(mode os.FileMode) string {
	buf := []byte("----------")
	if mode.IsDir() {
		buf[0] = 'd'
	} else if mode&os.ModeSymlink != 0 {
		buf[0] = 'l'
	}
	bits := []struct {
		bit os.FileMode
		idx int
		chr byte
	}{
		{0o400, 1, 'r'},
		{0o200, 2, 'w'},
		{0o100, 3, 'x'},
		{0o040, 4, 'r'},
		{0o020, 5, 'w'},
		{0o010, 6, 'x'},
		{0o004, 7, 'r'},
		{0o002, 8, 'w'},
		{0o001, 9, 'x'},
	}
	for _, b := range bits {
		if mode&b.bit != 0 {
			buf[b.idx] = b.chr
		}
	}
	return string(buf)
}

// consumeTransferHints atomically captures and clears both the REST restart
// offset and the ALLO expected-size hint. Calling it at the top of cmdStor
// (and cmdRetr) ensures that every exit path — error or success — always
// leaves both fields zeroed, with no risk of a stale hint leaking into a
// subsequent transfer command.
func (f *ftpSession) consumeTransferHints() (restartOffset, expectedSize int64) {
	restartOffset, expectedSize = f.restartOffset, f.expectedUploadSize
	f.restartOffset = 0
	f.expectedUploadSize = 0
	return
}

func (f *ftpSession) cmdRetr(arg string) {
	restartOffset, _ := f.consumeTransferHints()
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	file, err := f.fs.OpenRead(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	defer func() { _ = file.Close() }()

	if restartOffset > 0 {
		if _, err := file.Seek(restartOffset, io.SeekStart); err != nil {
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
	}

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer closeDataConn(dc)

	// Apply a per-Write idle deadline so a client that opens the data
	// connection but refuses to read (filling its TCP receive buffer) does
	// not pin this goroutine and FD indefinitely.
	idleDC := &netconn.IdleConn{Conn: dc}
	idleDC.SetWriteTimeout(ftpDataIdleTimeout)
	aborted, copyErr := f.runTransfer(dc, func() error {
		_, err := io.Copy(idleDC, file)
		return err
	})
	if aborted {
		f.replyAborted()
		return
	}
	if copyErr != nil {
		_ = f.reply(426, ftpErrMsg(copyErr))
		return
	}
	_ = f.reply(226, "transfer complete")
}

func (f *ftpSession) cmdStor(arg string, appendMode bool) {
	restartOffset, expectedSize := f.consumeTransferHints()
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if hasCRLF(arg) {
		_ = f.reply(553, "invalid filename")
		return
	}
	ftpPath := f.cleanPath(arg)

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer closeDataConn(dc)

	// O_CREATE/O_TRUNC can change the destination before any bytes arrive.
	// Open only after the data peer and, for FTPS, the control-session TLS
	// binding are validated, so failed setup leaves the destination untouched.
	file, ok := f.openUploadFile(ftpPath, appendMode, restartOffset)
	if !ok {
		return
	}

	// When resuming a STOR via REST, ALLO carried the total file size but
	// only the bytes from restartOffset onward travel on this transfer;
	// adjust the expected count so a correct resumed upload is not rejected
	// as a size mismatch. APPE ignores restartOffset, so leave it alone.
	if !appendMode && restartOffset > 0 && expectedSize > restartOffset {
		expectedSize -= restartOffset
	}

	log.Printf("upload protocol=ftp path=%q", ftpPath)
	written, aborted, copyErr, closeErr := f.runUploadCopy(dc, file)
	if !f.finalizeUploadStatus(ftpPath, written, expectedSize, aborted, copyErr, closeErr) {
		return
	}
	f.announceUpload(ftpPath, f.fs.FullPath(ftpPath))
	_ = f.reply(226, "transfer complete")
}

// openUploadFile opens the destination file for STOR/APPE with the
// appropriate O_TRUNC/O_APPEND semantics and applies the restart offset (for
// REST + STOR). It sends the appropriate FTP reply on any error and returns
// ok=false when the caller should bail out.
func (f *ftpSession) openUploadFile(ftpPath string, appendMode bool, restartOffset int64) (*os.File, bool) {
	flags := os.O_CREATE | os.O_WRONLY
	switch {
	case appendMode:
		flags |= os.O_APPEND
	case restartOffset > 0:
		// Keep existing bytes and resume at requested offset.
	default:
		flags |= os.O_TRUNC
	}

	file, err := f.fs.OpenWrite(ftpPath, flags, 0o600)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return nil, false
	}
	if restartOffset > 0 && !appendMode {
		if !f.applyRestartOffset(file, restartOffset) {
			return nil, false
		}
	}
	return file, true
}

// runUploadCopy performs the STOR data-channel copy and returns the byte
// count, abort flag, copy error, and close error. It owns the idle-deadline
// wrapping of the data connection so cmdStor's main flow stays linear.
//
// FTP STREAM mode signals "end of file" by half-closing the data
// connection, so a client that uploads N bytes then half-closes is
// indistinguishable at the protocol level from a client that intended to
// upload exactly N bytes. The only reliable defense is an explicit size
// hint from the client (ALLO); finalizeUploadStatus enforces it.
func (f *ftpSession) runUploadCopy(dc net.Conn, file *os.File) (written int64, aborted bool, copyErr, closeErr error) {
	idleDC := &netconn.IdleConn{Conn: dc}
	idleDC.SetReadTimeout(ftpDataIdleTimeout)
	aborted, copyErr = f.runTransfer(dc, func() error {
		n, err := io.Copy(file, idleDC)
		written = n
		return err
	})
	closeErr = file.Close()
	return written, aborted, copyErr, closeErr
}

// finalizeUploadStatus inspects the outcome of an upload and, on failure,
// sends the appropriate FTP reply and returns false. It returns true only
// when the upload should be announced as a successful CompletedUpload.
func (f *ftpSession) finalizeUploadStatus(ftpPath string, written, expectedSize int64, aborted bool, copyErr, closeErr error) bool {
	switch {
	case aborted:
		log.Printf("upload aborted protocol=ftp path=%q bytes=%d", ftpPath, written)
		f.replyAborted()
	case copyErr != nil:
		log.Printf("upload interrupted protocol=ftp path=%q: %v", ftpPath, copyErr)
		_ = f.reply(426, ftpErrMsg(copyErr))
	case closeErr != nil:
		log.Printf("upload interrupted protocol=ftp path=%q close: %v", ftpPath, closeErr)
		_ = f.reply(451, ftpErrMsg(closeErr))
	case expectedSize > 0 && written != expectedSize:
		log.Printf("upload size mismatch protocol=ftp path=%q expected=%d got=%d", ftpPath, expectedSize, written)
		_ = f.reply(551, fmt.Sprintf("expected %d bytes, received %d", expectedSize, written))
	default:
		return true
	}
	return false
}

// applyRestartOffset positions an open upload file at restartOffset for
// resumed transfers. It rejects offsets beyond the current end-of-file
// (which would otherwise produce a sparse hole that reads back as NULs and
// silently corrupts the upload), closes the file and sends the appropriate
// FTP reply on any error, and returns true only when the file is ready for
// the data copy.
func (f *ftpSession) applyRestartOffset(file *os.File, restartOffset int64) bool {
	st, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		_ = f.reply(550, ftpErrMsg(statErr))
		return false
	}
	if restartOffset > st.Size() {
		offset, size := restartOffset, st.Size()
		_ = file.Close()
		_ = f.reply(554, fmt.Sprintf("restart offset %d exceeds file size %d", offset, size))
		return false
	}
	if _, err := file.Seek(restartOffset, io.SeekStart); err != nil {
		_ = file.Close()
		_ = f.reply(550, ftpErrMsg(err))
		return false
	}
	return true
}

// announceUpload publishes the CompletedUpload event for a successful STOR.
//
// Completeness guarantee: when the client preceded STOR with ALLO, cmdStor
// verifies the byte count matches before calling here, so the event is
// authoritative. Without an ALLO hint, FTP STREAM mode cannot distinguish
// "client sent every intended byte then half-closed" from "client truncated
// mid-transfer", so the event is best-effort — its absence is not proof of
// failure and its presence is not proof of byte-level integrity.
func (f *ftpSession) announceUpload(ftpPath, fullPath string) {
	log.Printf("upload complete: %q", ftpPath)
	if shouldDeferCompletion(ftpPath, f.tempExts) {
		log.Printf("upload complete: %q is a deferred name (temp extension or dotfile), deferring CompletedUploads notification", ftpPath)
		return
	}
	publishUpload(f.uploads, CompletedUpload{
		Username:     f.username,
		FullFilePath: fullPath,
		FilePath:     ftpPath,
		ClientIP:     f.clientIP,
		Protocol:     CompletedUploadProtocolFTP,
	})
}

// cmdMLST answers MLST (RFC 3659). MLST returns machine-readable facts for a
// single path inline on the control connection, never opening a data
// connection. The reply format is "211-Listing\r\n <facts> name\r\n211 End".
func (f *ftpSession) cmdMLST(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	// The MLST fact-line is required to start with a single space, per RFC
	// 3659 §4.8 ("Each fact-set is preceded by a single space"). multilineReply
	// already prefixes intermediate lines with a space, so the payload here is
	// just "facts; name" without leading whitespace.
	line := mlstFactLine(st, ftpPath, f.user.CanWrite)
	_ = f.multilineReply(250, "Listing "+ftpQuotePath(ftpPath), []string{line}, "End")
}

// cmdMLSD answers MLSD (RFC 3659). MLSD returns machine-readable facts for
// every entry in a directory over the data connection, terminating with
// 226 once the listing has been written.
func (f *ftpSession) cmdMLSD(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	if !st.IsDir() {
		_ = f.reply(501, "MLSD requires a directory")
		return
	}

	if err := f.reply(150, "opening data connection"); err != nil {
		return
	}
	dc, err := f.acceptDataConn()
	if err != nil {
		_ = f.reply(425, ftpErrMsg(err))
		return
	}
	defer closeDataConn(dc)

	idleDC := &netconn.IdleConn{Conn: dc}
	idleDC.SetWriteTimeout(ftpDataIdleTimeout)
	aborted, copyErr := f.runTransfer(dc, func() error {
		// Stream entries straight to the data connection rather than
		// materialising the whole listing in memory — see cmdList.
		return f.fs.ListStream(ftpPath, func(info os.FileInfo) error {
			line := mlstFactLine(info, info.Name(), f.user.CanWrite)
			_, err := io.WriteString(idleDC, line+"\r\n")
			return err
		})
	})
	if aborted {
		f.replyAborted()
		return
	}
	if copyErr != nil {
		_ = f.reply(426, ftpErrMsg(copyErr))
		return
	}
	_ = f.reply(226, "transfer complete")
}

// mlstFactLine renders a single MLST/MLSD entry: a fact-set followed by a
// space and the entry name. The facts emitted match the FEAT advertisement
// (type, size, modify, perm, unique). For MLST the caller passes the full
// path; for MLSD the basename.
func mlstFactLine(info os.FileInfo, name string, canWrite bool) string {
	var typeFact string
	switch {
	case info.IsDir():
		typeFact = "dir"
	case info.Mode()&os.ModeSymlink != 0:
		typeFact = "OS.unix=symlink"
	default:
		typeFact = "file"
	}
	var b strings.Builder
	b.WriteString("type=")
	b.WriteString(typeFact)
	b.WriteString(";size=")
	b.WriteString(strconv.FormatInt(info.Size(), 10))
	b.WriteString(";modify=")
	b.WriteString(info.ModTime().UTC().Format(ftpTimestampLayout))
	b.WriteString(";perm=")
	b.WriteString(mlstPermFact(info, canWrite))
	b.WriteString(";unique=")
	b.WriteString(mlstUniqueFact(info))
	b.WriteString("; ")
	b.WriteString(sanitizeFTPText(name))
	return b.String()
}

// mlstPermFact builds the RFC 3659 "perm" fact for an entry. The flags
// reported are bounded by what this server actually exposes: read implies
// list/retrieve, write implies store/append/delete/rename/mkdir. Symlinks
// are never traversable through the jail and so report no permissions.
func mlstPermFact(info os.FileInfo, canWrite bool) string {
	if info.Mode()&os.ModeSymlink != 0 {
		return ""
	}
	var b strings.Builder
	if info.IsDir() {
		b.WriteString("el") // enter / list
		if canWrite {
			b.WriteString("cmp") // create / make-dir / delete contents
		}
	} else {
		b.WriteString("r") // retrieve
		if canWrite {
			b.WriteString("adfw") // append / delete / rename-from / store
		}
	}
	return b.String()
}

// mlstUniqueFact returns a stable per-entry identifier for the "unique"
// fact. Per RFC 3659 the value need only be unique within the server; we
// derive it from dev+ino when available and fall back to mtime+size.
func mlstUniqueFact(info os.FileInfo) string {
	if st, ok := info.Sys().(*unix.Stat_t); ok && st != nil {
		return fmt.Sprintf("%XU%X", st.Dev, st.Ino)
	}
	return fmt.Sprintf("M%XS%X", info.ModTime().UnixNano(), info.Size())
}

// ftpPathBase returns the basename of an FTP path, treating "/" as the root.
func ftpPathBase(p string) string {
	if p == "/" || p == "" {
		return "/"
	}
	return path.Base(p)
}
