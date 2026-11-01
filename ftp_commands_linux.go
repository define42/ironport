//go:build linux

package ironport

import (
	"fmt"
	"log"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
)

// hasCRLF reports whether s contains a CR or LF byte. Used to reject
// client-supplied filenames that, if accepted, would let a later listing or
// path-echoing reply inject fake FTP control-channel lines.
func hasCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// sanitizeFTPText returns s with every ASCII control byte (0x00–0x1F, 0x7F)
// replaced by '?'. Defense in depth for filenames that reach the FTP control
// channel (257 replies) or the LIST/NLST data channel: even if a control byte
// slips past the write-time guards (e.g. file created out-of-band), it cannot
// forge reply lines or corrupt line-oriented listing output.
func sanitizeFTPText(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7F {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c == 0x7F {
			b[i] = '?'
		}
	}
	return string(b)
}

func (f *ftpSession) handleFTPCommand(cmd, arg string) bool {
	f.dataMu.Lock()
	cancelled := f.cancelled
	f.dataMu.Unlock()
	if cancelled {
		return true
	}
	handled, quit := f.handlePreAuthCommand(cmd, arg)
	if handled {
		return quit
	}
	if !f.authenticated {
		_ = f.reply(530, "not logged in")
		return false
	}
	f.handleAuthenticatedCommand(cmd, arg)
	return false
}

// handlePreAuthCommand handles the commands that are accepted before
// authentication (or that have AUTH-TLS-specific gating). Returns
// handled=true when the command matched a pre-auth case, and quit=true when
// the session should terminate (only QUIT does this).
func (f *ftpSession) handlePreAuthCommand(cmd, arg string) (handled, quit bool) {
	if cmd == "QUIT" {
		_ = f.reply(221, "goodbye")
		return true, true
	}
	if handler, ok := preAuthFTPHandlers[cmd]; ok {
		handler(f, arg)
		return true, f.authTerminated
	}
	return false, false
}

// preAuthFTPHandlers maps each FTP verb that is accepted before
// authentication to a handler. QUIT is handled inline because it is the only
// pre-auth command that terminates the session.
//
//nolint:gochecknoglobals // immutable dispatch table populated at init
var preAuthFTPHandlers = map[string]func(*ftpSession, string){
	"USER": func(f *ftpSession, arg string) { f.cmdUser(arg) },
	"PASS": func(f *ftpSession, arg string) { f.cmdPass(arg) },
	"NOOP": func(f *ftpSession, _ string) { _ = f.reply(200, "ok") },
	"SYST": func(f *ftpSession, _ string) { _ = f.reply(215, "UNIX Type: L8") },
	"FEAT": func(f *ftpSession, _ string) { f.cmdFeat() },
	"HELP": func(f *ftpSession, arg string) { f.cmdHelp(arg) },
	// STAT with no argument is server status and is commonly issued before
	// login; cmdStat performs its own auth check for the path form.
	"STAT": func(f *ftpSession, arg string) { f.cmdStat(arg) },
	"LANG": func(f *ftpSession, arg string) { f.cmdLang(arg) },
	"HOST": func(f *ftpSession, arg string) { f.cmdHost(arg) },
	"REIN": func(f *ftpSession, _ string) { f.cmdRein() },
	"AUTH": func(f *ftpSession, arg string) { f.cmdAuth(arg) },
	"PBSZ": func(f *ftpSession, _ string) { f.cmdPbsz() },
	"PROT": func(f *ftpSession, arg string) { f.cmdProt(arg) },
	// RFC 4217 §12.3: refuse downgrade from TLS back to plaintext.
	"CCC": func(f *ftpSession, _ string) { _ = f.reply(534, "CCC refused") },
}

func (f *ftpSession) cmdUser(arg string) {
	if f.server.ftpRequireTLS && f.tlsConn == nil {
		_ = f.reply(534, "AUTH TLS required before login")
		return
	}
	f.closeDataEndpoint()
	f.logoutIfAuthenticated()
	// The previous user (if any) is now logged out; drop the connection's
	// user association so a RemoveUser for that name no longer evicts a
	// session that is mid-login as someone else. A successful PASS will
	// re-establish the association for the new user.
	f.server.setConnUser(f.rawConn, "")
	f.username = arg
	f.authenticated = false
	f.user = UserInfo{}
	_ = f.reply(331, "password required")
}

func (f *ftpSession) cmdPass(arg string) {
	if f.authenticated {
		_ = f.reply(503, "already logged in; send USER or REIN first")
		return
	}
	if f.server.ftpRequireTLS && f.tlsConn == nil {
		_ = f.reply(534, "AUTH TLS required before login")
		return
	}
	if f.username == "" {
		_ = f.reply(503, "send USER first")
		return
	}
	if f.server.allowAuth(f.username, f.clientIP) > 0 {
		f.server.authFailed(f.username, f.clientIP, CompletedUploadProtocolFTP, f.authEvents, true)
		f.authTerminated = true
		_ = f.reply(421, "authentication temporarily unavailable, closing control connection")
		return
	}
	if !f.authenticate(arg) {
		f.authFailures++
		f.server.authFailed(f.username, f.clientIP, CompletedUploadProtocolFTP, f.authEvents, false)
		if f.authFailures >= positiveLimit(f.server.ftpMaxAuthFailures, 5) {
			f.authTerminated = true
			_ = f.reply(421, "too many authentication failures, closing control connection")
			return
		}
		_ = f.reply(530, errInvalidCredentials.Error())
		return
	}
	f.server.authSucceeded(f.username, f.clientIP)
	log.Printf("login protocol=ftp user=%s root=%s from=%s", f.username, f.user.Root, f.conn.RemoteAddr())
	f.announceAuthEvent(AuthEventLoginSuccess)
	_ = f.reply(230, "login successful")
}

func (f *ftpSession) handleAuthenticatedCommand(cmd, arg string) {
	if ftpCommandUsesDataConn(cmd) && f.server.ftpRequireTLS && f.dataProt != 'P' {
		// REST and ALLO are one-shot hints. A policy-rejected transfer still
		// consumes them so they cannot alter a later protected transfer.
		switch cmd {
		case "RETR", "STOR", "APPE":
			f.consumeTransferHints()
		}
		f.closeDataEndpoint()
		_ = f.reply(534, errFTPDataProtectionRequired.Error())
		return
	}
	if handler, ok := authedFTPHandlers[cmd]; ok {
		handler(f, arg)
		return
	}
	// MFCT and SITE need to see the original cmd verb in their reply
	// (or have a fixed reply), and the rest fall through to the generic
	// "not implemented" path.
	switch cmd {
	case "MFCT":
		_ = f.reply(502, cmd+" not supported")
	default:
		_ = f.reply(502, "command not implemented")
	}
}

// ftpCommandUsesDataConn reports whether cmd transfers its payload over a
// separate FTP data connection rather than the protected control connection.
func ftpCommandUsesDataConn(cmd string) bool {
	switch cmd {
	case "LIST", "NLST", "RETR", "STOR", "APPE", "MLSD":
		return true
	}
	return false
}

// authedFTPHandlers maps each authenticated-only FTP verb to a handler. Keeping
// the dispatch table out of handleAuthenticatedCommand keeps the function's
// cyclomatic complexity at the level of the table lookup rather than the
// number of supported commands.
//
//nolint:gochecknoglobals // immutable dispatch table populated at init
var authedFTPHandlers = map[string]func(*ftpSession, string){
	"PWD": func(f *ftpSession, _ string) {
		_ = f.reply(257, fmt.Sprintf("%s is the current directory", ftpQuotePath(f.cwd)))
	},
	"XPWD": func(f *ftpSession, _ string) {
		_ = f.reply(257, fmt.Sprintf("%s is the current directory", ftpQuotePath(f.cwd)))
	},
	"CWD":  func(f *ftpSession, arg string) { f.cmdCWD(arg) },
	"CDUP": func(f *ftpSession, _ string) { f.cmdCWD("..") },
	"TYPE": func(f *ftpSession, arg string) { f.cmdType(arg) },
	"MODE": func(f *ftpSession, arg string) { f.cmdMode(arg) },
	"STRU": func(f *ftpSession, arg string) { f.cmdStru(arg) },
	"OPTS": func(f *ftpSession, arg string) { f.cmdOpts(arg) },
	"PASV": func(f *ftpSession, _ string) { f.enterPassive(false) },
	"EPSV": func(f *ftpSession, arg string) { f.cmdEpsv(arg) },
	"PORT": func(f *ftpSession, arg string) { f.enterActivePORT(arg) },
	"EPRT": func(f *ftpSession, arg string) { f.enterActiveEPRT(arg) },
	"LIST": func(f *ftpSession, arg string) { f.cmdList(arg, false) },
	"NLST": func(f *ftpSession, arg string) { f.cmdList(arg, true) },
	"RETR": func(f *ftpSession, arg string) { f.cmdRetr(arg) },
	"STOR": func(f *ftpSession, arg string) { f.cmdStor(arg, false) },
	"APPE": func(f *ftpSession, arg string) { f.cmdStor(arg, true) },
	"ALLO": func(f *ftpSession, arg string) { f.cmdAllo(arg) },
	"REST": func(f *ftpSession, arg string) { f.cmdRest(arg) },
	"SIZE": func(f *ftpSession, arg string) { f.cmdSize(arg) },
	"MDTM": func(f *ftpSession, arg string) { f.cmdMDTM(arg) },
	"MFMT": func(f *ftpSession, arg string) { f.cmdMFMT(arg) },
	"DELE": func(f *ftpSession, arg string) { f.cmdDelete(arg) },
	"MKD":  func(f *ftpSession, arg string) { f.cmdMkdir(arg) },
	"XMKD": func(f *ftpSession, arg string) { f.cmdMkdir(arg) },
	"RMD":  func(f *ftpSession, arg string) { f.cmdRmdir(arg) },
	"XRMD": func(f *ftpSession, arg string) { f.cmdRmdir(arg) },
	"RNFR": func(f *ftpSession, arg string) { f.cmdRnfr(arg) },
	"RNTO": func(f *ftpSession, arg string) { f.cmdRnto(arg) },
	"ABOR": func(f *ftpSession, _ string) {
		f.closeDataListener()
		f.restartOffset = 0
		f.expectedUploadSize = 0
		_ = f.reply(226, "abort successful")
	},
	"MLST": func(f *ftpSession, arg string) { f.cmdMLST(arg) },
	"MLSD": func(f *ftpSession, arg string) { f.cmdMLSD(arg) },
	"SITE": func(f *ftpSession, _ string) {
		// SITE has no portable subcommands here; reply cleanly rather than
		// the generic 502 so clients can probe without ambiguity.
		_ = f.reply(502, "SITE command not implemented")
	},
}

func (f *ftpSession) cmdType(arg string) {
	// Transfers are binary-safe. Accept ASCII and binary mode for client
	// compatibility, but do not transform bytes.
	upper := strings.ToUpper(strings.TrimSpace(arg))
	if upper == "A" || upper == "A N" || upper == "I" || upper == "L 8" {
		_ = f.reply(200, "type set")
		return
	}
	_ = f.reply(504, "unsupported type")
}

func (f *ftpSession) cmdMode(arg string) {
	if strings.EqualFold(strings.TrimSpace(arg), "S") {
		_ = f.reply(200, "mode set")
		return
	}
	_ = f.reply(504, "unsupported mode")
}

func (f *ftpSession) cmdStru(arg string) {
	if strings.EqualFold(strings.TrimSpace(arg), "F") {
		_ = f.reply(200, "structure set")
		return
	}
	_ = f.reply(504, "unsupported structure")
}

func (f *ftpSession) cmdOpts(arg string) {
	if strings.EqualFold(strings.TrimSpace(arg), "UTF8 ON") {
		_ = f.reply(200, "UTF8 enabled")
		return
	}
	_ = f.reply(501, "unsupported option")
}

func (f *ftpSession) cmdFeat() {
	features := []string{
		"UTF8",
		"EPSV",
		"PASV",
		"SIZE",
		"MDTM",
		"MFMT",
		"REST STREAM",
		"MLST type*;size*;modify*;perm*;unique*;",
		"MLSD",
		"TVFS",
		"LANG en-US*",
		"HOST",
	}
	if f.server.ftpAllowActiveMode {
		features = append(features, "EPRT")
	}
	if f.server.ftpTLSConfig != nil {
		features = append(features, "AUTH TLS", "PBSZ", "PROT")
	}
	_ = f.multilineReply(211, "Features:", features, "End")
}

func (f *ftpSession) cleanPath(p string) string {
	p = strings.TrimSpace(unquoteFTPPath(p))
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" {
		return f.cwd
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(f.cwd, p)
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	if p == "." {
		return "/"
	}
	return p
}

func unquoteFTPPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 && p[0] == '"' && p[len(p)-1] == '"' {
		p = p[1 : len(p)-1]
		p = strings.ReplaceAll(p, "\"\"", "\"")
	}
	return p
}

func ftpQuotePath(p string) string {
	p = sanitizeFTPText(p)
	return "\"" + strings.ReplaceAll(p, "\"", "\"\"") + "\""
}

// listPathArg extracts the pathname argument from a LIST/NLST/STAT line,
// discarding any leading ls-style flags. Only the first non-flag token is
// honoured: anything after it is dropped on the floor rather than being
// silently concatenated. FTP has no quoting convention for the LIST
// argument, so an unquoted multi-word path is ambiguous with a series of
// stray arguments — RFC 959 specifies a single optional pathname, so the
// strict interpretation is the safer one.
func listPathArg(arg string) string {
	for field := range strings.FieldsSeq(arg) {
		if strings.HasPrefix(field, "-") {
			continue
		}
		return field
	}
	return ""
}

func (f *ftpSession) cmdCWD(arg string) {
	if !f.user.CanRead && !f.user.CanWrite {
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
		_ = f.reply(550, "not a directory")
		return
	}
	f.cwd = ftpPath
	_ = f.reply(250, "directory changed")
}

// cmdHelp answers the HELP command. With no argument it returns a multi-line
// reply listing supported commands; with an argument it returns a short
// per-command line. The list deliberately covers only commands this server
// implements — clients that probe for an unlisted command will still get a
// 502 from the command dispatcher itself.
func (f *ftpSession) cmdHelp(arg string) {
	arg = strings.TrimSpace(arg)
	if arg != "" {
		upper := strings.ToUpper(arg)
		if (upper == "PORT" || upper == "EPRT") && !f.server.ftpAllowActiveMode {
			_ = f.reply(502, "active mode is disabled; use PASV or EPSV")
			return
		}
		_ = f.reply(214, fmt.Sprintf("%s command recognized", upper))
		return
	}
	lines := []string{
		"USER PASS QUIT NOOP SYST FEAT HELP STAT",
		"PWD CWD CDUP TYPE MODE STRU OPTS REIN",
		"PASV EPSV LIST NLST MLST MLSD",
		"RETR STOR APPE ALLO REST SIZE MDTM MFMT",
		"DELE MKD RMD RNFR RNTO ABOR",
		"LANG HOST",
	}
	if f.server.ftpAllowActiveMode {
		lines = append(lines, "PORT EPRT")
	}
	_ = f.multilineReply(214, "The following commands are recognized:", lines, "End")
}

// cmdLang answers the LANG command (RFC 2640). The server's only output
// language is English; UTF-8 byte semantics are already announced via OPTS
// UTF8. We accept "en", "en-US", or an empty argument as success and reject
// everything else with 504, mirroring how OpenSSH and other minimal servers
// handle language negotiation.
func (f *ftpSession) cmdLang(arg string) {
	tag := strings.TrimSpace(arg)
	if tag == "" {
		_ = f.reply(200, "language set to en-US")
		return
	}
	upper := strings.ToUpper(tag)
	if upper == "EN" || upper == "EN-US" {
		_ = f.reply(200, "language set to en-US")
		return
	}
	_ = f.reply(504, "language not supported")
}

// cmdHost answers the HOST command (RFC 7151). This server does not implement
// per-virtual-host user databases — every listener serves the single user set
// configured on the server. Accept any well-formed host name so HOST-aware
// clients can advance past the handshake; reject only the few cases where the
// argument is clearly malformed.
func (f *ftpSession) cmdHost(arg string) {
	if f.authenticated {
		// RFC 7151 §3.1: HOST must be sent before authentication. Once a user
		// is logged in, refuse to switch virtual hosts.
		_ = f.reply(503, "HOST cannot be issued after login")
		return
	}
	host := strings.TrimSpace(arg)
	if host == "" || hasCRLF(host) || len(host) > 255 {
		_ = f.reply(501, "invalid host name")
		return
	}
	_ = f.reply(220, "host accepted")
}

// cmdRein answers the REIN command. RFC 959 specifies that REIN flushes any
// authentication state and returns the session to the pre-login state without
// closing the control connection. Any pending data transfer is aborted.
//
// This implementation currently keeps the TLS control transport live across
// REIN, while resetting the data-channel protection level to Clear. PBSZ must
// be re-issued before a subsequent PROT.
func (f *ftpSession) cmdRein() {
	f.closeDataEndpoint()
	f.logoutIfAuthenticated()
	f.username = ""
	f.cwd = "/"
	f.rnfrPath = ""
	f.restartOffset = 0
	f.expectedUploadSize = 0
	f.epsvAll = false
	f.pbszSet = false
	f.dataProt = 'C'
	// The session is no longer tied to the previous user; clear the
	// connection's user association so a RemoveUser for that name does not
	// kick this now-anonymous session.
	f.server.setConnUser(f.rawConn, "")
	_ = f.reply(220, "ready for new user")
}

// cmdStat answers the STAT command. With no argument it reports server
// status; with a path argument it returns a directory/file listing inline
// over the control connection (no data connection), which clients often
// issue immediately after login as a low-overhead probe.
func (f *ftpSession) cmdStat(arg string) {
	// Use rawPath rather than path here: a local named "path" would shadow
	// the imported "path" package, so any future edit that calls path.Base
	// or path.Clean inside this function would silently become a method
	// call on a string.
	rawPath := strings.TrimSpace(arg)
	if rawPath == "" {
		lines := []string{
			fmt.Sprintf("Connected from %s", sanitizeFTPText(f.clientIP)),
			fmt.Sprintf("Logged in as %s", sanitizeFTPText(f.username)),
			"TYPE: BINARY",
			"No data connection",
		}
		_ = f.multilineReply(211, "Server status:", lines, "End of status")
		return
	}
	if !f.authenticated {
		_ = f.reply(530, "not logged in")
		return
	}
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(listPathArg(rawPath))
	st, err := f.fs.Stat(ftpPath)
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	var lines []string
	if st.IsDir() {
		entries, err := f.fs.List(ftpPath)
		if err != nil {
			_ = f.reply(550, ftpErrMsg(err))
			return
		}
		for _, info := range entries {
			lines = append(lines, ftpListLine(info, info.Name()))
		}
	} else {
		lines = append(lines, ftpListLine(st, ftpPathBase(ftpPath)))
	}
	_ = f.multilineReply(213, "Status of "+ftpQuotePath(ftpPath)+":", lines, "End of status")
}

// cmdAllo answers the ALLO command (RFC 959 §4.1.3). The size argument is
// recorded so the next STOR/APPE can verify the uploaded byte count matches
// — STREAM mode signals end-of-file by half-close, which is otherwise
// indistinguishable from a client that deliberately truncates the upload.
// The "R record-size" form is accepted for compatibility (STRU F is the
// only structure supported, so record size is meaningless here).
func (f *ftpSession) cmdAllo(arg string) {
	fields := strings.Fields(arg)
	if len(fields) == 0 {
		_ = f.reply(501, "missing size")
		return
	}
	size, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || size < 0 {
		_ = f.reply(501, "invalid size")
		return
	}
	f.expectedUploadSize = size
	_ = f.reply(200, "allocation noted")
}

func (f *ftpSession) cmdRest(arg string) {
	offset, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
	if err != nil || offset < 0 {
		f.restartOffset = 0
		_ = f.reply(501, "invalid restart offset")
		return
	}
	f.restartOffset = offset
	_ = f.reply(350, "restart position accepted")
}

func (f *ftpSession) cmdSize(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	st, err := f.fs.Stat(f.cleanPath(arg))
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	if st.IsDir() {
		_ = f.reply(550, "not a regular file")
		return
	}
	_ = f.reply(213, strconv.FormatInt(st.Size(), 10))
}

func (f *ftpSession) cmdMDTM(arg string) {
	if !f.user.CanRead {
		_ = f.reply(550, "permission denied")
		return
	}
	st, err := f.fs.Stat(f.cleanPath(arg))
	if err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(213, st.ModTime().UTC().Format(ftpTimestampLayout))
}

func (f *ftpSession) cmdMFMT(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	mtime, rawPath, ok := parseMFMTArg(arg)
	if !ok {
		_ = f.reply(501, "syntax: MFMT YYYYMMDDHHMMSS path")
		return
	}
	if err := f.fs.SetModTime(f.cleanPath(rawPath), mtime); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(213, mtime.UTC().Format(ftpTimestampLayout))
}

func parseMFMTArg(arg string) (time.Time, string, bool) {
	arg = strings.TrimSpace(arg)
	stamp, rawPath, ok := strings.Cut(arg, " ")
	rawPath = strings.TrimSpace(rawPath)
	if !ok || len(stamp) != len(ftpTimestampLayout) || rawPath == "" {
		return time.Time{}, "", false
	}
	mtime, err := time.Parse(ftpTimestampLayout, stamp)
	if err != nil {
		return time.Time{}, "", false
	}
	if mtime.Before(time.Unix(0, math.MinInt64)) || mtime.After(time.Unix(0, math.MaxInt64)) {
		return time.Time{}, "", false
	}
	return mtime, rawPath, true
}

func (f *ftpSession) cmdDelete(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if err := f.fs.Remove(f.cleanPath(arg)); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(250, "deleted")
}

func (f *ftpSession) cmdMkdir(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if hasCRLF(arg) {
		_ = f.reply(553, "invalid filename")
		return
	}
	ftpPath := f.cleanPath(arg)
	if err := f.fs.Mkdir(ftpPath, 0o750); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(257, fmt.Sprintf("%s created", ftpQuotePath(ftpPath)))
}

func (f *ftpSession) cmdRmdir(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	if err := f.fs.Rmdir(f.cleanPath(arg)); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	_ = f.reply(250, "removed")
}

func (f *ftpSession) cmdRnfr(arg string) {
	if !f.user.CanWrite {
		_ = f.reply(550, "permission denied")
		return
	}
	ftpPath := f.cleanPath(arg)
	if _, err := f.fs.Stat(ftpPath); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	f.rnfrPath = ftpPath
	_ = f.reply(350, "ready for RNTO")
}

func (f *ftpSession) cmdRnto(arg string) {
	if !f.user.CanWrite {
		f.rnfrPath = ""
		_ = f.reply(550, "permission denied")
		return
	}
	if f.rnfrPath == "" {
		_ = f.reply(503, "send RNFR first")
		return
	}
	if hasCRLF(arg) {
		f.rnfrPath = ""
		_ = f.reply(553, "invalid filename")
		return
	}
	oldPath := f.rnfrPath
	f.rnfrPath = ""

	newPath := f.cleanPath(arg)
	if err := f.fs.Rename(oldPath, newPath); err != nil {
		_ = f.reply(550, ftpErrMsg(err))
		return
	}
	destInfo, _ := f.fs.Stat(newPath)
	maybeAnnounceTempRename(f.uploads, f.tempExts, oldPath, destInfo, CompletedUpload{
		Username:     f.username,
		FullFilePath: f.fs.FullPath(newPath),
		FilePath:     newPath,
		ClientIP:     f.clientIP,
		Protocol:     CompletedUploadProtocolFTP,
	})
	_ = f.reply(250, "renamed")
}
