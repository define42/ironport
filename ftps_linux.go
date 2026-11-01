//go:build linux

package ironport

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// deriveFTPSessionTLSConfigs returns a private control/data config pair for a
// single FTP control session. Both configs receive the same freshly generated
// ticket key, while every other control session gets a different key. A data
// handshake can therefore resume only a TLS session minted for its own control
// connection, even when an attacker shares the same source IP.
func deriveFTPSessionTLSConfigs(base *tls.Config) (control, data *tls.Config, err error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, nil, fmt.Errorf("ftps: generating control-session ticket key: %w", err)
	}

	control, err = bindFTPTLSConfigToSession(base, key, false)
	if err != nil {
		return nil, nil, err
	}
	data, err = bindFTPTLSConfigToSession(base, key, true)
	if err != nil {
		return nil, nil, err
	}
	return control, data, nil
}

// bindFTPTLSConfigToSession clones base, installs the session-specific ticket
// key, and optionally requires resumption. GetConfigForClient needs special
// handling because a config returned by that callback replaces VerifyConnection
// and may carry its own ticket keys; clone and harden every returned config too.
func bindFTPTLSConfigToSession(base *tls.Config, key [32]byte, requireResume bool) (*tls.Config, error) {
	if err := validateFTPTLSSessionCallbacks(base); err != nil {
		return nil, err
	}

	config := base.Clone()
	config.SetSessionTicketKeys([][32]byte{key})
	if requireResume {
		requireFTPTLSResumption(config)
	}

	userGetConfig := config.GetConfigForClient
	if userGetConfig != nil {
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			selected, err := userGetConfig(hello)
			if err != nil || selected == nil {
				return selected, err
			}
			return bindFTPTLSConfigToSession(selected, key, requireResume)
		}
	}
	return config, nil
}

func validateFTPTLSSessionCallbacks(config *tls.Config) error {
	if config.WrapSession != nil || config.UnwrapSession != nil {
		return errors.New("ftps: custom TLS session wrapping is incompatible with control-session data binding")
	}
	return nil
}

func requireFTPTLSResumption(config *tls.Config) {
	userVerify := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if userVerify != nil {
			if err := userVerify(state); err != nil {
				return err
			}
		}
		if !state.DidResume {
			return errors.New("ftps: data connection must resume its control-channel TLS session")
		}
		return nil
	}
}

func (f *ftpSession) cmdPbsz() {
	if f.tlsConn == nil {
		_ = f.reply(503, "PBSZ only valid after AUTH TLS")
		return
	}
	// RFC 4217 §9: PBSZ over TLS is always 0; accept any non-negative
	// value and reply with 0 so non-conformant clients that send a
	// non-zero buffer size still proceed.
	_ = f.reply(200, "PBSZ=0")
	f.pbszSet = true
}

func (f *ftpSession) cmdProt(arg string) {
	if f.tlsConn == nil {
		_ = f.reply(503, "PROT only valid after AUTH TLS")
		return
	}
	if !f.pbszSet {
		_ = f.reply(503, "send PBSZ first")
		return
	}
	switch strings.ToUpper(strings.TrimSpace(arg)) {
	case "C":
		if f.server.ftpRequireTLS {
			_ = f.reply(534, "PROT C refused; data protection is required")
			return
		}
		f.dataProt = 'C'
		_ = f.reply(200, "protection level set to Clear")
	case "P":
		f.dataProt = 'P'
		_ = f.reply(200, "protection level set to Private")
	case "S", "E":
		_ = f.reply(536, "protection level not supported")
	default:
		_ = f.reply(504, "unknown protection level")
	}
}

// cmdAuth handles the AUTH command (RFC 4217 §4). It accepts AUTH TLS,
// AUTH TLS-C (TLS for control, data protection negotiated later via PROT),
// and the legacy AUTH SSL alias. It first stops the reader goroutine,
// performs the buffered-bytes injection check, sends the 234 reply, resets
// all session state that an attacker could have set pre-TLS, then performs
// the TLS handshake on the underlying socket and re-arms the reader on the
// encrypted stream.
//
// The buffered-bytes check is the defense against the FTPS "command
// injection across TLS" attack: an MITM on the cleartext segment can
// prepend commands (e.g. an extra "USER attacker\r\n") to the AUTH TLS
// line, and a naive server would re-read those bytes from the bufio
// reader after the upgrade, executing them inside the encrypted session.
// We refuse the upgrade if anything is buffered behind the AUTH line.
//
// Ordering is critical: the reader is stopped and the channel-clean check
// runs *before* the 234 reply. Once the client sees 234 it immediately
// sends a TLS ClientHello; if the reader were still running it could
// consume those handshake bytes (defeating the clean check and corrupting
// the handshake), and bytes the reader pulled out of f.r would be
// invisible to preTLSChannelClean. By stopping the reader and validating
// the channel first, anything buffered before the 234 is provably injected
// and anything after the 234 is the handshake.
func (f *ftpSession) cmdAuth(arg string) {
	if !f.validateAuthRequest(arg) {
		return
	}

	// Derive the private ticket key before sending 234. Once the client sees
	// that reply it immediately sends a ClientHello, so setup failures after
	// that point can only be handled by tearing down the connection.
	controlConfig, dataConfig, err := deriveFTPSessionTLSConfigs(f.server.ftpTLSConfig)
	if err != nil {
		log.Printf("ftp AUTH TLS setup from=%s: %v", f.conn.RemoteAddr(), err)
		_ = f.reply(451, "unable to initialize TLS")
		return
	}

	// Suspend the reader so the channel-clean check sees a stable f.r /
	// f.ctlMsg and so it cannot consume the client's post-234 ClientHello.
	f.stopReader()

	if !f.preTLSChannelClean() {
		_ = f.conn.Close()
		return
	}

	f.controlTLSConfig = controlConfig
	f.dataTLSConfig = dataConfig
	if err := f.reply(234, "ready for TLS"); err != nil {
		return
	}

	// RFC 4217 §4.3: any prior USER state is discarded across AUTH TLS so
	// the post-TLS session cannot inherit half-finished authentication.
	f.resetSessionStateForAuthTLS()

	if !f.performTLSHandshake() {
		return
	}
	f.startReader()
}

// validateAuthRequest returns true when AUTH is permitted with the supplied
// mechanism; otherwise it sends the appropriate FTP reply and returns false.
func (f *ftpSession) validateAuthRequest(arg string) bool {
	if f.server.ftpTLSConfig == nil {
		_ = f.reply(502, "AUTH not supported")
		return false
	}
	if f.tlsConn != nil {
		_ = f.reply(503, "already TLS")
		return false
	}
	switch strings.ToUpper(strings.TrimSpace(arg)) {
	case "TLS", "TLS-C", "SSL":
		return true
	case "":
		_ = f.reply(501, "AUTH requires a mechanism")
		return false
	default:
		_ = f.reply(504, "unsupported AUTH mechanism")
		return false
	}
}

// preTLSChannelClean reports whether the control channel is free of buffered
// plaintext data after AUTH but before the TLS handshake. Pending lines in
// ctlMsg or buffered bytes in f.r at this point came in over plaintext
// after the AUTH command — a man-in-the-middle could have injected them, so
// either form is fatal.
func (f *ftpSession) preTLSChannelClean() bool {
	for {
		select {
		case msg, ok := <-f.ctlMsg:
			if !ok {
				return f.r.Buffered() == 0 || f.logPreTLSBuffered()
			}
			if msg.err == nil && strings.TrimSpace(msg.line) != "" {
				log.Printf("ftp AUTH TLS rejected from=%s: pre-TLS line buffered: %q", f.conn.RemoteAddr(), msg.line)
				return false
			}
		default:
			if f.r.Buffered() > 0 {
				return f.logPreTLSBuffered()
			}
			return true
		}
	}
}

func (f *ftpSession) logPreTLSBuffered() bool {
	log.Printf("ftp AUTH TLS rejected from=%s: %d bytes buffered before TLS handshake", f.conn.RemoteAddr(), f.r.Buffered())
	return false
}

func (f *ftpSession) resetSessionStateForAuthTLS() {
	// RFC 4217 section 4.3 discards any authentication performed before
	// the TLS upgrade. If a plaintext login preceded AUTH TLS, run the
	// real logout path so the Logout event is announced and the jail fd
	// is released (both were previously skipped), and clear the
	// connection's user association so a RemoveUser for the pre-TLS user
	// cannot evict the now-anonymous session.
	f.closeDataEndpoint()
	f.logoutIfAuthenticated()
	f.username = ""
	f.authenticated = false
	f.user = UserInfo{}
	f.rnfrPath = ""
	f.restartOffset = 0
	f.expectedUploadSize = 0
	f.server.setConnUser(f.rawConn, "")
}

func (f *ftpSession) performTLSHandshake() bool {
	if f.controlTLSConfig == nil {
		log.Printf("ftp AUTH TLS handshake from=%s: control-session TLS config is unavailable", f.conn.RemoteAddr())
		_ = f.conn.Close()
		return false
	}

	deadline := time.Now().Add(ftpTLSHandshakeTimeout)
	_ = f.conn.SetDeadline(deadline)
	tlsConn := tls.Server(f.conn, f.controlTLSConfig)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		log.Printf("ftp AUTH TLS handshake from=%s: %v", f.conn.RemoteAddr(), err)
		_ = f.conn.Close()
		return false
	}
	_ = f.conn.SetDeadline(time.Time{})

	f.conn = tlsConn
	f.tlsConn = tlsConn
	f.r = bufio.NewReader(tlsConn)
	f.w = bufio.NewWriter(tlsConn)

	cs := tlsConn.ConnectionState()
	log.Printf("ftp AUTH TLS established from=%s version=%#x cipher=%#x", tlsConn.RemoteAddr(), cs.Version, cs.CipherSuite)
	return true
}
