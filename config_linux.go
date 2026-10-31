//go:build linux

package ironport

import (
	"crypto/tls"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Default timeouts and limits applied unless callers override them.
const (
	// defaultSFTPIdleTimeout is the default per-connection inactivity timeout
	// applied to SFTP sessions when Config.IdleTimeout is zero. A client that
	// sends no data for this duration has its connection closed.
	defaultSFTPIdleTimeout = 15 * time.Minute
	// sshHandshakeTimeout bounds the time the raw TCP connection has to
	// complete the SSH handshake before being dropped.
	sshHandshakeTimeout = 30 * time.Second
	// ftpMaxControlLineLen caps the size of a single FTP control command in
	// bytes (including the CRLF terminator). Longer commands are rejected to
	// prevent unbounded memory growth from malicious clients.
	ftpMaxControlLineLen = 4096
	// ftpDataIdleTimeout bounds how long an FTP data connection may sit
	// without transferring any bytes before being considered stalled. A
	// stalled transfer surfaces as a read error from io.Copy, which in turn
	// suppresses the CompletedUpload notification for a STOR/APPE that did
	// not finish cleanly.
	ftpDataIdleTimeout = 5 * time.Minute
	// defaultFTPDataAcceptTimeout bounds how long a passive-mode FTP data
	// listener waits after PASV/EPSV and how long an active-mode FTP dial may
	// take after PORT/EPRT.
	defaultFTPDataAcceptTimeout = 30 * time.Second
	// defaultCompletedUploadsSize is the fallback buffer size used for the
	// CompletedUploads channel.
	defaultCompletedUploadsSize = 64
	// defaultAuthEventsSize is the fallback buffer size used for the
	// AuthEvents channel.
	defaultAuthEventsSize = 64
	// ephemeralHostKeyBits is the size of the in-memory RSA host key generated
	// when a server is started without an explicit signer.
	ephemeralHostKeyBits = 3072
	// authorizedKeyTimingPad is the minimum number of constant-time key
	// comparisons performed by the public-key auth callback. Users with
	// fewer AuthorizedKeys are padded with dummy comparisons up to this
	// count so the response time does not leak how many keys a particular
	// user has configured. Users with more than this many keys still take
	// longer; tune upward if a deployment routinely exceeds it.
	authorizedKeyTimingPad = 32
	// defaultTCPKeepAlivePeriod is the SO_KEEPALIVE idle period applied
	// to accepted control connections when Config.TCPKeepAlivePeriod
	// is zero. Keepalive probes prevent stateful firewalls and NAT devices
	// from silently dropping long-idle control connections, and surface
	// half-open connections (e.g. peer reboot, route loss) as read errors
	// instead of leaving handler goroutines blocked indefinitely.
	defaultTCPKeepAlivePeriod = 30 * time.Second
	// ftpTLSHandshakeTimeout bounds how long the FTP control or data TLS
	// handshake may take. Without a deadline a peer that opens the TCP
	// connection and then never sends client-hello bytes would pin the
	// handler goroutine indefinitely.
	ftpTLSHandshakeTimeout = 30 * time.Second
	// maxConsecutiveAcceptErrors caps how many consecutive non-transient
	// Accept errors the accept loop tolerates before giving up and returning
	// the error. Transient errors (timeouts, EMFILE/ENFILE, …) reset the
	// counter and are retried indefinitely; this bound only stops a
	// permanently poisoned listener fd from spinning and logging forever.
	maxConsecutiveAcceptErrors = 10
	// ftpTimestampLayout is the UTC timestamp format used by MDTM, MFMT, and
	// MLST/MLSD modify facts.
	ftpTimestampLayout = "20060102150405"
)

// resolveDur applies the package-wide "configured duration" rule: zero selects
// defaultV, a negative value disables the deadline (returns 0), any other
// value is honoured as-is.
func resolveDur(configured, defaultV time.Duration) time.Duration {
	switch {
	case configured == 0:
		return defaultV
	case configured < 0:
		return 0
	}
	return configured
}

func normalizeTempExtensions(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, 0, len(src))
	for _, ext := range src {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		out = append(out, ext)
	}
	return out
}

// Config holds the values used to construct a server.
type Config struct {
	SftpAddr            string
	FtpAddr             string
	FtpPassivePortRange string
	// FtpDataAcceptTimeout bounds how long passive-mode FTP data listeners wait
	// for the client data connection after PASV/EPSV, and how long active-mode
	// FTP dials may take after PORT/EPRT. Zero selects the package default
	// (30 seconds); negative disables the deadline.
	FtpDataAcceptTimeout time.Duration
	// FtpAllowActiveMode enables FTP active mode (PORT/EPRT). It defaults to
	// false because active mode requires outbound connections from the server.
	// When enabled, this server only dials the same IP as the control connection.
	FtpAllowActiveMode bool
	// FtpTLSConfig, when non-nil, enables explicit FTPS (RFC 4217). The
	// AUTH TLS command upgrades the control connection using this config,
	// and PROT P wraps the data connection. A private config pair and ticket
	// key are derived for each control session so data connections can only
	// resume that control session. Callers should populate Certificates (or a
	// GetCertificate callback) but otherwise leave session-ticket settings at
	// their defaults. Custom WrapSession and UnwrapSession callbacks are not
	// supported because they can bypass the control-session binding. Leave nil
	// to disable FTPS.
	FtpTLSConfig *tls.Config
	// FtpRequireTLS, when true, refuses USER/PASS over the FTP control
	// connection until AUTH TLS has succeeded and refuses data-transfer
	// commands until the client has negotiated PBSZ followed by PROT P.
	// Requires FtpTLSConfig to be set; otherwise the FTP listener would have
	// no path to authentication and every login attempt would be rejected.
	FtpRequireTLS bool
	// FtpPassiveAdvertisedIP optionally overrides the IPv4 address sent to
	// clients in the PASV (227) reply. By default the control connection's
	// local IP is advertised, which is wrong behind NAT or a port-forward:
	// the address the server sees on its own socket is the internal one,
	// not the public address the client must dial. Set this to the
	// external/advertised IPv4 address in such deployments. It only affects
	// the PASV reply; EPSV does not carry an address. Leave empty to
	// advertise the control connection's local IP.
	FtpPassiveAdvertisedIP string
	Users                  map[string]UserInfo
	SftpSigner             ssh.Signer
	CompletedUploadSize    int
	AuthEventSize          int
	// SSHKeyExchanges, SSHCiphers, SSHMACs, and
	// SSHPublicKeyAuthAlgorithms optionally pin SSH negotiation and public-key
	// auth signature algorithms. Nil slices use golang.org/x/crypto/ssh
	// defaults.
	SSHKeyExchanges            []string
	SSHCiphers                 []string
	SSHMACs                    []string
	SSHPublicKeyAuthAlgorithms []string
	// TempExtensions marks file extensions that should defer completion
	// notifications until a later rename to a non-temp name. Matching is
	// case-insensitive.
	TempExtensions []string
	// IdleTimeout bounds authenticated SFTP connection inactivity and FTP
	// control-session inactivity between commands. Zero selects the package
	// default; negative disables the idle timeout.
	IdleTimeout time.Duration
	// TCPKeepAlivePeriod controls the SO_KEEPALIVE idle period applied to
	// accepted SFTP and FTP control connections. Zero selects the package
	// default (30 seconds); a negative value disables keepalive entirely.
	// Probes keep idle control connections alive through stateful
	// firewalls/NAT and surface half-open peers as read errors.
	TCPKeepAlivePeriod time.Duration
	// SftpAllowChown controls whether SFTP clients may change file ownership
	// inside their jail. It defaults to false.
	SftpAllowChown bool
}

// DefaultConfig returns a fresh server configuration with package
// defaults applied. Callers should set Users before starting the server. Set
// SftpSigner to use a stable host key; when SftpSigner is nil, ListenAndServe
// generates an ephemeral in-memory host key.
func DefaultConfig() *Config {
	return &Config{
		SftpAddr:            ":2022",
		FtpAddr:             "",
		FtpPassivePortRange: "5000-5010",
		CompletedUploadSize: defaultCompletedUploadsSize,
		AuthEventSize:       defaultAuthEventsSize,
	}
}

// configuredTempExtensions returns a copy of the normalised temp extensions
// configured at construction.
func (s *Server) configuredTempExtensions() []string {
	return slices.Clone(s.tempExtensions)
}

// effectiveIdleTimeout returns the effective idle timeout for SFTP connections.
// A zero configured timeout selects the package default; a negative timeout
// disables the deadline.
func (s *Server) effectiveIdleTimeout() time.Duration {
	return resolveDur(s.idleTimeout, defaultSFTPIdleTimeout)
}

// effectiveFTPDataAcceptTimeout returns the effective FTP data-connection
// setup timeout. A zero configured timeout selects the package default; a
// negative timeout disables the passive accept or active dial deadline.
func (s *Server) effectiveFTPDataAcceptTimeout() time.Duration {
	return resolveDur(s.ftpDataAcceptTimeout, defaultFTPDataAcceptTimeout)
}

// sftpChownAllowed returns the configured SFTP chown permission.
func (s *Server) sftpChownAllowed() bool {
	return s.sftpAllowChown
}

// effectiveTCPKeepAlivePeriod returns the effective SO_KEEPALIVE idle period for
// accepted control connections. A zero configured value selects the package
// default; a negative value disables keepalive (returns 0).
func (s *Server) effectiveTCPKeepAlivePeriod() time.Duration {
	return resolveDur(s.tcpKeepAlivePeriod, defaultTCPKeepAlivePeriod)
}
