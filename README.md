# ironport


[![Go Report Card](https://goreportcard.com/badge/github.com/define42/ironport)](https://goreportcard.com/report/github.com/define42/ironport)
[![codecov](https://codecov.io/gh/define42/ironport/graph/badge.svg?token=RI5OKZU3DR)](https://codecov.io/gh/define42/ironport)
[![Build Status](https://github.com/define42/ironport/actions/workflows/test.yml/badge.svg)](https://github.com/define42/ironport/actions/)

A production-ready, embeddable SFTP server and FTP server library for Go with a security-first design. The production-ready claim applies to the library API; the command under `cmd/ironport-demo` is only a runnable demo.

## Features

- **SFTP and FTP/FTPS in one binary** — a single server hosts both protocols against the same user database, jails, and permission flags. FTPS (explicit TLS via `AUTH TLS`, RFC 4217) opt-in with `FtpTLSConfig`; pair with `FtpRequireTLS` to refuse plaintext logins entirely
- **HTTP upload endpoint** — `HttpIngest()` returns an `http.HandlerFunc` you mount on your own router (`mux.HandleFunc("/upload", srv.HttpIngest())`). It accepts a `multipart/form-data` POST with the file under the `file` field (`key=file`), authenticates with HTTP Basic auth using the **same** username/password as SFTP/FTP/FTPS, and stores the file in the user's jail — sharing the same permission flags, `CompletedUploads`, and `AuthEvents` streams. Put it behind TLS (your own `http.Server`/reverse proxy), since Basic credentials are otherwise sent in the clear
- **SSH public-key and password authentication** — both methods use constant-time comparisons to prevent username enumeration via timing side-channels
- **Per-user jail (chroot)** — each user is confined to a configurable root directory. Every client path is resolved via Linux `openat2` with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, so the kernel itself rejects path traversal and any symlink anywhere in the lookup
- **Fine-grained permissions** — independent `CanRead` / `CanWrite` flags per user
- **Dynamic user management** — add, remove, and update users and their authorized keys at runtime without restarting the server
- **Upload notifications** — a buffered `CompletedUploads()` stream delivers a `CompletedUpload` struct (protocol — `SFTP`, `FTP`, or `HTTP` — username, full on-disk path, jail-relative path, and client IP) for every successfully closed upload
- **Auth notifications** — a buffered `AuthEvents()` stream delivers `LoginSuccess`, `LoginFailed`, and `Logout` events for SFTP and FTP sessions; HTTP uploads emit `LoginSuccess`/`LoginFailed` per authenticated request
- **Temp-file aware completion** — optionally set `TempExtensions` on the config (for example, `.tmp`, `.writing`) to suppress completion notifications for temporary upload names and emit the notification when the file is renamed to a non-temp name. Dotfiles (names beginning with `.`) are always treated as temporary in the same way
- **Graceful shutdown** — `Close()` stops the listener immediately and lets in-flight sessions finish on their own. `Shutdown(ctx)` stops the listener AND waits for in-flight sessions to finish, force-closing any that remain when `ctx` expires
- **Thread-safe runtime APIs** — user-management helpers and listener lifecycle methods are safe to call while the server is running
- **Resource limits** — finite caps on connections, SSH channels, SFTP handles, passive FTP listeners, and concurrent HTTP requests, with absolute login deadlines and shared authentication throttling
- **Handshake timeout** — connections that do not complete the SSH handshake within 30 seconds are dropped
- **SSH algorithm pinning** — optionally constrain SSH key exchange, ciphers, MACs, and public-key auth signature algorithms
- **Idle-session timeout** — configurable via `IdleTimeout` on the config (default 15 minutes); inactive authenticated SFTP sessions are reaped
- **Empty-password protection** — users whose stored `Password` is empty cannot authenticate via password, and empty supplied passwords are always rejected
- **Chown opt-in** — `Setstat`/`Fsetstat` requests that try to change file ownership (uid/gid) are rejected with a permission error unless `SftpAllowChown` is explicitly set to `true` on the config. Symlink creation by clients is always refused, while SFTP access/modification time changes (`Chtimes`) are applied through the same fd-relative jail policy.

## Platform support

This package is **Linux-only**. The path-containment guarantee depends on the
`openat2` syscall with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, available
since Linux 5.6. `ListenAndServe` probes for `openat2` at startup and
returns an error on older kernels rather than silently degrading the policy.

Existing files are pinned with `O_PATH`, checked to be regular files, and then
reopened through an accessible, trusted `/proc/self/fd` for I/O. This rejects
FIFOs, sockets, and devices before opening them for I/O while preserving normal
file-lease waits. Truncation occurs only after a successful open. Chmod uses the
same checks and also permits directories. These operations fail closed if
required descriptor reopening is unavailable.

Configured `UserInfo.Root` paths must name existing directories at login.
Symlinks in any root-path component and literal `..` components are rejected;
use the real directory path when migrating a symlinked configuration. Relative
roots are resolved from a verified working-directory snapshot at authentication
time, keeping the retained directory and its reporting path consistent.

`srv.ValidateJailRoots()` checks kernel support and logs warnings for configured
roots that cannot be opened securely. It returns an error only if the kernel
capability probe fails; invalid or missing user roots are advisory so directories
can be provisioned later. `ListenAndServe` and `HttpIngest()` call it automatically,
including for HTTP-only deployments. `AddUser` also checks its root after
publishing the user update and disconnecting revoked sessions. These checks may
block on filesystem or logger I/O, but do not hold the user lock or retain root
handles. They do not verify permissions for later file operations.

Root-open failures after a successful credential check produce server-side
explanations, sampled at most once per second per server with a suppressed count.
Usernames, paths, and errors are escaped in diagnostics; authentication replies
and events retain their generic failure reasons. These advisory checks do not
replace authentication-time validation.

Authentication opens and retains the root directory for the SSH/FTP session or
HTTP request, including every SFTP channel on that SSH connection. Renaming or
replacing the configured path does not redirect an authenticated session.
`CompletedUpload.FullFilePath` is a reporting path and may become stale after
a root or parent directory is renamed.

## Project policy

- Security reports: see [SECURITY.md](SECURITY.md).
- Release notes: see [CHANGELOG.md](CHANGELOG.md).
- Compatibility: release versions follow SemVer. While the major version is
  `v1`, exported Go APIs are backward compatible across minor and patch
  releases; breaking API changes require a major version bump.
- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).

## Quick start

```go
package main

import (
    "log"

    "github.com/define42/ironport"
)

func main() {
    users := map[string]ironport.UserInfo{
        "alice": {Password: "alicepw", Root: "/srv/sftp/alice", CanRead: true, CanWrite: true},
        "bob":   {Password: "bobpw",   Root: "/srv/sftp/bob",   CanRead: true, CanWrite: false},
    }

    // Load a stable host key from disk. If this is left unset, ListenAndServe
    // generates an ephemeral in-memory host key.
    signer, err := ironport.NewSignerFromFile("/etc/ssh/sftp_host_key")
    if err != nil {
        log.Printf("host key unavailable, using ephemeral key: %v", err)
    }

    // FtpAddr is "" by default, disabling the (plaintext) FTP listener.
    config := ironport.DefaultConfig()
    config.SftpAddr = ":2022"
    config.Users = users
    if signer != nil {
        config.SftpSigner = signer
    }
    srv := ironport.NewServer(config)

    // Drain upload notifications in the background.
    go func() {
        for ev := range srv.CompletedUploads() {
            log.Printf("upload complete: protocol=%q user=%q ip=%q path=%q full=%q",
                ev.Protocol, ev.Username, ev.ClientIP, ev.FilePath, ev.FullFilePath)
        }
    }()

    // Drain auth/session notifications in the background.
    go func() {
        for ev := range srv.AuthEvents() {
            log.Printf("auth event: type=%q protocol=%q user=%q ip=%q",
                ev.Type, ev.Protocol, ev.Username, ev.ClientIP)
        }
    }()

    log.Fatal(srv.ListenAndServe())
}
```

### Configuring the upload-notification buffer size

Set `CompletedUploadSize` on the server config:

```go
config := ironport.DefaultConfig()
config.Users = users
config.SftpSigner = signer
config.CompletedUploadSize = 256
srv := ironport.NewServer(config)
```

Read upload notifications from the receive-only `CompletedUploads()` stream.
The underlying channel is internal, so callers cannot send to it, close it, or
replace it while the server is running. To change the buffer capacity, set a
different `CompletedUploadSize` before calling `NewServer`.

### Configuring the auth-notification buffer size

Set `AuthEventSize` on the server config:

```go
config := ironport.DefaultConfig()
config.Users = users
config.SftpSigner = signer
config.AuthEventSize = 256
srv := ironport.NewServer(config)
```

Read authentication and logout notifications from the receive-only
`AuthEvents()` stream. The underlying channel is internal and follows the same
non-blocking, caller-drained behavior as `CompletedUploads()`.

### Deferring completion notifications until final rename

Many clients upload to a temporary filename first (for example `file.txt.tmp`
or `file.txt.writer`)
and rename to the final filename only after the upload is fully complete.
Configure `TempExtensions` to emit `CompletedUploads()` events at that final
rename boundary:

```go
config := ironport.DefaultConfig()
config.Users = users
config.SftpSigner = signer
config.TempExtensions = []string{".tmp", ".writing", ".writer"}
srv := ironport.NewServer(config)
```

With this setting:

- uploads that close with a temp extension are not announced yet
- clients may set the modification time on the temp file with SFTP `Chtimes`
- renaming from a temp extension to a non-temp name emits the completion event

In addition to configured temp extensions, files whose name begins with a dot
(for example `.in-progress` or `.foo.txt`) are always treated as in-progress:
their completion notification is deferred until the file is renamed to a
non-dot, non-temp name. This applies even when `TempExtensions` is empty. Only
renames whose destination is a regular file are announced, so renaming a hidden
directory (for example `.staging` to `staging`) never emits a completion event.

### Pinning SSH algorithms

Set SSH algorithm fields on the config before constructing the server to
restrict SSH negotiation. Nil fields keep the defaults from
`golang.org/x/crypto/ssh`; non-nil fields are used as allow-lists in the order
supplied:

```go
config := ironport.DefaultConfig()
config.Users = users
config.SftpSigner = signer
config.SSHKeyExchanges = []string{ssh.KeyExchangeCurve25519}
config.SSHCiphers = []string{ssh.CipherAES256CTR}
config.SSHMACs = []string{ssh.HMACSHA256}
config.SSHPublicKeyAuthAlgorithms = []string{
    ssh.KeyAlgoED25519,
    ssh.KeyAlgoRSASHA256,
}
srv := ironport.NewServer(config)
```

For RSA host-key signature pinning, pass a signer already restricted with
`ssh.NewSignerWithAlgorithms`.

## Resource and authentication limits

Limits belong to one `Server` and are shared by its protocol handlers. Configure
`Config.ResourceLimits` (`ResourceLimitConfig`) and `Config.AuthLimits`
(`AuthLimitConfig`) before calling `NewServer`; zero or negative fields select
finite defaults, including when constructing `Config` directly. For example:

```go
config := ironport.DefaultConfig()
config.ResourceLimits.MaxConnections = 256
config.ResourceLimits.SFTPMaxHandlesPerConnection = 16
config.ResourceLimits.HTTPMaxConcurrentRequests = 8
config.AuthLimits.MaxEntries = 4096
if err := config.Validate(); err != nil {
    return err
}
srv := ironport.NewServer(config)
```

The following fields belong to `Config.ResourceLimits`:

| Configuration | Default | Scope |
| --- | --- | --- |
| `MaxConnections` / `MaxConnectionsPerIP` | 128 / 32 | SFTP and FTP control connections combined, including unauthenticated clients |
| `SSHMaxChannels` | 16 | Simultaneous session channels per SSH connection |
| `SFTPMaxHandles` / `SFTPMaxHandlesPerUser` / `SFTPMaxHandlesPerConnection` | 256 / 64 / 32 | Open files and directories; the connection budget spans every channel on one SSH connection |
| `FTPMaxPassiveListeners` / `FTPMaxPassiveListenersPerUser` / `FTPMaxPassiveListenersPerIP` | 64 / 2 / 8 | Outstanding passive-port reservations, including data-connection setup |
| `HTTPMaxConcurrentRequests` | 32 | Requests executing across every `HttpIngest` handler created from this server |
| `HTTPMaxAuthorizationBytes` | 4,096 | Raw `Authorization` headers, before Basic-auth decoding |
| `HTTPMaxUsernameBytes` / `HTTPMaxPasswordBytes` | 256 / 1,024 | Decoded HTTP Basic-auth credentials |
| `FTPAuthTimeout` | 30 seconds | Absolute login window; anonymous `NOOP`, `USER`, and `REIN` cannot extend it |
| `FTPMaxAuthFailures` | 5 | Failed credential checks over the lifetime of one FTP control connection |

Connection overload closes new sockets before starting a handler. SSH channel
overload rejects only the new channel. SFTP handle admission happens before
opening, creating, or truncating a file; closing a handle or tearing down its
channel returns its permit. Passive FTP exhaustion returns `425`. Each passive
reservation expires from the time of `PASV`/`EPSV`, normally after 30 seconds,
and releases on replacement, logout, disconnect, cancellation, or completed
data setup. Established FTP transfers no longer occupy passive-listener slots.

Directory listings use bounded server memory: SFTP reads entries on demand
from an open directory cursor, and FTP `LIST`, `MLSD`, and `STAT` stream their
output. SFTP directory descriptors and handle permits remain held until the
client closes the handle or the session ends, including after end-of-directory.
Listings reflect filesystem changes during enumeration rather than a stable
snapshot. FTP `STAT` uses the complete-reply write deadline; a failure after
its multiline reply starts closes the control session.

SSH has an absolute 30-second handshake deadline in addition to its read idle
timeout. FTP successful login stops its login timer; logging out starts a new
window. `FTPMaxAuthFailures` is not reset by `USER`, `REIN`, or a successful login.

`AuthLimits` configures token buckets shared by SSH, FTP, and HTTP. Defaults
allow bursts of 200 attempts server-wide, 30 per source IP, and 20 per username,
refilling one token every 10 ms, one second, and one second respectively.
Successful credential checks consume tokens too. Each admitted SSH key eligibility
check consumes one token per bucket; an accepted check and its first signature
proof share that admission. Verified completion rechecks current credentials and
cooldown. Rejected key eligibility checks do not advance credential-failure
backoff, allowing clients to offer several keys before the authorized one. They
still emit `LoginFailed` events with reason `AuthFailureCredentials`.
Unsigned key queries check key eligibility without opening the jail or emitting
root diagnostics. The jail is opened and retained only after signature
verification, using the user's current root, keys, and permissions.
A repeated proof after a failed completion requires fresh admission. Every bucket
and the identity-table capacity must permit the attempt before tokens are
consumed or new identities retained.

Three failed credential checks start a 250 ms cooldown, doubling after each
further failure up to 30 seconds. Attempts during cooldown are rejected
immediately. HTTP returns `429` with `Retry-After`, FTP returns `421` and closes
the control connection, and SSH returns an authentication error. Success clears
only that username's failure state, preserving shared-IP backoff. Failure logs
and throttled failure events are sampled. `AuthEvent.Reason` distinguishes
`AuthFailureCredentials` from `AuthFailureThrottled` on `LoginFailed` events;
success and logout events leave it empty. Throttling events may be sampled even
when the event queue has room, so this stream is not a complete attempt count.
The combined IP/username table holds at most 8,192 entries by default. Idle
entries become eligible for expiry after 15 minutes, once their tokens have
fully refilled and active cooldowns have ended. Longer refill intervals therefore
retain their limits across idle periods. New identities are denied while the
table is full. IPs come from the transport peer,
never forwarded headers, so clients behind one proxy share its IP budget.

`Config.Validate()` rejects a positive `AuthLimits.MaxEntries` below two and
contradictory positive `BackoffInitial`/`BackoffMax` settings. If only the maximum
is set below 250 ms, the default initial delay is reduced to honor it. If only
the initial delay exceeds 30 seconds, the default maximum is raised to match.
`DefaultConfig()` fills in positive defaults: when lowering its maximum below
250 ms, also lower or zero its initial delay. For example, set
`config.AuthLimits = ironport.AuthLimitConfig{BackoffMax: 100 * time.Millisecond}`
to use a 100 ms maximum with other authentication defaults.
`NewServer` keeps its existing signature; invalid settings make `ListenAndServe`
return an error and HTTP ingest return `503` before authentication or body reads.
Validation is captured at construction, so later changes to the config do not
change a running server. Listener/TLS/kernel checks still run at startup.

Finite defaults introduce admission rejection for applications that previously
accepted unlimited work. Negative `FtpDataAcceptTimeout` now disables only active
FTP dial deadlines; passive reservations still expire after 30 seconds.

These are application admission limits, not OS file-descriptor or storage
quotas. `MaxConnections` excludes HTTP connections and FTP data sockets. HTTP
callers own the listener and must configure read-header, read, write, and idle
timeouts plus `MaxHeaderBytes`; the demo provides an example. HTTP request slots
remain occupied until the entire request body, including any multipart epilogue,
has been consumed or rejected. A stalled body therefore holds a slot until the
caller's read timeout or the client disconnects. Middleware must preserve HTTP
transport controls as described below. Multiple `Server` instances and processes
have separate budgets.

## FTP support (opt-in)

This package also exposes an FTP listener that shares the SFTP user database,
jails, and permission flags. The listener is disabled by default — set
`FtpAddr` to enable it. Without `FtpTLSConfig`, FTP transmits credentials and
data in the clear, so it should only be used on a trusted network segment
where you control all clients and intermediate hops. To require encryption,
set `FtpTLSConfig` and `FtpRequireTLS = true` (see [FTPS support](#ftps-support-rfc-4217-explicit-tls) below).

```go
config := ironport.DefaultConfig()
config.Users = users
config.SftpSigner = signer
config.FtpAddr = ":2121"
config.FtpPassivePortRange = "5000-5010"
config.FtpPassiveAdvertisedIP = "203.0.113.7" // advertise this IP in PASV (for NAT); empty uses the local IP
config.FtpDataAcceptTimeout = 30 * time.Second // zero selects this default
config.FtpAllowActiveMode = false              // opt in to PORT/EPRT when needed
srv := ironport.NewServer(config)
```

When FTP is enabled, passive mode (`PASV` / `EPSV`) is supported by default.
Active mode (`PORT` / `EPRT`) is refused unless `FtpAllowActiveMode` is true.
Even then, the server only dials back to the same IP as the control connection
to prevent FTP bounce behavior. Passive data connections are checked against the
control connection IP to prevent passive-port stealing. A rejected IP or FTPS
handshake leaves the passive endpoint available for another peer, up to 32
rejected connections within the original reservation deadline. Passive
reservations start at `PASV`/`EPSV` and active dials wait up to
`FtpDataAcceptTimeout`; retries do not extend that deadline. A negative value
disables only the active dial deadline; passive reservations still expire
after 30 seconds. Behind NAT or a port-forward, set `FtpPassiveAdvertisedIP`
to the external IPv4 address so the `PASV` reply advertises an address clients
can reach instead of the server's internal address.

Each complete FTP control reply, including multiline replies, has a five-minute
write deadline. A failed control write closes the session and cancels its data
operations.

For `STOR` and `APPE`, the server sends `150` and validates the data
connection, including FTPS session binding, before creating or truncating the
destination. Failed data setup leaves existing files unchanged and creates no
new file. Destination-open errors (`550`) and invalid restart offsets (`554`)
are reported after `150` and successful data setup; the data connection is
then closed and no upload-completion event is emitted.

FTP and FTPS clients can read modification times with `MDTM` or the `modify`
fact in `MLST`/`MLSD`, and can set file modification times with `MFMT
YYYYMMDDHHMMSS path`.

### FTPS support (RFC 4217, explicit TLS)

Set `FtpTLSConfig` to a `*tls.Config` that carries the server certificate to
advertise `AUTH TLS`, `PBSZ`, and `PROT` over the FTP listener. Set
`FtpRequireTLS = true` to require `AUTH TLS` before `USER`/`PASS` and
`PBSZ` followed by `PROT P` before any data transfer. This is the
recommended mode for any FTP listener that faces an untrusted network.

```go
cert, err := tls.LoadX509KeyPair("ftps.crt", "ftps.key")
if err != nil {
    log.Fatal(err)
}
config := ironport.DefaultConfig()
config.Users = users
config.SftpSigner = signer
config.FtpAddr = ":2121"
config.FtpTLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
config.FtpRequireTLS = true
srv := ironport.NewServer(config)
```

`WrapSession` and `UnwrapSession` must remain unset: custom ticket handling
could bypass the control-session binding, so the server rejects such FTPS
configs at startup when FTP is enabled. An enabled FTP listener also requires
`FtpTLSConfig` when `FtpRequireTLS` is true; otherwise `ListenAndServe` fails
before opening any listener. These FTP TLS checks are skipped when `FtpAddr`
is empty or whitespace-only.

A successful `AUTH TLS` clears the plaintext login, data endpoint, and
`EPSV ALL`/`PBSZ`/`PROT` state. Clients must log in again and send `PBSZ 0`
followed by `PROT P` to protect data transfers. Diagnostics for rejected
buffered commands record only a recognized command verb and byte count;
arguments and unknown command tokens are omitted.

The implementation covers the three FTPS implementation traps that are easy
to get wrong:

- **Buffered-bytes injection** — after replying `234` to `AUTH TLS`, the
  server verifies the receive buffer is empty before starting the TLS
  handshake. A man-in-the-middle on the plaintext segment cannot pipeline
  attacker-controlled commands behind the legitimate `AUTH TLS` line.
- **Data-channel binding** — every `AUTH TLS` control connection receives a
  private session-ticket key shared only with its data-connection config.
  `PROT P` also enforces `DidResume == true`, so a ticket obtained from a
  different control connection is rejected even when both clients share one
  public IP. A peer that hijacks the data port cannot mount a fresh handshake
  or reuse a ticket from another session.
- **Clean `close_notify` on transfers** — every TLS-wrapped data
  connection is half-closed with `CloseWrite` before the underlying
  socket is closed, so the client sees a proper TLS EOF and can
  distinguish a complete download from a truncated one.

Only explicit FTPS is supported; implicit FTPS (port 990, TLS from byte
zero) is intentionally not implemented. The `CCC` command is refused —
once TLS is negotiated, the session stays encrypted.

## HTTP upload endpoint (opt-in)

In addition to SFTP and FTP, the server can accept uploads over HTTP. Unlike
the SFTP/FTP listeners, the HTTP endpoint does **not** run its own listener:
`HttpIngest()` returns an `http.HandlerFunc` that you mount on your own
`*http.ServeMux` (or any router), so the upload URL lives inside your existing
HTTP application and you control the TLS termination, middleware, and routing.

```go
srv := ironport.NewServer(config)

mux := http.NewServeMux()
mux.HandleFunc("/upload", srv.HttpIngest())

// Terminate TLS yourself — HTTP Basic credentials are otherwise in the clear.
server := &http.Server{
    Addr: ":8443", Handler: ironport.WithHTTPControl(mux),
    ReadHeaderTimeout: 10 * time.Second,
    ReadTimeout: 30 * time.Minute, WriteTimeout: 30 * time.Minute,
    IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10,
}
log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))
```

When adding middleware, keep `WithHTTPControl` outermost:

```go
server.Handler = ironport.WithHTTPControl(middleware(mux))
```

It captures the original response controller in the request context so rejected
slow bodies can be interrupted even when middleware hides optional writer
interfaces. Middleware must preserve that context. The wrapper is optional if
all response-writer wrappers implement `Unwrap() http.ResponseWriter` and
middleware preserves the complete request body. Middleware that replaces or
limits the body needs the outer wrapper so any unread original body is consumed
before an upload releases its concurrency slot.

Without either mechanism, middleware that forwards `http.Hijacker` can still
have rejected HTTP/1 connections closed, but the error response is lost. If
middleware hides both deadline and hijacking support, the library logs a sampled
integration error; cleanup then depends on the server's read timeout. Install
`WithHTTPControl` outside that middleware to retain bounded cleanup and normal
HTTP error responses. HTTP/2 rejection affects only the request stream.

The endpoint accepts one or more files per request:

- **Method** — `POST` only; anything else is answered with `405` and an
  `Allow: POST` header.
- **Authentication** — HTTP Basic auth. The username and password are the
  **same** credentials used for SFTP/FTP/FTPS, validated with the same
  constant-time password comparison. A missing or wrong credential returns
  `401` with a `WWW-Authenticate` challenge. Throttled authentication returns
  `429` with `Retry-After`. Oversized raw credentials return `431`; oversized
  decoded credentials return `401`. Because Basic auth sends the
  credential on every request, run this endpoint over TLS (your own
  `http.Server` or a TLS-terminating reverse proxy).
- **Permission** — the authenticated user must have `CanWrite`, or the request
  is rejected with `403`.
- **Body** — `multipart/form-data` carrying one or more parts under the form
  field `file` (i.e. `key=file`). Each part's filename becomes the destination
  path, relative to the user's jail root. A nested name such as
  `reports/2026/q2.csv` (or `/reports/2026/q2.csv`) is stored at that path,
  creating any missing parent directories. The path is resolved through the same
  `openat2` no-symlink jail as SFTP/FTP, so `..` segments are collapsed and
  contained and a crafted filename (for example `../../etc/passwd`) can neither
  escape the jail nor follow a symlink.
- **Multiple files** — repeating the `file` field (a standard
  `<input type="file" name="file" multiple>` form, or `curl -F file=@a -F
  file=@b`) stores every part. Each file is written independently and announced
  separately, and one file's failure does not abort the others.
- **Success** — each file is stored (creating or overwriting) and streamed
  straight to disk (not buffered whole in memory or staged in a temp directory),
  and a `CompletedUpload` with `Protocol == "HTTP"` is announced per file on
  `CompletedUploads()`. The handler replies `201 Created` when at least one file
  was stored and none failed.
- **Partial/total failure** — if any file fails, the reply is an error status
  (`400` for client errors such as an invalid filename or no `file` part, `500`
  for a server-side write error) with a plain-text body listing each file's
  outcome (`stored <path>` / `failed <path> (<reason>)`), so a partial failure
  is never silent. Files that did store are kept.

`TempExtensions` and dotfile handling apply exactly as they do for SFTP/FTP: an
upload whose name ends in a configured temp extension, or begins with a dot, is
written but its completion is deferred. Because a single HTTP request has no
later rename step, such a deferred upload is only announced if the file is later
renamed to a final name over SFTP/FTP.

A quick upload with `curl`:

```sh
# Stored at the jail root as report.csv.
curl -u alice:alicepw -F file=@./report.csv https://host:8443/upload

# Stored at <jail>/reports/2026/q2.csv; the reports/2026 directories are created.
curl -u alice:alicepw -F 'file=@./q2.csv;filename=reports/2026/q2.csv' https://host:8443/upload

# Several files in one request — each part is stored and announced separately.
curl -u alice:alicepw -F file=@./a.csv -F file=@./b.csv https://host:8443/upload
```

The handler admits at most `ResourceLimits.HTTPMaxConcurrentRequests` requests at once across
all handlers created from the same server. Saturation returns `503` with
`Retry-After: 1` before authentication or body reads. Early rejection stops
request reads and disables HTTP/1 connection reuse through the preserved
transport controls described above, so slow bodies cannot keep occupying
resources after admission capacity has been returned.

The handler imposes no upload-size limit of its own (matching SFTP/FTP); wrap it
with `http.MaxBytesReader`, or bound the request body at your reverse proxy, if
you need a cap.

## Public-key authentication

Add one or more public keys to a user's `AuthorizedKeys` field at construction time, or use the `AddUserKey` / `RemoveUserKey` helpers at runtime:

```go
// At construction.
users["alice"] = ironport.UserInfo{
    Root:           "/srv/sftp/alice",
    CanRead:        true,
    CanWrite:       true,
    AuthorizedKeys: []ssh.PublicKey{alicePubKey},
}

// At runtime (safe to call while the server is running).
srv.AddUserKey("alice", newKey)
srv.RemoveUserKey("alice", oldKey)
```

`AddUserKey` preserves established sessions. Removing an existing key with
`RemoveUserKey` closes that user's SFTP/FTP sessions, including FTP data
operations. Removing a missing key leaves sessions connected.

## Dynamic user management

```go
// Add or replace a user.
srv.AddUser("carol", ironport.UserInfo{
    Password: "carolpw",
    Root:     "/srv/sftp/carol",
    CanRead:  true,
    CanWrite: true,
})

// Remove a user and terminate their active SFTP/FTP sessions.
srv.RemoveUser("carol")

// Remove all users without deleting any on-disk user data.
srv.RemoveAllUsers()
```

User changes are checked against pending logins: removing a user, replacing
credentials, or changing the root or permissions prevents an old authentication
snapshot from starting a new session, even if the same user is removed and
added again. An effective `AddUser` replacement also closes the user's existing
SFTP/FTP sessions. Equivalent replacements preserve them; authorized-key order,
duplicates, and nil entries do not count as credential changes.

Use `AddUserKey` to add a key without disconnecting established sessions. The
addition still invalidates pending authentication snapshots so login commits
use the current configuration. HTTP authentication is per request: updates
reject stale authentication, while uploads already authorized continue. HTTP
request cancellation and server shutdown remain owned by the caller.

## Graceful shutdown

`Shutdown(ctx)` stops the listeners so no new connections are accepted, then
waits for every in-flight handler to return. If `ctx` expires first, the
remaining tracked connections are force-closed and `ctx.Err()` is returned.
After `Shutdown` returns, `ListenAndServe` will have returned `nil`; the
same `Server` can be started again by calling `ListenAndServe`.

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := srv.Shutdown(ctx); err != nil {
    log.Printf("shutdown: %v", err)
}
```

Use `Close()` when you want the legacy behavior of closing the listener
without waiting for sessions to drain. The same `Server` can be started again
after `Close` returns; existing sessions from the previous run continue until
they finish or a later `Shutdown(ctx)` drains them.

## Host key

Use `NewSignerFromFile` to load a PEM-encoded RSA, ECDSA, or Ed25519 private key:

```go
signer, err := ironport.NewSignerFromFile("/etc/ssh/sftp_host_key")
```

If `config.SftpSigner` is nil, `ListenAndServe` generates an ephemeral in-memory
RSA-3072 host key and stores it on the server. This is convenient for demos, but
not suitable for production because clients will see a different host key after
each process restart.

## Running the demo binary

```sh
go run ./cmd/ironport-demo -host-key /path/to/host_key
```

`cmd/ironport-demo` is intentionally not an operator tool. It hard-codes
example users, uses basic logging, has no metrics, config file,
readiness/healthcheck endpoint, or service-manager integration, and is meant to
show library wiring rather than production deployment.

If `-host-key` is omitted, `ListenAndServe` generates a fresh RSA-3072 key on
every start. This is not suitable for production, as clients will see a
different host key each time.
The demo binary also accepts comma-separated `-ssh-key-exchanges`,
`-ssh-ciphers`, `-ssh-macs`, and `-ssh-public-key-auth-algorithms` flags.

## License

See [LICENSE](LICENSE) for details.
