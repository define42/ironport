# ironport


[![Go Report Card](https://goreportcard.com/badge/github.com/define42/ironport)](https://goreportcard.com/report/github.com/define42/ironport)
[![codecov](https://codecov.io/gh/define42/ironport/graph/badge.svg?token=RI5OKZU3DR)](https://codecov.io/gh/define42/ironport)
[![Build Status](https://github.com/define42/ironport/actions/workflows/test.yml/badge.svg)](https://github.com/define42/ironport/actions/)

A production-ready, embeddable SFTP server and FTP server library for Go with a security-first design. The production-ready claim applies to the library API; the command under `cmd/ironport-demo` is only a runnable demo.

## Features

- **SFTP and FTP/FTPS in one binary** — a single server hosts both protocols against the same user database, jails, and permission flags. FTPS (explicit TLS via `AUTH TLS`, RFC 4217) opt-in with `FtpTLSConfig`; pair with `FtpRequireTLS` to refuse plaintext logins entirely
- **HTTP upload endpoint** — `HttpIngest()` returns an `http.HandlerFunc` you mount on your own router (`mux.HandleFunc("/upload", srv.HttpIngest())`). It accepts a `multipart/form-data` POST with the file under the `file` field (`key=file`), authenticates with HTTP Basic auth using the **same** username/password as SFTP/FTP/FTPS, and stores the file in the user's jail — sharing the same permission flags, `CompletedUploads`, and `AuthEvents` streams. Concurrent requests and credential sizes are bounded by default. Put it behind a timeout-configured TLS `http.Server` or reverse proxy, since Basic credentials are otherwise sent in the clear
- **SSH public-key and password authentication** — both methods use constant-time comparisons to prevent username enumeration via timing side-channels
- **Per-user jail (chroot)** — each user is confined to a configurable root directory. The configured root is atomically opened with Linux `openat2` and `RESOLVE_NO_SYMLINKS`, which rejects a symlink in any root-path component. That directory FD is retained while the jail is active, and every client path is resolved from it with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, so later pathname replacement cannot redirect filesystem operations
- **Fine-grained permissions** — independent `CanRead` / `CanWrite` flags per user
- **Dynamic user management** — add, remove, and update users and their authorized keys at runtime without restarting the server
- **Upload notifications** — a buffered `CompletedUploads()` stream delivers a `CompletedUpload` struct (protocol — `SFTP`, `FTP`, or `HTTP` — username, full on-disk path, jail-relative path, and client IP) for every successfully closed upload
- **Auth notifications** — a buffered `AuthEvents()` stream delivers `LoginSuccess`, `LoginFailed`, and `Logout` events for SFTP and FTP sessions; HTTP uploads emit `LoginSuccess`/`LoginFailed` per authenticated request
- **Temp-file aware completion** — optionally set `TempExtensions` on the config (for example, `.tmp`, `.writing`) to suppress completion notifications for temporary upload names and emit the notification when the file is renamed to a non-temp name. Dotfiles (names beginning with `.`) are always treated as temporary in the same way
- **Graceful shutdown** — `Close()` stops the listener immediately and lets in-flight sessions finish on their own. `Shutdown(ctx)` stops the listener AND waits for in-flight sessions to finish, force-closing any that remain when `ctx` expires
- **Thread-safe runtime APIs** — user-management helpers and listener lifecycle methods are safe to call while the server is running
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
An accessible, trusted procfs at `/proc/self/fd` is also required: existing
files are pinned with `O_PATH`, checked for a permitted type, then reopened
through that descriptor for normal, lease-compatible I/O. File operations
fail closed if descriptor reopening is unavailable.

Jail-root paths are opened in one `openat2` lookup, validated as directories,
and retained by file descriptor for the authenticated connection (or HTTP
request). A configured root with a symlink in its final component or any
ancestor is rejected. If the pathname is renamed or replaced after it is
opened, file operations remain pinned to the original directory. Every jail
root, absolute or relative, must not contain a `..` component; use an
equivalent normalized path instead.

`ListenAndServe` and creation of `HttpIngest()` check configured roots and log
unusable paths before the first login. `ValidateJailRoots()` exposes the same
check for deployment tooling. Missing roots are warnings because they may be
provisioned later; unavailable kernel support is an error. Uploads and downloads
accept regular files only, so a FIFO or device placed inside a jail cannot be
used as a transfer endpoint. Directory listings are read incrementally.

The jail enforces pathname containment, not inode isolation: administrators must
not place hard links to sensitive files or untrusted bind mounts inside a jail.
Remote clients cannot create hard links or mount filesystems through these APIs.

`CompletedUpload.FullFilePath` is an informational pathname, not a stable
filesystem handle. If a retained jail directory is renamed, the reported path
may be stale even though the upload was safely written through the original
directory FD; consumers must not use this string as an authorization boundary.

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

`Config.SSHMaxChannels` limits simultaneous session channels on each SSH
connection. The default is 16; non-positive values also select that default.
Extra channels are rejected without closing existing sessions, and closing a
channel releases its slot.

## Resource and authentication limits

New servers enforce finite limits even when `Config` is constructed directly.
Non-positive values select these defaults. Tune positive values to the process
and filesystem capacity before calling `NewServer`.

| Configuration | Default | Scope |
| --- | --- | --- |
| `MaxConnections` / `MaxConnectionsPerIP` | 128 / 32 | All SFTP and FTP control connections, including unauthenticated clients |
| `FTPAuthTimeout` | 30 seconds | Absolute login window; unauthenticated `NOOP`, `USER`, and `REIN` do not extend it |
| `SFTPMaxHandles` / `SFTPMaxHandlesPerUser` / `SFTPMaxHandlesPerSession` | 256 / 64 / 32 | Files and directories; the session budget covers every channel on one SSH connection |
| `FtpMaxPassiveListeners` / `FtpMaxPassiveListenersPerUser` / `FtpMaxPassiveListenersPerIP` | 64 / 2 / 8 | Outstanding passive-port reservations |
| `MaxFileBytes` / `MaxTransferBytes` | 200 GiB / 200 GiB | Logical file size and bytes written per upload handle, including repeated-offset writes |
| `MaxJailBytes` / `MaxJailEntries` | 1 TiB / 1,000,000 | Cumulative logical regular-file bytes and directory entries, including directories |
| `HTTPMaxUploadBytes` / `HTTPMaxUploadParts` | 200 GiB / 1,000 | Entire multipart body and all parts |
| `HTTPMaxConcurrentRequests` | 32 | Requests executing across every `HttpIngest` handler created from one server |
| `HTTPMaxAuthorizationBytes` | 4,096 | Raw `Authorization` header, before Basic-auth decoding |
| `HTTPMaxUsernameBytes` / `HTTPMaxPasswordBytes` | 256 / 1,024 | Decoded HTTP Basic-auth credentials |
| `FTPMaxAuthFailures` | 5 | Credential failures across `USER`/`REIN` changes on one FTP connection |

Connection overload closes new sockets before starting a handler. Handle
overload rejects the open before creating or truncating a file. Closing a
handle or tearing down its channel returns its permit. FTP logout starts a new
absolute login window; successful authentication stops the timer. The SSH
handshake also has an absolute 30-second deadline.

`AuthLimits` configures shared token buckets for SSH, FTP, and HTTP. Defaults
allow bursts of 200 attempts globally, 30 per source IP, and 20 per username,
refilling one token every 10 ms, one second, and one second respectively.
Three failed credential checks start a 250 ms retry cooldown, doubling up to
30 seconds. Attempts during cooldown are rejected immediately. HTTP returns
`429` with `Retry-After`; FTP closes with `421` when throttled or its failure
limit is reached; SSH returns an authentication error. Admission is
transactional: the global, IP, username, and identity-table checks all succeed
before any token is consumed or identity entry is created. A successful login
clears only that username's failure state; it does not erase shared-IP
reputation. Failure and dropped-event logs are sampled. Identity tables are
bounded to 8,192 entries by default and expire idle entries. IPs come from the
transport peer, never `X-Forwarded-For`; proxied clients share the proxy's IP
budget unless a trusted gateway also controls admission.

Storage accounting is shared by users and protocols with the same root inode
in one `Server`. It scans existing contents when a root becomes active, counts
sparse file sizes, and keeps deleted files/directories charged while open
handles retain them. Concurrent writers cannot reserve the same free space.
Shrinking and deleting remain possible when existing usage exceeds a limit.
Root scans are bounded to depth 256 and the configured entry limit plus up to
10,000 entries; larger trees require administrator cleanup before login.
Quota failures do not generate upload-completion notifications.

**Filesystem byte and inode quotas are required for untrusted writers.**
Application limits do not cover physical allocation, external filesystem
writers, overlapping roots, or multiple server processes. Configure isolated
quota-controlled storage per tenant and leave capacity for the host. HTTP
callers must also configure server timeouts and a header-size limit. A transfer
that fails after writing starts may leave partial contents; use temporary upload
names and rename on success when an interrupted replacement must preserve the
old version.

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
control connection IP. This does not distinguish clients sharing a NAT;
require FTPS with `FtpRequireTLS` on untrusted networks. Passive reservations
expire `FtpDataAcceptTimeout` after `PASV`/`EPSV`, even without a transfer or
while receiving `NOOP`. Active dials use the same timeout. A negative value
disables only the active-dial deadline; passive reservations still expire after
30 seconds. Behind NAT or a port-forward, set `FtpPassiveAdvertisedIP` to the
external IPv4 address so the `PASV` reply advertises an address clients can
reach instead of the server's internal address.

A rejected source IP or FTPS ticket does not consume the passive listener:
the server keeps accepting within the setup deadline, up to 32 rejected peers.
User removal and forced shutdown cancel pending accepts, active dials, and
established data transfers even when the setup deadline is disabled. Control
reply writes, including streamed `STAT` listings, have a five-minute deadline.
After login, another `PASS` requires `USER` or `REIN` first. `AUTH TLS` clears
any previously configured data endpoint and EPSV/PBSZ/PROT state.

`STOR`/`APPE` send `150`, accept and validate the data peer (including FTPS
session binding), and only then open the destination. Failed data setup never
creates or truncates the target. A destination open failure is consequently
reported after `150`.

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
configs at startup.

The implementation covers the three FTPS implementation traps that are easy
to get wrong:

- **Buffered-bytes injection** — before replying `234` to `AUTH TLS`, the
  server stops the plaintext reader and verifies that no command or bytes are
  buffered, then starts the TLS handshake. A man-in-the-middle on the plaintext
  segment cannot pipeline attacker-controlled commands behind the legitimate
  `AUTH TLS` line. Rejections log only the command verb and byte count; a
  pipelined `PASS` argument is never logged.
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
httpServer := &http.Server{
    Addr:              ":8443",
    Handler:           mux,
    ReadHeaderTimeout: 10 * time.Second,
    ReadTimeout:       5 * time.Minute,
    WriteTimeout:      5 * time.Minute,
    IdleTimeout:       time.Minute,
    MaxHeaderBytes:    16 << 10,
}
log.Fatal(httpServer.ListenAndServeTLS("server.crt", "server.key"))
```

The endpoint accepts one or more files per request:

- **Method** — `POST` only; anything else is answered with `405` and an
  `Allow: POST` header.
- **Authentication** — HTTP Basic auth. The username and password are the
  **same** credentials used for SFTP/FTP/FTPS, validated with the same
  constant-time password comparison. A missing or wrong credential returns
  `401` with a `WWW-Authenticate` challenge. Raw authorization headers and
  decoded usernames/passwords are bounded before authentication; an oversized
  raw header returns `431` without being decoded. Because Basic auth sends the
  credential on every request, run this endpoint over TLS (your own
  `http.Server` or a TLS-terminating reverse proxy).
- **Browser protection** — every upload must send `X-Ironport-Upload: 1`,
  including command-line clients. Missing/invalid headers, cross-site Fetch
  Metadata, and disallowed/malformed `Origin` return `403` before authentication
  or filesystem changes. By default an Origin must match the direct request
  scheme and host. Behind TLS termination, set
  `config.HTTPAllowedOrigins = []string{"https://uploads.example.com"}` before
  `NewServer`. Requests without Origin remain supported with the custom header.
  Plain HTML forms cannot supply this header; browser clients must use
  `fetch`/XHR. This handler does not grant CORS preflights.
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
- **Multiple files** — repeating the `file` field with `FormData` or
  `curl -H 'X-Ironport-Upload: 1' -F file=@a -F file=@b` stores every part.
  Each file is written independently and announced
  separately, and one file's failure does not abort the others.
- **Success** — each file is stored (creating or overwriting) and streamed
  straight to disk (not buffered whole in memory or staged in a temp directory),
  and a `CompletedUpload` with `Protocol == "HTTP"` is announced per file on
  `CompletedUploads()`. The handler replies `201 Created` when at least one file
  was stored and none failed.
- **Partial/total failure** — if any file fails, the reply is an error status
  (`400` for client errors such as an invalid filename or no `file` part, `500`
  for a server-side write error, `507` for a storage quota) with a plain-text
  body listing each file's
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
curl -u alice:alicepw -H 'X-Ironport-Upload: 1' -F file=@./report.csv https://host:8443/upload

# Stored at <jail>/reports/2026/q2.csv; the reports/2026 directories are created.
curl -u alice:alicepw -H 'X-Ironport-Upload: 1' -F 'file=@./q2.csv;filename=reports/2026/q2.csv' https://host:8443/upload

# Several files in one request — each part is stored and announced separately.
curl -u alice:alicepw -H 'X-Ironport-Upload: 1' -F file=@./a.csv -F file=@./b.csv https://host:8443/upload
```

The handler limits each request to **200 GiB (200 × 2^30 bytes)**, **1000 multipart
parts**, and **32 concurrent requests** across all `HttpIngest` handlers
created from a server by default. Set positive `Config.HTTPMaxUploadBytes`,
`Config.HTTPMaxUploadParts`, and `Config.HTTPMaxConcurrentRequests` values
before `NewServer` to change those limits; zero or negative values select the
defaults. Saturation returns `503` with `Retry-After` before authentication or
body reads. Any rejection that leaves a body unread disables connection reuse
and stops further request reads before releasing its admission slot.
`HTTPMaxAuthorizationBytes`, `HTTPMaxUsernameBytes`, and
`HTTPMaxPasswordBytes` bound credentials. The body byte limit covers the whole
request, and the part limit includes skipped fields and invalid files. Exceeding
either returns `413` and stops reading. Earlier completed files remain stored
and are reported; an interrupted file may remain partially written and does not
emit a completion event. Application storage/transfer quotas return `507` and
also stop reading immediately. Configure read-header, read, write, and idle
timeouts plus `MaxHeaderBytes` on the HTTP server, and filesystem quotas as
described under resource limits above.

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

`AddUserKey` is additive and does not interrupt an authenticated session.
Removing an existing key with `RemoveUserKey` immediately terminates that
user's active SFTP/FTP sessions; removing a missing key is a no-op.

## Dynamic user management

```go
// Add or replace a user.
srv.AddUser("carol", ironport.UserInfo{
    Password: "carolpw",
    Root:     "/srv/sftp/carol",
    CanRead:  true,
    CanWrite: true,
})

// Remove a user and terminate their active SFTP/FTP sessions and FTP transfers.
srv.RemoveUser("carol")

// Remove all users without deleting any on-disk user data.
srv.RemoveAllUsers()
```

`AddUser` publishes replacement credentials before checking the root or writing
diagnostics, so a slow filesystem or logger cannot keep the previous credentials
valid. Root warnings include the checked user revision; superseded checks are
suppressed when detected. An effective `AddUser` replacement immediately
terminates that user's active SFTP/FTP sessions so credentials, permissions, and
jail changes cannot leave a stale authenticated snapshot. An equivalent
replacement preserves sessions. HTTP authentication is per request: changing or
removing a user rejects later authentication but does not cancel an upload that
was already authorized. The caller owns HTTP request cancellation and HTTP
server shutdown.

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
