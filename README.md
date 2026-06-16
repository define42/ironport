# ironport


[![Go Report Card](https://goreportcard.com/badge/github.com/define42/ironport)](https://goreportcard.com/report/github.com/define42/ironport)
[![codecov](https://codecov.io/gh/define42/ironport/graph/badge.svg?token=RI5OKZU3DR)](https://codecov.io/gh/define42/ironport)
[![Build Status](https://github.com/define42/ironport/actions/workflows/test.yml/badge.svg)](https://github.com/define42/ironport/actions/)

A production-ready, embeddable SFTP server and FTP server library for Go with a security-first design. The production-ready claim applies to the library API; the command under `cmd/ironport-demo` is only a runnable demo.

## Features

- **SFTP and FTP/FTPS in one binary** — a single server hosts both protocols against the same user database, jails, and permission flags. FTPS (explicit TLS via `AUTH TLS`, RFC 4217) opt-in with `FtpTLSConfig`; pair with `FtpRequireTLS` to refuse plaintext logins entirely
- **SSH public-key and password authentication** — both methods use constant-time comparisons to prevent username enumeration via timing side-channels
- **Per-user jail (chroot)** — each user is confined to a configurable root directory. Every filesystem operation is performed via Linux `openat2` with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, so the kernel itself rejects path traversal and any symlink anywhere in the lookup
- **Fine-grained permissions** — independent `CanRead` / `CanWrite` flags per user
- **Dynamic user management** — add, remove, and update users and their authorized keys at runtime without restarting the server
- **Upload notifications** — a buffered `CompletedUploads()` stream delivers a `CompletedUpload` struct (protocol, username, full on-disk path, jail-relative path, and client IP) for every successfully closed upload
- **Auth notifications** — a buffered `AuthEvents()` stream delivers `LoginSuccess`, `LoginFailed`, and `Logout` events for SFTP and FTP sessions
- **Temp-file aware completion** — optionally set `TempExtensions` on the config (for example, `.tmp`, `.writing`) to suppress completion notifications for temporary upload names and emit the notification when the file is renamed to a non-temp name
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
control connection IP to prevent passive-port stealing. Passive listeners and
active dials wait up to `FtpDataAcceptTimeout`; set it negative to disable that
deadline. Behind NAT or a port-forward, set `FtpPassiveAdvertisedIP` to the
external IPv4 address so the `PASV` reply advertises an address clients can
reach instead of the server's internal address.

FTP and FTPS clients can read modification times with `MDTM` or the `modify`
fact in `MLST`/`MLSD`, and can set file modification times with `MFMT
YYYYMMDDHHMMSS path`.

### FTPS support (RFC 4217, explicit TLS)

Set `FtpTLSConfig` to a `*tls.Config` that carries the server certificate to
advertise `AUTH TLS`, `PBSZ`, and `PROT` over the FTP listener. Set
`FtpRequireTLS = true` to refuse `USER`/`PASS` until the control connection
has been upgraded — this is the recommended mode for any FTP listener that
faces an untrusted network.

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

The implementation covers the three FTPS implementation traps that are easy
to get wrong:

- **Buffered-bytes injection** — after replying `234` to `AUTH TLS`, the
  server verifies the receive buffer is empty before starting the TLS
  handshake. A man-in-the-middle on the plaintext segment cannot pipeline
  attacker-controlled commands behind the legitimate `AUTH TLS` line.
- **Data-channel binding** — `PROT P` data connections are required to
  resume the TLS session from the control channel; the server's
  data-connection `tls.Config` enforces `DidResume == true` via
  `VerifyConnection`. A peer that hijacks the data port cannot mount a
  fresh handshake with its own certificate.
- **Clean `close_notify` on transfers** — every TLS-wrapped data
  connection is half-closed with `CloseWrite` before the underlying
  socket is closed, so the client sees a proper TLS EOF and can
  distinguish a complete download from a truncated one.

Only explicit FTPS is supported; implicit FTPS (port 990, TLS from byte
zero) is intentionally not implemented. The `CCC` command is refused —
once TLS is negotiated, the session stays encrypted.

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

## Dynamic user management

```go
// Add or replace a user.
srv.AddUser("carol", ironport.UserInfo{
    Password: "carolpw",
    Root:     "/srv/sftp/carol",
    CanRead:  true,
    CanWrite: true,
})

// Remove a user (active sessions for that user are not terminated).
srv.RemoveUser("carol")

// Remove all users without deleting any on-disk user data.
srv.RemoveAllUsers()
```

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
