# ironport

A production-ready, embeddable SFTP server and FTP server library for Go with a security-first design.

## Features

- **SSH public-key and password authentication** — both methods use constant-time comparisons to prevent username enumeration via timing side-channels
- **Per-user jail (chroot)** — each user is confined to a configurable root directory. Every filesystem operation is performed via Linux `openat2` with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, so the kernel itself rejects path traversal and any symlink anywhere in the lookup
- **Fine-grained permissions** — independent `CanRead` / `CanWrite` flags per user
- **Dynamic user management** — add, remove, and update users and their authorized keys at runtime without restarting the server
- **Upload notifications** — a buffered `CompletedUploads()` stream delivers a `CompletedUpload` struct (username, full on-disk path, jail-relative path, and client IP) for every successfully closed upload
- **Temp-file aware completion** — optionally set `TempExtensions` on the server returned by `NewServer` (for example, `.tmp`, `.writing`) to suppress completion notifications for temporary upload names and emit the notification when the file is renamed to a non-temp name
- **Graceful shutdown** — `Close()` stops the listener immediately and lets in-flight sessions finish on their own. `Shutdown(ctx)` stops the listener AND waits for in-flight sessions to finish, force-closing any that remain when `ctx` expires
- **Thread-safe runtime APIs** — user-management helpers and listener lifecycle methods are safe to call while the server is running
- **Handshake timeout** — connections that do not complete the SSH handshake within 30 seconds are dropped
- **SSH algorithm pinning** — optionally constrain SSH key exchange, ciphers, MACs, and public-key auth signature algorithms
- **Idle-session timeout** — configurable via `IdleTimeout` on the server returned by `NewServer` (default 15 minutes); inactive authenticated SFTP sessions are reaped
- **Empty-password protection** — users whose stored `Password` is empty cannot authenticate via password, and empty supplied passwords are always rejected
- **Chown opt-in** — `Setstat`/`Fsetstat` requests that try to change file ownership (uid/gid) are rejected with a permission error unless `AllowChown` is explicitly set to `true` on the server returned by `NewServer`. Symlink creation by clients is always refused, and `Setstat`/`Fsetstat` requests that try to change access/modification times (`Chtimes`) are likewise rejected.

## Platform support

This package is **Linux-only**. The path-containment guarantee depends on the
`openat2` syscall with `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS`, available
since Linux 5.6. `ListenAndServe` probes for `openat2` at startup and
returns an error on older kernels rather than silently degrading the policy.

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
    config := ironport.DefaultIronportConfig()
    config.Addr = ":2022"
    config.Users = users
    if signer != nil {
        config.Signer = signer
    }
    srv := ironport.NewServer(config)

    // Drain upload notifications in the background.
    go func() {
        for ev := range srv.CompletedUploads() {
            log.Printf("upload complete: user=%q ip=%q path=%q full=%q",
                ev.Username, ev.ClientIP, ev.FilePath, ev.FullFilePath)
        }
    }()

    log.Fatal(srv.ListenAndServe())
}
```

### Configuring the upload-notification buffer size

Set `CompletedUploadSize` on the server config:

```go
config := ironport.DefaultIronportConfig()
config.Users = users
config.Signer = signer
config.CompletedUploadSize = 256
srv := ironport.NewServer(config)
```

Read upload notifications from the receive-only `CompletedUploads()` stream.
The underlying channel is internal, so callers cannot send to it, close it, or
replace it while the server is running. To change the buffer capacity, set a
different `CompletedUploadSize` before calling `NewServer`.

### Deferring completion notifications until final rename

Many clients upload to a temporary filename first (for example `file.txt.tmp`)
and rename to the final filename only after the upload is fully complete.
Configure `TempExtensions` to emit `CompletedUploads()` events at that final
rename boundary:

```go
config := ironport.DefaultIronportConfig()
config.Users = users
config.Signer = signer
srv := ironport.NewServer(config)
srv.TempExtensions = []string{".tmp", ".writing"}
```

With this setting:

- uploads that close with a temp extension are not announced yet
- renaming from a temp extension to a non-temp name emits the completion event

### Pinning SSH algorithms

Set `SSHAlgorithms` before starting the server to restrict SSH negotiation.
Nil fields keep the defaults from `golang.org/x/crypto/ssh`; non-nil fields
are used as allow-lists in the order supplied:

```go
config := ironport.DefaultIronportConfig()
config.Users = users
config.Signer = signer
srv := ironport.NewServer(config)
srv.SSHAlgorithms = ironport.SSHAlgorithms{
    KeyExchanges: []string{ssh.KeyExchangeCurve25519},
    Ciphers:      []string{ssh.CipherAES256CTR},
    MACs:         []string{ssh.HMACSHA256},
    PublicKeyAuthAlgorithms: []string{
        ssh.KeyAlgoED25519,
        ssh.KeyAlgoRSASHA256,
    },
}
```

For RSA host-key signature pinning, pass a signer already restricted with
`ssh.NewSignerWithAlgorithms`.

## FTP support (plaintext, opt-in)

This package also exposes a passive-mode FTP listener that shares the SFTP
user database, jails, and permission flags. **FTP transmits credentials and
data in the clear and this server does not implement FTPS.** FTP is therefore
disabled by default; enable it only on a trusted network segment where you
control all clients and intermediate hops:

```go
config := ironport.DefaultIronportConfig()
config.Users = users
config.Signer = signer
config.FtpAddr = ":2121"
config.FtpPassivePortRange = "5000-5010"
srv := ironport.NewServer(config)
```

When FTP is enabled, only passive mode (`PASV` / `EPSV`) is supported; active
mode (`PORT` / `EPRT`) is refused, and the data connection peer IP is checked
against the control connection to prevent passive-port stealing.

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
server cannot be restarted (construct a new one instead).

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := srv.Shutdown(ctx); err != nil {
    log.Printf("shutdown: %v", err)
}
```

Use `Close()` when you want the legacy behavior of closing the listener
without waiting for sessions to drain.

## Host key

Use `NewSignerFromFile` to load a PEM-encoded RSA, ECDSA, or Ed25519 private key:

```go
signer, err := ironport.NewSignerFromFile("/etc/ssh/sftp_host_key")
```

If `config.Signer` is nil, `ListenAndServe` generates an ephemeral in-memory
RSA-3072 host key and stores it on the server. This is convenient for demos, but
not suitable for production because clients will see a different host key after
each process restart.

## Running the example binary

```sh
go run ./cmd/ironport -host-key /path/to/host_key
```

If `-host-key` is omitted, `ListenAndServe` generates a fresh RSA-3072 key on
every start. This is not suitable for production, as clients will see a
different host key each time.
The example binary also accepts comma-separated `-ssh-key-exchanges`,
`-ssh-ciphers`, `-ssh-macs`, and `-ssh-public-key-auth-algorithms` flags.

## License

See [LICENSE](LICENSE) for details.
