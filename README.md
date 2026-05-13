# sftpserver

A production-ready, embeddable SFTP server library for Go with a security-first design.

## Features

- **SSH public-key and password authentication** — both methods use constant-time comparisons to prevent username enumeration via timing side-channels
- **Per-user jail (chroot)** — each user is confined to a configurable root directory; path traversal and symlink escapes are blocked
- **Fine-grained permissions** — independent `CanRead` / `CanWrite` flags per user
- **Dynamic user management** — add, remove, and update users and their authorized keys at runtime without restarting the server
- **Upload notifications** — a buffered `CompletedUploads` channel delivers a `CompletedUpload` struct (username, full on-disk path, jail-relative path, and client IP) for every successfully closed upload
- **Graceful shutdown** — `Close()` stops the listener; in-flight sessions are not terminated
- **Thread-safe** — all shared state is protected by `sync.RWMutex`
- **Handshake timeout** — connections that do not complete the SSH handshake within 30 seconds are dropped
- **Idle-session timeout** — configurable via `Server.IdleTimeout` (default 15 minutes); inactive authenticated SFTP sessions are reaped
- **Empty-password protection** — users whose stored `Password` is empty cannot authenticate via password, and empty supplied passwords are always rejected
- **Chown opt-in** — `Setstat`/`Fsetstat` requests that try to change file ownership (uid/gid) are rejected with a permission error unless `Server.AllowChown` is explicitly set to `true`. Symlink creation by clients is always refused so a planted link cannot be followed to escape the jail.

## Quick start

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "log"

    "github.com/define42/sftpserver"
    "golang.org/x/crypto/ssh"
)

func main() {
    users := map[string]sftpserver.UserInfo{
        "alice": {Password: "alicepw", Root: "/srv/sftp/alice", CanRead: true, CanWrite: true},
        "bob":   {Password: "bobpw",   Root: "/srv/sftp/bob",   CanRead: true, CanWrite: false},
    }

    // Load a stable host key from disk; fall back to an ephemeral key for demos.
    signer, err := sftpserver.NewSignerFromFile("/etc/ssh/sftp_host_key")
    if err != nil {
        priv, _ := rsa.GenerateKey(rand.Reader, 3072)
        signer, _ = ssh.NewSignerFromKey(priv)
    }

    // ftpAddr is "" to disable the (plaintext) FTP listener.
    srv := sftpserver.NewServer(":2022", "", "", users, signer)

    // Drain upload notifications in the background.
    go func() {
        for ev := range srv.CompletedUploads {
            log.Printf("upload complete: user=%q ip=%q path=%q full=%q",
                ev.Username, ev.ClientIP, ev.FilePath, ev.FullFilePath)
        }
    }()

    log.Fatal(srv.ListenAndServe())
}
```

### Configuring the upload-notification buffer size

`NewServer` creates `CompletedUploads` with a buffer of 64. To use a different
capacity, replace the field with a channel of the desired size **before**
starting the consumer goroutine:

```go
srv := sftpserver.NewServer(":2022", "", "", users, signer)
srv.CompletedUploads = make(chan sftpserver.CompletedUpload, 256)

go func() {
    for ev := range srv.CompletedUploads {
        // handle ev
    }
}()

log.Fatal(srv.ListenAndServe())
```

When constructing a `Server` via a struct literal instead of `NewServer`,
set `CompletedUploadsSize` and leave `CompletedUploads` nil — `ListenAndServe`
will initialise the channel automatically with that capacity:

```go
srv := &sftpserver.Server{
    Addr:                 ":2022",
    Signer:               signer,
    Users:                users,
    CompletedUploadsSize: 256,
}
log.Fatal(srv.ListenAndServe())
```

## FTP support (plaintext, opt-in)

This package also exposes a passive-mode FTP listener that shares the SFTP
user database, jails, and permission flags. **FTP transmits credentials and
data in the clear and this server does not implement FTPS.** FTP is therefore
disabled by default; enable it only on a trusted network segment where you
control all clients and intermediate hops:

```go
srv := sftpserver.NewServer(":2022", ":2121", "5000-5010", users, signer)
```

When FTP is enabled, only passive mode (`PASV` / `EPSV`) is supported; active
mode (`PORT` / `EPRT`) is refused, and the data connection peer IP is checked
against the control connection to prevent passive-port stealing.

## Public-key authentication

Add one or more public keys to a user's `AuthorizedKeys` field at construction time, or use the `AddUserKey` / `RemoveUserKey` helpers at runtime:

```go
// At construction.
users["alice"] = sftpserver.UserInfo{
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
srv.AddUser("carol", sftpserver.UserInfo{
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

## Host key

Use `NewSignerFromFile` to load a PEM-encoded RSA, ECDSA, or Ed25519 private key:

```go
signer, err := sftpserver.NewSignerFromFile("/etc/ssh/sftp_host_key")
```

## Running the example binary

```sh
go run ./cmd/sftpserver -host-key /path/to/host_key
```

If `-host-key` is omitted a fresh RSA-3072 key is generated on every start (not suitable for production, as clients will see a different host key each time).

## License

See [LICENSE](LICENSE) for details.
