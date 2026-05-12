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

## Quick start

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "log"

    "github.com/define42/sftpserver/internal/sftpserver"
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

    srv := sftpserver.NewServer(":2022", users, signer)

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
```

## Host key

Use `NewSignerFromFile` to load a PEM-encoded RSA, ECDSA, or Ed25519 private key:

```go
signer, err := sftpserver.NewSignerFromFile("/etc/ssh/sftp_host_key")
```

## Running the example binary

```sh
go run . -host-key /path/to/host_key
```

If `-host-key` is omitted a fresh RSA-3072 key is generated on every start (not suitable for production, as clients will see a different host key each time).

## License

See [LICENSE](LICENSE) for details.
