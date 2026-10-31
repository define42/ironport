//go:build linux

// Package ironport provides an embeddable, security-hardened SFTP and FTP server.
//
// Core features:
//
//   - Per-user jail roots enforced via path resolution and symlink checks.
//   - Password and SSH public-key authentication with constant-time comparisons.
//   - Fine-grained CanRead / CanWrite per-user permission flags.
//   - Runtime user management (AddUser, RemoveUser, RemoveAllUsers, AddUserKey, RemoveUserKey).
//   - Optional SSH algorithm pinning for key exchange, ciphers, MACs, and public-key auth signatures.
//   - Graceful shutdown via Close; upload-completion notifications via CompletedUploads;
//     authentication/session notifications via AuthEvents.
//   - Optional FTP listener sharing the same users, jails, permissions,
//     temp-extension handling, CompletedUploads stream, and AuthEvents stream as SFTP.
//     FTP uses passive mode by default; active mode can be enabled explicitly.
//   - Optional FTPS (RFC 4217 explicit TLS via AUTH TLS) over the FTP
//     listener. Set Config.FtpTLSConfig to enable it and Config.FtpRequireTLS
//     to require protected login and data channels.
//
// Typical usage:
//
//	cfg := ironport.DefaultConfig()
//	cfg.SftpAddr = ":2022"
//	cfg.FtpAddr = ":2121"
//	cfg.Users = users
//	cfg.SftpSigner = signer
//	srv := ironport.NewServer(cfg)
//	log.Fatal(srv.ListenAndServe())
package ironport
