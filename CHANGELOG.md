# Changelog

All notable changes to ironport should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). While the
major version is `v1`, exported Go APIs are backward compatible across minor
and patch releases; breaking API changes require a major version bump.

## Unreleased

- Fixed a false `CompletedUploads` event when a hidden directory was renamed
  (for example `/.staging` to `/staging`): the leading dot marked the source as
  a deferred upload, so the rename was announced even though the destination is
  a directory. The rename completion is now only announced when the destination
  is a regular file.
- Hardened the `AUTH TLS` upgrade against a buffered-bytes race: the reader
  is now stopped and the channel-clean check runs *before* the `234` reply,
  so the client's post-`234` TLS `ClientHello` can never be consumed (or
  hidden) by the control reader.
- Made the public-key auth timing pad symmetric: padding iterations now
  perform the same SHA-256 + constant-time compare as real iterations, so
  response time no longer scales with a user's key count and an unknown user
  is indistinguishable from a user with keys.
- SFTP session goroutines spawned per channel are now tracked with a
  `WaitGroup` so a connection handler does not return — and `Shutdown` cannot
  complete — while jailed filesystem operations are still in flight.
- Added `Config.FtpPassiveAdvertisedIP` to override the IPv4 address sent in
  the `PASV` reply, for deployments behind NAT or a port-forward.
- `deriveFTPTLSConfigs` now fails fast (surfaced at `ListenAndServe`) if the
  system CSPRNG fails while generating the shared session-ticket key, instead
  of silently breaking `PROT P` session resumption.
- The FTP control idle timeout now sends a `421` reply before closing the
  connection instead of dropping it silently.
- `STOR`/`APPE` now open the destination file before sending `150` and
  accepting the data connection, so an open failure is reported before the
  client starts streaming.
- The accept loop now caps consecutive non-transient `Accept` errors so a
  permanently poisoned listener fd no longer spins and logs forever, while
  transient errors (timeouts, `EMFILE`/`ENFILE`, …) are still retried.
- `ALLO` size verification now accounts for the `REST` restart offset so a
  correct resumed `STOR` is not rejected as a size mismatch.
- Fixed `statFileInfo.ModTime` to compile on 32-bit Linux (arm, 386).
- Added explicit FTPS support (RFC 4217). Set `Config.FtpTLSConfig` to enable
  the `AUTH TLS`, `PBSZ`, and `PROT` commands on the FTP listener; set
  `Config.FtpRequireTLS` to refuse `USER`/`PASS` until the control connection
  is wrapped in TLS. `PROT P` data connections are TLS-wrapped using a
  derived config that requires session resumption from the control channel
  (defense against data-channel hijack), the buffered-bytes injection attack
  against `AUTH TLS` is detected and the connection torn down, and every
  TLS-wrapped data transfer is half-closed with `close_notify` so clients
  can distinguish a complete transfer from a truncated one.

## v1.0.10 - 2026-05-14

- Added unit tests for recent SFTP/FTP behavior.

## v1.0.9 - 2026-05-14

- Added config-based server construction with `DefaultConfig`.
- Added ephemeral host-key generation when `config.Signer` is nil.
- Renamed the runnable example command to `cmd/ironport-demo` and clarified
  that it is not an operator-ready production binary.
- Added project security and contribution documentation.
- Added a main-branch release workflow that bumps the next SemVer tag and
  creates a GitHub Release.
- Moved SSH algorithm pinning onto `Config` fields.
- Moved temp-extension handling and idle timeout configuration onto
  `Config`.
- Moved chown opt-in configuration onto `Config`.
- Added `CompletedUpload.Protocol` to distinguish SFTP and FTP uploads.
