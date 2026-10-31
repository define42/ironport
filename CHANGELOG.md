# Changelog

All notable changes to ironport should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). While the
major version is `v1`, exported Go APIs are backward compatible across minor
and patch releases; breaking API changes require a major version bump.

## Unreleased

- Security fixes: FTP `STOR`/`APPE` now validate the data connection, including
  FTPS session binding, before any destination create/truncate. Open failures
  now follow `150`; failed data setup preserves existing files.
- Added global/per-IP connection caps, an absolute FTP login timeout, absolute
  SSH handshake timeout, and global/per-user/per-connection SFTP file/directory
  handle limits. Passive reservations expire from `PASV`/`EPSV` and have
  global/per-user/per-IP caps. A negative `FtpDataAcceptTimeout` no longer
  disables passive reservation expiry.
- Added cumulative jail byte/entry quotas and per-file/per-upload limits shared
  by SFTP, FTP, and HTTP, including existing contents and open deleted files.
  Defaults are 200 GiB per file/upload and 1 TiB / 1,000,000 entries per jail.
  Filesystem byte/inode quotas remain required. The HTTP default body limit is
  reduced from 1 TB to 200 GiB; see README for all defaults.
- Added bounded shared IP/username/global authentication throttling, retry
  cooldowns, FTP failure limits, and sampled failure logs. HTTP throttling
  returns `429` with `Retry-After`. Admission now checks global, IP, username,
  and identity-table capacity before debiting tokens or creating entries, so a
  locally rejected attempt cannot consume global capacity or fill the table.
  Successful authentication clears username failure state without resetting
  shared-IP reputation.
- HTTP clients must now send `X-Ironport-Upload: 1`. Cross-site Fetch Metadata
  and disallowed Origin headers are rejected before authentication or writes.
  TLS-terminating proxies must configure `HTTPAllowedOrigins` for browser
  uploads. Updated examples include the required header.
- Bounded authenticated resource use: SSH now defaults to at most 16 session
  channels per connection (`SSHMaxChannels`), and HTTP uploads default to a
  200 GiB request body, 1000 multipart parts, and 32 concurrent requests shared
  across a server's handlers. Raw Basic-auth headers and decoded credentials
  have independent limits before password verification. Concurrency saturation
  returns 503, oversized headers return 431, and body/part excess returns 413
  without draining the rejected body. Early rejections terminate unread bodies
  before releasing admission, preventing post-handler drain pileups. Earlier
  files remain stored, while an
  interrupted file may remain partial without a completion event. The demo now
  uses an explicit `http.Server` with header/read/write/idle deadlines and
  `MaxHeaderBytes`. SFTP directory reads and FTP `STAT` stream entries in
  bounded batches.
- FTP user removal, forced shutdown, and control disconnect now cancel passive
  listeners, active dials, TLS handshakes, and data transfers. Rejected passive
  peers no longer consume the listener; acceptance retries within the configured
  deadline and a 32-rejection cap. Queued commands are discarded on cancellation.
  Control replies have a five-minute write deadline. `AUTH TLS` resets data
  endpoints and EPSV/PBSZ/PROT state; duplicate authenticated `PASS` is rejected.
- File transfers validate an `O_PATH`-pinned inode before opening it for I/O,
  avoiding FIFO/device open side effects while allowing normal file-lease waits.
  Existing files are reopened through trusted `/proc/self/fd` without repeating
  the client pathname lookup; truncation follows successful reopening. `Chmod`
  uses the same type-first approach. `MkdirAll` rejects an existing non-directory
  final component.
- SSH authentication rejected by the final revision check now emits `LoginFailed`.
  `AddUser` publishes credentials before diagnostic I/O and tags warnings with
  the checked revision. `HttpIngest()` now validates initial roots, and
  `ValidateJailRoots()` exposes that deployment check. Required FTPS without
  a TLS configuration now fails startup only when FTP is enabled. Corrected
  user-removal documentation and clarified the separate lifetime of
  already-authorized HTTP requests.
- Hardened configured jail roots against symlink and pathname-replacement
  redirection. Each root is now atomically opened with
  `openat2(RESOLVE_NO_SYMLINKS)`, validated as a directory, and retained by
  file descriptor for subsequent SFTP, FTP/FTPS, or HTTP operations. A symlink
  in any component of the configured root path now rejects authentication, and
  replacing the pathname after authentication cannot redirect the active jail.
  Deployments that previously configured a symlink as a jail root must instead
  configure the real directory path. `CompletedUpload.FullFilePath` remains an
  informational pathname and may become stale if that directory is renamed.
  Jail roots containing a `..` component are now rejected, whether relative
  or absolute; configure an equivalent normalized path instead. `AddUser`
  and server startup log a warning when a root cannot be opened, and a login
  rejected for that reason is logged server-side (clients still see a generic
  auth failure). Transient `openat2` probe errors are retried instead of being
  cached for the process lifetime.
- Closed an in-flight authentication revocation race. Authentication snapshots
  now carry a fresh per-user revision, SSH commits that revision atomically
  after its handshake, and FTP commits it before reporting login success.
  Removing or changing a user's credentials, root, or permissions before that
  commit rejects the stale login. Effective `AddUser` replacements and
  `RemoveUserKey` removals now close the user's established SFTP/FTP sessions;
  equivalent replacements and missing-key removals preserve them. `AddUserKey`
  remains additive and non-disruptive. Equivalent `AddUser` updates preserve
  the revision, including reparsed or reordered authorized keys;
  remove-and-readd still invalidates prior authentication.
- Added an HTTP upload endpoint: `Server.HttpIngest()` returns an
  `http.HandlerFunc` that callers mount on their own router. It accepts a
  `multipart/form-data` POST with the file under the `file` field (`key=file`),
  authenticates with HTTP Basic auth using the same credentials and
  constant-time password comparison as SFTP/FTP/FTPS, requires `CanWrite`, and
  streams the file into the user's `openat2` jail. A nested upload name such as
  `reports/2026/q2.csv` is stored at that path, creating any missing parent
  directories (via a new jailed `MkdirAll`); `..` segments are collapsed and
  contained within the jail. A request may carry several `file` parts (a
  standard multi-file form); each is stored independently and announced
  separately, the reply is `201` only when all succeed, and on any failure an
  error status carries a per-file summary so partial failures are never silent.
  Successful uploads are announced on `CompletedUploads()` with the new
  `CompletedUploadProtocolHTTP` (`"HTTP"`) protocol and honour
  `TempExtensions`/dotfile deferral; auth outcomes are reported on
  `AuthEvents()`. The endpoint runs no listener of its own, so TLS termination
  and routing stay with the caller.
- Fixed a false `CompletedUploads` event when a hidden directory was renamed
  (for example `/.staging` to `/staging`): the leading dot marked the source as
  a deferred upload, so the rename was announced even though the destination is
  a directory. The rename completion is now only announced when the destination
  is a regular file.
- Hardened the `AUTH TLS` upgrade against a buffered-bytes race: the reader
  is now stopped and the channel-clean check runs *before* the `234` reply,
  so the client's post-`234` TLS `ClientHello` can never be consumed (or
  hidden) by the control reader. Rejected pipelined plaintext is logged only as
  its command verb and byte count, so a pipelined `PASS` argument is never
  disclosed.
- Made the public-key auth timing pad symmetric: padding iterations now
  perform the same SHA-256 + constant-time compare as real iterations, so
  response time no longer scales with a user's key count and an unknown user
  is indistinguishable from a user with keys.
- SFTP session goroutines spawned per channel are now tracked with a
  `WaitGroup` so a connection handler does not return — and `Shutdown` cannot
  complete — while jailed filesystem operations are still in flight.
- Added `Config.FtpPassiveAdvertisedIP` to override the IPv4 address sent in
  the `PASV` reply, for deployments behind NAT or a port-forward.
- FTPS session tickets now use a distinct key for each `AUTH TLS` control
  connection. A ticket obtained from another, even unauthenticated, control
  connection can no longer resume a victim's `PROT P` data connection when
  the clients share one source IP. Configs selected by `GetConfigForClient`
  are hardened with the same key and resumption check; custom
  `WrapSession`/`UnwrapSession` callbacks are rejected because they could
  bypass the binding.
- The FTP control idle timeout now sends a `421` reply before closing the
  connection instead of dropping it silently.
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
  per-control-session config and ticket key that require resumption from that
  exact control connection (defense against data-channel hijack), the
  buffered-bytes injection attack against `AUTH TLS` is detected and the
  connection torn down, and every TLS-wrapped data transfer is half-closed
  with `close_notify` so clients can distinguish a complete transfer from a
  truncated one.

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
