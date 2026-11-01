# Changelog

All notable changes to ironport should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). While the
major version is `v1`, exported Go APIs are backward compatible across minor
and patch releases; breaking API changes require a major version bump.

## Unreleased

- FTP `STOR`/`APPE` now validate the data connection, including FTPS session
  binding, before creating or truncating the destination. Failed data setup
  preserves existing files and does not create new ones. Destination-open and
  restart-offset errors now follow the `150` reply and data setup; failed
  transfers do not emit `CompletedUploads` events.

- User changes now invalidate pending authentication snapshots. SSH and FTP
  atomically check the user revision when registering an authenticated
  connection, closing the race with removal, replacement, and remove/re-add.
  Effective `AddUser` replacements and `RemoveUserKey` removals also close
  existing SFTP/FTP sessions and FTP data operations. Equivalent replacements,
  missing-key removals, and additive `AddUserKey` calls preserve established
  sessions. Already-authorized HTTP uploads continue. Public API signatures
  are unchanged.

- Added configurable resource limits for combined SFTP/FTP control connections
  (128 total, 32 per IP), SSH channels (16 per connection), SFTP file/directory
  handles (256 total, 64 per user, 32 per connection), passive FTP reservations
  (64 total, 2 per user, 8 per IP), and HTTP ingest requests (32 per server).
  Settings are grouped under `Config.ResourceLimits` (`ResourceLimitConfig`),
  including `SFTPMaxHandlesPerConnection` for the budget shared by SSH channels.
  Zero or negative settings select finite defaults. Overload is rejected before
  expensive work, and teardown returns admission capacity.
- Added `Config.Validate()` for authentication-limit bounds. Invalid settings
  prevent listener startup and make HTTP ingest fail with `503`; explicit
  identity-table and backoff maximums are never silently enlarged. Added typed
  `AuthEvent.Reason` values for credential failures and throttling. Throttled
  events are sampled, including when the event queue has room.
- Added `WithHTTPControl(http.Handler)` for use outside middleware that hides
  optional response-writer interfaces. It preserves request-specific deadline
  controls, so rejected slow HTTP bodies close before cleanup escapes admission
  limits. Middleware forwarding only Hijacker falls back to closing HTTP/1
  connections; missing controls produce a sampled integration diagnostic. The
  demo installs the wrapper, and HTTP/2 rejections preserve other streams.
- Authentication-table expiry now retains depleted buckets and active cooldowns;
  a long configured refill interval can no longer be shortened by idle expiry.
- HTTP admission now covers the complete request body, including multipart
  epilogues, while preserving keepalive after full body consumption. SSH
  public-key login consumes one token per bucket for query and proof together,
  with credential/backoff rechecks at proof and fresh admission on retries.
- Added absolute 30-second SSH/FTP login deadlines, passive reservation expiry
  from PASV/EPSV, and shared server/IP/username authentication throttling across
  protocols. Repeated failures trigger bounded exponential cooldown; FTP also
  caps failures per connection. HTTP credentials are size-bounded, and early
  rejections stop body reads. The HTTP demo now includes read/write/idle
  timeouts and a header-size cap. Negative `FtpDataAcceptTimeout` disables only
  active-mode dial deadlines; passive reservations remain finite. These finite
  defaults can reject work that was previously admitted without a limit.

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
