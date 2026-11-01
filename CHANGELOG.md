# Changelog

All notable changes to ironport should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). While the
major version is `v1`, exported Go APIs are backward compatible across minor
and patch releases; breaking API changes require a major version bump.

## Unreleased

- SFTP read/write handles now dispatch reads to the file reader instead of
  writing zero-filled response buffers into the file. Combined handles retain
  write-only account compatibility while denying their read attempts.

- Authentication limits now use bounded, privately hashed source and username
  buckets, preventing identity-table saturation from rejecting every new
  identity. Collisions share limits conservatively without evicting active
  penalties. Configured and unknown usernames consume the same budgets, so
  adding or removing an account cannot bypass its cooldown.
  **Behavior change:** source limits now group IPv6 addresses by `/64`; IPv4
  remains per address. Successful logins clear username backoff only when all
  retained failures belong to that username; unsigned key queries cannot change
  failure ownership. Each bucket forgets one failure per `BackoffMax` without
  another failure, so penalties left by a finished attack fade even while
  legitimate logins keep the bucket active; steady failures still hold maximum
  backoff. Idle expiry also waits until every failure has decayed, so an
  `EntryTTL` close to `BackoffMax` no longer lets an attacker restart backoff by
  pausing. Authentication retains its original admission through dynamic user
  changes and SSH key proof. Public API signatures and configuration fields are
  unchanged.

- SSH key eligibility rejections no longer advance username or shared-IP
  credential-failure backoff, allowing clients to offer multiple keys before the
  authorized one. Key offers still consume admission tokens, and existing
  rejected-key authentication events remain unchanged. Password and verified-key
  completion failures continue to advance backoff. Public APIs are unchanged.

- Escape usernames and jail roots in SFTP/FTP login logs, usernames in FTP
  active-data dial logs, and HTTP upload-error text to prevent log injection.

- SSH public-key queries now check key eligibility without opening a jail or
  emitting root-open diagnostics. The jail is opened only after signature
  verification, using the current user configuration. Shared throttling,
  one-use query admission, and final revision checks remain enforced. Public
  API signatures are unchanged.

- Enabled FTP now rejects `FtpRequireTLS` without `FtpTLSConfig` before opening
  listeners. Unused FTP TLS configuration errors no longer prevent SFTP startup
  when FTP is disabled, including whitespace-only `FtpAddr` values.

- Added `Server.ValidateJailRoots()` and advisory root warnings at listener
  startup, HTTP handler creation, and `AddUser`. Missing or invalid user roots
  do not block startup or registration, allowing later provisioning. Root-open
  authentication failures now have escaped, sampled server-side explanations;
  client replies and authentication-event reasons stay generic. Temporary
  capability-probe failures during HTTP handler creation are retried on requests.
  Existing public API signatures are unchanged.

- Jailed `MkdirAll` now verifies every path component is a directory, including
  the final component. Existing files and symlinks are rejected instead of
  treating their `EEXIST` result as success.

- Temporary `openat2` capability-probe failures, such as descriptor exhaustion,
  no longer prevent all subsequent jail opens. Only success and `ENOSYS` are
  cached; other errors are returned to the caller and retried on the next check.

- SFTP handles now retain write errors, including append failures, so a later
  successful `CLOSE` does not emit a false `CompletedUploads` event. Successful
  writes after a failure do not clear that handle's failed-upload state.

- File reads, writes, truncation, and chmod now validate a pinned inode before
  opening it for I/O, rejecting FIFOs, sockets, and devices without triggering
  their open behavior. Existing files are reopened through `/proc/self/fd`, and
  truncation follows a successful open; normal file-lease waits are preserved.
  Chmod continues to support directories. **Deployment requirement:** an
  accessible, trusted procfs at `/proc/self/fd` is now required for descriptor
  reopening. Exported Go API signatures are unchanged.

- Jail roots are opened securely during authentication and retained through the
  SSH/FTP session or HTTP request. All SFTP channels share the authenticated
  root, so later path replacement cannot redirect access. Relative roots keep
  their reporting path consistent during concurrent working-directory changes.
  Configured root paths now reject symlinks in any component and literal `..`
  components; deployments using these must supply a direct directory path.
  Public API signatures are unchanged.

- SFTP directory reads and FTP `STAT` now stream entries with bounded memory,
  matching the existing FTP `LIST`/`MLSD` behavior. SFTP directory handles keep
  an open jailed cursor instead of a full snapshot, and release the descriptor
  and handle permit on `CLOSE` or session teardown. `STAT` retains its multiline
  format and complete-reply write deadline; failures after the reply starts
  close the control session. Public API signatures are unchanged.

- Hardened FTP control and data setup: rejected pre-TLS command logs omit
  passwords and other arguments; complete control replies have a five-minute
  write deadline, with failed writes closing the session and cancelling data
  operations. Passive endpoints retry rejected IPs and FTPS handshakes within
  their original reservation deadline, capped at 32 rejections. `AUTH TLS`
  also clears `EPSV ALL`, `PBSZ`, and `PROT` state. Public API signatures are
  unchanged.

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
