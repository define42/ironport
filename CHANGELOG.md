# Changelog

All notable changes to ironport should be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). While the
major version is `v1`, exported Go APIs are backward compatible across minor
and patch releases; breaking API changes require a major version bump.

## Unreleased

No unreleased changes.

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
