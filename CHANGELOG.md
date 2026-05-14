# Changelog

All notable changes to ironport should be documented in this file.

This project uses semantic versioning once releases are tagged. Until then,
changes are tracked under `Unreleased`.

## Unreleased

- Added config-based server construction with `DefaultIronportConfig`.
- Added ephemeral host-key generation when `config.Signer` is nil.
- Renamed the runnable example command to `cmd/ironport-demo` and clarified
  that it is not an operator-ready production binary.
- Added project security and contribution documentation.
- Added a main-branch release workflow that bumps the next SemVer tag and
  creates a GitHub Release.
- Moved SSH algorithm pinning onto `ironportConfig` fields.
- Moved temp-extension handling and idle timeout configuration onto
  `ironportConfig`.
- Moved chown opt-in configuration onto `ironportConfig`.

## Releases

No tagged releases yet.
