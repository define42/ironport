# Contributing

Thanks for helping improve ironport.

## Security Issues

Do not open public issues for suspected vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.

## Development

Before sending a change:

- Run `go test ./...`.
- Keep security-sensitive behavior covered by focused tests.
- Keep public API changes reflected in `README.md`.
- Add notable user-facing changes to `CHANGELOG.md`.

## Pull Requests

Pull requests should describe:

- The behavior being changed.
- Any security implications or threat-model assumptions.
- Tests that were added or run.
- Compatibility impact for embedders.

For changes touching jail containment, authentication, path handling, upload
completion, FTP reply text, or listener lifecycle, include regression tests when
practical.

## Demo Command

`cmd/ironport-demo` is a runnable library demo. It is not intended to become an
operator-ready server. Production deployments should embed the library and
provide their own user source, logging, metrics, health checks, process
supervision, and stable host-key management.

