# Security Policy

ironport is a security-focused library. Please report suspected vulnerabilities
privately before opening a public issue or pull request.

## Reporting a Vulnerability

Email vulnerability reports to `define42@github.com`.

Please include:

- A description of the issue and affected component.
- Steps to reproduce, proof of concept, or a minimal test case when possible.
- The impact you believe the issue has.
- Any affected versions, commits, or deployment details you know.

You should receive an acknowledgement within 7 days. Please avoid public
discussion until a fix or mitigation is available.

## Supported Versions

Until ironport has tagged releases, security fixes are made on the default
branch. After releases are tagged, this policy should be updated to state which
release lines receive security fixes.

## Security-Sensitive Areas

Reports are especially welcome for:

- Jail escape, path traversal, symlink traversal, or `openat2` containment bugs.
- Authentication bypass or timing side-channel regressions.
- FTP/SFTP command handling that leaks server paths or permits response
  injection.
- Upload completion behavior that reports partial or failed writes as complete.
- Denial-of-service issues that allow unbounded resource consumption.

