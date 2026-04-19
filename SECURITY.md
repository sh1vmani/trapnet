# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in trapnet, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Send details to the repository owner via GitHub's private vulnerability reporting feature (Security tab > Report a vulnerability), or by email if that is not available.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The version of trapnet and Python you are running
- Your name or alias for credit (optional)

You can expect an acknowledgment within 72 hours. We will work with you on a fix and coordinate a disclosure timeline.

## Scope

The following are in scope:

- Remote code execution or privilege escalation via the honeypot service handlers
- Authentication bypass on the web dashboard
- Log injection that corrupts the SQLite database or JSON log
- Dependency vulnerabilities with a known exploit

The following are out of scope:

- Vulnerabilities that require physical access to the machine
- Denial of service against the honeypot itself (it is, by design, exposed to the internet)
- Social engineering

## Supported versions

Only the latest release on `main` is supported. We do not backport fixes.
