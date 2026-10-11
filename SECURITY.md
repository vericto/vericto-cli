# Security Policy

Vericto is a security product. We take vulnerabilities seriously and
appreciate responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report it privately, by either channel:

- Email **security@vericto.com**.
- Open a private report on GitHub:
  [Report a vulnerability](https://github.com/vericto/vericto-cli/security/advisories/new)
  (Security tab → "Report a vulnerability"). Only the maintainers can see it.

Include:

- A description of the vulnerability and its impact.
- Steps to reproduce.
- The affected version (`vericto --version`) and how it was installed
  (npm, shell installer, Docker image, `cargo install`).
- Any suggested remediation.

You will receive an acknowledgement within **48 hours** and a status update
within **5 business days**.

## Scope

High-priority issues for the CLI include:

- **Credential exposure**: an API key, login code or OIDC token written,
  logged or sent anywhere other than the configured Vericto API over TLS.
- **Gate bypass**: a path where `vericto check` reports success for SQL it did
  not evaluate, outside an explicit `--allow-degraded`.
- **Supply chain**: a way to make an installer (npm, shell, Docker) run a binary
  other than the one the release published.

Issues in the SQL evaluation itself belong to
[vericto-engine](https://github.com/vericto/vericto-engine/security).

## Verifying what you install

Release artifacts ship SHA-256 checksums and build provenance attestations;
see [Verifying a download](README.md#verifying-a-download).

## Disclosure process

1. Report received and acknowledged (within 48h).
2. We confirm and assess severity.
3. We develop and test a fix.
4. We release the fix and credit you (unless you prefer to remain anonymous).
5. Public disclosure after users have had reasonable time to update.

## Supported versions

Security fixes are applied to the latest released version. Older versions are
patched at the maintainers' discretion.

Thank you for helping keep Vericto and its users safe.
