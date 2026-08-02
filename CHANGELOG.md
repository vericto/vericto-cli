# Changelog

All notable changes to the Vericto CLI are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-02

### Added
- **Inline SQL**: `vericto check --sql "UPDATE * FROM payments"` (short `-e`,
  repeatable) evaluates a statement without a file or stdin pipe. Mutually
  exclusive with files / --changed / --stdin-file-list; labelled `<inline>`
  in reports and subject to the workspace's raw/sanitized telemetry mode.
- **Update nudge**: `check` warns (stderr) when this CLI is older than the
  backend's minimum supported version, with the command to update — no
  self-`update` command (npm / the installer own the binary).

### Fixed
- The `GET /ci/config` pre-flight now retries 429/5xx (honoring Retry-After)
  instead of falling through to "proceed without sanitization" — so a
  transient rate-limit can't leak unsanitized literals for a `sanitized`
  workspace.

### CI
- The release pipeline now publishes the npm package automatically (custom
  publish job gated by the `prod` environment). Package docs point at the
  `vericto/` org; broken `DESIGN.md` link fixed.

## [1.1.0] - 2026-08-01

First release since 1.0.0. It ships work that had already landed on `main` but
was never in a published binary — most importantly **browser-based login**
(the 1.0.0 binary still prompts you to paste an API key).

### Added
- **Browser-based `vericto login`** (the default for a developer at a keyboard):
  with no flags it opens the dashboard's `/cli-auth` page, and the
  already-signed-in session mints a scoped, 30-day key handed back via a
  local loopback callback — nothing is typed or pasted. `--api-key` (verified
  before saving) and `--oidc` remain for CI / headless use.
- **`vericto rules`** — inspect the workspace's effective rule catalogue
  (`rules list`, `rules show <CODE>`).
- **`vericto baseline prune`** — drop baseline entries that no longer match any
  finding.
- A `vericto-cli/<version>` **User-Agent** on every request, so the backend can
  attribute CI checks to the CLI and its version.

### Changed
- `--api-key` login now **verifies the key against the backend before writing
  it to disk** — an invalid/revoked/wrong-scope key is caught immediately
  instead of on the first `check` mid-pipeline.
- Clearer `--help` text for end users.

### Fixed
- `PARSE_ERROR` findings now show a plain, self-explanatory message
  ("Could not parse this SQL — skipped, not blocked …") instead of the
  confusing `VERICTO [PARSE_ERROR] — PARSE_ERROR`.

## [1.0.0] - 2026-07-16

Initial public release: `vericto check` (files/stdin, `--changed` for CI),
SARIF / GitLab output formats, `doctor`, `init`, `verify-receipt`, and static
API-key / env-based auth. Distributed as prebuilt binaries and the
`@vericto/vericto-cli` npm package.

[1.2.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.2.0
[1.1.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.1.0
[1.0.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.0.0
