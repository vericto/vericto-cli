# Changelog

All notable changes to the Vericto CLI are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.2] - 2026-08-03

### Added
- **Legible failure summary on blocked runs.** When `check` fails the gate, the
  CLI now prints a human-readable summary to **stderr** regardless of
  `--format`/`--output` — previously a `--format sarif --output file` run left
  the console showing only a bare `exit code 1`, which read like a crash rather
  than an enforced rule. The summary lists each blocking finding (file, status,
  rule, severity, AST path, suggested fix), a framing line clarifying the exit
  code is intentional, and how to consciously allow a finding via an inline
  `-- vericto:ignore[RULE] <reason>` comment. `--quiet` still suppresses it.
- **GitHub Actions inline annotations.** Under GitHub Actions, blocking findings
  are also emitted as `::error::` workflow commands so they surface as inline
  PR annotations even without GitHub Advanced Security / Code Scanning.

## [1.4.1] - 2026-08-02

### Changed
- **`vericto docs`** got a readability pass: each topic is now a two-line block
  (slug + blurb, then its full `<base>/<slug>` URL on a dim, indented `↳` line),
  with a blank line between topics and bold category headings spaced above and
  below. Both the slug **and** the URL are clickable terminal hyperlinks (OSC 8)
  in terminals that support it (iTerm2, WezTerm, kitty, VS Code, Windows
  Terminal, GNOME Terminal, …); elsewhere the URL is still shown as plain,
  copyable text. Piped/redirected output stays plain (no escape bytes).

## [1.4.0] - 2026-08-02

### Added
- **`vericto feedback [message]`** — send a bug report, idea, or note to the
  Vericto team from the terminal. The message can be an argument, piped on
  stdin, or typed interactively (Ctrl-D to send). `--category bug|idea|other`
  (default `other`). Uses the same `ci_dryrun:execute` API key as `check`;
  writes to the workspace's feedback inbox (the same store as the dashboard's
  feedback widget) via the new `POST /api/v1/ci/feedback` endpoint. The CLI
  version is attached automatically through the User-Agent.

## [1.3.2] - 2026-08-02

### Changed
- **`vericto docs`** now groups topics by category (Getting started / Security &
  privacy / Workspace) with slugs aligned in a column, and shows the URL base
  once in the header instead of repeating the full URL on every row — easier to
  scan. `--json` gains a `category` field per topic. The `docs <topic>` open
  behavior is unchanged.

## [1.3.1] - 2026-08-02

### Added
- **`vericto rules show <CODE>`** now renders a curated **examples** section when
  the rule carries samples: a red `✗ triggers` line (SQL that fires the rule)
  and a green `✓ safe` line (a safe equivalent, when one exists). Standard rules
  only; custom rules and older backends that omit the fields simply hide the
  section. `--format json` passes `example_bad`/`example_good` through.

## [1.3.0] - 2026-08-02

### Added
- **`vericto keys list`** — inspect the workspace's API keys from the terminal
  (name, active/revoked status, scopes, last-used), with the key the CLI is
  authenticated as marked `*`. `--json` for scripting. Read-only and returns
  metadata only — never a key secret or hash. Create/revoke/rotate stay
  JWT-gated in the dashboard on purpose (an API key must not manage other keys).
  Uses the same `ci_dryrun:execute` scope as `check`; spends no check allowance.
- **`vericto docs [topic]`** — list documentation links by topic, or open one in
  your browser (`vericto docs enforcement`). `--json` for scripting. Purely
  local (no network/auth); links to `https://vericto.com/docs/<topic>`, with an
  `--app-url` / `$VERICTO_APP_URL` override for self-hosted/staging docs.

### Changed
- `vericto --help` / `vericto help` now prints the usage invocation on its own
  line under the `Usage:` label, instead of the single-line
  `Usage: vericto <COMMAND>`.

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

[1.4.1]: https://github.com/vericto/vericto-cli/releases/tag/v1.4.1
[1.4.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.4.0
[1.3.2]: https://github.com/vericto/vericto-cli/releases/tag/v1.3.2
[1.3.1]: https://github.com/vericto/vericto-cli/releases/tag/v1.3.1
[1.3.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.3.0
[1.2.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.2.0
[1.1.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.1.0
[1.0.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.0.0
