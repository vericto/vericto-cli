# Changelog

All notable changes to the Vericto CLI are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.11.0] - 2026-10-19

**Windows becomes a first-class platform: offline mode, ARM64, and Windows
installers.** The Windows binary embeds the engine, so `vericto check
--offline` works there as on macOS and Linux, and Windows on ARM64 gets a
native build. Nothing changes on macOS and Linux except the input fix under
Security, which applies everywhere.

### Security
- **SQL saved with a UTF-8 byte-order mark was not checked.** The BOM reached
  the parser as part of the first statement, which then failed to parse, and a
  parse error is allowed: offline, `DELETE FROM users;` saved that way passed
  with exit 0; online, the result was the workspace's parse-error policy
  instead of the rule. Windows editors and Windows PowerShell 5.1 (`Set-Content
  -Encoding UTF8`) write that BOM. Files and stdin are now read as UTF-8 with
  or without a BOM, or as UTF-16 with one (Windows PowerShell 5.1's `>` and
  `Out-File` write UTF-16LE, which used to stop the run with exit 2). Anything
  else is still refused with exit 2. Line endings are kept as they are, CRLF
  included, so lines, inline suppressions and statement hashes are unchanged.

### Added
- **Offline mode on Windows.** The `x86_64-pc-windows-msvc` build embeds
  `vericto-engine` like every other target (the Windows-only target gate and
  the `vericto_windows_offline` cfg are gone). `--offline` no longer exits 2
  on Windows.
- **Windows on ARM64:** `vericto-cli-aarch64-pc-windows-msvc.zip`, built
  natively on GitHub's `windows-11-arm` runner, with offline mode. The shell
  installer, npm package and the new Windows channels pick it on ARM64.
- **PowerShell installer:** `powershell -ExecutionPolicy Bypass -c "irm
  https://github.com/vericto/vericto-cli/releases/latest/download/vericto-cli-installer.ps1
  | iex"`. It is cargo-dist's PowerShell installer plus a SHA-256 check of the
  archive before anything is unpacked (cargo-dist 0.32's own does not check),
  rendered with the release's checksums (`windows/installer.ps1`,
  `windows/package.js`) and test-installed on Windows by the release workflow
  before the release is published.
- **Scoop and winget publish jobs** (`scoop install vericto/vericto` from
  `vericto/scoop-bucket`, `winget install Vericto.VerictoCLI`), both pinning
  the archives' SHA-256. They publish once their owner steps are done (the
  bucket repo, the first winget submission and their tokens); until then they
  succeed without publishing and say so.
- README: a Windows install section (PowerShell, winget, Scoop, npm, a manual
  zip with its checksum check, SmartScreen). DESIGN §9 "Windows channels":
  the channels, the owner steps and the code-signing options.

### Fixed
- **`vericto login` on Windows opened a broken URL.** The browser was started
  with `cmd /C start`, which treats the `&` between query parameters as a
  command separator, so the login page opened without its `port` and could
  not return to the CLI. It now uses `rundll32 url.dll,FileProtocolHandler`,
  which receives the URL as one argument. `vericto docs` opens links the same
  way.
- **The config file on Windows is readable by your user only.** `vericto
  login` wrote `%APPDATA%\vericto\config.toml` with the folder's inherited
  permissions; on Unix it has always been `0600`. On Windows the file (and a
  config folder the CLI creates) now gets a protected access list with a
  single entry, full control for the current user, and an existing file is
  replaced by a new owner-only one. An empty `XDG_CONFIG_HOME` now means unset
  on Windows too (`%APPDATA%`), not `~/.config`.
- **Windows paths in reports use `/`.** A file passed as `db\m.sql` is
  reported as `db/m.sql` in SARIF URIs, GitHub annotations, GitLab reports and
  new baseline entries, so they resolve and match what `--changed` or a Linux
  runner produce. Baselines written before 1.11.0 with `\` paths still match.

### CI
- The Windows job is no longer informational: `Windows build & test`, on
  `windows-2022` and `windows-11-arm`, runs clippy (the Linux lint job never
  compiles the Windows-only code), the build and the whole suite, and is meant
  to be a required check.
- The installer tests run on `windows-latest` too: they install a .zip through
  the npm package and run it (arguments and exit code), refuse a tampered one,
  and run the rendered PowerShell installer against a good and a tampered
  archive.

## [1.10.1] - 2026-10-19

**The container image builds again, and no change in behavior.** The container
images for 1.9.0 and 1.10.0 were never published: the `Docker` workflow failed
on both tags, so `ghcr.io/vericto/vericto-cli` stayed at 1.8.2 (`latest`
included). The binaries on GitHub Releases, the npm package and the Homebrew
formula come from the release pipeline (cargo-dist), not from the image, and
are unaffected. Every command, output and exit code is as in 1.10.0.

### Fixed
- **Container image: the linux/arm64 build failed in pg_query's build script
  with `protoc failed`.** Since 1.9.0 the image embeds the engine, and its
  pg_query regenerates protobuf bindings whenever spawning `protoc` succeeds.
  The builder has no `protoc`, which the native arch (amd64) detects. arm64 is
  built under QEMU, and there spawning a missing binary reports success, so the
  build tried to run it and failed. The build stage now installs
  `protobuf-compiler`, so every arch takes the same path (`Dockerfile`). The
  `rustfmt is not installed` message in that log is a non-fatal bindgen step,
  not the cause.

## [1.10.0] - 2026-10-18

**A new license, and no change in behavior.** From this version on, the CLI is
licensed under the Functional Source License, Version 1.1, ALv2 Future License
(SPDX `FSL-1.1-ALv2`) instead of the Elastic License 2.0, the same license as
the engine it embeds for offline mode. **All previously released versions,
1.9.1 and earlier, remain under the Elastic License 2.0.** Every command,
output and exit code is as in 1.9.1. The embedded engine moves to 4.3.0, the
engine's own relicensing release, which has no code change from 4.2.0: the
only visible difference is that offline results name `engine 4.3.0` and
`standard@engine-4.3.0`.

### Changed
- **License: FSL-1.1-ALv2, which becomes Apache-2.0 after two years.**
  `LICENSE` is the FSL-1.1-ALv2 text from fsl.software, unmodified, with
  "Copyright 2026 Vericto S.A.S." in its notice. It lets you use, copy, modify
  and redistribute the CLI for any purpose other than a Competing Use: a
  commercial product or service that substitutes for the CLI, or for a Vericto
  product that uses it, or that offers substantially similar functionality.
  Running it in your own CI, hooks and pipelines, including at a company, is a
  permitted purpose. Each version is also licensed under the Apache License 2.0
  from the second anniversary of the date it is made available, irrevocably.
- **The embedded engine: vericto-engine 4.3.0, under FSL-1.1-ALv2.** Offline
  mode runs vericto-engine v4.3.0 (was v4.2.0), pinned by tag, the first
  engine release under FSL-1.1-ALv2. So the whole binary, engine included, is
  under one license, and the engine's metadata and its entry in
  `THIRD_PARTY_LICENSES` say `FSL-1.1-ALv2` too. Engine releases up to 4.2.0
  stay under the Elastic License 2.0.
- **Third-party notices ship with the binary.** New `THIRD_PARTY_LICENSES`: the
  crates compiled into the binary for the release targets, with their
  versions, declared licenses and license and notice files, plus the C code
  pg_query compiles in (libpg_query, PostgreSQL, protobuf-c, xxHash).
  `third-party/notices.py` generates it from `Cargo.lock` with `cargo metadata`
  only, and CI (`cargo-deny + cargo-audit`) fails when it is out of date.
  `NOTICE` and `THIRD_PARTY_LICENSES` are in every release archive
  (`include` in `dist-workspace.toml`), so in what the npm package and the
  Homebrew formula install, and in the container image next to `LICENSE`
  (`/usr/share/doc/vericto/`).
- **Metadata:** `Cargo.toml` and `Cargo.lock` declare
  `license = "FSL-1.1-ALv2"` (the SPDX identifier) and version 1.10.0, which
  dist carries into the npm package's `license` and the Homebrew formula's
  `license`. The container image label is
  `org.opencontainers.image.licenses=FSL-1.1-ALv2` (`Dockerfile`,
  `docker.yml`).
- `NOTICE` states the copyright, the license, the Apache-2.0 future license,
  that versions up to 1.9.1 stay under the Elastic License 2.0, the engine
  it embeds, the dist-generated installers (MIT OR Apache-2.0) and where the
  third-party licenses are. **New `LICENSING.md`** (versions and a short FAQ)
  and **`TRADEMARKS.md`** (the license grants no right to the Vericto name or
  logo).
- `deny.toml`: `Elastic-2.0` is no longer an allowed dependency license;
  `FSL-1.1-ALv2` is allowed for vericto-cli and vericto-engine only, so a
  third-party dependency under a source-available license still fails
  `cargo deny check`.
- Every Rust and JavaScript source file starts with `SPDX-FileCopyrightText`
  and `SPDX-License-Identifier` lines (the REUSE convention);
  `npm-installer/binary-install.js` names axodotdev's copyright and
  MIT OR Apache-2.0 too.
- README (License section), CONTRIBUTING and DESIGN name the new license.
  CONTRIBUTING explains that CLA 1.0, which names the Elastic License 2.0,
  also covers later and other licenses.

### CI
- **npm publishing uses Trusted Publishing (OIDC) instead of an npm token.**
  The `npm-publish` job no longer reads `NPM_TOKEN`: npm exchanges the job's
  GitHub OIDC token for a short-lived credential, so there is no long-lived
  publish token to expire or leak (npm caps write tokens at 90 days, and an
  expired one made the 1.9.0 npm publish fail with E404). The job runs on
  Node 24 and checks for npm >= 11.5.1. Publishing stays gated by the `prod`
  environment and keeps provenance. 1.9.0 and 1.9.1 were not published to npm;
  they are on GitHub Releases and Homebrew. No code change.
- **The CLA check runs in GitHub Actions** instead of cla-assistant.io, whose
  webhook failed on every delivery on 2026-10-17 and 2026-10-18 and left pull
  requests without a status. `.github/workflows/cla.yml` (CLA Assistant Lite,
  pinned by commit SHA) reports the `CLA` check, which replaces `license/cla`
  among the required checks. The agreement is unchanged (ICLA v1.0, now also
  in `CLA.md`). Contributors sign it by commenting
  `I have read the CLA Document and I hereby sign the CLA` on their pull
  request, and `recheck` reruns the check. Signatures are kept on the
  `cla-signatures` branch. The workflow never checks out pull request code.
  No code change.

## [1.9.1] - 2026-10-18

Offline mode moves to `vericto-engine` 4.2.0 and takes its rules, version and
decision from the engine. Offline verdicts are unchanged; online checks are
unchanged.

### Changed

- **Engine 4.2.0 in the binary.** `vericto check --offline` evaluates with
  `vericto-engine` 4.2.0 (was 4.1.3), pinned by tag. Every offline result says
  so: `engine 4.2.0` and `ruleset_version` `standard@engine-4.2.0`, in the
  same format as 1.9.0.
- **The engine's standard ruleset and decision.** The 42 rules now come from
  the engine's `standard_rules()` and the version from its `ENGINE_VERSION`,
  so the CLI no longer keeps its own copy of the rule table. Engine 4.2.0
  decides by the strongest resolved action across all violations, which is
  what 1.9.0 corrected locally for engine 4.1.3 (a capped `DROP TABLE` no
  longer hides a WHERE-less `UPDATE` in the same file); that local correction
  is gone. The tests that pin the outcome stay. The same offline inputs give
  the same status, rule, severity, action and fix as 1.9.0: compared on 3,427
  inputs (the engine's test and corpus SQL, alone and combined into
  multi-statement files) in each of the six dialects, with no difference.

### Fixed

- **The Windows offline CI job.** Its integration tests clear the environment
  of the `vericto` process they start, which on Windows also removed
  `SystemRoot`; without it Winsock cannot initialize, so the process could not
  reach the local mock API (`a_key_without_offline_stays_online_and_says_so`
  failed with "error sending request"). The test helpers now keep
  `SystemRoot`, `windir` and `SystemDrive`. Test-only: the binary is
  unchanged, and the Windows binary stays online-only in this release.

## [1.9.0] - 2026-10-18

**Offline mode.** `vericto check --offline` checks SQL on your machine with the
engine built into the binary and its standard rules, with no account and no
network. Until now the CLI was online-only by design, "no offline mode, ever";
that decision is reversed for the standard rules only, and DESIGN §1, §12.4,
§13 and §14 record the new one, its limits, and why online stays the product:
your workspace's own policy (custom rules, overrides, sensitive columns and
masking, agent allowlists), the audit trail and signed receipts are online
only, and an offline result says so wherever it appears. Online checks are
unchanged.

### Added
- **`vericto check --offline`, or `VERICTO_OFFLINE=1`.** It evaluates with
  `vericto-engine` 4.1.3, pinned by tag, and its 42 standard rules at their
  default severities, under the policy a CI check gets in a workspace without
  overrides: Critical and High block, Medium flags, Low is monitored, parse
  errors are reported without failing, and schema changes (DROP, ALTER,
  TRUNCATE) are flagged rather than blocked, as online CI caps them. Statuses
  are the ones online checks report. Every output format, `--fail-on`,
  `--monitor`, `--baseline`, inline suppressions, files, stdin, `--sql`,
  `--changed` and `--since` work as online, with the same exit codes. Each file
  is one result, with its strongest finding. On the engine's own corpora
  (1,452 statements in four dialects) offline mode gives the engine's verdict
  every time.
- **No request of any kind.** The offline path returns before an HTTP client
  exists: no check, no workspace config, no telemetry, no OIDC token fetch.
  A test points the API URL, every proxy variable and the GitHub OIDC endpoint
  at recording servers, runs every format from a file, stdin and `--sql`, and
  checks that nothing arrived.
- **Every result names its mode.** The text summary and the CI failure header
  read `(ruleset standard@engine-4.1.3 · mode: offline (engine 4.1.3, 42
  standard rules, no workspace policy))`; JSON has `"mode"` and
  `"engine_version"` at the top level; SARIF has a run `properties` bag with
  the mode, the engine version and the ruleset version; each GitLab Code
  Quality and SAST finding carries the same note; GitHub annotations are
  titled `Vericto (offline)`. A note on stderr states the limits. Online JSON
  and SARIF gain the same fields with `"mode": "online"` and
  `"engine_version": null`; online text output is unchanged.
- **The strongest action decides.** Engine 4.1.3 picks the finding to report
  by severity, then rule code, after the CI cap. In a file holding
  `DROP TABLE a; UPDATE accounts SET balance = 0;` that is the DROP (Critical,
  capped to flag), so the file would pass with a WHERE-less UPDATE in it.
  Offline mode reports the finding with the strongest action instead, here
  the UPDATE (VERICTO-030, BLOCKED), in every format and in the exit code. A
  single statement's verdict never changes.
- **Refused, not ignored.** `--receipt`, `--oidc` (and `--audience`,
  `--oidc-token-env`), `--allow-degraded` and `--allow-unsanitized` need a
  workspace; with `--offline` they exit `2` and say why.
- `.vericto.toml` rejects an `offline` key (exit `2`), as it rejects `api_key`
  and `allow_degraded`: a committed file must not be able to switch CI to
  fewer rules.
- A default cargo feature, `offline`. `cargo install --no-default-features`
  builds the thin client alone, as before.

### Changed
- **Outside CI, a run with no credential checks offline.** With no API key
  (flag, environment or config file), no login and no OIDC token, and none of
  the usual CI variables set (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`,
  `CIRCLECI`, `JENKINS_URL`, `TF_BUILD`, `BITBUCKET_BUILD_NUMBER`,
  `TEAMCITY_VERSION`, `CODEBUILD_BUILD_ID`), `vericto check` now gives the
  offline verdict, with a note on stderr, instead of exit `3`. A first
  `npx @vericto/vericto-cli check file.sql` or a fresh pre-commit hook gets an
  answer. **In CI nothing changes:** a missing credential is still exit `3`,
  now with a hint to pass `--offline`, because a pipeline whose secret went
  missing must not quietly fall back to fewer rules. A key that is present
  but invalid is still exit `3`, and an unreachable backend is still exit `4`;
  neither ever switches to offline mode.
- **The Docker image sets `CI=true`.** A container does not see the runner's
  CI variables unless they are passed in, so without it a pipeline whose
  `VERICTO_API_KEY` secret went missing would check offline instead of
  failing. In the image a missing key is exit `3`; pass `--offline` to choose
  offline mode, or `-e CI=` to use the image as a local tool.
- **The binary is about 3× larger** because it embeds the engine, almost all of
  it PostgreSQL's parser (libpg_query): on aarch64-apple-darwin 14.0 MiB
  instead of 4.5 MiB, and the `.tar.xz` download about 3.7 MiB instead of
  about 1.7 MiB.
  Start-up time stays under 10 ms (`vericto --version`: 8.4 ms against
  7.9 ms, median of 60 runs on an M3 Pro).
- **Building needs a C compiler and libclang.** The release's musl runners and
  CI install `clang` and `libclang-dev`. The Docker image is built in a Debian
  builder that cross-compiles to static musl, instead of an Alpine one, whose
  static build scripts cannot load libclang; the image is still a static
  binary on distroless. `cargo-deny` allows the engine's git repository as a
  source, by tag only. CONTRIBUTING lists the prerequisites per platform.
- **Each pull request now builds every release target** (cargo-dist
  `pr-run-mode = "upload"`) and uploads the archives as workflow artifacts,
  so a toolchain break shows up before the tag. Nothing is published from a
  pull request.

### Fixed
- **`VERICTO_ALLOW_UNSANITIZED=1` works.** The variable accepted only `true`
  and `false`, so `=1` was a usage error. It now reads values as
  `VERICTO_OFFLINE` does, in `check`, `baseline` and `baseline prune`, and
  both read them the same way: `1`, `true`, `yes` and `on` turn the flag on,
  `0`, `false`, `no` and `off` leave it off, in any case and with surrounding
  spaces ignored. An empty value is the same as unset, as in the SDKs (an
  empty `VERICTO_OFFLINE` was an error), and anything else exits `2` with an
  error that names the variable. One parser serves both, and a test checks
  that every boolean flag with an environment variable uses it.

### Notes
- **Windows is online-only for now.** The Windows build does not embed the
  engine yet: `--offline` and `VERICTO_OFFLINE=1` exit `2` there with a message
  saying so, and a run without a credential stays exit `3`. A new,
  informational CI job builds and tests the engine on `windows-2022`; it is
  not required, and once it passes, Windows gets offline mode in a later
  release. Meanwhile, offline mode works under WSL.
- **Offline is not your workspace.** It has no custom rules, overrides,
  sensitive columns, allowlists, parse-error policy, audit trail, run reports
  or receipts, and offline runs are not metered or recorded. One result per
  file instead of one per statement means a baseline recorded online does not
  match offline findings: they show up again (fail-closed, but noisy). Inline
  suppressions work in both modes.
- **The next release moves to engine 4.2.0.** Engine 4.1.3 exports no standard
  ruleset and no version, so 1.9.0 carries its own copy of the 42-rule table
  (a test keeps it equal to the engine's catalogue) and corrects the
  strongest-action choice itself. Engine 4.2.0, in preparation, exports
  `standard_rules()` and its version and picks the strongest action in the
  engine; the CLI will then drop the local table and the local workaround.
- `VERICTO_OFFLINE` accepts `1`, `true`, `yes` and `on` (and `0`, `false`,
  `no`, `off`).

## [1.8.2] - 2026-10-18

A security release for **sanitized mode** (a workspace whose telemetry query
mode is `sanitized`). That mode promises that no literal value leaves the
machine, and the sanitizer kept that promise only for the plain cases: in the
ones below, part of a literal was sent as written. The sanitizer is rewritten
as a lexer that ends every literal where the dialect's own lexer ends it, and
it fails closed: what it cannot read with certainty is replaced, never sent.
Nothing changes for a workspace in `raw` mode.

### Security
- **Snowflake backslash escapes.** Snowflake reads `\'` inside `'...'` as an
  escaped quote; the sanitizer did not, so `'it\'s secret'` ended at `\'` and
  `s secret` was sent. Backslash escapes now apply to every Snowflake string.
- **MySQL with `NO_BACKSLASH_ESCAPES`.** MySQL's escape mode is a server
  setting the CLI cannot see. Only the default mode was read, so on a server
  without backslash escapes `'C:\' AND q = 'secret'` sent `secret`. A MySQL
  statement with a backslash is now read in both modes, as the engine's MySQL
  lexer does: a reading that leaves something unterminated is dropped, and
  where both readings are possible and disagree, whatever is a literal in
  either is replaced.
- **MySQL double-quoted strings.** `"..."` is a string in MySQL (without
  `ANSI_QUOTES`) and was copied as an identifier, value included.
- **Oracle quote-delimited strings.** `q'[...]'`, `q'{...}'`, `q'(...)'`,
  `q'<...>'`, `q'!...!'` (any delimiter) and `nq'...'` were not recognized:
  their content was sent from the first `'` inside it on.
- **Dollar-quoted strings and bodies.** `$$...$$` and `$tag$...$tag$` were
  copied as written, literals inside included. A dollar-quoted string is now
  a literal like any other (`$1` / `?`); after `AS` or `DO` it is a function
  or `DO` body, which the engine flags without reading, and becomes the empty
  body `$$$$` so the statement still parses. A `$` inside an identifier
  (`a$b$c`) no longer opens a dollar quote, which copied everything up to the
  next `$b$` as written.
- **Comments the dialect reads differently.** A `'` inside a comment the
  sanitizer did not know as one opened a literal there, so the real literal
  after it was sent: MySQL `#` comments, Snowflake `//` comments, and nested
  Postgres and MSSQL comments (`/* a /* b */ don't */`). In MySQL, `--` starts
  a comment only before whitespace, so `5--'secret'` is now a literal, and the
  content of `/*! ... */`, which MySQL executes, is now sanitized.
- **Prefixed literals and numbers.** The prefix of `N'...'`, `U&'...'`,
  `X'...'`, `B'...'` and MySQL `_utf8mb4'...'` stayed in front of the
  placeholder; `0x4142`, `1e10`, `.5` and MSSQL money (`$12.50`) were sent in
  part (`$1e10`, `.$2`); a unary sign stayed (`-$1`). Each is now one
  placeholder.
- **Fail closed.** An unterminated quoted identifier, comment, dollar quote or
  q-quote was copied to the end as written. Now everything from the point
  where the text cannot be read with certainty (also: a q-quote without a
  usable delimiter, a nested comment in MySQL, a comment inside `/*! ... */`)
  to the end is one placeholder.

### Fixed
- **Bind parameters are kept as written.** Oracle `:1` became `:$1` and an
  MSSQL `[col 1]` identifier became `[col $1]`. `:1` / `:name` (Oracle,
  Snowflake, SQLite) and `[...]` (MSSQL, with `]]`) are now copied as they are.
- **Placeholders never reuse an existing parameter.** `id = $1 AND n = 5`
  became `id = $1 AND n = $1`, one parameter for two values. New placeholders
  are numbered after the highest `$N` (and Oracle `:N`) already in the
  statement, as libpg_query's normalization numbers them.
- **Non-ASCII text outside literals.** The sanitizer worked byte by byte and
  wrote each byte of a multi-byte character as a character of its own:
  `ñandú` became `Ã±andÃº`, and the digit in `café2` was read as a number.
  Identifiers, comments and quoted names in any script now come out as they
  went in.
- The dialect name is matched case-insensitively (`--dialect MySQL`).

### Tests
- `tests/fixtures/sanitize.json` holds the sanitizer's test vectors (133:
  vericto-cli 1.8.0's 19, one of them updated for dollar-quoted bodies, and
  one or more per leak and dialect above); each group is a test in
  `src/sanitize.rs`, and vericto-python 0.3.2 runs the same file against its
  port. A seeded property test builds random statements in all seven dialects
  (the six named plus an unknown one) with a secret marker inside literals of
  every kind and checks that no marker comes out; it found the
  `NO_BACKSLASH_ESCAPES` case with an executable comment that this release also
  covers. Other tests check that non-ASCII characters always come out whole and
  that pathological input stays linear.
- Unit and integration test line coverage from 85.7% to 91.2% (cargo-llvm-cov;
  production lines only, without the in-file test modules: 81.3% to 88.8%).
  New tests cover every `--format` written to `--output` with the exit code
  kept, GitHub `::error` annotations and the provenance sent from GitHub
  Actions and GitLab CI, `--fail-on` thresholds and `.vericto.toml` defaults,
  the rejection of a `.vericto.toml` carrying `api_key` or `allow_degraded`,
  empty / missing input, `--since` / `--changed` against a real git repository
  (only changed `.sql` files, empty diff, unknown or undetectable base), backend
  refusals and an unreachable backend mapped to exit codes 3 and 4, an
  incompatible backend major version, the quota and upgrade nudges staying on
  stderr, an unusable CA bundle failing before any request, retries honoring
  `Retry-After`, a chunked run failing closed on one failed chunk, the GitHub
  OIDC token endpoint and exchange failures, and the remaining `doctor`,
  `logout` and `init` branches. These tests change nothing in the binary.

## [1.8.1] - 2026-10-18

### Added
- **Homebrew.** `brew install vericto/tap/vericto` on macOS (arm64 and x86_64)
  and Linux (arm64 and x86_64, the static musl binaries). Every release now
  builds a `vericto` formula with cargo-dist's Homebrew installer and pushes it
  to the new [`vericto/homebrew-tap`](https://github.com/vericto/homebrew-tap)
  repository, so the tap gets its first formula with the next release. The
  formula installs the same archives as the other channels, each pinned by the
  SHA-256 in the release's `sha256.sum`, and its `test do` block runs
  `vericto --version`. The binary is unchanged.

### Changed
- **The formula is published by a custom job, not cargo-dist's built-in one.**
  Pushing to the tap needs a token with write access to it
  (`HOMEBREW_TAP_TOKEN`). The built-in `homebrew` publish job declares no
  GitHub Environment, so it could only read that token as a repository secret,
  which any workflow in this public repository can reach. As with
  `NPM_TOKEN`, the token lives in the reviewer-gated `prod` environment
  instead, and `.github/workflows/homebrew-publish.yml` (wired in as
  `publish-jobs = ["./npm-publish", "./homebrew-publish"]`) is the only job
  that declares it. The job does not persist the token in its checkout of the
  tap or hand it to the `brew` steps, and refuses to push a formula
  whose URLs are not this release's four macOS/Linux archives or whose SHA-256
  are not in `sha256.sum`. It also adds the `test do` block the cargo-dist
  0.32 template lacks and drops the `version` line that `brew audit --strict`
  rejects as redundant with the URLs. If the token is missing or expired the
  job fails, and the GitHub release is not announced until it is fixed and
  the job re-run: the same failure mode as the npm job. `dist plan` warns that
  a tap is set while the built-in Homebrew job is off; that is intended.
- `Cargo.toml`: `description` no longer starts with "Vericto CLI" (Homebrew
  rejects a description that starts with the formula name; it is also the npm
  package description) and `homepage` is https://vericto.com.

## [1.8.0] - 2026-10-14

### Added
- **Snowflake and SQLite in the dialect list.** `--dialect` (and
  `default_dialect` in `.vericto.toml`) documents `snowflake` and `sqlite`
  next to `postgres`, `mysql`, `oracle` and `mssql`. The CLI passes the
  dialect to the workspace as before; the server evaluates Snowflake since
  vericto-engine 4.0.0 and SQLite since 4.1.0 (`vericto check --dialect sqlite
  migrations/*.sql`, with the SQLite rules VERICTO-098 to VERICTO-101).

### Fixed
- **Sanitized mode** (a workspace whose telemetry query mode is `sanitized`):
  - Snowflake and SQLite get `?` placeholders, as MySQL does (on Snowflake
    `$1` is a staged file's first column, not a parameter; `?` is SQLite's
    canonical bind form). SQLite `[name]` identifiers are copied as they are,
    and `$name` is a bind parameter there, not a dollar quote.
  - Bind parameters the client already wrote are kept: the digits of `$1`
    and `?1` were read as a numeric literal, so `$1` became `$$1`, which then
    read as the start of a dollar-quoted string.

## [1.7.2] - 2026-10-14

### Security
- `rustls` 0.23.45 → 0.23.46 for RUSTSEC-2026-0346 (`Debug` output of client
  session values exposes TLS secrets), RUSTSEC-2026-0347 (buffered data sent to
  the outer server after an ECH rejection), RUSTSEC-2026-0348 (Brotli
  certificate decompression can allocate up to 1 GiB before authentication)
  and RUSTSEC-2026-0349 (an unauthenticated ServerHello can downgrade later
  connections to classical key exchange). rustls is the TLS stack of the CLI's
  requests to the Vericto API.
- `quinn-proto` 0.11.16 → 0.11.18 (merged after 1.7.1) for RUSTSEC-2026-0338
  to RUSTSEC-2026-0343 (panics and memory-exhaustion guards in the QUIC
  implementation).

Lockfile only: no code or behaviour changes.

## [1.7.1] - 2026-10-12

### Added
- **LICENSE file.** The Elastic License 2.0 text (the same file as the Vericto
  engine and proxy), which `Cargo.toml` already declared as `Elastic-2.0`. It
  ships in the release archives, the `@vericto/vericto-cli` npm package (whose
  publish step now refuses a package without it) and the container image
  (`/usr/share/doc/vericto/LICENSE`, with the
  `org.opencontainers.image.licenses=Elastic-2.0` label, empty in 1.7.0).

### Changed
- Dependencies: clap 4.6.7, clap_complete 4.6.11, tokio 1.53.2, serde 1.0.229,
  serde_json 1.0.151.
- CI actions: actions/setup-node 7.1.0, docker/setup-qemu-action 4.4.0,
  docker/login-action 4.6.0, docker/metadata-action 6.2.0,
  docker/build-push-action 7.4.0.

### Fixed
- The container image is tagged `latest` once, and only for a release:
  prerelease tags no longer move `latest`.
- A manual run of the Docker workflow on a branch builds the image instead of
  failing; only a version tag publishes and attests it.
- The integration tests no longer read the developer's own
  `~/.config/vericto/config.toml`: each run of the binary gets an empty temp
  `HOME` / `XDG_CONFIG_HOME`, so a stored login on macOS no longer fails them.

## [1.7.0] - 2026-10-11

### Security
- **The npm installer verifies the binary it downloads.** The published
  `@vericto/vericto-cli` package carries the SHA-256 of every platform archive,
  taken from the release's checksums, and its installer refuses an archive that
  does not match, or one it has no checksum for, before extracting anything.
  Downloads and their redirects must be `https://`. The package is published
  with npm provenance.
- **Credentials go only to an `https://` API.** The CLI refuses to send an API
  key, login code or OIDC token to an `http://` API URL other than localhost
  (an `Auth` error, which `--allow-degraded` does not bypass), and follows
  redirects only within the same origin.
- **The stored API key stays owner-only.** `vericto login` narrows an existing
  `config.toml` to `0600` before writing the key (the mode used to apply only to
  a new file), and creates the config directory as `0700`.
- **Only ID-token-shaped values are read as OIDC tokens.** The variable named by
  `--oidc-token-env` / `.vericto.toml` `oidc_token_env` is used only when its
  value has the shape of a JWT, so a committed config cannot make the CLI send
  another CI secret to the API.
- Docker base images pinned by digest; every GitHub Action pinned by SHA, including
  release and publish; CI adds cargo-deny, cargo-audit and gitleaks; Dependabot
  for Cargo, GitHub Actions and npm.

### Added
- **`vericto rules simulate <file>`**: runs a candidate rule change (new or
  edited custom rules, standard rules enabled, disabled or re-severitied)
  against up to 30 days of the workspace's recorded production traffic, waits
  for the result and prints the report: the headline ("Would have blocked 2
  legitimate flows (9,442 executions)"), newly blocked / flagged / no longer
  blocked flows with identities and masked samples, and engine drift apart.
  Exit 1 when legitimate flows would break (`--fail-on-break`, default 0; with
  `--strict`, also Inconclusive). Needs an API key with the `rules:simulate`
  scope (Builder or above). `--format json` prints the API response.

## [1.6.0] - 2026-10-08

Minor rather than patch: a new flag (`--allow-unsanitized`) and two exit-code
changes a CI script may depend on (a failed config read exits 4 without sending
SQL; an exhausted allowance exits 3).

### Security
- **Fail closed when the workspace config can't be read.** If `GET /ci/config`
  failed, `check`, `baseline` and `baseline prune` sent the SQL unsanitized,
  even in a workspace that requires sanitized mode. They now send nothing and
  exit 4; `--allow-unsanitized` (`VERICTO_ALLOW_UNSANITIZED`) opts out.
- **Sanitization handles backslash escapes.** In MySQL and in Postgres
  `E'...'` strings, `\'` doesn't end a literal; the sanitizer treated it as
  the end, and the rest of the literal was sent verbatim.

### Fixed
- **An exhausted monthly allowance exits 3**, as the exit-code table says
  ("plan not entitled"), instead of being retried as a rate limit and
  exiting 4.
- **The pre-commit hook checks the staged content** (`git show :path`), not
  the working-tree file, and handles paths with spaces.

### Documentation
- The README said the receipt-signing public key is bundled; none is yet, so
  `verify-receipt` needs `--public-key` (from
  `GET /api/v1/meta/export-signing-key`).

## [1.5.2] - 2026-10-04

### Security
- **rustls 0.23.41 → 0.23.45 (RUSTSEC-2026-0285)** and **h2 0.4.15 → 0.4.19
  (RUSTSEC-2026-0258).** rustls accepted TLS 1.3 handshake messages across
  encryption-level boundaries; h2 did not bound empty DATA frames. The CLI is a
  client that only talks to the Vericto API, so the exposure was low, but every
  HTTPS call goes through both crates. `chacha20` 0.10.1, a yanked version, is
  also updated. Dependency-only release: no behaviour change; `cargo audit`
  reports no vulnerabilities and no warnings.

### Documentation
- **Verifying attestations:** the README now downloads the artifact before
  `gh attestation verify`, which checks a local file and failed with
  "no such file or directory" when run as written.

## [1.5.1] - 2026-10-03

### Added
- **Build attestations on every release artifact.** Each binary archive now
  ships with a Sigstore-backed GitHub attestation tying it to
  `vericto/vericto-cli`, the release workflow and the source commit; verify one
  with `gh attestation verify <artifact> --repo vericto/vericto-cli`. The Docker
  image gets the same, pushed to GHCR next to it
  (`gh attestation verify oci://ghcr.io/vericto/vericto-cli:<tag> --repo vericto/vericto-cli`). They were
  wired in but off while the repository was a user-owned private one, where
  GitHub does not offer attestations. SHA-256 checksums still ship alongside, so
  nothing changes for anyone verifying that way.

## [1.5.0] - 2026-10-03

### Changed
- **Per-statement results.** Against a backend that advertises the
  `check_files` capability (`GET /ci/config`), `check` and `baseline` send each
  input as a whole file and the backend reports **every statement** with its
  real line. Previously a file was evaluated as a single unit, so only its most
  severe finding was reported and every annotation pointed at line 1. Now:
  - text output and the failure summary show `path:line`;
  - SARIF `region.startLine`, GitLab Code Quality `lines.begin`, GitLab SAST
    `start_line` and GitHub `::error` annotations use the statement's line;
  - `--format json` adds `file_index` to each result (`line` is then the
    statement's line in that file).

  A file still costs **one** check from the monthly allowance, whatever its
  statement count. Against an older backend the CLI keeps the previous request
  shape and output, unchanged.

  **If you use a baseline:** fingerprints (rule, file, AST path) are unchanged,
  so existing entries keep matching. Findings that were previously hidden behind
  a file's most severe one can now surface as new; re-run `vericto baseline` to
  accept them, or fix them.

### Fixed
- **`vericto init` templates pointed at an image that does not exist.** The
  GitLab and Docker templates used `ghcr.io/donkan168/vericto-cli`; the image is
  published as `ghcr.io/vericto/vericto-cli`. The installer URL in the GitHub
  workflow and the pre-commit hook now use the `vericto` org too.
- **One suppression no longer covers every look-alike finding.** Suppression was
  keyed on the finding's fingerprint (rule, file, AST path), so a single
  baseline entry or inline ignore also silenced every other finding with that
  fingerprint — e.g. baselining one `DELETE` without `WHERE` let any later one
  in the same file pass. Suppression is now decided per result.
- **Per-statement baselines (format v2).** With a backend that returns
  `statement_hash`, `vericto baseline` keys each entry on the statement's text
  as well (re-indenting a statement keeps its entry; changing its SQL does
  not), and records the line for reviewers. v1 baselines are still matched as
  before, with a note recommending `vericto baseline` to upgrade.
- **Inline ignores apply to their statement.** In per-statement mode,
  `-- vericto:ignore[RULE] reason` covers the statement it sits on or directly
  above — not every statement in the file, as the failure hint already
  described. Results that cover a whole file keep the file-wide behaviour.
- **`baseline` and `baseline prune` honor sanitized mode.** They skipped the
  `GET /ci/config` preflight and sent raw SQL even when the workspace requires
  literals to be normalized client-side; they now sanitize exactly like `check`
  (which also keeps baseline keys consistent with the SQL `check` sends).

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

[1.5.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.5.0
[1.4.2]: https://github.com/vericto/vericto-cli/releases/tag/v1.4.2
[1.4.1]: https://github.com/vericto/vericto-cli/releases/tag/v1.4.1
[1.4.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.4.0
[1.3.2]: https://github.com/vericto/vericto-cli/releases/tag/v1.3.2
[1.3.1]: https://github.com/vericto/vericto-cli/releases/tag/v1.3.1
[1.3.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.3.0
[1.2.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.2.0
[1.1.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.1.0
[1.0.0]: https://github.com/vericto/vericto-cli/releases/tag/v1.0.0
