# vericto-cli

> Validate SQL against your Vericto workspace's security rules **before** it runs —
> in pre-commit hooks and CI/CD pipelines.

The installed command is `vericto`. By default it is a **thin client**: it sends SQL to the
Vericto backend (`POST /api/v1/ci/check-key`, API-key auth) and mirrors the verdict
as a process exit code. With `--offline` it evaluates locally instead, with the
embedded engine and the standard rules only (see [Offline mode](#offline-mode)). Available on **every plan**
— checks are metered by a monthly CLI allowance (free tier included; team/
enterprise unmetered). See [DESIGN.md](https://github.com/vericto/vericto-cli/blob/main/DESIGN.md) for the full design.

## Install

Releases are built with [`cargo-dist`](https://opensource.axo.dev/cargo-dist/):
cross-compiled binaries for Linux (x86_64/aarch64, static musl), macOS
(x86_64/aarch64), and Windows (x86_64/aarch64) are published to GitHub Releases on every
version tag, each with SHA-256 checksums (see _Verifying a download_ below).
Every other channel serves those same binaries.

```bash
# Homebrew (macOS arm64/x86_64, Linux arm64/x86_64)
brew install vericto/tap/vericto
brew upgrade vericto           # later releases
brew uninstall vericto         # and `brew untap vericto/tap` to drop the tap
```

```bash
# npm (great in CI: runners already have Node)
npm install -g @vericto/vericto-cli      # or, zero-install: npx @vericto/vericto-cli check ...
```

```bash
# Shell installer (Linux/macOS)
curl -fsSL https://github.com/vericto/vericto-cli/releases/latest/download/vericto-cli-installer.sh | sh
# (Windows: see "Windows" below)

# Docker (CI runners that prefer an image step). The image sets CI=true, so a
# missing key is exit 3 there, never an automatic offline run.
docker run --rm -e VERICTO_API_KEY ghcr.io/vericto/vericto-cli:latest check migrations/*.sql

# Or download a prebuilt binary directly:
#   https://github.com/vericto/vericto-cli/releases
```

```bash
# From source
cargo install --path .
```

> **Homebrew:** the formula lives in the
> [`vericto/homebrew-tap`](https://github.com/vericto/homebrew-tap) tap and is
> published by the release pipeline on every version tag, starting with
> 1.8.1. It installs the same prebuilt binaries as every
> other channel (on Linux, the static musl ones), each pinned by its SHA-256;
> Homebrew refuses a download that does not match. `brew install
> vericto/tap/vericto` names the tap explicitly, which also tells Homebrew to
> trust that formula. If `vericto` is already installed with
> `npm install -g`, remove that one first (`npm uninstall -g
> @vericto/vericto-cli`): both put a `vericto` in the same `bin` directory
> under a Homebrew-managed Node.
>
> **npm:** the release pipeline builds **and publishes** `@vericto/vericto-cli`
> to the registry on every version tag, for every platform, Windows included.

> Building from source needs a C compiler and libclang (the embedded engine's
> `pg_query` compiles PostgreSQL's parser and runs bindgen): Xcode Command Line
> Tools on macOS, `clang` and `libclang-dev` on Debian/Ubuntu, and on Windows the
> Visual Studio Build Tools (C++ workload) and LLVM (`winget install LLVM.LLVM`). The
> `rust:*-alpine` images cannot load libclang from a build script; build in a
> Debian container targeting musl, as the `Dockerfile` does. To build the thin
> client only, without offline mode:
> `cargo install --path . --no-default-features`. See
> [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Windows

Windows 10/11 on x64 and on ARM64 (a native `aarch64` build since 1.11.0), offline
mode included. Any of these, in PowerShell (Windows PowerShell 5.1 or PowerShell 7):

```powershell
# PowerShell installer: puts vericto.exe in %USERPROFILE%\.cargo\bin and adds it
# to PATH. It checks the archive's SHA-256 before unpacking anything.
powershell -ExecutionPolicy Bypass -c "irm https://github.com/vericto/vericto-cli/releases/latest/download/vericto-cli-installer.ps1 | iex"

# winget
winget install Vericto.VerictoCLI

# Scoop, from Vericto's bucket
scoop bucket add vericto https://github.com/vericto/scoop-bucket
scoop install vericto/vericto

# npm (Node 18+), also zero-install: npx @vericto/vericto-cli check ...
npm install -g @vericto/vericto-cli
```

`-ExecutionPolicy Bypass` applies to that one command only; Windows' default
policy (`Restricted`) refuses to run the installer otherwise. winget and Scoop
are updated by the release pipeline and pin the archive's SHA-256 too; if
either cannot find the package yet (both are new in 1.11.0), use the installer
or npm.

A manual install, with the checksum check (use
`vericto-cli-aarch64-pc-windows-msvc.zip` on ARM64):

```powershell
$v = "1.11.0"; $zip = "vericto-cli-x86_64-pc-windows-msvc.zip"
$base = "https://github.com/vericto/vericto-cli/releases/download/v$v"
Invoke-WebRequest "$base/$zip" -OutFile $zip
Invoke-WebRequest "$base/$zip.sha256" -OutFile "$zip.sha256"
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne (Get-Content "$zip.sha256").Split(" ")[0]) { throw "SHA-256 mismatch" }
Expand-Archive $zip -DestinationPath "$env:LOCALAPPDATA\Programs\vericto"
# then add $env:LOCALAPPDATA\Programs\vericto to your PATH
```

> **SmartScreen:** the Windows binaries are not code-signed yet. A `vericto.exe`
> unpacked from a zip downloaded **with a browser** carries the "downloaded from
> the internet" mark, and Windows may stop it with "Windows protected your PC".
> Check the SHA-256 (above) or the build attestation
> (`gh attestation verify <zip> --repo vericto/vericto-cli`), then
> `Unblock-File vericto.exe`. The PowerShell installer and npm download with
> PowerShell or Node, which do not add that mark.

On Windows, `vericto login` stores its config in
`%APPDATA%\vericto\config.toml`, readable by your user only (see
[Configuration](#configuration)). SQL files are read as UTF-8, with or without
a byte-order mark, or as UTF-16 with one (what Windows PowerShell 5.1's `>`
writes), and CRLF line endings are fine.

### Verifying a download

Every release ships SHA-256 checksums — `sha256.sum` (all artifacts) and a
per-artifact `.sha256` — for an integrity check:

```bash
# Verify a downloaded artifact against the published checksum
sha256sum -c vericto-cli-x86_64-unknown-linux-musl.tar.xz.sha256
```

Releases from v1.5.1 on also carry **keyless build attestations** (§9):
Sigstore-backed provenance that ties each artifact to this repository, the
release workflow and the commit it was built from. Checksums show the download
is intact; the attestation shows who built it and from what source:

```bash
# Requires the GitHub CLI (gh 2.49+). Download the artifact first:
# `gh attestation verify` checks a local file, not a URL.
gh release download v1.6.0 --repo vericto/vericto-cli -p 'vericto-cli-x86_64-unknown-linux-musl.tar.xz'
gh attestation verify vericto-cli-x86_64-unknown-linux-musl.tar.xz --repo vericto/vericto-cli

# The Docker image carries the same, stored in GHCR (no download needed)
gh attestation verify oci://ghcr.io/vericto/vericto-cli:1.6.0 --repo vericto/vericto-cli
```

Homebrew checks the SHA-256 pinned in the formula before it installs
anything. To check the attestation of the archive it downloaded:

```bash
gh attestation verify "$(brew --cache vericto/tap/vericto)" --repo vericto/vericto-cli
```

The npm package checks the binary it downloads on install: from the next
release on, `@vericto/vericto-cli` carries the published SHA-256 of every
platform archive and refuses to install one that does not match (or that it
has no checksum for). It is published with npm provenance, so
`npm audit signatures` verifies that it was built by this repository's release
workflow.


## Commands

```
vericto check [files...]   Evaluate SQL files (or '-' for stdin). The core command.
vericto baseline [files]   Record current findings to .vericto-baseline.json.
vericto baseline prune     Remove baseline entries that no longer match any finding.
vericto rules list         List the workspace's effective rule catalogue.
vericto rules show <CODE>  Show one rule's detail (e.g. VERICTO-001), incl. its AST condition.
vericto rules simulate <F> Run a candidate rule change against recorded production traffic.
vericto keys list          List the workspace's API keys (read-only; manage them in the dashboard).
vericto docs [topic]       List documentation links by topic, or open one in your browser.
vericto feedback [msg]     Send feedback (bug/idea/other) to the Vericto team.
vericto login              Log in via your browser (default), or --api-key/--oidc for CI.
vericto logout             Remove the stored API key.
vericto doctor             Verify config, connectivity, auth, and plan quota.
vericto init               Scaffold a CI workflow (+ pre-commit hook with --hook).
vericto verify-receipt <f> Verify a signed run receipt offline (no network/account).
vericto version            Print the CLI version.
vericto completions <sh>   Print a shell completion script (bash|zsh|fish|powershell|elvish).
```

Enable completions by writing the script where your shell looks for them, e.g.:

```bash
vericto completions bash > ~/.local/share/bash-completion/completions/vericto
vericto completions zsh  > "${fpath[1]}/_vericto"   # zsh
vericto completions fish > ~/.config/fish/completions/vericto.fish
```

## Baseline & suppression

Adopting the CLI on a repo with pre-existing unsafe SQL shouldn't turn the build
red on day one. Record the current findings, then only *new* ones fail:

```bash
vericto baseline migrations/*.sql          # writes .vericto-baseline.json
vericto check migrations/*.sql --baseline .vericto-baseline.json
```

Over time, some baselined findings get fixed — `check --baseline` already
notices this ("N baseline entr(y/ies) no longer match") but leaves the file
alone. Clean it up with `vericto baseline prune`, which re-runs the same check
and drops entries that no longer match anything:

```bash
vericto baseline prune migrations/*.sql --file .vericto-baseline.json
vericto baseline prune migrations/*.sql --dry-run   # preview, no write
```

Pass the same file set the baseline was originally recorded against — pruning
against a smaller set would drop entries for files that simply weren't
re-checked, not ones that were actually fixed.

Baselines record each finding's **statement**, not just its rule and file
(format v2, with a backend that reports per statement). Accepting one
`DELETE` without `WHERE` does not accept the next one someone adds to the same
file. A baseline from an older CLI (v1) keeps working as before; `check` notes
that it hides new findings of a baselined rule in that file — re-run
`vericto baseline` to upgrade it. In a workspace in sanitized mode, `baseline`
normalizes literals before sending, exactly like `check`. If the workspace
config can't be read, both fail closed (exit 4) without sending any SQL, unless
you pass `--allow-unsanitized`.

Suppress a single finding inline (a **reason is required**, so it stays
accountable). The comment applies to **its statement only**: put it directly
above the statement (no blank line in between) or on one of its lines:

```sql
-- vericto:ignore[VERICTO-001] one-off backfill, tracked in JIRA-42
DELETE FROM users;

DELETE FROM sessions; -- vericto:ignore[VERICTO-001] expired rows only, JIRA-43
```

Against an older backend that reports one result per file, an inline ignore
still applies to the whole file.

## Inspecting rules (`vericto rules`)

See what a `check` run is actually scored against, without opening the
dashboard — useful when a CI failure only shows a rule code and you want the
full picture (name, severity, resolved action, AST condition):

```bash
vericto rules list                 # every active + inactive rule in the workspace
vericto rules list --active-only   # skip disabled rules
vericto rules show VERICTO-001     # full detail, including the AST condition
vericto rules list --format json   # machine-readable, for scripting
```

Both are read-only and use the same `ci_dryrun:execute`-scoped API key as
`check` — no extra scope or setup needed. Neither spends the monthly CLI
check allowance.

## Simulating a rule change (`vericto rules simulate`)

Before you enforce a new or tightened rule, replay up to the last 30 days of the
workspace's recorded traffic with it and see which legitimate flows it would
have blocked. Nothing runs against your database and nothing is blocked; the
backend decrypts and evaluates the recorded queries and returns masked samples
only.

```yaml
# .vericto/rules/orders.yaml
rules:
  - name: protect-orders-delete
    code: CUSTOM-004          # omit for a new rule
    severity: high
    dialect: postgres
    ast_condition_yaml: |
      rule: protect-orders-delete
      node_type: DeleteStmt
      condition:
        relation: "shop_order"
standard:
  - code: VERICTO-050
    severity: high
```

```bash
vericto rules simulate .vericto/rules/orders.yaml --days 30 --fail-on-break 0
vericto rules simulate rules.yaml --strict           # Inconclusive fails too
vericto rules simulate rules.yaml --format json      # the API response, for PR comments
```

It needs an API key with the **`rules:simulate`** scope (create it in the
dashboard; it is never a default), on Builder or above. Exit codes: `0` Pass or
Warn, `1` Fail (more legitimate flows would break than `--fail-on-break`; with
`--strict`, also Inconclusive), `2` bad file or rejected candidate, `3` key,
scope or plan, `4` backend (also another simulation already running, or
`--wait`, default `15m`, running out). The file may also be JSON with the same
keys.

In GitHub Actions, on the PRs that change rule files:

```yaml
- name: Simulate changed rule files against 30 days of production
  env:
    VERICTO_API_KEY: ${{ secrets.VERICTO_SIMULATE_KEY }}   # scope rules:simulate
  run: |
    for f in $(git diff --name-only origin/${{ github.base_ref }}... -- .vericto/rules/); do
      npx -y @vericto/vericto-cli rules simulate "$f" --days 30 --fail-on-break 0
    done
```

(`fetch-depth: 0` on checkout is needed for the diff.)

## Inspecting API keys (`vericto keys`)

See which API keys exist in the workspace — handy for spotting a stale CI key or
confirming *which* key a runner is authenticated as (marked `*`):

```bash
vericto keys list          # name, status, scopes, last-used — current key marked *
vericto keys list --json   # machine-readable, for scripting
```

Read-only by design and returns metadata only — never a key secret or hash.
Creating, revoking, or rotating keys stays in the dashboard: an API key must not
be able to manage other keys (that would be privilege escalation). Uses the same
`ci_dryrun:execute`-scoped key as `check`, and spends no check allowance.

## Documentation links (`vericto docs`)

Jump to the right doc without leaving the terminal — list every topic with its
URL, or open one straight in your browser:

```bash
vericto docs                 # topics grouped by category, with slugs to open
vericto docs enforcement     # open the "enforcement" page in your browser
vericto docs --json          # machine-readable, for scripting
```

The list groups topics by category (Getting started / Security & privacy /
Workspace). Each topic shows its name + a one-line blurb, with its full URL on
an indented line below. In terminals that support OSC 8 hyperlinks (iTerm2,
WezTerm, kitty, VS Code, Windows Terminal, GNOME Terminal, …) both the topic
name and the URL are **clickable** — click either to open that doc; elsewhere
the URL is shown as plain, copyable text.

Purely local — no network, no auth, no config needed. Links point at
`https://vericto.com/docs/<topic>`; override the base with `--app-url`
(or `$VERICTO_APP_URL`) for a self-hosted or staging docs site.

## Sending feedback (`vericto feedback`)

Send a bug report, an idea, or a note straight from the terminal — it lands in
your workspace's feedback inbox (the same place the dashboard's "share
feedback" writes to):

```bash
vericto feedback "the docs output looks great"
vericto feedback --category bug "rules show crashes on VERICTO-999"
echo "idea: add a --watch mode" | vericto feedback --category idea
vericto feedback            # no message → type it, then Ctrl-D
```

Categories are `bug`, `idea`, or `other` (default). Uses the same
`ci_dryrun:execute`-scoped API key as `check`; your CLI version is attached
automatically (via the User-Agent) so the team knows which build it came from.

## Project config (`.vericto.toml`)

Commit repo-wide defaults so pipelines don't repeat flags. Credentials are never
allowed here (use `vericto login` / env). Flags and env still override it.

```toml
# .vericto.toml
default_dialect = "postgres"
fail_on = "flag"
baseline = ".vericto-baseline.json"
```

Resolution order (first wins): flags → env → `.vericto.toml` → `~/.config/vericto/config.toml`
(`%APPDATA%\vericto\config.toml` on Windows).

## Browser login (default, for a developer at a keyboard)

`vericto login` with no flags opens your browser instead of asking you to paste
a key by hand — the same "verified login" pattern `gcloud`/`aws sso`/`gh` use:

```bash
vericto login
```

1. The CLI starts a local server on `127.0.0.1` and opens
   `https://vericto.com/cli-auth?state=...&port=...` in your default browser.
2. You're already signed in to the dashboard (or it prompts you to sign in and
   comes right back here) — pick the workspace you want the CLI to use and
   click **Authorize CLI**.
3. The dashboard mints a **30-day**, `ci_dryrun:execute`-scoped key and hands
   your browser a one-time code — never the key itself — which it passes back
   to the CLI's local server.
4. The CLI exchanges that code for the actual key server-to-server and saves
   it. The browser tab tells you it's done; the terminal picks up right after.

Nothing is typed or pasted. Revoke the key anytime from the dashboard's
Settings → API Keys (it's named "CLI (browser login)"), same as any other key.
This requires a browser on the same machine as the CLI — for a remote/headless
session, use `--api-key` (below) or `--oidc` (CI, see next section).

## CI login without a long-lived key (OIDC)

Instead of storing a static `vtro_...` key in a CI secret, a pipeline can
authenticate with a short-lived, per-run token via OIDC / workload-identity — the
same federation GitHub Actions and GitLab CI already provide for cloud vendors.
The CLI obtains the provider's OIDC ID token, exchanges it at the backend for a
key scoped to `ci_dryrun:execute` only, and holds it **in memory** for the run —
it is never written to disk.

```bash
# One-time: point the CLI at a workspace (stores no secret). If run in CI with a
# token available, it also verifies the exchange works.
vericto login --oidc --workspace ws_123

# In CI: --oidc is auto-enabled when there's no static key and a token exists.
vericto check --changed --oidc --workspace ws_123
```

- **GitHub Actions** — needs `permissions: id-token: write`; the CLI fetches the
  token from the Actions token endpoint with audience `vericto`.
- **GitLab CI** — add an `id_tokens:` entry exported as `VERICTO_ID_TOKEN` (override
  the var name with `--oidc-token-env`), audience `vericto`.
- Create a **trust policy** for the workspace in the dashboard (issuer, audience,
  and a subject glob like `repo:my-org/*`) so the backend knows which tokens to
  honor. `vericto doctor --workspace ws_123` reports the active auth mode.

`vericto init --oidc --workspace ws_123` scaffolds CI templates wired for this (no
`VERICTO_API_KEY` secret). Static keys keep working unchanged for local dev and
providers without OIDC.

## Signed run receipts (audit evidence you keep)

`--receipt` asks the backend for a **signed, self-contained record** of a check
and writes it to a file. It's verifiable **offline** — no Vericto account, no
network — so it stays valid as durable compliance evidence regardless of your
plan's dashboard retention.

```bash
# Produce a receipt alongside the check
vericto check migrations/*.sql --receipt vericto-receipt.json

# Later (or on another machine), verify authenticity offline
vericto verify-receipt vericto-receipt.json --show
```

- Signed with Ed25519 over the SHA-256 of the canonical payload (scheme
  `ed25519-sha256`, the same infra as Vericto's audit-trail export).
- `verify-receipt` reports **exit 0** when authentic, **exit 3** when the
  signature or payload doesn't check out, **exit 2** for a malformed file.
- Archive the file as a CI artifact (GitHub/GitLab retention, or your own
  storage) — retention becomes *your* decision.
- No public key is bundled in the binary yet, so pass it with
  `--public-key <PEM|path>` (or `$VERICTO_RECEIPT_PUBLIC_KEY`). Get it once from
  `GET /api/v1/meta/export-signing-key` (the `public_key` field; for a receipt
  signed before a key rotation, add `?key_id=<the receipt's public_key_id>`)
  and keep the `.pem` with your artifacts; verification itself stays offline.
  Without a key, `verify-receipt` exits `3` and says so. A large run split
  into chunks writes a JSON array of per-chunk receipts (all must verify).

> If the deployment hasn't configured signing, `--receipt` prints a warning and
> writes nothing — the check itself still runs and gates as usual.

## Scaffolding CI (`vericto init`)

`vericto init` detects your CI provider from the git remote and writes a ready-to-run
config; nothing is overwritten without `--force`.

```bash
vericto init                 # auto-detect GitHub/GitLab
vericto init --hook          # also install a git pre-commit hook for staged SQL
vericto init --target gitlab --dialect mysql
```

- **GitHub** → `.github/workflows/vericto.yml` (runs `vericto check --changed`, uploads
  SARIF to Code Scanning). Add `VERICTO_API_KEY` as a repo secret.
- **GitLab** → `.vericto/gitlab-ci.yml` (Code Quality report on MRs). `include:` it
  from your `.gitlab-ci.yml` and add `VERICTO_API_KEY` as a masked CI/CD variable.
- **`--oidc --workspace <id>`** → templates wired for OIDC / workload-identity
  (GitHub `id-token: write`, GitLab `id_tokens:`) — no `VERICTO_API_KEY` secret.
- **`--hook`** → `.git/hooks/pre-commit` checking staged `*.sql` (bypass with
  `git commit --no-verify`).

## Getting started

```bash
# One-time: opens your browser, mints a scoped key for the workspace you pick
vericto login

# Confirm everything works (reachability, auth, remaining quota)
vericto doctor
```

For scripts, headless boxes, or CI providers without OIDC support (§ below),
skip the browser and provide a key directly — it's verified against the
backend before anything is saved (a bad/revoked/wrong-scope key is rejected
here, not on the first `check` run mid-pipeline):

```bash
vericto login --api-key vtro_...
```

## Usage

```bash
# Check a migration file (exit 1 if anything is blocked)
VERICTO_API_KEY=vtro_... vericto check migrations/0001_init.sql --dialect postgres

# Multiple files / globs (shell-expanded)
vericto check migrations/*.sql

# From stdin (pre-commit hooks)
git show :migrations/0001_init.sql | vericto check - --dialect mysql

# Machine-readable output
vericto check schema.sql --format json

# Dry-run: report findings but never fail the build
vericto check schema.sql --monitor
```

### Options (`vericto check`)

| Flag | Default | Description |
|------|---------|-------------|
| `[files...]` | — | SQL files; `-` reads stdin. Optional with `--changed`/`--since` |
| `--changed` | off | Check only `*.sql` changed vs the CI merge base |
| `--since <ref>` | — | Explicit base ref for changed-file selection |
| `--stdin-file-list` | off | Read file paths from stdin, one per line (e.g. `git diff --name-only ... \| vericto check --stdin-file-list`) |
| `--dialect` | `postgres` | `postgres` \| `mysql` \| `oracle` \| `mssql` \| `snowflake` \| `sqlite` |
| `--format` | `text` | `text` \| `json` \| `sarif` \| `gitlab-codequality` \| `gitlab-sast` |
| `--output <file>` | stdout | Write the report to a file (CI artifacts) |
| `--receipt <file>` | — | Request a signed run receipt and write it to `<file>` (verify with `vericto verify-receipt`) |
| `--baseline <file>` | — | Ignore findings recorded in the baseline |
| `--monitor` | off | Report findings but exit 0 (dry-run) |
| `--fail-on` | `block` | `block` \| `flag` \| `any` — what causes exit 1 |
| `--timeout <secs>` | `30` | Per-request timeout (`$VERICTO_TIMEOUT`) |
| `--concurrency <n>` | `4` | Max in-flight chunk requests, capped at 8 (`$VERICTO_CONCURRENCY`) |
| `--ca-bundle <path>` | — | Extra CA PEM to trust (`$VERICTO_CA_BUNDLE`, then `$SSL_CERT_FILE`) |
| `--allow-degraded <reason>` | off | Exit 0 (not 4) if the backend is unreachable; reason required |
| `--allow-unsanitized` | off | If the workspace config can't be read, send the SQL as-is instead of failing (`$VERICTO_ALLOW_UNSANITIZED`) |
| `--api-key` | `$VERICTO_API_KEY` / config | Vericto API key (`vtro_...`) |
| `--api-url` | `https://api.vericto.com` | Backend URL (`$VERICTO_API_URL` / config) |
| `--oidc` | off | Authenticate via CI workload-identity (§ OIDC above); auto-enabled when no key + a token is present |
| `--workspace <id>` | `$VERICTO_WORKSPACE_ID` / config | Workspace to authenticate against for OIDC |
| `--audience <aud>` | `vericto` | OIDC audience to request in the ID token |
| `--oidc-token-env <VAR>` | `VERICTO_ID_TOKEN` | Env var holding a pre-minted OIDC token (GitLab-style) |
| `--quiet` / `-q` | off | Only print the summary line |
| `--no-color` | off | Disable ANSI color (also auto-off for non-TTY / `NO_COLOR`) |
| `--offline` | off | Evaluate locally with the standard rules, no network (`$VERICTO_OFFLINE`); see [Offline mode](#offline-mode) |

`--dialect`, `--fail-on` and `--baseline` fall back to `.vericto.toml`, then their
defaults.

### Configuration

Credentials and defaults resolve in this order (first wins):

1. `--api-key` / `--api-url` flags
2. `VERICTO_API_KEY` / `VERICTO_API_URL` environment variables
3. Config file written by `vericto login`:
   `$XDG_CONFIG_HOME/vericto/config.toml` (default `~/.config/vericto/config.toml`;
   on Windows `%APPDATA%\vericto\config.toml`), created with `0600` permissions,
   and on Windows with an access list that grants your user alone (no
   inherited entries).

```toml
# ~/.config/vericto/config.toml
api_url = "https://api.vericto.com"
api_key = "vtro_..."       # 0600; never logged
default_dialect = "postgres"
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Nothing at/above `--fail-on` |
| `1` | A finding at/above `--fail-on` |
| `2` | Usage error (bad args, unreadable file) |
| `3` | Auth/config error (missing/invalid key, plan not entitled, monthly check allowance used up) |
| `4` | Backend/network error (incl. a workspace config that can't be read — no SQL is sent) |

Distinct non-zero codes let CI distinguish a real block from an outage.

## Offline mode

```bash
# No account, no network: the standard rules at their default severities
vericto check --offline migrations/*.sql
git show :db/schema.sql | vericto check --offline - --dialect mysql
VERICTO_OFFLINE=1 vericto check db/migrate/
```

`--offline` (or `VERICTO_OFFLINE=1`) evaluates on your machine with the engine
built into the binary (`vericto-engine` 4.3.0) and its **42 standard rules at
their default severities**: Critical and High block, Medium flags, Low is
monitored, and, as in every online CI check, schema changes (DROP, ALTER,
TRUNCATE) are flagged rather than blocked. No request is made, to Vericto or
anyone else, and the SQL never leaves the machine. `--dialect`, `--fail-on`,
`--format`, `--output`, `--quiet`, `--monitor`, `--baseline`, inline
`-- vericto:ignore[...]`, `--changed` and `--since` (a local git diff) all work
as online, and the exit codes are the same.

It is a baseline gate: "is this SQL obviously dangerous?". It is not your
workspace's policy and not evidence that a check took place. Log in for your
workspace's rules and for the record.

### Offline and online compared

| | Offline (`--offline`) | Online (default) |
|---|---|---|
| Account, network | none; nothing leaves the machine | API key, login or OIDC; SQL goes to your workspace |
| Rules | the 42 standard rules, at their default severities | your workspace's rules: standard rules with your overrides, plus custom rules |
| Engine | the one in the binary (4.3.0 in 1.11.0) | the server's, always current |
| Schema DDL (DROP, ALTER, TRUNCATE) | flagged, as in every CI check | your workspace's policy, with the same CI cap |
| Sensitive columns, masking, agent allowlists, observe mode | no | yes |
| Parse errors | allowed and reported | your workspace's parse-error policy |
| Granularity | one result per file, with its strongest finding | one result per statement, at its line |
| Audit trail, run reports | no record anywhere | every check recorded, with CI provenance |
| Signed receipts (`--receipt`) | refused (exit `2`) | yes |
| Baselines | inline suppressions work; a baseline recorded online does not match offline findings | yes |
| Metered | no | counts against the plan's monthly CLI allowance |
| Windows | yes (x64 and ARM64), since 1.11.0 | yes |

### Which mode a run uses

- `--offline` or `VERICTO_OFFLINE=1`: offline, also in CI, even if a key is set.
- Outside CI, with no API key, no login and no OIDC token: offline on its own,
  and it says so on stderr.
- In CI (any of `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `CIRCLECI`,
  `JENKINS_URL`, `TF_BUILD`, `BITBUCKET_BUILD_NUMBER`, `TEAMCITY_VERSION`,
  `CODEBUILD_BUILD_ID`), a missing credential stays exit `3`: a pipeline whose
  secret went missing must not quietly fall back to fewer rules. Pass
  `--offline` there to choose it.
- Otherwise online. A present but invalid key is exit `3`, and an unreachable
  backend is exit `4` (or `--allow-degraded`): neither ever switches to offline.
- `.vericto.toml` cannot choose it: a committed `offline` key is rejected
  (exit `2`), like `api_key` and `allow_degraded`.

`--receipt`, `--oidc`, `--allow-degraded` and `--allow-unsanitized` need a
workspace, so offline mode refuses them (exit `2`) rather than ignoring them.

Every offline result says where it came from: `mode: offline` with the engine
version in the text summary and the CI failure header, `"mode": "offline"` and
`"engine_version"` in `--format json`, a `properties` bag (mode, engine and
ruleset version) in SARIF, a note on each finding in the GitLab reports, and
`Vericto (offline)` as the title of GitHub annotations. The ruleset version is
`standard@engine-<version>`. Online JSON and SARIF carry `"mode": "online"`.

A file with several statements reports the finding with the strongest action:
in `DROP TABLE a; UPDATE accounts SET balance = 0;` the DROP is flagged, but
the WHERE-less UPDATE blocks, so the file is BLOCKED and the run fails.

## CI/CD

GitHub and GitLab are both first-class: findings render inline on PRs/MRs, not
just as an exit code. See DESIGN §10 for the full integration design.

**GitHub Actions** (SARIF → Code Scanning annotations):
```yaml
- run: vericto check --changed --format sarif --output vericto.sarif
  env:
    VERICTO_API_KEY: ${{ secrets.VERICTO_API_KEY }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vericto.sarif
```

**GitLab CI** (Code Quality report → MR annotations):
```yaml
vericto-check:
  script: vericto check --changed --format gitlab-codequality --output gl-code-quality.json
  variables:
    VERICTO_API_KEY: $VERICTO_API_KEY
  artifacts:
    reports:
      codequality: gl-code-quality.json
  rules:
    - changes: [ "migrations/**/*.sql" ]
```

## Known limitations

- Workspace checks require network access to the Vericto backend; offline mode
  covers the standard rules only (see above). The API key
  needs the `ci_dryrun:execute` scope; checks count against the plan's monthly
  CLI allowance (free tier included).
- Findings are reported **per statement, at their line**, when the backend
  supports it (`check_files`). Against an older backend each file is evaluated
  as one unit and reported at **file granularity** (its most severe finding,
  annotated at line 1).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the checks CI
runs and how releases are cut. Report vulnerabilities as described in
[SECURITY.md](SECURITY.md), not in public issues.

## License

Source-available under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE)
(SPDX `FSL-1.1-ALv2`) since 1.10.0, the same license as the Vericto engine and
proxy: use, modify and redistribute it for any purpose other than a Competing
Use, and each version becomes Apache-2.0 two years after it is released.
Versions 1.9.1 and earlier remain under the Elastic License 2.0.
[LICENSING.md](LICENSING.md) answers the common questions, including how the
embedded engine is licensed; see also [NOTICE](NOTICE) and
[TRADEMARKS.md](TRADEMARKS.md).

`LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES` (the licenses of every crate and
C library compiled into the binary, generated by `third-party/notices.py`) ship
with every distribution: in each release archive, so also in what the
`@vericto/vericto-cli` npm package and the Homebrew formula install (the npm
package carries `LICENSE` itself too), and in the container image
(`/usr/share/doc/vericto/`, label `org.opencontainers.image.licenses=FSL-1.1-ALv2`).
