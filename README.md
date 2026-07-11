# vetro-cli

> Validate SQL against your Vetro workspace's security rules **before** it runs —
> in pre-commit hooks and CI/CD pipelines.

The installed command is `vetro`. It is a **thin client**: it sends SQL to the
Vetro backend (`POST /api/v1/ci/check-key`, API-key auth) and mirrors the verdict
as a process exit code. It does not evaluate locally. Available on **every plan**
— checks are metered by a monthly CLI allowance (free tier included; team/
enterprise unmetered). See [DESIGN.md](DESIGN.md) for the full design.

## Install

Releases are built with [`cargo-dist`](https://opensource.axo.dev/cargo-dist/):
cross-compiled binaries for Linux (x86_64/aarch64, static musl), macOS
(x86_64/aarch64), and Windows (x86_64) are published to GitHub Releases on every
version tag, each with SHA-256 checksums (see _Verifying a download_ below).
Every other channel serves those same binaries.

```bash
# Phase 1 — shell installer (Linux/macOS)
curl -fsSL https://github.com/donkan168/vetro-cli/releases/latest/download/vetro-cli-installer.sh | sh

# Phase 1 — Docker (CI runners that prefer an image step)
docker run --rm -e VETRO_API_KEY ghcr.io/donkan168/vetro-cli:latest check migrations/*.sql

# Or download a prebuilt binary directly:
#   https://github.com/donkan168/vetro-cli/releases
```

```bash
# Phase 2 — npm (great in CI: runners already have Node)
npm install -g @vetro/vetro-cli      # or: npx @vetro/vetro-cli check ...
```

```bash
# From source
cargo install --path .
```

> **npm:** the release pipeline builds the `@vetro/vetro-cli` package on every
> tag; publishing to the npm registry requires an `NPM_TOKEN` repo secret (see
> _Publishing to npm_ below). **Homebrew/Scoop remain planned** —
> `brew install donkan168/vetro/vetro`, `scoop install vetro` — pending a tap /
> bucket repo. Until a channel is live, use the shell installer, Docker image,
> or `cargo install`.

> The CLI is a network-only thin client — it always evaluates against your live
> Vetro workspace. There is no offline/local mode.

### Verifying a download

Every release ships SHA-256 checksums — `sha256.sum` (all artifacts) and a
per-artifact `.sha256` — for an integrity check:

```bash
# Verify a downloaded artifact against the published checksum
sha256sum -c vetro-cli-x86_64-unknown-linux-musl.tar.xz.sha256
```

> **Keyless build attestations** (Sigstore-backed provenance tied to the GitHub
> Actions identity that built the artifact, §9) are wired into the release
> pipeline but **currently disabled**: GitHub artifact attestations aren't
> available for user-owned _private_ repositories. Once this repo is public or
> moves under an org, re-enable them (see `dist-workspace.toml`) and verification
> becomes `gh attestation verify <artifact> --repo donkan168/vetro-cli`.

### Publishing to npm (maintainers)

The release pipeline builds the `@vetro/vetro-cli` npm package tarball on every
tag, but does not publish it. To publish `v0.1.0` to the registry:

```bash
# One-time: create an automation token at npmjs.com and grant the @vetro org
# publish rights, then either publish manually…
gh release download v0.1.0 --repo donkan168/vetro-cli --pattern 'vetro-cli-npm-package.tar.gz'
tar -xf vetro-cli-npm-package.tar.gz
cd vetro-cli-npm-package && npm publish --access public   # needs `npm login` / NPM_TOKEN
```

To automate it in CI, add an `NPM_TOKEN` repo secret and a publish step (or
cargo-dist's `publish-jobs = ["npm"]`) so tags publish the package directly.

## Commands

```
vetro check [files...]   Evaluate SQL files (or '-' for stdin). The core command.
vetro baseline [files]   Record current findings to .vetro-baseline.json.
vetro login              Store an API key (and optional URL/dialect) in config.
vetro logout             Remove the stored API key.
vetro doctor             Verify config, connectivity, auth, and plan quota.
vetro init               Scaffold a CI workflow (+ pre-commit hook with --hook).
vetro verify-receipt <f> Verify a signed run receipt offline (no network/account).
vetro version            Print the CLI version.
vetro completions <sh>   Print a shell completion script (bash|zsh|fish|powershell|elvish).
```

Enable completions by writing the script where your shell looks for them, e.g.:

```bash
vetro completions bash > ~/.local/share/bash-completion/completions/vetro
vetro completions zsh  > "${fpath[1]}/_vetro"   # zsh
vetro completions fish > ~/.config/fish/completions/vetro.fish
```

## Baseline & suppression

Adopting the CLI on a repo with pre-existing unsafe SQL shouldn't turn the build
red on day one. Record the current findings, then only *new* ones fail:

```bash
vetro baseline migrations/*.sql          # writes .vetro-baseline.json
vetro check migrations/*.sql --baseline .vetro-baseline.json
```

Suppress a single finding inline (a **reason is required**, so it stays
accountable):

```sql
DELETE FROM users; -- vetro:ignore[VETRO-001] one-off backfill, tracked in JIRA-42
```

## Project config (`.vetro.toml`)

Commit repo-wide defaults so pipelines don't repeat flags. Credentials are never
allowed here (use `vetro login` / env). Flags and env still override it.

```toml
# .vetro.toml
default_dialect = "postgres"
fail_on = "flag"
baseline = ".vetro-baseline.json"
```

Resolution order (first wins): flags → env → `.vetro.toml` → `~/.config/vetro/config.toml`.

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
vetro login --oidc --workspace ws_123

# In CI: --oidc is auto-enabled when there's no static key and a token exists.
vetro check --changed --oidc --workspace ws_123
```

- **GitHub Actions** — needs `permissions: id-token: write`; the CLI fetches the
  token from the Actions token endpoint with audience `vetro`.
- **GitLab CI** — add an `id_tokens:` entry exported as `VETRO_ID_TOKEN` (override
  the var name with `--oidc-token-env`), audience `vetro`.
- Create a **trust policy** for the workspace in the dashboard (issuer, audience,
  and a subject glob like `repo:my-org/*`) so the backend knows which tokens to
  honor. `vetro doctor --workspace ws_123` reports the active auth mode.

`vetro init --oidc --workspace ws_123` scaffolds CI templates wired for this (no
`VETRO_API_KEY` secret). Static keys keep working unchanged for local dev and
providers without OIDC.

## Signed run receipts (audit evidence you keep)

`--receipt` asks the backend for a **signed, self-contained record** of a check
and writes it to a file. It's verifiable **offline** — no Vetro account, no
network — so it stays valid as durable compliance evidence regardless of your
plan's dashboard retention.

```bash
# Produce a receipt alongside the check
vetro check migrations/*.sql --receipt vetro-receipt.json

# Later (or on another machine), verify authenticity offline
vetro verify-receipt vetro-receipt.json --show
```

- Signed with Ed25519 over the SHA-256 of the canonical payload (scheme
  `ed25519-sha256`, the same infra as Vetro's audit-trail export).
- `verify-receipt` reports **exit 0** when authentic, **exit 3** when the
  signature or payload doesn't check out, **exit 2** for a malformed file.
- Archive the file as a CI artifact (GitHub/GitLab retention, or your own
  storage) — retention becomes *your* decision.
- The public key is bundled in the binary; override with `--public-key <PEM|path>`
  (or `$VETRO_RECEIPT_PUBLIC_KEY`), fetched from
  `GET /api/v1/meta/export-signing-key`. A large run split into chunks writes a
  JSON array of per-chunk receipts (all must verify).

> If the deployment hasn't configured signing, `--receipt` prints a warning and
> writes nothing — the check itself still runs and gates as usual.

## Scaffolding CI (`vetro init`)

`vetro init` detects your CI provider from the git remote and writes a ready-to-run
config; nothing is overwritten without `--force`.

```bash
vetro init                 # auto-detect GitHub/GitLab
vetro init --hook          # also install a git pre-commit hook for staged SQL
vetro init --target gitlab --dialect mysql
```

- **GitHub** → `.github/workflows/vetro.yml` (runs `vetro check --changed`, uploads
  SARIF to Code Scanning). Add `VETRO_API_KEY` as a repo secret.
- **GitLab** → `.vetro/gitlab-ci.yml` (Code Quality report on MRs). `include:` it
  from your `.gitlab-ci.yml` and add `VETRO_API_KEY` as a masked CI/CD variable.
- **`--oidc --workspace <id>`** → templates wired for OIDC / workload-identity
  (GitHub `id-token: write`, GitLab `id_tokens:`) — no `VETRO_API_KEY` secret.
- **`--hook`** → `.git/hooks/pre-commit` checking staged `*.sql` (bypass with
  `git commit --no-verify`).

## Getting started

```bash
# One-time: store your key (prompts if --api-key is omitted)
vetro login --api-key vtro_...

# Confirm everything works (reachability, auth, remaining quota)
vetro doctor
```

## Usage

```bash
# Check a migration file (exit 1 if anything is blocked)
VETRO_API_KEY=vtro_... vetro check migrations/0001_init.sql --dialect postgres

# Multiple files / globs (shell-expanded)
vetro check migrations/*.sql

# From stdin (pre-commit hooks)
git show :migrations/0001_init.sql | vetro check - --dialect mysql

# Machine-readable output
vetro check schema.sql --format json

# Dry-run: report findings but never fail the build
vetro check schema.sql --monitor
```

### Options (`vetro check`)

| Flag | Default | Description |
|------|---------|-------------|
| `[files...]` | — | SQL files; `-` reads stdin. Optional with `--changed`/`--since` |
| `--changed` | off | Check only `*.sql` changed vs the CI merge base |
| `--since <ref>` | — | Explicit base ref for changed-file selection |
| `--stdin-file-list` | off | Read file paths from stdin, one per line (e.g. `git diff --name-only ... \| vetro check --stdin-file-list`) |
| `--dialect` | `postgres` | `postgres` \| `mysql` \| `oracle` \| `mssql` |
| `--format` | `text` | `text` \| `json` \| `sarif` \| `gitlab-codequality` \| `gitlab-sast` |
| `--output <file>` | stdout | Write the report to a file (CI artifacts) |
| `--receipt <file>` | — | Request a signed run receipt and write it to `<file>` (verify with `vetro verify-receipt`) |
| `--baseline <file>` | — | Ignore findings recorded in the baseline |
| `--monitor` | off | Report findings but exit 0 (dry-run) |
| `--fail-on` | `block` | `block` \| `flag` \| `any` — what causes exit 1 |
| `--timeout <secs>` | `30` | Per-request timeout (`$VETRO_TIMEOUT`) |
| `--concurrency <n>` | `4` | Max in-flight chunk requests, capped at 8 (`$VETRO_CONCURRENCY`) |
| `--ca-bundle <path>` | — | Extra CA PEM to trust (`$VETRO_CA_BUNDLE`, then `$SSL_CERT_FILE`) |
| `--allow-degraded <reason>` | off | Exit 0 (not 4) if the backend is unreachable; reason required |
| `--api-key` | `$VETRO_API_KEY` / config | Vetro API key (`vtro_...`) |
| `--api-url` | `https://api.vetro.dev` | Backend URL (`$VETRO_API_URL` / config) |
| `--oidc` | off | Authenticate via CI workload-identity (§ OIDC above); auto-enabled when no key + a token is present |
| `--workspace <id>` | `$VETRO_WORKSPACE_ID` / config | Workspace to authenticate against for OIDC |
| `--audience <aud>` | `vetro` | OIDC audience to request in the ID token |
| `--oidc-token-env <VAR>` | `VETRO_ID_TOKEN` | Env var holding a pre-minted OIDC token (GitLab-style) |
| `--quiet` / `-q` | off | Only print the summary line |
| `--no-color` | off | Disable ANSI color (also auto-off for non-TTY / `NO_COLOR`) |

`--dialect`, `--fail-on` and `--baseline` fall back to `.vetro.toml`, then their
defaults.

### Configuration

Credentials and defaults resolve in this order (first wins):

1. `--api-key` / `--api-url` flags
2. `VETRO_API_KEY` / `VETRO_API_URL` environment variables
3. Config file written by `vetro login`:
   `$XDG_CONFIG_HOME/vetro/config.toml` (default `~/.config/vetro/config.toml`),
   created with `0600` permissions.

```toml
# ~/.config/vetro/config.toml
api_url = "https://api.vetro.dev"
api_key = "vtro_..."       # 0600; never logged
default_dialect = "postgres"
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Nothing at/above `--fail-on` |
| `1` | A finding at/above `--fail-on` |
| `2` | Usage error (bad args, unreadable file) |
| `3` | Auth/config error (missing/invalid key, plan not entitled) |
| `4` | Backend/network error |

Distinct non-zero codes let CI distinguish a real block from an outage.

## CI/CD

GitHub and GitLab are both first-class: findings render inline on PRs/MRs, not
just as an exit code. See DESIGN §10 for the full integration design.

**GitHub Actions** (SARIF → Code Scanning annotations — v0.2):
```yaml
- run: vetro check --changed --format sarif --output vetro.sarif
  env:
    VETRO_API_KEY: ${{ secrets.VETRO_API_KEY }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vetro.sarif
```

**GitLab CI** (Code Quality report → MR annotations — v0.2):
```yaml
vetro-check:
  script: vetro check --changed --format gitlab-codequality --output gl-code-quality.json
  variables:
    VETRO_API_KEY: $VETRO_API_KEY
  artifacts:
    reports:
      codequality: gl-code-quality.json
  rules:
    - changes: [ "migrations/**/*.sql" ]
```

## Known limitations

- Requires network access to the Vetro backend. No offline mode. The API key
  needs the `ci_dryrun:execute` scope; checks count against the plan's monthly
  CLI allowance (free tier included).
- Each file is sent whole and reported at **file granularity** (the most severe
  finding + its AST path), not per exact line.

## License

Elastic License 2.0.
