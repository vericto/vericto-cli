# vericto-cli

> Validate SQL against your Vericto workspace's security rules **before** it runs —
> in pre-commit hooks and CI/CD pipelines.

The installed command is `vericto`. It is a **thin client**: it sends SQL to the
Vericto backend (`POST /api/v1/ci/check-key`, API-key auth) and mirrors the verdict
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
curl -fsSL https://github.com/donkan168/vericto-cli/releases/latest/download/vericto-cli-installer.sh | sh

# Phase 1 — Docker (CI runners that prefer an image step)
docker run --rm -e VERICTO_API_KEY ghcr.io/donkan168/vericto-cli:latest check migrations/*.sql

# Or download a prebuilt binary directly:
#   https://github.com/donkan168/vericto-cli/releases
```

```bash
# Phase 2 — npm (great in CI: runners already have Node)
npm install -g @vericto/vericto-cli      # or: npx @vericto/vericto-cli check ...
```

```bash
# From source
cargo install --path .
```

> **npm:** the release pipeline builds the `@vericto/vericto-cli` package on every
> tag; publishing to the npm registry requires an `NPM_TOKEN` repo secret (see
> _Publishing to npm_ below). **Homebrew/Scoop remain planned** —
> `brew install donkan168/vericto/vericto`, `scoop install vericto` — pending a tap /
> bucket repo. Until a channel is live, use the shell installer, Docker image,
> or `cargo install`.

> The CLI is a network-only thin client — it always evaluates against your live
> Vericto workspace. There is no offline/local mode.

### Verifying a download

Every release ships SHA-256 checksums — `sha256.sum` (all artifacts) and a
per-artifact `.sha256` — for an integrity check:

```bash
# Verify a downloaded artifact against the published checksum
sha256sum -c vericto-cli-x86_64-unknown-linux-musl.tar.xz.sha256
```

> **Keyless build attestations** (Sigstore-backed provenance tied to the GitHub
> Actions identity that built the artifact, §9) are wired into the release
> pipeline but **currently disabled**: GitHub artifact attestations aren't
> available for user-owned _private_ repositories. Once this repo is public or
> moves under an org, re-enable them (see `dist-workspace.toml`) and verification
> becomes `gh attestation verify <artifact> --repo donkan168/vericto-cli`.

### Publishing to npm (maintainers)

The release pipeline builds the `@vericto/vericto-cli` npm package tarball on every
tag, but does not publish it. To publish `v0.1.0` to the registry:

```bash
# One-time: create an automation token at npmjs.com and grant the @vericto org
# publish rights, then either publish manually…
gh release download v0.1.0 --repo donkan168/vericto-cli --pattern 'vericto-cli-npm-package.tar.gz'
tar -xf vericto-cli-npm-package.tar.gz
cd vericto-cli-npm-package && npm publish --access public   # needs `npm login` / NPM_TOKEN
```

To automate it in CI, add an `NPM_TOKEN` repo secret and a publish step (or
cargo-dist's `publish-jobs = ["npm"]`) so tags publish the package directly.

## Commands

```
vericto check [files...]   Evaluate SQL files (or '-' for stdin). The core command.
vericto baseline [files]   Record current findings to .vericto-baseline.json.
vericto baseline prune     Remove baseline entries that no longer match any finding.
vericto rules list         List the workspace's effective rule catalogue.
vericto rules show <CODE>  Show one rule's detail (e.g. VERICTO-001), incl. its AST condition.
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

Suppress a single finding inline (a **reason is required**, so it stays
accountable):

```sql
DELETE FROM users; -- vericto:ignore[VERICTO-001] one-off backfill, tracked in JIRA-42
```

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

## Project config (`.vericto.toml`)

Commit repo-wide defaults so pipelines don't repeat flags. Credentials are never
allowed here (use `vericto login` / env). Flags and env still override it.

```toml
# .vericto.toml
default_dialect = "postgres"
fail_on = "flag"
baseline = ".vericto-baseline.json"
```

Resolution order (first wins): flags → env → `.vericto.toml` → `~/.config/vericto/config.toml`.

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
- The public key is bundled in the binary; override with `--public-key <PEM|path>`
  (or `$VERICTO_RECEIPT_PUBLIC_KEY`), fetched from
  `GET /api/v1/meta/export-signing-key`. A large run split into chunks writes a
  JSON array of per-chunk receipts (all must verify).

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
| `--dialect` | `postgres` | `postgres` \| `mysql` \| `oracle` \| `mssql` |
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
| `--api-key` | `$VERICTO_API_KEY` / config | Vericto API key (`vtro_...`) |
| `--api-url` | `https://api.vericto.com` | Backend URL (`$VERICTO_API_URL` / config) |
| `--oidc` | off | Authenticate via CI workload-identity (§ OIDC above); auto-enabled when no key + a token is present |
| `--workspace <id>` | `$VERICTO_WORKSPACE_ID` / config | Workspace to authenticate against for OIDC |
| `--audience <aud>` | `vericto` | OIDC audience to request in the ID token |
| `--oidc-token-env <VAR>` | `VERICTO_ID_TOKEN` | Env var holding a pre-minted OIDC token (GitLab-style) |
| `--quiet` / `-q` | off | Only print the summary line |
| `--no-color` | off | Disable ANSI color (also auto-off for non-TTY / `NO_COLOR`) |

`--dialect`, `--fail-on` and `--baseline` fall back to `.vericto.toml`, then their
defaults.

### Configuration

Credentials and defaults resolve in this order (first wins):

1. `--api-key` / `--api-url` flags
2. `VERICTO_API_KEY` / `VERICTO_API_URL` environment variables
3. Config file written by `vericto login`:
   `$XDG_CONFIG_HOME/vericto/config.toml` (default `~/.config/vericto/config.toml`),
   created with `0600` permissions.

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
| `3` | Auth/config error (missing/invalid key, plan not entitled) |
| `4` | Backend/network error |

Distinct non-zero codes let CI distinguish a real block from an outage.

## CI/CD

GitHub and GitLab are both first-class: findings render inline on PRs/MRs, not
just as an exit code. See DESIGN §10 for the full integration design.

**GitHub Actions** (SARIF → Code Scanning annotations — v0.2):
```yaml
- run: vericto check --changed --format sarif --output vericto.sarif
  env:
    VERICTO_API_KEY: ${{ secrets.VERICTO_API_KEY }}
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vericto.sarif
```

**GitLab CI** (Code Quality report → MR annotations — v0.2):
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

- Requires network access to the Vericto backend. No offline mode. The API key
  needs the `ci_dryrun:execute` scope; checks count against the plan's monthly
  CLI allowance (free tier included).
- Each file is sent whole and reported at **file granularity** (the most severe
  finding + its AST path), not per exact line.

## License

Elastic License 2.0.
