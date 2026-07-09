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
signed, cross-compiled binaries on GitHub Releases feed every channel.

```bash
# Phase 1 — shell installer (Linux/macOS)
curl -fsSL https://github.com/donkan168/vetro-cli/releases/latest/download/vetro-installer.sh | sh

# Phase 1 — Docker (CI runners that prefer an image step)
docker run --rm -e VETRO_API_KEY ghcr.io/donkan168/vetro-cli check migrations/*.sql

# Or download a prebuilt binary directly:
#   https://github.com/donkan168/vetro-cli/releases
```

```bash
# Phase 2 — package managers
npm install -g @vetro/cli            # or: npx @vetro/cli check ...  (great in CI)
brew install donkan168/vetro/vetro   # macOS / Linux
scoop install vetro                  # Windows
```

```bash
# From source (until the above channels are published)
cargo install --path .
```

> The CLI is a network-only thin client — it always evaluates against your live
> Vetro workspace. There is no offline/local mode.

## Commands

```
vetro check [files...]   Evaluate SQL files (or '-' for stdin). The core command.
vetro login              Store an API key (and optional URL/dialect) in config.
vetro logout             Remove the stored API key.
vetro doctor             Verify config, connectivity, auth, and plan quota.
```

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
| `[files...]` | — | SQL files; `-` reads stdin (required) |
| `--dialect` | `postgres` | `postgres` \| `mysql` \| `oracle` \| `mssql` |
| `--format` | `text` | `text` \| `json` |
| `--monitor` | off | Report findings but exit 0 (dry-run) |
| `--fail-on` | `block` | `block` \| `flag` \| `any` — what causes exit 1 |
| `--api-key` | `$VETRO_API_KEY` / config | Vetro API key (`vtro_...`) |
| `--api-url` | `https://api.vetro.dev` | Backend URL (`$VETRO_API_URL` / config) |
| `--quiet` / `-q` | off | Only print the summary line |

`--dialect` falls back to the config's `default_dialect`, then `postgres`.

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

> `--changed`, `--format sarif|gitlab-*`, and `--output` are v0.2 (designed in
> DESIGN §10, not yet shipped). For v0.1, run `vetro check migrations/*.sql` and
> gate on the exit code.

## Known limitations (v0.1)

- Requires network access to the Vetro backend. No offline mode. The API key
  needs the `ci_dryrun:execute` scope; checks count against the plan's monthly
  CLI allowance (free tier included).
- Each file is sent whole and reported at **file granularity** (the most severe
  finding + its AST path), not per exact line.

## License

Elastic License 2.0.
