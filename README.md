# vetro-cli

> Validate SQL against your Vetro workspace's security rules **before** it runs —
> in pre-commit hooks and CI/CD pipelines.

The installed command is `vetro`. It is a **thin client**: it sends SQL to the
Vetro backend (`POST /api/v1/ci/check-key`, API-key auth) and mirrors the verdict
as a process exit code. It does not evaluate locally. Available on **every plan**
— checks are metered by a monthly CLI allowance (free tier included; team/
enterprise unmetered). See [DESIGN.md](DESIGN.md) for the full design.

## Install

```bash
# from source (until prebuilt binaries are published)
cargo install --path .
```

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

**GitHub Actions:**
```yaml
- run: cargo install --path .    # or download a released binary
- run: vetro check migrations/*.sql --dialect postgres
  env:
    VETRO_API_KEY: ${{ secrets.VETRO_API_KEY }}
```

**GitLab CI:**
```yaml
vetro-check:
  script: vetro check migrations/*.sql --dialect postgres
  variables:
    VETRO_API_KEY: $VETRO_API_KEY
  rules:
    - changes: [ "migrations/**/*.sql" ]
```

## Known limitations (v0.1)

- Requires network access to the Vetro backend. No offline mode. The API key
  needs the `ci_dryrun:execute` scope; checks count against the plan's monthly
  CLI allowance (free tier included).
- Each file is sent whole and reported at **file granularity** (the most severe
  finding + its AST path), not per exact line.

## License

Elastic License 2.0.
