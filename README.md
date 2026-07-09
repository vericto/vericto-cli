# vetro-cli

> Validate SQL against your Vetro workspace's security rules **before** it runs —
> in pre-commit hooks and CI/CD pipelines.

The installed command is `vetro`. It is a **thin client**: it sends SQL to the
Vetro backend (`POST /api/v1/ci/check-key`, API-key auth, TEAM+ plan) and mirrors
the verdict as a process exit code. It does not evaluate locally. See
[DESIGN.md](DESIGN.md) for the full design and rationale.

## Install

```bash
# from source (until prebuilt binaries are published)
cargo install --path .
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
| `--api-key` | `$VETRO_API_KEY` | Vetro API key (`vtro_...`) |
| `--api-url` | `https://api.vetro.dev` | Backend URL (`$VETRO_API_URL`) |
| `--quiet` / `-q` | off | Only print the summary line |

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

- Requires network access to the Vetro backend and a **TEAM+** plan
  (`ci_dryrun:execute` scope). No offline mode.
- Each file is sent whole and reported at **file granularity** (the most severe
  finding + its AST path), not per exact line.

## License

Elastic License 2.0.
