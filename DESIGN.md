# vetro-cli — Design (v0)

> Status: **v0.1 scaffold implemented** (`vetro check`).
> Decisions locked: **thin-client of the SaaS**, **new repo `vetro-cli`**, **Rust**,
> **HTTP/JSON transport** (gRPC evaluated and rejected — see §3), **whole-file
> submission** (no client-side statement splitting — see §5 / §12.3).

## 1. What it is

`vetro` is a command-line client for validating SQL against a Vetro workspace's
rules **before** it runs — in pre-commit hooks, code review, and CI/CD pipelines
("shift-left"). It is a **thin client**: it does not embed the engine or evaluate
locally. It sends SQL to the Vetro backend and reports the verdict.

```
migration.sql ──► vetro check ──HTTPS──► POST /api/v1/ci/check-key ──► engine
                      │                                                    │
                      └────────────── verdict + exit code ◄───────────────┘
```

### Goals
- One command to gate a pipeline on destructive/unsafe SQL: **exit 1 on block**.
- Use the workspace's **actual rules and enforcement policy** (same as runtime).
- Every check is recorded in the **central audit trail** (server-side).
- Trivial distribution: a single self-contained binary.

### Non-goals (v0)
- No offline / local evaluation (that's the local-first path we deliberately
  deferred — see §11 Open questions).
- No proxying or query execution — it only *evaluates*.
- No rule authoring UI (rules are managed in the dashboard).

## 2. Backend contract (already exists)

The CLI consumes the existing batch endpoint — no backend work required for v0:

- **Endpoint:** `POST /api/v1/ci/check-key`  (backend `routes/ci.ts`)
- **Auth:** API key `vtro_...` via `X-API-Key` (or `Authorization: Bearer`).
  Requires the **`ci_dryrun:execute`** scope; **gated to TEAM+** plans.
- **Request:**
  ```json
  {
    "queries": [ { "line": 12, "sql": "DELETE FROM users" } ],   // 1..500 items
    "dialect": "postgres",          // postgres|mysql|oracle|mssql (default postgres)
    "file_name": "migration.sql",   // optional, for the audit record
    "output_format": "json"          // text|json (we always request json; see §7)
  }
  ```
- **Response:**
  ```json
  {
    "summary": { "total": 3, "blocked": 1, "allowed": 2, "flagged": 0,
                 "monitored": 0, "parse_errors": 0, "ruleset_version": "v1.0.0-20260708" },
    "queries": [ {
      "line": 12, "sql_preview": "DELETE FROM users",
      "status": "BLOCKED", "action": "block",
      "rule_code": "VETRO-001", "ast_node_path": "DeleteStmt > WhereClause = NULL",
      "severity": "critical", "suggested_fix": "DELETE FROM users WHERE id = $1"
    } ],
    "exit_code": 1                   // 1 iff at least one BLOCKED (not parse errors)
  }
  ```

The CLI mirrors `exit_code` from the server as its process exit status.

## 3. Language / stack

**Recommendation: Rust** (with `clap` + `reqwest`), producing one static binary.

Rationale:
- Consistency with the rest of the stack (engine, proxy, eval are Rust).
- **Forward-compatible**: if we later add the local-first mode (embed
  `vetro-engine`, evaluate offline), it's a feature flag in the same binary, not
  a rewrite. A Go/Node thin-client would have to be thrown away to go local.
- Single static musl binary → trivial distribution (§9).

Alternative considered: **Go** — pragmatic for a pure HTTP client (fast builds,
great CLI ergonomics) but a dead end if we ever go local-first. Rejected for that
reason, not on merit.

### Transport: HTTP/JSON, not gRPC

**Decision: HTTP/JSON.** gRPC was evaluated and rejected:
- The backend is HTTP/REST (Fastify) and speaks no gRPC — adopting it would mean
  building a gRPC surface server-side first, for a client that doesn't exist yet.
- gRPC's strengths (bidirectional streaming, persistent low-latency channels,
  high-volume service-to-service RPC) don't apply: the CLI makes one batch POST
  per CI run and exits. No stream, no persistence, trivial volume.
- gRPC (HTTP/2) suffers over corporate proxies, firewalls and TLS-inspecting
  middleboxes — exactly the CI/CD environments the CLI runs in. HTTP/JSON passes
  everywhere and is debuggable with `curl`.
- The target endpoint (`/api/v1/ci/check-key`) already exists as REST, so the MVP
  ships with zero backend work.

Revisit only if a future feature needs streaming (e.g. a live "watch" mode) —
not on the roadmap.

## 4. Commands

```
vetro check [files...]     Evaluate SQL files (or stdin with '-'). The core command.
vetro login                Store an API key (interactive or --api-key).
vetro logout               Remove stored credentials.
vetro doctor               Verify config, connectivity, auth, and plan entitlement.
vetro version              Print version.
```

### `vetro check` — flags
| Flag | Default | Description |
|------|---------|-------------|
| `[files...]` | — | One or more `.sql` files or globs; `-` reads stdin |
| `--dialect <d>` | `postgres` | `postgres` \| `mysql` \| `oracle` \| `mssql` |
| `--format <f>` | `text` | `text` (human) \| `json` \| `sarif` (v0.2) |
| `--monitor` | off | Dry-run: report what *would* block, but exit 0 |
| `--fail-on <level>` | `block` | `block` \| `flag` \| `any` — what causes exit 1 |
| `--api-key <k>` | env/config | Override stored key |
| `--api-url <u>` | `https://api.vetro.dev` | Override backend |
| `--quiet` / `-q` | off | Only print the summary line |
| `--no-color` | off | Disable ANSI color (also honors `NO_COLOR`) |

## 5. Input handling

- **Files / globs:** `vetro check migrations/*.sql` — each file is read and split
  into statements (naive `;` split client-side; the server's engine does the real
  multi-statement parse). Each statement becomes a `{line, sql}` item so the
  report points at the offending line.
- **stdin:** `git diff --cached --name-only | ...` patterns, or
  `vetro check - < migration.sql` for pre-commit hooks.
- **Batching:** the endpoint accepts ≤500 queries per call. The CLI chunks larger
  inputs into multiple calls and aggregates the summary. **Chunking is logged** so
  a truncation is never silent.

## 6. Config & auth

Resolution order (first wins):
1. `--api-key` / `--api-url` flags
2. Env: `VETRO_API_KEY`, `VETRO_API_URL`
3. Config file: `~/.config/vetro/config.toml` (written by `vetro login`)

```toml
# ~/.config/vetro/config.toml
api_url = "https://api.vetro.dev"
api_key = "vtro_..."      # 0600 perms; never logged
default_dialect = "postgres"
```

`vetro login` stores the key; `vetro doctor` validates it and reports the plan
(surfacing the TEAM+ gate clearly rather than a raw 403 at check time).

## 7. Output

- **text** (default): colorized, one block per finding + a summary footer.
  ```
  ✖ migration.sql:12  BLOCKED  VETRO-001 (critical)  DELETE without WHERE
      DeleteStmt > WhereClause = NULL
      fix: DELETE FROM users WHERE id = $1

  1 blocked · 2 allowed · 0 flagged   (ruleset v1.0.0-20260708)
  ```
- **json**: the server response verbatim (plus CLI metadata) for scripting.
  The CLI **always requests `output_format=json`** from the server and renders
  text locally, so text/sarif formatting is a client concern and stays flexible.
- **sarif** (v0.2): emit SARIF 2.1.0 so GitHub Code Scanning shows findings as PR
  annotations — the headline shift-left integration.

## 8. Exit codes

| Code | Meaning |
|------|---------|
| `0` | No finding at/above `--fail-on` (default: nothing blocked) |
| `1` | At least one finding at/above `--fail-on` |
| `2` | Usage error (bad flag, unreadable file) |
| `3` | Auth/config error (missing/invalid key, plan not entitled) |
| `4` | Backend/network error (unreachable, 5xx, timeout) |

Distinct non-zero codes matter in CI so a network blip isn't confused with a real
block. (`--monitor` forces `0` for findings but not for codes 2–4.)

## 9. Distribution

- Prebuilt static binaries (Linux musl x86_64/arm64, macOS, Windows) attached to
  GitHub Releases of `vetro-cli`.
- `curl | sh` installer + Homebrew tap (`brew install vetro`).
- A tiny container image `ghcr.io/donkan168/vetro-cli` for CI runners that prefer
  an image step.
- **Versioning:** independent SemVer for the CLI. It pins a **minimum backend API
  version** it's compatible with and checks it in `doctor`.

## 10. CI/CD integration (the point of the product)

- **GitHub Actions:** a thin composite action wrapping the binary; `vetro check`
  on changed `.sql` files, `--format sarif` uploaded to Code Scanning.
- **Pre-commit hook:** `vetro init --hook` writes a `.git/hooks/pre-commit` (or a
  `.pre-commit-config.yaml` entry) that runs `vetro check` on staged SQL.
- **Generic:** any pipeline just runs `vetro check migrations/ && deploy`.

## 11. Phasing

- **v0.1 (MVP):** `check` (files + stdin), `--dialect`, `--format text|json`,
  `--monitor`, `--fail-on`, exit codes, `login`/`logout`, `doctor`, config+env.
- **v0.2:** globbing + chunking polish, `--format sarif`, GitHub Action,
  `vetro init` (hook + workflow scaffolding).
- **v0.3:** watch/dev ergonomics; consider caching the ruleset version in
  `doctor` output; shell completions.

## 12. Open questions (need product decisions)

1. **Plan gating.** `/ci/check-key` is TEAM+ only, so the CLI is effectively a
   paid feature with no free tier. Intentional? If free/builder users should get
   *something*, options: (a) a lower-tier endpoint with built-in rules only, or
   (b) revisit the local-first mode (offline, no account) for the free path. This
   is the biggest strategic call and blocks nothing technical, but shapes reach.
2. **Which dialect by default when files mix engines?** v0 assumes one `--dialect`
   per run. A repo with both PG and MySQL migrations needs either per-file
   detection or separate invocations. Propose: per-invocation for v0, document it.
3. **Statement splitting — RESOLVED.** The CLI sends each file **whole** as one
   `{line: 1, sql: <file>}` item; the engine already parses multi-statement SQL
   server-side, so no client-side `;` splitting (which breaks on `;` inside
   strings / `DO $$…$$`) and **no backend change** was needed — the existing
   `sql` field accepts the full text. Tradeoff: findings are reported at
   **file granularity** (most severe finding + its AST path), not per exact
   line. Acceptable for a CI gate; per-line mapping is a possible v0.2 refinement
   (client tokenizer or a backend that returns per-statement offsets).
4. **Backend availability in air-gapped CI.** A thin-client can't run where the
   runner has no egress to `api.vetro.dev`. Document as a known limitation (again
   points back to the local-first path for that audience).

## 13. Why not local-first (recorded for context)

We chose thin-client to reuse the workspace's live rules + central audit with zero
new evaluation code. The tradeoffs accepted: requires network + a TEAM+ account,
and the SQL leaves the machine (to the customer's own Vetro tenant). The engine is
a pure, I/O-free library (`evaluate(sql, dialect, rules, policy)`) with an embedded
28-rule default set, so a local-first mode remains possible later as a flag in the
same Rust binary without a rewrite — that's the main reason to build the CLI in
Rust now (see §3).
```
