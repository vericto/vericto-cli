# vetro-cli — Design (v0)

> Status: **v0.1 (MVP) implemented** — `check`, `login`, `logout`, `doctor`,
> config file + env/flag resolution, exit codes. Verified end-to-end against the
> local backend stack.
> Decisions locked: **thin-client of the SaaS** (no local/offline mode — ever,
> see §1/§13), **new repo `vetro-cli`**, **Rust**, **HTTP/JSON transport** (gRPC
> evaluated and rejected — see §3), **whole-file submission** (no client-side
> statement splitting — see §5 / §12.3), **distribution via `cargo-dist`** —
> GitHub Releases as the base, then `curl | sh` + Docker (phase 1) and Homebrew +
> Scoop + npm (phase 2), see §9.
> Enterprise-readiness additions: **OIDC/workload-identity login (§6.1)** and
> **portable signed run receipts + `verify-receipt` (§7.1)** — both ✅
> implemented this revision — plus workspace-driven query sanitization instead of
> a CLI-side flag (§6/§7), CI provenance metadata on every check (§2), bounded
> chunk concurrency (§5), project-level `.vetro.toml` config (§6), system +
> custom CA trust (§6), and a degraded-mode break-glass with its own exit code
> (§6/§8) — all implemented. **Distribution (§9)**: cargo-dist Level 0 + Phase 1
> (GitHub Releases with cross-compiled binaries + SHA-256 checksums + `curl | sh`
> installer + distroless Docker image) ✅ implemented; keyless build attestations
> are wired but gated off until the repo is public/org (§9 Notes), and package
> Phase 2 npm ✅ (the `@vetro/vetro-cli` package is built by the pipeline;
> publishing needs an `NPM_TOKEN`), Homebrew/Scoop remain 🔜. Rationale in §14.

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

### Non-goals (permanent)
- **No offline / local evaluation — ever.** The CLI is a thin client by design:
  it always evaluates against the live workspace (rules + enforcement policy +
  central audit) over the network. A local-first / embedded-engine mode is
  explicitly **out of scope** (not merely deferred). Air-gapped CI is a
  documented limitation, not a gap to close (see §12.4).
- No proxying or query execution — it only *evaluates*.
- No rule authoring UI (rules are managed in the dashboard).

## 2. Backend contract (already exists)

The CLI consumes the existing batch endpoint — no backend work required for v0:

- **Endpoint:** `POST /api/v1/ci/check-key`  (backend `routes/ci.ts`)
- **Auth:** API key `vtro_...` via `X-API-Key` (or `Authorization: Bearer`).
  Requires the **`ci_dryrun:execute`** scope. **Available on every plan**, metered
  by a monthly CLI allowance (`monthly_ci_check_count` vs `PLAN_CI_LIMIT`: free
  1000, builder 10000, team/enterprise unmetered) — see §12.1.
- **Request:**
  ```json
  {
    "queries": [ { "line": 12, "sql": "DELETE FROM users" } ],   // 1..500 items
    "dialect": "postgres",          // postgres|mysql|oracle|mssql (default postgres)
    "file_name": "migration.sql",   // optional, for the audit record
    "output_format": "json",         // text|json (we always request json; see §7)
    "provenance": {                  // 🔜 new — CI run metadata, see §2.1
      "git_sha": "a1b2c3d",
      "git_ref": "refs/heads/feature/x",
      "ci_provider": "github",
      "ci_run_url": "https://github.com/org/repo/actions/runs/123456",
      "actor": "octocat"
    }
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

### 2.1 CI provenance metadata (🔜 — point 3)

Without provenance, an audit-trail entry says *what* was checked but not
*where from* — which defeats the "immutable audit trail" pitch the moment a
compliance reviewer asks "show me the check for commit `a1b2c3d`". The CLI
auto-detects and attaches a `provenance` object on every `check-key` call,
best-effort (never fails the check if detection fails — fields are simply
omitted):

| Field | Source | Notes |
|---|---|---|
| `git_sha` | `git rev-parse HEAD` (shells out; no libgit2 dependency for this) | Omitted outside a git repo or on shallow clones without `HEAD` |
| `git_ref` | `GITHUB_REF` / `CI_COMMIT_REF_NAME` / `git symbolic-ref` fallback | Same detection family as `--changed` (§10) — one provider-detection module, reused |
| `ci_provider` | Presence of `GITHUB_ACTIONS` / `GITLAB_CI` / neither → `"local"` | |
| `ci_run_url` | Built from `GITHUB_SERVER_URL`/`GITHUB_REPOSITORY`/`GITHUB_RUN_ID`, or `CI_JOB_URL` (GitLab sets it directly) | |
| `actor` | `GITHUB_ACTOR` / `GITLAB_USER_LOGIN` | Never the API key or any credential — just the CI-reported username |

This is additive to the existing `/api/v1/ci/check-key` contract (new optional
object, no breaking change) and is stored alongside the existing
`ci_run_reports` row (§9 Notes) so a report can be traced to an exact commit,
branch, and pipeline run without the backend having to re-derive it from
`file_name` alone.

## 3. Language / stack

**Recommendation: Rust** (with `clap` + `reqwest`), producing one static binary.

Rationale:
- Consistency with the rest of the stack (engine, proxy, eval are Rust) — shared
  tooling, one language for the team to maintain.
- Single static binary → trivial, dependency-free distribution across platforms
  (§9), which also makes the npm and Homebrew wrappers thin.
- Mature CLI ergonomics (`clap`) and a rustls HTTP client with no system OpenSSL
  dependency — important for slim CI images.

Alternative considered: **Go** — also pragmatic for a pure HTTP client (fast
builds, great CLI ergonomics). Rust wins here purely on stack consistency; there
is no local-first ambition driving the choice (that mode is out of scope — §1).

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
vetro login                Store an API key (interactive or --api-key), or --oidc setup (§6.1).
vetro logout               Remove stored credentials.
vetro doctor               Verify config, connectivity, auth, and plan entitlement.
vetro baseline [files...]  Record current findings to .vetro-baseline.json (§10).
vetro init                 Scaffold CI workflow + pre-commit hook (§10); --oidc for workload-identity.
vetro verify-receipt <f>   Verify a signed run receipt offline (§7.1).
vetro version              Print the CLI version (same as --version).
vetro completions <shell>  Print a shell completion script (bash|zsh|fish|powershell|elvish).
```

### `vetro check` — flags
| Flag | Default | Description |
|------|---------|-------------|
| `[files...]` | — | One or more `.sql` files or globs; `-` reads stdin |
| `--changed` | off | Check only files changed vs the CI merge base (§10) |
| `--since <ref>` | — | Explicit base ref for changed-file selection (§10) |
| `--stdin-file-list` | off | Read the file paths to check from stdin, one per line (§10) |
| `--dialect <d>` | `postgres` | `postgres` \| `mysql` \| `oracle` \| `mssql` |
| `--format <f>` | `text` | `text` \| `json` \| `sarif` \| `gitlab-codequality` \| `gitlab-sast` |
| `--baseline <f>` | — | Ignore findings recorded in the baseline file (§10) |
| `--output <f>` | stdout | Write the report to a file (for CI artifacts) |
| `--receipt <f>` | — | Request a signed run receipt and write it to `<f>` (§7.1). Chunked runs write an array |
| `--monitor` | off | Dry-run: report what *would* block, but exit 0 |
| `--fail-on <level>` | `block` | `block` \| `flag` \| `any` — what causes exit 1 |
| `--timeout <secs>` | `30` | Per-request timeout (`VETRO_TIMEOUT`) — §6 |
| `--concurrency <n>` | `4` | Max in-flight chunk requests, capped at 8 (`VETRO_CONCURRENCY`) — §5 |
| `--api-key <k>` | env/config | Override stored key |
| `--api-url <u>` | `https://api.vetro.dev` | Override backend |
| `--oidc` | off | Authenticate via CI workload-identity instead of a static key (§6.1). Auto-enabled when no key is present and a CI OIDC token is available |
| `--workspace <id>` | env/config | Workspace to authenticate against for OIDC (`VETRO_WORKSPACE_ID`) — §6.1 |
| `--audience <aud>` | `vetro` | OIDC audience to request in the ID token — §6.1 |
| `--oidc-token-env <VAR>` | `VETRO_ID_TOKEN` | Env var holding a pre-minted OIDC ID token (GitLab-style) — §6.1 |
| `--ca-bundle <path>` | — | Extra trusted CA PEM bundle (`VETRO_CA_BUNDLE` / `SSL_CERT_FILE`) — §6.4 |
| `--allow-degraded <reason>` | off | Break-glass: exit 0 on backend-unreachable instead of 4, with a required reason — §6.5 |
| `--quiet` / `-q` | off | Only print the summary line |
| `--no-color` | off | Disable ANSI color (also honors `NO_COLOR`) |

## 5. Input handling

- **Files:** `vetro check migrations/*.sql` — the shell expands the glob; each
  file is read **whole** and sent as one `{line: N, sql: <file>}` item (no
  client-side `;` splitting — see §12.3). One item per file, indexed by argument
  position. Empty inputs are skipped.
- **stdin:** `vetro check - < migration.sql`, or `git show :file.sql | vetro
  check -` for pre-commit hooks.
- **Batching (v0.2):** the endpoint accepts ≤500 queries per call. v0.1 sends one
  item per file in a single call; explicit chunking/aggregation for very large
  file sets is a v0.2 refinement (and will be logged, never silently truncated).
- **Chunk concurrency (🔜 — point 7):** a large monorepo with thousands of
  migration files means dozens of 500-item chunks; running them strictly
  sequentially turns into dozens of serial round-trips per CI run, adding
  real wall-clock time to every pipeline. Chunks run with **bounded
  concurrency** — default 4 in-flight requests, overridable with
  `--concurrency <n>` / `VETRO_CONCURRENCY` (capped at 8 to stay a well-behaved
  client against the shared `PLAN_CI_LIMIT` budget; §12.1). This changes
  *scheduling* only, not the fail-closed semantics below — the aggregation
  step still waits for every dispatched chunk before deciding the run's
  outcome, in-flight or not.
- **Partial-failure semantics (chunked runs):** when input is split across
  multiple calls, chunk results (run with the concurrency above) are merged
  into one aggregated summary. If a chunk fails *transiently*, it is retried
  (§6 Network resilience); if it still fails, the whole run **fails closed** —
  the CLI reports which chunk failed and exits `4` (backend/network) rather than
  emitting a partial summary that could be mistaken for "all clear". A finding in
  any completed chunk still governs the finding exit code. This "no silent
  partial pass" rule mirrors the fail-closed posture of the proxy. See §6.5 for
  the one deliberate, explicit escape hatch from this rule.

## 6. Config & auth

Resolution order (first wins):
1. `--api-key` / `--api-url` flags
2. Env: `VETRO_API_KEY`, `VETRO_API_URL`
3. Project config: `.vetro.toml` at the repo root (🔜 — see §6.3)
4. User config file: `~/.config/vetro/config.toml` (written by `vetro login`)

```toml
# ~/.config/vetro/config.toml
api_url = "https://api.vetro.dev"
api_key = "vtro_..."      # 0600 perms; never logged
default_dialect = "postgres"
```

`vetro login` stores the key; `vetro doctor` validates it and reports the
remaining monthly CLI allowance (surfacing an exhausted-quota or scope problem
clearly rather than a raw 4xx at check time).

### 6.1 OIDC / workload-identity login (✅ — point 1)

A static `vtro_...` key with no expiry, sitting in a CI secrets vault
indefinitely, is exactly what enterprise security reviews flag first —
GitHub Actions and GitLab CI both already support OIDC federation for this
reason (AWS, GCP, and most vendor CLIs accept a workload token instead of a
long-lived credential).

**Design:** `vetro login --oidc` (or auto-detected when `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
/ GitLab's `CI_JOB_JWT_V2`-successor `id_tokens` are present and no `--api-key`
was given):

1. The CLI requests a short-lived OIDC ID token from the CI provider (GitHub's
   `ACTIONS_ID_TOKEN_REQUEST_URL`, or GitLab's configured `id_tokens` claim).
2. The CLI exchanges that token at a new backend endpoint,
   `POST /api/v1/auth/oidc-exchange`, presenting the ID token plus the target
   `workspace_id`. The backend validates the token's issuer/audience against a
   per-workspace trust configuration (dashboard-managed: "trust tokens from
   `repo:my-org/*`" — the same trust-policy shape as AWS IAM OIDC providers).
3. On success, the backend returns a **short-lived access token** (default
   15 min, capped to the job's expected runtime) scoped to `ci_dryrun:execute`
   only — never a full-scope API key.
4. The CLI holds this token in memory for the process lifetime only; it is
   never written to `~/.config/vetro/config.toml` or any file.

This is additive: static `vtro_...` keys keep working unchanged (needed for
local dev and CI providers without OIDC support). `doctor` reports which auth
mode is active.

**Implemented (this revision).** CLI side: `src/oidc.rs` obtains the provider ID
token — GitHub via the `ACTIONS_ID_TOKEN_REQUEST_URL`/`_TOKEN` endpoint (with the
requested `audience`), GitLab via the `id_tokens:`-exported env var (default
`VETRO_ID_TOKEN`, overridable with `--oidc-token-env`). `api::oidc_exchange`
POSTs `{ id_token, workspace_id }` to `/api/v1/auth/oidc-exchange` and receives
the short-lived key, held in memory only. Auth resolution (`resolve_auth` in
`main.rs`, shared by `check`/`baseline`/`doctor`) uses a static key when present
unless `--oidc` forces workload-identity, and auto-falls back to OIDC when no
static key exists but a CI token is available. `vetro login --oidc --workspace
<id>` stores the workspace/audience (never a secret) and, when run inside CI,
verifies the exchange live. `vetro init --oidc --workspace <id>` scaffolds
OIDC-flavored CI templates (GitHub `id-token: write` + `--oidc`; GitLab
`id_tokens:` + `--oidc`), with no `VETRO_API_KEY` secret. Backend side was
already in place: `services/oidc-exchange.ts` (JWKS validation, subject glob
matching, short-lived `ci_dryrun:execute` key minting), `routes/auth.ts`
`POST /oidc-exchange`, and `routes/oidc-policies.ts` (per-workspace trust-policy
CRUD).

Flags: `--oidc`, `--workspace <id>` (or `VETRO_WORKSPACE_ID` / `.vetro.toml`
`workspace_id` / config), `--audience <aud>` (default `vetro`),
`--oidc-token-env <VAR>`.

### 6.2 Query sanitization — inherits the workspace setting (🔜 — point 2)

`vetro-proxy` already has `TelemetryQueryMode` (`Raw` | `Sanitized` — literals
normalized to `$1, $2…` before anything leaves the process) as a
workspace-level, dashboard-configured setting synced via `/sync/rules`. The
CLI must **not** introduce a second, independent `--sanitize` flag: a
per-invocation client flag that a developer can forget (or a CI template that
doesn't set it) would silently create a data-residency gap the platform
already closed for the proxy path. Sanitization is a workspace policy, not a
per-command choice.

**Design:** the CLI has no `--sanitize` flag. Instead:

- The `/api/v1/ci/check-key` response (and the dashboard-side ruleset sync the
  CLI already implicitly depends on) carries the workspace's active
  `telemetry_query_mode` (`raw` | `sanitized`) — the same value `vetro-proxy`
  already resolves from `/sync/rules`, exposed here for the CLI path too.
- Today, `sql_preview` in the response is already server-truncated/rendered —
  the missing piece is that the **request body** (the full file text sent as
  `sql`) is always raw, regardless of the workspace setting. When the
  workspace is in `sanitized` mode, the CLI normalizes literals client-side
  *before* sending (same normalization the engine/proxy already do — see
  `vetro-eval`'s literal handling), so raw literal values never leave the
  machine in the first place. `doctor` reports the effective mode so a
  developer isn't guessed at.
- `--dialect`-aware normalization only (no attempt to sanitize inside opaque
  string blobs like `DO $$…$$` bodies — those are flagged, not rewritten,
  consistent with the engine's existing conservative-parsing stance).
- One workspace setting, enforced consistently across `vetro-proxy` and
  `vetro-cli` — no per-tool drift.

### 6.3 Project-level config: `.vetro.toml` (🔜 — point 8)

A rollout across hundreds of repos shouldn't mean re-typing `--dialect
mysql --fail-on flag` in every pipeline YAML. `.vetro.toml`, committed at the
repo root, is a fourth (lowest-priority-but-one) source in the resolution
order above — reviewable in a PR like any other config, unlike `~/.config`:

```toml
# .vetro.toml — committed to the repo, PR-reviewable
default_dialect = "mysql"
fail_on = "flag"
baseline = ".vetro-baseline.json"   # relative to repo root
```

No credentials are ever allowed in this file (`vetro check` rejects `api_key`
if present here, pointing at `vetro login` / env / OIDC instead) — it's
config, not a secrets store. Flags and env still override it.

### 6.4 CA trust — corporate TLS-inspecting proxies (🔜 — point 6)

The CLI's own rationale for HTTP/JSON over gRPC (§3) is that plain HTTPS
traverses TLS-inspecting corporate middleboxes better than HTTP/2. That
argument only holds if the HTTP client actually trusts the middlebox's CA.
`reqwest` with `rustls-tls` (the current setup) bundles `webpki-roots` and, by
default, does **not** read the OS trust store the way an OpenSSL-based client
would — so a network with a TLS-inspecting proxy that presents an internal CA
can still fail to connect even though the traffic is "just HTTPS".

**Design:**
- `--ca-bundle <path>` / `VETRO_CA_BUNDLE`: an additional PEM bundle trusted
  for the API connection, on top of the bundled Mozilla root store.
- Honor `SSL_CERT_FILE` (the common convention already respected by `curl`,
  Go, and most CLIs) as an implicit equivalent when the flag/env isn't set.
- Document the platform-native alternative for teams that would rather trust
  the OS store wholesale: switching the TLS backend to
  `rustls-tls-native-roots` (a `reqwest` feature flag) at build time — kept as
  a documented build option rather than the default, since it changes the
  trust model for every install, not just the ones behind an inspecting proxy.

### Network resilience

The CLI runs inside CI runners and behind corporate proxies, so transport has to
be robust and not fail a build for a transient blip:

- **Corporate proxies:** honors the standard `HTTP_PROXY` / `HTTPS_PROXY` /
  `NO_PROXY` environment variables (the `reqwest` client picks these up by
  default). This is a concrete payoff of the HTTP/JSON-over-gRPC choice (§3) —
  plain HTTPS traverses TLS-inspecting middleboxes that break HTTP/2.
- **Timeout:** per-request timeout defaults to 30s, overridable with
  `--timeout <secs>` / `VETRO_TIMEOUT` for slow links or large batches.
- **Retries:** transient failures (connection reset, timeout, and `429`/`5xx`
  responses) are retried up to 3 times with exponential backoff + jitter. A `429`
  honors the `Retry-After` header. Auth (`401`/`403`) and validation (`4xx` other
  than `429`) are **not** retried — they won't succeed on repeat. Exhausted
  retries surface as exit `4` (backend/network), distinct from a real finding.

### 6.5 Degraded-mode break-glass (🔜 — point 9)

With `--fail-on` gating a pipeline, a `api.vetro.dev` outage — even a short
one — fails every gated pipeline for every customer simultaneously. Today the
only escape is removing the `vetro check` step from the pipeline by hand,
which leaves no record that the gate was bypassed. For a control a compliance
team is relying on, an unauditable bypass is worse than a documented one.

**Design:** an explicit, narrow escape hatch — not a silent fallback:

- `--allow-degraded` (env: `VETRO_ALLOW_DEGRADED=1`): when the backend is
  unreachable after exhausting retries (§6), instead of exiting `4`, the CLI
  exits `0` **but** prints a prominent stderr warning and — critically — writes
  a local "degraded run" record so the bypass leaves an auditable trace instead
  of vanishing.
  - **Implemented (this revision):** the record is appended as one JSON line to
    `.vetro/degraded-runs.jsonl` (`kind`/`version`/`unix_time`/`reason`/`files`/
    `provenance` from §2.1), best-effort (a write failure never turns the
    break-glass back into a hard failure). The intended workflow is that the
    pipeline archives this file as a CI artifact, so the gap is visible after
    the fact.
  - **Not yet built (honest status):** there is *no* server-side reconciliation
    endpoint, so the record is **local only** — it is not uploaded or folded
    into the central audit trail on the next successful check. The original
    "uploaded and reconciled server-side" design remains 🔜 and depends on a new
    backend endpoint; until it lands the stderr warning says so explicitly, and
    the durable trace is whatever the pipeline archives. This is a deliberately
    conservative gap: in ephemeral CI runners the local file often dies with the
    runner, so "reconciled server-side" cannot be claimed as working when it
    isn't. See §14.
- Requires a **reason**: `--allow-degraded="<why>"` — an empty/missing reason
  is a usage error (exit `2`), not silently accepted. The reason is included in
  the local record.
- This does *not* change the §5 fail-closed rule for a *partially completed*
  chunked run (a backend that is reachable but returning errors mid-run) — it
  only applies when the backend is unreachable from the very first request,
  i.e. there was no run to speak of, degraded or otherwise. See "Fail-closed
  posture" discussion in §14 for why the boundary is drawn here.
- Off by default. Turning it on is a deliberate per-invocation (or per-pipeline
  env var) choice, never a config-file default — `.vetro.toml` (§6.3) rejects
  `allow_degraded` the same way it rejects credentials, for the same reason:
  it's a decision that should be visible in the pipeline YAML that made it, not
  buried in a file a reviewer might not think to check.

### Data handling & logging

The CLI submits SQL to the backend and prints results, so it must be disciplined
about what it writes and where:

- **Never logs the API key.** It is redacted from all output/verbose/error paths
  (clap's `hide_env_values`; the config file is `0600`). Error bodies from the
  server are shown as their human message only (§ `extract_message`), never raw
  auth headers.
- **SQL is user data, not a secret to the CLI — but it leaves the machine.** By
  design the SQL is sent to the customer's own Vetro tenant for evaluation (§13).
  The CLI never persists SQL locally beyond the request. Output shows a truncated
  `sql_preview` (returned by the server); `--quiet` prints only the summary line
  for logs that shouldn't echo query text at all.
- **Verbose mode (`-v`)** may print request URLs and timings but **never** the
  API key or full request bodies.
- **`--format json` / report artifacts** go to **stdout**; all diagnostics,
  notes and warnings go to **stderr**, so piping JSON never mixes in log noise.

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
- **gitlab-codequality** (v0.2): GitLab Code Quality report JSON, for inline MR
  annotations + the Code Quality widget (the GitLab analogue of SARIF; see §10).
- **gitlab-sast** (v0.2): GitLab SAST report JSON, so findings also appear in the
  MR Security tab for security-oriented teams (see §10).

All formats are rendered client-side from the one `output_format=json` response
the CLI always requests, so adding a format is a client concern — no backend
change.

### 7.1 Signed run receipts — retention-independent evidence (✅ — point 4)

§12.1 gates *browsing* history by plan (`PLAN_RETENTION_DAYS`: free 7 days,
builder 30, team 90). That's a reasonable growth lever for the dashboard
experience, but it means an enterprise buyer's audit evidence would otherwise
depend on staying on a given tier (or the retention window) years after a
check ran — a real procurement objection, since "keep paying or lose your
compliance evidence" is not a position most compliance teams will accept
contractually.

**Design:** decouple "evidence exists" from "the dashboard can show it to you."
`check-key`'s response already includes everything needed to prove what
happened; the addition is making that response **independently verifiable**,
not just displayable.

**Implemented (this revision).** Backend (already in place): `services/ci-receipt.ts`
builds a canonical `payload` (`kind`/`version`/`workspace_id`/`file_name`/`dialect`/
`summary`/`queries`/`exit_code`/`provenance`/`signed_at`), signs the SHA-256
digest of its **sorted-keys, compact JSON** (`canonicalJson`) with the existing
Ed25519 export-signing key (`utils/signing.ts`, scheme `ed25519-sha256`), and
attaches `{ payload, scheme, signature, public_key_id, sha256 }` to the
`check-key` response when the request sets `receipt: true`. The public key is
published at `GET /api/v1/meta/export-signing-key`. CLI side (new):

- The request sets `receipt: true` only when `--receipt <path>` is given.
- `--receipt <path>` writes the signed receipt as standalone JSON. A **chunked**
  run (each HTTP response signs only its own chunk) writes a JSON **array** of
  per-chunk receipts, since separate signatures can't be merged into one — no
  silent loss of coverage.
- `vetro verify-receipt <file>` verifies **offline** (no network, no account):
  `src/receipt.rs` reproduces the exact canonicalization (`serde_json` sorts keys
  and emits compact JSON — byte-for-byte identical to the backend, cross-checked
  against `canonicalJson`), recomputes the SHA-256 (a mismatch → clear
  "payload altered" error, distinct from a bad signature), and verifies the
  Ed25519 signature. It accepts a single receipt or an array; every one must
  verify. `--public-key <PEM|path>` overrides the key (or `VETRO_RECEIPT_PUBLIC_KEY`).
- Key handling (`src/pubkeys.rs`): the trusted public key(s) are bundled by
  `public_key_id`. Crucially, **multiple keys coexist**, so a signing-key
  rotation is handled by *adding* the new public key (keeping the old), not a
  major-version bump — old receipts keep verifying. Until an official key is
  published the registry is empty and verification requires `--public-key`
  (fetched from `/meta/export-signing-key`).
- Exit codes: a verification/authenticity failure is exit `3`; a malformed or
  unreadable receipt file is exit `2`.
- The customer's own pipeline archives this file as a build artifact
  (GitHub/GitLab artifact retention, or their own object storage) — retention
  becomes the customer's decision, on their own infrastructure, not bounded by
  Vetro's plan tier. The dashboard's hosted history remains the convenient,
  browsable *default*; the receipt is the durable, contractually
  defensible *fallback*.

## 8. Exit codes

| Code | Meaning |
|------|---------|
| `0` | No finding at/above `--fail-on` (default: nothing blocked) |
| `1` | At least one finding at/above `--fail-on` |
| `2` | Usage error (bad flag, unreadable file) |
| `3` | Auth/config error (missing/invalid key, plan not entitled) |
| `4` | Backend/network error (unreachable, 5xx, timeout) |

Distinct non-zero codes matter in CI so a network blip isn't confused with a real
block. (`--monitor` forces `0` for findings but not for codes 2–4. `--allow-degraded`,
§6.5, forces `0` in place of `4` specifically — and only — for a backend that is
unreachable from the first request, with a required reason and a server-side
reconciliation record; a stderr warning still prints so the exit code alone
doesn't hide it from a human watching the log.)

## 9. Distribution

Define **one release pipeline** — GitHub Releases with signed cross-compiled
binaries — and every other channel consumes from it. Channels differ wildly in
effort, so we layer them.

> **Status (this revision): Level 0 + Phase 1 ✅ implemented.** `cargo-dist` is
> configured (`dist-workspace.toml`) and generates `.github/workflows/release.yml`,
> which on every version tag cross-compiles all five targets, publishes them to
> GitHub Releases with SHA-256 checksums, and generates the `vetro-cli-installer.sh`
> `curl | sh` installer. (Keyless **build attestations** are wired but currently
> gated off — see the signing note below.) The image channel is a thin distroless
> `Dockerfile` (static musl binary) published multi-arch (amd64 + arm64) to GHCR
> by a separate `.github/workflows/docker.yml` — separate because `dist generate`
> owns and would overwrite `release.yml`. `dist plan`
> validates the artifact set. **Phase 2:** npm ✅ (built by the pipeline as
> `@vetro/vetro-cli`; publishing needs `NPM_TOKEN`), Homebrew/Scoop 🔜.

### Level 0 — the base (everything else depends on it)

**GitHub Releases with cross-compiled binaries.** A workflow that, on every tag,
builds for: `x86_64`/`aarch64-linux` (musl, static), `x86_64`/`aarch64-macOS`,
`x86_64-windows`. This is the prerequisite for nearly every channel below.

**Tooling: [`cargo-dist`](https://opensource.axo.dev/cargo-dist/).** It generates
the release workflow **plus** the `curl | sh` installer **plus** the
Homebrew/Scoop configs automatically — it's what `ripgrep`, `uv`, etc. use. This
keeps the whole distribution surface as config, not hand-maintained scripts.

### Rollout phases

- **Phase 1 (launch): GitHub Releases + `curl | sh` + Docker.** This covers CI/CD
  (the CLI's primary use case) and devs installing by hand. ~1 day of work with
  `cargo-dist` (the installer and release workflow are generated; the Docker
  image is a thin `FROM scratch`/`distroless` wrapper over the static musl
  binary).
- **Phase 2 (adoption): npm ✅, Homebrew + Scoop 🔜.** Cover the Node ecosystem,
  macOS, and Windows.
  - **npm — done (this revision):** `cargo-dist`'s `npm` installer
    (`installers = ["shell", "npm"]`, `npm-scope = "@vetro"`) generates the
    `@vetro/vetro-cli` package whose `postinstall` downloads the matching
    prebuilt binary from the GitHub release and installs the `vetro` shim. Worth
    it because CI runners overwhelmingly already have Node, so
    `npx @vetro/vetro-cli check` is zero-install. The pipeline *builds* the
    package tarball on every tag; *publishing* to the registry needs an
    `NPM_TOKEN` (a `npm publish` step or `dist`'s publish job) — the one manual
    setup left. (Package name is `@vetro/vetro-cli`, derived from the crate;
    not `@vetro/cli`.)
  - **Homebrew + Scoop — 🔜:** `cargo-dist` makes these nearly free but each
    needs an external repo you own (a Homebrew *tap* and a Scoop *bucket*); add
    `"homebrew"`/`tap = "..."` and a Scoop bucket to `dist-workspace.toml` once
    those repos exist.

### Notes

- **Signing (concrete mechanism, point 5 — designed, gated on repo visibility):**
  "signed" was previously unspecified — for a binary that runs inside CI
  pipelines holding credentials (§6.1), that's exactly the kind of vagueness a
  supply-chain security review pushes back on. The mechanism is **GitHub build
  attestations** (`github-attestations` in `dist-workspace.toml` → `release.yml`
  runs `actions/attest` with `id-token: write`): keyless, Sigstore-backed
  provenance for every release artifact — the same trust model originally
  sketched as `cosign` (keyless, transparency-logged, no private key to manage),
  wired in natively by `cargo-dist` 0.32 so it stays config, not a hand-rolled
  script. Verification would be `gh attestation verify <artifact> --repo
  donkan168/vetro-cli`. **Currently disabled**, though: GitHub artifact
  attestations are not available for user-owned *private* repos (the first
  `v0.1.0` release surfaced this — the Attest step fails with "Feature not
  available for user-owned private repositories"). Until the repo is public or
  under an org, `github-attestations` is off and releases ship **SHA-256
  checksums** (`sha256.sum` + per-artifact `.sha256`) for integrity; re-enabling
  is a one-line config change + `dist generate`. Same story for the Docker image
  attestation in `docker.yml`.
- **Versioning:** independent SemVer for the CLI. Every channel's package version
  tracks the CLI's git tag exactly.
- **Backend compatibility check (✅ — implemented).** The CLI fails clearly on
  an incompatible backend instead of mis-parsing a response: (1) the backend
  exposes `GET /api/v1/version` returning `{ api_version, min_cli_version }` and
  sets an `X-Vetro-Api-Version` header on `/ci/check-key` (both present in
  `routes/version.ts` / `routes/ci.ts`); (2) the CLI embeds the **minimum
  backend API version** it requires (`MIN_BACKEND_API_VERSION`); (3) `doctor`
  fetches `/version` and reports both, and `check` reads the response header and
  **warns on a minor skew, fails (exit 4) on a hard major mismatch**. An older
  backend that sends neither is treated as unknown and not blocked.
- **Platforms vs channels:** Linux/macOS/Windows are *targets* (the Level-0 build
  matrix), not channels — each channel just serves the right prebuilt binary for
  the host.
- **apt/yum deferred:** native Linux system packages (hosted repos, GPG signing,
  per-distro metadata) are the highest-maintenance option and are not planned —
  the `curl | sh` installer, Docker image, and npm already cover Linux CI.

## 10. CI/CD integration (the point of the product)

The verdict-in-the-terminal is table stakes; the product win is **findings shown
inline where code is reviewed** (PR/MR annotations). We treat **GitHub and GitLab
as equal first-class targets** — an earlier draft only detailed GitHub, which
undercut the growth loop §12.1 depends on (annotations are what take Vetro from
"one dev's terminal" to "the whole team's review").

### GitHub

- **Action:** a thin composite action wrapping the binary; `vetro check` on the
  PR's changed `.sql` files, `--format sarif` uploaded to **Code Scanning**
  (`github/codeql-action/upload-sarif`), which renders findings as PR
  annotations. `vetro init` can scaffold this workflow.

### GitLab (first-class parity)

GitLab does not consume SARIF; it has its own native report artifacts that render
in the Merge Request. We emit both so GitLab users get the same inline
experience, not just an exit code:

- **`--format gitlab-codequality`** → a **Code Quality report** (JSON). GitLab
  shows each finding as an inline MR annotation on the changed lines and a
  "Code Quality" MR widget. This is the GitLab analogue of GitHub's SARIF→Code
  Scanning path.
- **`--format gitlab-sast`** (optional) → a **SAST report** so findings also land
  in the MR Security tab / vulnerability report for security-oriented teams.
- Wired via `artifacts:reports:codequality:` (and `:sast:`) in `.gitlab-ci.yml`;
  `vetro init` can scaffold this too.

### Changed-files selection (the real CI flow)

The common need is "check the SQL *in this PR/MR*", not the whole tree. The CLI
supports selecting the diff so a large repo isn't re-checked every run:

- `--changed` — check only files changed vs the merge base (auto-detects the CI
  provider's base ref: `GITHUB_BASE_REF` / `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`,
  falling back to the default branch).
- `--since <ref>` — explicit base (e.g. `--since origin/main`).
- Filtered to `*.sql` (configurable). With no changed SQL, `check` exits 0 and
  says so — an empty diff is a pass, never an error.
- Composes with hand-rolled patterns too: `git diff --name-only --diff-filter=d
  $BASE...HEAD -- '*.sql' | vetro check --stdin-file-list` (✅ implemented) reads
  the paths from stdin, one per line, for pipelines that already compute the set.

### Baseline / suppression (adoption in legacy repos)

Without a baseline, dropping the CLI into a repo with pre-existing unsafe SQL
turns the build red on day one — the fastest way to get uninstalled. So:

- `vetro baseline` writes a `.vetro-baseline.json` capturing the *current* set of
  findings (by stable fingerprint: rule code + normalized AST path + file, **not**
  line number, so edits elsewhere don't shift it).
- `vetro check --baseline .vetro-baseline.json` reports baselined findings as
  informational and **does not fail** on them; only *new* findings above
  `--fail-on` trip the exit code.
- Inline suppression: a `-- vetro:ignore[VETRO-001] reason` comment on/above a
  statement suppresses that one finding (reason required, surfaced in reports for
  auditability).
- Baseline drift (a baselined finding that disappeared) is reported so stale
  entries can be pruned.

### Pre-commit & generic

- **Pre-commit hook:** `vetro init --hook` writes a `.git/hooks/pre-commit` (or a
  `.pre-commit-config.yaml` entry) that runs `vetro check --changed` on staged SQL.
- **Generic:** any pipeline can just run `vetro check migrations/ && deploy`.

## 11. Phasing

- **v0.1 (MVP) — DONE:** `check` (files + stdin), `--dialect`, `--format
  text|json`, `--monitor`, `--fail-on`, exit codes, `login`/`logout`, `doctor`,
  config file + env + flags.
- **v0.2 — DONE:** the "make it a real team tool" release —
  - Output: `--format sarif` + `gitlab-codequality` + `gitlab-sast` (§7).
  - Integration: GitHub Action **and** GitLab CI templates; `vetro init`
    (hook + workflow scaffolding, `--oidc` variant) (§10).
  - Changed-files selection: `--changed` / `--since` / `--stdin-file-list` (§10).
  - Baseline + inline suppression: `vetro baseline`, `--baseline`,
    `-- vetro:ignore[...]` (§10).
  - Network resilience: `--timeout`, retries w/ backoff, proxy env (§6).
  - Chunking + partial-failure semantics (§5).
- **Enterprise-readiness — DONE (this revision):** OIDC/workload-identity login
  (§6.1), signed run receipts + `verify-receipt` (§7.1), CI provenance (§2.1),
  `.vetro.toml` (§6.3), CA trust (§6.4), degraded-mode break-glass (§6.5, with
  the server-side reconciliation caveat noted there), bounded chunk concurrency
  (§5), backend compatibility check (§9), `--no-color`, `vetro version`,
  `vetro completions <shell>` (bash/zsh/fish/powershell/elvish).
- **Distribution (§9) — Level 0 + Phase 1 DONE, Phase 2 npm DONE:** `cargo-dist`
  (`dist-workspace.toml` + generated `release.yml`) publishes cross-compiled
  binaries + SHA-256 checksums to GitHub Releases with a `curl | sh` installer,
  plus a distroless multi-arch Docker image to GHCR (`docker.yml`), plus the
  `@vetro/vetro-cli` npm package (built on tag; publishing needs `NPM_TOKEN`).
  Keyless build attestations are wired but gated off on a private repo (§9
  Notes). **Homebrew + Scoop** remain 🔜 (need an external tap/bucket repo).
- **Still 🔜:** distribution Homebrew/Scoop; npm registry publish (`NPM_TOKEN`);
  keyless attestations (repo must be public/org); server-side reconciliation of
  degraded runs (§6.5); watch/dev ergonomics. (No local-first mode — out of
  scope, §1.)

## 12. Open questions (need product decisions)

1. **Plan gating — RESOLVED (strategy below).** The CLI is available on **every
   plan**, not just TEAM+. The mechanism is done; the surrounding pricing
   strategy is the design direction we're steering toward (most rows below are
   still roadmap — see the ✅/🔜 markers).

   **Principle — don't gate the tool, gate scale and advanced features.** The
   fear is real and common: if the free tier does everything, the pricing table
   doesn't convert. But the answer isn't to deny free users the CLI — it's to
   give it in free, limited by *volume and depth*, so free delights and the
   limit pushes. A free, powerful CLI is the **adoption hook**: a dev drops it
   into their pre-commit, loves it, brings it to their team — and *that's* where
   volume + team features force the upgrade. Semgrep, Snyk and Trivy all grew
   exactly this way (free CLI, monetize scale + collaboration + compliance).

   **In one line:** free = one dev protects their laptop · Builder = a project
   with its own rules · Team = a team with compliance evidence. The CLI spans all
   three, but each tier tops out exactly where the next plan solves the pain.

   **How it avoids cannibalization — the tier map** (✅ = implemented today,
   🔜 = roadmap):

   | Dimension | Free | Builder ($49) | Team ($149) | Enterprise |
   |---|---|---|---|---|
   | Runtime queries/mo (proxy) | 500K ✅ | 5M ✅ | unlimited ✅ | unlimited ✅ |
   | CLI checks/mo (separate counter) | 500–1000 ✅ | 10000 ✅ | unlimited ✅ | unlimited ✅ |
   | Rules in the CLI | built-in (28) ✅ | + custom (5) ✅ | + custom (20) ✅ | unlimited ✅ |
   | Output format | text/json ✅ | + SARIF 🔜 | + SARIF 🔜 | + SARIF 🔜 |
   | Run reports in dashboard/audit | terminal-only, no history 🔜 | 30-day history 🔜 | 90-day history + export 🔜 | unlimited 🔜 |
   | SARIF → PR annotations, `vetro init` | basic 🔜 | ✅ 🔜 | ✅ 🔜 | ✅ 🔜 |

   Why this converts without cannibalizing:
   - **The CLI-checks limit bites where it should.** 500–1000 checks/mo is plenty
     for an individual dev testing locally, but a team with CI on every PR burns
     through them in days. The limit isn't "you can't use the CLI", it's "you
     can't scale it to your team without paying" — exactly when they should pay.
   - **Custom rules stay Builder's hook.** Free uses the 28 built-ins; the moment
     a user wants "block DELETE on *our* `payments` table specifically" (a custom
     rule) they need Builder. The free CLI gets them to that moment faster.
   - **Audit/compliance stays Team.** Free can run checks; the *historical,
     exportable* record is Team — the SOC2 differentiator we already built
     (Ed25519 signatures).

   **Refinements to the raw strategy (deliberate design calls):**
   - **Run reports: persist for everyone, gate retention + access — do NOT make
     free truly ephemeral.** Persisting a run is cheap, and history is the best
     conversion lever we have ("upgrade to see your last 30 days of checks").
     So: `check-key` keeps writing `ci_run_reports` on every plan (it already
     does); free just can't *browse* history — the dashboard/history view and
     export are gated by `PLAN_RETENTION_DAYS` (free 7 / builder 30 / team 90).
     Free is "go/no-go in your terminal"; paid unlocks the record that already
     exists. (Needs a plan-gated read endpoint for `ci_run_reports` — 🔜.)
   - **SARIF: give the *format* free, charge the *integration convenience*.**
     SARIF-in-PRs is precisely the viral loop from "one dev" to "the whole team
     sees Vetro", so gating the raw output would throttle the growth that drives
     Team conversions. Plan: `--format sarif` output is free; the polished
     GitHub Action + `vetro init` scaffolding + custom rules are where Builder+
     earns it. (SARIF itself is v0.2 — 🔜.)

   **Technical change this implies (the runtime-vs-CI counter split):** ✅ done —
   `assertQueryQuota` (runtime) and `assertCiQuota` (CLI) are now separate.
   `workspaces.monthly_ci_check_count` is metered by `PLAN_CI_LIMIT` (free 1000,
   builder 10000, team/enterprise unmetered) instead of a hard plan floor, so any
   plan can consume up to its cap without touching the runtime-query budget that
   protects the production database. The response carries `ci_checks_remaining`;
   the CLI warns as it runs low and `doctor` reports it. Still 🔜: SARIF gating,
   the `ci_run_reports` history read endpoint, and format/feature gates.
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
4. **Backend availability in air-gapped CI — RESOLVED (won't fix).** A thin
   client can't run where the runner has no egress to `api.vetro.dev`. This is an
   **accepted, permanent limitation**, documented as such. There is no local /
   offline fallback (§1); air-gapped environments are simply not a supported
   audience for the CLI.

## 13. Why thin-client, and why *not* local-first (decision)

We chose thin-client to reuse the workspace's live rules + enforcement policy +
central audit with zero new evaluation code, and this is now a **settled
decision, not a stepping stone**. The tradeoffs are accepted permanently:

- **Requires network egress** to the customer's Vetro backend (air-gapped CI is
  unsupported — §12.4).
- **SQL leaves the machine** — sent to the customer's own Vetro tenant for
  evaluation.

In exchange the CLI always reflects the *live* ruleset and every check lands in
the central audit trail — properties a local/offline evaluator could not offer
without duplicating rule distribution and forgoing the audit record. A
local-first / embedded-engine mode is **explicitly out of scope** (§1); the CLI
will not ship an offline evaluator. Rust remains the right choice on stack
consistency and single-binary distribution grounds alone (§3) — the earlier
"keeps local-first open" rationale no longer applies and has been removed.

## 14. Enterprise-readiness rationale (this revision)

This section records *why* §2.1/§6.1–§6.5/§7.1/§9 were added, and draws the
line on what they deliberately do not change.

### Fail-closed posture — reaffirmed, boundary clarified

The existing fail-closed rule (§5: a chunk that fails after retries fails the
*whole run* rather than emitting a partial summary) is the right call for this
product and is **not weakened** by this revision — it's the correct default
for a security gate, and loosening it by default would undermine the "shift
left" pitch (§1). What this revision adds is not a softer default, but a
**narrow, explicit, logged exception** (§6.5 `--allow-degraded`) for exactly
one scenario: the backend is unreachable before any evaluation happened at
all. That's a materially different failure than "some queries were evaluated,
some weren't" (which stays fail-closed, full stop) — it's "the security gate
itself is down," which is an availability incident, not a security decision,
and forcing every customer's deploys to halt during a Vetro-side outage with
no recorded, auditable way to proceed is its own risk (an unreviewed manual
bypass, with no trace, is worse than a reviewed one).

The design keeps three properties that matter for an enterprise buyer
evaluating this as a *control*, not just a feature:
1. **Off by default** — nothing changes unless a team opts in per-pipeline.
2. **Never silent** — a reason is mandatory, a stderr warning always prints,
   and the bypass writes a local `.vetro/degraded-runs.jsonl` record (reason +
   provenance + timestamp) meant to be archived as a CI artifact. *Server-side*
   reconciliation into the central audit trail is still 🔜 (§6.5): today the
   trace is local only, so the honest claim is "leaves an auditable local
   record", not "reconciled server-side". Closing that gap needs a new backend
   ingest endpoint.
3. **Scoped to unreachability, not to findings** — it cannot be used to skip a
   `BLOCKED` verdict that was actually returned; it only overrides exit `4`
   (backend/network), never exit `1` (a real finding). A team cannot use
   `--allow-degraded` to wave through a query the engine already flagged.

If anything, I'd push this further than "designed" to "load-bearing for the
sales motion": document in the buyer-facing materials (not just this design
doc) that the *absence* of any bypass is itself sometimes the wrong answer —
some enterprise security teams will explicitly ask "what happens to our
deploys when Vetro is down?" and "nothing, ever, no matter what" is not
always the answer they want either. Having a reviewed, audited answer to that
question is a sales asset, not just a technical safety valve.

### Air-gapped / fully offline environments — still out of scope, and why that's fine to say plainly

§1/§13 already close the door on a local-evaluation mode, permanently. This
revision doesn't reopen that door — OIDC (§6.1) still requires reaching the
Vetro backend; sanitization (§6.2) still requires a workspace policy fetched
from the backend; signed receipts (§7.1) still require a signature *from* the
backend. None of this makes the CLI work without network egress to
`api.vetro.dev`.

That means a specific, real buyer segment is **not addressable** by this
product as designed: banks, defense, and other heavily regulated
organizations that run CI on fully air-gapped runners with no egress to any
external SaaS, as a hard compliance requirement (not a preference) — often
mandated by the regulator, not just internal policy. For that segment, "the
tool needs to phone home to work" is disqualifying on its own, independent of
how good the rest of the product is.

The reason to say this **explicitly in the document** rather than leave it
implicit: a design that quietly doesn't mention this reads, to a future
engineer or a sales engineer scoping a deal, as an oversight to eventually
fix. Stating it as a deliberate, permanent scope boundary — the same way §1
already labels "no local mode" a decision and not a gap — sets the correct
expectation before a sales cycle is sunk into a prospect that was never
approvable, and prevents a well-meaning future contributor from "fixing" it
by building the local-evaluation mode §13 already rejected for good reasons
(duplicating rule distribution, forgoing the central audit trail). It's the
same discipline §12.4 already applies to air-gapped CI generally — this
revision's OIDC/sanitization/receipts features just make the boundary sharper
because they add *more* backend-dependent capability, not less.
