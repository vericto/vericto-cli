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
> Enterprise-readiness additions (this revision — design only, 🔜 not yet
> implemented): OIDC/workload-identity login (§6), workspace-driven query
> sanitization instead of a CLI-side flag (§6/§7), CI provenance metadata on
> every check (§2), portable signed run receipts (§7), Sigstore/cosign binary
> signing (§9), system + custom CA trust (§6), bounded chunk concurrency (§5),
> project-level `.vetro.toml` config (§6), and a degraded-mode break-glass with
> its own exit code (§6/§8). Rationale and procurement framing in §14.

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
vetro login                Store an API key (interactive or --api-key).
vetro logout               Remove stored credentials.
vetro doctor               Verify config, connectivity, auth, and plan entitlement.
vetro baseline [files...]  Record current findings to .vetro-baseline.json (v0.2, §10).
vetro init                 Scaffold CI workflow + pre-commit hook (v0.2, §10).
vetro version              Print version.
```

### `vetro check` — flags
| Flag | Default | Description |
|------|---------|-------------|
| `[files...]` | — | One or more `.sql` files or globs; `-` reads stdin |
| `--changed` | off | Check only files changed vs the CI merge base (§10) — v0.2 |
| `--since <ref>` | — | Explicit base ref for changed-file selection (§10) — v0.2 |
| `--dialect <d>` | `postgres` | `postgres` \| `mysql` \| `oracle` \| `mssql` |
| `--format <f>` | `text` | `text` \| `json` \| `sarif` \| `gitlab-codequality` \| `gitlab-sast` (v0.2) |
| `--baseline <f>` | — | Ignore findings recorded in the baseline file (§10) — v0.2 |
| `--output <f>` | stdout | Write the report to a file (for CI artifacts) — v0.2 |
| `--monitor` | off | Dry-run: report what *would* block, but exit 0 |
| `--fail-on <level>` | `block` | `block` \| `flag` \| `any` — what causes exit 1 |
| `--timeout <secs>` | `30` | Per-request timeout (`VETRO_TIMEOUT`) — §6 |
| `--concurrency <n>` | `4` | Max in-flight chunk requests, capped at 8 (`VETRO_CONCURRENCY`) — §5, 🔜 |
| `--api-key <k>` | env/config | Override stored key |
| `--api-url <u>` | `https://api.vetro.dev` | Override backend |
| `--ca-bundle <path>` | — | Extra trusted CA PEM bundle (`VETRO_CA_BUNDLE` / `SSL_CERT_FILE`) — §6.4, 🔜 |
| `--allow-degraded <reason>` | off | Break-glass: exit 0 on backend-unreachable instead of 4, with a required reason — §6.5, 🔜 |
| `--quiet` / `-q` | off | Only print the summary line |
| `--no-color` | off | Disable ANSI color (also honors `NO_COLOR`) |

> Flags marked v0.2 are designed here but not yet implemented (see §11).

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

### 6.1 OIDC / workload-identity login (🔜 — point 1)

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
mode is active. Backend work required: the trust-policy config surface (new,
dashboard + `/oidc-exchange` route) — tracked as a dependency, not CLI-only.

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
  a local "degraded run" record (`file_name`, timestamp, git provenance from
  §2.1) that is **uploaded and reconciled server-side on the next successful
  check** from that workspace, so a gap in the audit trail is visible after the
  fact, not hidden.
- Requires a **reason**: `--allow-degraded="<why>"` — an empty/missing reason
  is a usage error (exit `2`), not silently accepted. The reason is included in
  the reconciliation record.
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

### 7.1 Signed run receipts — retention-independent evidence (🔜 — point 4)

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
not just displayable:

- The backend signs the response body (`summary` + `queries` + `provenance` +
  timestamp) with an existing key — reusing the **Ed25519 signing
  infrastructure already built for audit-trail export** (`vetro-fmw`,
  mentioned in §12.1) rather than introducing a second signing scheme.
- `--receipt <path>` (or default alongside `--output`, 🔜) writes the signed
  response as a standalone JSON file: `{ payload, signature, public_key_id }`.
- A `vetro verify-receipt <file>` subcommand (offline — no network call)
  checks the signature against the published Vetro public key (bundled in the
  CLI binary, rotated via a new-major-version bump if the signing key ever
  rotates) and prints pass/fail.
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
- **Phase 2 (adoption): Homebrew + Scoop + npm.** Cover macOS, Windows, and the
  Node ecosystem with little effort. `cargo-dist` makes Homebrew/Scoop nearly
  free; **npm** is the only one with real work — a package whose `postinstall`
  downloads the matching prebuilt binary from the GitHub release and installs the
  `vetro` shim (worth it because CI runners overwhelmingly already have Node, so
  `npx @vetro/cli check` is zero-install).

### Notes

- **Signing (concrete mechanism, 🔜 — point 5):** "signed" was previously
  unspecified — for a binary that runs inside CI pipelines holding credentials
  (§6.1), that's exactly the kind of vagueness a supply-chain security review
  pushes back on. Concrete plan: **Sigstore/`cosign` keyless signing**,
  integrated via `cargo-dist`'s native Sigstore support (it generates the
  signing step in the release workflow, so this is config, not a hand-rolled
  script — consistent with §9's "distribution surface as config" principle).
  Every release artifact gets a `.sig` + `.bundle` alongside the existing
  checksums; `cosign verify-blob` against the public Sigstore transparency log
  is the documented verification step (README, and referenced from
  `vetro init`-scaffolded CI templates so consuming pipelines can pin to a
  verified binary instead of trusting `curl | sh` on faith). No private key
  management burden — keyless signing ties the artifact to the GitHub Actions
  OIDC identity that built it, which is independently auditable.
- **Versioning:** independent SemVer for the CLI. Every channel's package version
  tracks the CLI's git tag exactly.
- **Backend compatibility check (🔜 — not yet built).** The CLI should fail
  clearly on an incompatible backend instead of mis-parsing a response. Concrete
  design: (1) the backend exposes its API version — a lightweight
  `GET /api/v1/version` returning `{ api_version, min_cli_version }`, and/or an
  `X-Vetro-Api-Version` response header on `/ci/check-key`; (2) the CLI embeds
  the **minimum backend API version** it requires; (3) `doctor` fetches and
  reports both, and `check` warns (not fails) on a minor skew, failing only on a
  hard major mismatch. Until this lands, `doctor` reports `ruleset_version` only —
  the §9 "pins a min backend version" guarantee is aspirational, tracked here so
  it isn't mistaken for implemented.
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
  $BASE...HEAD -- '*.sql' | vetro check --stdin-file-list` remains supported for
  pipelines that already compute the set.

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
- **v0.2:** the "make it a real team tool" release —
  - Output: `--format sarif` + `gitlab-codequality` + `gitlab-sast` (§7).
  - Integration: GitHub Action **and** GitLab CI templates; `vetro init`
    (hook + workflow scaffolding) (§10).
  - Changed-files selection: `--changed` / `--since` (§10).
  - Baseline + inline suppression: `vetro baseline`, `--baseline`,
    `-- vetro:ignore[...]` (§10).
  - Network resilience: `--timeout`, retries w/ backoff, proxy env (§6).
  - Chunking + partial-failure semantics (§5).
- **Distribution (parallel track, §9):** set up `cargo-dist` for Level 0 (signed
  cross-compiled binaries on GitHub Releases), then **Phase 1** (GitHub Releases
  + `curl | sh` + Docker) at launch, then **Phase 2** (Homebrew + Scoop + npm) as
  adoption grows. Can land alongside v0.2.
- **v0.3:** backend compatibility check (§9 Notes); watch/dev ergonomics;
  ruleset-version caching in `doctor`; shell completions. (No local-first mode —
  out of scope, §1.)

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
   and the bypass is reconciled server-side (visible in the audit trail as a
   gap with a reason attached, not as a clean run).
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
