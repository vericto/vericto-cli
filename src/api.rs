//! HTTP client for the Vericto CI dry-run endpoint.
//!
//! The CLI is a thin client: it does not evaluate SQL locally. It sends the SQL
//! to `POST /api/v1/ci/check-key` (API-key auth, `ci_dryrun:execute` scope) and
//! renders the verdict. The request/response shapes here mirror the backend
//! contract (`routes/ci.ts`).

use serde::{Deserialize, Serialize};

/// One SQL unit to evaluate. We send the whole file as a single item (line 1):
/// the engine parses multi-statement SQL server-side, so we don't split here.
#[derive(Debug, Clone, Serialize)]
pub struct QueryInput {
    pub line: u32,
    pub sql: String,
}

/// CI run provenance (§2.1). Attached best-effort to every request so the audit
/// record can be traced to a commit/branch/pipeline. Additive to the backend
/// contract — older backends ignore the unknown field. Empty fields are omitted.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    pub ci_provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_run_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

/// Request body for `POST /api/v1/ci/check-key`.
#[derive(Debug, Serialize)]
pub struct CheckRequest {
    pub queries: Vec<QueryInput>,
    pub dialect: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    /// The backend can render text/json; we always request json and format
    /// locally, so this stays "json".
    pub output_format: String,
    /// CI provenance (§2.1); omitted entirely when detection produced nothing
    /// useful (e.g. no git, no CI env).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// Request a signed run receipt (§7.1). Only sent when true, so older
    /// backends and non-receipt runs see the unchanged body.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub receipt: bool,
}

/// A signed run receipt (§7.1): self-contained, offline-verifiable evidence that
/// a check happened, independent of dashboard retention. The backend signs the
/// canonical JSON of `payload` (recursively sorted keys) with Ed25519 over its
/// SHA-256 digest (scheme `ed25519-sha256`). `verify-receipt` reproduces that
/// canonicalization and checks the signature against the bundled/ published
/// public key — no network, no account.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Receipt {
    /// The exact object that was signed. Kept as an opaque `Value` so the CLI
    /// re-serializes it byte-identically to how the backend canonicalized it,
    /// rather than risking drift from a typed re-encode.
    pub payload: serde_json::Value,
    /// Signature scheme identifier, e.g. `ed25519-sha256`.
    pub scheme: String,
    /// Base64 Ed25519 signature over the SHA-256 digest of the canonical payload.
    pub signature: String,
    /// Which published key signed this, so a verifier can select the right one.
    pub public_key_id: String,
    /// Hex SHA-256 of the canonical payload (for human inspection / sanity check).
    pub sha256: String,
}

/// Per-query verdict in the response.
#[derive(Debug, Deserialize)]
pub struct QueryResult {
    pub line: u32,
    pub sql_preview: String,
    pub status: String, // BLOCKED | ALLOWED | FLAGGED | MONITORED | PARSE_ERROR
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub rule_code: Option<String>,
    #[serde(default)]
    pub ast_node_path: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub suggested_fix: Option<String>,
}

/// Aggregate counts for a run.
#[derive(Debug, Deserialize)]
pub struct Summary {
    pub total: u32,
    pub blocked: u32,
    pub allowed: u32,
    pub flagged: u32,
    pub monitored: u32,
    pub parse_errors: u32,
    pub ruleset_version: String,
}

/// Response body from `POST /api/v1/ci/check-key`.
#[derive(Debug, Deserialize)]
pub struct CheckResponse {
    pub summary: Summary,
    pub queries: Vec<QueryResult>,
    /// Server-computed: 1 iff at least one query was BLOCKED.
    pub exit_code: i32,
    /// Remaining CLI checks this month for the plan; null = unmetered
    /// (team/enterprise). Absent on older backends.
    #[serde(default)]
    pub ci_checks_remaining: Option<i64>,
    /// Workspace telemetry query mode ('raw' | 'sanitized'), §6.2. Absent on
    /// older backends → treated as 'raw'.
    #[serde(default)]
    pub telemetry_query_mode: Option<String>,
    /// Oldest CLI this backend still speaks to. When our own version is older,
    /// `check` nudges the user to update. Absent on older backends → no nudge.
    #[serde(default)]
    pub min_cli_version: Option<String>,
    /// Signed run receipt (§7.1), present only when the request set `receipt` and
    /// signing is configured server-side. `null`/absent otherwise.
    #[serde(default)]
    pub receipt: Option<Receipt>,
    /// Receipts from a chunked run — one per chunk, since each HTTP response
    /// signs only its own chunk's summary/queries and they can't be merged into
    /// one signature. Not on the wire (populated by `merge_responses`); empty for
    /// a single-call run, where `receipt` carries the sole receipt instead.
    #[serde(skip)]
    pub merged_receipts: Vec<Receipt>,
    /// The backend API version from the `X-Vericto-Api-Version` response header
    /// (§9), captured so `check` can warn on a minor skew / fail on a major
    /// mismatch without a separate `/version` round-trip. Not part of the JSON
    /// body — set from the header in `try_once`. `None` on older backends.
    #[serde(skip)]
    pub api_version_header: Option<String>,
}

impl CheckResponse {
    /// All receipts for this run: the per-chunk set from a chunked run, or the
    /// single `receipt` for a one-call run. Empty when none were issued.
    pub fn all_receipts(&self) -> Vec<Receipt> {
        if !self.merged_receipts.is_empty() {
            self.merged_receipts.clone()
        } else {
            self.receipt.iter().cloned().collect()
        }
    }
}

/// Response of `GET /api/v1/version` (§9). Absent fields tolerate older
/// backends that predate this endpoint (the call itself would 404 there).
#[derive(Debug, Deserialize)]
pub struct VersionInfo {
    #[serde(default)]
    pub api_version: Option<String>,
    #[serde(default)]
    pub min_cli_version: Option<String>,
}

/// Response of `POST /api/v1/auth/oidc-exchange` (§6.1). The backend validates a
/// CI-provider OIDC ID token against the workspace's trust policies and mints a
/// short-lived, `ci_dryrun:execute`-only `vtro_...` key. The CLI holds this in
/// memory for the process only — it is never written to disk.
#[derive(Debug, Deserialize)]
pub struct OidcExchangeResult {
    /// The minted short-lived API key (a normal `vtro_...` value the existing
    /// `X-API-Key` path accepts, so nothing else in the client special-cases it).
    pub api_key: String,
    /// ISO-8601 expiry of the minted key (default ~15 min server-side).
    #[serde(default)]
    pub expires_at: Option<String>,
    /// The scope granted — always `ci_dryrun:execute`. Part of the wire contract;
    /// deserialized for completeness even though the CLI doesn't branch on it.
    #[serde(default)]
    #[allow(dead_code)]
    pub scope: Option<String>,
    /// The trust policy that authorized the exchange (for `doctor`/diagnostics).
    #[serde(default)]
    pub policy_id: Option<String>,
}

/// Response of `GET /api/v1/ci/config` — the pre-flight workspace config the CLI
/// fetches before sending SQL (§6.2). All fields tolerate an older backend that
/// lacks the endpoint (the call 404s and the caller degrades gracefully).
#[derive(Debug, Deserialize)]
pub struct WorkspaceConfig {
    /// 'raw' | 'sanitized'. When 'sanitized', the CLI normalizes literals
    /// client-side before sending so raw values never leave the machine.
    #[serde(default)]
    pub telemetry_query_mode: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub ci_checks_remaining: Option<i64>,
    #[serde(default)]
    pub ruleset_version: Option<String>,
    // Note: the backend also returns api_version/min_cli_version here, but the
    // CLI's compatibility check uses the dedicated GET /version (§9), so we
    // don't duplicate those fields on this struct.
}

/// One rule in the workspace's effective catalogue, as returned by
/// `GET /api/v1/ci/rules` (`vericto rules list`). No internal IDs — just what a
/// developer needs to understand what a `check` run is scored against.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSummary {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub severity: String,
    pub dialect: String,
    /// "standard" | "custom".
    pub rule_type: String,
    pub is_active: bool,
    /// The enforcement action ("block" | "flag" | "monitor") this severity
    /// resolves to under the workspace's current policy — not just the engine
    /// default, so what the CLI prints matches what a `check` will actually do.
    pub resolved_action: String,
}

/// Response body of `GET /api/v1/ci/rules`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RulesListResponse {
    pub rules: Vec<RuleSummary>,
    pub ruleset_version: String,
}

/// Response body of `GET /api/v1/ci/rules/:code` (`vericto rules show <CODE>`).
/// A superset of `RuleSummary`: adds the YAML condition the engine actually
/// evaluates against, for a developer who wants to understand exactly what
/// triggers the rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleDetail {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub severity: String,
    pub dialect: String,
    pub rule_type: String,
    pub is_active: bool,
    pub resolved_action: String,
    #[serde(default)]
    pub ast_condition_yaml: Option<String>,
    pub ruleset_version: String,
}

/// Errors the client surfaces, mapped to CLI exit codes by the caller.
#[derive(Debug)]
pub enum ApiError {
    /// Auth/entitlement problem (401/403) — bad key, missing scope, plan gate.
    Auth(String),
    /// Any other non-2xx from the backend.
    Backend { status: u16, message: String },
    /// Transport failure (DNS, connection, timeout) — the request never got a
    /// response. This is the only error `--allow-degraded` may bypass (§6.5).
    Transport(String),
    /// A chunked run where some chunks completed but another failed after
    /// retries. Fail-closed (§5): NOT bypassable by `--allow-degraded`, because
    /// part of the batch WAS evaluated — "some queries checked, some weren't" is
    /// materially different from "the gate was never reachable".
    PartialFailure(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Auth(m) => write!(f, "authentication/authorization failed: {m}"),
            ApiError::Backend { status, message } => {
                write!(f, "backend error ({status}): {message}")
            }
            ApiError::Transport(m) => write!(f, "could not reach the Vericto API: {m}"),
            ApiError::PartialFailure(m) => write!(f, "{m}"),
        }
    }
}

use std::time::Duration;

/// The default per-request timeout, overridable via `--timeout` / `VERICTO_TIMEOUT`.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Max retry attempts for transient failures (so 1 initial try + this many
/// retries). Applies to connection errors, timeouts, and 429/5xx responses.
const MAX_RETRIES: u32 = 3;

/// Base backoff before the first retry; doubled each subsequent attempt.
const BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Max queries per request the backend accepts (§5); larger inputs are chunked.
pub const MAX_QUERIES_PER_CALL: usize = 500;

/// Transport options shared by every request builder: the per-request timeout
/// and an optional extra CA bundle (§6.4) for corporate TLS-inspecting proxies.
#[derive(Debug, Clone, Default)]
pub struct Transport {
    pub timeout: Duration,
    /// Path to an additional PEM bundle to trust, on top of the bundled roots.
    /// Resolved by the caller from `--ca-bundle` / `VERICTO_CA_BUNDLE` /
    /// `SSL_CERT_FILE`.
    pub ca_bundle: Option<std::path::PathBuf>,
}

/// Builds the HTTP client used for every request. Honors `HTTP(S)_PROXY` /
/// `NO_PROXY` (reqwest default). One client is shared across concurrent chunks.
/// When `ca_bundle` is set, every PEM certificate in it is added to the trust
/// store on top of the bundled Mozilla roots (§6.4).
pub(crate) fn build_client(t: &Transport) -> Result<reqwest::Client, ApiError> {
    // Identify the client so the backend can attribute checks to the CLI + its
    // version (populates ci_run_reports.client_name/client_version for the
    // dashboard's per-channel latency + adoption analytics). Format: the
    // conventional "<product>/<version>".
    let mut builder = reqwest::Client::builder()
        .timeout(t.timeout)
        .user_agent(concat!("vericto-cli/", env!("CARGO_PKG_VERSION")));

    if let Some(path) = &t.ca_bundle {
        let pem = std::fs::read(path).map_err(|e| {
            ApiError::Transport(format!("cannot read CA bundle {}: {e}", path.display()))
        })?;
        // A bundle may hold multiple concatenated PEM certs; add each.
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
            ApiError::Transport(format!("invalid CA bundle {}: {e}", path.display()))
        })?;
        if certs.is_empty() {
            return Err(ApiError::Transport(format!(
                "no PEM certificates found in CA bundle {}",
                path.display()
            )));
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }

    builder
        .build()
        .map_err(|e| ApiError::Transport(e.to_string()))
}

/// Fetches `GET /api/v1/version` (§9). No auth. Used by `doctor` to check
/// backend compatibility. A `404`/older backend without this endpoint surfaces
/// as `Backend { status: 404, .. }` so the caller can treat it as "unknown".
pub async fn version(api_url: &str, transport: &Transport) -> Result<VersionInfo, ApiError> {
    let client = build_client(transport)?;
    let url = format!("{}/api/v1/version", api_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Backend {
            status: status.as_u16(),
            message: "version endpoint unavailable".to_string(),
        });
    }
    resp.json::<VersionInfo>()
        .await
        .map_err(|e| ApiError::Backend {
            status: status.as_u16(),
            message: format!("invalid version body: {e}"),
        })
}

/// Fetches `GET /api/v1/ci/config` (§6.2) with the API key — the pre-flight
/// workspace config, read BEFORE any SQL is sent. Maps 401/403 to `Auth` and
/// other non-2xx (incl. an older backend's 404) to `Backend` so the caller can
/// degrade gracefully.
pub async fn config(
    api_url: &str,
    api_key: &str,
    transport: &Transport,
) -> Result<WorkspaceConfig, ApiError> {
    let client = build_client(transport)?;
    let url = format!("{}/api/v1/ci/config", api_url.trim_end_matches('/'));
    // Retry 429/5xx (honoring Retry-After on a 429) so a transient throttle on
    // this pre-flight doesn't fall through to check's fail-open path — which
    // would send unsanitized literals when the workspace policy is 'sanitized'.
    let mut attempt = 0u32;
    loop {
        let sent = client.get(&url).header("X-API-Key", api_key).send().await;
        let resp = match sent {
            Ok(r) => r,
            Err(e) => {
                if attempt < MAX_RETRIES {
                    tokio::time::sleep(backoff_delay(attempt)).await;
                    attempt += 1;
                    continue;
                }
                return Err(ApiError::Transport(e.to_string()));
            }
        };
        let status = resp.status();
        if status.is_success() {
            return resp
                .json::<WorkspaceConfig>()
                .await
                .map_err(|e| ApiError::Backend {
                    status: status.as_u16(),
                    message: format!("invalid config body: {e}"),
                });
        }
        let code = status.as_u16();
        // Transient (429 / 5xx): back off and retry, respecting Retry-After.
        if (code == 429 || code >= 500) && attempt < MAX_RETRIES {
            let delay = if code == 429 {
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| backoff_delay(attempt))
            } else {
                backoff_delay(attempt)
            };
            tokio::time::sleep(delay).await;
            attempt += 1;
            continue;
        }
        let body = resp.text().await.unwrap_or_default();
        return if code == 401 || code == 403 {
            Err(ApiError::Auth(extract_message(&body)))
        } else {
            Err(ApiError::Backend {
                status: code,
                message: extract_message(&body),
            })
        };
    }
}

/// Fetches `GET /api/v1/ci/rules` (`vericto rules list`) — the workspace's
/// effective rule catalogue (standard + custom, override-merged). Read-only:
/// does not spend the monthly CI-check allowance. Maps 401/403 to `Auth` and
/// other non-2xx (incl. an older backend's 404) to `Backend`.
pub async fn rules_list(
    api_url: &str,
    api_key: &str,
    transport: &Transport,
) -> Result<RulesListResponse, ApiError> {
    let client = build_client(transport)?;
    let url = format!("{}/api/v1/ci/rules", api_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("X-API-Key", api_key)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        return resp
            .json::<RulesListResponse>()
            .await
            .map_err(|e| ApiError::Backend {
                status: status.as_u16(),
                message: format!("invalid rules list body: {e}"),
            });
    }
    let body = resp.text().await.unwrap_or_default();
    let code = status.as_u16();
    if code == 401 || code == 403 {
        Err(ApiError::Auth(extract_message(&body)))
    } else {
        Err(ApiError::Backend {
            status: code,
            message: extract_message(&body),
        })
    }
}

/// Fetches `GET /api/v1/ci/rules/:code` (`vericto rules show <CODE>`) — one
/// rule's full detail, including the YAML condition the engine evaluates. A
/// `404` (unknown code) surfaces as `Backend { status: 404, .. }` so the
/// caller can print a clear "rule not found" instead of a generic error.
pub async fn rules_show(
    api_url: &str,
    api_key: &str,
    code: &str,
    transport: &Transport,
) -> Result<RuleDetail, ApiError> {
    let client = build_client(transport)?;
    let url = format!(
        "{}/api/v1/ci/rules/{}",
        api_url.trim_end_matches('/'),
        urlencode_path_segment(code)
    );
    let resp = client
        .get(&url)
        .header("X-API-Key", api_key)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        return resp
            .json::<RuleDetail>()
            .await
            .map_err(|e| ApiError::Backend {
                status: status.as_u16(),
                message: format!("invalid rule detail body: {e}"),
            });
    }
    let body = resp.text().await.unwrap_or_default();
    let code_status = status.as_u16();
    if code_status == 401 || code_status == 403 {
        Err(ApiError::Auth(extract_message(&body)))
    } else {
        Err(ApiError::Backend {
            status: code_status,
            message: extract_message(&body),
        })
    }
}

/// Percent-encodes a single path segment (just enough for a rule code: letters,
/// digits, `-`/`_` pass through; anything else — notably `/` — is escaped so a
/// crafted code can't smuggle an extra path segment into the URL).
fn urlencode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Redeems the one-time code from the browser-login callback (§6, "verified
/// login") for the plaintext key the dashboard minted. Server-to-server; no
/// browser/session context involved — the code alone is the credential for
/// this single call. Maps 401 (unknown/expired/already-consumed code) to
/// `Auth`, everything else non-2xx to `Backend`.
pub async fn cli_login_exchange(
    api_url: &str,
    code: &str,
    transport: &Transport,
) -> Result<String, ApiError> {
    let client = build_client(transport)?;
    let url = format!(
        "{}/api/v1/auth/cli-login/exchange",
        api_url.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "code": code }))
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        #[derive(Deserialize)]
        struct ExchangeResponse {
            api_key: String,
        }
        return resp
            .json::<ExchangeResponse>()
            .await
            .map(|r| r.api_key)
            .map_err(|e| ApiError::Backend {
                status: status.as_u16(),
                message: format!("invalid exchange response: {e}"),
            });
    }
    let body = resp.text().await.unwrap_or_default();
    let code_status = status.as_u16();
    if code_status == 401 || code_status == 403 {
        Err(ApiError::Auth(extract_message(&body)))
    } else {
        Err(ApiError::Backend {
            status: code_status,
            message: extract_message(&body),
        })
    }
}

/// Exchanges a CI-provider OIDC ID token for a short-lived API key (§6.1) via
/// `POST /api/v1/auth/oidc-exchange`. No API key is presented — the ID token IS
/// the credential. `401/403` map to `Auth` (no trust policy matched, token not
/// verifiable), other non-2xx to `Backend`, and network failures to `Transport`.
pub async fn oidc_exchange(
    api_url: &str,
    workspace_id: &str,
    id_token: &str,
    transport: &Transport,
) -> Result<OidcExchangeResult, ApiError> {
    let client = build_client(transport)?;
    let url = format!(
        "{}/api/v1/auth/oidc-exchange",
        api_url.trim_end_matches('/')
    );
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "id_token": id_token,
            "workspace_id": workspace_id,
        }))
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        return resp
            .json::<OidcExchangeResult>()
            .await
            .map_err(|e| ApiError::Backend {
                status: status.as_u16(),
                message: format!("invalid oidc-exchange body: {e}"),
            });
    }
    let body = resp.text().await.unwrap_or_default();
    let code = status.as_u16();
    if code == 401 || code == 403 {
        Err(ApiError::Auth(extract_message(&body)))
    } else {
        Err(ApiError::Backend {
            status: code,
            message: extract_message(&body),
        })
    }
}

/// One check against a shared client + resolved URL, with the retry loop.
///
/// Transient failures — connection reset/timeout and `429`/`5xx` responses — are
/// retried up to `MAX_RETRIES` times with exponential backoff + jitter; a `429`
/// honors `Retry-After`. Auth (`401`/`403`) and other `4xx` are returned
/// immediately (they won't succeed on repeat).
async fn check_with_client(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    req: &CheckRequest,
) -> Result<CheckResponse, ApiError> {
    let mut attempt: u32 = 0;
    loop {
        match try_once(client, url, api_key, req).await {
            Ok(resp) => return Ok(resp),
            Err(outcome) => {
                let retryable = outcome.retry_after_hint.is_some() || outcome.retryable;
                if retryable && attempt < MAX_RETRIES {
                    let delay = outcome
                        .retry_after_hint
                        .unwrap_or_else(|| backoff_delay(attempt));
                    eprintln!(
                        "note: transient failure ({}); retry {}/{} in {}ms",
                        outcome.err,
                        attempt + 1,
                        MAX_RETRIES,
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Err(outcome.err);
            }
        }
    }
}

/// Connection + shared per-chunk fields for `check_all`, so the entry point
/// stays a small, named parameter set rather than a long positional list.
pub struct CheckParams<'a> {
    pub api_url: &'a str,
    pub api_key: &'a str,
    pub dialect: &'a str,
    pub file_name: Option<String>,
    pub provenance: Option<Provenance>,
    pub transport: Transport,
    /// Max in-flight chunk requests (the caller clamps this to a sane cap).
    pub concurrency: usize,
    /// Request a signed run receipt (§7.1). For a chunked run, only the first
    /// chunk requests it — the receipt covers that chunk's summary/queries; see
    /// `merge_responses` for why we don't ask every chunk.
    pub receipt: bool,
}

/// Runs a full check, chunking `queries` into ≤`MAX_QUERIES_PER_CALL` batches and
/// dispatching them with **bounded concurrency** (`p.concurrency`, capped by the
/// caller). Every chunk carries the same `dialect`/`file_name`/`provenance`.
///
/// Fail-closed (§5): the run waits for every dispatched chunk; if any chunk
/// fails after its own retries, the whole run returns that error (the caller
/// exits 4) rather than a partial summary. On success, per-query results and
/// summary counts are merged into one `CheckResponse`.
pub async fn check_all(
    p: CheckParams<'_>,
    queries: Vec<QueryInput>,
) -> Result<CheckResponse, ApiError> {
    let CheckParams {
        api_url,
        api_key,
        dialect,
        file_name,
        provenance,
        transport,
        concurrency,
        receipt,
    } = p;
    let client = build_client(&transport)?;
    let url = format!("{}/api/v1/ci/check-key", api_url.trim_end_matches('/'));

    // Single chunk: no fan-out, no cloning of the shared fields.
    if queries.len() <= MAX_QUERIES_PER_CALL {
        let req = CheckRequest {
            queries,
            dialect: dialect.to_string(),
            file_name,
            output_format: "json".to_string(),
            provenance,
            receipt,
        };
        return check_with_client(&client, &url, api_key, &req).await;
    }

    let chunks: Vec<Vec<QueryInput>> = queries
        .chunks(MAX_QUERIES_PER_CALL)
        .map(|c| c.to_vec())
        .collect();
    let total_chunks = chunks.len();
    eprintln!(
        "note: {} queries exceed the {}-per-call limit; splitting into {} chunks (concurrency {})",
        chunk_total(&chunks),
        MAX_QUERIES_PER_CALL,
        total_chunks,
        concurrency
    );

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let client = std::sync::Arc::new(client);
    let mut set = tokio::task::JoinSet::new();

    for (idx, chunk) in chunks.into_iter().enumerate() {
        let sem = semaphore.clone();
        let client = client.clone();
        let url = url.clone();
        let api_key = api_key.to_string();
        let dialect = dialect.to_string();
        let file_name = file_name.clone();
        let provenance = provenance.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore not closed");
            let req = CheckRequest {
                queries: chunk,
                dialect,
                file_name,
                output_format: "json".to_string(),
                provenance,
                // Each chunk requests its own receipt so every query in the run
                // is covered by a signature (one receipt per chunk; see
                // merge_responses / all_receipts).
                receipt,
            };
            let res = check_with_client(&client, &url, &api_key, &req).await;
            (idx, res)
        });
    }

    // Collect every chunk (barrier). Fail closed on the first hard error.
    // Chunks finish out of order, so keep the index and sort before merging so
    // per-query order (and per-chunk receipts) match the original input order.
    let mut ok: Vec<(usize, CheckResponse)> = Vec::with_capacity(total_chunks);
    let mut first_err: Option<(usize, ApiError)> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((idx, Ok(resp))) => ok.push((idx, resp)),
            Ok((idx, Err(e))) => {
                if first_err.as_ref().map(|(i, _)| idx < *i).unwrap_or(true) {
                    first_err = Some((idx, e));
                }
            }
            Err(join_err) => {
                // Task panicked/aborted — treat as a transport-level failure.
                if first_err.is_none() {
                    first_err = Some((usize::MAX, ApiError::Transport(join_err.to_string())));
                }
            }
        }
    }

    if let Some((idx, e)) = first_err {
        let which = if idx == usize::MAX {
            "a".to_string()
        } else {
            format!("chunk {}/{}", idx + 1, total_chunks)
        };
        return Err(ApiError::PartialFailure(format!(
            "{which} failed, failing the run closed: {e}"
        )));
    }

    ok.sort_by_key(|(idx, _)| *idx);
    Ok(merge_responses(ok.into_iter().map(|(_, r)| r).collect()))
}

/// Total query count across chunks (for the split log line).
fn chunk_total(chunks: &[Vec<QueryInput>]) -> usize {
    chunks.iter().map(|c| c.len()).sum()
}

/// Merges per-chunk responses into one: summary counts add up, `exit_code` is 1
/// if any chunk blocked, `ruleset_version` is taken from the first chunk, and
/// per-query results are concatenated.
fn merge_responses(mut parts: Vec<CheckResponse>) -> CheckResponse {
    if parts.len() == 1 {
        return parts.pop().unwrap();
    }
    let mut summary = Summary {
        total: 0,
        blocked: 0,
        allowed: 0,
        flagged: 0,
        monitored: 0,
        parse_errors: 0,
        ruleset_version: parts
            .first()
            .map(|p| p.summary.ruleset_version.clone())
            .unwrap_or_default(),
    };
    let mut queries = Vec::new();
    let mut exit_code = 0;
    // ci_checks_remaining: report the smallest (most conservative) seen.
    let mut remaining: Option<i64> = None;
    // Workspace-level, identical across chunks — keep the first non-empty.
    let telemetry_query_mode = parts.iter().find_map(|p| p.telemetry_query_mode.clone());
    // One receipt per chunk that returned one (§7.1) — they can't be merged into
    // one signature, so we keep them all in input order.
    let mut merged_receipts = Vec::new();
    // API version is workspace/deployment-level, identical across chunks — keep
    // the first non-empty.
    let api_version_header = parts.iter().find_map(|p| p.api_version_header.clone());
    // Deployment-level, identical across chunks — keep the first non-empty.
    let min_cli_version = parts.iter().find_map(|p| p.min_cli_version.clone());
    for p in parts {
        summary.total += p.summary.total;
        summary.blocked += p.summary.blocked;
        summary.allowed += p.summary.allowed;
        summary.flagged += p.summary.flagged;
        summary.monitored += p.summary.monitored;
        summary.parse_errors += p.summary.parse_errors;
        exit_code = exit_code.max(p.exit_code);
        if let Some(r) = p.ci_checks_remaining {
            remaining = Some(remaining.map_or(r, |cur| cur.min(r)));
        }
        if let Some(r) = p.receipt {
            merged_receipts.push(r);
        }
        queries.extend(p.queries);
    }
    CheckResponse {
        summary,
        queries,
        exit_code,
        ci_checks_remaining: remaining,
        telemetry_query_mode,
        min_cli_version,
        receipt: None,
        merged_receipts,
        api_version_header,
    }
}

/// The result of one attempt's failure, plus whether it's worth retrying.
struct Attempt {
    err: ApiError,
    retryable: bool,
    /// Explicit delay from a `429 Retry-After`, when present.
    retry_after_hint: Option<Duration>,
}

/// Performs a single request. Ok on 2xx; otherwise classifies the failure.
async fn try_once(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
    req: &CheckRequest,
) -> Result<CheckResponse, Attempt> {
    let sent = client
        .post(url)
        .header("X-API-Key", api_key)
        .json(req)
        .send()
        .await;

    let resp = match sent {
        Ok(r) => r,
        // Network/DNS/timeout — transient, retry.
        Err(e) => {
            return Err(Attempt {
                err: ApiError::Transport(e.to_string()),
                retryable: true,
                retry_after_hint: None,
            })
        }
    };

    let status = resp.status();
    if status.is_success() {
        // Read the API-version header before consuming the body (§9).
        let api_version_header = resp
            .headers()
            .get("x-vericto-api-version")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        return resp
            .json::<CheckResponse>()
            .await
            .map(|mut r| {
                r.api_version_header = api_version_header;
                r
            })
            .map_err(|e| Attempt {
                // A malformed 2xx body is not transient — don't retry.
                err: ApiError::Backend {
                    status: status.as_u16(),
                    message: format!("invalid response body: {e}"),
                },
                retryable: false,
                retry_after_hint: None,
            });
    }

    let code = status.as_u16();
    // 429: honor Retry-After (seconds form) before falling back to backoff.
    let retry_after_hint = if code == 429 {
        resp.headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
    } else {
        None
    };

    let body = resp.text().await.unwrap_or_default();
    let err = if code == 401 || code == 403 {
        ApiError::Auth(extract_message(&body))
    } else {
        ApiError::Backend {
            status: code,
            message: extract_message(&body),
        }
    };
    // Retry 429 and 5xx; everything else (other 4xx, auth) is terminal.
    let retryable = code == 429 || (500..=599).contains(&code);
    Err(Attempt {
        err,
        retryable,
        retry_after_hint,
    })
}

/// Exponential backoff with jitter for retry `attempt` (0-based):
/// `BACKOFF_BASE * 2^attempt` plus up to ~250ms of jitter. The jitter is
/// derived from the wall clock (no `rand` dependency).
fn backoff_delay(attempt: u32) -> Duration {
    let base = BACKOFF_BASE * 2u32.pow(attempt);
    let jitter_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_millis() as u64) % 250)
        .unwrap_or(0);
    base + Duration::from_millis(jitter_ms)
}

/// Pulls a human message out of a JSON error body, falling back to the raw
/// body. The backend uses a nested envelope `{"error": {"code","message"}}`;
/// older/other responses may use a flat `{"error": "..."}`. Handle both.
fn extract_message(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(err) = v.get("error") {
            // Nested: { error: { code, message } }
            if let Some(msg) = err.get("message").and_then(|m| m.as_str()) {
                return msg.to_string();
            }
            // Flat: { error: "..." }
            if let Some(msg) = err.as_str() {
                return msg.to_string();
            }
        }
        // Some handlers return { message: "..." } at the top level.
        if let Some(msg) = v.get("message").and_then(|m| m.as_str()) {
            return msg.to_string();
        }
    }
    body.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::{backoff_delay, extract_message, BACKOFF_BASE};
    use std::time::Duration;

    #[test]
    fn extracts_nested_envelope() {
        let body = r#"{"error":{"code":"UNAUTHORIZED","message":"API key inválida."}}"#;
        assert_eq!(extract_message(body), "API key inválida.");
    }

    #[test]
    fn extracts_flat_error() {
        assert_eq!(extract_message(r#"{"error":"boom"}"#), "boom");
    }

    #[test]
    fn falls_back_to_raw_body() {
        assert_eq!(extract_message("plain text error"), "plain text error");
    }

    #[test]
    fn backoff_grows_exponentially_within_jitter() {
        // attempt 0 ≈ base, attempt 2 ≈ base*4; jitter adds <250ms, so bounds hold.
        let jitter_cap = Duration::from_millis(250);
        let d0 = backoff_delay(0);
        assert!(d0 >= BACKOFF_BASE && d0 < BACKOFF_BASE + jitter_cap);
        let d2 = backoff_delay(2);
        let base2 = BACKOFF_BASE * 4;
        assert!(d2 >= base2 && d2 < base2 + jitter_cap);
    }

    // ── HTTP-client tests against an in-process mock server ──────────────────

    use super::{check_all, config, version, ApiError, CheckParams, QueryInput, Transport};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn transport() -> Transport {
        Transport {
            timeout: Duration::from_secs(5),
            ca_bundle: None,
        }
    }

    fn ok_body(total: u32, blocked: u32, remaining: i64, mode: &str) -> serde_json::Value {
        serde_json::json!({
            "summary": {
                "total": total, "blocked": blocked, "allowed": total - blocked,
                "flagged": 0, "monitored": 0, "parse_errors": 0,
                "ruleset_version": "v1"
            },
            "queries": (0..total).map(|i| serde_json::json!({
                "line": i + 1,
                "sql_preview": "x",
                "status": if i < blocked { "BLOCKED" } else { "ALLOWED" },
            })).collect::<Vec<_>>(),
            "exit_code": if blocked > 0 { 1 } else { 0 },
            "ci_checks_remaining": remaining,
            "telemetry_query_mode": mode,
        })
    }

    fn params<'a>(server_uri: &'a str, key: &'a str) -> CheckParams<'a> {
        CheckParams {
            api_url: server_uri,
            api_key: key,
            dialect: "postgres",
            file_name: None,
            provenance: None,
            transport: transport(),
            concurrency: 4,
            receipt: false,
        }
    }

    #[tokio::test]
    async fn version_parses_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "api_version": "1.2.0", "min_cli_version": "0.1.0"
            })))
            .mount(&server)
            .await;
        let info = version(&server.uri(), &transport()).await.unwrap();
        assert_eq!(info.api_version.as_deref(), Some("1.2.0"));
        assert_eq!(info.min_cli_version.as_deref(), Some("0.1.0"));
    }

    #[tokio::test]
    async fn version_404_is_backend_error() {
        let server = MockServer::start().await;
        // No mock for /version → 404.
        let err = version(&server.uri(), &transport()).await.unwrap_err();
        assert!(matches!(err, ApiError::Backend { status: 404, .. }));
    }

    #[tokio::test]
    async fn check_captures_api_version_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ci/check-key"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("X-Vericto-Api-Version", "1.4.0")
                    .set_body_json(ok_body(1, 0, 999, "raw")),
            )
            .mount(&server)
            .await;
        let uri = server.uri();
        let queries = vec![QueryInput {
            line: 1,
            sql: "SELECT 1".into(),
        }];
        let resp = check_all(params(&uri, "vtro_k"), queries).await.unwrap();
        assert_eq!(resp.api_version_header.as_deref(), Some("1.4.0"));
    }

    #[tokio::test]
    async fn config_sends_api_key_and_parses_mode() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ci/config"))
            .and(header("x-api-key", "vtro_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "telemetry_query_mode": "sanitized",
                "plan": "team",
                "ci_checks_remaining": null,
                "ruleset_version": "v1"
            })))
            .mount(&server)
            .await;
        let cfg = config(&server.uri(), "vtro_test", &transport())
            .await
            .unwrap();
        assert_eq!(cfg.telemetry_query_mode.as_deref(), Some("sanitized"));
        assert_eq!(cfg.plan.as_deref(), Some("team"));
    }

    #[tokio::test]
    async fn oidc_exchange_mints_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/oidc-exchange"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "api_key": "vtro_minted",
                "expires_at": "2026-07-10T00:15:00Z",
                "scope": "ci_dryrun:execute",
                "policy_id": "pol_123"
            })))
            .mount(&server)
            .await;
        let res = super::oidc_exchange(&server.uri(), "ws_1", "gh.jwt", &transport())
            .await
            .unwrap();
        assert_eq!(res.api_key, "vtro_minted");
        assert_eq!(res.policy_id.as_deref(), Some("pol_123"));
    }

    #[tokio::test]
    async fn oidc_exchange_403_is_auth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/oidc-exchange"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": { "message": "no trust policy" }
            })))
            .mount(&server)
            .await;
        let err = super::oidc_exchange(&server.uri(), "ws_1", "gh.jwt", &transport())
            .await
            .unwrap_err();
        match err {
            ApiError::Auth(m) => assert_eq!(m, "no trust policy"),
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn config_401_is_auth_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ci/config"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "code": "UNAUTHORIZED", "message": "bad key" }
            })))
            .mount(&server)
            .await;
        let err = config(&server.uri(), "vtro_bad", &transport())
            .await
            .unwrap_err();
        match err {
            ApiError::Auth(m) => assert_eq!(m, "bad key"),
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn check_all_single_chunk_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ci/check-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(2, 1, 998, "raw")))
            .mount(&server)
            .await;
        let uri = server.uri();
        let queries = vec![
            QueryInput {
                line: 1,
                sql: "DELETE FROM t".into(),
            },
            QueryInput {
                line: 2,
                sql: "SELECT 1".into(),
            },
        ];
        let resp = check_all(params(&uri, "vtro_k"), queries).await.unwrap();
        assert_eq!(resp.summary.total, 2);
        assert_eq!(resp.summary.blocked, 1);
        assert_eq!(resp.exit_code, 1);
    }

    #[tokio::test]
    async fn check_all_retries_then_succeeds_on_503() {
        let server = MockServer::start().await;
        // First response 503 (retryable), then 200.
        Mock::given(method("POST"))
            .and(path("/api/v1/ci/check-key"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ci/check-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(1, 0, 999, "raw")))
            .mount(&server)
            .await;
        let uri = server.uri();
        let queries = vec![QueryInput {
            line: 1,
            sql: "SELECT 1".into(),
        }];
        let resp = check_all(params(&uri, "vtro_k"), queries).await.unwrap();
        assert_eq!(resp.summary.total, 1);
    }

    #[tokio::test]
    async fn check_all_auth_error_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ci/check-key"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": { "message": "forbidden" }
            })))
            .mount(&server)
            .await;
        let uri = server.uri();
        let queries = vec![QueryInput {
            line: 1,
            sql: "SELECT 1".into(),
        }];
        let err = check_all(params(&uri, "vtro_k"), queries)
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Auth(_)));
    }

    #[tokio::test]
    async fn cli_login_exchange_returns_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/cli-login/exchange"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "api_key": "vtro_from_browser_login"
            })))
            .mount(&server)
            .await;
        let key = super::cli_login_exchange(&server.uri(), "some-code", &transport())
            .await
            .unwrap();
        assert_eq!(key, "vtro_from_browser_login");
    }

    #[tokio::test]
    async fn cli_login_exchange_401_is_auth_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/cli-login/exchange"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "message": "Código de autenticación inválido, expirado o ya utilizado." }
            })))
            .mount(&server)
            .await;
        let err = super::cli_login_exchange(&server.uri(), "bad-code", &transport())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Auth(_)));
    }

    #[tokio::test]
    async fn rules_list_parses_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ci/rules"))
            .and(header("x-api-key", "vtro_k"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "rules": [{
                    "code": "VERICTO-001",
                    "name": "DELETE without WHERE",
                    "description": "Blocks DELETE with no WHERE clause",
                    "severity": "critical",
                    "dialect": "all",
                    "rule_type": "standard",
                    "is_active": true,
                    "resolved_action": "block"
                }],
                "ruleset_version": "v1.0.0-20260711"
            })))
            .mount(&server)
            .await;
        let resp = super::rules_list(&server.uri(), "vtro_k", &transport())
            .await
            .unwrap();
        assert_eq!(resp.rules.len(), 1);
        assert_eq!(resp.rules[0].code, "VERICTO-001");
        assert_eq!(resp.ruleset_version, "v1.0.0-20260711");
    }

    #[tokio::test]
    async fn rules_list_401_is_auth_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ci/rules"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "message": "bad key" }
            })))
            .mount(&server)
            .await;
        let err = super::rules_list(&server.uri(), "vtro_bad", &transport())
            .await
            .unwrap_err();
        match err {
            ApiError::Auth(m) => assert_eq!(m, "bad key"),
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rules_show_parses_detail_with_yaml() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ci/rules/VERICTO-001"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "code": "VERICTO-001",
                "name": "DELETE without WHERE",
                "description": "Blocks DELETE with no WHERE clause",
                "severity": "critical",
                "dialect": "all",
                "rule_type": "standard",
                "is_active": true,
                "resolved_action": "block",
                "ast_condition_yaml": "node_type: DeleteStmt\nwhere_null: true",
                "ruleset_version": "v1.0.0-20260711"
            })))
            .mount(&server)
            .await;
        let detail = super::rules_show(&server.uri(), "vtro_k", "VERICTO-001", &transport())
            .await
            .unwrap();
        assert_eq!(detail.code, "VERICTO-001");
        assert!(detail.ast_condition_yaml.unwrap().contains("DeleteStmt"));
    }

    #[tokio::test]
    async fn rules_show_404_is_backend_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ci/rules/VERICTO-999"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": { "message": "Regla no encontrada: VERICTO-999" }
            })))
            .mount(&server)
            .await;
        let err = super::rules_show(&server.uri(), "vtro_k", "VERICTO-999", &transport())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Backend { status: 404, .. }));
    }

    #[test]
    fn urlencode_path_segment_escapes_slash_and_passes_dash() {
        assert_eq!(super::urlencode_path_segment("VERICTO-001"), "VERICTO-001");
        assert_eq!(super::urlencode_path_segment("a/b"), "a%2Fb");
    }

    #[tokio::test]
    async fn check_all_chunks_and_merges() {
        let server = MockServer::start().await;
        // Each call returns a 1-query response; with 600 queries we expect 2
        // chunks, merged to total 2 here (the mock returns a fixed body per call).
        Mock::given(method("POST"))
            .and(path("/api/v1/ci/check-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body(1, 1, 500, "raw")))
            .mount(&server)
            .await;
        let uri = server.uri();
        let queries: Vec<QueryInput> = (0..600)
            .map(|i| QueryInput {
                line: i + 1,
                sql: "DELETE FROM t".into(),
            })
            .collect();
        let resp = check_all(params(&uri, "vtro_k"), queries).await.unwrap();
        // 2 chunks × (total 1, blocked 1) merged.
        assert_eq!(resp.summary.total, 2);
        assert_eq!(resp.summary.blocked, 2);
        assert_eq!(resp.exit_code, 1);
    }
}
