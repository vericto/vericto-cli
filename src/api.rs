//! HTTP client for the Vetro CI dry-run endpoint.
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

/// Errors the client surfaces, mapped to CLI exit codes by the caller.
#[derive(Debug)]
pub enum ApiError {
    /// Auth/entitlement problem (401/403) — bad key, missing scope, plan gate.
    Auth(String),
    /// Any other non-2xx from the backend.
    Backend { status: u16, message: String },
    /// Transport failure (DNS, connection, timeout).
    Transport(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Auth(m) => write!(f, "authentication/authorization failed: {m}"),
            ApiError::Backend { status, message } => {
                write!(f, "backend error ({status}): {message}")
            }
            ApiError::Transport(m) => write!(f, "could not reach the Vetro API: {m}"),
        }
    }
}

use std::time::Duration;

/// The default per-request timeout, overridable via `--timeout` / `VETRO_TIMEOUT`.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Max retry attempts for transient failures (so 1 initial try + this many
/// retries). Applies to connection errors, timeouts, and 429/5xx responses.
const MAX_RETRIES: u32 = 3;

/// Base backoff before the first retry; doubled each subsequent attempt.
const BACKOFF_BASE: Duration = Duration::from_millis(500);

/// Max queries per request the backend accepts (§5); larger inputs are chunked.
pub const MAX_QUERIES_PER_CALL: usize = 500;

/// Builds the HTTP client used for every request. Honors `HTTP(S)_PROXY` /
/// `NO_PROXY` (reqwest default). One client is shared across concurrent chunks.
fn build_client(timeout: Duration) -> Result<reqwest::Client, ApiError> {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| ApiError::Transport(e.to_string()))
}

/// Fetches `GET /api/v1/version` (§9). No auth. Used by `doctor` to check
/// backend compatibility. A `404`/older backend without this endpoint surfaces
/// as `Backend { status: 404, .. }` so the caller can treat it as "unknown".
pub async fn version(api_url: &str, timeout: Duration) -> Result<VersionInfo, ApiError> {
    let client = build_client(timeout)?;
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
    timeout: Duration,
) -> Result<WorkspaceConfig, ApiError> {
    let client = build_client(timeout)?;
    let url = format!("{}/api/v1/ci/config", api_url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("X-API-Key", api_key)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;
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
    pub timeout: Duration,
    /// Max in-flight chunk requests (the caller clamps this to a sane cap).
    pub concurrency: usize,
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
        timeout,
        concurrency,
    } = p;
    let client = build_client(timeout)?;
    let url = format!("{}/api/v1/ci/check-key", api_url.trim_end_matches('/'));

    // Single chunk: no fan-out, no cloning of the shared fields.
    if queries.len() <= MAX_QUERIES_PER_CALL {
        let req = CheckRequest {
            queries,
            dialect: dialect.to_string(),
            file_name,
            output_format: "json".to_string(),
            provenance,
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
            };
            let res = check_with_client(&client, &url, &api_key, &req).await;
            (idx, res)
        });
    }

    // Collect every chunk (barrier). Fail closed on the first hard error.
    let mut ok: Vec<CheckResponse> = Vec::with_capacity(total_chunks);
    let mut first_err: Option<(usize, ApiError)> = None;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((_idx, Ok(resp))) => ok.push(resp),
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
        return Err(ApiError::Transport(format!(
            "{which} failed, failing the run closed: {e}"
        )));
    }

    Ok(merge_responses(ok))
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
        queries.extend(p.queries);
    }
    CheckResponse {
        summary,
        queries,
        exit_code,
        ci_checks_remaining: remaining,
        telemetry_query_mode,
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
        return resp.json::<CheckResponse>().await.map_err(|e| Attempt {
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
}
