//! HTTP client for the Vetro CI dry-run endpoint.
//!
//! The CLI is a thin client: it does not evaluate SQL locally. It sends the SQL
//! to `POST /api/v1/ci/check-key` (API-key auth, `ci_dryrun:execute` scope) and
//! renders the verdict. The request/response shapes here mirror the backend
//! contract (`routes/ci.ts`).

use serde::{Deserialize, Serialize};

/// One SQL unit to evaluate. We send the whole file as a single item (line 1):
/// the engine parses multi-statement SQL server-side, so we don't split here.
#[derive(Debug, Serialize)]
pub struct QueryInput {
    pub line: u32,
    pub sql: String,
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

/// Calls `POST {api_url}/api/v1/ci/check-key` with the given API key.
pub async fn check(
    api_url: &str,
    api_key: &str,
    req: &CheckRequest,
) -> Result<CheckResponse, ApiError> {
    let url = format!("{}/api/v1/ci/check-key", api_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ApiError::Transport(e.to_string()))?;

    let resp = client
        .post(&url)
        .header("X-API-Key", api_key)
        .json(req)
        .send()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;

    let status = resp.status();
    if status.is_success() {
        return resp
            .json::<CheckResponse>()
            .await
            .map_err(|e| ApiError::Backend {
                status: status.as_u16(),
                message: format!("invalid response body: {e}"),
            });
    }

    let body = resp.text().await.unwrap_or_default();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        Err(ApiError::Auth(extract_message(&body)))
    } else {
        Err(ApiError::Backend {
            status: status.as_u16(),
            message: extract_message(&body),
        })
    }
}

/// Pulls a human message out of a JSON error body (`{"error": "..."}`),
/// falling back to the raw body.
fn extract_message(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or_else(|| body.trim().to_string())
}
