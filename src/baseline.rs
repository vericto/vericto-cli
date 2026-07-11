//! Baseline + suppression (§10).
//!
//! Dropping the CLI into a repo with pre-existing unsafe SQL would turn the
//! build red on day one — the fastest way to get uninstalled. A baseline records
//! the *current* set of findings so `check --baseline` only fails on **new**
//! ones; baselined findings are reported as informational.
//!
//! Findings are keyed by a stable fingerprint (rule + file + AST path — NOT line
//! number, from `output::fingerprint`) so edits elsewhere in a file don't shift
//! them.

use crate::api::{CheckResponse, QueryResult};
use crate::output::{file_for, fingerprint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// On-disk `.vetro-baseline.json`. `entries` is a sorted set of fingerprints;
/// the human fields are stored alongside for reviewability in the committed file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema marker for forward compatibility.
    pub version: u32,
    pub entries: Vec<Entry>,
}

/// One baselined finding. `fingerprint` is what matching keys on; the rest is
/// context for a human reading the file in a PR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub fingerprint: String,
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl Baseline {
    /// Builds a baseline capturing every non-ALLOWED finding in `resp`.
    pub fn from_response(resp: &CheckResponse, files: &[String]) -> Baseline {
        let mut entries: Vec<Entry> = resp
            .queries
            .iter()
            .filter(|q| q.status != "ALLOWED")
            .map(|q| {
                let file = file_for(files, q.line);
                Entry {
                    fingerprint: fingerprint(q, &file),
                    file,
                    rule_code: q.rule_code.clone(),
                    status: Some(q.status.clone()),
                }
            })
            .collect();
        // Stable order + de-dup by fingerprint for a clean, diff-friendly file.
        entries.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);
        Baseline {
            version: 1,
            entries,
        }
    }

    /// Loads a baseline file. A missing file is an error (the caller passed
    /// `--baseline`, so it expected one).
    pub fn load(path: &Path) -> std::io::Result<Baseline> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid baseline at {}: {e}", path.display()),
            )
        })
    }

    /// Writes the baseline as pretty JSON.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        std::fs::write(path, text)
    }

    /// The set of baselined fingerprints, for fast membership tests.
    pub fn set(&self) -> BTreeSet<&str> {
        self.entries
            .iter()
            .map(|e| e.fingerprint.as_str())
            .collect()
    }
}

/// Whether a finding is covered by the baseline (matched by fingerprint).
pub fn is_baselined(q: &QueryResult, files: &[String], baselined: &BTreeSet<&str>) -> bool {
    if q.status == "ALLOWED" {
        return false;
    }
    let file = file_for(files, q.line);
    baselined.contains(fingerprint(q, &file).as_str())
}

/// Baseline entries whose fingerprint no longer appears in `resp` — stale rows a
/// user can prune. Returns the drifted entries' fingerprints.
pub fn drifted<'a>(
    baseline: &'a Baseline,
    resp: &CheckResponse,
    files: &[String],
) -> Vec<&'a Entry> {
    let current: BTreeSet<String> = resp
        .queries
        .iter()
        .filter(|q| q.status != "ALLOWED")
        .map(|q| fingerprint(q, &file_for(files, q.line)))
        .collect();
    baseline
        .entries
        .iter()
        .filter(|e| !current.contains(&e.fingerprint))
        .collect()
}

/// Whether `sql` contains an inline suppression for `rule_code`, i.e. a comment
/// `-- vetro:ignore[VETRO-001] reason` (reason required — a bare
/// `-- vetro:ignore[VETRO-001]` with no reason does NOT suppress, so a
/// suppression is always accountable). Case-insensitive on the directive.
/// Returns the reason when suppressed.
pub fn inline_suppression<'a>(sql: &'a str, rule_code: &str) -> Option<&'a str> {
    for line in sql.lines() {
        // Find the directive anywhere on the line (typically in a `-- ...` comment).
        let lower = line.to_ascii_lowercase();
        let Some(pos) = lower.find("vetro:ignore[") else {
            continue;
        };
        let after = &line[pos + "vetro:ignore[".len()..];
        let Some(close) = after.find(']') else {
            continue;
        };
        let code = after[..close].trim();
        if !code.eq_ignore_ascii_case(rule_code) {
            continue;
        }
        let reason = after[close + 1..].trim();
        if reason.is_empty() {
            continue; // reason required
        }
        return Some(reason);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Summary;

    #[test]
    fn inline_ignore_requires_matching_rule_and_reason() {
        let sql = "DELETE FROM t; -- vetro:ignore[VETRO-001] legacy cleanup job";
        assert_eq!(
            inline_suppression(sql, "VETRO-001"),
            Some("legacy cleanup job")
        );
        // Different rule → not suppressed.
        assert_eq!(inline_suppression(sql, "VETRO-010"), None);
        // No reason → not suppressed (accountability).
        assert_eq!(
            inline_suppression("DELETE FROM t; -- vetro:ignore[VETRO-001]", "VETRO-001"),
            None
        );
    }

    fn q(status: &str, rule: &str, path: &str) -> QueryResult {
        QueryResult {
            line: 1,
            sql_preview: String::new(),
            status: status.into(),
            action: None,
            rule_code: Some(rule.into()),
            ast_node_path: Some(path.into()),
            severity: None,
            suggested_fix: None,
        }
    }

    fn resp(queries: Vec<QueryResult>) -> CheckResponse {
        CheckResponse {
            summary: Summary {
                total: queries.len() as u32,
                blocked: 0,
                allowed: 0,
                flagged: 0,
                monitored: 0,
                parse_errors: 0,
                ruleset_version: "t".into(),
            },
            queries,
            exit_code: 0,
            ci_checks_remaining: None,
            telemetry_query_mode: None,
            receipt: None,
            merged_receipts: Vec::new(),
            api_version_header: None,
        }
    }

    #[test]
    fn baseline_captures_and_matches_findings() {
        let files = vec!["m.sql".to_string()];
        let r = resp(vec![q("BLOCKED", "VETRO-001", "DeleteStmt")]);
        let bl = Baseline::from_response(&r, &files);
        assert_eq!(bl.entries.len(), 1);
        let set = bl.set();
        // The same finding is baselined; a different rule/path is not.
        assert!(is_baselined(
            &q("BLOCKED", "VETRO-001", "DeleteStmt"),
            &files,
            &set
        ));
        assert!(!is_baselined(
            &q("BLOCKED", "VETRO-010", "DropStmt"),
            &files,
            &set
        ));
    }

    #[test]
    fn allowed_is_never_baselined() {
        let files = vec!["m.sql".to_string()];
        let bl = Baseline::from_response(&resp(vec![q("ALLOWED", "", "")]), &files);
        assert!(bl.entries.is_empty());
    }

    #[test]
    fn drift_reports_missing_entries() {
        let files = vec!["m.sql".to_string()];
        let bl =
            Baseline::from_response(&resp(vec![q("BLOCKED", "VETRO-001", "DeleteStmt")]), &files);
        // A run where that finding disappeared → the entry drifted.
        let now = resp(vec![q("ALLOWED", "", "")]);
        assert_eq!(drifted(&bl, &now, &files).len(), 1);
    }
}
