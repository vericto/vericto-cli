//! Baseline + suppression (§10).
//!
//! Dropping the CLI into a repo with pre-existing unsafe SQL would turn the
//! build red on day one — the fastest way to get uninstalled. A baseline records
//! the *current* set of findings so `check --baseline` only fails on **new**
//! ones; baselined findings are reported as informational.
//!
//! Findings are keyed by a stable key that is NOT the line number, so edits
//! elsewhere in a file don't shift them:
//!
//! - **v2** (backends that return `statement_hash`): rule + file + AST path +
//!   the statement's text. Two `DELETE`s without `WHERE` in one file are two
//!   entries; baselining one does not hide the other.
//! - **v1** (older backends, and baselines written before v2): rule + file + AST
//!   path. Still matched as before so upgrading never turns a green build red,
//!   but it hides every later finding of a baselined rule in that file, so
//!   `check` suggests regenerating.

use crate::api::{CheckResponse, QueryResult};
use crate::output::{file_of, fingerprint};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// On-disk `.vericto-baseline.json`. `entries` is a sorted set of fingerprints;
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
    /// Where the statement was when baselined — context for a reviewer only;
    /// matching never uses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// The baseline format that keys entries per statement (see the module docs).
pub const PER_STATEMENT_VERSION: u32 = 2;

/// The v2 key: the v1 fingerprint with the statement's text folded in, when the
/// backend reported it; the plain v1 fingerprint otherwise.
pub fn statement_key(q: &QueryResult, file: &str) -> String {
    match q.statement_hash.as_deref() {
        Some(h) => fingerprint(q, &format!("{file}#{h}")),
        None => fingerprint(q, file),
    }
}

impl Baseline {
    /// Builds a baseline capturing every non-ALLOWED finding in `resp`.
    pub fn from_response(resp: &CheckResponse, files: &[String]) -> Baseline {
        // v2 only when every finding can be keyed per statement; a response
        // from an older backend keeps the v1 shape it can actually match.
        let findings = resp.queries.iter().filter(|q| q.status != "ALLOWED");
        let version = if findings.clone().all(|q| q.statement_hash.is_some()) {
            PER_STATEMENT_VERSION
        } else {
            1
        };
        let mut entries: Vec<Entry> = resp
            .queries
            .iter()
            .filter(|q| q.status != "ALLOWED")
            .map(|q| {
                let file = file_of(files, q);
                Entry {
                    fingerprint: key_for(version, q, &file),
                    line: q.file_index.map(|_| q.line),
                    file,
                    rule_code: q.rule_code.clone(),
                    status: Some(q.status.clone()),
                }
            })
            .collect();
        // Stable order + de-dup by fingerprint for a clean, diff-friendly file.
        entries.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);
        Baseline { version, entries }
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

/// The key a finding is matched by under a baseline of `version`.
pub fn key_for(version: u32, q: &QueryResult, file: &str) -> String {
    if version >= PER_STATEMENT_VERSION {
        statement_key(q, file)
    } else {
        fingerprint(q, file)
    }
}

/// Whether a finding is covered by the baseline.
pub fn is_baselined(
    q: &QueryResult,
    files: &[String],
    baseline: &Baseline,
    baselined: &BTreeSet<&str>,
) -> bool {
    if q.status == "ALLOWED" {
        return false;
    }
    let file = file_of(files, q);
    baselined.contains(key_for(baseline.version, q, &file).as_str())
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
        .map(|q| key_for(baseline.version, q, &file_of(files, q)))
        .collect();
    baseline
        .entries
        .iter()
        .filter(|e| !current.contains(&e.fingerprint))
        .collect()
}

/// Whether `sql` contains an inline suppression for `rule_code`, i.e. a comment
/// `-- vericto:ignore[VERICTO-001] reason` (reason required — a bare
/// `-- vericto:ignore[VERICTO-001]` with no reason does NOT suppress, so a
/// suppression is always accountable). Case-insensitive on the directive.
/// Returns the reason when suppressed.
pub fn inline_suppression<'a>(sql: &'a str, rule_code: &str) -> Option<&'a str> {
    sql.lines()
        .find_map(|line| directive_on_line(line, rule_code))
}

/// The directive's reason when `line` carries one for `rule_code`.
fn directive_on_line<'a>(line: &'a str, rule_code: &str) -> Option<&'a str> {
    // Find the directive anywhere on the line (typically in a `-- ...` comment).
    let lower = line.to_ascii_lowercase();
    let pos = lower.find("vericto:ignore[")?;
    let after = &line[pos + "vericto:ignore[".len()..];
    let close = after.find(']')?;
    let code = after[..close].trim();
    if !code.eq_ignore_ascii_case(rule_code) {
        return None;
    }
    let reason = after[close + 1..].trim();
    // Reason required, so a suppression is always accountable.
    (!reason.is_empty()).then_some(reason)
}

fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    // Not `*`: a SQL line can start with it (`SELECT\n  *\nFROM t`), and the
    // upward scan must not walk into the previous statement.
    t.starts_with("--") || t.starts_with('#') || t.starts_with("/*")
}

/// Statement-scoped `inline_suppression`, for per-statement results: the
/// directive must sit in the comment block directly above the statement (no
/// blank line in between) or on one of the statement's own lines — not anywhere
/// in the file. `start` is the statement's first line (1-based); `next_start`,
/// the next statement's in the same file. Comment lines right above the next
/// statement belong to it, not to this one.
pub fn inline_suppression_scoped<'a>(
    sql: &'a str,
    rule_code: &str,
    start: u32,
    next_start: Option<u32>,
) -> Option<&'a str> {
    let lines: Vec<&str> = sql.lines().collect();
    let start = start.max(1) as usize;
    if start > lines.len() {
        return None;
    }
    // The statement's own lines: up to the next statement, minus the comment
    // block (and blank lines) that lead into it.
    let mut end = next_start
        .map(|n| (n as usize).saturating_sub(1))
        .unwrap_or(lines.len())
        .min(lines.len())
        // The file can change between the check and this read.
        .max(start);
    while end > start && (lines[end - 1].trim().is_empty() || is_comment_line(lines[end - 1])) {
        end -= 1;
    }
    if let Some(reason) = lines[start - 1..end]
        .iter()
        .find_map(|l| directive_on_line(l, rule_code))
    {
        return Some(reason);
    }
    // The comment block directly above.
    lines[..start - 1]
        .iter()
        .rev()
        .take_while(|l| is_comment_line(l))
        .find_map(|l| directive_on_line(l, rule_code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Summary;

    #[test]
    fn inline_ignore_requires_matching_rule_and_reason() {
        let sql = "DELETE FROM t; -- vericto:ignore[VERICTO-001] legacy cleanup job";
        assert_eq!(
            inline_suppression(sql, "VERICTO-001"),
            Some("legacy cleanup job")
        );
        // Different rule → not suppressed.
        assert_eq!(inline_suppression(sql, "VERICTO-010"), None);
        // No reason → not suppressed (accountability).
        assert_eq!(
            inline_suppression(
                "DELETE FROM t; -- vericto:ignore[VERICTO-001]",
                "VERICTO-001"
            ),
            None
        );
    }

    fn q(status: &str, rule: &str, path: &str) -> QueryResult {
        QueryResult {
            line: 1,
            file_index: None,
            statement_hash: None,
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
            min_cli_version: None,
            receipt: None,
            merged_receipts: Vec::new(),
            api_version_header: None,
        }
    }

    #[test]
    fn baseline_captures_and_matches_findings() {
        let files = vec!["m.sql".to_string()];
        let r = resp(vec![q("BLOCKED", "VERICTO-001", "DeleteStmt")]);
        let bl = Baseline::from_response(&r, &files);
        assert_eq!(bl.entries.len(), 1);
        let set = bl.set();
        // The same finding is baselined; a different rule/path is not.
        assert!(is_baselined(
            &q("BLOCKED", "VERICTO-001", "DeleteStmt"),
            &files,
            &bl,
            &set
        ));
        assert!(!is_baselined(
            &q("BLOCKED", "VERICTO-010", "DropStmt"),
            &files,
            &bl,
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
        let bl = Baseline::from_response(
            &resp(vec![q("BLOCKED", "VERICTO-001", "DeleteStmt")]),
            &files,
        );
        // A run where that finding disappeared → the entry drifted.
        let now = resp(vec![q("ALLOWED", "", "")]);
        assert_eq!(drifted(&bl, &now, &files).len(), 1);
    }

    #[test]
    fn drift_keeps_entries_still_present() {
        let files = vec!["m.sql".to_string()];
        let bl = Baseline::from_response(
            &resp(vec![
                q("BLOCKED", "VERICTO-001", "DeleteStmt"),
                q("BLOCKED", "VERICTO-010", "DropStmt"),
            ]),
            &files,
        );
        // Only the second finding is still present in the new run.
        let now = resp(vec![q("BLOCKED", "VERICTO-010", "DropStmt")]);
        let stale = drifted(&bl, &now, &files);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].rule_code.as_deref(), Some("VERICTO-001"));
    }

    #[test]
    fn drift_empty_when_everything_still_matches() {
        let files = vec!["m.sql".to_string()];
        let r = resp(vec![q("BLOCKED", "VERICTO-001", "DeleteStmt")]);
        let bl = Baseline::from_response(&r, &files);
        // Re-running the identical check finds nothing stale.
        assert!(drifted(&bl, &r, &files).is_empty());
    }

    // ── per-statement baselines (v2) and statement-scoped inline ignores ─────

    /// A per-statement result: `line` in file 1, with the statement's hash.
    fn stmt(rule: &str, path: &str, line: u32, hash: &str) -> QueryResult {
        let mut r = q("BLOCKED", rule, path);
        r.file_index = Some(1);
        r.line = line;
        r.statement_hash = Some(hash.into());
        r
    }

    #[test]
    fn v2_baseline_does_not_hide_a_new_statement_of_the_same_rule() {
        let files = vec!["m.sql".to_string()];
        let bl = Baseline::from_response(
            &resp(vec![stmt("VERICTO-001", "DeleteStmt", 5, "aaaa")]),
            &files,
        );
        assert_eq!(bl.version, PER_STATEMENT_VERSION);
        assert_eq!(bl.entries[0].line, Some(5));
        let set = bl.set();
        // The baselined statement, even after moving down the file.
        assert!(is_baselined(
            &stmt("VERICTO-001", "DeleteStmt", 12, "aaaa"),
            &files,
            &bl,
            &set
        ));
        // A different DELETE without WHERE added later: a new finding.
        assert!(!is_baselined(
            &stmt("VERICTO-001", "DeleteStmt", 10, "bbbb"),
            &files,
            &bl,
            &set
        ));
    }

    #[test]
    fn v1_baselines_keep_matching_by_rule_and_file() {
        // Written by an older CLI or against an older backend: matched as before,
        // so upgrading never turns a green build red.
        let files = vec!["m.sql".to_string()];
        let legacy = Baseline::from_response(
            &resp(vec![q("BLOCKED", "VERICTO-001", "DeleteStmt")]),
            &files,
        );
        assert_eq!(legacy.version, 1);
        let set = legacy.set();
        assert!(is_baselined(
            &stmt("VERICTO-001", "DeleteStmt", 10, "bbbb"),
            &files,
            &legacy,
            &set
        ));
    }

    #[test]
    fn baseline_stays_v1_when_any_finding_lacks_a_statement_hash() {
        let files = vec!["m.sql".to_string()];
        let bl = Baseline::from_response(
            &resp(vec![
                stmt("VERICTO-001", "DeleteStmt", 5, "aaaa"),
                q("BLOCKED", "VERICTO-010", "DropStmt"),
            ]),
            &files,
        );
        assert_eq!(bl.version, 1);
    }

    #[test]
    fn scoped_ignore_covers_only_its_statement() {
        let sql = "\
DELETE FROM sessions;
-- vericto:ignore[VERICTO-001] approved purge, TICKET-42
DELETE FROM orders;

DELETE FROM users; -- vericto:ignore[VERICTO-001] trailing form
DELETE FROM audit;";
        // Line 1: the directive on line 2 belongs to the statement below it.
        assert_eq!(
            inline_suppression_scoped(sql, "VERICTO-001", 1, Some(3)),
            None
        );
        // Line 3: directly above → suppressed.
        assert_eq!(
            inline_suppression_scoped(sql, "VERICTO-001", 3, Some(5)),
            Some("approved purge, TICKET-42")
        );
        // Line 5: trailing comment on the statement's own line.
        assert_eq!(
            inline_suppression_scoped(sql, "VERICTO-001", 5, Some(6)),
            Some("trailing form")
        );
        // Line 6: nothing for it, although the file has two directives.
        assert_eq!(inline_suppression_scoped(sql, "VERICTO-001", 6, None), None);
        // The file-wide form (results that cover a whole file) still sees them.
        assert!(inline_suppression(sql, "VERICTO-001").is_some());
    }

    #[test]
    fn scoped_ignore_requires_no_gap_and_the_right_rule() {
        let sql = "-- vericto:ignore[VERICTO-001] reason\n\nDELETE FROM t;\n-- vericto:ignore[VERICTO-010] reason\nDELETE FROM u;";
        // A blank line separates the comment from the statement: not attached.
        assert_eq!(
            inline_suppression_scoped(sql, "VERICTO-001", 3, Some(5)),
            None
        );
        // Attached, but for another rule.
        assert_eq!(inline_suppression_scoped(sql, "VERICTO-001", 5, None), None);
    }

    #[test]
    fn scoped_ignore_does_not_reach_into_the_previous_statement() {
        // `*` on its own line is SQL, not a comment: the scan above line 4 stops
        // there, so the previous statement's trailing directive is not picked up.
        let sql = "SELECT\n  * -- vericto:ignore[VERICTO-050] reason\nFROM t;\nDELETE FROM u;";
        assert_eq!(inline_suppression_scoped(sql, "VERICTO-050", 4, None), None);
        // A file shorter than the reported line (edited since the check) is not a panic.
        assert_eq!(
            inline_suppression_scoped("DELETE FROM u;", "VERICTO-001", 1, Some(9)),
            None
        );
    }
}
