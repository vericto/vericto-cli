//! Rendering of check results.
//!
//! Human `text` (colored) + machine formats that CI systems consume:
//! `json`, `sarif` (GitHub Code Scanning), `gitlab-codequality` and
//! `gitlab-sast` (GitLab MR annotations). All are produced client-side from the
//! one JSON response the CLI always requests (§7), so a format is a client
//! concern — no backend change.
//!
//! Findings are reported at **file granularity** (§12.3): each file is sent
//! whole as one item, so an annotation points at the file (line 1) with the
//! rule's AST node path in the message.

use crate::api::{CheckResponse, QueryResult, RuleDetail, RuleSummary};
use anstyle::{AnsiColor, Style};
use std::io::{self, Write};
use std::path::Path;

/// Output format for `vericto check`. clap renders these as kebab-case:
/// `text`, `json`, `sarif`, `gitlab-codequality`, `gitlab-sast`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Colored, human-readable summary (default).
    Text,
    /// The raw check response as JSON, for scripting.
    Json,
    /// SARIF, for GitHub Code Scanning annotations.
    Sarif,
    /// GitLab Code Quality report format, for merge request annotations.
    GitlabCodequality,
    /// GitLab SAST report format, for the Security/Vulnerability tab.
    GitlabSast,
}

/// A finding worth reporting to a CI annotation surface — everything except a
/// clean ALLOWED verdict.
fn is_finding(q: &QueryResult) -> bool {
    q.status != "ALLOWED"
}

/// Maps `q.line` (the 1-based argument index the request used) back to the
/// source file path. stdin ("-") renders as "<stdin>"; an out-of-range index
/// (shouldn't happen) falls back to a synthetic name so output stays valid.
pub(crate) fn file_for(files: &[String], line: u32) -> String {
    let idx = line.saturating_sub(1) as usize;
    match files.get(idx).map(String::as_str) {
        Some("-") | None => "<stdin>".to_string(),
        Some(p) => p.to_string(),
    }
}

/// Renders `resp` in `format`. When `output` is set, machine formats and text
/// are written (plain, no ANSI) to that file; otherwise text/json go to stdout
/// (text colored unless `color` is false). `files` maps result lines to source
/// paths for annotations.
pub fn render(
    resp: &CheckResponse,
    format: Format,
    files: &[String],
    quiet: bool,
    output: Option<&Path>,
    color: bool,
) -> io::Result<()> {
    // Machine formats produce a single string; text is special-cased for color.
    let rendered = match format {
        Format::Json => Some(render_json(resp)),
        Format::Sarif => Some(render_sarif(resp, files)),
        Format::GitlabCodequality => Some(render_gitlab_codequality(resp, files)),
        Format::GitlabSast => Some(render_gitlab_sast(resp, files)),
        Format::Text => None,
    };

    if let Some(body) = rendered {
        match output {
            Some(path) => std::fs::write(path, body.as_bytes())?,
            None => {
                let mut out = io::stdout();
                out.write_all(body.as_bytes())?;
                out.write_all(b"\n")?;
            }
        }
        return Ok(());
    }

    // Text format. `--no-color` (or a file target) uses the plain renderer;
    // otherwise anstream still auto-disables color for non-TTY / NO_COLOR.
    match output {
        Some(path) => {
            let plain = render_text_plain(resp, files, quiet);
            std::fs::write(path, plain.as_bytes())?;
        }
        None if !color => {
            print!("{}", render_text_plain(resp, files, quiet));
        }
        None => render_text_colored(resp, files, quiet),
    }
    Ok(())
}

// ── json ────────────────────────────────────────────────────────────────────

fn render_json(resp: &CheckResponse) -> String {
    // Re-serialize the parsed response so output is stable/pretty regardless of
    // how the server formatted it.
    let value = serde_json::json!({
        "summary": {
            "total": resp.summary.total,
            "blocked": resp.summary.blocked,
            "allowed": resp.summary.allowed,
            "flagged": resp.summary.flagged,
            "monitored": resp.summary.monitored,
            "parse_errors": resp.summary.parse_errors,
            "ruleset_version": resp.summary.ruleset_version,
        },
        "queries": resp.queries.iter().map(|q| serde_json::json!({
            "line": q.line,
            "status": q.status,
            "action": q.action,
            "rule_code": q.rule_code,
            "severity": q.severity,
            "ast_node_path": q.ast_node_path,
            "suggested_fix": q.suggested_fix,
            "sql_preview": q.sql_preview,
        })).collect::<Vec<_>>(),
        "exit_code": resp.exit_code,
    });
    serde_json::to_string_pretty(&value).unwrap_or_default()
}

// ── SARIF 2.1.0 (GitHub Code Scanning) ───────────────────────────────────────

/// SARIF result level from the finding's severity/status.
fn sarif_level(q: &QueryResult) -> &'static str {
    match q.status.as_str() {
        "BLOCKED" => "error",
        "PARSE_ERROR" => "warning",
        _ => match q.severity.as_deref() {
            Some("critical") | Some("high") => "error",
            Some("medium") => "warning",
            _ => "note", // low / informational / monitored / unknown
        },
    }
}

/// A one-line human message for a finding.
fn finding_message(q: &QueryResult) -> String {
    // PARSE_ERROR is informational, not a rule match: the engine couldn't parse
    // the statement, so there's no rule_code/severity, and ast_node_path is just
    // the literal "PARSE_ERROR" (which made the old message read
    // "VERICTO [PARSE_ERROR] — PARSE_ERROR"). Give it a plain, self-explanatory
    // line that says what happened and that it doesn't block.
    if q.status == "PARSE_ERROR" {
        return "Could not parse this SQL — skipped, not blocked (check the syntax or --dialect)"
            .to_string();
    }

    let rule = q.rule_code.as_deref().unwrap_or("VERICTO");
    let sev = q.severity.as_deref().unwrap_or("");
    let path = q.ast_node_path.as_deref().unwrap_or("");
    let mut msg = format!("{rule} [{}]", q.status);
    if !sev.is_empty() {
        msg.push_str(&format!(" ({sev})"));
    }
    // Skip a path that just echoes the status (e.g. PARSE_ERROR handled above,
    // but guard generally against a redundant "— <STATUS>" tail).
    if !path.is_empty() && path != q.status {
        msg.push_str(&format!(" — {path}"));
    }
    if let Some(fix) = &q.suggested_fix {
        msg.push_str(&format!(" · fix: {fix}"));
    }
    msg
}

fn render_sarif(resp: &CheckResponse, files: &[String]) -> String {
    // Collect the distinct rules that fired, for the tool.driver.rules table.
    let mut rule_ids: Vec<String> = Vec::new();
    for q in resp.queries.iter().filter(|q| is_finding(q)) {
        if let Some(code) = &q.rule_code {
            if !rule_ids.contains(code) {
                rule_ids.push(code.clone());
            }
        }
    }

    let results: Vec<serde_json::Value> = resp
        .queries
        .iter()
        .filter(|q| is_finding(q))
        .map(|q| {
            serde_json::json!({
                "ruleId": q.rule_code.clone().unwrap_or_else(|| "VERICTO".to_string()),
                "level": sarif_level(q),
                "message": { "text": finding_message(q) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": file_for(files, q.line) },
                        "region": { "startLine": 1 }
                    }
                }]
            })
        })
        .collect();

    let rules: Vec<serde_json::Value> = rule_ids
        .iter()
        .map(|id| serde_json::json!({ "id": id, "name": id }))
        .collect();

    let sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "vericto",
                "informationUri": "https://vericto.com",
                "version": env!("CARGO_PKG_VERSION"),
                "rules": rules,
            }},
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

// ── GitLab Code Quality report ───────────────────────────────────────────────

/// CodeClimate/GitLab severity: info | minor | major | critical | blocker.
fn gitlab_cq_severity(q: &QueryResult) -> &'static str {
    match q.status.as_str() {
        "BLOCKED" => "blocker",
        "PARSE_ERROR" => "info",
        _ => match q.severity.as_deref() {
            Some("critical") => "critical",
            Some("high") => "major",
            Some("medium") => "minor",
            _ => "info",
        },
    }
}

/// A stable per-finding fingerprint (rule + file + ast path — NOT line number,
/// so edits elsewhere in the file don't shift it). FNV-1a hex, dependency-free.
/// Shared with the baseline module so a report's fingerprints match what
/// `vericto baseline` recorded.
pub(crate) fn fingerprint(q: &QueryResult, file: &str) -> String {
    let rule = q.rule_code.as_deref().unwrap_or("");
    let path = q.ast_node_path.as_deref().unwrap_or("");
    let seed = format!("{rule}|{file}|{path}");
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn render_gitlab_codequality(resp: &CheckResponse, files: &[String]) -> String {
    let issues: Vec<serde_json::Value> = resp
        .queries
        .iter()
        .filter(|q| is_finding(q))
        .map(|q| {
            let file = file_for(files, q.line);
            let rule = q.rule_code.clone().unwrap_or_else(|| "VERICTO".to_string());
            serde_json::json!({
                "description": finding_message(q),
                "check_name": rule,
                "fingerprint": fingerprint(q, &file),
                "severity": gitlab_cq_severity(q),
                "location": { "path": file, "lines": { "begin": 1 } },
            })
        })
        .collect();
    serde_json::to_string_pretty(&issues).unwrap_or_default()
}

// ── GitLab SAST report ───────────────────────────────────────────────────────

/// GitLab SAST severity: capitalized (Critical/High/Medium/Low/Info/Unknown).
fn gitlab_sast_severity(q: &QueryResult) -> &'static str {
    match q.status.as_str() {
        "BLOCKED" => "Critical",
        "PARSE_ERROR" => "Info",
        _ => match q.severity.as_deref() {
            Some("critical") => "Critical",
            Some("high") => "High",
            Some("medium") => "Medium",
            Some("low") => "Low",
            Some("informational") => "Info",
            _ => "Unknown",
        },
    }
}

fn render_gitlab_sast(resp: &CheckResponse, files: &[String]) -> String {
    let vulns: Vec<serde_json::Value> = resp
        .queries
        .iter()
        .filter(|q| is_finding(q))
        .map(|q| {
            let file = file_for(files, q.line);
            let rule = q.rule_code.clone().unwrap_or_else(|| "VERICTO".to_string());
            serde_json::json!({
                "id": fingerprint(q, &file),
                "category": "sast",
                "name": rule,
                "message": finding_message(q),
                "severity": gitlab_sast_severity(q),
                "location": { "file": file, "start_line": 1 },
                "identifiers": [{
                    "type": "vericto_rule",
                    "name": rule,
                    "value": rule,
                }],
            })
        })
        .collect();

    let report = serde_json::json!({
        "version": "15.0.6",
        "scan": {
            "scanner": {
                "id": "vericto",
                "name": "Vericto",
                "version": env!("CARGO_PKG_VERSION"),
                "vendor": { "name": "Vericto" },
            },
            "type": "sast",
            "status": "success",
        },
        "vulnerabilities": vulns,
    });
    serde_json::to_string_pretty(&report).unwrap_or_default()
}

// ── text ─────────────────────────────────────────────────────────────────────

fn render_text_colored(resp: &CheckResponse, files: &[String], quiet: bool) {
    let mut out = anstream::stdout();

    if !quiet {
        for q in resp.queries.iter().filter(|q| is_finding(q)) {
            let (mark, style) = status_style(&q.status);
            let file = file_for(files, q.line);
            let rule = q.rule_code.as_deref().unwrap_or("");
            let sev = q.severity.as_deref().unwrap_or("");
            let _ = writeln!(
                out,
                "{style}{mark} {file}  {status}{style:#}  {rule} {sev}",
                status = q.status,
            );
            if let Some(path) = &q.ast_node_path {
                let _ = writeln!(out, "    {path}");
            }
            if let Some(fix) = &q.suggested_fix {
                let _ = writeln!(out, "    fix: {fix}");
            }
        }
    }

    let s = &resp.summary;
    let dim = Style::new().dimmed();
    let _ = writeln!(
        out,
        "{dim}{blocked} blocked · {allowed} allowed · {flagged} flagged · {monitored} monitored   (ruleset {ver}){dim:#}",
        blocked = s.blocked,
        allowed = s.allowed,
        flagged = s.flagged,
        monitored = s.monitored,
        ver = s.ruleset_version,
    );
}

/// The same text report without ANSI, for `--output`.
fn render_text_plain(resp: &CheckResponse, files: &[String], quiet: bool) -> String {
    let mut buf = String::new();
    if !quiet {
        for q in resp.queries.iter().filter(|q| is_finding(q)) {
            let file = file_for(files, q.line);
            let rule = q.rule_code.as_deref().unwrap_or("");
            let sev = q.severity.as_deref().unwrap_or("");
            buf.push_str(&format!("{} {file}  {rule} {sev}\n", q.status));
            if let Some(path) = &q.ast_node_path {
                buf.push_str(&format!("    {path}\n"));
            }
            if let Some(fix) = &q.suggested_fix {
                buf.push_str(&format!("    fix: {fix}\n"));
            }
        }
    }
    let s = &resp.summary;
    buf.push_str(&format!(
        "{} blocked · {} allowed · {} flagged · {} monitored   (ruleset {})\n",
        s.blocked, s.allowed, s.flagged, s.monitored, s.ruleset_version,
    ));
    buf
}

/// Maps a status to a marker + color for the text renderer.
fn status_style(status: &str) -> (&'static str, Style) {
    match status {
        "BLOCKED" => (
            "✖",
            Style::new().fg_color(Some(AnsiColor::Red.into())).bold(),
        ),
        "FLAGGED" => ("!", Style::new().fg_color(Some(AnsiColor::Yellow.into()))),
        "MONITORED" => ("•", Style::new().fg_color(Some(AnsiColor::Blue.into()))),
        "PARSE_ERROR" => ("?", Style::new().fg_color(Some(AnsiColor::Yellow.into()))),
        _ => ("✓", Style::new().fg_color(Some(AnsiColor::Green.into()))),
    }
}

// ── rules list / show (text) ─────────────────────────────────────────────────

/// A short marker + color for a severity, mirroring `status_style`'s scheme so
/// `rules list`/`show` visually match `check`'s output.
fn severity_style(severity: &str) -> Style {
    match severity {
        "critical" => Style::new().fg_color(Some(AnsiColor::Red.into())).bold(),
        "high" => Style::new().fg_color(Some(AnsiColor::Red.into())),
        "medium" => Style::new().fg_color(Some(AnsiColor::Yellow.into())),
        "low" => Style::new().fg_color(Some(AnsiColor::Blue.into())),
        _ => Style::new().dimmed(), // informational / unknown
    }
}

/// `vericto rules list` (text format): one line per rule, widest-first columns
/// so the table stays readable whether or not a terminal supports color.
pub fn render_rules_list(rules: &[&RuleSummary], ruleset_version: &str) {
    let mut out = anstream::stdout();
    if rules.is_empty() {
        let _ = writeln!(out, "No rules found.");
        return;
    }
    let code_w = rules.iter().map(|r| r.code.len()).max().unwrap_or(4).max(4);
    let sev_w = rules
        .iter()
        .map(|r| r.severity.len())
        .max()
        .unwrap_or(8)
        .max(8);
    for r in rules {
        let style = severity_style(&r.severity);
        let active = if r.is_active { "active" } else { "inactive" };
        let _ = writeln!(
            out,
            "{:<code_w$}  {style}{:<sev_w$}{style:#}  {:<7}  {:<8}  {}",
            r.code, r.severity, r.resolved_action, active, r.name,
        );
    }
    let dim = Style::new().dimmed();
    let _ = writeln!(
        out,
        "{dim}{} rules   (ruleset {ruleset_version}){dim:#}",
        rules.len()
    );
}

/// `vericto rules show <CODE>` (text format): a detail block including the
/// AST condition the engine actually evaluates against.
pub fn render_rule_detail(r: &RuleDetail) {
    let mut out = anstream::stdout();
    let style = severity_style(&r.severity);
    let _ = writeln!(out, "{} — {}", r.code, r.name);
    let _ = writeln!(
        out,
        "  severity: {style}{}{style:#}    action: {}    type: {}    dialect: {}    {}",
        r.severity,
        r.resolved_action,
        r.rule_type,
        r.dialect,
        if r.is_active { "active" } else { "inactive" },
    );
    if let Some(desc) = &r.description {
        if !desc.is_empty() {
            let _ = writeln!(out, "\n  {desc}");
        }
    }
    if let Some(yaml) = &r.ast_condition_yaml {
        let _ = writeln!(out, "\n  condition:");
        for line in yaml.lines() {
            let _ = writeln!(out, "    {line}");
        }
    }
    let dim = Style::new().dimmed();
    let _ = writeln!(out, "\n{dim}ruleset {}{dim:#}", r.ruleset_version);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Summary;

    fn q(status: &str, rule: Option<&str>, sev: Option<&str>) -> QueryResult {
        QueryResult {
            line: 1,
            sql_preview: "DELETE FROM t".into(),
            status: status.into(),
            action: None,
            rule_code: rule.map(String::from),
            ast_node_path: Some("DeleteStmt > WhereClause = NULL".into()),
            severity: sev.map(String::from),
            suggested_fix: Some("add WHERE".into()),
        }
    }

    fn resp(queries: Vec<QueryResult>) -> CheckResponse {
        CheckResponse {
            summary: Summary {
                total: queries.len() as u32,
                blocked: 1,
                allowed: 0,
                flagged: 0,
                monitored: 0,
                parse_errors: 0,
                ruleset_version: "v1".into(),
            },
            queries,
            exit_code: 1,
            ci_checks_remaining: None,
            telemetry_query_mode: None,
            receipt: None,
            merged_receipts: Vec::new(),
            api_version_header: None,
        }
    }

    #[test]
    fn file_for_maps_line_to_path_and_stdin() {
        let files = vec!["a.sql".to_string(), "-".to_string()];
        assert_eq!(file_for(&files, 1), "a.sql");
        assert_eq!(file_for(&files, 2), "<stdin>"); // "-" → stdin
        assert_eq!(file_for(&files, 9), "<stdin>"); // out of range
    }

    #[test]
    fn is_finding_excludes_allowed() {
        assert!(!is_finding(&q("ALLOWED", None, None)));
        assert!(is_finding(&q(
            "BLOCKED",
            Some("VERICTO-001"),
            Some("critical")
        )));
    }

    #[test]
    fn sarif_level_from_status_and_severity() {
        assert_eq!(sarif_level(&q("BLOCKED", None, None)), "error");
        assert_eq!(sarif_level(&q("PARSE_ERROR", None, None)), "warning");
        assert_eq!(sarif_level(&q("FLAGGED", None, Some("high"))), "error");
        assert_eq!(sarif_level(&q("FLAGGED", None, Some("medium"))), "warning");
        assert_eq!(sarif_level(&q("MONITORED", None, Some("low"))), "note");
    }

    #[test]
    fn gitlab_severities_map() {
        assert_eq!(gitlab_cq_severity(&q("BLOCKED", None, None)), "blocker");
        assert_eq!(
            gitlab_cq_severity(&q("FLAGGED", None, Some("critical"))),
            "critical"
        );
        assert_eq!(
            gitlab_cq_severity(&q("FLAGGED", None, Some("medium"))),
            "minor"
        );
        assert_eq!(gitlab_sast_severity(&q("BLOCKED", None, None)), "Critical");
        assert_eq!(
            gitlab_sast_severity(&q("FLAGGED", None, Some("low"))),
            "Low"
        );
        assert_eq!(gitlab_sast_severity(&q("FLAGGED", None, None)), "Unknown");
    }

    #[test]
    fn fingerprint_is_stable_and_rule_sensitive() {
        let a = fingerprint(&q("BLOCKED", Some("VERICTO-001"), None), "m.sql");
        let b = fingerprint(&q("BLOCKED", Some("VERICTO-001"), None), "m.sql");
        let c = fingerprint(&q("BLOCKED", Some("VERICTO-010"), None), "m.sql");
        assert_eq!(a, b); // deterministic
        assert_ne!(a, c); // different rule → different fp
    }

    #[test]
    fn finding_message_includes_rule_severity_path() {
        let m = finding_message(&q("BLOCKED", Some("VERICTO-001"), Some("critical")));
        assert!(m.contains("VERICTO-001"));
        assert!(m.contains("BLOCKED"));
        assert!(m.contains("critical"));
        assert!(m.contains("fix:"));
    }

    #[test]
    fn finding_message_parse_error_is_plain_and_not_redundant() {
        // Backend sends status=PARSE_ERROR, no rule_code/severity, and
        // ast_node_path echoing the literal "PARSE_ERROR". The message must not
        // read "VERICTO [PARSE_ERROR] — PARSE_ERROR".
        let pe = QueryResult {
            line: 1,
            sql_preview: "COPY t FROM stdin".into(),
            status: "PARSE_ERROR".into(),
            action: None,
            rule_code: None,
            ast_node_path: Some("PARSE_ERROR".into()),
            severity: None,
            suggested_fix: None,
        };
        let m = finding_message(&pe);
        assert!(!m.contains("VERICTO"), "should not show a bogus rule code: {m}");
        assert!(!m.contains("— PARSE_ERROR"), "should not echo the status as a path: {m}");
        assert!(m.to_lowercase().contains("parse"), "should say it couldn't parse: {m}");
        assert!(
            m.to_lowercase().contains("not blocked") || m.to_lowercase().contains("skipped"),
            "should reassure it doesn't block: {m}"
        );
    }

    #[test]
    fn render_json_roundtrips() {
        let out = render_json(&resp(vec![q(
            "BLOCKED",
            Some("VERICTO-001"),
            Some("critical"),
        )]));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["summary"]["blocked"], 1);
        assert_eq!(v["queries"][0]["status"], "BLOCKED");
        assert_eq!(v["exit_code"], 1);
    }

    #[test]
    fn render_sarif_has_results_and_rules() {
        let files = vec!["m.sql".to_string()];
        let out = render_sarif(
            &resp(vec![q("BLOCKED", Some("VERICTO-001"), Some("critical"))]),
            &files,
        );
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "VERICTO-001");
        assert_eq!(v["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            v["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "m.sql"
        );
    }

    #[test]
    fn render_gitlab_codequality_shape() {
        let files = vec!["m.sql".to_string()];
        let out =
            render_gitlab_codequality(&resp(vec![q("BLOCKED", Some("VERICTO-001"), None)]), &files);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v[0]["check_name"], "VERICTO-001");
        assert_eq!(v[0]["severity"], "blocker");
        assert_eq!(v[0]["location"]["path"], "m.sql");
        assert!(v[0]["fingerprint"].as_str().unwrap().len() == 16);
    }

    #[test]
    fn render_gitlab_sast_shape() {
        let files = vec!["m.sql".to_string()];
        let out = render_gitlab_sast(&resp(vec![q("BLOCKED", Some("VERICTO-001"), None)]), &files);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["scan"]["scanner"]["id"], "vericto");
        assert_eq!(v["vulnerabilities"][0]["severity"], "Critical");
        assert_eq!(v["vulnerabilities"][0]["location"]["file"], "m.sql");
    }

    #[test]
    fn render_text_plain_lists_findings_and_summary() {
        let files = vec!["m.sql".to_string()];
        let out = render_text_plain(
            &resp(vec![q("BLOCKED", Some("VERICTO-001"), Some("critical"))]),
            &files,
            false,
        );
        assert!(out.contains("m.sql"));
        assert!(out.contains("VERICTO-001"));
        assert!(out.contains("blocked"));
        // quiet mode: only the summary line, no per-finding lines.
        let quiet = render_text_plain(
            &resp(vec![q("BLOCKED", Some("VERICTO-001"), None)]),
            &files,
            true,
        );
        assert!(!quiet.contains("VERICTO-001"));
        assert!(quiet.contains("blocked"));
    }

    #[test]
    fn render_to_file_writes_json() {
        let files = vec!["m.sql".to_string()];
        let dir = std::env::temp_dir().join(format!("vericto-out-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.json");
        render(
            &resp(vec![q("BLOCKED", Some("VERICTO-001"), None)]),
            Format::Json,
            &files,
            false,
            Some(&path),
            true,
        )
        .unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("\"blocked\": 1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_style_marks() {
        assert_eq!(status_style("BLOCKED").0, "✖");
        assert_eq!(status_style("FLAGGED").0, "!");
        assert_eq!(status_style("MONITORED").0, "•");
        assert_eq!(status_style("PARSE_ERROR").0, "?");
        assert_eq!(status_style("ALLOWED").0, "✓");
    }

    fn rule(code: &str, severity: &str, active: bool) -> RuleSummary {
        RuleSummary {
            code: code.to_string(),
            name: format!("{code} name"),
            description: Some("desc".into()),
            severity: severity.to_string(),
            dialect: "all".into(),
            rule_type: "standard".into(),
            is_active: active,
            resolved_action: "block".into(),
        }
    }

    #[test]
    fn render_rules_list_handles_empty() {
        // Just verifying it doesn't panic on an empty slice; output goes to
        // stdout so we can't easily capture it here, but a panic would fail
        // the test either way.
        render_rules_list(&[], "v1.0.0");
    }

    #[test]
    fn render_rules_list_handles_rules() {
        let r1 = rule("VERICTO-001", "critical", true);
        let r2 = rule("VERICTO-002", "medium", false);
        render_rules_list(&[&r1, &r2], "v1.0.0-20260711");
    }

    #[test]
    fn render_rule_detail_handles_full_and_minimal() {
        let full = RuleDetail {
            code: "VERICTO-001".into(),
            name: "DELETE without WHERE".into(),
            description: Some("Blocks DELETE with no WHERE clause".into()),
            severity: "critical".into(),
            dialect: "all".into(),
            rule_type: "standard".into(),
            is_active: true,
            resolved_action: "block".into(),
            ast_condition_yaml: Some("node_type: DeleteStmt\nwhere_null: true".into()),
            ruleset_version: "v1.0.0".into(),
        };
        render_rule_detail(&full);

        let minimal = RuleDetail {
            code: "CUSTOM-001".into(),
            name: "Custom rule".into(),
            description: None,
            severity: "high".into(),
            dialect: "postgres".into(),
            rule_type: "custom".into(),
            is_active: false,
            resolved_action: "flag".into(),
            ast_condition_yaml: None,
            ruleset_version: "v1.0.0".into(),
        };
        render_rule_detail(&minimal);
    }

    #[test]
    fn severity_style_covers_all_levels() {
        // No assertions on the exact color codes — just that every known
        // severity (and an unknown one) resolves without panicking.
        for sev in [
            "critical",
            "high",
            "medium",
            "low",
            "informational",
            "bogus",
        ] {
            let _ = severity_style(sev);
        }
    }
}
