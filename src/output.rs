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

use crate::api::{CheckResponse, QueryResult};
use anstyle::{AnsiColor, Style};
use std::io::{self, Write};
use std::path::Path;

/// Output format for `vetro check`. clap renders these as kebab-case:
/// `text`, `json`, `sarif`, `gitlab-codequality`, `gitlab-sast`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
    GitlabCodequality,
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
/// (text colored). `files` maps result lines to source paths for annotations.
pub fn render(
    resp: &CheckResponse,
    format: Format,
    files: &[String],
    quiet: bool,
    output: Option<&Path>,
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

    // Text format.
    match output {
        Some(path) => {
            let plain = render_text_plain(resp, files, quiet);
            std::fs::write(path, plain.as_bytes())?;
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
    let rule = q.rule_code.as_deref().unwrap_or("VETRO");
    let sev = q.severity.as_deref().unwrap_or("");
    let path = q.ast_node_path.as_deref().unwrap_or("");
    let mut msg = format!("{rule} [{}]", q.status);
    if !sev.is_empty() {
        msg.push_str(&format!(" ({sev})"));
    }
    if !path.is_empty() {
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
                "ruleId": q.rule_code.clone().unwrap_or_else(|| "VETRO".to_string()),
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
                "name": "vetro",
                "informationUri": "https://vetro.dev",
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
/// `vetro baseline` recorded.
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
            let rule = q.rule_code.clone().unwrap_or_else(|| "VETRO".to_string());
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
            let rule = q.rule_code.clone().unwrap_or_else(|| "VETRO".to_string());
            serde_json::json!({
                "id": fingerprint(q, &file),
                "category": "sast",
                "name": rule,
                "message": finding_message(q),
                "severity": gitlab_sast_severity(q),
                "location": { "file": file, "start_line": 1 },
                "identifiers": [{
                    "type": "vetro_rule",
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
                "id": "vetro",
                "name": "Vetro",
                "version": env!("CARGO_PKG_VERSION"),
                "vendor": { "name": "Vetro" },
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
