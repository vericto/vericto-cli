//! Rendering of check results — human `text` (colored) and machine `json`.

use crate::api::CheckResponse;
use anstyle::{AnsiColor, Style};
use std::io::Write;

/// Output format for `vetro check`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
}

/// Renders the response to stdout in the requested format.
pub fn render(resp: &CheckResponse, format: Format, quiet: bool) {
    match format {
        Format::Json => render_json(resp),
        Format::Text => render_text(resp, quiet),
    }
}

fn render_json(resp: &CheckResponse) {
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
    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_default()
    );
}

fn render_text(resp: &CheckResponse, quiet: bool) {
    let mut out = anstream::stdout();

    if !quiet {
        for q in &resp.queries {
            // Only the non-clean statuses are worth a line each.
            if q.status == "ALLOWED" {
                continue;
            }
            let (mark, style) = status_style(&q.status);
            let rule = q.rule_code.as_deref().unwrap_or("");
            let sev = q.severity.as_deref().unwrap_or("");
            let _ = writeln!(
                out,
                "{style}{mark} {status}{style:#}  {rule} {sev}",
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
