// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The local decision log: one JSON object per line, appended by every hook
//! run that found something (and by every deny), so a user can see what the
//! agent tried. Nothing leaves the machine.
//!
//! Location: `VERICTO_GUARD_LOG`, else `[guard] log_path`, else
//! `<state dir>/vericto/guard.jsonl` (`~/.local/state` on Linux,
//! `~/Library/Application Support` on macOS, `%LOCALAPPDATA%` on Windows).
//! Past 10 MiB the file is rotated to `guard.jsonl.1` (one generation).
//!
//! Secrets: commands are redacted (`target::redact`) and string literals in
//! them are replaced with `'?'` before they are written, then truncated to
//! 500 characters; `log_sql = "hash"` keeps only a SHA-256, `"none"` neither.
//! Targets keep the host and database name only, never credentials.

use std::io::Write;
use std::path::PathBuf;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::config::{GuardConfig, LogSql};
use super::{Decision, Verdict};

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

pub fn path(cfg: &GuardConfig) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("VERICTO_GUARD_LOG").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = &cfg.log_path {
        return Some(p.clone());
    }
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .map(|d| d.join("vericto").join("guard.jsonl"))
}

/// `2026-11-15T12:34:56Z` from a Unix time (UTC, no external crate).
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil from days (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Replaces quoted text with `'?'` (keeps the shape, drops values).
fn strip_literals(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\'' {
            out.push_str("'?'");
            for n in it.by_ref() {
                if n == '\'' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

pub fn command_field(cfg: &GuardConfig, text: &str) -> Value {
    match cfg.log_sql {
        LogSql::None => Value::Null,
        LogSql::Hash => json!(format!("sha256:{:x}", Sha256::digest(text.as_bytes()))),
        LogSql::Redacted => {
            let r = strip_literals(&super::target::redact(text));
            let r: String = r.chars().take(500).collect();
            json!(r)
        }
    }
}

/// Where a decision was taken.
pub struct Origin<'a> {
    pub agent: &'a str,
    pub session: Option<&'a str>,
    pub event: &'a str,
    pub tool: &'a str,
    pub cwd: &'a str,
}

/// One log record.
pub fn record(
    origin: &Origin,
    cfg: &GuardConfig,
    action_text: &str,
    d: &Decision,
    effective: Verdict,
) -> Value {
    let Origin {
        agent,
        session,
        event,
        tool,
        cwd,
    } = *origin;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let findings: Vec<Value> = d
        .applied
        .iter()
        .map(|a| {
            json!({
                "code": a.finding.code,
                "severity": a.finding.severity.as_str(),
                "kind": a.finding.kind.as_str(),
                "verdict": a.verdict.as_str(),
                "title": strip_literals(&a.finding.title),
                "prod": a.prod,
                "allowed_by": a.allowed_by,
                "targets": a.finding.targets.iter().map(|t| json!({
                    "host": t.host, "database": t.database, "class": t.class.as_str(), "source": t.source
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "ts": rfc3339(now),
        "agent": agent,
        "session": session,
        "event": event,
        "tool": tool,
        "cwd": cwd,
        "verdict": effective.as_str(),
        "policy_verdict": d.verdict.as_str(),
        "mode": cfg.mode.as_str(),
        "command": command_field(cfg, action_text),
        "findings": findings,
        "cli_version": env!("CARGO_PKG_VERSION"),
    })
}

/// Appends `rec`. Errors are returned for the caller to mention on stderr;
/// a log failure never changes a decision.
pub fn append(cfg: &GuardConfig, rec: &Value) -> std::io::Result<()> {
    if !cfg.log {
        return Ok(());
    }
    let Some(p) = path(cfg) else { return Ok(()) };
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if std::fs::metadata(&p)
        .map(|m| m.len() > MAX_LOG_BYTES)
        .unwrap_or(false)
    {
        let mut rotated = p.clone().into_os_string();
        rotated.push(".1");
        let _ = std::fs::rename(&p, rotated);
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)?;
    let mut line = rec.to_string();
    line.push('\n');
    f.write_all(line.as_bytes())
}

/// The last `n` records.
pub fn tail(cfg: &GuardConfig, n: usize) -> std::io::Result<Vec<Value>> {
    let Some(p) = path(cfg) else {
        return Ok(Vec::new());
    };
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..]
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_763_208_000), "2025-11-15T12:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn command_field_hides_secrets_and_values() {
        let cfg = GuardConfig::default();
        let v = command_field(&cfg, "PGPASSWORD=hunter2 psql postgres://u:pw@h/db -c \"DELETE FROM t WHERE email = 'a@b.c'\"");
        let s = v.as_str().unwrap();
        assert!(
            !s.contains("hunter2") && !s.contains(":pw@") && !s.contains("a@b.c"),
            "{s}"
        );
        let mut h = GuardConfig {
            log_sql: LogSql::Hash,
            ..GuardConfig::default()
        };
        assert!(command_field(&h, "x")
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
        h.log_sql = LogSql::None;
        assert!(command_field(&h, "x").is_null());
    }
}
