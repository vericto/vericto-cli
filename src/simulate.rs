// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! `vericto rules simulate <file>`: run a candidate rule change against the
//! workspace's recorded production traffic (the backend's rule simulator) and
//! fail the CI job when it would block legitimate flows.
//!
//! The file is the one the dashboard's custom rule editor writes, in YAML (the
//! subset below) or JSON with the same keys:
//!
//! ```yaml
//! rules:
//!   - name: protect-orders-delete
//!     code: CUSTOM-004          # omit for a new rule
//!     severity: high
//!     dialect: postgres
//!     ast_condition_yaml: |
//!       rule: protect-orders-delete
//!       node_type: DeleteStmt
//!       condition:
//!         relation: "shop_order"
//! standard:
//!   - code: VERICTO-050
//!     severity: high
//!     is_active: true
//! ```
//!
//! The YAML reader is deliberately small (no new dependency): two top-level
//! lists of flat maps, scalar values (optionally quoted), `#` comments, and `|`
//! block scalars. Anything else is a usage error (exit 2), never a guess.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// A candidate change, as `POST /api/v1/ci/rules/simulate` takes it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Candidate {
    CustomNew {
        name: String,
        severity: String,
        dialect: String,
        ast_condition_yaml: String,
    },
    CustomEdit {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        severity: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        dialect: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ast_condition_yaml: Option<String>,
    },
    StandardOverride {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        severity: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_active: Option<bool>,
    },
}

type Entry = Vec<(String, String)>;

#[derive(Default, Debug)]
struct RuleFile {
    rules: Vec<Entry>,
    standard: Vec<Entry>,
}

/// Parses the rule file into candidates (YAML subset or JSON).
pub fn parse_rule_file(text: &str) -> Result<Vec<Candidate>, String> {
    let file = if text.trim_start().starts_with('{') {
        parse_json(text)?
    } else {
        parse_yaml(text)?
    };
    let mut out = Vec::new();
    for (i, e) in file.rules.iter().enumerate() {
        let get = |k: &str| e.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        for (k, _) in e {
            if ![
                "name",
                "code",
                "severity",
                "dialect",
                "ast_condition_yaml",
                "description",
            ]
            .contains(&k.as_str())
            {
                return Err(format!("rules[{i}]: unknown key `{k}`"));
            }
        }
        match get("code") {
            Some(code) => out.push(Candidate::CustomEdit {
                code: code.to_uppercase(),
                name: get("name"),
                severity: get("severity"),
                dialect: get("dialect"),
                ast_condition_yaml: get("ast_condition_yaml"),
            }),
            None => {
                let need =
                    |k: &str| get(k).ok_or_else(|| format!("rules[{i}]: a new rule needs `{k}`"));
                out.push(Candidate::CustomNew {
                    name: need("name")?,
                    severity: need("severity")?,
                    dialect: get("dialect").unwrap_or_else(|| "all".to_string()),
                    ast_condition_yaml: need("ast_condition_yaml")?,
                })
            }
        }
    }
    for (i, e) in file.standard.iter().enumerate() {
        let get = |k: &str| e.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        for (k, _) in e {
            if !["code", "severity", "is_active"].contains(&k.as_str()) {
                return Err(format!("standard[{i}]: unknown key `{k}`"));
            }
        }
        let code = get("code").ok_or_else(|| format!("standard[{i}]: needs `code`"))?;
        let is_active = match get("is_active").as_deref() {
            None => None,
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(v) => {
                return Err(format!(
                    "standard[{i}]: is_active must be true or false, not `{v}`"
                ))
            }
        };
        out.push(Candidate::StandardOverride {
            code: code.to_uppercase(),
            severity: get("severity"),
            is_active,
        });
    }
    if out.is_empty() {
        return Err("the file has no `rules` or `standard` entries".to_string());
    }
    if out.len() > 20 {
        return Err(format!(
            "{} candidates; at most 20 per simulation",
            out.len()
        ));
    }
    Ok(out)
}

fn parse_json(text: &str) -> Result<RuleFile, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("invalid JSON: {e}"))?;
    let list = |k: &str| -> Result<Vec<Entry>, String> {
        let Some(items) = v.get(k) else {
            return Ok(vec![]);
        };
        let items = items
            .as_array()
            .ok_or_else(|| format!("`{k}` must be a list"))?;
        items
            .iter()
            .map(|item| {
                let obj = item
                    .as_object()
                    .ok_or_else(|| format!("`{k}` entries must be objects"))?;
                Ok(obj
                    .iter()
                    .map(|(key, val)| {
                        let s = match val {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        (key.clone(), s)
                    })
                    .collect())
            })
            .collect()
    };
    Ok(RuleFile {
        rules: list("rules")?,
        standard: list("standard")?,
    })
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Removes a trailing ` # comment` that is outside quotes.
fn strip_comment(s: &str) -> &str {
    let (mut single, mut double) = (false, false);
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            b'#' if !single && !double && (i == 0 || bytes[i - 1] == b' ') => {
                return s[..i].trim_end()
            }
            _ => {}
        }
    }
    s.trim_end()
}

fn unquote(v: &str) -> String {
    let v = v.trim();
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

fn split_kv(s: &str, lineno: usize) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once(':')
        .ok_or_else(|| format!("line {lineno}: expected `key: value`"))?;
    let k = k.trim();
    if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("line {lineno}: invalid key `{k}`"));
    }
    Ok((k.to_string(), v.trim().to_string()))
}

fn parse_yaml(text: &str) -> Result<RuleFile, String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut file = RuleFile::default();
    let mut section: Option<&str> = None;
    let mut current: Option<Entry> = None;
    let mut item_indent = 0usize;
    let mut i = 0;
    let flush = |file: &mut RuleFile, section: Option<&str>, current: &mut Option<Entry>| {
        if let (Some(sec), Some(e)) = (section, current.take()) {
            if sec == "rules" {
                file.rules.push(e)
            } else {
                file.standard.push(e)
            }
        }
    };
    while i < lines.len() {
        let raw = lines[i];
        let lineno = i + 1;
        i += 1;
        if raw.contains('\t') {
            return Err(format!("line {lineno}: tabs are not allowed in YAML"));
        }
        let line = strip_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        let ind = indent_of(line);
        let body = line.trim_start();
        if ind == 0 {
            flush(&mut file, section, &mut current);
            let (k, v) = split_kv(body, lineno)?;
            if !v.is_empty() {
                return Err(format!("line {lineno}: `{k}` must be a list"));
            }
            section = match k.as_str() {
                "rules" => Some("rules"),
                "standard" => Some("standard"),
                other => {
                    return Err(format!(
                    "line {lineno}: unknown top-level key `{other}` (expected rules or standard)"
                ))
                }
            };
            continue;
        }
        if section.is_none() {
            return Err(format!(
                "line {lineno}: indented line outside `rules` or `standard`"
            ));
        }
        let kv_text = if let Some(rest) = body.strip_prefix("- ") {
            flush(&mut file, section, &mut current);
            current = Some(Vec::new());
            item_indent = ind + 2;
            rest
        } else {
            if current.is_none() || ind != item_indent {
                return Err(format!("line {lineno}: unexpected indentation"));
            }
            body
        };
        let (k, v) = split_kv(kv_text, lineno)?;
        let value = if v == "|" || v == "|-" {
            // Block scalar: the following lines indented deeper than the key.
            let mut block: Vec<String> = Vec::new();
            let mut base: Option<usize> = None;
            while i < lines.len() {
                let l = lines[i];
                if l.trim().is_empty() {
                    block.push(String::new());
                    i += 1;
                    continue;
                }
                let li = indent_of(l);
                if li < item_indent + 1 {
                    break;
                }
                let b = *base.get_or_insert(li);
                if li < b {
                    return Err(format!(
                        "line {}: block scalar indentation decreased",
                        i + 1
                    ));
                }
                block.push(l[b..].to_string());
                i += 1;
            }
            while block.last().is_some_and(|l| l.is_empty()) {
                block.pop();
            }
            block.join("\n")
        } else {
            unquote(&v)
        };
        let entry = current.as_mut().expect("entry");
        if entry.iter().any(|(key, _)| *key == k) {
            return Err(format!("line {lineno}: duplicate key `{k}`"));
        }
        entry.push((k, value));
    }
    flush(&mut file, section, &mut current);
    Ok(file)
}

/// The request body.
pub fn request_body(
    candidates: &[Candidate],
    days: u32,
    database: Option<&str>,
    fail_on_break: u32,
) -> Value {
    let mut body = json!({
        "candidates": candidates,
        "days": days,
        "thresholds": { "fail_on_break": fail_on_break },
    });
    if let Some(db) = database {
        body["database_id"] = json!(db);
    }
    body
}

/// What the CLI needs from a simulation (the rest is printed with `--format json`).
#[derive(Debug, Clone, Deserialize)]
pub struct Simulation {
    pub simulation_id: String,
    pub status: String,
    #[serde(default)]
    pub summary: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub findings: Vec<Value>,
}

/// Exit code for a finished simulation: 0 Pass/Warn, 1 Fail (or Inconclusive with
/// `--strict`), 4 when the job itself failed.
pub fn exit_for(sim: &Simulation, strict: bool) -> u8 {
    if sim.status != "succeeded" {
        return 4;
    }
    let verdict = sim
        .summary
        .as_ref()
        .and_then(|s| s.get("verdict"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match verdict {
        "fail" => 1,
        "inconclusive" if strict => 1,
        "pass" | "warn" | "inconclusive" => 0,
        _ => 4,
    }
}

fn n(v: Option<&Value>) -> u64 {
    v.and_then(|x| x.as_u64()).unwrap_or(0)
}

fn group(x: u64) -> String {
    let s = x.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The text report (the use case's layout).
pub fn render_text(sim: &Simulation) -> String {
    let mut out = String::new();
    let Some(s) = sim.summary.as_ref() else {
        out.push_str(&format!(
            "Vericto rule simulation {}  {}{}\n",
            short(&sim.simulation_id),
            sim.status,
            sim.error
                .as_deref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        ));
        return out;
    };
    let w = &s["window"];
    let cov = &s["coverage"];
    let cats = &s["categories"];
    out.push_str(&format!(
        "Vericto rule simulation  {}   window {} → {} ({} days)\n",
        short(&sim.simulation_id),
        w["start"].as_str().unwrap_or("").get(..10).unwrap_or(""),
        w["end"].as_str().unwrap_or("").get(..10).unwrap_or(""),
        n(w.get("days"))
    ));
    out.push_str(&format!(
        "Events {} · fingerprints {} · evaluated statements {} (budget {})\n",
        group(n(s.get("events"))),
        group(n(s.get("fingerprints"))),
        group(n(s.get("evaluated_statements"))),
        group(n(s.get("budget")))
    ));
    out.push_str(&format!(
        "Coverage {:.1}% (evaluated {} + inferred {} executions) · not replayable {}\n",
        cov["ratio"].as_f64().unwrap_or(0.0) * 100.0,
        group(n(cov.get("evaluated_executions"))),
        group(n(cov.get("inferred_executions"))),
        group(n(cov.get("not_replayable_executions")))
    ));
    out.push_str(&format!(
        "Text mode: {}\n\n",
        s["query_text_mode"].as_str().unwrap_or("raw")
    ));
    out.push_str(&format!(
        "{}  {}\n",
        s["verdict"].as_str().unwrap_or("?").to_uppercase(),
        s["headline"].as_str().unwrap_or("")
    ));
    for (cat, title) in [
        ("newly_blocked", "NEWLY BLOCKED"),
        ("newly_flagged", "NEWLY FLAGGED"),
        ("no_longer_blocked", "NO LONGER BLOCKED"),
    ] {
        let fs: Vec<&Value> = sim
            .findings
            .iter()
            .filter(|f| f["category"] == cat)
            .collect();
        if fs.is_empty() {
            out.push_str(&format!("\n{title:<20}none\n"));
            continue;
        }
        out.push_str(&format!("\n{title}\n"));
        for f in fs {
            let mark = if f["legitimate"].as_bool() == Some(true) {
                "!"
            } else {
                "·"
            };
            let codes: Vec<&str> = f["rule_codes"]
                .as_array()
                .map(|a| a.iter().filter_map(|c| c.as_str()).collect())
                .unwrap_or_default();
            out.push_str(&format!(
                "  {mark} {}   {}\n",
                codes.join(", "),
                if f["legitimate"].as_bool() == Some(true) {
                    "legitimate"
                } else {
                    "not classified legitimate"
                }
            ));
            let text = f["samples"]
                .get(0)
                .and_then(|x| x["text"].as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    format!(
                        "{} {}",
                        f["statement_kind"].as_str().unwrap_or("SQL"),
                        f["tables"]
                            .as_array()
                            .map(|t| t
                                .iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", "))
                            .unwrap_or_default()
                    )
                });
            out.push_str(&format!("    {text}\n"));
            let who: Vec<String> = f["identities"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .take(3)
                        .map(|i| {
                            format!(
                                "{} ({})",
                                i["name"]
                                    .as_str()
                                    .or(i["ref"].as_str())
                                    .unwrap_or("unknown"),
                                group(n(i.get("executions")))
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            let sources: Vec<&str> = f["sources"]
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter(|(_, v)| v.as_u64().unwrap_or(0) > 0)
                        .map(|(k, _)| k.as_str())
                        .collect()
                })
                .unwrap_or_default();
            out.push_str(&format!(
                "    {} executions · {}/{} days · source {} · {}\n",
                group(n(f.get("executions"))),
                n(f.get("days_seen")),
                n(w.get("days")),
                sources.join(", "),
                who.join(", ")
            ));
        }
    }
    out.push_str(&format!(
        "UNCHANGED           {} fingerprints · {} executions\n",
        group(n(cats["unchanged"].get("fingerprints"))),
        group(n(cats["unchanged"].get("executions")))
    ));
    if let Some(cands) = s["candidates"].as_array() {
        for c in cands {
            if n(c.get("matched_executions")) == 0 {
                out.push_str(&format!(
                    "  {} {}: 0 matches in the window\n",
                    c["code"].as_str().unwrap_or(""),
                    c["name"].as_str().unwrap_or("")
                ));
            }
        }
    }
    let drift = &cats["drift"];
    out.push_str(&format!(
        "\nDRIFT (not caused by this change)   {} fingerprints · {} executions\n",
        group(n(drift.get("fingerprints"))),
        group(n(drift.get("executions")))
    ));
    out
}

fn short(id: &str) -> String {
    format!("{}…", id.get(..4).unwrap_or(id))
}

/// Parses `--wait` (`15m`, `90s`, `1h`, or plain seconds).
pub fn parse_wait(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    let v: u64 = num
        .parse()
        .map_err(|_| format!("invalid duration `{s}` (e.g. 15m, 90s)"))?;
    Ok(std::time::Duration::from_secs(v * mult))
}

#[cfg(test)]
mod tests {
    use super::*;

    const USE_CASE: &str = r#"# .vericto/rules/deletes.yaml
rules:
  - name: no-physical-delete-orders
    severity: high
    dialect: postgres
    ast_condition_yaml: |
      rule: no-physical-delete-orders
      node_type: DeleteStmt
      condition:
        relation: "shop_order"
  - name: protect-orders-delete
    code: custom-004          # an edit
    severity: critical
standard:
  - code: VERICTO-050
    severity: "high"
    is_active: true
"#;

    #[test]
    fn parses_the_documented_yaml() {
        let c = parse_rule_file(USE_CASE).unwrap();
        assert_eq!(
            c[0],
            Candidate::CustomNew {
                name: "no-physical-delete-orders".into(),
                severity: "high".into(),
                dialect: "postgres".into(),
                ast_condition_yaml: "rule: no-physical-delete-orders\nnode_type: DeleteStmt\ncondition:\n  relation: \"shop_order\"".into(),
            }
        );
        assert_eq!(
            c[1],
            Candidate::CustomEdit {
                code: "CUSTOM-004".into(),
                name: Some("protect-orders-delete".into()),
                severity: Some("critical".into()),
                dialect: None,
                ast_condition_yaml: None
            }
        );
        assert_eq!(
            c[2],
            Candidate::StandardOverride {
                code: "VERICTO-050".into(),
                severity: Some("high".into()),
                is_active: Some(true)
            }
        );
        let body = request_body(&c, 30, None, 0);
        assert_eq!(body["candidates"][0]["kind"], "custom_new");
        assert_eq!(body["candidates"][1]["kind"], "custom_edit");
        assert!(body["candidates"][1].get("dialect").is_none());
        assert_eq!(body["thresholds"]["fail_on_break"], 0);
    }

    #[test]
    fn parses_json_with_the_same_keys() {
        let c =
            parse_rule_file(r#"{"standard":[{"code":"VERICTO-010","is_active":false}]}"#).unwrap();
        assert_eq!(
            c,
            vec![Candidate::StandardOverride {
                code: "VERICTO-010".into(),
                severity: None,
                is_active: Some(false)
            }]
        );
    }

    #[test]
    fn rejects_what_it_does_not_understand() {
        assert!(parse_rule_file("rules:\n  - name: x\n    severity: high\n")
            .unwrap_err()
            .contains("ast_condition_yaml"));
        assert!(parse_rule_file("other:\n  - a: b\n")
            .unwrap_err()
            .contains("unknown top-level key"));
        assert!(parse_rule_file("rules:\n  - name: x\n    sevrity: high\n")
            .unwrap_err()
            .contains("unknown key"));
        assert!(parse_rule_file("rules:\n\t- name: x\n")
            .unwrap_err()
            .contains("tabs"));
        assert!(parse_rule_file("").unwrap_err().contains("no `rules`"));
        assert!(
            parse_rule_file("standard:\n  - code: VERICTO-001\n    is_active: maybe\n").is_err()
        );
    }

    #[test]
    fn exit_codes_follow_the_verdict() {
        let sim = |status: &str, verdict: &str| Simulation {
            simulation_id: "x".into(),
            status: status.into(),
            summary: Some(json!({ "verdict": verdict })),
            error: None,
            findings: vec![],
        };
        assert_eq!(exit_for(&sim("succeeded", "pass"), false), 0);
        assert_eq!(exit_for(&sim("succeeded", "warn"), false), 0);
        assert_eq!(exit_for(&sim("succeeded", "fail"), false), 1);
        assert_eq!(exit_for(&sim("succeeded", "inconclusive"), false), 0);
        assert_eq!(exit_for(&sim("succeeded", "inconclusive"), true), 1);
        assert_eq!(exit_for(&sim("failed", ""), false), 4);
    }

    #[test]
    fn parses_wait_durations() {
        assert_eq!(parse_wait("15m").unwrap().as_secs(), 900);
        assert_eq!(parse_wait("90s").unwrap().as_secs(), 90);
        assert_eq!(parse_wait("120").unwrap().as_secs(), 120);
        assert!(parse_wait("soon").is_err());
    }

    #[test]
    fn renders_the_headline_and_findings() {
        let sim = Simulation {
            simulation_id: "7f3c-1".into(),
            status: "succeeded".into(),
            summary: Some(json!({
                "verdict": "fail",
                "headline": "Would have blocked 2 legitimate flows (9,442 executions) in the last 30 days.",
                "window": { "start": "2026-09-10T00:00:00Z", "end": "2026-10-10T00:00:00Z", "days": 30 },
                "events": 1842310, "fingerprints": 2914, "evaluated_statements": 41206, "budget": 200000,
                "coverage": { "ratio": 0.996, "evaluated_executions": 1207553, "inferred_executions": 627312, "not_replayable_executions": 7445 },
                "categories": { "unchanged": { "fingerprints": 2911, "executions": 1825422 }, "drift": { "fingerprints": 3, "executions": 12 } },
                "candidates": [{ "code": "SIM-002", "name": "ledger-append-only", "matched_executions": 0 }],
                "query_text_mode": "raw"
            })),
            error: None,
            findings: vec![json!({
                "category": "newly_blocked", "legitimate": true, "rule_codes": ["SIM-001"],
                "samples": [{ "text": "DELETE FROM \"cart_cartitem\" WHERE \"cart_cartitem\".\"id\" = $1" }],
                "executions": 9412, "days_seen": 30, "sources": { "tcp": 9412 },
                "identities": [{ "name": "app_web", "executions": 9412 }]
            })],
        };
        let t = render_text(&sim);
        assert!(
            t.contains("FAIL  Would have blocked 2 legitimate flows (9,442 executions)"),
            "{t}"
        );
        assert!(t.contains("Coverage 99.6% (evaluated 1,207,553 + inferred 627,312 executions) · not replayable 7,445"), "{t}");
        assert!(t.contains("! SIM-001   legitimate"), "{t}");
        assert!(
            t.contains("9,412 executions · 30/30 days · source tcp · app_web (9,412)"),
            "{t}"
        );
        assert!(
            t.contains("SIM-002 ledger-append-only: 0 matches in the window"),
            "{t}"
        );
        assert!(
            t.contains("DRIFT (not caused by this change)   3 fingerprints · 12 executions"),
            "{t}"
        );
    }
}
