// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! SQL the agent is about to send to a database, checked with the embedded
//! engine exactly as `vericto check --offline --sql` checks it (the runtime
//! profile: `DROP TABLE` blocks), or as a migration file when it is one (the
//! CI profile's schema-DDL cap, so a reviewed migration's `ALTER TABLE` is
//! asked about rather than denied).
//!
//! Text the engine cannot parse (a client meta-command, another dialect, a
//! fragment with an unresolved `$VAR`) falls back to a keyword reading that
//! only reports statements which are destructive on their face: `DROP
//! TABLE|DATABASE|SCHEMA`, `TRUNCATE`, and `DELETE` / `UPDATE` with no
//! `WHERE`.

use super::Severity;
use crate::api::QueryInput;
use crate::offline::{self, Profile};

/// What the engine (or the keyword reading) found in one piece of SQL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlFinding {
    pub code: String,
    pub severity: Severity,
    /// The engine reported High (not Critical): `high_sql` decides.
    pub high: bool,
    pub title: String,
    pub fix: String,
    /// The statement text, shortened.
    pub preview: String,
}

/// Short titles for the engine's rule codes, for the reason an agent reads.
pub fn rule_title(code: &str) -> &'static str {
    match code {
        "VERICTO-001" => "DELETE without WHERE",
        "VERICTO-002" => "DELETE with LIMIT 0",
        "VERICTO-003" => "DELETE with an always-true WHERE",
        "VERICTO-010" => "DROP TABLE / DATABASE",
        "VERICTO-011" => "TRUNCATE",
        "VERICTO-012" => "DROP SCHEMA / DATABASE",
        "VERICTO-013" => "DROP INDEX without IF EXISTS",
        "VERICTO-015" => "ALTER TABLE DROP COLUMN",
        "VERICTO-016" => "ALTER TABLE RENAME",
        "VERICTO-017" => "ALTER TABLE DROP CONSTRAINT",
        "VERICTO-018" => "ALTER COLUMN TYPE",
        "VERICTO-019" => "DISABLE TRIGGER / ROW LEVEL SECURITY",
        "VERICTO-030" | "VERICTO-042" => "UPDATE without WHERE",
        "VERICTO-031" => "UPDATE in a CTE without WHERE",
        "VERICTO-033" => "DELETE in a subquery/CTE without WHERE",
        "VERICTO-040" => "INSERT … SELECT without a filter",
        "VERICTO-070" => "sleep function",
        "VERICTO-080" => "COPY … PROGRAM (runs a shell command on the server)",
        "VERICTO-081" => "DO block (opaque code)",
        "VERICTO-082" => "GRANT / REVOKE",
        "VERICTO-083" => "MERGE",
        "VERICTO-084" => "CREATE TABLE AS SELECT",
        "VERICTO-086" => "MySQL text read two ways",
        "VERICTO-090" => "OR tautology in WHERE",
        "VERICTO-091" => "stage unload / file transfer",
        "VERICTO-092" => "external stage or integration",
        "VERICTO-093" => "share to another account",
        "VERICTO-094" => "recovery reduced",
        "VERICTO-096" => "code that runs later",
        "VERICTO-097" => "role switch",
        "VERICTO-098" => "ATTACH DATABASE",
        "VERICTO-099" => "safety PRAGMA turned off",
        "VERICTO-100" => "extension loading / file functions",
        "VERICTO-101" => "VACUUM INTO",
        "VG-301" => "DROP (unparsed SQL)",
        "VG-302" => "TRUNCATE (unparsed SQL)",
        "VG-303" => "DELETE without WHERE (unparsed SQL)",
        "VG-304" => "UPDATE without WHERE (unparsed SQL)",
        _ => "destructive SQL",
    }
}

fn preview(sql: &str) -> String {
    let one: String = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > 120 {
        let mut s: String = one.chars().take(117).collect();
        s.push('…');
        s
    } else {
        one
    }
}

/// Drops psql / sqlite3 / mysql client commands (`\c db`, `.tables`,
/// `\dt`), which are not SQL, keeping line structure.
pub fn strip_client_commands(sql: &str) -> String {
    sql.lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with('\\')
                || (t.starts_with('.') && t.len() > 1 && t.as_bytes()[1].is_ascii_alphabetic()))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Checks `sql` in `dialect`. `migration`: the text is a versioned migration
/// file (CI profile cap). Returns the strongest finding, if any.
pub fn check(sql: &str, dialect: &str, migration: bool) -> Option<SqlFinding> {
    let cleaned = strip_client_commands(sql);
    if cleaned.trim().is_empty() || cleaned.trim().trim_matches(';').trim().is_empty() {
        return None;
    }
    if !offline::AVAILABLE {
        return keyword_check(&cleaned);
    }
    let input = [QueryInput {
        line: 1,
        sql: cleaned.clone(),
    }];
    let profile = if migration {
        Profile::Ci
    } else {
        Profile::Runtime
    };
    let result = offline::check_with(&input, dialect, profile, &|_| migration).ok()?;
    let q = result.queries.into_iter().next()?;
    let sev = q.severity.as_deref().unwrap_or("");
    let finding = |severity: Severity, high: bool| {
        let code = q.rule_code.clone().unwrap_or_else(|| "VERICTO".into());
        SqlFinding {
            title: rule_title(&code).to_string(),
            code,
            severity,
            high,
            fix: q.suggested_fix.clone().unwrap_or_default(),
            preview: preview(&cleaned),
        }
    };
    match q.status.as_str() {
        "BLOCKED" if sev == "critical" => Some(finding(Severity::Critical, false)),
        "BLOCKED" => Some(finding(Severity::Medium, true)),
        // A migration's capped schema DDL: asked about, not denied.
        "FLAGGED" if sev == "critical" || sev == "high" => Some(finding(Severity::Medium, false)),
        "PARSE_ERROR" => keyword_check(&cleaned),
        _ => None,
    }
}

/// The keyword reading for text the engine could not parse. Comments and
/// quoted text are removed first, so `SELECT 'DROP TABLE x'` reports nothing.
pub fn keyword_check(sql: &str) -> Option<SqlFinding> {
    let bare = strip_comments_and_strings(sql).to_ascii_uppercase();
    for stmt in bare.split(';') {
        let words: Vec<&str> = stmt.split_whitespace().collect();
        let hit = match words.as_slice() {
            ["DROP", kind, ..] if matches!(*kind, "TABLE" | "DATABASE" | "SCHEMA") => Some((
                "VG-301",
                "Drop only what a reviewed migration drops, on a disposable database first.",
            )),
            ["TRUNCATE", ..] => Some((
                "VG-302",
                "Delete the rows you mean with a WHERE clause, or run it on a disposable database.",
            )),
            ["DELETE", ..] if !words.contains(&"WHERE") => Some((
                "VG-303",
                "Add a WHERE clause that selects the rows to delete.",
            )),
            ["UPDATE", ..] if words.contains(&"SET") && !words.contains(&"WHERE") => Some((
                "VG-304",
                "Add a WHERE clause that selects the rows to update.",
            )),
            _ => None,
        };
        if let Some((code, fix)) = hit {
            return Some(SqlFinding {
                code: code.into(),
                severity: Severity::Critical,
                high: false,
                title: rule_title(code).into(),
                fix: fix.into(),
                preview: preview(sql),
            });
        }
    }
    None
}

/// Replaces `--`/`#` line comments, `/* */` blocks, and `'…'`, `"…"`,
/// `` `…` `` and `$tag$…$tag$` text with spaces.
pub fn strip_comments_and_strings(sql: &str) -> String {
    let c: Vec<char> = sql.chars().collect();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '-' if c.get(i + 1) == Some(&'-') => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '#' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            '/' if c.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < c.len() && !(c[i] == '*' && c[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            q @ ('\'' | '"' | '`') => {
                i += 1;
                while i < c.len() {
                    if c[i] == q {
                        if c.get(i + 1) == Some(&q) {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    if c[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                out.push(' ');
            }
            '$' => {
                // $tag$ … $tag$
                let start = i;
                let mut j = i + 1;
                while j < c.len() && (c[j].is_alphanumeric() || c[j] == '_') {
                    j += 1;
                }
                if j < c.len() && c[j] == '$' {
                    let tag: String = c[start..=j].iter().collect();
                    let rest: String = c[j + 1..].iter().collect();
                    match rest.find(&tag) {
                        Some(p) => {
                            i = j + 1 + rest[..p].chars().count() + tag.chars().count();
                        }
                        None => i = c.len(),
                    }
                    out.push(' ');
                } else {
                    out.push('$');
                    i += 1;
                }
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "offline")]
    fn code(sql: &str, dialect: &str) -> Option<String> {
        check(sql, dialect, false).map(|f| f.code)
    }

    #[cfg(feature = "offline")]
    #[test]
    fn engine_findings() {
        assert_eq!(
            code("DELETE FROM users", "postgres").as_deref(),
            Some("VERICTO-001")
        );
        assert_eq!(
            code("drop table users;", "postgres").as_deref(),
            Some("VERICTO-010")
        );
        assert_eq!(
            code("TRUNCATE orders", "mysql").as_deref(),
            Some("VERICTO-011")
        );
        assert!(matches!(
            code("UPDATE users SET admin = true", "postgres").as_deref(),
            Some("VERICTO-042" | "VERICTO-030")
        ));
        assert_eq!(
            code("SELECT 1; DROP TABLE x", "postgres").as_deref(),
            Some("VERICTO-010")
        );
        assert_eq!(
            code("DROP DATABASE app", "mysql").map(|c| c.starts_with("VERICTO-01")),
            Some(true)
        );
        assert_eq!(
            code("DELETE FROM t WHERE 1=1", "postgres").as_deref(),
            Some("VERICTO-003")
        );
    }

    #[test]
    fn safe_sql_is_allowed() {
        for sql in [
            "SELECT * FROM users",
            "SELECT id FROM users WHERE id = 1",
            "DELETE FROM sessions WHERE expires_at < now()",
            "UPDATE users SET name = 'x' WHERE id = 1",
            "INSERT INTO t (a) VALUES (1)",
            "CREATE TABLE t (id int)",
            "SELECT 'DROP TABLE users'",
            "-- DROP TABLE users\nSELECT 1",
            "\\dt",
            "\\c app\nSELECT 1;",
            "",
            ";",
        ] {
            assert_eq!(check(sql, "postgres", false), None, "{sql}");
        }
    }

    #[cfg(feature = "offline")]
    #[test]
    fn high_findings_are_medium() {
        let f = check("ALTER TABLE users DROP COLUMN email", "postgres", false).unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.high);
        assert_eq!(f.code, "VERICTO-015");
    }

    #[cfg(feature = "offline")]
    #[test]
    fn migrations_are_capped() {
        let f = check("DROP TABLE old_users", "postgres", true).unwrap();
        assert_eq!(f.severity, Severity::Medium);
        assert!(!f.high);
        // TRUNCATE is never capped.
        let f = check("TRUNCATE t", "postgres", true).unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn keyword_fallback() {
        assert_eq!(keyword_check("DROP TABLE $T").unwrap().code, "VG-301");
        assert_eq!(
            keyword_check("truncate table x SETTINGS a=1").unwrap().code,
            "VG-302"
        );
        assert_eq!(keyword_check("delete from $T").unwrap().code, "VG-303");
        assert_eq!(keyword_check("update x set a=1").unwrap().code, "VG-304");
        assert_eq!(keyword_check("DELETE FROM x WHERE id = $1"), None);
        assert_eq!(keyword_check("select 'drop table x' -- drop table y"), None);
        assert_eq!(keyword_check("SELECT $$DROP TABLE x$$"), None);
        assert_eq!(keyword_check("/* TRUNCATE x */ SELECT 1"), None);
        // Unparseable with a variable: the engine fails, the keywords catch it.
        assert_eq!(
            check("DROP TABLE $TABLE", "postgres", false).unwrap().code,
            "VG-301"
        );
    }

    #[test]
    fn client_commands() {
        assert_eq!(
            strip_client_commands("\\c x\nselect 1\n.tables"),
            "select 1"
        );
        assert_eq!(strip_client_commands(".5 + 1"), ".5 + 1");
    }
}
