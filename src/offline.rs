// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Offline mode (DESIGN §13): `vericto check --offline` evaluates with
//! the embedded `vericto-engine` and its standard rules at their default
//! severities, with no network call at all.
//!
//! What it reproduces is exactly what a workspace with no overrides gets from
//! `POST /api/v1/ci/check-key`: the same 42 standard rules (the table
//! `vericto-proxy` seeds as its built-in ruleset, kept equal to the engine's
//! catalogue by a test below), the engine's default enforcement policy
//! (Critical/High → BLOCK, Medium → FLAG, Low → MONITOR, parse errors allowed
//! and reported), plus the CI channel's schema-migration cap: DROP/ALTER/
//! TRUNCATE are FLAGGED, not BLOCKED, as the backend does for every CI check
//! (`CI_SCHEMA_MIGRATION_CAP` in vericto-fmw's ci-service.ts). The status
//! mapping is vericto-eval's (`proxy.rs`), so a result reads the same as the
//! online one.
//!
//! What it cannot reproduce, by construction: custom rules, severity and
//! action overrides, sensitive columns and masking, agent allowlists, the
//! workspace's parse-error policy, the audit trail and signed receipts. Those
//! live in the workspace, and the result says `mode: offline` so nobody
//! mistakes one for the other.
//!
//! Granularity: one result per input (whole file, stdin or `--sql` entry), the
//! shape older backends return (§12.3), because the per-statement split lives
//! in the backend (sql-split.ts). Moving that splitter into the engine would
//! give offline mode exact lines too.
//!
//! The rule table, the version and the decision are the engine's: the 42
//! rules come from `vericto_engine::standard_rules()`, the version from
//! `vericto_engine::ENGINE_VERSION`, and the verdict is the engine's own
//! decision, which since engine 4.2.0 is the strongest resolved action across
//! all violations (so a capped DROP TABLE never hides a blocking UPDATE in the
//! same file). Until CLI 1.9.1 this module carried its own copy of all three,
//! because engine 4.1.3 exported none of them and picked its winner by
//! severity first.
//!
//! Windows: since 1.11.0 the engine is built for Windows like every other
//! target, and the Windows CI job (a required check) runs the whole suite,
//! offline tests included, on `windows-2022` and `windows-11-arm`. Until then
//! the Windows binary was online-only.

use crate::api::{CheckResponse, QueryInput, RunMode, Summary};

/// Whether this build can evaluate offline: the `offline` feature (default,
/// on every release target) embeds the engine.
pub const AVAILABLE: bool = cfg!(feature = "offline");

/// Version of the embedded `vericto-engine`: the engine's own constant.
#[cfg(feature = "offline")]
pub const ENGINE_VERSION: &str = vericto_engine::ENGINE_VERSION;
/// A build with no engine never reports an offline result (`check` fails with
/// `Unavailable` first), so this only keeps the type the same.
#[cfg(not(feature = "offline"))]
pub const ENGINE_VERSION: &str = "none";

/// Number of standard rules evaluated offline: the engine's standard ruleset.
#[cfg(feature = "offline")]
pub const STANDARD_RULE_COUNT: usize = vericto_engine::STANDARD_RULES.len();
/// No engine, no rules (never reported, see `ENGINE_VERSION`).
#[cfg(not(feature = "offline"))]
pub const STANDARD_RULE_COUNT: usize = 0;

/// The `ruleset_version` an offline result reports: the standard set is a
/// function of the engine version alone, so the version names both. The
/// format (`standard@engine-X.Y.Z`) is the one 1.9.0 shipped, so baselines and
/// dashboards that read it keep working.
pub fn ruleset_version() -> String {
    format!("standard@engine-{ENGINE_VERSION}")
}

/// Whether this looks like a CI job, where a missing credential must stay an
/// error instead of switching to offline mode. Broader than
/// `ci_env::Provider` (GitHub/GitLab only): any of the variables the common CI
/// systems set. A miss here only means a CI job without credentials runs
/// offline, and says so on stderr and in every output format.
pub fn in_ci() -> bool {
    const VARS: &[&str] = &[
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "BUILDKITE",
        "CIRCLECI",
        "JENKINS_URL",
        "TF_BUILD",
        "BITBUCKET_BUILD_NUMBER",
        "TEAMCITY_VERSION",
        "CODEBUILD_BUILD_ID",
    ];
    VARS.iter()
        .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()))
}

/// Why an offline check could not run at all.
#[derive(Debug, PartialEq, Eq)]
pub enum OfflineError {
    /// This build has no engine (built with `--no-default-features`).
    Unavailable,
    /// The dialect is not one the engine knows.
    #[cfg_attr(not(feature = "offline"), allow(dead_code))]
    Dialect(String),
}

impl std::fmt::Display for OfflineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OfflineError::Unavailable => write!(
                f,
                "this build of vericto was compiled without the `offline` feature, so it has no \
                 offline evaluator. Use online mode (`vericto login` or VERICTO_API_KEY), or a \
                 release build."
            ),
            OfflineError::Dialect(d) => write!(
                f,
                "unsupported dialect '{d}' (use postgres, mysql, oracle, mssql, snowflake or sqlite)"
            ),
        }
    }
}

/// Evaluates every input locally and returns a response shaped exactly like
/// the backend's, marked `RunMode::Offline`. No I/O of any kind.
pub fn check(queries: &[QueryInput], dialect: &str) -> Result<CheckResponse, OfflineError> {
    let results = engine::evaluate_all(queries, dialect)?;
    let count = |s: &str| results.iter().filter(|q| q.status == s).count() as u32;
    let blocked = count("BLOCKED");
    Ok(CheckResponse {
        summary: Summary {
            total: results.len() as u32,
            blocked,
            allowed: count("ALLOWED"),
            flagged: count("FLAGGED"),
            monitored: count("MONITORED"),
            parse_errors: count("PARSE_ERROR"),
            ruleset_version: ruleset_version(),
        },
        exit_code: i32::from(blocked > 0),
        queries: results,
        ci_checks_remaining: None,
        telemetry_query_mode: None,
        min_cli_version: None,
        receipt: None,
        merged_receipts: Vec::new(),
        api_version_header: None,
        mode: RunMode::Offline {
            engine_version: ENGINE_VERSION,
            rules: STANDARD_RULE_COUNT,
        },
    })
}

#[cfg(feature = "offline")]
mod engine {
    use super::OfflineError;
    use crate::api::{QueryInput, QueryResult};
    use vericto_engine::parser::{parser_for, Dialect};
    use vericto_engine::{
        standard_rules, Decision, EnforcementAction, EnforcementPolicy, RuleEngine,
    };

    /// Largest input evaluated. Online, the sidecar refuses analysis past
    /// 64 KiB per statement because it is multi-tenant; offline the input is a
    /// whole file on the user's own machine, so the limit is vericto-proxy's
    /// (10 MiB, about 3.5 s of parsing). Past it the input is a PARSE_ERROR,
    /// as online.
    pub(super) const MAX_INPUT_BYTES: usize = 10 * 1024 * 1024;

    /// The backend's `sql_preview`: the first 100 characters.
    fn preview(sql: &str) -> String {
        sql.chars().take(100).collect()
    }

    /// A PARSE_ERROR result, as vericto-eval reports one with no sensitive
    /// columns and no allowlist: no rule, no severity, no action.
    fn parse_error(line: u32, sql: &str) -> QueryResult {
        QueryResult {
            line,
            file_index: None,
            statement_hash: None,
            sql_preview: preview(sql),
            status: "PARSE_ERROR".to_string(),
            action: None,
            rule_code: None,
            ast_node_path: Some("PARSE_ERROR".to_string()),
            severity: None,
            suggested_fix: None,
        }
    }

    /// The policy a CI check runs under in a workspace with no overrides: the
    /// engine default plus the CI channel's schema-migration cap (FLAG).
    pub(super) fn ci_policy() -> EnforcementPolicy {
        EnforcementPolicy {
            schema_migration_cap: Some(EnforcementAction::Flag),
            ..EnforcementPolicy::default()
        }
    }

    fn action_str(a: EnforcementAction) -> &'static str {
        match a {
            EnforcementAction::Block => "block",
            EnforcementAction::Flag => "flag",
            EnforcementAction::Monitor => "monitor",
        }
    }

    pub(super) fn evaluate_all(
        queries: &[QueryInput],
        dialect: &str,
    ) -> Result<Vec<QueryResult>, OfflineError> {
        let dialect =
            Dialect::parse_dialect(dialect).map_err(|_| OfflineError::Dialect(dialect.into()))?;
        let rules = standard_rules();
        let policy = ci_policy();
        let parser = parser_for(dialect);
        Ok(queries
            .iter()
            .map(|q| {
                if q.sql.len() > MAX_INPUT_BYTES {
                    return parse_error(q.line, &q.sql);
                }
                let Ok(parsed) = parser.parse(&q.sql) else {
                    return parse_error(q.line, &q.sql);
                };
                // The engine's decision is the strongest resolved action across
                // all violations (engine 4.2.0), and `rule_code` is the
                // violation that holds it, so every output format and the exit
                // code agree on it.
                let o = RuleEngine::evaluate(&parsed, &rules, &policy);
                // vericto-eval's mapping (proxy.rs), so statuses read the same.
                let status = match (o.decision, o.action) {
                    (Decision::Allow, Some(EnforcementAction::Monitor)) => "MONITORED",
                    (Decision::Allow, _) => "ALLOWED",
                    (Decision::Flag, _) => "FLAGGED",
                    (Decision::Block, _) => "BLOCKED",
                };
                QueryResult {
                    line: q.line,
                    file_index: None,
                    statement_hash: None,
                    sql_preview: preview(&q.sql),
                    status: status.to_string(),
                    action: o.action.map(|a| action_str(a).to_string()),
                    rule_code: o.rule_code,
                    ast_node_path: o.ast_node_path,
                    severity: o.severity.map(|s| s.as_str().to_string()),
                    suggested_fix: o.suggested_safe_query.or(o.rewritten_query),
                }
            })
            .collect())
    }
}

#[cfg(not(feature = "offline"))]
mod engine {
    use super::OfflineError;
    use crate::api::{QueryInput, QueryResult};

    pub(super) fn evaluate_all(
        _queries: &[QueryInput],
        _dialect: &str,
    ) -> Result<Vec<QueryResult>, OfflineError> {
        Err(OfflineError::Unavailable)
    }
}

#[cfg(all(test, feature = "offline"))]
mod tests {
    use super::*;
    use crate::api::QueryResult;
    use std::collections::BTreeSet;

    fn q(sql: &str) -> Vec<QueryInput> {
        vec![QueryInput {
            line: 1,
            sql: sql.to_string(),
        }]
    }

    fn one(sql: &str, dialect: &str) -> QueryResult {
        check(&q(sql), dialect).unwrap().queries.remove(0)
    }

    /// Offline evaluates the engine's whole standard ruleset: 42 rules, one per
    /// code. The engine's own `rule_catalogue_sync` test keeps that table equal
    /// to its README and to the evaluator, so the CLI no longer checks it.
    #[test]
    fn evaluates_the_engines_42_standard_rules() {
        let rules = vericto_engine::standard_rules();
        let codes: BTreeSet<&str> = rules.iter().map(|r| r.rule_id.as_str()).collect();
        assert_eq!(STANDARD_RULE_COUNT, 42);
        assert_eq!(rules.len(), STANDARD_RULE_COUNT);
        assert_eq!(codes.len(), STANDARD_RULE_COUNT, "no duplicate codes");
    }

    /// The reported versions are the engine's, in the format 1.9.0 shipped.
    #[test]
    fn versions_are_the_engines() {
        assert_eq!(ENGINE_VERSION, vericto_engine::ENGINE_VERSION);
        assert_eq!(
            ruleset_version(),
            format!("standard@engine-{}", vericto_engine::ENGINE_VERSION)
        );
    }

    #[test]
    fn engine_version_matches_cargo_lock() {
        let lock = include_str!("../Cargo.lock");
        let block = lock
            .split("[[package]]")
            .find(|p| p.contains("name = \"vericto-engine\""))
            .expect("vericto-engine in Cargo.lock");
        assert!(
            block.contains(&format!("version = \"{ENGINE_VERSION}\"")),
            "ENGINE_VERSION {ENGINE_VERSION} differs from Cargo.lock:\n{block}"
        );
    }

    #[test]
    fn delete_without_where_blocks() {
        let r = one("DELETE FROM users", "postgres");
        assert_eq!(r.status, "BLOCKED");
        assert_eq!(r.rule_code.as_deref(), Some("VERICTO-001"));
        assert_eq!(r.severity.as_deref(), Some("critical"));
        assert_eq!(r.action.as_deref(), Some("block"));
    }

    /// The CI channel caps schema DDL at FLAG, as the backend does.
    #[test]
    fn drop_table_is_flagged_not_blocked() {
        let r = one("DROP TABLE users", "postgres");
        assert_eq!(r.status, "FLAGGED");
        assert_eq!(r.rule_code.as_deref(), Some("VERICTO-010"));
        assert_eq!(r.action.as_deref(), Some("flag"));
    }

    /// A capped DROP must not hide a blocking statement later in the file.
    /// Engine 4.1.3 reported VERICTO-010 (FLAGGED) for this input and 1.9.0
    /// corrected it locally; since engine 4.2.0 the engine's own decision is
    /// the strongest resolved action, and this pins the same outcome.
    #[test]
    fn a_capped_ddl_does_not_hide_a_block_in_the_same_file() {
        let r = one(
            "DROP TABLE a;\nUPDATE accounts SET balance = 0;",
            "postgres",
        );
        assert_eq!(r.status, "BLOCKED");
        // UPDATE without WHERE: VERICTO-030 and -042 both match; 030 sorts first.
        assert_eq!(r.rule_code.as_deref(), Some("VERICTO-030"));
        assert_eq!(r.action.as_deref(), Some("block"));
        // The same on one line, and the summary and exit code follow.
        let resp = check(
            &q("DROP TABLE a; UPDATE accounts SET balance = 0;"),
            "postgres",
        )
        .unwrap();
        assert_eq!(resp.queries[0].status, "BLOCKED");
        assert_eq!(resp.queries[0].rule_code.as_deref(), Some("VERICTO-030"));
        assert_eq!((resp.summary.blocked, resp.summary.flagged), (1, 0));
        assert_eq!(resp.exit_code, 1);
        let r = one("DROP TABLE a;\nINSERT INTO b SELECT * FROM c;", "postgres");
        assert_eq!(r.status, "BLOCKED");
        assert_eq!(r.rule_code.as_deref(), Some("VERICTO-040"));
        // Nothing stronger than the winner: unchanged.
        let r = one("DROP TABLE a;\nSELECT * FROM t;", "postgres");
        assert_eq!(r.status, "FLAGGED");
        assert_eq!(r.rule_code.as_deref(), Some("VERICTO-010"));
    }

    #[test]
    fn insert_without_columns_is_monitored() {
        let r = one("INSERT INTO t VALUES (1)", "postgres");
        assert_eq!(r.status, "MONITORED");
        assert_eq!(r.rule_code.as_deref(), Some("VERICTO-060"));
    }

    #[test]
    fn safe_query_is_allowed() {
        let r = one("SELECT id FROM users WHERE id = 1 LIMIT 1", "postgres");
        assert_eq!(r.status, "ALLOWED");
        assert_eq!(r.rule_code, None);
    }

    #[test]
    fn parse_error_is_reported_not_blocked() {
        let resp = check(&q("SELEC broken FROM"), "postgres").unwrap();
        assert_eq!(resp.queries[0].status, "PARSE_ERROR");
        assert_eq!(
            resp.queries[0].ast_node_path.as_deref(),
            Some("PARSE_ERROR")
        );
        assert_eq!(resp.summary.parse_errors, 1);
        assert_eq!(resp.summary.blocked, 0);
        assert_eq!(resp.exit_code, 0);
    }

    #[test]
    fn oversized_input_is_a_parse_error() {
        let big = format!(
            "SELECT 1; {}",
            "-- pad\n".repeat(engine::MAX_INPUT_BYTES / 7 + 1)
        );
        assert_eq!(one(&big, "postgres").status, "PARSE_ERROR");
    }

    #[test]
    fn dialects_are_honored() {
        // MySQL backticks parse only as MySQL.
        assert_eq!(one("DELETE FROM `users`", "mysql").status, "BLOCKED");
        assert_eq!(one("DELETE FROM `users`", "postgres").status, "PARSE_ERROR");
        assert_eq!(
            check(&q("SELECT 1"), "db2").err(),
            Some(OfflineError::Dialect("db2".into()))
        );
    }

    #[test]
    fn summary_and_mode_are_offline() {
        let resp = check(
            &[
                QueryInput {
                    line: 1,
                    sql: "DELETE FROM a".into(),
                },
                QueryInput {
                    line: 2,
                    sql: "SELECT id FROM a WHERE id = 1 LIMIT 1".into(),
                },
            ],
            "postgres",
        )
        .unwrap();
        assert_eq!(resp.summary.total, 2);
        assert_eq!(resp.summary.blocked, 1);
        assert_eq!(resp.summary.allowed, 1);
        assert_eq!(resp.exit_code, 1);
        assert_eq!(resp.summary.ruleset_version, "standard@engine-4.3.0");
        assert_eq!(
            resp.mode,
            RunMode::Offline {
                engine_version: ENGINE_VERSION,
                rules: STANDARD_RULE_COUNT
            }
        );
    }
}
