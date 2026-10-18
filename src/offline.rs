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
//! Engine 4.1.3 workarounds, removed with engine 4.2.0: 4.1.3 exports no
//! standard ruleset and no version constant, and its winner is severity-first.
//! So this module carries its own copy of the standard-rules table
//! (`engine::STANDARD_RULES`), its own `ENGINE_VERSION`, and a local
//! strongest-action correction (`engine::strongest_action_wins`). Engine 4.2.0
//! fixes the winner and exports `standard_rules()` plus version constants; the
//! release after 1.9.0 moves to it and drops all three. Until then the tests
//! below keep the table equal to the engine README and the version equal to
//! Cargo.lock.
//!
//! Windows: the engine is not built for Windows in this release (see
//! Cargo.toml), so `AVAILABLE` is false there and `--offline` exits 2. The
//! `vericto_windows_offline` cfg, set only by the windows-offline CI job,
//! turns it on to find out whether pg_query builds there.

use crate::api::{CheckResponse, QueryInput, RunMode, Summary};

/// Whether this build can evaluate offline: the `offline` feature is on and
/// the target has the engine (every target but Windows, see Cargo.toml).
pub const AVAILABLE: bool = cfg!(all(
    feature = "offline",
    any(not(windows), vericto_windows_offline)
));

/// Version of the embedded `vericto-engine`. Engine 4.1.3 exports no version
/// constant, so it is written here and a test keeps it equal to Cargo.lock.
/// With engine 4.2.0 this becomes the engine's own constant.
pub const ENGINE_VERSION: &str = "4.1.3";

/// Number of standard rules evaluated offline (the engine catalogue).
pub const STANDARD_RULE_COUNT: usize = 42;

/// The `ruleset_version` an offline result reports: the standard set is a
/// function of the engine version alone, so the version names both.
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
    /// This build has no engine (feature off, or Windows).
    Unavailable,
    /// The dialect is not one the engine knows.
    #[cfg_attr(
        not(all(feature = "offline", any(not(windows), vericto_windows_offline))),
        allow(dead_code)
    )]
    Dialect(String),
}

impl std::fmt::Display for OfflineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OfflineError::Unavailable if cfg!(all(windows, not(vericto_windows_offline))) => {
                write!(
                    f,
                    "offline mode is not available on Windows yet: vericto {} for Windows is \
                     online-only. Use online mode (`vericto login` or VERICTO_API_KEY), or run \
                     --offline on macOS, Linux or WSL.",
                    env!("CARGO_PKG_VERSION")
                )
            }
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

#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
mod engine {
    use super::OfflineError;
    use crate::api::{QueryInput, QueryResult};
    use vericto_engine::parser::{parser_for, Dialect};
    use vericto_engine::{
        Decision, EnforcementAction, EnforcementPolicy, EvaluationOutcome, Rule, RuleEngine,
        RuleType, Severity,
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

    /// (code, severity, default action): vericto-proxy's built-in ruleset
    /// (`evaluator::default_ruleset`, the R13 table), which is the engine's
    /// catalogue. Kept equal to the engine README by `matches_engine_catalogue`.
    ///
    /// A local copy only because engine 4.1.3 exports no ruleset. The next
    /// release moves to engine 4.2.0's `standard_rules()` and deletes this
    /// table (keep the catalogue test until then).
    pub(super) const STANDARD_RULES: &[(&str, Severity, EnforcementAction)] = &[
        ("VERICTO-001", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-003", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-010", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-011", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-012", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-030", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-042", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-090", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-080", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-081", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-086", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-091", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-092", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-093", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-100", Severity::Critical, EnforcementAction::Block),
        ("VERICTO-002", Severity::High, EnforcementAction::Block),
        ("VERICTO-013", Severity::High, EnforcementAction::Block),
        ("VERICTO-015", Severity::High, EnforcementAction::Block),
        ("VERICTO-016", Severity::High, EnforcementAction::Block),
        ("VERICTO-017", Severity::High, EnforcementAction::Block),
        ("VERICTO-018", Severity::High, EnforcementAction::Block),
        ("VERICTO-019", Severity::High, EnforcementAction::Block),
        ("VERICTO-031", Severity::High, EnforcementAction::Block),
        ("VERICTO-033", Severity::High, EnforcementAction::Block),
        ("VERICTO-040", Severity::High, EnforcementAction::Block),
        ("VERICTO-070", Severity::High, EnforcementAction::Block),
        ("VERICTO-082", Severity::High, EnforcementAction::Block),
        ("VERICTO-083", Severity::High, EnforcementAction::Block),
        ("VERICTO-084", Severity::High, EnforcementAction::Block),
        // Engine-driven: acts only on sensitive-column tags and agent
        // allowlists, which offline mode never has; listed so the set is whole.
        ("VERICTO-085", Severity::High, EnforcementAction::Block),
        ("VERICTO-087", Severity::High, EnforcementAction::Block),
        ("VERICTO-094", Severity::High, EnforcementAction::Block),
        ("VERICTO-095", Severity::High, EnforcementAction::Block),
        ("VERICTO-096", Severity::High, EnforcementAction::Block),
        ("VERICTO-097", Severity::High, EnforcementAction::Block),
        ("VERICTO-098", Severity::High, EnforcementAction::Block),
        ("VERICTO-099", Severity::High, EnforcementAction::Block),
        ("VERICTO-101", Severity::High, EnforcementAction::Block),
        ("VERICTO-050", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-051", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-061", Severity::Medium, EnforcementAction::Flag),
        ("VERICTO-060", Severity::Low, EnforcementAction::Monitor),
    ];

    pub(super) fn standard_ruleset() -> Vec<Rule> {
        STANDARD_RULES
            .iter()
            .map(|(code, severity, default_action)| Rule {
                rule_id: code.to_string(),
                code: code.to_string(),
                severity: *severity,
                default_action: *default_action,
                rule_type: RuleType::Standard,
                ast_condition_yaml: None,
            })
            .collect()
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

    /// The engine ranks violations by severity, then rule code, and takes the
    /// decision from that winner alone, with the CI cap already applied to its
    /// action. Offline evaluates a whole file at once, so a capped DROP TABLE
    /// (Critical, FLAG) outranks a WHERE-less UPDATE later in the same file
    /// (Critical, BLOCK) and the file would pass. Online per-statement mode
    /// never meets this (each statement is evaluated alone). Report the
    /// violation with the strongest resolved action instead; the engine's
    /// order breaks ties, so a single-statement outcome never changes.
    ///
    /// Every output format and the exit code read the status this produces,
    /// so they all agree. A local workaround for engine 4.1.3: engine 4.2.0
    /// picks an action-aware winner itself, and the next release drops this
    /// function (keep its tests, which then guard the engine's behavior).
    fn strongest_action_wins(o: &mut EvaluationOutcome) {
        let Some(top) = o
            .violations
            .iter()
            .enumerate()
            .max_by_key(|(i, v)| (v.action, std::cmp::Reverse(*i)))
            .map(|(_, v)| v.clone())
        else {
            return;
        };
        if o.action.is_some_and(|a| a >= top.action) {
            return;
        }
        o.decision = match top.action {
            EnforcementAction::Block => Decision::Block,
            EnforcementAction::Flag => Decision::Flag,
            EnforcementAction::Monitor => Decision::Allow,
        };
        o.action = Some(top.action);
        o.severity = Some(top.severity);
        o.rule_id = Some(top.rule_id);
        o.rule_code = Some(top.rule_code);
        o.ast_node_path = Some(top.ast_node_path);
        o.estimated_rows_affected = top.estimated_rows_affected;
        o.suggested_safe_query = top.suggested_safe_query;
    }

    pub(super) fn evaluate_all(
        queries: &[QueryInput],
        dialect: &str,
    ) -> Result<Vec<QueryResult>, OfflineError> {
        let dialect =
            Dialect::parse_dialect(dialect).map_err(|_| OfflineError::Dialect(dialect.into()))?;
        let rules = standard_ruleset();
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
                let mut o = RuleEngine::evaluate(&parsed, &rules, &policy);
                strongest_action_wins(&mut o);
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

#[cfg(not(all(feature = "offline", any(not(windows), vericto_windows_offline))))]
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

#[cfg(all(test, feature = "offline", any(not(windows), vericto_windows_offline)))]
mod tests {
    use super::*;
    use crate::api::QueryResult;
    use std::collections::{BTreeMap, BTreeSet};
    use vericto_engine::Severity;

    fn q(sql: &str) -> Vec<QueryInput> {
        vec![QueryInput {
            line: 1,
            sql: sql.to_string(),
        }]
    }

    fn one(sql: &str, dialect: &str) -> QueryResult {
        check(&q(sql), dialect).unwrap().queries.remove(0)
    }

    #[test]
    fn standard_set_is_42_unique_rules() {
        let codes: BTreeSet<&str> = engine::STANDARD_RULES.iter().map(|r| r.0).collect();
        assert_eq!(engine::STANDARD_RULES.len(), STANDARD_RULE_COUNT);
        assert_eq!(codes.len(), STANDARD_RULE_COUNT, "no duplicate codes");
        assert_eq!(engine::standard_ruleset().len(), STANDARD_RULE_COUNT);
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

    /// The standard set is the engine catalogue: same codes and severities as
    /// the `VERICTO-NNN` rows of the engine README (which the engine's own
    /// `rule_catalogue_sync` test keeps equal to its evaluator). Fails on an
    /// engine bump that adds, drops or re-grades a rule until this table follows.
    #[test]
    fn matches_engine_catalogue() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let out = std::process::Command::new(cargo)
            .args(["metadata", "--format-version", "1", "--locked"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("run cargo metadata");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let manifest = meta["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "vericto-engine")
            .and_then(|p| p["manifest_path"].as_str())
            .expect("vericto-engine in the graph")
            .to_string();
        let readme_path = std::path::Path::new(&manifest).with_file_name("README.md");
        let readme = std::fs::read_to_string(readme_path).expect("engine README");
        let mut severity = None;
        let mut catalogue = BTreeMap::new();
        for line in readme.lines() {
            if let Some(h) = line.strip_prefix("### ") {
                severity = match h.trim() {
                    "Critical" => Some(Severity::Critical),
                    "High" => Some(Severity::High),
                    "Medium" => Some(Severity::Medium),
                    "Low" => Some(Severity::Low),
                    "Informational" => Some(Severity::Informational),
                    _ => None,
                };
                continue;
            }
            let Some(row) = line.trim_start().strip_prefix("| VERICTO-") else {
                continue;
            };
            let digits: String = row.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() || !row[digits.len()..].trim_start().starts_with('|') {
                continue;
            }
            catalogue.insert(
                format!("VERICTO-{digits}"),
                severity.expect("severity section"),
            );
        }
        let ours: BTreeMap<String, Severity> = engine::STANDARD_RULES
            .iter()
            .map(|(c, s, _)| (c.to_string(), *s))
            .collect();
        assert_eq!(
            ours, catalogue,
            "standard set differs from the engine catalogue"
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

    /// A capped DROP must not hide a blocking statement later in the file:
    /// the engine alone reports VERICTO-010 (FLAGGED) for this input.
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
        assert_eq!(resp.summary.ruleset_version, "standard@engine-4.1.3");
        assert_eq!(
            resp.mode,
            RunMode::Offline {
                engine_version: ENGINE_VERSION,
                rules: STANDARD_RULE_COUNT
            }
        );
    }
}
