//! vetro — CLI to validate SQL against a Vetro workspace's rules before it runs.
//!
//! Thin client: sends SQL to `POST /api/v1/ci/check-key` and mirrors the
//! verdict as a process exit code, for pre-commit hooks and CI/CD gates.

mod api;
mod output;

use std::io::Read;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use api::{ApiError, CheckRequest, CheckResponse, QueryInput};
use output::Format;

/// Exit codes (see DESIGN §8). Distinct codes let CI tell a real block from a
/// network/auth failure.
mod exit {
    pub const OK: u8 = 0;
    pub const FINDING: u8 = 1; // something at/above --fail-on
    pub const USAGE: u8 = 2; // bad args / unreadable file
    pub const AUTH: u8 = 3; // missing/invalid key, plan not entitled
    pub const BACKEND: u8 = 4; // unreachable / 5xx / bad response
}

#[derive(Parser)]
#[command(
    name = "vetro",
    version,
    about = "Validate SQL against your Vetro rules before it runs"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate SQL files (or stdin with '-') against the workspace ruleset.
    Check(CheckArgs),
}

#[derive(Parser)]
struct CheckArgs {
    /// SQL files to check. Use '-' to read from stdin.
    #[arg(required = true)]
    files: Vec<String>,

    /// SQL dialect of the files.
    #[arg(long, default_value = "postgres")]
    dialect: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Dry-run: report findings but always exit 0 (don't fail the build).
    #[arg(long)]
    monitor: bool,

    /// Which severity of finding causes a non-zero exit.
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,

    /// Vetro API key (or set VETRO_API_KEY).
    #[arg(long, env = "VETRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Vetro API base URL (or set VETRO_API_URL).
    #[arg(long, env = "VETRO_API_URL", default_value = "https://api.vetro.dev")]
    api_url: String,

    /// Only print the summary line.
    #[arg(short, long)]
    quiet: bool,
}

/// What counts as a failure for the exit code.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum FailOn {
    /// Only BLOCKED findings fail the run (default).
    Block,
    /// BLOCKED or FLAGGED fail the run.
    Flag,
    /// Any finding (BLOCKED / FLAGGED / MONITORED) fails the run.
    Any,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check(args) => run_check(args).await,
    }
}

async fn run_check(args: CheckArgs) -> ExitCode {
    let Some(api_key) = args.api_key.clone() else {
        eprintln!("error: no API key. Pass --api-key or set VETRO_API_KEY.");
        return ExitCode::from(exit::AUTH);
    };

    // Read each file (or stdin) as a whole; the engine parses multi-statement
    // SQL server-side, so we don't split here. One query item per file.
    let mut queries = Vec::new();
    for (i, path) in args.files.iter().enumerate() {
        let sql = match read_source(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: cannot read '{path}': {e}");
                return ExitCode::from(exit::USAGE);
            }
        };
        if sql.trim().is_empty() {
            continue;
        }
        queries.push(QueryInput {
            line: (i + 1) as u32,
            sql,
        });
    }
    if queries.is_empty() {
        eprintln!("error: no SQL to check (all inputs were empty).");
        return ExitCode::from(exit::USAGE);
    }

    let file_name = if args.files.len() == 1 && args.files[0] != "-" {
        Some(args.files[0].clone())
    } else {
        None
    };

    let req = CheckRequest {
        queries,
        dialect: args.dialect.clone(),
        file_name,
        output_format: "json".to_string(),
    };

    let resp = match api::check(&args.api_url, &api_key, &req).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return match e {
                ApiError::Auth(_) => ExitCode::from(exit::AUTH),
                ApiError::Backend { .. } | ApiError::Transport(_) => ExitCode::from(exit::BACKEND),
            };
        }
    };

    output::render(&resp, args.format, args.quiet);

    if args.monitor {
        // Dry-run never fails the build on findings (but §8: usage/auth/backend
        // codes still apply — those already returned above).
        return ExitCode::from(exit::OK);
    }
    if has_failure(&resp, args.fail_on) {
        ExitCode::from(exit::FINDING)
    } else {
        ExitCode::from(exit::OK)
    }
}

/// Reads a file path, or stdin when `path` is "-".
fn read_source(path: &str) -> std::io::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path)
    }
}

/// Whether the response contains a finding at/above the `--fail-on` threshold.
fn has_failure(resp: &CheckResponse, fail_on: FailOn) -> bool {
    resp.queries.iter().any(|q| match fail_on {
        FailOn::Block => q.status == "BLOCKED",
        FailOn::Flag => q.status == "BLOCKED" || q.status == "FLAGGED",
        FailOn::Any => matches!(q.status.as_str(), "BLOCKED" | "FLAGGED" | "MONITORED"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{QueryResult, Summary};

    fn resp_with(statuses: &[&str]) -> CheckResponse {
        CheckResponse {
            summary: Summary {
                total: statuses.len() as u32,
                blocked: statuses.iter().filter(|s| **s == "BLOCKED").count() as u32,
                allowed: 0,
                flagged: statuses.iter().filter(|s| **s == "FLAGGED").count() as u32,
                monitored: statuses.iter().filter(|s| **s == "MONITORED").count() as u32,
                parse_errors: 0,
                ruleset_version: "test".into(),
            },
            queries: statuses
                .iter()
                .enumerate()
                .map(|(i, s)| QueryResult {
                    line: i as u32,
                    sql_preview: String::new(),
                    status: (*s).into(),
                    action: None,
                    rule_code: None,
                    ast_node_path: None,
                    severity: None,
                    suggested_fix: None,
                })
                .collect(),
            exit_code: 0,
        }
    }

    #[test]
    fn fail_on_block_only_trips_on_blocked() {
        assert!(has_failure(&resp_with(&["BLOCKED"]), FailOn::Block));
        assert!(!has_failure(&resp_with(&["FLAGGED"]), FailOn::Block));
        assert!(!has_failure(
            &resp_with(&["ALLOWED", "MONITORED"]),
            FailOn::Block
        ));
    }

    #[test]
    fn fail_on_flag_trips_on_blocked_or_flagged() {
        assert!(has_failure(&resp_with(&["FLAGGED"]), FailOn::Flag));
        assert!(has_failure(&resp_with(&["BLOCKED"]), FailOn::Flag));
        assert!(!has_failure(&resp_with(&["MONITORED"]), FailOn::Flag));
    }

    #[test]
    fn fail_on_any_trips_on_monitored_too() {
        assert!(has_failure(&resp_with(&["MONITORED"]), FailOn::Any));
        assert!(!has_failure(&resp_with(&["ALLOWED"]), FailOn::Any));
    }
}
