//! vetro — CLI to validate SQL against a Vetro workspace's rules before it runs.
//!
//! Thin client: sends SQL to `POST /api/v1/ci/check-key` and mirrors the
//! verdict as a process exit code, for pre-commit hooks and CI/CD gates.

mod api;
mod config;
mod output;

use std::io::{Read, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use api::{ApiError, CheckRequest, CheckResponse, QueryInput};
use config::Config;
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
    /// Store an API key (and optional API URL) in the config file.
    Login(LoginArgs),
    /// Remove stored credentials from the config file.
    Logout,
    /// Verify config, connectivity, auth, and plan entitlement.
    Doctor(DoctorArgs),
}

#[derive(Parser)]
struct LoginArgs {
    /// API key to store. If omitted, you'll be prompted (input is not echoed
    /// where the terminal supports it).
    #[arg(long, env = "VETRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// API base URL to store alongside the key.
    #[arg(long, env = "VETRO_API_URL")]
    api_url: Option<String>,

    /// Default SQL dialect to store (used by `check` when --dialect is omitted).
    #[arg(long)]
    dialect: Option<String>,
}

#[derive(Parser)]
struct DoctorArgs {
    /// Vetro API key (or set VETRO_API_KEY, or `vetro login`).
    #[arg(long, env = "VETRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Vetro API base URL (or set VETRO_API_URL, or `vetro login`).
    #[arg(long, env = "VETRO_API_URL")]
    api_url: Option<String>,
}

#[derive(Parser)]
struct CheckArgs {
    /// SQL files to check. Use '-' to read from stdin.
    #[arg(required = true)]
    files: Vec<String>,

    /// SQL dialect of the files. Falls back to the config's default_dialect,
    /// then "postgres".
    #[arg(long)]
    dialect: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Dry-run: report findings but always exit 0 (don't fail the build).
    #[arg(long)]
    monitor: bool,

    /// Which severity of finding causes a non-zero exit.
    #[arg(long, value_enum, default_value_t = FailOn::Block)]
    fail_on: FailOn,

    /// Vetro API key (or set VETRO_API_KEY, or `vetro login`).
    #[arg(long, env = "VETRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Vetro API base URL (or set VETRO_API_URL, or `vetro login`).
    #[arg(long, env = "VETRO_API_URL")]
    api_url: Option<String>,

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
        Command::Login(args) => run_login(args),
        Command::Logout => run_logout(),
        Command::Doctor(args) => run_doctor(args).await,
    }
}

/// Loads the config file, warning (but not failing) if it is malformed.
fn load_config() -> Config {
    match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: {e}");
            Config::default()
        }
    }
}

async fn run_check(args: CheckArgs) -> ExitCode {
    let file = load_config();
    let resolved = config::resolve(
        args.api_url.as_deref().unwrap_or(config::DEFAULT_API_URL),
        args.api_url.is_none(),
        args.api_key.as_deref(),
        &file,
    );
    let Some(api_key) = resolved.api_key else {
        eprintln!("error: no API key. Pass --api-key, set VETRO_API_KEY, or run `vetro login`.");
        return ExitCode::from(exit::AUTH);
    };
    let api_url = resolved.api_url;
    // dialect precedence: flag > config default_dialect > "postgres".
    let dialect = args
        .dialect
        .clone()
        .or_else(|| file.default_dialect.clone())
        .unwrap_or_else(|| "postgres".to_string());

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
        dialect,
        file_name,
        output_format: "json".to_string(),
    };

    let resp = match api::check(&api_url, &api_key, &req).await {
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

    // Nudge toward an upgrade as the monthly CLI allowance runs low (stderr, so
    // it never pollutes --format json on stdout). null = unmetered plan.
    if let Some(remaining) = resp.ci_checks_remaining {
        if remaining <= 50 {
            eprintln!(
                "note: {remaining} CLI checks left this month on your plan. Upgrade at https://vetro.dev/pricing for more."
            );
        }
    }

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

/// `vetro login` — persist an API key (and optional URL/dialect) to the config
/// file. The key comes from --api-key/env, or an interactive prompt.
fn run_login(args: LoginArgs) -> ExitCode {
    let api_key = match args.api_key {
        Some(k) => k,
        None => match prompt_secret("Vetro API key (vtro_...): ") {
            Ok(k) if !k.trim().is_empty() => k.trim().to_string(),
            Ok(_) => {
                eprintln!("error: no API key entered.");
                return ExitCode::from(exit::USAGE);
            }
            Err(e) => {
                eprintln!("error: could not read API key: {e}");
                return ExitCode::from(exit::USAGE);
            }
        },
    };

    // Merge onto any existing config so we don't clobber unrelated fields.
    let mut cfg = load_config();
    cfg.api_key = Some(api_key);
    if let Some(url) = args.api_url {
        cfg.api_url = Some(url);
    }
    if let Some(d) = args.dialect {
        cfg.default_dialect = Some(d);
    }

    match cfg.save() {
        Ok(path) => {
            println!("Saved credentials to {}", path.display());
            ExitCode::from(exit::OK)
        }
        Err(e) => {
            eprintln!("error: could not write config: {e}");
            ExitCode::from(exit::USAGE)
        }
    }
}

/// `vetro logout` — drop the stored API key (keeps url/dialect prefs).
fn run_logout() -> ExitCode {
    let Some(path) = config::config_path() else {
        eprintln!("error: could not resolve a config directory.");
        return ExitCode::from(exit::USAGE);
    };
    if !path.exists() {
        println!("No stored credentials.");
        return ExitCode::from(exit::OK);
    }
    let mut cfg = load_config();
    if cfg.api_key.is_none() {
        println!("No stored API key.");
        return ExitCode::from(exit::OK);
    }
    cfg.api_key = None;
    match cfg.save() {
        Ok(_) => {
            println!("Removed stored API key from {}", path.display());
            ExitCode::from(exit::OK)
        }
        Err(e) => {
            eprintln!("error: could not update config: {e}");
            ExitCode::from(exit::USAGE)
        }
    }
}

/// `vetro doctor` — validate config, connectivity, auth and plan entitlement so
/// problems surface here rather than as a cryptic failure mid-pipeline. It
/// probes by sending one trivial, always-safe query through the real endpoint.
async fn run_doctor(args: DoctorArgs) -> ExitCode {
    let file = load_config();
    let resolved = config::resolve(
        args.api_url.as_deref().unwrap_or(config::DEFAULT_API_URL),
        args.api_url.is_none(),
        args.api_key.as_deref(),
        &file,
    );

    let config_loc = config::config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(unavailable)".to_string());
    println!("config file: {config_loc}");
    println!("api url:     {}", resolved.api_url);
    println!("api key:     {}", resolved.key_source.label());

    let Some(api_key) = resolved.api_key else {
        println!("\n✖ no API key. Run `vetro login`, pass --api-key, or set VETRO_API_KEY.");
        return ExitCode::from(exit::AUTH);
    };

    // A trivial, always-ALLOWED probe: exercises connectivity + auth + quota
    // without tripping any rule or consuming a meaningful amount of allowance.
    let req = CheckRequest {
        queries: vec![QueryInput {
            line: 1,
            sql: "SELECT 1 LIMIT 1".to_string(),
        }],
        dialect: file
            .default_dialect
            .clone()
            .unwrap_or_else(|| "postgres".to_string()),
        file_name: None,
        output_format: "json".to_string(),
    };

    match api::check(&resolved.api_url, &api_key, &req).await {
        Ok(resp) => {
            println!("\n✓ reachable and authenticated");
            println!("  ruleset: {}", resp.summary.ruleset_version);
            match resp.ci_checks_remaining {
                Some(n) => println!("  CLI checks remaining this month: {n}"),
                None => println!("  CLI checks: unmetered (team/enterprise)"),
            }
            ExitCode::from(exit::OK)
        }
        Err(e @ ApiError::Auth(_)) => {
            println!("\n✖ auth/entitlement failed: {e}");
            println!("  Check the key's scope (ci_dryrun:execute) and your plan quota.");
            ExitCode::from(exit::AUTH)
        }
        Err(e) => {
            println!("\n✖ could not reach the backend: {e}");
            ExitCode::from(exit::BACKEND)
        }
    }
}

/// Prompts on the terminal and reads a line. Best-effort no-echo on Unix TTYs
/// (toggles the terminal's echo flag via stty); falls back to a visible read.
fn prompt_secret(prompt: &str) -> std::io::Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;

    #[cfg(unix)]
    let echo_disabled = std::process::Command::new("stty")
        .arg("-echo")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut line = String::new();
    let res = std::io::stdin().read_line(&mut line);

    #[cfg(unix)]
    if echo_disabled {
        let _ = std::process::Command::new("stty").arg("echo").status();
        println!(); // move past the (unechoed) newline the user typed
    }

    res?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
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
            ci_checks_remaining: None,
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
