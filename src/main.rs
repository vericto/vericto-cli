//! vetro — CLI to validate SQL against a Vetro workspace's rules before it runs.
//!
//! Thin client: sends SQL to `POST /api/v1/ci/check-key` and mirrors the
//! verdict as a process exit code, for pre-commit hooks and CI/CD gates.

mod api;
mod ci_env;
mod config;
mod output;
mod scaffold;

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

/// The minimum backend API version this CLI is known to be compatible with
/// (§9). `doctor` warns on a minor skew and fails on a major mismatch.
const MIN_BACKEND_API_VERSION: &str = "1.0.0";

/// Parses "MAJOR.MINOR.PATCH" (leading/trailing junk tolerated) into
/// `(major, minor)`. Returns None if it can't read at least a major.
fn parse_major_minor(v: &str) -> Option<(u32, u32)> {
    let core = v.trim().trim_start_matches('v');
    let mut it = core.split('.');
    let major = it.next()?.parse::<u32>().ok()?;
    let minor = it.next().and_then(|s| {
        // stop at any non-digit (e.g. "0-rc1")
        let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u32>().ok()
    });
    Some((major, minor.unwrap_or(0)))
}

/// Compatibility verdict between the backend's reported API version and the
/// minimum this CLI requires.
enum Compat {
    Ok,
    /// Same major, backend minor < our required minor — usable, warn.
    MinorSkew,
    /// Major differs — hard incompatibility.
    MajorMismatch,
    /// Couldn't parse one of the versions — don't block on it.
    Unknown,
}

/// Compares the backend `api_version` against `MIN_BACKEND_API_VERSION`.
fn backend_compat(api_version: &str) -> Compat {
    let (Some((b_major, b_minor)), Some((min_major, min_minor))) = (
        parse_major_minor(api_version),
        parse_major_minor(MIN_BACKEND_API_VERSION),
    ) else {
        return Compat::Unknown;
    };
    if b_major != min_major {
        Compat::MajorMismatch
    } else if b_minor < min_minor {
        Compat::MinorSkew
    } else {
        Compat::Ok
    }
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
    /// Scaffold CI workflow + pre-commit hook (§10).
    Init(InitArgs),
}

#[derive(Parser)]
struct InitArgs {
    /// Which CI provider to scaffold for. Auto-detected from the git remote when
    /// omitted.
    #[arg(long, value_enum)]
    target: Option<InitTarget>,

    /// Also write a git pre-commit hook that checks staged SQL.
    #[arg(long)]
    hook: bool,

    /// SQL dialect to bake into the generated templates.
    #[arg(long, default_value = "postgres")]
    dialect: String,

    /// Overwrite existing files instead of skipping them.
    #[arg(long)]
    force: bool,
}

/// CI provider choices for `vetro init --target`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum InitTarget {
    Github,
    Gitlab,
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

    /// Per-request timeout in seconds.
    #[arg(long, env = "VETRO_TIMEOUT", value_name = "SECS")]
    timeout: Option<u64>,
}

#[derive(Parser)]
struct CheckArgs {
    /// SQL files to check. Use '-' to read from stdin. Optional when --changed
    /// or --since selects files from the git diff.
    files: Vec<String>,

    /// Check only *.sql files changed vs the CI merge base (auto-detected), or
    /// vs --since when given.
    #[arg(long)]
    changed: bool,

    /// Explicit base ref for changed-file selection (implies --changed),
    /// e.g. `origin/main`.
    #[arg(long, value_name = "REF")]
    since: Option<String>,

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

    /// Write the report to a file instead of stdout (for CI artifacts).
    #[arg(long, value_name = "FILE")]
    output: Option<std::path::PathBuf>,

    /// Per-request timeout in seconds.
    #[arg(long, env = "VETRO_TIMEOUT", value_name = "SECS")]
    timeout: Option<u64>,

    /// Max in-flight chunk requests when the input exceeds 500 queries
    /// (capped at 8).
    #[arg(long, env = "VETRO_CONCURRENCY", value_name = "N")]
    concurrency: Option<usize>,

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
        Command::Init(args) => run_init(args),
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

    // Resolve the file list: explicit args, or the git diff when --changed/--since.
    let use_changed = args.changed || args.since.is_some();
    let files: Vec<String> = if use_changed {
        if !args.files.is_empty() {
            eprintln!("error: pass files OR --changed/--since, not both.");
            return ExitCode::from(exit::USAGE);
        }
        let provider = ci_env::Provider::detect();
        let base = match args
            .since
            .clone()
            .or_else(|| ci_env::detected_base_ref(provider))
        {
            Some(b) => b,
            None => {
                eprintln!(
                    "error: could not determine a base ref for --changed. Pass --since <ref> \
                     (e.g. --since origin/main)."
                );
                return ExitCode::from(exit::USAGE);
            }
        };
        match ci_env::changed_sql_files(&base) {
            Ok(list) if list.is_empty() => {
                // An empty diff is a pass, never an error (§10).
                println!("No changed .sql files vs {base} — nothing to check.");
                return ExitCode::from(exit::OK);
            }
            Ok(list) => list,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(exit::USAGE);
            }
        }
    } else {
        if args.files.is_empty() {
            eprintln!("error: no files given. Pass SQL files, '-' for stdin, or --changed.");
            return ExitCode::from(exit::USAGE);
        }
        args.files.clone()
    };

    // Read each file (or stdin) as a whole; the engine parses multi-statement
    // SQL server-side, so we don't split here. One query item per file.
    let mut queries = Vec::new();
    for (i, path) in files.iter().enumerate() {
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

    let file_name = if files.len() == 1 && files[0] != "-" {
        Some(files[0].clone())
    } else {
        None
    };

    let timeout = std::time::Duration::from_secs(args.timeout.unwrap_or(api::DEFAULT_TIMEOUT_SECS));
    // Concurrency for chunked runs: default 4, capped at 8 to stay a well-behaved
    // client against the shared CI quota (§5/§12.1).
    let concurrency = args.concurrency.unwrap_or(4).clamp(1, 8);
    let resp = match api::check_all(
        api::CheckParams {
            api_url: &api_url,
            api_key: &api_key,
            dialect: &dialect,
            file_name,
            provenance: build_provenance(),
            timeout,
            concurrency,
        },
        queries,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return match e {
                ApiError::Auth(_) => ExitCode::from(exit::AUTH),
                ApiError::Backend { .. } | ApiError::Transport(_) => ExitCode::from(exit::BACKEND),
            };
        }
    };

    if let Err(e) = output::render(
        &resp,
        args.format,
        &files,
        args.quiet,
        args.output.as_deref(),
    ) {
        eprintln!("error: could not write output: {e}");
        return ExitCode::from(exit::USAGE);
    }

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

/// `vetro init` — scaffold a CI workflow (GitHub or GitLab) and, with --hook, a
/// git pre-commit hook. Existing files are skipped unless --force. Returns
/// usage (2) if the target can't be determined or a write fails.
fn run_init(args: InitArgs) -> ExitCode {
    use scaffold::{CiTarget, Written};

    let target = match args.target {
        Some(InitTarget::Github) => CiTarget::GitHub,
        Some(InitTarget::Gitlab) => CiTarget::GitLab,
        None => scaffold::detect_target(),
    };

    let mut plans: Vec<(std::path::PathBuf, String, bool)> = Vec::new();
    match target {
        CiTarget::GitHub => plans.push((
            std::path::PathBuf::from(".github/workflows/vetro.yml"),
            scaffold::github_workflow(&args.dialect),
            false,
        )),
        CiTarget::GitLab => plans.push((
            // Never clobber an existing .gitlab-ci.yml — write an include the
            // user wires in (printed below).
            std::path::PathBuf::from(".vetro/gitlab-ci.yml"),
            scaffold::gitlab_job(&args.dialect),
            false,
        )),
        CiTarget::Unknown => {
            eprintln!(
                "error: could not detect a CI provider (no github.com/gitlab remote, \
                 no .github/ or .gitlab-ci.yml). Pass --target github|gitlab."
            );
            return ExitCode::from(exit::USAGE);
        }
    }

    if args.hook {
        plans.push((
            std::path::PathBuf::from(".git/hooks/pre-commit"),
            scaffold::precommit_hook(&args.dialect),
            true,
        ));
    }

    let mut any_created = false;
    for (path, body, executable) in plans {
        match scaffold::write_file(&path, &body, args.force, executable) {
            Ok(Written::Created(p)) => {
                println!("created {}", p.display());
                any_created = true;
            }
            Ok(Written::Skipped(p)) => {
                println!("exists, skipped {} (use --force to overwrite)", p.display());
            }
            Err(e) => {
                eprintln!("error: could not write {}: {e}", path.display());
                return ExitCode::from(exit::USAGE);
            }
        }
    }

    // Provider-specific next steps.
    match target {
        CiTarget::GitHub => {
            println!(
                "\nNext: add VETRO_API_KEY as a repository secret \
                 (Settings → Secrets and variables → Actions)."
            );
        }
        CiTarget::GitLab => {
            println!(
                "\nNext:\n  1. Add VETRO_API_KEY as a masked CI/CD variable \
                 (Settings → CI/CD → Variables).\n  \
                 2. Include the job from your .gitlab-ci.yml:\n       \
                 include:\n         - local: .vetro/gitlab-ci.yml"
            );
        }
        CiTarget::Unknown => {}
    }
    if args.hook {
        println!("\nThe pre-commit hook runs `vetro check` on staged SQL. Bypass with `git commit --no-verify`.");
    }
    let _ = any_created;
    ExitCode::from(exit::OK)
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

    let timeout = std::time::Duration::from_secs(args.timeout.unwrap_or(api::DEFAULT_TIMEOUT_SECS));

    // Backend compatibility (§9): unauthenticated, so it doubles as the first
    // reachability check. A major mismatch is fatal (the CLI may mis-parse
    // responses); a minor skew only warns; an older backend without /version is
    // treated as unknown and not blocked.
    println!("\ncli version: {}", env!("CARGO_PKG_VERSION"));
    match api::version(&resolved.api_url, timeout).await {
        Ok(info) => match info.api_version.as_deref() {
            Some(api_version) => {
                print!("backend api: {api_version}");
                if let Some(min) = &info.min_cli_version {
                    print!(" (min cli {min})");
                }
                println!();
                match backend_compat(api_version) {
                    Compat::Ok => {}
                    Compat::MinorSkew => println!(
                        "  ⚠ backend api {api_version} is older than this CLI expects \
                         (>= {MIN_BACKEND_API_VERSION}); some features may be unavailable."
                    ),
                    Compat::MajorMismatch => {
                        println!(
                            "\n✖ incompatible backend: api {api_version} vs CLI requires \
                             {MIN_BACKEND_API_VERSION} (major mismatch). Upgrade the CLI or backend."
                        );
                        return ExitCode::from(exit::BACKEND);
                    }
                    Compat::Unknown => {}
                }
            }
            None => println!("backend api: (version endpoint returned no api_version)"),
        },
        // Older backend without /version, or a transient error — don't block;
        // the auth probe below is the real connectivity/auth gate.
        Err(_) => println!("backend api: (version endpoint unavailable — older backend?)"),
    }

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
        provenance: None,
    };

    match api::check(&resolved.api_url, &api_key, &req, timeout).await {
        Ok(resp) => {
            println!("\n✓ reachable and authenticated");
            println!("  ruleset: {}", resp.summary.ruleset_version);
            match resp.ci_checks_remaining {
                Some(n) => println!("  CLI checks remaining this month: {n}"),
                None => println!("  CLI checks: unmetered (team/enterprise)"),
            }
            // §6.2: report the effective query mode so the dev isn't guessing.
            println!(
                "  query mode: {}",
                resp.telemetry_query_mode.as_deref().unwrap_or("raw")
            );
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

/// Collects CI provenance (§2.1) for the request. Returns `None` when nothing
/// useful was detected (no git, no CI) so we don't send an all-empty object —
/// `ci_provider` alone ("local") isn't worth attaching.
fn build_provenance() -> Option<api::Provenance> {
    let p = ci_env::collect_provenance();
    let has_signal =
        p.git_sha.is_some() || p.git_ref.is_some() || p.ci_run_url.is_some() || p.actor.is_some();
    if !has_signal {
        return None;
    }
    Some(api::Provenance {
        git_sha: p.git_sha,
        git_ref: p.git_ref,
        ci_provider: p.ci_provider.to_string(),
        ci_run_url: p.ci_run_url,
        actor: p.actor,
    })
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

    #[test]
    fn parse_major_minor_variants() {
        assert_eq!(parse_major_minor("1.2.3"), Some((1, 2)));
        assert_eq!(parse_major_minor("v2.0.0"), Some((2, 0)));
        assert_eq!(parse_major_minor("1"), Some((1, 0)));
        assert_eq!(parse_major_minor("3.4-rc1"), Some((3, 4)));
        assert_eq!(parse_major_minor("nope"), None);
    }

    #[test]
    fn backend_compat_matrix() {
        // MIN_BACKEND_API_VERSION is "1.0.0".
        assert!(matches!(backend_compat("1.0.0"), Compat::Ok));
        assert!(matches!(backend_compat("1.3.0"), Compat::Ok)); // newer minor is fine
        assert!(matches!(backend_compat("2.0.0"), Compat::MajorMismatch));
        assert!(matches!(backend_compat("0.9.0"), Compat::MajorMismatch));
        assert!(matches!(backend_compat("garbage"), Compat::Unknown));
    }

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
            telemetry_query_mode: None,
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
