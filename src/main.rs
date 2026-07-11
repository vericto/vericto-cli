//! vetro — CLI to validate SQL against a Vetro workspace's rules before it runs.
//!
//! Thin client: sends SQL to `POST /api/v1/ci/check-key` and mirrors the
//! verdict as a process exit code, for pre-commit hooks and CI/CD gates.

mod api;
mod baseline;
mod ci_env;
mod config;
mod oidc;
mod output;
mod pubkeys;
mod receipt;
mod sanitize;
mod scaffold;

use std::io::{Read, Write};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use api::{ApiError, CheckResponse, QueryInput};
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
    /// Record current findings to a baseline file (§10).
    Baseline(BaselineArgs),
    /// Verify a signed run receipt offline (§7.1) — no network, no account.
    VerifyReceipt(VerifyReceiptArgs),
    /// Print the CLI version (same as `--version`).
    Version,
    /// Print a shell completion script to stdout (bash|zsh|fish|powershell|elvish).
    Completions(CompletionsArgs),
}

#[derive(Parser)]
struct CompletionsArgs {
    /// The shell to generate completions for. Pipe the output into your shell's
    /// completion dir, e.g. `vetro completions bash > /etc/bash_completion.d/vetro`.
    shell: Shell,
}

#[derive(Parser)]
struct VerifyReceiptArgs {
    /// Path to the receipt file written by `vetro check --receipt` (a single
    /// receipt object, or a JSON array of per-chunk receipts).
    file: std::path::PathBuf,

    /// Public key PEM to verify against (or a path to a `.pem` file). Overrides
    /// the bundled key. Fetch it from `GET /api/v1/meta/export-signing-key`.
    #[arg(long, value_name = "PEM_OR_PATH", env = "VETRO_RECEIPT_PUBLIC_KEY")]
    public_key: Option<String>,

    /// Print the verified payload (summary + provenance) on success.
    #[arg(long)]
    show: bool,
}

#[derive(Parser)]
struct BaselineArgs {
    /// SQL files to baseline. Use '-' for stdin. Supports --changed/--since.
    files: Vec<String>,

    /// Baseline only files changed vs the CI merge base (§10).
    #[arg(long)]
    changed: bool,

    /// Explicit base ref for changed-file selection.
    #[arg(long, value_name = "REF")]
    since: Option<String>,

    /// SQL dialect. Falls back to config default, then "postgres".
    #[arg(long)]
    dialect: Option<String>,

    /// Where to write the baseline.
    #[arg(long, default_value = ".vetro-baseline.json")]
    out: std::path::PathBuf,

    /// Vetro API key (or set VETRO_API_KEY, or `vetro login`).
    #[arg(long, env = "VETRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Vetro API base URL (or set VETRO_API_URL, or `vetro login`).
    #[arg(long, env = "VETRO_API_URL")]
    api_url: Option<String>,

    /// Authenticate via CI workload-identity (OIDC) instead of a static key
    /// (§6.1). Auto-enabled when no static key is present and a token is
    /// available.
    #[arg(long)]
    oidc: bool,

    /// Workspace ID to authenticate against for OIDC.
    #[arg(long, value_name = "ID", env = "VETRO_WORKSPACE_ID")]
    workspace: Option<String>,

    /// OIDC audience to request in the ID token.
    #[arg(long, value_name = "AUD")]
    audience: Option<String>,

    /// Env var holding a pre-minted OIDC ID token (GitLab-style).
    #[arg(long, value_name = "VAR")]
    oidc_token_env: Option<String>,

    /// Per-request timeout in seconds.
    #[arg(long, env = "VETRO_TIMEOUT", value_name = "SECS")]
    timeout: Option<u64>,

    /// Extra CA bundle (PEM) to trust (§6.4). Falls back to VETRO_CA_BUNDLE,
    /// then SSL_CERT_FILE.
    #[arg(long, env = "VETRO_CA_BUNDLE", value_name = "PATH")]
    ca_bundle: Option<std::path::PathBuf>,
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

    /// Scaffold OIDC / workload-identity auth (§6.1) instead of a static
    /// VETRO_API_KEY secret. Requires --workspace.
    #[arg(long)]
    oidc: bool,

    /// Workspace ID to bake into OIDC templates (required with --oidc).
    #[arg(long, value_name = "ID")]
    workspace: Option<String>,

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

    /// Configure OIDC / workload-identity login instead of storing a static key
    /// (§6.1). Stores the workspace_id (and audience) so CI runs authenticate
    /// with a short-lived, per-run token — no long-lived key on disk. When run
    /// inside CI with an OIDC token available, also verifies the exchange works.
    #[arg(long)]
    oidc: bool,

    /// Workspace ID to authenticate against (required with --oidc).
    #[arg(long, value_name = "ID")]
    workspace: Option<String>,

    /// OIDC audience to request (defaults to "vetro").
    #[arg(long, value_name = "AUD")]
    audience: Option<String>,
}

#[derive(Parser)]
struct DoctorArgs {
    /// Vetro API key (or set VETRO_API_KEY, or `vetro login`).
    #[arg(long, env = "VETRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Vetro API base URL (or set VETRO_API_URL, or `vetro login`).
    #[arg(long, env = "VETRO_API_URL")]
    api_url: Option<String>,

    /// Test OIDC / workload-identity auth (§6.1) instead of a static key.
    /// Auto-enabled when no static key is present and a token is available.
    #[arg(long)]
    oidc: bool,

    /// Workspace ID to authenticate against for OIDC.
    #[arg(long, value_name = "ID", env = "VETRO_WORKSPACE_ID")]
    workspace: Option<String>,

    /// OIDC audience to request in the ID token.
    #[arg(long, value_name = "AUD")]
    audience: Option<String>,

    /// Env var holding a pre-minted OIDC ID token (GitLab-style).
    #[arg(long, value_name = "VAR")]
    oidc_token_env: Option<String>,

    /// Per-request timeout in seconds.
    #[arg(long, env = "VETRO_TIMEOUT", value_name = "SECS")]
    timeout: Option<u64>,

    /// Extra CA bundle (PEM) to trust (§6.4). Falls back to VETRO_CA_BUNDLE,
    /// then SSL_CERT_FILE.
    #[arg(long, env = "VETRO_CA_BUNDLE", value_name = "PATH")]
    ca_bundle: Option<std::path::PathBuf>,
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

    /// Read the list of SQL files to check from stdin, one path per line (for
    /// pipelines that already compute the set, e.g. `git diff --name-only ... |
    /// vetro check --stdin-file-list`). Mutually exclusive with files/--changed.
    #[arg(long)]
    stdin_file_list: bool,

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

    /// Which severity of finding causes a non-zero exit. Falls back to
    /// .vetro.toml's fail_on, then "block".
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    /// Vetro API key (or set VETRO_API_KEY, or `vetro login`).
    #[arg(long, env = "VETRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,

    /// Vetro API base URL (or set VETRO_API_URL, or `vetro login`).
    #[arg(long, env = "VETRO_API_URL")]
    api_url: Option<String>,

    /// Authenticate via CI workload-identity (OIDC) instead of a static key
    /// (§6.1). Auto-enabled when no static key is present and a CI OIDC token is
    /// available; pass this to require it (and error if unavailable).
    #[arg(long)]
    oidc: bool,

    /// Workspace ID to authenticate against for OIDC (falls back to .vetro.toml /
    /// config `workspace_id`). Required for OIDC.
    #[arg(long, value_name = "ID", env = "VETRO_WORKSPACE_ID")]
    workspace: Option<String>,

    /// OIDC audience to request in the ID token (must match the workspace trust
    /// policy). Falls back to config, then "vetro".
    #[arg(long, value_name = "AUD")]
    audience: Option<String>,

    /// Env var holding a pre-minted OIDC ID token (GitLab-style). Falls back to
    /// .vetro.toml `oidc_token_env`, then "VETRO_ID_TOKEN".
    #[arg(long, value_name = "VAR")]
    oidc_token_env: Option<String>,

    /// Write the report to a file instead of stdout (for CI artifacts).
    #[arg(long, value_name = "FILE")]
    output: Option<std::path::PathBuf>,

    /// Request a signed run receipt (§7.1) and write it to this path — a
    /// self-contained, offline-verifiable record (see `vetro verify-receipt`).
    /// A chunked run writes a JSON array of per-chunk receipts.
    #[arg(long, value_name = "FILE")]
    receipt: Option<std::path::PathBuf>,

    /// Ignore findings recorded in this baseline file; only new findings can
    /// fail the run (§10).
    #[arg(long, value_name = "FILE")]
    baseline: Option<std::path::PathBuf>,

    /// Per-request timeout in seconds.
    #[arg(long, env = "VETRO_TIMEOUT", value_name = "SECS")]
    timeout: Option<u64>,

    /// Max in-flight chunk requests when the input exceeds 500 queries
    /// (capped at 8).
    #[arg(long, env = "VETRO_CONCURRENCY", value_name = "N")]
    concurrency: Option<usize>,

    /// Extra CA bundle (PEM) to trust, for corporate TLS-inspecting proxies
    /// (§6.4). Falls back to VETRO_CA_BUNDLE, then SSL_CERT_FILE.
    #[arg(long, env = "VETRO_CA_BUNDLE", value_name = "PATH")]
    ca_bundle: Option<std::path::PathBuf>,

    /// Break-glass (§6.5): if the backend is unreachable from the first request,
    /// exit 0 instead of 4. Requires a reason. Never bypasses a real finding or
    /// a partially-completed run.
    #[arg(long, env = "VETRO_ALLOW_DEGRADED", value_name = "REASON")]
    allow_degraded: Option<String>,

    /// Only print the summary line.
    #[arg(short, long)]
    quiet: bool,

    /// Disable ANSI color in text output. Color is also auto-disabled when
    /// stdout isn't a TTY or when `NO_COLOR` is set (anstream default).
    #[arg(long)]
    no_color: bool,
}

/// What counts as a failure for the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum FailOn {
    /// Only BLOCKED findings fail the run (default).
    Block,
    /// BLOCKED or FLAGGED fail the run.
    Flag,
    /// Any finding (BLOCKED / FLAGGED / MONITORED) fails the run.
    Any,
}

/// Builds the transport (timeout + CA trust). The CA bundle comes from the flag
/// (which already folds in `VETRO_CA_BUNDLE` via clap), else `SSL_CERT_FILE` —
/// the convention curl/Go and most CLIs already honor (§6.4).
fn resolve_transport(
    timeout_secs: Option<u64>,
    ca_bundle: Option<std::path::PathBuf>,
) -> api::Transport {
    let ca = ca_bundle.or_else(|| std::env::var_os("SSL_CERT_FILE").map(std::path::PathBuf::from));
    api::Transport {
        timeout: std::time::Duration::from_secs(timeout_secs.unwrap_or(api::DEFAULT_TIMEOUT_SECS)),
        ca_bundle: ca,
    }
}

/// The OIDC inputs a command collected from its flags — resolved against config
/// by `resolve_auth`. Kept separate from the parsed args so `check`, `baseline`
/// and `doctor` share one resolution path.
struct OidcOpts {
    /// `--oidc` was passed: require OIDC (error if a token can't be obtained)
    /// rather than only using it as an auto-fallback.
    forced: bool,
    workspace: Option<String>,
    audience: Option<String>,
    token_env: Option<String>,
}

/// How the effective API key was obtained — for `doctor`/diagnostics.
enum AuthMode {
    /// A static `vtro_...` key (flag/env/config).
    Static(config::KeySource),
    /// A short-lived key minted via OIDC exchange, with the token's source.
    Oidc {
        source: String,
        policy_id: Option<String>,
    },
}

/// Resolves the effective API key: a static key when one is present (unless
/// `--oidc` forces workload-identity), otherwise a short-lived key minted by
/// exchanging a CI OIDC token (§6.1). Returns the key plus how it was obtained.
///
/// Precedence: an explicit static key (flag/env/config) is used as-is unless
/// `--oidc` was passed. With `--oidc`, or when no static key exists but a CI
/// OIDC token is available, the CLI fetches the provider ID token and exchanges
/// it at `/auth/oidc-exchange`. The minted key lives only in memory.
async fn resolve_auth(
    api_url: &str,
    static_key: Option<String>,
    static_source: config::KeySource,
    opts: &OidcOpts,
    project: &config::ProjectConfig,
    file: &config::Config,
    transport: &api::Transport,
) -> Result<(String, AuthMode), ExitCode> {
    // A static key wins unless the user explicitly asked for OIDC.
    if let Some(key) = static_key {
        if !opts.forced {
            return Ok((key, AuthMode::Static(static_source)));
        }
    }

    let token_env = opts
        .token_env
        .clone()
        .or_else(|| project.oidc_token_env.clone())
        .unwrap_or_else(|| oidc::DEFAULT_GITLAB_TOKEN_ENV.to_string());

    let Some(avail) = oidc::availability(&token_env) else {
        if opts.forced {
            eprintln!(
                "error: --oidc requested but no OIDC token is available. Run inside GitHub \
                 Actions (permissions: id-token: write) or GitLab CI with an `id_tokens:` \
                 entry exported as {token_env}."
            );
            return Err(ExitCode::from(exit::AUTH));
        }
        // Auto-mode with no token and no static key: nothing to authenticate with.
        eprintln!(
            "error: no API key and no OIDC token. Pass --api-key, set VETRO_API_KEY, \
             run `vetro login`, or run in CI with workload-identity (§6.1)."
        );
        return Err(ExitCode::from(exit::AUTH));
    };

    // Workspace + audience: flag > .vetro.toml > user config > default.
    let Some(workspace) = opts
        .workspace
        .clone()
        .or_else(|| project.workspace_id.clone())
        .or_else(|| file.workspace_id.clone())
    else {
        eprintln!(
            "error: OIDC login needs a workspace. Pass --workspace <id>, set \
             VETRO_WORKSPACE_ID, or add workspace_id to .vetro.toml / `vetro login --oidc`."
        );
        return Err(ExitCode::from(exit::AUTH));
    };
    let audience = opts
        .audience
        .clone()
        .or_else(|| project.oidc_audience.clone())
        .or_else(|| file.oidc_audience.clone())
        .unwrap_or_else(|| config::DEFAULT_OIDC_AUDIENCE.to_string());

    let source = match &avail {
        oidc::Availability::GitHubEndpoint { .. } => "github-actions".to_string(),
        oidc::Availability::EnvToken { var, .. } => format!("env:{var}"),
    };

    let id_token = match oidc::fetch_token(&avail, Some(&audience), transport).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: could not obtain an OIDC ID token: {e}");
            return Err(ExitCode::from(exit::AUTH));
        }
    };

    match api::oidc_exchange(api_url, &workspace, &id_token, transport).await {
        Ok(res) => {
            eprintln!(
                "note: authenticated via OIDC ({source}); minted a short-lived key{}.",
                res.expires_at
                    .as_deref()
                    .map(|e| format!(" (expires {e})"))
                    .unwrap_or_default()
            );
            Ok((
                res.api_key,
                AuthMode::Oidc {
                    source,
                    policy_id: res.policy_id,
                },
            ))
        }
        Err(e) => {
            eprintln!("error: OIDC token exchange failed: {e}");
            let code = match e {
                ApiError::Auth(_) => exit::AUTH,
                _ => exit::BACKEND,
            };
            Err(ExitCode::from(code))
        }
    }
}

/// Resolves the effective `--fail-on`: the flag wins; else `.vetro.toml`'s
/// `fail_on` (parsed leniently); else the default `Block`. An unrecognized
/// value in the file is ignored (falls through to default) with no hard error,
/// since a typo there shouldn't wedge every run — it just doesn't take effect.
fn resolve_fail_on(flag: Option<FailOn>, project: Option<&str>) -> FailOn {
    if let Some(f) = flag {
        return f;
    }
    match project.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("block") => FailOn::Block,
        Some("flag") => FailOn::Flag,
        Some("any") => FailOn::Any,
        _ => FailOn::Block,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check(args) => run_check(args).await,
        Command::Login(args) => run_login(args).await,
        Command::Logout => run_logout(),
        Command::Doctor(args) => run_doctor(args).await,
        Command::Init(args) => run_init(args),
        Command::Baseline(args) => run_baseline(args).await,
        Command::VerifyReceipt(args) => run_verify_receipt(args),
        Command::Version => {
            println!("vetro {}", env!("CARGO_PKG_VERSION"));
            ExitCode::from(exit::OK)
        }
        Command::Completions(args) => run_completions(args),
    }
}

/// `vetro completions <shell>` — write a shell completion script to stdout.
/// clap generates it from the same command tree the CLI already defines, so it
/// stays in sync with the flags/subcommands automatically.
fn run_completions(args: CompletionsArgs) -> ExitCode {
    let mut cmd = Cli::command();
    let bin = cmd.get_name().to_string();
    clap_complete::generate(args.shell, &mut cmd, bin, &mut std::io::stdout());
    ExitCode::from(exit::OK)
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
    // Project config (.vetro.toml): PR-reviewable defaults; rejected if it
    // carries secrets/allow_degraded. A malformed file is a hard error.
    let project = match config::load_project() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(exit::USAGE);
        }
    };
    let resolved = config::resolve(
        args.api_url.as_deref().unwrap_or(config::DEFAULT_API_URL),
        args.api_url.is_none(),
        args.api_key.as_deref(),
        &file,
    );
    let api_url = resolved.api_url.clone();
    let transport = resolve_transport(args.timeout, args.ca_bundle.clone());
    // Auth: a static key, or a short-lived key minted via OIDC (§6.1).
    let oidc_opts = OidcOpts {
        forced: args.oidc,
        workspace: args.workspace.clone(),
        audience: args.audience.clone(),
        token_env: args.oidc_token_env.clone(),
    };
    let (api_key, _auth_mode) = match resolve_auth(
        &api_url,
        resolved.api_key,
        resolved.key_source,
        &oidc_opts,
        &project,
        &file,
        &transport,
    )
    .await
    {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    // dialect precedence: flag > .vetro.toml > user config default > "postgres".
    let dialect = args
        .dialect
        .clone()
        .or_else(|| project.default_dialect.clone())
        .or_else(|| file.default_dialect.clone())
        .unwrap_or_else(|| "postgres".to_string());
    // fail_on precedence: flag > .vetro.toml > default (block).
    let fail_on = resolve_fail_on(args.fail_on, project.fail_on.as_deref());
    // baseline precedence: flag > .vetro.toml.
    let baseline_path = args
        .baseline
        .clone()
        .or_else(|| project.baseline.as_ref().map(std::path::PathBuf::from));

    // Resolve the file list: explicit args, the git diff (--changed/--since), or
    // a newline-delimited list piped in (--stdin-file-list).
    let files = match resolve_files(&args.files, args.changed, &args.since, args.stdin_file_list) {
        FileResolution::Files(f) => f,
        FileResolution::EmptyDiff(msg) => {
            println!("{msg}");
            return ExitCode::from(exit::OK);
        }
        FileResolution::Usage(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(exit::USAGE);
        }
    };

    let mut queries = match collect_queries(&files) {
        Some(q) => q,
        None => return ExitCode::from(exit::USAGE),
    };
    if queries.is_empty() {
        eprintln!("error: no SQL to check (all inputs were empty).");
        return ExitCode::from(exit::USAGE);
    }

    let file_name = if files.len() == 1 && files[0] != "-" {
        Some(files[0].clone())
    } else {
        None
    };

    // Pre-flight (§6.2): learn the workspace's telemetry query mode BEFORE
    // sending any SQL. When 'sanitized', normalize literals client-side so raw
    // values never leave the machine. Best-effort: if the config endpoint is
    // unavailable (older backend) we proceed unsanitized rather than block —
    // the check itself is the security gate.
    match api::config(&api_url, &api_key, &transport).await {
        Ok(cfg) if cfg.telemetry_query_mode.as_deref() == Some("sanitized") => {
            for q in &mut queries {
                q.sql = sanitize::sanitize(&q.sql, &dialect);
            }
            eprintln!("note: workspace is in sanitized mode — literals normalized before sending.");
        }
        Ok(_) => {}
        Err(ApiError::Auth(e)) => {
            // A bad key surfaces here first — clearer than failing mid-check.
            eprintln!("error: {}", ApiError::Auth(e));
            return ExitCode::from(exit::AUTH);
        }
        Err(_) => {
            // Older backend without /ci/config, or a transient blip: proceed.
            // If the workspace truly requires sanitization this is a gap, so warn.
            eprintln!("note: could not read workspace config; proceeding without client-side sanitization.");
        }
    }

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
            transport: transport.clone(),
            concurrency,
            receipt: args.receipt.is_some(),
        },
        queries,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // §6.5 break-glass: ONLY a from-the-first-request unreachable
            // (Transport) may be waved through, and only with a reason. A real
            // backend error, an auth failure, or a partially-completed chunked
            // run (PartialFailure) always fails closed.
            if let ApiError::Transport(_) = e {
                if let Some(reason) = args.allow_degraded.as_deref() {
                    let reason = reason.trim();
                    if reason.is_empty() {
                        eprintln!("error: --allow-degraded requires a reason.");
                        return ExitCode::from(exit::USAGE);
                    }
                    eprintln!("error: {e}");
                    // Write a local, append-only degraded-run record (§6.5) so the
                    // bypass leaves an auditable trace even though the backend was
                    // unreachable. Best-effort: a write failure must not turn the
                    // break-glass back into a hard failure.
                    let record_path = write_degraded_record(reason, &files);
                    let where_str = record_path
                        .as_deref()
                        .map(|p| format!(" Recorded locally at {p}."))
                        .unwrap_or_default();
                    eprintln!(
                        "⚠ DEGRADED: backend unreachable; proceeding due to --allow-degraded \
                         (reason: {reason}). The SQL was NOT checked.{where_str} Archive this \
                         record as a CI artifact — server-side reconciliation is not yet \
                         available (see DESIGN §6.5)."
                    );
                    return ExitCode::from(exit::OK);
                }
            }
            eprintln!("error: {e}");
            return match e {
                ApiError::Auth(_) => ExitCode::from(exit::AUTH),
                ApiError::Backend { .. } | ApiError::Transport(_) | ApiError::PartialFailure(_) => {
                    ExitCode::from(exit::BACKEND)
                }
            };
        }
    };

    // Backend compatibility (§9): the response carries an `X-Vetro-Api-Version`
    // header. Warn on a minor skew, fail on a major mismatch (the CLI may
    // mis-parse a future major's response). Absent header (older backend) → skip.
    if let Some(v) = resp.api_version_header.as_deref() {
        match backend_compat(v) {
            Compat::Ok | Compat::Unknown => {}
            Compat::MinorSkew => eprintln!(
                "note: backend api {v} is older than this CLI expects (>= {MIN_BACKEND_API_VERSION}); some features may be unavailable."
            ),
            Compat::MajorMismatch => {
                eprintln!(
                    "error: incompatible backend api {v} (CLI requires {MIN_BACKEND_API_VERSION}, major mismatch). Upgrade the CLI or backend."
                );
                return ExitCode::from(exit::BACKEND);
            }
        }
    }

    if let Err(e) = output::render(
        &resp,
        args.format,
        &files,
        args.quiet,
        args.output.as_deref(),
        !args.no_color,
    ) {
        eprintln!("error: could not write output: {e}");
        return ExitCode::from(exit::USAGE);
    }

    // Signed run receipt (§7.1): write the server-signed evidence to --receipt.
    // A single-call run writes one object; a chunked run writes an array of
    // per-chunk receipts. If signing isn't configured server-side the response
    // carries no receipt — warn (the check still succeeded) rather than fail.
    if let Some(path) = args.receipt.as_deref() {
        let receipts = resp.all_receipts();
        if receipts.is_empty() {
            eprintln!(
                "warning: --receipt requested but the backend returned no receipt \
                 (signing may not be configured on this deployment). No file written."
            );
        } else if let Err(e) = write_receipts(path, &receipts) {
            eprintln!("error: could not write receipt to {}: {e}", path.display());
            return ExitCode::from(exit::USAGE);
        } else {
            let n = receipts.len();
            eprintln!(
                "note: wrote {} signed receipt{} to {}. Verify with `vetro verify-receipt {}`.",
                n,
                if n == 1 { "" } else { "s" },
                path.display(),
                path.display()
            );
        }
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

    // Suppression (§10): a finding does not fail the run if it is baselined or
    // carries an inline `-- vetro:ignore[RULE] reason`. Reporting still shows it;
    // only the exit code is affected.
    let suppressed = suppressed_fingerprints(&resp, &files, baseline_path.as_deref());
    let suppressed = match suppressed {
        Ok(s) => s,
        Err(code) => return code,
    };
    let fails = resp.queries.iter().any(|q| {
        let fp = output::fingerprint(q, &output::file_for(&files, q.line));
        !suppressed.contains(&fp) && finding_fails(q, fail_on)
    });
    if fails {
        ExitCode::from(exit::FINDING)
    } else {
        ExitCode::from(exit::OK)
    }
}

/// Collects the set of finding fingerprints that should NOT fail the run:
/// baselined entries (from `--baseline`) plus inline `-- vetro:ignore` matches.
/// Prints what it suppressed (and any baseline drift) to stderr. Returns an
/// ExitCode on a hard error (unreadable baseline).
fn suppressed_fingerprints(
    resp: &CheckResponse,
    files: &[String],
    baseline_path: Option<&std::path::Path>,
) -> Result<std::collections::HashSet<String>, ExitCode> {
    use std::collections::HashSet;
    let mut suppressed: HashSet<String> = HashSet::new();

    // 1) Baseline file.
    if let Some(path) = baseline_path {
        let bl = match baseline::Baseline::load(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: {e}");
                return Err(ExitCode::from(exit::USAGE));
            }
        };
        let set = bl.set();
        let mut n = 0;
        for q in resp.queries.iter().filter(|q| q.status != "ALLOWED") {
            if baseline::is_baselined(q, files, &set) {
                suppressed.insert(output::fingerprint(q, &output::file_for(files, q.line)));
                n += 1;
            }
        }
        if n > 0 {
            eprintln!(
                "note: {n} finding(s) suppressed by baseline {}.",
                path.display()
            );
        }
        let drift = baseline::drifted(&bl, resp, files);
        if !drift.is_empty() {
            eprintln!(
                "note: {} baseline entr(y/ies) no longer match — consider re-running `vetro baseline`.",
                drift.len()
            );
        }
    }

    // 2) Inline `-- vetro:ignore[RULE] reason` in the source file.
    for q in resp.queries.iter().filter(|q| q.status != "ALLOWED") {
        let Some(rule) = q.rule_code.as_deref() else {
            continue;
        };
        let path = output::file_for(files, q.line);
        if path == "<stdin>" {
            continue; // can't re-read stdin
        }
        if let Ok(sql) = std::fs::read_to_string(&path) {
            if let Some(reason) = baseline::inline_suppression(&sql, rule) {
                suppressed.insert(output::fingerprint(q, &path));
                eprintln!("note: {path}: {rule} suppressed inline — {reason}");
            }
        }
    }

    Ok(suppressed)
}

/// `vetro baseline` — run a check and record the current findings to a baseline
/// file (§10), so a later `check --baseline` only fails on *new* findings.
async fn run_baseline(args: BaselineArgs) -> ExitCode {
    let file = load_config();
    // Project config (for OIDC workspace/audience defaults, like `check`).
    let project = match config::load_project() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(exit::USAGE);
        }
    };
    let resolved = config::resolve(
        args.api_url.as_deref().unwrap_or(config::DEFAULT_API_URL),
        args.api_url.is_none(),
        args.api_key.as_deref(),
        &file,
    );
    let api_url = resolved.api_url.clone();
    let transport = resolve_transport(args.timeout, args.ca_bundle.clone());
    let oidc_opts = OidcOpts {
        forced: args.oidc,
        workspace: args.workspace.clone(),
        audience: args.audience.clone(),
        token_env: args.oidc_token_env.clone(),
    };
    let (api_key, _auth_mode) = match resolve_auth(
        &api_url,
        resolved.api_key,
        resolved.key_source,
        &oidc_opts,
        &project,
        &file,
        &transport,
    )
    .await
    {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let dialect = args
        .dialect
        .clone()
        .or_else(|| project.default_dialect.clone())
        .or_else(|| file.default_dialect.clone())
        .unwrap_or_else(|| "postgres".to_string());

    let files = match resolve_files(&args.files, args.changed, &args.since, false) {
        FileResolution::Files(f) => f,
        FileResolution::EmptyDiff(msg) => {
            println!("{msg}");
            return ExitCode::from(exit::OK);
        }
        FileResolution::Usage(msg) => {
            eprintln!("error: {msg}");
            return ExitCode::from(exit::USAGE);
        }
    };
    let queries = match collect_queries(&files) {
        Some(q) if !q.is_empty() => q,
        Some(_) => {
            eprintln!("error: no SQL to baseline (all inputs were empty).");
            return ExitCode::from(exit::USAGE);
        }
        None => return ExitCode::from(exit::USAGE),
    };

    let resp = match api::check_all(
        api::CheckParams {
            api_url: &api_url,
            api_key: &api_key,
            dialect: &dialect,
            file_name: None,
            provenance: build_provenance(),
            transport,
            concurrency: 4,
            receipt: false,
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
                _ => ExitCode::from(exit::BACKEND),
            };
        }
    };

    let bl = baseline::Baseline::from_response(&resp, &files);
    match bl.save(&args.out) {
        Ok(()) => {
            println!(
                "Wrote {} finding(s) to {}.",
                bl.entries.len(),
                args.out.display()
            );
            ExitCode::from(exit::OK)
        }
        Err(e) => {
            eprintln!("error: could not write baseline: {e}");
            ExitCode::from(exit::USAGE)
        }
    }
}

/// Writes run receipts (§7.1) to `path`: a single receipt as one JSON object,
/// or several (a chunked run) as a JSON array — the shape `verify-receipt`
/// accepts on the way back in.
fn write_receipts(path: &std::path::Path, receipts: &[api::Receipt]) -> std::io::Result<()> {
    let json = if receipts.len() == 1 {
        serde_json::to_string_pretty(&receipts[0])
    } else {
        serde_json::to_string_pretty(receipts)
    }
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// `vetro verify-receipt <file>` — verify a signed run receipt (§7.1) offline.
/// Accepts a single receipt object or an array (chunked run); every receipt must
/// verify for the command to exit 0. Prints a clear reason on failure.
fn run_verify_receipt(args: VerifyReceiptArgs) -> ExitCode {
    let text = match std::fs::read_to_string(&args.file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", args.file.display());
            return ExitCode::from(exit::USAGE);
        }
    };

    // Accept either a single receipt or an array of them.
    let receipts: Vec<api::Receipt> = match serde_json::from_str::<api::Receipt>(&text) {
        Ok(one) => vec![one],
        Err(_) => match serde_json::from_str::<Vec<api::Receipt>>(&text) {
            Ok(many) => many,
            Err(e) => {
                eprintln!(
                    "error: {} is not a valid receipt (or array of receipts): {e}",
                    args.file.display()
                );
                return ExitCode::from(exit::USAGE);
            }
        },
    };
    if receipts.is_empty() {
        eprintln!("error: no receipts found in {}.", args.file.display());
        return ExitCode::from(exit::USAGE);
    }

    // --public-key may be an inline PEM or a path to a .pem file.
    let override_pem = match args.public_key.as_deref() {
        Some(v) if v.contains("BEGIN") => Some(v.to_string()),
        Some(pathish) => match std::fs::read_to_string(pathish) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("error: cannot read public key file '{pathish}': {e}");
                return ExitCode::from(exit::USAGE);
            }
        },
        None => None,
    };

    let total = receipts.len();
    for (i, r) in receipts.iter().enumerate() {
        match receipt::verify(r, override_pem.as_deref()) {
            Ok(()) => {
                let label = if total == 1 {
                    "receipt".to_string()
                } else {
                    format!("receipt {}/{}", i + 1, total)
                };
                println!(
                    "✓ {label} verified (key {}, {}).",
                    r.public_key_id, r.scheme
                );
                if args.show {
                    print_receipt_summary(r);
                }
            }
            Err(e) => {
                eprintln!("✖ receipt {}/{} failed to verify: {e}", i + 1, total);
                // A verification failure is an auth/authenticity problem (exit 3),
                // distinct from a malformed file (exit 2, handled above).
                return ExitCode::from(exit::AUTH);
            }
        }
    }
    ExitCode::from(exit::OK)
}

/// Prints the human-relevant fields of a verified receipt payload (best-effort;
/// the payload is an opaque Value, so missing fields are simply skipped).
fn print_receipt_summary(r: &api::Receipt) {
    let p = &r.payload;
    let get = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("-").to_string();
    println!("  workspace: {}", get("workspace_id"));
    println!("  file:      {}", get("file_name"));
    println!("  dialect:   {}", get("dialect"));
    println!("  signed_at: {}", get("signed_at"));
    if let Some(s) = p.get("summary") {
        println!("  summary:   {s}");
    }
    if let Some(code) = p.get("exit_code") {
        println!("  exit_code: {code}");
    }
}

/// `vetro login` — persist an API key (and optional URL/dialect) to the config
/// file. The key comes from --api-key/env, or an interactive prompt.
async fn run_login(args: LoginArgs) -> ExitCode {
    // OIDC mode stores no secret — just the workspace/audience so CI runs
    // authenticate with a short-lived, per-run token (§6.1).
    if args.oidc {
        return run_login_oidc(args).await;
    }
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

/// `vetro login --oidc` — configure workload-identity login (§6.1). Stores only
/// the workspace_id (and audience) — never a secret. When run inside CI with an
/// OIDC token available, it also verifies the exchange works so the developer
/// gets immediate feedback rather than a failure on the first CI check.
async fn run_login_oidc(args: LoginArgs) -> ExitCode {
    let Some(workspace) = args.workspace.clone() else {
        eprintln!("error: `vetro login --oidc` requires --workspace <id>.");
        return ExitCode::from(exit::USAGE);
    };

    let mut cfg = load_config();
    // OIDC stores no api_key; clear any stale static key so `check` doesn't
    // silently prefer it over workload-identity.
    cfg.api_key = None;
    cfg.workspace_id = Some(workspace.clone());
    if let Some(url) = args.api_url.clone() {
        cfg.api_url = Some(url);
    }
    if let Some(aud) = args.audience.clone() {
        cfg.oidc_audience = Some(aud);
    }

    let path = match cfg.save() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: could not write config: {e}");
            return ExitCode::from(exit::USAGE);
        }
    };
    println!(
        "Configured OIDC login for workspace {workspace} (audience {}) in {}.",
        args.audience
            .as_deref()
            .unwrap_or(config::DEFAULT_OIDC_AUDIENCE),
        path.display()
    );

    // Best-effort live verification when a token is actually available here.
    let token_env = oidc::DEFAULT_GITLAB_TOKEN_ENV.to_string();
    if oidc::availability(&token_env).is_some() {
        println!("Detected an OIDC token in this environment — verifying the exchange...");
        let api_url = cfg.api_url.clone().unwrap_or_else(|| {
            args.api_url
                .clone()
                .unwrap_or_else(|| config::DEFAULT_API_URL.to_string())
        });
        let audience = args
            .audience
            .clone()
            .or(cfg.oidc_audience.clone())
            .unwrap_or_else(|| config::DEFAULT_OIDC_AUDIENCE.to_string());
        let transport = resolve_transport(None, None);
        let avail = oidc::availability(&token_env).unwrap();
        let ok = match oidc::fetch_token(&avail, Some(&audience), &transport).await {
            Ok(tok) => match api::oidc_exchange(&api_url, &workspace, &tok, &transport).await {
                Ok(_) => {
                    println!("✓ OIDC exchange succeeded — CI runs are ready to authenticate.");
                    true
                }
                Err(e) => {
                    eprintln!("✖ OIDC exchange failed: {e}");
                    eprintln!(
                        "  Check that a trust policy for this workspace matches the token's \
                         issuer/audience/subject (dashboard → OIDC policies)."
                    );
                    false
                }
            },
            Err(e) => {
                eprintln!("✖ could not obtain an OIDC token: {e}");
                false
            }
        };
        return ExitCode::from(if ok { exit::OK } else { exit::AUTH });
    }

    println!(
        "Not in a CI environment with an OIDC token — configuration saved. In CI, ensure a token \
         is available (GitHub: permissions: id-token: write · GitLab: an `id_tokens:` entry \
         exported as {token_env})."
    );
    ExitCode::from(exit::OK)
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
    use scaffold::{AuthStyle, CiTarget, Written};

    // OIDC scaffolding needs a workspace to bake into the templates.
    let auth = if args.oidc {
        let Some(ws) = args.workspace.clone() else {
            eprintln!("error: `vetro init --oidc` requires --workspace <id>.");
            return ExitCode::from(exit::USAGE);
        };
        AuthStyle::Oidc { workspace_id: ws }
    } else {
        AuthStyle::StaticKey
    };

    let target = match args.target {
        Some(InitTarget::Github) => CiTarget::GitHub,
        Some(InitTarget::Gitlab) => CiTarget::GitLab,
        None => scaffold::detect_target(),
    };

    let mut plans: Vec<(std::path::PathBuf, String, bool)> = Vec::new();
    match target {
        CiTarget::GitHub => plans.push((
            std::path::PathBuf::from(".github/workflows/vetro.yml"),
            scaffold::github_workflow(&args.dialect, &auth),
            false,
        )),
        CiTarget::GitLab => plans.push((
            // Never clobber an existing .gitlab-ci.yml — write an include the
            // user wires in (printed below).
            std::path::PathBuf::from(".vetro/gitlab-ci.yml"),
            scaffold::gitlab_job(&args.dialect, &auth),
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
    let oidc = matches!(auth, AuthStyle::Oidc { .. });
    match target {
        CiTarget::GitHub => {
            if oidc {
                println!(
                    "\nNext: create an OIDC trust policy for this workspace in the Vetro \
                     dashboard (issuer https://token.actions.githubusercontent.com, audience \
                     'vetro', subject e.g. repo:your-org/your-repo:*). No secret needed — the \
                     workflow mints a short-lived token per run."
                );
            } else {
                println!(
                    "\nNext: add VETRO_API_KEY as a repository secret \
                     (Settings → Secrets and variables → Actions)."
                );
            }
        }
        CiTarget::GitLab => {
            if oidc {
                println!(
                    "\nNext:\n  1. Create an OIDC trust policy for this workspace in the Vetro \
                     dashboard (issuer https://gitlab.com, audience 'vetro', subject e.g. \
                     project_path:your-group/your-project:*).\n  \
                     2. Include the job from your .gitlab-ci.yml:\n       \
                     include:\n         - local: .vetro/gitlab-ci.yml"
                );
            } else {
                println!(
                    "\nNext:\n  1. Add VETRO_API_KEY as a masked CI/CD variable \
                     (Settings → CI/CD → Variables).\n  \
                     2. Include the job from your .gitlab-ci.yml:\n       \
                     include:\n         - local: .vetro/gitlab-ci.yml"
                );
            }
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
/// checks backend compatibility (`/version`) and reads the workspace config
/// (`/ci/config`) — the latter validates auth WITHOUT spending a CLI check.
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

    let transport = resolve_transport(args.timeout, args.ca_bundle.clone());

    // Backend compatibility (§9): unauthenticated, so it doubles as the first
    // reachability check. A major mismatch is fatal (the CLI may mis-parse
    // responses); a minor skew only warns; an older backend without /version is
    // treated as unknown and not blocked.
    println!("\ncli version: {}", env!("CARGO_PKG_VERSION"));
    match api::version(&resolved.api_url, &transport).await {
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

    // Auth: static key, or a short-lived key minted via OIDC (§6.1). `doctor`
    // reports which mode is active so the developer isn't guessing.
    let project = config::load_project().unwrap_or_default();
    let api_url = resolved.api_url.clone();
    let oidc_opts = OidcOpts {
        forced: args.oidc,
        workspace: args.workspace.clone(),
        audience: args.audience.clone(),
        token_env: args.oidc_token_env.clone(),
    };
    let (api_key, auth_mode) = match resolve_auth(
        &api_url,
        resolved.api_key,
        resolved.key_source,
        &oidc_opts,
        &project,
        &file,
        &transport,
    )
    .await
    {
        Ok(pair) => pair,
        Err(code) => {
            println!("\n✖ authentication unavailable.");
            return code;
        }
    };
    match &auth_mode {
        AuthMode::Static(src) => println!("auth mode:   static key ({})", src.label()),
        AuthMode::Oidc { source, policy_id } => {
            print!("auth mode:   OIDC workload-identity via {source}");
            if let Some(pid) = policy_id {
                print!(" (policy {pid})");
            }
            println!();
        }
    }

    // Validate auth + read the workspace config WITHOUT spending a CLI check
    // (read-only endpoint). Reports plan, quota, ruleset and the query mode.
    match api::config(&api_url, &api_key, &transport).await {
        Ok(cfg) => {
            println!("\n✓ reachable and authenticated");
            if let Some(plan) = &cfg.plan {
                println!("  plan: {plan}");
            }
            if let Some(rs) = &cfg.ruleset_version {
                println!("  ruleset: {rs}");
            }
            match cfg.ci_checks_remaining {
                Some(n) => println!("  CLI checks remaining this month: {n}"),
                None => println!("  CLI checks: unmetered (team/enterprise)"),
            }
            // §6.2: report the effective query mode so the dev isn't guessing.
            println!(
                "  query mode: {}",
                cfg.telemetry_query_mode.as_deref().unwrap_or("raw")
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

/// Writes an append-only degraded-run record (§6.5) to `.vetro/degraded-runs.jsonl`
/// when `--allow-degraded` waves through an unreachable backend, so the bypass
/// leaves an auditable trace: reason, timestamp, the files that went unchecked,
/// and CI provenance. Returns the path written, or `None` on any I/O error
/// (best-effort — the break-glass must not fail on a write problem).
///
/// Note: this is a *local* record. There is no server-side reconciliation
/// endpoint yet (see DESIGN §6.5 / §14) — the record is meant to be archived as
/// a CI artifact so the gap is visible after the fact.
fn write_degraded_record(reason: &str, files: &[String]) -> Option<String> {
    use std::io::Write;
    // Unix-epoch seconds; avoids a chrono dependency for a single timestamp.
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prov = build_provenance();
    let record = serde_json::json!({
        "kind": "vetro-degraded-run",
        "version": 1,
        "unix_time": ts,
        "reason": reason,
        "files": files,
        "provenance": prov.map(|p| serde_json::json!({
            "git_sha": p.git_sha,
            "git_ref": p.git_ref,
            "ci_provider": p.ci_provider,
            "ci_run_url": p.ci_run_url,
            "actor": p.actor,
        })),
    });

    let dir = std::path::Path::new(".vetro");
    if std::fs::create_dir_all(dir).is_err() {
        return None;
    }
    let path = dir.join("degraded-runs.jsonl");
    let mut line = serde_json::to_string(&record).ok()?;
    line.push('\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()?;
    f.write_all(line.as_bytes()).ok()?;
    Some(path.display().to_string())
}

/// Outcome of resolving which files to check (shared by `check`/`baseline`).
enum FileResolution {
    /// The resolved list of file paths (or "-" for stdin).
    Files(Vec<String>),
    /// A `--changed` run with an empty diff — a pass, print `msg` and exit 0.
    EmptyDiff(String),
    /// A usage problem — `msg` already suitable for stderr; exit 2.
    Usage(String),
}

/// Resolves the file list from explicit args, the git diff (`--changed` /
/// `--since`), or a newline-delimited list on stdin (`--stdin-file-list`).
/// Shared so `check` and `baseline` behave identically.
fn resolve_files(
    files: &[String],
    changed: bool,
    since: &Option<String>,
    stdin_file_list: bool,
) -> FileResolution {
    // --stdin-file-list: read file paths (one per line) from stdin. For pipelines
    // that already compute the set, e.g.
    //   git diff --name-only --diff-filter=d $BASE...HEAD -- '*.sql' | vetro check --stdin-file-list
    if stdin_file_list {
        if !files.is_empty() || changed || since.is_some() {
            return FileResolution::Usage(
                "--stdin-file-list can't be combined with files or --changed/--since.".to_string(),
            );
        }
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            return FileResolution::Usage(format!("could not read file list from stdin: {e}"));
        }
        let list: Vec<String> = buf
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        if list.is_empty() {
            return FileResolution::EmptyDiff("No files on stdin — nothing to check.".to_string());
        }
        return FileResolution::Files(list);
    }

    let use_changed = changed || since.is_some();
    if use_changed {
        if !files.is_empty() {
            return FileResolution::Usage("pass files OR --changed/--since, not both.".to_string());
        }
        let provider = ci_env::Provider::detect();
        let Some(base) = since
            .clone()
            .or_else(|| ci_env::detected_base_ref(provider))
        else {
            return FileResolution::Usage(
                "could not determine a base ref for --changed. Pass --since <ref> \
                 (e.g. --since origin/main)."
                    .to_string(),
            );
        };
        match ci_env::changed_sql_files(&base) {
            Ok(list) if list.is_empty() => FileResolution::EmptyDiff(format!(
                "No changed .sql files vs {base} — nothing to check."
            )),
            Ok(list) => FileResolution::Files(list),
            Err(e) => FileResolution::Usage(e),
        }
    } else if files.is_empty() {
        FileResolution::Usage(
            "no files given. Pass SQL files, '-' for stdin, or --changed.".to_string(),
        )
    } else {
        FileResolution::Files(files.to_vec())
    }
}

/// Reads each file (or stdin) whole into one query item per file, indexed by
/// position (1-based `line`). Returns None if a file can't be read (message
/// already printed) — the caller maps that to exit 2. Empty inputs are skipped;
/// an all-empty set yields an empty Vec (the caller decides what that means).
fn collect_queries(files: &[String]) -> Option<Vec<QueryInput>> {
    let mut queries = Vec::new();
    for (i, path) in files.iter().enumerate() {
        let sql = match read_source(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: cannot read '{path}': {e}");
                return None;
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
    Some(queries)
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

/// Whether a single finding is at/above the `--fail-on` threshold.
fn finding_fails(q: &api::QueryResult, fail_on: FailOn) -> bool {
    match fail_on {
        FailOn::Block => q.status == "BLOCKED",
        FailOn::Flag => q.status == "BLOCKED" || q.status == "FLAGGED",
        FailOn::Any => matches!(q.status.as_str(), "BLOCKED" | "FLAGGED" | "MONITORED"),
    }
}

/// Whether the response contains any finding at/above the threshold (ignores
/// suppression — used in unit tests).
#[cfg(test)]
fn has_failure(resp: &CheckResponse, fail_on: FailOn) -> bool {
    resp.queries.iter().any(|q| finding_fails(q, fail_on))
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
            receipt: None,
            merged_receipts: Vec::new(),
            api_version_header: None,
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
