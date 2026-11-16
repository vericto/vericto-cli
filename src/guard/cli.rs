// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The `vericto guard` subcommands.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};

use super::config::{self, Loaded};
use super::hook::{self, Agent};
use super::install::{self, Scope};
use super::target::Class;
use super::{log, Action, Decision, Verdict};

/// Protect coding agents (Claude Code, Cursor, Codex): check the SQL and the
/// destructive database commands they are about to run, offline.
#[derive(Parser)]
pub struct GuardArgs {
    #[command(subcommand)]
    pub command: GuardCommand,
}

#[derive(Subcommand)]
pub enum GuardCommand {
    /// The hook itself: reads the agent's hook JSON on stdin and answers in
    /// that agent's format (what the agents' configuration runs).
    Hook(HookArgs),
    /// Show the decision for a command, as the hook would take it.
    Test(TestArgs),
    /// Add the hook to the agents' configuration (merges; keeps a backup).
    Install(InstallArgs),
    /// Remove the hook from the agents' configuration.
    Uninstall(InstallArgs),
    /// Where the hook is installed, which policy applies, where the log is.
    Status(StatusArgs),
    /// The last decisions from the local log.
    Log(LogArgs),
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum AgentArg {
    Claude,
    Cursor,
    Codex,
}

impl From<AgentArg> for Agent {
    fn from(a: AgentArg) -> Agent {
        match a {
            AgentArg::Claude => Agent::Claude,
            AgentArg::Cursor => Agent::Cursor,
            AgentArg::Codex => Agent::Codex,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum AgentsArg {
    Claude,
    Cursor,
    Codex,
    All,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum ScopeArg {
    Project,
    User,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum FormatArg {
    Text,
    Json,
}

#[derive(Parser)]
pub struct HookArgs {
    /// Which agent's hook protocol to speak.
    #[arg(long, value_enum)]
    pub agent: AgentArg,
}

#[derive(Parser)]
pub struct TestArgs {
    /// The shell command to check (quote it), or the MCP arguments as JSON
    /// with --mcp.
    pub command: String,
    /// Check an MCP tool call instead: SERVER/TOOL (e.g. supabase/execute_sql).
    #[arg(long, value_name = "SERVER/TOOL")]
    pub mcp: Option<String>,
    /// Also print the exact hook answer for this agent.
    #[arg(long, value_enum)]
    pub agent: Option<AgentArg>,
    /// Directory the command runs in (default: the current directory).
    #[arg(long)]
    pub cwd: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    pub format: FormatArg,
}

#[derive(Parser)]
pub struct InstallArgs {
    /// Which agent (default: every agent found on this machine / project).
    #[arg(long, value_enum)]
    pub agent: Option<AgentsArg>,
    /// `user`: every project for this user (default). `project`: this
    /// repository's agent config (commit it to share with the team).
    #[arg(long, value_enum, default_value_t = ScopeArg::User)]
    pub scope: ScopeArg,
    /// Print what would change, write nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// The vericto binary the hook runs (default: this one, by its PATH name
    /// when it is on PATH).
    #[arg(long, value_name = "PATH")]
    pub bin: Option<String>,
    /// Cursor only: do not set `failClosed`, so a crash or timeout of the
    /// hook lets the command run (Cursor's default) instead of blocking it.
    #[arg(long)]
    pub fail_open: bool,
}

#[derive(Parser)]
pub struct StatusArgs {
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    pub format: FormatArg,
}

#[derive(Parser)]
pub struct LogArgs {
    /// How many decisions to show.
    #[arg(short = 'n', long, default_value_t = 20)]
    pub limit: usize,
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    pub format: FormatArg,
}

pub fn run(args: GuardArgs) -> ExitCode {
    match args.command {
        GuardCommand::Hook(a) => run_hook(a.agent.into()),
        GuardCommand::Test(a) => run_test(a),
        GuardCommand::Install(a) => run_install(a, false),
        GuardCommand::Uninstall(a) => run_install(a, true),
        GuardCommand::Status(a) => run_status(a),
        GuardCommand::Log(a) => run_log(a),
    }
}

fn env_lookup(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// Largest hook input read (an agent sends a few KiB).
const MAX_INPUT: u64 = 8 * 1024 * 1024;

fn emit(out: &hook::Output) -> ExitCode {
    use std::io::Write;
    if let Some(s) = &out.stdout {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{s}");
        let _ = o.flush();
    }
    if let Some(s) = &out.stderr {
        eprintln!("{s}");
    }
    ExitCode::from(out.exit)
}

fn resolve_cwd(input_cwd: Option<&str>) -> PathBuf {
    input_cwd
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .or_else(|| {
            ["CLAUDE_PROJECT_DIR", "CURSOR_PROJECT_DIR"]
                .iter()
                .find_map(|k| env_lookup(k).map(PathBuf::from).filter(|p| p.is_dir()))
        })
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn run_hook(agent: Agent) -> ExitCode {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().take(MAX_INPUT).read_to_string(&mut raw) {
        let (out, _) = hook::render_unreadable(agent, &raw, &format!("stdin: {e}"));
        return emit(&out);
    }
    let parsed: Result<hook::HookInput, String> = serde_json::from_str::<Value>(&raw)
        .map_err(|e| format!("invalid JSON: {e}"))
        .and_then(|v| hook::parse_input(agent, &v));
    let input = match parsed {
        Ok(i) => i,
        Err(e) => {
            let (out, verdict) = hook::render_unreadable(agent, &raw, &e);
            let cfg = config::GuardConfig::default();
            let rec = json!({"ts": log::rfc3339(now()), "agent": agent.as_str(), "verdict": verdict.as_str(), "error": e, "command": log::command_field(&cfg, &raw)});
            let _ = log::append(&cfg, &rec);
            return emit(&out);
        }
    };
    let Some(action) = input.action.clone() else {
        // Not a tool the guard checks.
        let out = match agent {
            Agent::Cursor => hook::Output {
                stdout: Some(json!({"permission": "allow"}).to_string()),
                stderr: None,
                exit: 0,
            },
            _ => hook::Output {
                stdout: None,
                stderr: None,
                exit: 0,
            },
        };
        return emit(&out);
    };
    let cwd = resolve_cwd(input.cwd.as_deref());
    let loaded = config::load(&cwd);
    // A bug in a detector must not let a destructive command through, nor
    // block everything: fall back to the keyword reading of the raw input.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::evaluate(&action, &cwd, &loaded, &env_lookup)
    }));
    let Ok(d) = result else {
        let (out, _) = hook::render_unreadable(agent, &raw, "internal error");
        return emit(&out);
    };
    let eff = hook::effective(agent, d.verdict, &input);
    let mut out = hook::render(agent, &d, eff, d.verdict);
    if let Some(e) = &loaded.error {
        let note = format!("vericto guard: {e}; using the default policy");
        out.stderr = Some(match out.stderr.take() {
            Some(s) => format!("{s}\n{note}"),
            None => note,
        });
    }
    if !d.applied.is_empty() || eff != Verdict::Allow {
        let cwd_text = cwd.to_string_lossy();
        let origin = log::Origin {
            agent: agent.as_str(),
            session: input.session.as_deref(),
            event: &input.event,
            tool: &input.tool,
            cwd: &cwd_text,
        };
        let rec = log::record(&origin, &loaded.config, &action.text(), &d, eff);
        if let Err(e) = log::append(&loaded.config, &rec) {
            if agent != Agent::Cursor && out.exit == 0 && out.stdout.is_none() {
                eprintln!("vericto guard: could not write the decision log: {e}");
            }
        }
    }
    emit(&out)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_mcp_spec(spec: &str) -> (String, String) {
    if let Some((s, t)) = super::detect::split_mcp_name(spec) {
        return (s.to_string(), t.to_string());
    }
    match spec.split_once('/') {
        Some((s, t)) => (s.to_string(), t.to_string()),
        None => (String::new(), spec.to_string()),
    }
}

fn decision_json(d: &Decision, loaded: &Loaded, action: &Action) -> Value {
    json!({
        "verdict": d.verdict.as_str(),
        "agents": {
            "claude": eff_for(Agent::Claude, d).as_str(),
            "cursor": eff_for(Agent::Cursor, d).as_str(),
            "codex": eff_for(Agent::Codex, d).as_str(),
        },
        "command": super::target::redact(&action.text()),
        "findings": d.applied.iter().map(|a| json!({
            "code": a.finding.code,
            "severity": a.finding.severity.as_str(),
            "kind": a.finding.kind.as_str(),
            "verdict": a.verdict.as_str(),
            "title": a.finding.title,
            "fix": a.finding.fix,
            "prod": a.prod,
            "allowed_by": a.allowed_by,
            "targets": a.finding.targets.iter().map(|t| json!({"host": t.host, "database": t.database, "class": t.class.as_str(), "source": t.source})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "config": loaded.path.as_ref().map(|p| p.display().to_string()),
        "config_error": loaded.error,
        "mode": loaded.config.mode.as_str(),
    })
}

fn eff_for(agent: Agent, d: &Decision) -> Verdict {
    let input = hook::HookInput {
        action: None,
        cwd: None,
        unattended: false,
        session: None,
        event: String::new(),
        tool: String::new(),
    };
    hook::effective(agent, d.verdict, &input)
}

fn run_test(a: TestArgs) -> ExitCode {
    let cwd = a
        .cwd
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let action = match &a.mcp {
        Some(spec) => {
            let (server, tool) = parse_mcp_spec(spec);
            let input: Value = match serde_json::from_str(&a.command) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "error: with --mcp the argument is the tool's arguments as JSON ({e})"
                    );
                    return ExitCode::from(2);
                }
            };
            Action::Mcp {
                server,
                tool,
                input,
            }
        }
        None => Action::Shell(a.command.clone()),
    };
    let loaded = config::load(&cwd);
    let d = super::evaluate(&action, &cwd, &loaded, &env_lookup);
    if a.format == FormatArg::Json {
        let mut v = decision_json(&d, &loaded, &action);
        if let Some(ag) = a.agent {
            let ag: Agent = ag.into();
            let eff = eff_for(ag, &d);
            let out = hook::render(ag, &d, eff, d.verdict);
            v["hook_output"] = json!({"stdout": out.stdout.as_deref().and_then(|s| serde_json::from_str::<Value>(s).ok()), "stderr": out.stderr, "exit": out.exit});
        }
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        print_decision(&d, &loaded, &action);
        if let Some(ag) = a.agent {
            let ag: Agent = ag.into();
            let eff = eff_for(ag, &d);
            let out = hook::render(ag, &d, eff, d.verdict);
            println!("\n{} hook answer (exit {}):", ag.as_str(), out.exit);
            if let Some(s) = &out.stdout {
                let pretty = serde_json::from_str::<Value>(s)
                    .ok()
                    .and_then(|v| serde_json::to_string_pretty(&v).ok())
                    .unwrap_or_else(|| s.clone());
                println!("stdout: {pretty}");
            }
            if let Some(s) = &out.stderr {
                println!("stderr: {s}");
            }
            if out.stdout.is_none() && out.stderr.is_none() {
                println!("(no output: allowed)");
            }
        }
    }
    ExitCode::from(u8::from(d.verdict >= Verdict::Ask))
}

fn print_decision(d: &Decision, loaded: &Loaded, action: &Action) {
    let mark = match d.verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Warn => "WARN",
        Verdict::Ask => "ASK",
        Verdict::Deny => "DENY",
    };
    println!("{mark}  {}", super::target::redact(&action.text()));
    if d.verdict == Verdict::Ask {
        println!("      (Claude Code and Cursor ask the user; Codex cannot ask, so it denies)");
    }
    for a in &d.applied {
        println!(
            "  {:<5} {} [{}] {}",
            a.verdict.as_str(),
            a.finding.code,
            a.finding.severity.as_str(),
            a.finding.title
        );
        for t in &a.finding.targets {
            if t.class != Class::Unknown {
                println!("        target: {}", t.describe());
            }
        }
        if !a.finding.fix.is_empty() {
            println!("        fix: {}", a.finding.fix);
        }
        if let Some(r) = &a.allowed_by {
            println!("        allowed by .vericto.toml: {r}");
        }
    }
    match (&loaded.path, &loaded.error) {
        (_, Some(e)) => println!("policy: defaults (could not use {e})"),
        (Some(p), None) => println!(
            "policy: {} (mode {})",
            p.display(),
            loaded.config.mode.as_str()
        ),
        (None, None) => println!("policy: defaults (mode block; no .vericto.toml [guard] section)"),
    }
}

fn agents_for(
    sel: Option<AgentsArg>,
    scope: Scope,
    root: &Path,
    home: &Path,
) -> Result<Vec<Agent>, String> {
    let all = [Agent::Claude, Agent::Cursor, Agent::Codex];
    match sel {
        Some(AgentsArg::All) => Ok(all.to_vec()),
        Some(AgentsArg::Claude) => Ok(vec![Agent::Claude]),
        Some(AgentsArg::Cursor) => Ok(vec![Agent::Cursor]),
        Some(AgentsArg::Codex) => Ok(vec![Agent::Codex]),
        None => {
            let found: Vec<Agent> = all
                .into_iter()
                .filter(|a| {
                    let dir = match a {
                        Agent::Claude => ".claude",
                        Agent::Cursor => ".cursor",
                        Agent::Codex => ".codex",
                    };
                    let user = install::config_path(*a, Scope::User, root, home, &env_lookup);
                    home.join(dir).is_dir()
                        || user.parent().is_some_and(Path::is_dir)
                        || (scope == Scope::Project && root.join(dir).is_dir())
                })
                .collect();
            if found.is_empty() {
                Err("no Claude Code, Cursor or Codex configuration found; pass --agent claude|cursor|codex|all".into())
            } else {
                Ok(found)
            }
        }
    }
}

/// The home directory the agents use: `$HOME` (`%USERPROFILE%` on
/// Windows) when set, as Claude Code, Cursor and Codex read it, else the OS
/// answer.
fn home() -> Result<PathBuf, String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .ok_or_else(|| "cannot find the home directory".to_string())
}

fn run_install(a: InstallArgs, remove: bool) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let root = config::load(&cwd).root;
    let home = match home() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let scope = match a.scope {
        ScopeArg::Project => Scope::Project,
        ScopeArg::User => Scope::User,
    };
    let agents = match agents_for(a.agent, scope, &root, &home) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let bin = a
        .bin
        .clone()
        .unwrap_or_else(|| install::default_bin(&env_lookup));
    let mut failed = false;
    for agent in agents {
        let path = install::config_path(agent, scope, &root, &home, &env_lookup);
        let plan = if remove {
            install::plan_uninstall(agent, &path)
        } else {
            install::plan_install(
                agent,
                &path,
                &install::hook_command(&bin, agent),
                a.fail_open,
            )
        };
        let plan = match plan {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {}: {e}", agent.as_str());
                failed = true;
                continue;
            }
        };
        let label = format!("{} ({})", agent.as_str(), scope.as_str());
        if !plan.changed {
            println!(
                "{label}: {} {}",
                if remove {
                    "not installed in"
                } else {
                    "already installed in"
                },
                path.display()
            );
            continue;
        }
        if a.dry_run {
            println!(
                "{label}: would {} {}",
                if remove || plan.before.is_some() {
                    "update"
                } else {
                    "create"
                },
                path.display()
            );
            print!(
                "{}",
                install::diff(plan.before.as_deref().unwrap_or(""), &plan.after)
            );
            continue;
        }
        match install::apply(&plan) {
            Ok(backup) => {
                println!(
                    "{label}: {} {}",
                    if remove {
                        "removed from"
                    } else {
                        "installed in"
                    },
                    path.display()
                );
                if let Some(b) = backup {
                    println!("  backup: {}", b.display());
                }
                if !remove {
                    match agent {
                        Agent::Claude => println!("  takes effect in new Claude Code sessions (check with /hooks)"),
                        Agent::Cursor => println!("  Cursor reloads hooks.json on save; check the Hooks tab in Cursor Settings"),
                        Agent::Codex => println!("  Codex runs a new hook only after you trust it: open Codex and run /hooks to review it"),
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {label}: {e}");
                failed = true;
            }
        }
    }
    if !remove && !a.dry_run && !failed {
        println!("check it: vericto guard test \"npx prisma migrate reset --force\"");
    }
    ExitCode::from(if failed { 2 } else { 0 })
}

fn run_status(a: StatusArgs) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let loaded = config::load(&cwd);
    let home = home().unwrap_or_else(|_| PathBuf::from("~"));
    let mut rows = Vec::new();
    for agent in [Agent::Claude, Agent::Cursor, Agent::Codex] {
        for scope in [Scope::User, Scope::Project] {
            let path = install::config_path(agent, scope, &loaded.root, &home, &env_lookup);
            let s = install::status(agent, &path);
            let programs: Vec<(String, bool)> = s
                .commands
                .iter()
                .filter_map(|c| install::command_program(c))
                .map(|p| {
                    let ok = Path::new(&p).is_file() || (!p.contains('/') && which(&p));
                    (p, ok)
                })
                .collect();
            rows.push((agent, scope, s, programs));
        }
    }
    // Hard-mode hint: a production-looking database URL the agent can see.
    let ctx_findings = prod_urls_visible(&cwd, &loaded);
    let log_path = log::path(&loaded.config);
    if a.format == FormatArg::Json {
        let v = json!({
            "cli_version": env!("CARGO_PKG_VERSION"),
            "engine_version": crate::offline::ENGINE_VERSION,
            "offline_engine": crate::offline::AVAILABLE,
            "config": loaded.path.as_ref().map(|p| p.display().to_string()),
            "config_error": loaded.error,
            "mode": loaded.config.mode.as_str(),
            "log": log_path.as_ref().map(|p| p.display().to_string()),
            "hooks": rows.iter().map(|(ag, sc, s, progs)| json!({
                "agent": ag.as_str(), "scope": sc.as_str(), "path": s.path.display().to_string(),
                "exists": s.exists, "installed": !s.commands.is_empty(), "commands": s.commands, "error": s.error,
                "binaries_found": progs.iter().all(|(_, ok)| *ok),
            })).collect::<Vec<_>>(),
            "production_urls_visible": ctx_findings,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        return ExitCode::SUCCESS;
    }
    println!(
        "vericto {} (engine {}{})",
        env!("CARGO_PKG_VERSION"),
        crate::offline::ENGINE_VERSION,
        if crate::offline::AVAILABLE {
            ""
        } else {
            ", not embedded: SQL is read by keywords only"
        }
    );
    for (ag, sc, s, progs) in &rows {
        let state = if let Some(e) = &s.error {
            format!("unreadable ({e})")
        } else if s.commands.is_empty() {
            "not installed".to_string()
        } else if progs.iter().all(|(_, ok)| *ok) {
            "installed".to_string()
        } else {
            format!(
                "installed, but {} is missing",
                progs
                    .iter()
                    .filter(|(_, ok)| !ok)
                    .map(|(p, _)| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        println!(
            "  {:<6} {:<7} {:<16} {}",
            ag.as_str(),
            sc.as_str(),
            state,
            s.path.display()
        );
    }
    println!("  (Claude Code can also use the plugin: /plugin marketplace add vericto/vericto-cli, then /plugin install vericto-guard@vericto)");
    if rows
        .iter()
        .any(|(ag, _, s, _)| *ag == Agent::Codex && !s.commands.is_empty())
    {
        println!(
            "  Codex: a new or changed hook runs only after you trust it with /hooks in Codex."
        );
    }
    match (&loaded.path, &loaded.error) {
        (_, Some(e)) => println!("policy: defaults; {e}"),
        (Some(p), None) => println!(
            "policy: {} (mode {}, {} allow entr{})",
            p.display(),
            loaded.config.mode.as_str(),
            loaded.config.allow.len(),
            if loaded.config.allow.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ),
        (None, None) => println!("policy: defaults (mode block)"),
    }
    match log_path {
        Some(p) if loaded.config.log => println!("log: {}", p.display()),
        _ => println!("log: off"),
    }
    for u in &ctx_findings {
        println!("note: the agent can see a production-looking database URL ({u}). Hooks are a guardrail, not a boundary: see \"hard mode\" in docs/guard.md (read-only credentials, the Vericto MCP server or proxy, no production credentials in the agent's environment).");
    }
    ExitCode::SUCCESS
}

fn which(p: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            .any(|d| d.join(p).is_file() || d.join(format!("{p}.exe")).is_file())
    })
}

/// Production-looking URLs in the environment or the project's `.env` files
/// (host and source only).
fn prod_urls_visible(cwd: &Path, loaded: &Loaded) -> Vec<String> {
    let mut layers = super::target::project_env_layers(cwd, &loaded.root);
    let mut vars = Vec::new();
    for v in super::target::URL_VARS {
        if let Ok(x) = std::env::var(v) {
            vars.push((v.to_string(), x));
        }
    }
    layers.push(super::target::EnvLayer {
        vars,
        source: "the environment".into(),
        prod_file: false,
    });
    let mut out = Vec::new();
    for l in &layers {
        for t in super::target::targets_from_layer(l, &loaded.config, super::target::URL_VARS) {
            if t.class == Class::Prod {
                out.push(t.describe());
            }
        }
    }
    out
}

fn run_log(a: LogArgs) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let loaded = config::load(&cwd);
    let recs = match log::tail(&loaded.config, a.limit) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: cannot read the log: {e}");
            return ExitCode::from(2);
        }
    };
    if a.format == FormatArg::Json {
        for r in &recs {
            println!("{r}");
        }
        return ExitCode::SUCCESS;
    }
    if recs.is_empty() {
        println!(
            "no decisions logged yet ({})",
            log::path(&loaded.config)
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
        return ExitCode::SUCCESS;
    }
    for r in &recs {
        let codes: Vec<&str> = r["findings"]
            .as_array()
            .map(|f| f.iter().filter_map(|x| x["code"].as_str()).collect())
            .unwrap_or_default();
        println!(
            "{} {:<5} {:<6} [{}] {}",
            r["ts"].as_str().unwrap_or(""),
            r["verdict"].as_str().unwrap_or(""),
            r["agent"].as_str().unwrap_or(""),
            codes.join(","),
            r["command"].as_str().unwrap_or("")
        );
    }
    ExitCode::SUCCESS
}
