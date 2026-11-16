// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto guard install --hard`, `uninstall --hard` and the hard-mode part
//! of `status`.
//!
//! Install: find the database credentials an agent can see (redacted), move
//! the chosen ones into the OS keychain through `vericto-proxy mcp credential
//! set` (the URL on its stdin), check the role with `credential test
//! --require-read-only`, point each agent's MCP configuration at
//! `vericto-proxy mcp --database-url-keychain <name> --require-read-only`,
//! install the hook with `--hard` (and Claude Code `permissions.deny` rules),
//! then, only with consent, take the plaintext URLs out of their files.
//! Every changed file is copied first into a private backup directory, never
//! next to the file (a copy of a `.env` in the project is one more place the
//! agent and `git add` can reach).

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde_json::{json, Value};

use super::exposure::{self, Credential, Exposure, Place, ScanCtx, Secret};
use super::hook::Agent;
use super::install::{self, Plan, Scope};
use super::mcpconf::{self, Want};
use super::proxy::{self, Proxy, RoleState};

/// What the hard-mode flags asked for.
#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub name: Option<String>,
    pub yes: bool,
    pub dry_run: bool,
    pub remove_plaintext: bool,
    pub allow_write_role: bool,
    pub allow_unreachable: bool,
    pub delete_credential: bool,
    pub proxy: Option<PathBuf>,
    pub fail_open: bool,
}

/// Where hard mode keeps its backups: `<state dir>/vericto/guard-backups`
/// (`~/.local/state` on Linux, `~/Library/Application Support` on macOS,
/// `%LOCALAPPDATA%` on Windows), readable by the user only.
pub fn backup_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("VERICTO_GUARD_BACKUP_DIR").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("vericto")
        .join("guard-backups")
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

fn locate_proxy(opts: &Opts, home: &Path) -> Result<Proxy, String> {
    let cands = proxy::candidates(env("PATH").as_deref(), home, env("CARGO_HOME").as_deref());
    proxy::locate(opts.proxy.as_deref(), &cands).map_err(|e| e.message())
}

/// Reads one answer from the terminal.
fn prompt(q: &str) -> String {
    print!("{q} ");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s.trim().to_string()
}

fn confirm(q: &str) -> bool {
    matches!(
        prompt(&format!("{q} [y/N]")).to_ascii_lowercase().as_str(),
        "y" | "yes"
    )
}

/// Asks, or takes `flag` when nobody can be asked.
fn consent(interactive: bool, flag: bool, q: &str) -> bool {
    if interactive {
        flag || confirm(q)
    } else {
        flag
    }
}

fn print_exposures(creds: &[Credential], rest: &[Exposure], home: &Path) {
    if creds.is_empty() && rest.is_empty() {
        println!("No PostgreSQL, MySQL or MariaDB credentials found in the project's .env files, the environment, the agents' MCP configuration, ~/.pgpass or ~/.my.cnf.");
        return;
    }
    println!("Database credentials an agent can read (passwords are never shown):");
    for (i, c) in creds.iter().enumerate() {
        println!(
            "  [{}] {}  ({})",
            i + 1,
            c.info.redacted(),
            c.info.dialect.as_str()
        );
        for p in &c.places {
            println!("        {}", p.describe(home));
        }
    }
    if !rest.is_empty() {
        println!("  Also found (not moved automatically):");
        for e in rest {
            let shown = if e.info.is_some() {
                format!("{}  ", e.shown())
            } else {
                String::new()
            };
            println!("    - {shown}{}", e.place.describe(home));
            if let Some(n) = &e.note {
                println!("        {n}");
            }
        }
    }
}

/// `all`, `none`, or `1,3`.
fn parse_selection(s: &str, n: usize) -> Result<Vec<usize>, String> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() || s == "all" || s == "a" {
        return Ok((0..n).collect());
    }
    if s == "none" || s == "n" || s == "0" {
        return Ok(Vec::new());
    }
    let mut v = Vec::new();
    for part in s.split([',', ' ']).filter(|p| !p.is_empty()) {
        let i: usize = part.parse().map_err(|_| format!("not a number: {part}"))?;
        if i == 0 || i > n {
            return Err(format!("no credential [{i}]"));
        }
        if !v.contains(&(i - 1)) {
            v.push(i - 1);
        }
    }
    Ok(v)
}

/// Unique keychain names for the chosen credentials.
fn names_for(chosen: &[&Credential], explicit: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in chosen {
        let base = match explicit {
            Some(n) => exposure::sanitize_name(n),
            None => exposure::default_name(&c.info),
        };
        let mut n = base.clone();
        let mut i = 2;
        while out.contains(&n) {
            n = format!("{base}-{i}");
            i += 1;
        }
        out.push(n);
    }
    out
}

fn hard_cmd(bin: &str, agent: Agent) -> String {
    format!("{} --hard", install::hook_command(bin, agent))
}

/// The settings / hooks file with the hook (and, for Claude, the deny
/// rules) merged; `None` rules removes them.
fn plan_settings(
    agent: Agent,
    path: &Path,
    cmd: &str,
    fail_open: bool,
    add_rules: Option<&[String]>,
    strip_rules: Option<&[String]>,
) -> Result<Plan, String> {
    let (before, mut j) = install::read_json(path)?;
    install::merge_hook(agent, path, &mut j, cmd, fail_open)?;
    if agent == Agent::Claude {
        if let Some(r) = add_rules {
            mcpconf::merge_deny(path, &mut j, r)?;
        }
        if let Some(r) = strip_rules {
            mcpconf::strip_deny(&mut j, r);
        }
    }
    let after = install::to_text(&j);
    Ok(Plan {
        path: path.to_path_buf(),
        changed: before.as_deref() != Some(after.as_str()),
        before,
        after,
    })
}

fn show_plan(p: &Plan, home: &Path) {
    if !p.changed {
        println!("  {}: no change", exposure::short(&p.path, home));
        return;
    }
    println!(
        "  {} {}:",
        if p.before.is_some() {
            "update"
        } else {
            "create"
        },
        exposure::short(&p.path, home)
    );
    for l in install::diff(p.before.as_deref().unwrap_or(""), &p.after).lines() {
        println!("    {l}");
    }
}

fn apply_all(plans: &[Plan], home: &Path) -> bool {
    let dir = backup_dir();
    let mut ok = true;
    for p in plans.iter().filter(|p| p.changed) {
        match install::apply_with(p, Some(&dir)) {
            Ok(b) => {
                print!("  wrote {}", exposure::short(&p.path, home));
                if let Some(b) = b {
                    print!(" (backup {})", exposure::short(&b, home));
                }
                println!();
            }
            Err(e) => {
                eprintln!("error: {e}");
                ok = false;
            }
        }
    }
    ok
}

/// The outcome of one credential.
struct Stored {
    name: String,
    cred: Option<Credential>,
    require_read_only: bool,
    created: bool,
}

fn print_role_problem(a: &proxy::Answer, state: RoleState, dialect: &str, database: Option<&str>) {
    let reasons = a.reasons();
    match state {
        RoleState::CanWrite => println!(
            "    The database role can write{}.",
            if reasons.is_empty() {
                String::new()
            } else {
                format!(" ({})", reasons.join("; "))
            }
        ),
        _ => println!(
            "    The proxy could not verify that the role is read-only{}.",
            if reasons.is_empty() {
                String::new()
            } else {
                format!(" ({})", reasons.join("; "))
            }
        ),
    }
    println!("    Hard mode needs a role that can only read. Create one, store its URL instead, and run this again:");
    for l in proxy::read_only_role_sql(dialect, database).lines() {
        println!("      {l}");
    }
    println!("    (docs: vericto-proxy docs/MCP.md, \"Read-only database roles\"; --allow-write-role configures it anyway, which is not hard mode)");
}

fn dialect_key(c: Option<&Credential>, a: &proxy::Answer) -> String {
    a.json["dialect"]
        .as_str()
        .map(String::from)
        .or_else(|| {
            c.map(|c| match c.info.dialect {
                exposure::Dialect::Postgres => "postgres".to_string(),
                _ => "mysql".to_string(),
            })
        })
        .unwrap_or_else(|| "postgres".into())
}

fn rollback(proxy: &Proxy, stored: &[Stored]) {
    for s in stored.iter().filter(|s| s.created) {
        let a = proxy.delete(&s.name);
        if a.code == 0 {
            println!(
                "  removed the keychain entry vericto-proxy/{} this run created",
                s.name
            );
        }
    }
}

pub fn install(
    agents: &[Agent],
    scope: Scope,
    cwd: &Path,
    root: &Path,
    home: &Path,
    bin: &str,
    opts: &Opts,
) -> ExitCode {
    let proxy = match locate_proxy(opts, home) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    println!("vericto-proxy {} ({})", proxy.version, proxy.path.display());
    let tty = std::io::stdin().is_terminal();
    let interactive = tty && !opts.yes;
    if !tty && !opts.yes && !opts.dry_run {
        eprintln!("error: hard mode asks before it stores a credential or edits a file; run it in a terminal, or pass --yes (and --remove-plaintext to also take the URLs out of their files)");
        return ExitCode::from(2);
    }
    let sctx = ScanCtx::new(
        cwd.to_path_buf(),
        root.to_path_buf(),
        home.to_path_buf(),
        std::env::vars().collect(),
    );
    let exps = exposure::scan(&sctx);
    let (creds, rest) = exposure::group(&exps);
    print_exposures(&creds, &rest, home);

    // Which credentials.
    let chosen: Vec<&Credential> = if creds.is_empty() {
        Vec::new()
    } else if interactive {
        loop {
            let a = prompt(&format!(
                "Move which into the OS keychain? [all / numbers, e.g. 1,{} / none] (all):",
                creds.len().min(2)
            ));
            match parse_selection(&a, creds.len()) {
                Ok(v) => break v.into_iter().map(|i| &creds[i]).collect(),
                Err(e) => println!("  {e}"),
            }
        }
    } else {
        creds.iter().collect()
    };
    if opts.name.is_some() && chosen.len() > 1 {
        eprintln!("error: --name names one keychain entry, and {} credentials were chosen; choose one (interactively), or leave --name out", chosen.len());
        return ExitCode::from(2);
    }
    let use_existing = chosen.is_empty();
    if use_existing && opts.name.is_none() {
        eprintln!("error: no credential to move. Store one yourself (the URL is read from stdin, hidden on a terminal):\n  {} mcp credential set <name>\nthen run: vericto guard install --hard --name <name>", proxy.path.display());
        return ExitCode::from(2);
    }
    let names = if use_existing {
        vec![exposure::sanitize_name(
            opts.name.as_deref().unwrap_or_default(),
        )]
    } else {
        names_for(&chosen, opts.name.as_deref())
    };
    if names.iter().any(String::is_empty) {
        eprintln!("error: --name must have letters or digits ([A-Za-z0-9._@:-])");
        return ExitCode::from(2);
    }
    let pdisp = proxy.path.to_string_lossy().replace('\\', "/");

    if opts.dry_run {
        println!("\nDry run: nothing is stored or written.");
        for (i, n) in names.iter().enumerate() {
            match chosen.get(i) {
                Some(c) => println!("  would store {} as keychain entry vericto-proxy/{n}: the URL on the stdin of `{pdisp} mcp credential set {n}`, then `… credential test {n} --require-read-only`", c.info.redacted()),
                None => println!("  would use the existing keychain entry vericto-proxy/{n} (`… credential test {n} --require-read-only`)"),
            }
        }
        let wants: Vec<Want> = names
            .iter()
            .map(|n| Want {
                name: n.clone(),
                require_read_only: true,
            })
            .collect();
        for p in agent_plans(agents, scope, root, home, &pdisp, &wants, bin, opts) {
            match p {
                Ok(p) => show_plan(&p, home),
                Err(e) => println!("  error: {e}"),
            }
        }
        let items = removal_items(&chosen, &names);
        if let Ok(rs) = mcpconf::removals(&items) {
            for r in rs {
                println!(
                    "  with consent, would take {} out of {}",
                    r.what.join(", "),
                    exposure::short(&r.plan.path, home)
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    // Store and check each credential.
    println!();
    let mut stored: Vec<Stored> = Vec::new();
    let mut refused = false;
    for (i, name) in names.iter().enumerate() {
        let cred = chosen.get(i).copied();
        let mut created = false;
        if let Some(c) = cred {
            if interactive
                && !confirm(&format!(
                    "Store {} in the {} as vericto-proxy/{name}?",
                    c.info.redacted(),
                    store_name()
                ))
            {
                println!("  skipped {}", c.info.redacted());
                continue;
            }
            let a = proxy.set(name, &c.url);
            if a.code != 0 {
                eprintln!("error: vericto-proxy could not store it: {}", a.message());
                rollback(&proxy, &stored);
                return ExitCode::from(2);
            }
            created = !a.json["replaced"].as_bool().unwrap_or(false);
            println!(
                "  stored {} as {} ({}){}",
                c.info.redacted(),
                a.json["entry"].as_str().unwrap_or(name),
                a.json["backend"].as_str().unwrap_or("OS keychain"),
                if created {
                    ""
                } else {
                    ", replacing the entry's previous URL"
                }
            );
        }
        let t = proxy.test(name, true, None);
        let state = t.role();
        let entry = Stored {
            name: name.clone(),
            cred: cred.cloned(),
            require_read_only: true,
            created,
        };
        match state {
            RoleState::ReadOnly => {
                println!("  checked vericto-proxy/{name}: connected, the role is read-only");
                stored.push(entry);
            }
            RoleState::CanWrite | RoleState::Unverified => {
                println!("  checked vericto-proxy/{name}: {}", state.as_str());
                print_role_problem(
                    &t,
                    state,
                    &dialect_key(cred, &t),
                    cred.and_then(|c| c.info.database.as_deref()),
                );
                if opts.allow_write_role {
                    println!("    --allow-write-role: configuring it without --require-read-only. This is NOT hard mode: the server still runs reads only, in a read-only transaction, but nothing stops a write the role allows if that check were ever bypassed.");
                    stored.push(Stored {
                        require_read_only: false,
                        ..entry
                    });
                } else {
                    refused = true;
                    if entry.created {
                        let _ = proxy.delete(name);
                        println!(
                            "    removed the keychain entry again; nothing was configured for it"
                        );
                    }
                }
            }
            RoleState::Unreachable => {
                println!("  checked vericto-proxy/{name}: the database is unreachable or refused the login ({})", t.message());
                if opts.allow_unreachable {
                    println!("    --allow-unreachable: configuring it anyway; the server checks the role when it starts and refuses to run unless it is read-only");
                    stored.push(entry);
                } else {
                    stored.push(entry);
                    println!("    stopping (pass --allow-unreachable to configure an entry that cannot be checked now)");
                    rollback(&proxy, &stored);
                    return ExitCode::from(1);
                }
            }
            RoleState::NoEntry => {
                eprintln!("error: there is no keychain entry vericto-proxy/{name}; store it first: {pdisp} mcp credential set {name}");
                rollback(&proxy, &stored);
                return ExitCode::from(2);
            }
            RoleState::Failed => {
                eprintln!(
                    "error: vericto-proxy mcp credential test {name} failed: {}",
                    t.message()
                );
                stored.push(entry);
                rollback(&proxy, &stored);
                return ExitCode::from(2);
            }
        }
    }
    if stored.is_empty() {
        println!("Nothing configured.");
        return ExitCode::from(if refused { 1 } else { 0 });
    }

    // The agents' files.
    let wants: Vec<Want> = stored
        .iter()
        .map(|s| Want {
            name: s.name.clone(),
            require_read_only: s.require_read_only,
        })
        .collect();
    println!("\nAgent configuration:");
    let mut plans = Vec::new();
    for p in agent_plans(agents, scope, root, home, &pdisp, &wants, bin, opts) {
        match p {
            Ok(p) => {
                show_plan(&p, home);
                plans.push(p);
            }
            Err(e) => {
                eprintln!("error: {e}");
                rollback(&proxy, &stored);
                return ExitCode::from(2);
            }
        }
    }
    if interactive && plans.iter().any(|p| p.changed) && !confirm("Write these changes?") {
        println!("Nothing written.");
        rollback(&proxy, &stored);
        return ExitCode::from(1);
    }
    let mut ok = apply_all(&plans, home);

    // The plaintext copies.
    let moved: Vec<&Credential> = stored.iter().filter_map(|s| s.cred.as_ref()).collect();
    let moved_names: Vec<String> = stored
        .iter()
        .filter(|s| s.cred.is_some())
        .map(|s| s.name.clone())
        .collect();
    let items = removal_items(&moved, &moved_names);
    match mcpconf::removals(&items) {
        Ok(rs) if !rs.is_empty() => {
            println!("\nThe URL is still in plaintext here (the agent can still read it):");
            for r in &rs {
                println!(
                    "  {}: {}",
                    exposure::short(&r.plan.path, home),
                    r.what.join(", ")
                );
            }
            println!("  Taking it out replaces each line with a comment that points to hard mode (an MCP server entry is removed: JSON has no comments). A copy of each file goes to {} first. Programs that read the URL from these files (your app, Prisma, psql through ~/.pgpass) stop finding it: give them the URL another way, outside the agent's reach.", exposure::short(&backup_dir(), home));
            let mut chosen_plans = Vec::new();
            for r in rs {
                if consent(
                    interactive,
                    opts.remove_plaintext,
                    &format!(
                        "Take {} out of {}?",
                        r.what.join(", "),
                        exposure::short(&r.plan.path, home)
                    ),
                ) {
                    chosen_plans.push(r.plan);
                }
            }
            if chosen_plans.is_empty() {
                println!(
                    "  left as they are{}",
                    if interactive {
                        ""
                    } else {
                        " (pass --remove-plaintext to take them out)"
                    }
                );
            } else {
                ok &= apply_all(&chosen_plans, home);
            }
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: {e}");
            ok = false;
        }
    }
    let backups: Vec<&Exposure> = rest
        .iter()
        .filter(|e| matches!(e.place, Place::Backup { .. }))
        .collect();
    if !backups.is_empty() {
        println!("\nEarlier vericto guard backups next to your files hold a database URL:");
        for b in &backups {
            println!("  {}", b.place.describe(home));
        }
        if consent(
            interactive,
            opts.remove_plaintext,
            "Move them into the private backup directory?",
        ) {
            for b in backups {
                if let Place::Backup { path } = &b.place {
                    match move_to_backups(path) {
                        Ok(to) => println!("  moved to {}", exposure::short(&to, home)),
                        Err(e) => {
                            eprintln!("error: {e}");
                            ok = false;
                        }
                    }
                }
            }
        }
    }
    let manual: Vec<String> = items
        .iter()
        .filter(|(p, _, _)| !mcpconf::editable(p))
        .map(|(p, _, _)| match p {
            Place::Environment { var } => format!("unset {var} in the shell that starts the agent (shell profile, direnv, the IDE's environment)"),
            Place::UrlFile { path, .. } => format!("delete {} once the new entry works (its MCP server reads the URL from it)", exposure::short(path, home)),
            other => format!("remove it from {}", other.describe(home)),
        })
        .collect();
    if !manual.is_empty() {
        println!("\nDo these yourself (vericto guard does not change them):");
        for m in manual {
            println!("  - {m}");
        }
    }

    println!("\nHard mode is configured. Next:");
    println!("  - restart the agent (Claude Code, Cursor, Codex) so it starts the vericto-db MCP server and reads the new rules");
    if agents.contains(&Agent::Codex) {
        println!("  - Codex: run /hooks and trust the changed hook");
    }
    if scope == Scope::Project && agents.contains(&Agent::Claude) {
        println!(
            "  - Claude Code asks you to approve the project's .mcp.json server the first time"
        );
    }
    println!("  - check it: vericto guard status");
    println!(
        "  Limits: the server runs as your OS user. {}",
        same_user_note()
    );
    println!("  For strict isolation run the server as another OS user, in a container or on another host (docs/guard.md, Hard mode).");
    ExitCode::from(if !ok {
        2
    } else if refused {
        1
    } else {
        0
    })
}

fn store_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(windows) {
        "Windows Credential Manager"
    } else {
        "Secret Service (secret-tool)"
    }
}

fn same_user_note() -> &'static str {
    if cfg!(target_os = "macos") {
        "On macOS other programs get a Keychain prompt before they can read the entry (unless someone clicks Always Allow)."
    } else if cfg!(windows) {
        "On Windows any process of your user can read a Credential Manager entry without a prompt: the entry keeps the URL out of files and the environment, not out of your processes."
    } else {
        "On Linux any process of your user can read the Secret Service entry while the keyring is unlocked (the whole desktop session), without a prompt."
    }
}

fn removal_items(chosen: &[&Credential], names: &[String]) -> Vec<(Place, Secret, String)> {
    chosen
        .iter()
        .zip(names)
        .flat_map(|(c, n)| {
            c.places
                .iter()
                .map(move |p| (p.clone(), c.url.clone(), n.clone()))
        })
        .collect()
}

fn move_to_backups(path: &Path) -> Result<PathBuf, String> {
    let dir = backup_dir();
    install::private_dir(&dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let to = dir.join(format!("moved-{name}"));
    std::fs::copy(path, &to).map_err(|e| format!("cannot copy {}: {e}", path.display()))?;
    install::restrict(&to);
    std::fs::remove_file(path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
    Ok(to)
}

#[allow(clippy::too_many_arguments)]
fn agent_plans(
    agents: &[Agent],
    scope: Scope,
    root: &Path,
    home: &Path,
    proxy: &str,
    wants: &[Want],
    bin: &str,
    opts: &Opts,
) -> Vec<Result<Plan, String>> {
    let rules = mcpconf::deny_rules(Some(&backup_dir()), home);
    let mut out = Vec::new();
    for &agent in agents {
        let (mp, toml) = mcpconf::mcp_path(agent, scope, root, home, &env);
        out.push(
            mcpconf::plan_add(agent, &mp, toml, proxy, wants)
                .map_err(|e| format!("{}: {e}", agent.as_str())),
        );
        let sp = install::config_path(agent, scope, root, home, &env);
        out.push(
            plan_settings(
                agent,
                &sp,
                &hard_cmd(bin, agent),
                opts.fail_open,
                Some(&rules),
                None,
            )
            .map_err(|e| format!("{}: {e}", agent.as_str())),
        );
    }
    out
}

pub fn uninstall(
    agents: &[Agent],
    scope: Scope,
    root: &Path,
    home: &Path,
    opts: &Opts,
) -> ExitCode {
    let tty = std::io::stdin().is_terminal();
    let interactive = tty && !opts.yes;
    let rules = mcpconf::deny_rules(Some(&backup_dir()), home);
    let mut plans = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut commands: Vec<String> = Vec::new();
    let mut failed = false;
    for &agent in agents {
        let (mp, toml) = mcpconf::mcp_path(agent, scope, root, home, &env);
        if let Ok(ss) = mcpconf::servers(&mp, toml) {
            commands.extend(ss.into_iter().map(|s| s.command));
        }
        match mcpconf::plan_remove(&mp, toml, None) {
            Ok((p, n)) => {
                for x in n {
                    if !names.contains(&x) {
                        names.push(x);
                    }
                }
                plans.push(p);
            }
            Err(e) => {
                eprintln!("error: {}: {e}", agent.as_str());
                failed = true;
            }
        }
        let sp = install::config_path(agent, scope, root, home, &env);
        let st = install::status(agent, &sp);
        if let Some(e) = st.error {
            eprintln!("error: {}: {e}", agent.as_str());
            failed = true;
            continue;
        }
        // Back to the plain guard hook (the hook stays: `vericto guard
        // uninstall` removes it).
        let plan = match st.commands.iter().find(|c| install::is_hard(c)) {
            Some(c) => {
                let plain = c
                    .split(' ')
                    .filter(|w| *w != "--hard")
                    .collect::<Vec<_>>()
                    .join(" ");
                plan_settings(agent, &sp, &plain, opts.fail_open, None, Some(&rules))
            }
            None if agent == Agent::Claude => install::read_json(&sp).map(|(before, mut j)| {
                mcpconf::strip_deny(&mut j, &rules);
                let after = install::to_text(&j);
                Plan {
                    path: sp.clone(),
                    changed: before.is_some() && before.as_deref() != Some(after.as_str()),
                    before,
                    after,
                }
            }),
            None => continue,
        };
        match plan {
            Ok(p) => plans.push(p),
            Err(e) => {
                eprintln!("error: {}: {e}", agent.as_str());
                failed = true;
            }
        }
    }
    let changed: Vec<Plan> = plans.into_iter().filter(|p| p.changed).collect();
    if changed.is_empty() {
        println!(
            "Hard mode is not configured for {} ({} scope).",
            agents
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            scope.as_str()
        );
    } else {
        println!("Hard mode off:");
        for p in &changed {
            show_plan(p, home);
        }
        if opts.dry_run {
            println!("Dry run: nothing written.");
            return ExitCode::SUCCESS;
        }
        if interactive && !confirm("Write these changes?") {
            println!("Nothing written.");
            return ExitCode::from(1);
        }
        failed |= !apply_all(&changed, home);
        println!("  The guard hook stays installed without --hard (remove it with `vericto guard uninstall`).");
    }
    let dir = backup_dir();
    if dir.is_dir() {
        println!("  Copies of the files hard mode changed, with the URLs they held, are in {} (readable by you only). Nothing is put back automatically: a plaintext URL goes back only if you copy it back.", exposure::short(&dir, home));
    }
    if opts.dry_run {
        return ExitCode::from(if failed { 2 } else { 0 });
    }
    if !names.is_empty() {
        // The binary the entries ran (it created the keychain items), else
        // --proxy / PATH.
        let proxy = match opts.proxy {
            Some(_) => locate_proxy(opts, home),
            None => commands
                .iter()
                .find_map(|c| proxy::locate(Some(Path::new(c)), &[]).ok())
                .ok_or(())
                .or_else(|_| locate_proxy(opts, home)),
        };
        for n in &names {
            if !consent(
                interactive,
                opts.delete_credential,
                &format!("Delete the keychain entry vericto-proxy/{n} too?"),
            ) {
                println!(
                    "  kept the keychain entry vericto-proxy/{n}{}",
                    if interactive {
                        ""
                    } else {
                        " (pass --delete-credential to delete it)"
                    }
                );
                continue;
            }
            match &proxy {
                Ok(p) => {
                    let a = p.delete(n);
                    match a.code {
                        0 => println!("  deleted the keychain entry vericto-proxy/{n}"),
                        2 => println!("  there was no keychain entry vericto-proxy/{n}"),
                        _ => {
                            eprintln!("error: could not delete vericto-proxy/{n}: {}", a.message());
                            failed = true;
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "error: {e}\n(or delete it with: vericto-proxy mcp credential delete {n})"
                    );
                    failed = true;
                }
            }
        }
    }
    ExitCode::from(if failed { 2 } else { 0 })
}

/// The hard-mode part of `status`: text lines and the JSON.
pub fn status(
    cwd: &Path,
    root: &Path,
    home: &Path,
    config_hard: bool,
    test: bool,
) -> (Vec<String>, Value) {
    let mut lines = Vec::new();
    let mut rows = Vec::new();
    // Keychain name → the proxy its MCP entry runs (that binary is tested).
    let mut names: Vec<(String, String)> = Vec::new();
    let rules = mcpconf::deny_rules(Some(&backup_dir()), home);
    let mut any = config_hard;
    for agent in [Agent::Claude, Agent::Cursor, Agent::Codex] {
        for scope in [Scope::User, Scope::Project] {
            let (mp, toml) = mcpconf::mcp_path(agent, scope, root, home, &env);
            let servers = mcpconf::servers(&mp, toml);
            let sp = install::config_path(agent, scope, root, home, &env);
            let st = install::status(agent, &sp);
            let hook_hard = st.commands.iter().any(|c| install::is_hard(c));
            let deny = if agent == Agent::Claude {
                install::read_json(&sp)
                    .ok()
                    .map(|(_, j)| mcpconf::deny_present(&j, &rules))
            } else {
                None
            };
            let servers = match servers {
                Ok(s) => s,
                Err(e) => {
                    lines.push(format!(
                        "  {:<6} {:<7} unreadable: {e}",
                        agent.as_str(),
                        scope.as_str()
                    ));
                    continue;
                }
            };
            if servers.is_empty() && !hook_hard && deny.unwrap_or(0) == 0 {
                continue;
            }
            any = true;
            for s in &servers {
                if !names.iter().any(|(n, _)| n == &s.name) {
                    names.push((s.name.clone(), s.command.clone()));
                }
            }
            let srv = if servers.is_empty() {
                "no vericto-db MCP server".to_string()
            } else {
                servers
                    .iter()
                    .map(|s| {
                        format!(
                            "MCP {} → keychain {}{}{}",
                            s.key,
                            s.name,
                            if s.require_read_only {
                                " (read-only required)"
                            } else {
                                " (read-only NOT required: not hard mode)"
                            },
                            if Path::new(&s.command).is_file() {
                                ""
                            } else {
                                ", proxy binary missing"
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            let mut l = format!(
                "  {:<6} {:<7} {srv}; hook {}",
                agent.as_str(),
                scope.as_str(),
                if hook_hard {
                    "--hard"
                } else if st.commands.is_empty() {
                    "missing"
                } else {
                    "without --hard"
                }
            );
            if let Some(n) = deny {
                l.push_str(&format!("; deny rules {n}/{}", rules.len()));
            }
            lines.push(l);
            rows.push(json!({
                "agent": agent.as_str(), "scope": scope.as_str(), "mcp_path": mp.display().to_string(),
                "servers": servers.iter().map(|s| json!({"key": s.key, "keychain": s.name, "require_read_only": s.require_read_only, "command": s.command, "command_found": Path::new(&s.command).is_file()})).collect::<Vec<_>>(),
                "hook_hard": hook_hard, "deny_rules": deny, "deny_rules_expected": if agent == Agent::Claude { Some(rules.len()) } else { None },
            }));
        }
    }
    if !any {
        lines.insert(0, "hard mode: off (vericto guard install --hard moves the database URL into the OS keychain and gives the agent the Vericto MCP server instead)".into());
        return (
            lines,
            json!({"configured": false, "config_hard": config_hard}),
        );
    }
    lines.insert(
        0,
        format!(
            "hard mode:{}",
            if config_hard {
                " on in .vericto.toml ([guard] hard = true)"
            } else {
                ""
            }
        ),
    );
    let mut creds = Vec::new();
    if !names.is_empty() {
        for (n, command) in &names {
            let proxy = proxy::locate(Some(Path::new(command)), &[]).map_err(|e| e.message());
            let (state, key, reasons) = match (&proxy, test) {
                (_, false) => (
                    "not tested (--no-test)".to_string(),
                    "not_tested",
                    Vec::new(),
                ),
                (Err(e), true) => (
                    format!("not tested: {}", e.lines().next().unwrap_or("")),
                    "not_tested",
                    Vec::new(),
                ),
                (Ok(p), true) => {
                    let a = p.test(n, true, Some(Duration::from_secs(20)));
                    let r = a.role();
                    let s = match r {
                        RoleState::Unreachable | RoleState::Failed => format!(
                            "{} ({})",
                            r.as_str(),
                            a.message().lines().next().unwrap_or("")
                        ),
                        _ => r.as_str().to_string(),
                    };
                    (s, r.key(), a.reasons())
                }
            };
            lines.push(format!(
                "  credential vericto-proxy/{n}: {state}{}",
                if reasons.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", reasons.join("; "))
                }
            ));
            creds.push(json!({"name": n, "state": key, "message": state, "reasons": reasons}));
        }
    }
    let sctx = ScanCtx::new(
        cwd.to_path_buf(),
        root.to_path_buf(),
        home.to_path_buf(),
        std::env::vars().collect(),
    );
    let exps = exposure::scan(&sctx);
    if exps.is_empty() {
        lines.push("  remaining exposures: none found".into());
    } else {
        lines.push("  remaining exposures (the agent can still read these):".into());
        for e in &exps {
            lines.push(format!("    - {}  {}", e.shown(), e.place.describe(home)));
        }
    }
    let v = json!({
        "configured": true,
        "config_hard": config_hard,
        "agents": rows,
        "credentials": creds,
        "exposures": exps.iter().map(|e| json!({"url": e.shown(), "place": e.place.describe(home)})).collect::<Vec<_>>(),
        "backup_dir": backup_dir().display().to_string(),
    });
    (lines, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selections() {
        assert_eq!(parse_selection("", 3).unwrap(), vec![0, 1, 2]);
        assert_eq!(parse_selection("all", 2).unwrap(), vec![0, 1]);
        assert_eq!(parse_selection("none", 2).unwrap(), Vec::<usize>::new());
        assert_eq!(parse_selection("2, 1,2", 3).unwrap(), vec![1, 0]);
        assert!(parse_selection("4", 3).is_err());
        assert!(parse_selection("x", 3).is_err());
    }

    #[test]
    fn unique_names() {
        let c = |u: &str| Credential {
            url: Secret::new(u),
            info: exposure::parse_db_url(u).unwrap(),
            places: Vec::new(),
        };
        let a = c("postgres://u@h/shop");
        let b = c("postgres://v@h2/shop");
        assert_eq!(names_for(&[&a, &b], None), vec!["shop", "shop-2"]);
        assert_eq!(names_for(&[&a], Some("my db")), vec!["my-db"]);
    }
}
