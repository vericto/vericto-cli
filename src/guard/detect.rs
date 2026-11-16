// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The detectors: what in a shell command or an MCP tool call is destructive,
//! and which database it points at.
//!
//! A command line is read into simple commands (`shell`), each one is
//! unwrapped from the launchers around it (`sudo`, `env`, `npx`, `pnpm exec`,
//! `bundle exec`, `dotenv -e … --`, `uv run`, `docker exec`, `ssh host '…'`,
//! `bash -c '…'`, package.json scripts…), and the program left is matched
//! against three packs:
//!
//! - **SQL clients** (`psql`, `mysql`, `sqlite3`, `sqlcmd`, `duckdb`,
//!   `clickhouse-client`, `cockroach sql`, `wrangler d1 execute`, `turso db
//!   shell`, `heroku pg:psql`, `prisma db execute`, `manage.py dbshell`): the
//!   SQL they would send (`-c`, `-e`, `-f file`, heredoc, here-string, pipe,
//!   `< file`) goes to the engine.
//! - **ORM and migration tools** (Prisma, Drizzle, Rails, Alembic / Flask-
//!   Migrate, Django, Laravel, Knex, Sequelize, TypeORM, MikroORM, Ecto,
//!   Flyway, Liquibase, Doctrine, EF Core, sqlx, Diesel, dbmate, goose,
//!   golang-migrate, Atlas, Sqitch, Supabase CLI, SQLAlchemy `drop_all`) and
//!   **database CLIs** (`dropdb`, `mysqladmin drop`, `redis-cli FLUSHALL`,
//!   `mongosh` drops, `pg_restore --clean`, `mongorestore --drop`).
//! - **Platform** commands that delete a database, a project or its data
//!   (`heroku pg:reset`, `neonctl projects delete`, `aws rds
//!   delete-db-instance`, `docker compose down -v`…).
//!
//! Every finding carries the targets the command points at, so the policy can
//! treat production differently.

use std::cell::OnceCell;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::config::GuardConfig;
use super::shell::{self, Cmd, Input, SUBST};
use super::sql;
use super::target::{self, Class, EnvLayer, Target};
use super::{Finding, Kind, Severity};

/// Deepest nesting of `bash -c`, `ssh`, `$(…)` and package scripts followed.
const MAX_DEPTH: usize = 6;
/// Largest SQL file read.
const MAX_SQL_FILE: u64 = 10 * 1024 * 1024;

/// What the detectors need from the outside world.
pub struct Ctx<'a> {
    pub cwd: PathBuf,
    pub root: PathBuf,
    pub cfg: &'a GuardConfig,
    pub migration_paths: &'a [String],
    pub env: &'a dyn Fn(&str) -> Option<String>,
    project_env: OnceCell<Vec<EnvLayer>>,
}

impl<'a> Ctx<'a> {
    pub fn new(
        cwd: PathBuf,
        root: PathBuf,
        cfg: &'a GuardConfig,
        migration_paths: &'a [String],
        env: &'a dyn Fn(&str) -> Option<String>,
    ) -> Self {
        Ctx {
            cwd,
            root,
            cfg,
            migration_paths,
            env,
            project_env: OnceCell::new(),
        }
    }

    fn project_layers(&self) -> &[EnvLayer] {
        self.project_env
            .get_or_init(|| target::project_env_layers(&self.cwd, &self.root))
    }

    fn path(&self, p: &str) -> PathBuf {
        let p = p.strip_prefix("file:").unwrap_or(p);
        if let Some(rest) = p.strip_prefix("~/") {
            if let Some(h) = dirs::home_dir() {
                return h.join(rest);
            }
        }
        let path = Path::new(p);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        }
    }

    /// The process environment as a layer, for the variables the guard reads.
    fn process_layer(&self) -> EnvLayer {
        let mut vars = Vec::new();
        let names = target::URL_VARS
            .iter()
            .chain(target::ENV_NAME_VARS)
            .chain(target::HOST_VARS.iter().flat_map(|(h, d)| [h, d]))
            .chain(["PGSERVICE"].iter());
        for n in names {
            if let Some(v) = (self.env)(n) {
                vars.push((n.to_string(), v));
            }
        }
        EnvLayer {
            vars,
            source: "the agent's environment".into(),
            prod_file: false,
        }
    }
}

/// One command after unwrapping.
#[derive(Clone)]
struct Exec {
    argv: Vec<String>,
    stdin: Option<Input>,
    /// Command-scope variables, highest precedence first.
    layers: Vec<EnvLayer>,
    /// Where the command runs when not here (ssh host, kubectl context…).
    context: Vec<Target>,
    /// Files written earlier in the same script (`cat > x.sql <<EOF`).
    virtual_files: Vec<(String, String)>,
}

impl Exec {
    fn var(&self, name: &str) -> Option<(&str, &str)> {
        self.layers
            .iter()
            .find_map(|l| l.get(name).map(|v| (v, l.source.as_str())))
    }
    fn shown(&self) -> String {
        let s = self
            .argv
            .iter()
            .map(|a| {
                let a = a.replace(SUBST, "$(…)");
                if a.contains(' ') || a.is_empty() {
                    format!("'{a}'")
                } else {
                    a
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let s = target::redact(&s);
        if s.chars().count() > 160 {
            let mut t: String = s.chars().take(157).collect();
            t.push('…');
            t
        } else {
            s
        }
    }
}

/// The analysis of a whole shell command line.
pub fn shell(ctx: &Ctx, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    analyze_script(ctx, text, &[], &[], 0, &mut out);
    out
}

fn analyze_script(
    ctx: &Ctx,
    text: &str,
    outer_layers: &[EnvLayer],
    outer_context: &[Target],
    depth: usize,
    out: &mut Vec<Finding>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let lookup = |n: &str| -> Option<String> {
        outer_layers
            .iter()
            .find_map(|l| l.get(n).map(String::from))
            .or_else(|| (ctx.env)(n))
    };
    let script = shell::parse(text, &lookup);
    // Script-scope variables: sourced env files, then plain assignments.
    let mut script_layers: Vec<EnvLayer> = Vec::new();
    if !script.vars.is_empty() {
        script_layers.push(EnvLayer {
            vars: script
                .vars
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            source: "the command line".into(),
            prod_file: false,
        });
    }
    for f in &script.sourced {
        script_layers.push(target::named_env_layer(&ctx.cwd, f));
    }
    script_layers.extend(outer_layers.iter().cloned());

    let mut virtual_files: Vec<(String, String)> = Vec::new();
    for cmd in &script.cmds {
        if let Some(text) = written_text(cmd) {
            for w in &cmd.writes {
                virtual_files.push((w.clone(), text.clone()));
            }
        }
        let mut layers = Vec::new();
        if !cmd.assigns.is_empty() {
            layers.push(EnvLayer {
                vars: cmd.assigns.clone(),
                source: "the command's environment".into(),
                prod_file: false,
            });
        }
        layers.extend(script_layers.iter().cloned());
        let exec = Exec {
            argv: cmd.argv.clone(),
            stdin: cmd.stdin.clone(),
            layers,
            context: outer_context.to_vec(),
            virtual_files: virtual_files.clone(),
        };
        analyze_exec(ctx, exec, depth, out);
    }
    for n in &script.nested {
        analyze_script(ctx, n, &script_layers, outer_context, depth + 1, out);
    }
}

/// Text a command writes to the files it redirects to.
fn written_text(cmd: &Cmd) -> Option<String> {
    if cmd.writes.is_empty() {
        return None;
    }
    let name = base(cmd.argv.first()?);
    match name {
        "cat" | "tee" => match &cmd.stdin {
            Some(Input::Text(t)) => Some(t.clone()),
            _ => None,
        },
        "echo" => Some(
            cmd.argv[1..]
                .iter()
                .filter(|a| !matches!(a.as_str(), "-n" | "-e" | "-E"))
                .cloned()
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "printf" => Some(cmd.argv[1..].join(" ").replace("\\n", "\n")),
        _ => None,
    }
}

fn base(s: &str) -> &str {
    s.rsplit(['/', '\\']).next().unwrap_or(s)
}

/// The program name: the file name, without `.exe` / `.cmd`, `./bin/rails`
/// read as `rails`.
fn prog(s: &str) -> String {
    let b = base(s);
    let b = b
        .strip_suffix(".exe")
        .or_else(|| b.strip_suffix(".cmd"))
        .or_else(|| b.strip_suffix(".ps1"))
        .unwrap_or(b);
    b.to_ascii_lowercase()
}

/// Strips a version from an npx package spec: `prisma@6` → `prisma`,
/// `@scope/pkg@1` → `@scope/pkg`.
fn strip_version(spec: &str) -> &str {
    let start = usize::from(spec.starts_with('@'));
    match spec[start..].find('@') {
        Some(p) => &spec[..start + p],
        None => spec,
    }
}

/// Skips leading options of a launcher. `with_value` lists options that take
/// the next word; `--` ends options. Returns the index of the first operand.
fn skip_opts(args: &[String], with_value: &[&str]) -> usize {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            return i + 1;
        }
        if !a.starts_with('-') || a == "-" {
            return i;
        }
        if !a.contains('=') && with_value.contains(&a.as_str()) {
            i += 2;
        } else {
            i += 1;
        }
    }
    i
}

/// Option scanner for a database client. Long options take `=value` or the
/// next word when listed; short ones take an attached or next value when
/// listed; clusters (`-tAc`) are read letter by letter.
fn scan<'s>(
    args: &'s [String],
    with_value: &[&str],
    clusters: bool,
) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut positional_only = false;
    while i < args.len() {
        let a: &'s str = &args[i];
        i += 1;
        if positional_only || !a.starts_with('-') || a == "-" {
            out.push((String::new(), Some(a.to_string())));
            continue;
        }
        if a == "--" {
            positional_only = true;
            continue;
        }
        if a.starts_with("--") {
            if let Some((k, v)) = a.split_once('=') {
                out.push((k.to_string(), Some(v.to_string())));
            } else if with_value.contains(&a) {
                out.push((a.to_string(), args.get(i).cloned()));
                i += 1;
            } else {
                out.push((a.to_string(), None));
            }
            continue;
        }
        if !clusters || a.len() == 2 {
            if with_value.contains(&a) {
                out.push((a.to_string(), args.get(i).cloned()));
                i += 1;
            } else if let Some((k, v)) = a.split_once('=') {
                out.push((k.to_string(), Some(v.to_string())));
            } else if a.len() > 2 && !clusters {
                // `-cmd`, `-init` (sqlite3 / duckdb long single-dash options)
                // not in the list: a flag.
                out.push((a.to_string(), None));
            } else {
                out.push((a.to_string(), None));
            }
            continue;
        }
        // A cluster: `-tAc` / `-cSQL` / `-uroot`.
        let chars: Vec<char> = a[1..].chars().collect();
        let mut k = 0;
        while k < chars.len() {
            let flag = format!("-{}", chars[k]);
            if with_value.contains(&flag.as_str()) {
                let rest: String = chars[k + 1..].iter().collect();
                if rest.is_empty() {
                    out.push((flag, args.get(i).cloned()));
                    i += 1;
                } else {
                    out.push((flag, Some(rest)));
                }
                break;
            }
            out.push((flag, None));
            k += 1;
        }
    }
    out
}

fn positionals(items: &[(String, Option<String>)]) -> Vec<&str> {
    items
        .iter()
        .filter(|(k, _)| k.is_empty())
        .filter_map(|(_, v)| v.as_deref())
        .collect()
}

fn opt<'s>(items: &'s [(String, Option<String>)], names: &[&str]) -> Vec<&'s str> {
    items
        .iter()
        .filter(|(k, _)| names.contains(&k.as_str()))
        .filter_map(|(_, v)| v.as_deref())
        .collect()
}

fn has(items: &[(String, Option<String>)], names: &[&str]) -> bool {
    items.iter().any(|(k, _)| names.contains(&k.as_str()))
}

/// Non-option words of a tool's arguments (rough: every word that does not
/// start with `-`).
fn words(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect()
}

fn flag(args: &[String], names: &[&str]) -> bool {
    args.iter().any(|a| {
        let k = a.split_once('=').map(|(k, _)| k).unwrap_or(a);
        names.contains(&k)
    })
}

fn flag_value<'s>(args: &'s [String], names: &[&str]) -> Option<&'s str> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some((k, v)) = a.split_once('=') {
            if names.contains(&k) {
                return Some(v);
            }
        } else if names.contains(&a.as_str()) {
            return args.get(i + 1).map(String::as_str);
        } else if let Some(n) = names
            .iter()
            .find(|n| n.len() == 2 && a.starts_with(**n) && a.len() > 2 && !a.starts_with("--"))
        {
            return Some(&a[n.len()..]);
        }
        i += 1;
    }
    None
}

/// Contiguous `seq` among `ws`.
fn seq(ws: &[&str], s: &[&str]) -> bool {
    !s.is_empty() && ws.windows(s.len()).any(|w| w == s)
}

/// `bash -c`, `sh -lc`, `zsh -ec`…: the script, when there is one.
fn shell_c_script(args: &[String]) -> Option<&str> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            return None;
        }
        if a.starts_with('-') && !a.starts_with("--") && a[1..].contains('c') {
            return args.get(i + 1).map(String::as_str);
        }
        if a == "-o" || a == "+o" || a == "--rcfile" || a == "--init-file" {
            i += 2;
            continue;
        }
        if !a.starts_with('-') && !a.starts_with('+') {
            return None;
        }
        i += 1;
    }
    None
}

/// A finding builder.
struct Hit {
    code: &'static str,
    severity: Severity,
    title: String,
    fix: &'static str,
}

fn hit(
    code: &'static str,
    severity: Severity,
    title: impl Into<String>,
    fix: &'static str,
) -> Option<Hit> {
    Some(Hit {
        code,
        severity,
        title: title.into(),
        fix,
    })
}

const FIX_LOCAL_DB: &str =
    "Run it only against a disposable local database (check DATABASE_URL first), or ask the user to run it.";

fn analyze_exec(ctx: &Ctx, mut e: Exec, depth: usize, out: &mut Vec<Finding>) {
    // Unwrap launchers.
    for _ in 0..12 {
        if e.argv.is_empty() {
            return;
        }
        let name = prog(&e.argv[0]);
        let args: Vec<String> = e.argv[1..].to_vec();
        let next: Option<Vec<String>> = match name.as_str() {
            "sudo" | "doas" => {
                let i = skip_opts(
                    &args,
                    &[
                        "-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "--user", "--group",
                    ],
                );
                Some(args[i..].to_vec())
            }
            "env" => {
                let mut i = 0;
                let mut assigns = Vec::new();
                while i < args.len() {
                    let a = &args[i];
                    if a == "-u" || a == "-C" || a == "--unset" || a == "--chdir" {
                        i += 2;
                    } else if a == "-S" || a == "--split-string" {
                        if let Some(s) = args.get(i + 1) {
                            let mut rest = vec![s.clone()];
                            rest.extend(args[i + 2..].iter().cloned());
                            analyze_script(
                                ctx,
                                &rest.join(" "),
                                &e.layers,
                                &e.context,
                                depth + 1,
                                out,
                            );
                        }
                        return;
                    } else if a.starts_with('-') {
                        i += 1;
                    } else if let Some((k, v)) =
                        a.split_once('=').filter(|(k, _)| shell::is_name(k))
                    {
                        assigns.push((k.to_string(), v.to_string()));
                        i += 1;
                    } else {
                        break;
                    }
                }
                push_assigns(&mut e, assigns);
                Some(args[i..].to_vec())
            }
            "nice" | "ionice" | "stdbuf" | "chrt" | "taskset" => {
                let i = skip_opts(&args, &["-n", "-c", "-o", "-e", "-i", "-p", "--adjustment"]);
                Some(args[i..].to_vec())
            }
            "nohup" | "time" | "command" | "builtin" | "exec" | "caffeinate" | "unbuffer" => {
                let i = skip_opts(&args, &["-w", "-t"]);
                Some(args[i..].to_vec())
            }
            "timeout" | "gtimeout" => {
                let i = skip_opts(&args, &["-s", "-k", "--signal", "--kill-after"]);
                Some(
                    args.get(i + 1..)
                        .map(<[String]>::to_vec)
                        .unwrap_or_default(),
                )
            }
            "watch" => {
                let i = skip_opts(&args, &["-n", "-d", "--interval"]);
                Some(args[i..].to_vec())
            }
            "xargs" => {
                let i = skip_opts(
                    &args,
                    &[
                        "-I",
                        "-i",
                        "-n",
                        "-P",
                        "-d",
                        "-L",
                        "-E",
                        "-s",
                        "-a",
                        "--max-args",
                        "--max-procs",
                        "--delimiter",
                    ],
                );
                e.stdin = Some(Input::Unknown("xargs".into()));
                Some(args[i..].to_vec())
            }
            "npx" | "bunx" | "pnpx" | "uvx" | "pipx" => {
                let mut a = args.clone();
                if name == "pipx" {
                    if a.first().map(String::as_str) != Some("run") {
                        None
                    } else {
                        a.remove(0);
                        let i = skip_opts(&a, &["--spec", "--python"]);
                        Some(a[i..].to_vec())
                    }
                } else {
                    if let Some(script) = flag_value(&a, &["-c", "--call"]) {
                        analyze_script(ctx, script, &e.layers, &e.context, depth + 1, out);
                        return;
                    }
                    let i = skip_opts(
                        &a,
                        &["-p", "--package", "--from", "--with", "--python", "--cache"],
                    );
                    let mut rest = a.split_off(i);
                    if let Some(first) = rest.first_mut() {
                        *first = strip_version(first).to_string();
                    }
                    Some(rest)
                }
            }
            "npm" => match args.first().map(String::as_str) {
                Some("exec" | "x") => {
                    let mut a = args[1..].to_vec();
                    if let Some(script) = flag_value(&a, &["-c", "--call"]) {
                        analyze_script(ctx, script, &e.layers, &e.context, depth + 1, out);
                        return;
                    }
                    let i = skip_opts(&a, &["-p", "--package", "-w", "--workspace"]);
                    let mut rest = a.split_off(i);
                    if let Some(first) = rest.first_mut() {
                        *first = strip_version(first).to_string();
                    }
                    Some(rest)
                }
                Some("run" | "run-script" | "rum" | "urn") => {
                    run_package_script(ctx, &e, &args[1..], depth, out);
                    return;
                }
                Some("start" | "test" | "t" | "restart" | "stop") => {
                    let script = match args[0].as_str() {
                        "t" => "test",
                        s => s,
                    };
                    let mut a = vec![script.to_string()];
                    a.extend(args[1..].iter().cloned());
                    run_package_script(ctx, &e, &a, depth, out);
                    return;
                }
                _ => None,
            },
            "pnpm" | "yarn" | "bun" => {
                let i = skip_opts(
                    &args,
                    &[
                        "--filter",
                        "-F",
                        "-C",
                        "--dir",
                        "--cwd",
                        "-w",
                        "--workspace",
                    ],
                );
                let a = &args[i..];
                match a.first().map(String::as_str) {
                    None => None,
                    Some("exec" | "dlx" | "x") => {
                        let rest = &a[1..];
                        let j = skip_opts(rest, &["-p", "--package"]);
                        let mut r = rest[j..].to_vec();
                        if let Some(first) = r.first_mut() {
                            *first = strip_version(first).to_string();
                        }
                        Some(r)
                    }
                    Some("run" | "run-script") => {
                        let rest = &a[1..];
                        if !run_package_script(ctx, &e, rest, depth, out) {
                            // `bun run prisma …` / `yarn run prisma …`: a bin.
                            Some(rest.to_vec())
                        } else {
                            return;
                        }
                    }
                    Some(
                        "install" | "i" | "add" | "remove" | "rm" | "update" | "up" | "upgrade"
                        | "init" | "create" | "link" | "unlink" | "publish" | "pack" | "outdated"
                        | "why" | "list" | "ls" | "info" | "config" | "store" | "cache" | "audit"
                        | "build" | "help" | "--version" | "-v",
                    ) => None,
                    Some(_) => {
                        // A script of that name, else a bin (`pnpm prisma …`).
                        if run_package_script(ctx, &e, a, depth, out) {
                            return;
                        }
                        Some(a.to_vec())
                    }
                }
            }
            "dotenv" => {
                // dotenv-cli: -e FILE (repeatable), -c [ENV], -v K=V, --.
                let mut i = 0;
                let mut files = Vec::new();
                let mut assigns = Vec::new();
                let mut cascade: Option<String> = None;
                while i < args.len() {
                    let a = &args[i];
                    match a.as_str() {
                        "--" => {
                            i += 1;
                            break;
                        }
                        "-e" => {
                            if let Some(f) = args.get(i + 1) {
                                files.push(f.clone());
                            }
                            i += 2;
                        }
                        "-v" => {
                            if let Some((k, v)) = args.get(i + 1).and_then(|s| s.split_once('=')) {
                                assigns.push((k.to_string(), v.to_string()));
                            }
                            i += 2;
                        }
                        "-c" => match args.get(i + 1) {
                            Some(v) if !v.starts_with('-') && !is_known_tool(v) => {
                                cascade = Some(v.clone());
                                i += 2;
                            }
                            _ => {
                                cascade = Some(String::new());
                                i += 1;
                            }
                        },
                        "-p" => i += 2,
                        s if s.starts_with('-') => i += 1,
                        _ => break,
                    }
                }
                if files.is_empty() {
                    files.push(".env".into());
                }
                if let Some(c) = cascade.filter(|c| !c.is_empty()) {
                    files.insert(0, format!(".env.{c}"));
                    files.insert(0, format!(".env.{c}.local"));
                }
                push_assigns(&mut e, assigns);
                push_env_files(ctx, &mut e, &files);
                Some(args[i..].to_vec())
            }
            "dotenvx" if args.first().map(String::as_str) == Some("run") => {
                let a = &args[1..];
                let mut i = 0;
                let mut files = Vec::new();
                let mut assigns = Vec::new();
                while i < a.len() {
                    match a[i].as_str() {
                        "--" => {
                            i += 1;
                            break;
                        }
                        "-f" | "--env-file" => {
                            if let Some(f) = a.get(i + 1) {
                                files.push(f.clone());
                            }
                            i += 2;
                        }
                        "--env" | "-e" => {
                            if let Some((k, v)) = a.get(i + 1).and_then(|s| s.split_once('=')) {
                                assigns.push((k.to_string(), v.to_string()));
                            }
                            i += 2;
                        }
                        s if s.starts_with('-') => i += 1,
                        _ => break,
                    }
                }
                if files.is_empty() {
                    files.push(".env".into());
                }
                push_assigns(&mut e, assigns);
                push_env_files(ctx, &mut e, &files);
                Some(a[i..].to_vec())
            }
            "env-cmd" => {
                let mut i = 0;
                let mut files = vec![];
                while i < args.len() {
                    match args[i].as_str() {
                        "-f" | "--file" => {
                            if let Some(f) = args.get(i + 1) {
                                files.push(f.clone());
                            }
                            i += 2;
                        }
                        "-e" | "--environments" => {
                            if let Some(env) = args.get(i + 1) {
                                for n in env.split(',') {
                                    if target::is_prod_env_name(n) {
                                        e.context.push(target::env_target(
                                            &format!("env-cmd -e {n}"),
                                            "the command line",
                                        ));
                                    }
                                }
                            }
                            i += 2;
                        }
                        "-r" | "--rc-file" => i += 2,
                        "--" => {
                            i += 1;
                            break;
                        }
                        s if s.starts_with('-') => i += 1,
                        _ => break,
                    }
                }
                if files.is_empty() {
                    files.push(".env".into());
                }
                push_env_files(ctx, &mut e, &files);
                Some(args[i..].to_vec())
            }
            "cross-env" => {
                let mut i = 0;
                let mut assigns = Vec::new();
                while let Some((k, v)) = args
                    .get(i)
                    .and_then(|a| a.split_once('='))
                    .filter(|(k, _)| shell::is_name(k))
                {
                    assigns.push((k.to_string(), v.to_string()));
                    i += 1;
                }
                push_assigns(&mut e, assigns);
                Some(args[i..].to_vec())
            }
            "cross-env-shell" => {
                analyze_script(ctx, &args.join(" "), &e.layers, &e.context, depth + 1, out);
                return;
            }
            "doppler" | "infisical" | "op" | "railway" | "vercel" | "netlify" | "aws-vault"
            | "teller" | "chamber"
                if matches!(args.first().map(String::as_str), Some("run" | "exec")) =>
            {
                let a = &args[1..];
                // The environment the secrets come from.
                for (names, what) in [
                    (&["-c", "--config"][..], "doppler config"),
                    (&["--env", "-e", "--environment"][..], "environment"),
                    (&["--profile"][..], "profile"),
                ] {
                    if let Some(v) = flag_value(a, names) {
                        if target::is_prod_env_name(v) || v.to_ascii_lowercase().contains("prod") {
                            e.context
                                .push(target::env_target(&format!("{what} {v}"), &name));
                        }
                    }
                }
                if let Some(f) = flag_value(a, &["--env-file"]) {
                    push_env_files(ctx, &mut e, &[f.to_string()]);
                }
                if name == "aws-vault" || name == "chamber" {
                    // `aws-vault exec PROFILE -- cmd`
                    if let Some(p) = a.iter().find(|x| !x.starts_with('-')) {
                        if p.to_ascii_lowercase().contains("prod") {
                            e.context
                                .push(target::env_target(&format!("profile {p}"), &name));
                        }
                    }
                }
                match a.iter().position(|x| x == "--") {
                    Some(p) => Some(a[p + 1..].to_vec()),
                    None => {
                        let i = skip_opts(
                            a,
                            &[
                                "-c",
                                "--config",
                                "-p",
                                "--project",
                                "--env",
                                "-e",
                                "--environment",
                                "--env-file",
                                "--profile",
                                "--path",
                                "--token",
                                "-s",
                                "--service",
                            ],
                        );
                        let mut rest = a[i..].to_vec();
                        if name == "aws-vault" && !rest.is_empty() {
                            rest.remove(0);
                        }
                        Some(rest)
                    }
                }
            }
            "uv" | "poetry" | "pipenv" | "pdm" | "hatch" | "rye" | "conda" | "mamba"
            | "micromamba"
                if args.first().map(String::as_str) == Some("run") =>
            {
                let a = &args[1..];
                if let Some(f) = flag_value(a, &["--env-file"]) {
                    push_env_files(ctx, &mut e, &[f.to_string()]);
                }
                let i = skip_opts(
                    a,
                    &[
                        "--with",
                        "--python",
                        "-p",
                        "--project",
                        "--directory",
                        "--env-file",
                        "--package",
                        "-n",
                        "--name",
                        "--prefix",
                        "--extra",
                        "--group",
                        "-e",
                    ],
                );
                Some(a[i..].to_vec())
            }
            "bundle" | "bundler" if args.first().map(String::as_str) == Some("exec") => {
                Some(args[1..].to_vec())
            }
            "python" | "python3" | "py" | "pypy3" => python_next(ctx, &mut e, &args, depth, out),
            n if n.starts_with("python3.") => python_next(ctx, &mut e, &args, depth, out),
            "php" => {
                let i = skip_opts(&args, &["-d", "-c"]);
                let a = &args[i..];
                match a.first().map(|s| prog(s)).as_deref() {
                    Some("artisan") => {
                        let mut r = vec!["artisan".to_string()];
                        r.extend(a[1..].iter().cloned());
                        Some(r)
                    }
                    Some("console") => {
                        let mut r = vec!["symfony-console".to_string()];
                        r.extend(a[1..].iter().cloned());
                        Some(r)
                    }
                    _ => None,
                }
            }
            "manage.py" => {
                let mut r = vec!["django-admin".to_string()];
                r.extend(args.iter().cloned());
                Some(r)
            }
            "symfony" if args.first().map(String::as_str) == Some("console") => {
                let mut r = vec!["symfony-console".to_string()];
                r.extend(args[1..].iter().cloned());
                Some(r)
            }
            "console" if e.argv[0].contains("bin/") => {
                let mut r = vec!["symfony-console".to_string()];
                r.extend(args.iter().cloned());
                Some(r)
            }
            "bash" | "sh" | "zsh" | "dash" | "ksh" | "ash" | "fish" | "busybox" => {
                let a = if name == "busybox" {
                    args.get(1..).map(<[String]>::to_vec).unwrap_or_default()
                } else {
                    args.clone()
                };
                if let Some(script) = shell_c_script(&a) {
                    analyze_script(ctx, script, &e.layers, &e.context, depth + 1, out);
                } else if a.iter().all(|x| x.starts_with('-')) {
                    if let Some(Input::Text(t)) = &e.stdin {
                        analyze_script(ctx, t, &e.layers, &e.context, depth + 1, out);
                    }
                }
                return;
            }
            "eval" => {
                analyze_script(ctx, &args.join(" "), &e.layers, &e.context, depth + 1, out);
                return;
            }
            "docker" | "podman" | "nerdctl" => docker_next(ctx, &mut e, &args, out),
            "docker-compose" | "podman-compose" => compose_next(ctx, &mut e, &args, out),
            "kubectl" | "oc" | "kubecolor" => {
                if !args.iter().any(|a| a == "exec") {
                    None
                } else {
                    let ctxv = flag_value(&args, &["--context", "--cluster"]).map(String::from);
                    let ns = flag_value(&args, &["-n", "--namespace"]).map(String::from);
                    let label = ctxv
                        .clone()
                        .or(ns.clone())
                        .unwrap_or_else(|| "current kubectl context".into());
                    let class = if [ctxv.as_deref(), ns.as_deref()].iter().flatten().any(|v| {
                        target::is_prod_env_name(v)
                            || v.to_ascii_lowercase()
                                .split(['-', '_', '.'])
                                .any(|t| matches!(t, "prod" | "production" | "prd"))
                    }) {
                        Class::Prod
                    } else {
                        Class::Remote
                    };
                    e.context.push(Target {
                        host: format!("kubernetes {label}"),
                        database: None,
                        class,
                        source: "kubectl exec".into(),
                    });
                    args.iter()
                        .position(|a| a == "--")
                        .map(|p| args[p + 1..].to_vec())
                }
            }
            "ssh" | "mosh" => {
                let with_value = [
                    "-p", "-i", "-l", "-o", "-J", "-F", "-L", "-R", "-D", "-W", "-E", "-c", "-m",
                    "-b", "-e", "-S", "-O", "-Q", "-w", "-B", "-I",
                ];
                let mut i = 0;
                while i < args.len() {
                    let a = &args[i];
                    if a == "--" {
                        i += 1;
                        break;
                    }
                    if !a.starts_with('-') {
                        break;
                    }
                    if with_value.contains(&a.as_str()) {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                let Some(host) = args.get(i) else { return };
                let host = host.rsplit('@').next().unwrap_or(host).to_string();
                let rest = &args[i + 1..];
                if rest.is_empty() {
                    return;
                }
                e.context
                    .push(target::host_target(&host, None, "ssh", ctx.cfg));
                analyze_script(ctx, &rest.join(" "), &e.layers, &e.context, depth + 1, out);
                return;
            }
            "heroku" if args.first().map(String::as_str) == Some("run") => {
                let app = flag_value(&args, &["-a", "--app"])
                    .unwrap_or("app")
                    .to_string();
                e.context.push(platform_target("heroku app", &app));
                let i = skip_opts(
                    &args[1..],
                    &[
                        "-a", "--app", "-r", "--remote", "-s", "--size", "-e", "--env", "--type",
                    ],
                );
                let rest = &args[1 + i..];
                analyze_script(ctx, &rest.join(" "), &e.layers, &e.context, depth + 1, out);
                return;
            }
            "fly" | "flyctl" if args.iter().any(|a| a == "ssh") => {
                if let Some(c) = flag_value(&args, &["-C", "--command"]) {
                    let app = flag_value(&args, &["-a", "--app"])
                        .unwrap_or("app")
                        .to_string();
                    e.context.push(platform_target("fly app", &app));
                    analyze_script(ctx, c, &e.layers, &e.context, depth + 1, out);
                }
                return;
            }
            _ => None,
        };
        match next {
            Some(n) if !n.is_empty() => e.argv = n,
            Some(_) => return,
            None => break,
        }
    }
    detect_tool(ctx, &e, out);
}

fn is_known_tool(s: &str) -> bool {
    matches!(
        prog(s).as_str(),
        "prisma"
            | "drizzle-kit"
            | "rails"
            | "rake"
            | "knex"
            | "sequelize"
            | "sequelize-cli"
            | "typeorm"
            | "node"
            | "npm"
            | "npx"
    )
}

fn push_assigns(e: &mut Exec, assigns: Vec<(String, String)>) {
    if !assigns.is_empty() {
        e.layers.insert(
            0,
            EnvLayer {
                vars: assigns,
                source: "the command's environment".into(),
                prod_file: false,
            },
        );
    }
}

fn push_env_files(ctx: &Ctx, e: &mut Exec, files: &[String]) {
    // The first file listed wins in dotenv-cli; keep that precedence.
    let mut layers: Vec<EnvLayer> = files
        .iter()
        .map(|f| target::named_env_layer(&ctx.cwd, f))
        .collect();
    for l in &layers {
        if l.prod_file {
            e.context
                .push(target::env_target(&l.source, "the env file name"));
        }
    }
    let pos = e
        .layers
        .iter()
        .position(|l| l.source != "the command's environment")
        .unwrap_or(e.layers.len());
    for (k, l) in layers.drain(..).enumerate() {
        e.layers.insert(pos + k, l);
    }
}

fn platform_target(kind: &str, name: &str) -> Target {
    let lower = name.to_ascii_lowercase();
    let prod = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| matches!(t, "prod" | "production" | "prd" | "live"));
    Target {
        host: format!("{kind} {name}"),
        database: None,
        class: if prod { Class::Prod } else { Class::Remote },
        source: kind.to_string(),
    }
}

/// `npm run X` and friends: the script's command from package.json.
/// Returns whether a script was found.
fn run_package_script(
    ctx: &Ctx,
    e: &Exec,
    args: &[String],
    depth: usize,
    out: &mut Vec<Finding>,
) -> bool {
    let i = skip_opts(args, &["-w", "--workspace", "--prefix"]);
    let Some(name) = args.get(i) else {
        return false;
    };
    let extra = &args[i + 1..];
    let extra: Vec<&String> = extra.iter().filter(|a| a.as_str() != "--").collect();
    let Ok(text) = std::fs::read_to_string(ctx.cwd.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    let Some(script) = json
        .get("scripts")
        .and_then(|s| s.get(name))
        .and_then(Value::as_str)
    else {
        return false;
    };
    let mut full = script.to_string();
    for a in extra {
        full.push(' ');
        full.push_str(&shell_quote(a));
    }
    let before = out.len();
    analyze_script(ctx, &full, &e.layers, &e.context, depth + 1, out);
    for f in &mut out[before..] {
        f.what = format!(
            "{} (package.json script \"{name}\": {})",
            f.what,
            target::redact(script)
        );
    }
    true
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn python_next(
    ctx: &Ctx,
    e: &mut Exec,
    args: &[String],
    depth: usize,
    out: &mut Vec<Finding>,
) -> Option<Vec<String>> {
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-m" => {
                return args.get(i + 1..).map(<[String]>::to_vec);
            }
            "-c" => {
                if let Some(code) = args.get(i + 1) {
                    python_code(ctx, e, code, out);
                }
                return None;
            }
            "-W" | "-X" => i += 2,
            s if s.starts_with('-') => i += 1,
            s => {
                if prog(s) == "manage.py" {
                    let mut r = vec!["django-admin".to_string()];
                    r.extend(args[i + 1..].iter().cloned());
                    return Some(r);
                }
                let _ = depth;
                return None;
            }
        }
    }
    None
}

/// `python -c "…"`: SQLAlchemy `drop_all`, Django `.delete()` on all rows.
fn python_code(ctx: &Ctx, e: &Exec, code: &str, out: &mut Vec<Finding>) {
    if !ctx.cfg.checks.orm {
        return;
    }
    let c = code.replace(' ', "");
    if c.contains(".drop_all(") || c.contains("drop_database(") {
        push(
            ctx,
            e,
            out,
            Hit {
                code: "VG-196",
                severity: Severity::Critical,
                title: "SQLAlchemy drop_all / drop_database drops every table".into(),
                fix: FIX_LOCAL_DB,
            },
            Kind::Orm,
            true,
        );
    } else if c.contains(".objects.all().delete()") {
        push(
            ctx,
            e,
            out,
            Hit {
                code: "VG-124",
                severity: Severity::Medium,
                title: "Django .objects.all().delete() deletes every row".into(),
                fix: "Filter the queryset to the rows you mean.",
            },
            Kind::Orm,
            true,
        );
    }
}

fn docker_next(
    ctx: &Ctx,
    e: &mut Exec,
    args: &[String],
    out: &mut Vec<Finding>,
) -> Option<Vec<String>> {
    let gi = skip_opts(
        args,
        &[
            "-H",
            "--host",
            "--context",
            "-c",
            "--config",
            "-l",
            "--log-level",
        ],
    );
    let a = &args[gi..];
    match a.first().map(String::as_str) {
        Some("exec") => {
            let rest = &a[1..];
            let i = skip_opts(
                rest,
                &[
                    "-e",
                    "--env",
                    "-u",
                    "--user",
                    "-w",
                    "--workdir",
                    "--env-file",
                    "--detach-keys",
                ],
            );
            let container = rest.get(i)?;
            e.context
                .push(target::host_target(container, None, "docker exec", ctx.cfg));
            Some(rest[i + 1..].to_vec())
        }
        Some("compose") => compose_next(ctx, e, &a[1..], out),
        Some("run") => {
            let rest = &a[1..];
            let i = skip_opts(
                rest,
                &[
                    "-e",
                    "--env",
                    "-v",
                    "--volume",
                    "-p",
                    "--publish",
                    "--name",
                    "--network",
                    "--net",
                    "--entrypoint",
                    "-w",
                    "--workdir",
                    "-u",
                    "--user",
                    "--env-file",
                    "-l",
                    "--label",
                    "--platform",
                    "--mount",
                    "-m",
                    "--memory",
                    "--cpus",
                    "--add-host",
                    "-h",
                    "--hostname",
                    "--pull",
                    "--restart",
                    "--link",
                ],
            );
            let image = rest.get(i)?;
            let image_name = image
                .rsplit('/')
                .next()
                .unwrap_or(image)
                .split([':', '@'])
                .next()
                .unwrap_or(image)
                .to_string();
            let cmd = rest[i + 1..].to_vec();
            if matches!(
                image_name.as_str(),
                "flyway" | "liquibase" | "dbmate" | "migrate" | "atlas" | "sqitch"
            ) && cmd.first().map(|c| prog(c) != image_name).unwrap_or(true)
            {
                let mut r = vec![image_name];
                r.extend(cmd);
                return Some(r);
            }
            Some(cmd)
        }
        Some("volume") => {
            let rest = &a[1..];
            match rest.first().map(String::as_str) {
                Some("rm" | "remove") => {
                    let names: Vec<&str> = words(&rest[1..]);
                    if names.iter().any(|n| looks_like_db_volume(n)) {
                        push_platform(
                            ctx,
                            e,
                            out,
                            "VG-405",
                            Severity::Medium,
                            format!("docker volume rm {} deletes database data", names.join(" ")),
                            "Keep the volume, or confirm it holds only disposable data.",
                        );
                    }
                }
                Some("prune") => {
                    push_platform(
                        ctx,
                        e,
                        out,
                        "VG-405",
                        Severity::Medium,
                        "docker volume prune deletes the data of every unused volume",
                        "Remove only the volumes you mean, by name.",
                    );
                }
                _ => {}
            }
            None
        }
        Some("system")
            if a.get(1).map(String::as_str) == Some("prune") && flag(a, &["--volumes"]) =>
        {
            push_platform(
                ctx,
                e,
                out,
                "VG-405",
                Severity::Medium,
                "docker system prune --volumes deletes the data of every unused volume",
                "Prune without --volumes.",
            );
            None
        }
        _ => None,
    }
}

fn looks_like_db_volume(n: &str) -> bool {
    let l = n.to_ascii_lowercase();
    [
        "pg",
        "postgres",
        "mysql",
        "maria",
        "mongo",
        "redis",
        "db",
        "data",
        "sql",
        "clickhouse",
    ]
    .iter()
    .any(|k| l.contains(k))
}

fn compose_next(
    ctx: &Ctx,
    e: &mut Exec,
    args: &[String],
    out: &mut Vec<Finding>,
) -> Option<Vec<String>> {
    let gi = skip_opts(
        args,
        &[
            "-f",
            "--file",
            "-p",
            "--project-name",
            "--profile",
            "--env-file",
            "--project-directory",
            "--ansi",
            "--parallel",
        ],
    );
    if let Some(f) = flag_value(&args[..gi], &["--env-file"]) {
        push_env_files(ctx, e, &[f.to_string()]);
    }
    let a = &args[gi..];
    match a.first().map(String::as_str) {
        Some("exec" | "run") => {
            let rest = &a[1..];
            let i = skip_opts(
                rest,
                &[
                    "-e",
                    "--env",
                    "-u",
                    "--user",
                    "-w",
                    "--workdir",
                    "--index",
                    "--entrypoint",
                    "-v",
                    "--volume",
                    "-p",
                    "--publish",
                    "--name",
                    "-l",
                    "--label",
                ],
            );
            let service = rest.get(i)?;
            e.context.push(target::host_target(
                service,
                None,
                "docker compose",
                ctx.cfg,
            ));
            Some(rest[i + 1..].to_vec())
        }
        Some("down") if flag(a, &["-v", "--volumes"]) => {
            push_platform(
                ctx,
                e,
                out,
                "VG-405",
                Severity::Medium,
                "docker compose down -v deletes the project's volumes (database data included)",
                "Run `docker compose down` without -v to keep the data.",
            );
            None
        }
        _ => None,
    }
}

/// Pushes a finding for the current command with its targets.
fn push(ctx: &Ctx, e: &Exec, out: &mut Vec<Finding>, h: Hit, kind: Kind, orm_env: bool) {
    let targets = orm_targets(ctx, e, orm_env);
    push_with(e, out, h, kind, targets);
}

fn push_with(e: &Exec, out: &mut Vec<Finding>, h: Hit, kind: Kind, mut targets: Vec<Target>) {
    targets.extend(e.context.iter().cloned());
    dedup(&mut targets);
    out.push(Finding {
        code: h.code.to_string(),
        severity: h.severity,
        kind,
        title: h.title,
        what: e.shown(),
        fix: h.fix.to_string(),
        targets,
        preset: None,
    });
}

fn push_platform(
    ctx: &Ctx,
    e: &Exec,
    out: &mut Vec<Finding>,
    code: &'static str,
    severity: Severity,
    title: impl Into<String>,
    fix: &'static str,
) {
    if !ctx.cfg.checks.platform {
        return;
    }
    push_with(
        e,
        out,
        Hit {
            code,
            severity,
            title: title.into(),
            fix,
        },
        Kind::Platform,
        Vec::new(),
    );
}

fn dedup(t: &mut Vec<Target>) {
    let mut seen = Vec::<(String, Option<String>)>::new();
    t.retain(|x| {
        let k = (x.host.clone(), x.database.clone());
        if seen.contains(&k) {
            false
        } else {
            seen.push(k);
            true
        }
    });
}

/// Targets an ORM or migration tool reaches: the command's own URL flags are
/// read by the caller; here, the environment (command, env files, the
/// agent's environment, then the project's `.env` files when `project`).
fn orm_targets(ctx: &Ctx, e: &Exec, project: bool) -> Vec<Target> {
    let mut out = Vec::new();
    let mut layers: Vec<EnvLayer> = e.layers.clone();
    layers.push(ctx.process_layer());
    if project {
        layers.extend(ctx.project_layers().iter().cloned());
    }
    // URL variables: the first layer that sets each one.
    let mut url_found = false;
    for v in target::URL_VARS.iter().copied() {
        if let Some(l) = layers.iter().find(|l| l.get(v).is_some()) {
            let single = EnvLayer {
                vars: vec![(v.to_string(), l.get(v).unwrap_or_default().to_string())],
                source: l.source.clone(),
                prod_file: false,
            };
            let t = target::targets_from_layer(&single, ctx.cfg, &[v]);
            url_found |= !t.is_empty();
            out.extend(t);
        }
    }
    for (hv, dv) in target::HOST_VARS {
        if url_found {
            break;
        }
        if let Some(l) = layers.iter().find(|l| l.get(hv).is_some()) {
            let h = l.get(hv).unwrap_or_default();
            let db = l.get(dv);
            out.push(target::host_target(
                h,
                db,
                &format!("{hv} in {}", l.source),
                ctx.cfg,
            ));
        }
    }
    // Environment names and production env files, from any layer.
    for l in &layers {
        for v in target::ENV_NAME_VARS {
            if let Some(val) = l.get(v) {
                if target::is_prod_env_name(val) {
                    out.push(target::env_target(&format!("{v}={val}"), &l.source));
                }
            }
        }
    }
    out
}

/// A `--env production` / `-e production` style flag.
fn env_flag_target(args: &[String], names: &[&str]) -> Option<Target> {
    let v = flag_value(args, names)?;
    target::is_prod_env_name(v)
        .then(|| target::env_target(&format!("{} {v}", names[0]), "the command line"))
}

fn url_flag_target(ctx: &Ctx, args: &[String], names: &[&str]) -> Option<Target> {
    let v = flag_value(args, names)?;
    target::conn_target(v, names[0], ctx.cfg)
}

fn detect_tool(ctx: &Ctx, e: &Exec, out: &mut Vec<Finding>) {
    let name = prog(&e.argv[0]);
    let args: &[String] = &e.argv[1..];
    let cfg = ctx.cfg;
    // SQL clients.
    if cfg.checks.sql {
        let handled = match name.as_str() {
            "psql" => {
                client_psql(ctx, e, args, out);
                true
            }
            "mysql" | "mariadb" => {
                client_mysql(ctx, e, args, out);
                true
            }
            "sqlite3" | "sqlite" | "libsql" => {
                client_sqlite(ctx, e, args, out);
                true
            }
            "sqlcmd" => {
                client_sqlcmd(ctx, e, args, out);
                true
            }
            "duckdb" => {
                client_duckdb(ctx, e, args, out);
                true
            }
            "clickhouse-client" | "clickhouse-local" => {
                client_clickhouse(ctx, e, args, out);
                true
            }
            "clickhouse"
                if matches!(args.first().map(String::as_str), Some("client" | "local")) =>
            {
                client_clickhouse(ctx, e, &args[1..], out);
                true
            }
            "cockroach" if args.first().map(String::as_str) == Some("sql") => {
                client_cockroach(ctx, e, &args[1..], out);
                true
            }
            _ => false,
        };
        if handled {
            return;
        }
    }
    match name.as_str() {
        "mongosh" | "mongo" => client_mongo(ctx, e, args, out),
        "redis-cli" | "valkey-cli" | "keydb-cli" => client_redis(ctx, e, args, out),
        "dropdb" if cfg.checks.orm => {
            let items = scan(
                args,
                &[
                    "-h",
                    "--host",
                    "-p",
                    "--port",
                    "-U",
                    "--username",
                    "--maintenance-db",
                ],
                true,
            );
            let Some(db) = positionals(&items).last().map(|s| s.to_string()) else {
                return;
            };
            let db = Some(db);
            let mut t = pg_targets(ctx, e, &items, db.as_deref());
            if t.is_empty() {
                if let Some(d) = &db {
                    t.push(target::host_target("localhost", Some(d), "dropdb", cfg));
                }
            }
            push_with(
                e,
                out,
                Hit {
                    code: "VG-201",
                    severity: Severity::Critical,
                    title: format!("dropdb drops the database {}", db.as_deref().unwrap_or("")),
                    fix: FIX_LOCAL_DB,
                },
                Kind::Orm,
                t,
            );
        }
        "dropuser" if cfg.checks.orm => {
            let items = scan(
                args,
                &["-h", "--host", "-p", "--port", "-U", "--username"],
                true,
            );
            let t = pg_targets(ctx, e, &items, None);
            push_with(
                e,
                out,
                Hit {
                    code: "VG-207",
                    severity: Severity::Medium,
                    title: "dropuser removes a database role".into(),
                    fix: "Confirm the role is unused, or ask the user.",
                },
                Kind::Orm,
                t,
            );
        }
        "mysqladmin" | "mariadb-admin" if cfg.checks.orm => {
            let items = scan(
                args,
                &[
                    "-h", "--host", "-P", "--port", "-u", "--user", "-S", "--socket",
                ],
                true,
            );
            let pos = positionals(&items);
            if let Some(p) = pos.iter().position(|w| w.eq_ignore_ascii_case("drop")) {
                let db = pos.get(p + 1).copied();
                let t = mysql_targets(ctx, e, &items, db);
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-202",
                        severity: Severity::Critical,
                        title: format!("mysqladmin drop {} drops a database", db.unwrap_or("")),
                        fix: FIX_LOCAL_DB,
                    },
                    Kind::Orm,
                    t,
                );
            }
        }
        "pg_restore" if cfg.checks.orm => {
            let items = scan(
                args,
                &[
                    "-d",
                    "--dbname",
                    "-h",
                    "--host",
                    "-p",
                    "--port",
                    "-U",
                    "--username",
                    "-f",
                    "--file",
                    "-n",
                    "--schema",
                    "-t",
                    "--table",
                    "-j",
                    "--jobs",
                    "-F",
                    "--format",
                    "-L",
                    "--use-list",
                    "-I",
                    "--index",
                    "-P",
                    "--function",
                    "-T",
                    "--trigger",
                    "-S",
                    "--superuser",
                    "--role",
                ],
                true,
            );
            if has(&items, &["-c", "--clean"]) && has(&items, &["-d", "--dbname"]) {
                let db = opt(&items, &["-d", "--dbname"]).first().copied();
                let mut t = pg_targets(ctx, e, &items, None);
                if let Some(d) = db {
                    if let Some(c) = target::conn_target(d, "--dbname", cfg) {
                        t.push(c);
                    }
                }
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-205",
                        severity: Severity::Critical,
                        title:
                            "pg_restore --clean drops every object it restores before recreating it"
                                .into(),
                        fix: "Restore into a new, empty database instead.",
                    },
                    Kind::Orm,
                    t,
                );
            }
        }
        "mongorestore" if cfg.checks.orm && flag(args, &["--drop"]) => {
            let t: Vec<Target> = flag_value(args, &["--uri", "--host", "-h"])
                .and_then(|v| {
                    target::conn_target(v, "--uri", cfg)
                        .or_else(|| Some(target::host_target(v, None, "--host", cfg)))
                })
                .into_iter()
                .collect();
            push_with(
                e,
                out,
                Hit {
                    code: "VG-206",
                    severity: Severity::Critical,
                    title: "mongorestore --drop drops each collection before restoring it".into(),
                    fix: "Restore into a new database instead.",
                },
                Kind::Orm,
                t,
            );
        }
        _ => {
            if cfg.checks.orm && orm(ctx, e, &name, args, out) {
                return;
            }
            if cfg.checks.platform {
                platform(ctx, e, &name, args, out);
            }
        }
    }
}

// ---------------------------------------------------------------- clients

/// An SQL source of a client invocation.
enum Src {
    Text(String, &'static str),
    File(String),
    Stdin,
}

fn read_sql_file(ctx: &Ctx, e: &Exec, f: &str) -> Option<String> {
    if let Some((_, t)) = e.virtual_files.iter().rev().find(|(p, _)| p == f) {
        return Some(t.clone());
    }
    let p = ctx.path(f);
    let meta = std::fs::metadata(&p).ok()?;
    if !meta.is_file() || meta.len() > MAX_SQL_FILE {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

/// Evaluates the SQL sources of one client command.
fn eval_sources(
    ctx: &Ctx,
    e: &Exec,
    srcs: Vec<Src>,
    dialect: &str,
    targets: Vec<Target>,
    out: &mut Vec<Finding>,
) {
    let mut srcs = srcs;
    if srcs.is_empty() {
        if e.stdin.is_some() {
            srcs.push(Src::Stdin);
        } else {
            return;
        }
    }
    let mut queue: std::collections::VecDeque<Src> = srcs.into();
    let mut includes = 0usize;
    while let Some(s) = queue.pop_front() {
        let (text, origin, migration) = match s {
            Src::Text(t, o) => (Some(t), o.to_string(), false),
            Src::File(f) => {
                let mig = crate::migration::is_migration(&f, ctx.migration_paths, Some(&ctx.cwd));
                (read_sql_file(ctx, e, &f), format!("file {f}"), mig)
            }
            Src::Stdin => match &e.stdin {
                Some(Input::Text(t)) => (Some(t.clone()), "standard input".into(), false),
                Some(Input::File(f)) => {
                    let mig =
                        crate::migration::is_migration(f, ctx.migration_paths, Some(&ctx.cwd));
                    (read_sql_file(ctx, e, f), format!("file {f}"), mig)
                }
                Some(Input::Unknown(p)) => (None, format!("the output of `{p}`"), false),
                None => continue,
            },
        };
        let text = text.filter(|t| !t.contains(SUBST));
        // Client include commands (`\i f`, `source f`, `.read f`): the
        // included files are checked too (one level, a few files).
        if let Some(t) = &text {
            for f in client_includes(t) {
                if includes < 16 {
                    includes += 1;
                    queue.push_back(Src::File(f));
                }
            }
        }
        match text {
            Some(t) => {
                if let Some(f) = sql::check(&t, dialect, migration) {
                    let mut targets = targets.clone();
                    targets.extend(e.context.iter().cloned());
                    dedup(&mut targets);
                    let preset = f.high.then_some(ctx.cfg.high_sql);
                    out.push(Finding {
                        title: format!(
                            "{} in SQL sent by {} ({origin}): {}",
                            f.title,
                            prog(&e.argv[0]),
                            f.preview
                        ),
                        code: f.code,
                        severity: f.severity,
                        kind: Kind::Sql,
                        what: e.shown(),
                        fix: fix_text(&f.fix),
                        targets,
                        preset,
                    });
                }
            }
            None => {
                let mut targets = targets.clone();
                targets.extend(e.context.iter().cloned());
                dedup(&mut targets);
                out.push(Finding {
                    code: "VG-305".into(),
                    severity: Severity::Sensitive,
                    kind: Kind::Sql,
                    title: format!(
                        "SQL that vericto guard cannot read ({origin}) sent by {}",
                        prog(&e.argv[0])
                    ),
                    what: e.shown(),
                    fix: "Pass the SQL with -c/-e or a file the guard can read.".into(),
                    targets,
                    preset: Some(ctx.cfg.unverified_sql),
                });
            }
        }
    }
}

/// Files a client script includes: psql `\i` / `\ir` / `\include`,
/// mysql `source` / `\.`, sqlite3 `.read`.
fn client_includes(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for l in text.lines() {
        let t = l.trim();
        let rest = [
            "\\include_relative ",
            "\\include ",
            "\\ir ",
            "\\i ",
            "\\. ",
            ".read ",
            "source ",
            "SOURCE ",
        ]
        .iter()
        .find_map(|p| t.strip_prefix(p));
        if let Some(f) = rest {
            let f = f
                .trim()
                .trim_end_matches(';')
                .trim_matches(|c| c == '\'' || c == '"');
            if !f.is_empty() {
                out.push(f.to_string());
            }
        }
    }
    out
}

/// The engine's suggested fix as advice: a rewritten statement is quoted as
/// an example, prose is kept as it is.
fn fix_text(fix: &str) -> String {
    let first = fix.split_whitespace().next().unwrap_or("");
    if fix.is_empty() {
        "Rewrite the statement so it only touches the rows you mean.".into()
    } else if matches!(
        first,
        "DELETE"
            | "UPDATE"
            | "SELECT"
            | "INSERT"
            | "ALTER"
            | "DROP"
            | "TRUNCATE"
            | "WITH"
            | "CREATE"
            | "MERGE"
    ) {
        format!("e.g. `{fix}`")
    } else {
        fix.to_string()
    }
}

/// Targets of a libpq client: `-h`, `-d`/positional URI or conninfo, PGHOST.
fn pg_targets(
    ctx: &Ctx,
    e: &Exec,
    items: &[(String, Option<String>)],
    db_hint: Option<&str>,
) -> Vec<Target> {
    let cfg = ctx.cfg;
    let mut out = Vec::new();
    let mut db: Option<String> = opt(items, &["-d", "--dbname"])
        .first()
        .map(|s| s.to_string());
    let mut conn_found = false;
    for v in opt(items, &["-d", "--dbname"])
        .into_iter()
        .chain(positionals(items).into_iter().take(1))
    {
        if let Some(t) = resolve_conn(ctx, e, v, "the connection string") {
            out.push(t);
            conn_found = true;
        } else if db.is_none() && !v.starts_with('$') {
            db = Some(v.to_string());
        }
    }
    let db = db.or(db_hint.map(String::from));
    if let Some(h) = opt(items, &["-h", "--host"]).first() {
        out.push(target::host_target(h, db.as_deref(), "--host", cfg));
    } else if !conn_found {
        if let Some((h, src)) = e
            .var("PGHOST")
            .map(|(h, s)| (h.to_string(), s.to_string()))
            .or_else(|| (ctx.env)("PGHOST").map(|h| (h, "the agent's environment".into())))
        {
            let db = db
                .clone()
                .or_else(|| e.var("PGDATABASE").map(|(d, _)| d.to_string()));
            out.push(target::host_target(
                &h,
                db.as_deref(),
                &format!("PGHOST in {src}"),
                cfg,
            ));
        } else if let Some(d) = &db {
            if target::classify("localhost", Some(d), cfg) == Class::Prod {
                out.push(target::host_target(
                    "localhost",
                    Some(d),
                    "the database name",
                    cfg,
                ));
            }
        }
    }
    out
}

/// A connection string given as an argument, possibly a `$VAR` the guard
/// resolves from the command's layers or, as a hint, the project's `.env`.
fn resolve_conn(ctx: &Ctx, e: &Exec, v: &str, source: &str) -> Option<Target> {
    if let Some(t) = target::conn_target(v, source, ctx.cfg) {
        return Some(t);
    }
    let name = v.strip_prefix('$')?.trim_matches(|c| c == '{' || c == '}');
    if !shell::is_name(name) {
        return None;
    }
    if let Some((val, src)) = e.var(name) {
        return target::conn_target(val, &format!("{name} in {src}"), ctx.cfg);
    }
    for l in ctx.project_layers() {
        if let Some(val) = l.get(name) {
            return target::conn_target(val, &format!("{name} in {} (assumed)", l.source), ctx.cfg);
        }
    }
    None
}

fn client_psql(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    let items = scan(
        args,
        &[
            "-c",
            "--command",
            "-f",
            "--file",
            "-h",
            "--host",
            "-p",
            "--port",
            "-U",
            "--username",
            "-d",
            "--dbname",
            "-v",
            "--set",
            "--variable",
            "-o",
            "--output",
            "-L",
            "--log-file",
            "-P",
            "--pset",
            "-F",
            "--field-separator",
            "-R",
            "--record-separator",
            "-T",
            "--table-attr",
        ],
        true,
    );
    let mut srcs = Vec::new();
    for (k, v) in &items {
        match (k.as_str(), v) {
            ("-c" | "--command", Some(v)) => srcs.push(Src::Text(v.clone(), "-c")),
            ("-f" | "--file", Some(v)) if v != "-" => srcs.push(Src::File(v.clone())),
            ("-f" | "--file", Some(_)) => srcs.push(Src::Stdin),
            _ => {}
        }
    }
    let t = pg_targets(ctx, e, &items, None);
    eval_sources(ctx, e, srcs, "postgres", t, out);
}

fn mysql_targets(
    ctx: &Ctx,
    e: &Exec,
    items: &[(String, Option<String>)],
    db: Option<&str>,
) -> Vec<Target> {
    let cfg = ctx.cfg;
    let db = opt(items, &["-D", "--database"])
        .first()
        .copied()
        .or(db)
        .or_else(|| positionals(items).first().copied());
    if let Some(h) = opt(items, &["-h", "--host"]).first() {
        return vec![target::host_target(h, db, "--host", cfg)];
    }
    if let Some((h, src)) = e
        .var("MYSQL_HOST")
        .map(|(h, s)| (h.to_string(), s.to_string()))
        .or_else(|| (ctx.env)("MYSQL_HOST").map(|h| (h, "the agent's environment".into())))
    {
        return vec![target::host_target(
            &h,
            db,
            &format!("MYSQL_HOST in {src}"),
            cfg,
        )];
    }
    match db {
        Some(d) if target::classify("localhost", Some(d), cfg) == Class::Prod => {
            vec![target::host_target(
                "localhost",
                Some(d),
                "the database name",
                cfg,
            )]
        }
        _ => Vec::new(),
    }
}

fn client_mysql(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    let items = scan(
        args,
        &[
            "-e",
            "--execute",
            "-h",
            "--host",
            "-P",
            "--port",
            "-u",
            "--user",
            "-D",
            "--database",
            "-S",
            "--socket",
            "--default-character-set",
            "--defaults-file",
            "--login-path",
        ],
        true,
    );
    let mut srcs = Vec::new();
    for (k, v) in &items {
        if let ("-e" | "--execute", Some(v)) = (k.as_str(), v) {
            srcs.push(Src::Text(v.clone(), "-e"));
        }
    }
    let t = mysql_targets(ctx, e, &items, None);
    eval_sources(ctx, e, srcs, "mysql", t, out);
}

fn client_sqlite(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    let items = scan(
        args,
        &[
            "-cmd",
            "-init",
            "-separator",
            "-newline",
            "-nullvalue",
            "-vfs",
            "-maxsize",
            "-mmap",
            "-pagecache",
            "-lookaside",
            "-heap",
        ],
        false,
    );
    let mut srcs = Vec::new();
    for v in opt(&items, &["-cmd"]) {
        srcs.push(Src::Text(v.to_string(), "-cmd"));
    }
    if let Some(f) = opt(&items, &["-init"]).first() {
        srcs.push(Src::File(f.to_string()));
    }
    let pos = positionals(&items);
    let file = pos.first().copied().unwrap_or(":memory:");
    for sqltext in pos.iter().skip(1) {
        srcs.push(Src::Text(sqltext.to_string(), "an argument"));
    }
    let t = vec![Target {
        host: format!("sqlite file {file}"),
        database: None,
        class: if target::classify(file, None, ctx.cfg) == Class::Prod {
            Class::Prod
        } else {
            Class::Local
        },
        source: "the database file".into(),
    }];
    eval_sources(ctx, e, srcs, "sqlite", t, out);
}

fn client_sqlcmd(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    let items = scan(
        args,
        &[
            "-S",
            "-d",
            "-U",
            "-P",
            "-Q",
            "-q",
            "-i",
            "-o",
            "-H",
            "-t",
            "-l",
            "-s",
            "-w",
            "-v",
            "-f",
            "-c",
            "-a",
            "-A",
            "-W",
            "-h",
            "-K",
            "-M",
            "-N",
            "-G",
            "--server",
            "--database-name",
            "--user-name",
            "--query",
            "--initial-query",
            "--input-file",
        ],
        true,
    );
    let mut srcs = Vec::new();
    for (k, v) in &items {
        match (k.as_str(), v) {
            ("-Q" | "-q" | "--query" | "--initial-query", Some(v)) => {
                srcs.push(Src::Text(v.clone(), "-Q"))
            }
            ("-i" | "--input-file", Some(v)) => {
                for f in v.split(',') {
                    srcs.push(Src::File(f.to_string()));
                }
            }
            _ => {}
        }
    }
    let db = opt(&items, &["-d", "--database-name"]).first().copied();
    let mut t = Vec::new();
    if let Some(s) = opt(&items, &["-S", "--server"]).first() {
        let host = s
            .trim_start_matches("tcp:")
            .split([',', '\\'])
            .next()
            .unwrap_or(s);
        let host = if host == "." || host == "(local)" {
            "localhost"
        } else {
            host
        };
        t.push(target::host_target(host, db, "-S", ctx.cfg));
    }
    eval_sources(ctx, e, srcs, "mssql", t, out);
}

fn client_duckdb(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    let items = scan(
        args,
        &["-c", "-s", "-cmd", "-init", "-separator", "-nullvalue"],
        false,
    );
    let mut srcs = Vec::new();
    for v in opt(&items, &["-c", "-s", "-cmd"]) {
        srcs.push(Src::Text(v.to_string(), "-c"));
    }
    let pos = positionals(&items);
    for s in pos.iter().skip(1) {
        srcs.push(Src::Text(s.to_string(), "an argument"));
    }
    let file = pos.first().copied().unwrap_or(":memory:");
    let remote = file.starts_with("md:") || file.starts_with("motherduck:");
    let t = vec![Target {
        host: format!("duckdb {file}"),
        database: None,
        class: if remote { Class::Remote } else { Class::Local },
        source: "the database file".into(),
    }];
    eval_sources(ctx, e, srcs, "postgres", t, out);
}

fn client_clickhouse(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    let items = scan(
        args,
        &[
            "--query",
            "-q",
            "--host",
            "-h",
            "--port",
            "--user",
            "-u",
            "--password",
            "--database",
            "-d",
            "--queries-file",
            "--config-file",
            "-C",
            "--format",
            "-f",
            "--param",
        ],
        false,
    );
    let mut srcs = Vec::new();
    for v in opt(&items, &["--query", "-q"]) {
        srcs.push(Src::Text(v.to_string(), "--query"));
    }
    for v in opt(&items, &["--queries-file"]) {
        srcs.push(Src::File(v.to_string()));
    }
    // `clickhouse-client "SELECT …"` (a positional query).
    for p in positionals(&items) {
        srcs.push(Src::Text(p.to_string(), "an argument"));
    }
    let db = opt(&items, &["--database", "-d"]).first().copied();
    let t: Vec<Target> = opt(&items, &["--host", "-h"])
        .first()
        .map(|h| target::host_target(h, db, "--host", ctx.cfg))
        .into_iter()
        .collect();
    eval_sources(ctx, e, srcs, "postgres", t, out);
}

fn client_cockroach(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    let items = scan(
        args,
        &[
            "-e",
            "--execute",
            "--url",
            "--host",
            "-d",
            "--database",
            "-f",
            "--file",
            "-u",
            "--user",
            "--certs-dir",
            "--format",
        ],
        true,
    );
    let mut srcs = Vec::new();
    for (k, v) in &items {
        match (k.as_str(), v) {
            ("-e" | "--execute", Some(v)) => srcs.push(Src::Text(v.clone(), "-e")),
            ("-f" | "--file", Some(v)) => srcs.push(Src::File(v.clone())),
            _ => {}
        }
    }
    let db = opt(&items, &["-d", "--database"]).first().copied();
    let mut t = Vec::new();
    if let Some(u) = opt(&items, &["--url"]).first() {
        t.extend(target::conn_target(u, "--url", ctx.cfg));
    } else if let Some(h) = opt(&items, &["--host"]).first() {
        t.push(target::host_target(h, db, "--host", ctx.cfg));
    }
    eval_sources(ctx, e, srcs, "postgres", t, out);
}

/// Destructive operations in mongosh JavaScript.
pub fn mongo_js_destructive(js: &str) -> Option<&'static str> {
    let c: String = js.chars().filter(|c| !c.is_whitespace()).collect();
    if c.contains(".dropDatabase(")
        || c.contains("{dropDatabase:")
        || c.contains("{\"dropDatabase\":")
    {
        return Some("dropDatabase() drops the whole database");
    }
    if c.contains(".drop()") || c.contains("{drop:") || c.contains("{\"drop\":") {
        return Some("drop() drops a collection");
    }
    for m in [
        ".deleteMany({})",
        ".deleteMany()",
        ".remove({})",
        ".remove()",
        ".deleteMany({},",
        ".remove({},",
    ] {
        if c.contains(m) {
            return Some("deleteMany({}) / remove({}) deletes every document");
        }
    }
    if c.contains(".updateMany({},") {
        return Some("updateMany({}, …) rewrites every document");
    }
    if c.contains(".dropAllUsers(") || c.contains(".dropAllRoles(") {
        return Some("dropAllUsers()/dropAllRoles() removes every user or role");
    }
    None
}

fn client_mongo(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    if !ctx.cfg.checks.sql {
        return;
    }
    let items = scan(
        args,
        &[
            "--eval",
            "-f",
            "--file",
            "--host",
            "--port",
            "-u",
            "--username",
            "-p",
            "--password",
            "--authenticationDatabase",
            "--apiVersion",
            "--tlsCAFile",
        ],
        false,
    );
    let mut scripts: Vec<String> = Vec::new();
    for v in opt(&items, &["--eval"]) {
        scripts.push(v.to_string());
    }
    let mut targets = Vec::new();
    for p in positionals(&items) {
        if p.ends_with(".js") {
            if let Some(t) = read_sql_file(ctx, e, p) {
                scripts.push(t);
            }
        } else if let Some(t) = resolve_conn(ctx, e, p, "the connection string") {
            targets.push(t);
        } else if p.contains('/') && !p.starts_with('/') {
            let host = p.split('/').next().unwrap_or(p);
            targets.push(target::host_target(
                target::parse_conn(&format!("mongodb://{host}"))
                    .map(|c| c.host)
                    .as_deref()
                    .unwrap_or(host),
                None,
                "the address",
                ctx.cfg,
            ));
        }
    }
    for f in opt(&items, &["-f", "--file"]) {
        if let Some(t) = read_sql_file(ctx, e, f) {
            scripts.push(t);
        }
    }
    if let Some(h) = opt(&items, &["--host"]).first() {
        targets.push(target::host_target(h, None, "--host", ctx.cfg));
    }
    if scripts.is_empty() {
        if let Some(Input::Text(t)) = &e.stdin {
            scripts.push(t.clone());
        }
    }
    for s in scripts {
        if let Some(what) = mongo_js_destructive(&s) {
            push_with(e, out, Hit { code: "VG-204", severity: Severity::Critical, title: format!("mongosh: {what}"), fix: "Filter the operation to the documents you mean, or run it on a disposable database." }, Kind::Sql, targets.clone());
            return;
        }
    }
}

fn client_redis(ctx: &Ctx, e: &Exec, args: &[String], out: &mut Vec<Finding>) {
    if !ctx.cfg.checks.sql {
        return;
    }
    let items = scan(
        args,
        &[
            "-h",
            "-p",
            "-a",
            "-n",
            "-u",
            "-s",
            "--user",
            "--pass",
            "--cacert",
            "--cert",
            "--key",
            "-i",
            "-r",
            "-d",
            "--sni",
            "--cacertdir",
        ],
        false,
    );
    let mut cmds: Vec<String> = vec![positionals(&items)
        .first()
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_default()];
    if let Some(Input::Text(t)) = &e.stdin {
        for l in t.lines() {
            if let Some(w) = l.split_whitespace().next() {
                cmds.push(w.to_ascii_uppercase());
            }
        }
    }
    if let Some(c) = cmds
        .iter()
        .find(|c| matches!(c.as_str(), "FLUSHALL" | "FLUSHDB"))
    {
        let mut t = Vec::new();
        if let Some(u) = opt(&items, &["-u"]).first() {
            t.extend(target::conn_target(u, "-u", ctx.cfg));
        } else if let Some(h) = opt(&items, &["-h"]).first() {
            t.push(target::host_target(h, None, "-h", ctx.cfg));
        }
        push_with(e, out, Hit { code: "VG-203", severity: Severity::Critical, title: format!("redis-cli {c} deletes every key"), fix: "Delete only the keys you mean (SCAN + DEL with a pattern), or use a disposable instance." }, Kind::Sql, t);
    }
}

// ------------------------------------------------------------------- ORMs

/// Matches the ORM / migration pack. Returns whether `name` was one of its
/// tools (so the platform pack is not tried).
fn orm(ctx: &Ctx, e: &Exec, name: &str, args: &[String], out: &mut Vec<Finding>) -> bool {
    let cfg = ctx.cfg;
    let ws = words(args);
    let crit = Severity::Critical;
    let med = Severity::Medium;
    let sens = Severity::Sensitive;
    // (hit, extra targets from flags)
    let (h, extra): (Option<Hit>, Vec<Target>) = match name {
        "prisma" => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["--url"]).into_iter().collect();
            let h = if seq(&ws, &["migrate", "reset"]) {
                hit(
                    "VG-101",
                    crit,
                    "prisma migrate reset drops the database and re-applies every migration",
                    FIX_LOCAL_DB,
                )
            } else if seq(&ws, &["db", "push"]) && flag(args, &["--force-reset"]) {
                hit(
                    "VG-102",
                    crit,
                    "prisma db push --force-reset drops every table before pushing the schema",
                    FIX_LOCAL_DB,
                )
            } else if seq(&ws, &["db", "push"]) && flag(args, &["--accept-data-loss"]) {
                hit(
                    "VG-103",
                    crit,
                    "prisma db push --accept-data-loss applies changes that delete data",
                    "Write a migration (prisma migrate dev --create-only) and review it.",
                )
            } else if seq(&ws, &["db", "execute"]) {
                // SQL through Prisma: --stdin / --file.
                let mut srcs = Vec::new();
                if let Some(f) = flag_value(args, &["--file"]) {
                    srcs.push(Src::File(f.to_string()));
                }
                if flag(args, &["--stdin"]) {
                    srcs.push(Src::Stdin);
                }
                let mut t = orm_targets(ctx, e, true);
                t.extend(extra.iter().cloned());
                if cfg.checks.sql {
                    eval_sources(ctx, e, srcs, "postgres", t, out);
                }
                return true;
            } else if seq(&ws, &["migrate", "deploy"]) || seq(&ws, &["db", "push"]) {
                hit(
                    "VG-501",
                    sens,
                    "prisma applies schema changes to the database",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else {
                None
            };
            (h, extra)
        }
        "drizzle-kit" => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["--url"]).into_iter().collect();
            let h = match ws.first().copied() {
                Some("push") if flag(args, &["--force"]) => hit(
                    "VG-106",
                    crit,
                    "drizzle-kit push --force applies data-loss statements without asking",
                    "Run drizzle-kit generate and review the migration.",
                ),
                Some("drop") => hit(
                    "VG-107",
                    med,
                    "drizzle-kit drop deletes a migration",
                    "Keep the migration history; write a new migration instead.",
                ),
                Some("push" | "migrate") => hit(
                    "VG-501",
                    sens,
                    "drizzle-kit applies schema changes to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "rails" | "rake" => {
            let mut extra = Vec::new();
            if let Some(t) = env_flag_target(args, &["-e", "--environment"]) {
                extra.push(t);
            }
            // `rake db:drop RAILS_ENV=production` / `DISABLE_DATABASE_ENVIRONMENT_CHECK=1`
            for a in args {
                if let Some((k, v)) = a.split_once('=') {
                    if target::ENV_NAME_VARS.contains(&k) && target::is_prod_env_name(v) {
                        extra.push(target::env_target(a, "the command line"));
                    }
                    if k == "DATABASE_URL" {
                        extra.extend(target::conn_target(v, "DATABASE_URL argument", cfg));
                    }
                }
            }
            if args
                .iter()
                .any(|a| a.starts_with("DISABLE_DATABASE_ENVIRONMENT_CHECK="))
                || e.var("DISABLE_DATABASE_ENVIRONMENT_CHECK").is_some()
            {
                extra.push(target::env_target(
                    "DISABLE_DATABASE_ENVIRONMENT_CHECK (Rails' production check turned off)",
                    "the command line",
                ));
            }
            let tasks: Vec<&str> = ws
                .iter()
                .map(|w| w.trim_end_matches(','))
                .filter(|w| w.starts_with("db:"))
                .collect();
            let is = |base: &str, t: &str| t == base || t.starts_with(&format!("{base}:"));
            let critical = [
                "db:drop",
                "db:reset",
                "db:schema:load",
                "db:structure:load",
                "db:migrate:reset",
                "db:purge",
                "db:truncate_all",
                "db:seed:replant",
            ];
            let medium = [
                "db:rollback",
                "db:migrate:down",
                "db:migrate:redo",
                "db:setup",
                "db:fixtures:load",
            ];
            let h = if let Some(t) = tasks
                .iter()
                .find(|t| !t.starts_with("db:test:") && critical.iter().any(|c| is(c, t)))
            {
                hit(
                    "VG-111",
                    crit,
                    format!("rails {t} deletes the database or its data"),
                    FIX_LOCAL_DB,
                )
            } else if let Some(t) = tasks
                .iter()
                .find(|t| !t.starts_with("db:test:") && medium.iter().any(|c| is(c, t)))
            {
                hit(
                    "VG-112",
                    med,
                    format!("rails {t} reverts migrations or reloads data"),
                    "Write a new forward migration instead, or ask the user.",
                )
            } else if matches!(ws.first().copied(), Some("runner" | "r"))
                && ws.iter().skip(1).any(|c| {
                    c.contains(".delete_all")
                        || c.contains(".destroy_all")
                        || c.contains("drop_table")
                        || c.contains("truncate")
                })
            {
                hit(
                    "VG-113",
                    med,
                    "rails runner deletes or drops data",
                    "Scope the deletion with where(...), or ask the user.",
                )
            } else if tasks
                .iter()
                .any(|t| is("db:migrate", t) || *t == "db:prepare" || *t == "db:seed")
            {
                hit(
                    "VG-501",
                    sens,
                    "rails applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else if matches!(ws.first().copied(), Some("dbconsole" | "db")) && name == "rails" {
                if cfg.checks.sql {
                    let t = orm_targets(ctx, e, true)
                        .into_iter()
                        .chain(extra.iter().cloned())
                        .collect();
                    eval_sources(ctx, e, vec![], "postgres", t, out);
                }
                return true;
            } else {
                None
            };
            (h, extra)
        }
        "alembic" | "flask" => {
            let a: Vec<String> = if name == "flask" {
                match args.iter().position(|x| x == "db") {
                    Some(p) => args[p + 1..].to_vec(),
                    None => return false,
                }
            } else {
                args.to_vec()
            };
            let mut extra = Vec::new();
            for v in [flag_value(&a, &["-n", "--name"]), flag_value(&a, &["-x"])]
                .into_iter()
                .flatten()
            {
                let val = v.split_once('=').map(|(_, v)| v).unwrap_or(v);
                if target::is_prod_env_name(val) {
                    extra.push(target::env_target(v, "the command line"));
                }
            }
            let i = skip_opts(&a, &["-c", "--config", "-n", "--name", "-x", "--raiseerr"]);
            let rest = &a[i..];
            let w: Vec<&str> = words(rest);
            let h = match w.first().copied() {
                Some("downgrade") if flag(rest, &["--sql"]) => None,
                Some("downgrade") if w.get(1).copied() == Some("base") => hit(
                    "VG-116",
                    crit,
                    "alembic downgrade base reverts every migration (drops the schema)",
                    FIX_LOCAL_DB,
                ),
                Some("downgrade") => hit(
                    "VG-117",
                    med,
                    format!(
                        "alembic downgrade {} reverts migrations",
                        rest.iter()
                            .find(|x| x.as_str() != "downgrade")
                            .map(String::as_str)
                            .unwrap_or("")
                    ),
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("upgrade") if !flag(rest, &["--sql"]) => hit(
                    "VG-501",
                    sens,
                    "alembic applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "django-admin" => {
            let mut extra = Vec::new();
            if let Some(s) = flag_value(args, &["--settings"]) {
                if target::is_prod_env_name(s) || s.to_ascii_lowercase().contains("prod") {
                    extra.push(target::env_target(
                        &format!("--settings {s}"),
                        "the command line",
                    ));
                }
            }
            if let Some(d) = flag_value(args, &["--database"]) {
                if target::is_prod_env_name(d) || d.to_ascii_lowercase().contains("prod") {
                    extra.push(target::env_target(
                        &format!("--database {d}"),
                        "the command line",
                    ));
                }
            }
            let h = match ws.first().copied() {
                Some("flush") => hit("VG-121", crit, "manage.py flush deletes every row of every table", FIX_LOCAL_DB),
                Some("migrate") if ws.get(2).copied() == Some("zero") => hit("VG-122", crit, format!("manage.py migrate {} zero reverts every migration of the app (drops its tables)", ws.get(1).unwrap_or(&"")), FIX_LOCAL_DB),
                Some("reset_db" | "reset_schema") => hit("VG-123", crit, format!("manage.py {} drops and recreates the database", ws[0]), FIX_LOCAL_DB),
                Some("migrate") => hit("VG-501", sens, "manage.py migrate applies migrations to the database", "Apply migrations to production through the deploy pipeline."),
                Some("dbshell") => {
                    if cfg.checks.sql {
                        let mut srcs = Vec::new();
                        if let Some(p) = args.iter().position(|x| x == "--") {
                            let sub = &args[p + 1..];
                            if let Some(c) = flag_value(sub, &["-c", "--command", "-e", "--execute"]) {
                                srcs.push(Src::Text(c.to_string(), "-c"));
                            }
                        }
                        let t = orm_targets(ctx, e, true).into_iter().chain(extra.iter().cloned()).collect();
                        eval_sources(ctx, e, srcs, "postgres", t, out);
                    }
                    return true;
                }
                _ => None,
            };
            (h, extra)
        }
        "artisan" => {
            let mut extra = Vec::new();
            if let Some(t) = env_flag_target(args, &["--env"]) {
                extra.push(t);
            }
            if let Some(d) = flag_value(args, &["--database"]) {
                if d.to_ascii_lowercase().contains("prod") {
                    extra.push(target::env_target(
                        &format!("--database {d}"),
                        "the command line",
                    ));
                }
            }
            let h = match ws.first().copied() {
                Some(c @ ("migrate:fresh" | "migrate:reset" | "migrate:refresh" | "db:wipe")) => {
                    hit(
                        "VG-126",
                        crit,
                        format!("artisan {c} drops or empties every table"),
                        FIX_LOCAL_DB,
                    )
                }
                Some("migrate:rollback") => hit(
                    "VG-127",
                    med,
                    "artisan migrate:rollback reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("migrate") => hit(
                    "VG-501",
                    sens,
                    "artisan migrate applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "knex" => {
            let extra: Vec<Target> = env_flag_target(args, &["--env"]).into_iter().collect();
            let h = match ws.first().copied() {
                Some("migrate:rollback") if flag(args, &["--all"]) => hit(
                    "VG-131",
                    crit,
                    "knex migrate:rollback --all reverts every migration",
                    FIX_LOCAL_DB,
                ),
                Some("migrate:rollback" | "migrate:down") => hit(
                    "VG-132",
                    med,
                    "knex reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("migrate:latest" | "migrate:up") => hit(
                    "VG-501",
                    sens,
                    "knex applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "sequelize" | "sequelize-cli" => {
            let mut extra: Vec<Target> = env_flag_target(args, &["--env"]).into_iter().collect();
            extra.extend(url_flag_target(ctx, args, &["--url"]));
            let h = match ws.first().copied() {
                Some(c @ ("db:drop" | "db:migrate:undo:all")) => hit(
                    "VG-136",
                    crit,
                    format!("sequelize {c} drops the database or reverts every migration"),
                    FIX_LOCAL_DB,
                ),
                Some(c @ ("db:migrate:undo" | "db:seed:undo:all" | "db:seed:undo")) => hit(
                    "VG-137",
                    med,
                    format!("sequelize {c} reverts migrations or seeds"),
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("db:migrate") => hit(
                    "VG-501",
                    sens,
                    "sequelize applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "typeorm" | "typeorm-ts-node-commonjs" | "typeorm-ts-node-esm" => {
            let h = match ws.first().copied() {
                Some("schema:drop") => hit(
                    "VG-141",
                    crit,
                    "typeorm schema:drop drops every table",
                    FIX_LOCAL_DB,
                ),
                Some(c @ ("migration:revert" | "schema:sync")) => hit(
                    "VG-142",
                    med,
                    format!("typeorm {c} can drop columns or revert migrations"),
                    "Generate a migration and review it.",
                ),
                Some("migration:run") => hit(
                    "VG-501",
                    sens,
                    "typeorm applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, Vec::new())
        }
        "mikro-orm" | "mikro-orm-esm" => {
            let h = match ws.first().copied() {
                Some(c @ ("schema:drop" | "schema:fresh")) if !flag(args, &["--dump", "-d"]) => {
                    hit(
                        "VG-146",
                        crit,
                        format!("mikro-orm {c} drops the schema"),
                        FIX_LOCAL_DB,
                    )
                }
                Some("migration:fresh") => hit(
                    "VG-146",
                    crit,
                    "mikro-orm migration:fresh drops the schema and re-runs every migration",
                    FIX_LOCAL_DB,
                ),
                Some("migration:down") => hit(
                    "VG-147",
                    med,
                    "mikro-orm migration:down reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("schema:update")
                    if flag(args, &["--run", "-r"]) && !flag(args, &["--safe"]) =>
                {
                    hit(
                        "VG-147",
                        med,
                        "mikro-orm schema:update --run can drop columns and tables",
                        "Use --safe, or generate a migration and review it.",
                    )
                }
                Some("migration:up") => hit(
                    "VG-501",
                    sens,
                    "mikro-orm applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, Vec::new())
        }
        "mix" => {
            let tasks: Vec<&str> = ws.iter().map(|w| w.trim_end_matches(',')).collect();
            let h = if let Some(t) = tasks
                .iter()
                .find(|t| matches!(**t, "ecto.drop" | "ecto.reset"))
            {
                hit(
                    "VG-151",
                    crit,
                    format!("mix {t} drops the database"),
                    FIX_LOCAL_DB,
                )
            } else if tasks.contains(&"ecto.rollback") && flag(args, &["--all"]) {
                hit(
                    "VG-151",
                    crit,
                    "mix ecto.rollback --all reverts every migration",
                    FIX_LOCAL_DB,
                )
            } else if tasks.contains(&"ecto.rollback") {
                hit(
                    "VG-152",
                    med,
                    "mix ecto.rollback reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                )
            } else if tasks.contains(&"ecto.migrate") {
                hit(
                    "VG-501",
                    sens,
                    "mix ecto.migrate applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else if tasks.iter().any(|t| t.starts_with("ecto."))
                || tasks.iter().any(|t| t.starts_with("phx."))
            {
                None
            } else {
                return false;
            };
            (h, Vec::new())
        }
        "flyway" => {
            let mut extra: Vec<Target> =
                url_flag_target(ctx, args, &["-url"]).into_iter().collect();
            for k in ["-environment", "-configFiles"] {
                if let Some(v) = flag_value(args, &[k]) {
                    if v.to_ascii_lowercase().contains("prod") {
                        extra.push(target::env_target(&format!("{k}={v}"), "the command line"));
                    }
                }
            }
            if let Some((v, s)) = e.var("FLYWAY_URL") {
                extra.extend(target::conn_target(v, &format!("FLYWAY_URL in {s}"), cfg));
            }
            let h = if ws.contains(&"clean") {
                hit(
                    "VG-156",
                    crit,
                    "flyway clean drops every object in the configured schemas",
                    FIX_LOCAL_DB,
                )
            } else if ws.contains(&"undo") {
                hit(
                    "VG-157",
                    med,
                    "flyway undo reverts the last migration",
                    "Write a new forward migration instead, or ask the user.",
                )
            } else if ws.contains(&"migrate") {
                hit(
                    "VG-501",
                    sens,
                    "flyway applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else {
                None
            };
            (h, extra)
        }
        "liquibase" => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["--url"]).into_iter().collect();
            let lower: Vec<String> = ws
                .iter()
                .map(|w| w.to_ascii_lowercase().replace('-', ""))
                .collect();
            let h = if lower.iter().any(|w| w == "dropall") {
                hit(
                    "VG-161",
                    crit,
                    "liquibase drop-all drops every object in the database",
                    FIX_LOCAL_DB,
                )
            } else if lower.iter().any(|w| w.starts_with("rollback")) {
                hit(
                    "VG-162",
                    med,
                    "liquibase rollback reverts changesets",
                    "Write a new changeset instead, or ask the user.",
                )
            } else if lower.iter().any(|w| w == "update") {
                hit(
                    "VG-501",
                    sens,
                    "liquibase applies changesets to the database",
                    "Apply changesets to production through the deploy pipeline.",
                )
            } else {
                None
            };
            (h, extra)
        }
        "symfony-console" => {
            let extra: Vec<Target> = env_flag_target(args, &["--env", "-e"])
                .into_iter()
                .collect();
            let h = match ws.first().copied() {
                Some("doctrine:database:drop") if flag(args, &["--force", "-f"]) => hit(
                    "VG-166",
                    crit,
                    "doctrine:database:drop --force drops the database",
                    FIX_LOCAL_DB,
                ),
                Some("doctrine:schema:drop")
                    if flag(args, &["--force", "-f", "--full-database"]) =>
                {
                    hit(
                        "VG-166",
                        crit,
                        "doctrine:schema:drop drops the schema",
                        FIX_LOCAL_DB,
                    )
                }
                Some("doctrine:fixtures:load") if !flag(args, &["--append"]) => hit(
                    "VG-166",
                    crit,
                    "doctrine:fixtures:load purges the database before loading fixtures",
                    "Pass --append, or run it on a disposable database.",
                ),
                Some("doctrine:migrations:migrate") if ws.get(1).copied() == Some("first") => hit(
                    "VG-166",
                    crit,
                    "doctrine:migrations:migrate first reverts every migration",
                    FIX_LOCAL_DB,
                ),
                Some("doctrine:migrations:migrate") if ws.get(1).copied() == Some("prev") => hit(
                    "VG-167",
                    med,
                    "doctrine:migrations:migrate prev reverts a migration",
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("doctrine:schema:update") if flag(args, &["--force", "-f"]) => hit(
                    "VG-167",
                    med,
                    "doctrine:schema:update --force can drop columns and tables",
                    "Generate a migration (doctrine:migrations:diff) and review it.",
                ),
                Some("doctrine:migrations:migrate") => hit(
                    "VG-501",
                    sens,
                    "doctrine applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "dotnet" if ws.first().copied() == Some("ef") => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["--connection"])
                .into_iter()
                .collect();
            let h = if seq(&ws, &["database", "drop"]) {
                hit(
                    "VG-171",
                    crit,
                    "dotnet ef database drop drops the database",
                    FIX_LOCAL_DB,
                )
            } else if seq(&ws, &["database", "update", "0"]) {
                hit(
                    "VG-171",
                    crit,
                    "dotnet ef database update 0 reverts every migration",
                    FIX_LOCAL_DB,
                )
            } else if seq(&ws, &["database", "update"]) {
                hit(
                    "VG-501",
                    sens,
                    "dotnet ef applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else {
                None
            };
            (h, extra)
        }
        "sqlx" | "cargo" if name == "sqlx" || ws.first().copied() == Some("sqlx") => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["--database-url", "-D"])
                .into_iter()
                .collect();
            let h = if seq(&ws, &["database", "drop"]) || seq(&ws, &["database", "reset"]) {
                hit(
                    "VG-176",
                    crit,
                    "sqlx database drop/reset drops the database",
                    FIX_LOCAL_DB,
                )
            } else if seq(&ws, &["migrate", "revert"]) {
                hit(
                    "VG-178",
                    med,
                    "sqlx migrate revert reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                )
            } else if seq(&ws, &["migrate", "run"]) {
                hit(
                    "VG-501",
                    sens,
                    "sqlx applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else {
                None
            };
            (h, extra)
        }
        "diesel" => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["--database-url"])
                .into_iter()
                .collect();
            let h = if seq(&ws, &["database", "reset"])
                || (seq(&ws, &["migration", "revert"]) && flag(args, &["--all", "-a"]))
            {
                hit(
                    "VG-177",
                    crit,
                    "diesel resets the database or reverts every migration",
                    FIX_LOCAL_DB,
                )
            } else if seq(&ws, &["migration", "revert"]) || seq(&ws, &["migration", "redo"]) {
                hit(
                    "VG-178",
                    med,
                    "diesel reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                )
            } else if seq(&ws, &["migration", "run"]) {
                hit(
                    "VG-501",
                    sens,
                    "diesel applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else {
                None
            };
            (h, extra)
        }
        "dbmate" => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["-u", "--url"])
                .into_iter()
                .collect();
            let h = match ws.first().copied() {
                Some("drop") => hit(
                    "VG-181",
                    crit,
                    "dbmate drop drops the database",
                    FIX_LOCAL_DB,
                ),
                Some("down" | "rollback") => hit(
                    "VG-182",
                    med,
                    "dbmate rollback reverts a migration",
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("up" | "migrate") => hit(
                    "VG-501",
                    sens,
                    "dbmate applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "goose" => {
            let i = skip_opts(
                args,
                &[
                    "-dir",
                    "-table",
                    "-env",
                    "-certfile",
                    "-ssl-cert",
                    "-ssl-key",
                ],
            );
            let pos: Vec<&str> = words(&args[i..]);
            // goose DRIVER DBSTRING COMMAND, or the command alone with GOOSE_* env.
            let (cmd, extra): (Option<&str>, Vec<Target>) = if pos.len() >= 3 {
                (
                    Some(pos[2]),
                    target::conn_target(pos[1], "the goose dbstring", cfg)
                        .into_iter()
                        .collect(),
                )
            } else {
                (pos.first().copied(), Vec::new())
            };
            let h = match cmd {
                Some("reset") => hit(
                    "VG-183",
                    crit,
                    "goose reset reverts every migration",
                    FIX_LOCAL_DB,
                ),
                Some("down-to") if pos.last().copied() == Some("0") => hit(
                    "VG-183",
                    crit,
                    "goose down-to 0 reverts every migration",
                    FIX_LOCAL_DB,
                ),
                Some("down" | "down-to" | "redo") => hit(
                    "VG-184",
                    med,
                    "goose reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some("up" | "up-by-one" | "up-to") => hit(
                    "VG-501",
                    sens,
                    "goose applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "migrate"
            if flag(
                args,
                &[
                    "-database",
                    "--database",
                    "-path",
                    "--path",
                    "-source",
                    "--source",
                ],
            ) =>
        {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["-database", "--database"])
                .into_iter()
                .collect();
            let pos: Vec<&str> = words(args)
                .into_iter()
                .filter(|w| !w.contains("://") && !w.contains('/'))
                .collect();
            let h = match pos
                .iter()
                .position(|w| matches!(*w, "drop" | "down" | "up" | "force"))
                .map(|p| (pos[p], pos.get(p + 1).copied()))
            {
                Some(("drop", _)) => hit(
                    "VG-186",
                    crit,
                    "migrate drop drops everything in the database",
                    FIX_LOCAL_DB,
                ),
                Some(("down", None)) => hit(
                    "VG-186",
                    crit,
                    "migrate down with no count reverts every migration",
                    FIX_LOCAL_DB,
                ),
                Some(("down", Some(_))) => hit(
                    "VG-185",
                    med,
                    "migrate down reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                ),
                Some(("up", _)) => hit(
                    "VG-501",
                    sens,
                    "migrate applies migrations to the database",
                    "Apply migrations to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, extra)
        }
        "atlas" => {
            let extra: Vec<Target> = url_flag_target(ctx, args, &["-u", "--url"])
                .into_iter()
                .collect();
            let h = if seq(&ws, &["schema", "clean"]) {
                hit(
                    "VG-187",
                    crit,
                    "atlas schema clean drops every object in the database",
                    FIX_LOCAL_DB,
                )
            } else if (seq(&ws, &["schema", "apply"]) || seq(&ws, &["migrate", "down"]))
                && flag(args, &["--auto-approve"])
            {
                hit(
                    "VG-189",
                    med,
                    "atlas applies destructive changes without review (--auto-approve)",
                    "Drop --auto-approve and review the plan.",
                )
            } else if seq(&ws, &["migrate", "apply"]) || seq(&ws, &["schema", "apply"]) {
                hit(
                    "VG-501",
                    sens,
                    "atlas applies schema changes to the database",
                    "Apply changes to production through the deploy pipeline.",
                )
            } else {
                None
            };
            (h, extra)
        }
        "sqitch" => {
            let h = match ws.first().copied() {
                Some(c @ ("revert" | "rebase")) => hit(
                    "VG-188",
                    med,
                    format!("sqitch {c} reverts changes"),
                    "Write a new change instead, or ask the user.",
                ),
                Some("deploy") => hit(
                    "VG-501",
                    sens,
                    "sqitch deploys changes to the database",
                    "Apply changes to production through the deploy pipeline.",
                ),
                _ => None,
            };
            (h, Vec::new())
        }
        "supabase" => {
            let mut extra: Vec<Target> = Vec::new();
            let remote = || {
                if flag(args, &["--linked"]) {
                    Some(Target {
                        host: "linked Supabase project".into(),
                        database: None,
                        class: Class::Remote,
                        source: "--linked".into(),
                    })
                } else {
                    None
                }
            };
            if let Some(t) = url_flag_target(ctx, args, &["--db-url"]) {
                extra.push(t);
            } else if let Some(t) = remote() {
                extra.push(t);
            } else if seq(&ws, &["db", "reset"]) || seq(&ws, &["migration", "down"]) {
                extra.push(Target {
                    host: "local Supabase stack".into(),
                    database: None,
                    class: Class::Local,
                    source: "supabase CLI default".into(),
                });
            }
            let h = if seq(&ws, &["db", "reset"]) {
                hit(
                    "VG-191",
                    crit,
                    "supabase db reset drops the database and re-applies migrations",
                    FIX_LOCAL_DB,
                )
            } else if seq(&ws, &["migration", "down"]) {
                hit(
                    "VG-192",
                    med,
                    "supabase migration down reverts migrations",
                    "Write a new forward migration instead, or ask the user.",
                )
            } else if seq(&ws, &["projects", "delete"]) {
                if cfg.checks.platform {
                    push_with(
                        e,
                        out,
                        Hit {
                            code: "VG-402",
                            severity: crit,
                            title: "supabase projects delete deletes the project and its database"
                                .into(),
                            fix: "Ask the user to do this in the dashboard.",
                        },
                        Kind::Platform,
                        Vec::new(),
                    );
                }
                return true;
            } else if seq(&ws, &["branches", "delete"]) {
                if cfg.checks.platform {
                    push_with(
                        e,
                        out,
                        Hit {
                            code: "VG-404",
                            severity: med,
                            title: "supabase branches delete deletes a database branch".into(),
                            fix: "Confirm the branch is disposable, or ask the user.",
                        },
                        Kind::Platform,
                        Vec::new(),
                    );
                }
                return true;
            } else if seq(&ws, &["db", "push"]) {
                hit(
                    "VG-501",
                    sens,
                    "supabase db push applies migrations to the linked project",
                    "Apply migrations to production through the deploy pipeline.",
                )
            } else {
                None
            };
            // supabase decides its target itself; do not read DATABASE_URL.
            if let Some(h) = h {
                push_with(e, out, h, Kind::Orm, extra);
            }
            return true;
        }
        _ => return false,
    };
    if let Some(h) = h {
        let explicit = extra.iter().any(|x| !x.host.starts_with("environment "));
        let mut t = extra;
        if explicit {
            // The command names its database: the environment only adds an
            // environment name (`RAILS_ENV=production`), not another URL.
            t.extend(
                orm_targets(ctx, e, true)
                    .into_iter()
                    .filter(|x| x.host.starts_with("environment ")),
            );
        } else {
            t.extend(orm_targets(ctx, e, true));
        }
        push_with(e, out, h, Kind::Orm, t);
    }
    true
}

// --------------------------------------------------------------- platform

fn platform(ctx: &Ctx, e: &Exec, name: &str, args: &[String], out: &mut Vec<Finding>) {
    let ws = words(args);
    let crit = Severity::Critical;
    let med = Severity::Medium;
    match name {
        "heroku" => {
            let app = flag_value(args, &["-a", "--app"]).unwrap_or("app");
            let t = vec![platform_target("heroku app", app)];
            match ws.first().copied() {
                Some("pg:reset") => push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-401",
                        severity: crit,
                        title: "heroku pg:reset deletes every table of the app's database".into(),
                        fix: "Ask the user to run it.",
                    },
                    Kind::Platform,
                    t,
                ),
                Some("pg:psql") if ctx.cfg.checks.sql => {
                    let srcs = flag_value(args, &["-c", "--command"])
                        .map(|c| vec![Src::Text(c.to_string(), "-c")])
                        .unwrap_or_default();
                    eval_sources(ctx, e, srcs, "postgres", t, out);
                }
                Some("apps:destroy" | "addons:destroy") => push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-402",
                        severity: crit,
                        title: format!("heroku {} deletes an app or add-on (and its data)", ws[0]),
                        fix: "Ask the user to do it.",
                    },
                    Kind::Platform,
                    t,
                ),
                _ => {}
            }
        }
        "neonctl" | "neon" => {
            if seq(&ws, &["projects", "delete"])
                || seq(&ws, &["project", "delete"])
                || seq(&ws, &["databases", "delete"])
            {
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-402",
                        severity: crit,
                        title: "neonctl deletes a project or database".into(),
                        fix: "Ask the user to do it in the console.",
                    },
                    Kind::Platform,
                    Vec::new(),
                );
            } else if seq(&ws, &["branches", "delete"])
                || seq(&ws, &["branches", "reset"])
                || seq(&ws, &["branch", "delete"])
            {
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-404",
                        severity: med,
                        title: "neonctl deletes or resets a branch".into(),
                        fix: "Confirm the branch is disposable, or ask the user.",
                    },
                    Kind::Platform,
                    Vec::new(),
                );
            }
        }
        "pscale" => {
            if seq(&ws, &["database", "delete"]) {
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-402",
                        severity: crit,
                        title: "pscale database delete deletes the database".into(),
                        fix: "Ask the user to do it.",
                    },
                    Kind::Platform,
                    Vec::new(),
                );
            } else if seq(&ws, &["branch", "delete"]) {
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-404",
                        severity: med,
                        title: "pscale branch delete deletes a database branch".into(),
                        fix: "Confirm the branch is disposable, or ask the user.",
                    },
                    Kind::Platform,
                    Vec::new(),
                );
            }
        }
        "turso" => {
            if seq(&ws, &["db", "destroy"]) || seq(&ws, &["group", "destroy"]) {
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-402",
                        severity: crit,
                        title: "turso destroys a database".into(),
                        fix: "Ask the user to do it.",
                    },
                    Kind::Platform,
                    Vec::new(),
                );
            } else if seq(&ws, &["db", "shell"]) && ctx.cfg.checks.sql {
                let i = ws.iter().position(|w| *w == "shell").unwrap_or(0);
                let db = ws.get(i + 1).copied().unwrap_or("db");
                let srcs: Vec<Src> = ws
                    .get(i + 2..)
                    .unwrap_or(&[])
                    .iter()
                    .map(|s| Src::Text(s.to_string(), "an argument"))
                    .collect();
                eval_sources(
                    ctx,
                    e,
                    srcs,
                    "sqlite",
                    vec![platform_target("turso database", db)],
                    out,
                );
            }
        }
        "wrangler" => {
            if seq(&ws, &["d1", "delete"]) {
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-402",
                        severity: crit,
                        title: "wrangler d1 delete deletes a D1 database".into(),
                        fix: "Ask the user to do it.",
                    },
                    Kind::Platform,
                    Vec::new(),
                );
            } else if seq(&ws, &["d1", "execute"]) && ctx.cfg.checks.sql {
                let mut srcs = Vec::new();
                if let Some(c) = flag_value(args, &["--command"]) {
                    srcs.push(Src::Text(c.to_string(), "--command"));
                }
                if let Some(f) = flag_value(args, &["--file"]) {
                    srcs.push(Src::File(f.to_string()));
                }
                let db = ws.get(2).copied().unwrap_or("db");
                let t = if flag(args, &["--remote"]) {
                    platform_target("Cloudflare D1 (remote)", db)
                } else {
                    Target {
                        host: format!("Cloudflare D1 {db} (local)"),
                        database: None,
                        class: Class::Local,
                        source: "wrangler default".into(),
                    }
                };
                eval_sources(ctx, e, srcs, "sqlite", vec![t], out);
            }
        }
        "aws" => {
            let svc = ws.first().copied();
            let op = ws.get(1).copied().unwrap_or("");
            let deletes = match svc {
                Some("rds") => matches!(
                    op,
                    "delete-db-instance"
                        | "delete-db-cluster"
                        | "delete-db-snapshot"
                        | "delete-db-cluster-snapshot"
                        | "delete-global-cluster"
                ),
                Some("dynamodb") => matches!(op, "delete-table" | "delete-backup"),
                Some("redshift") => matches!(op, "delete-cluster" | "delete-cluster-snapshot"),
                Some("docdb" | "neptune") => {
                    matches!(op, "delete-db-cluster" | "delete-db-instance")
                }
                Some("elasticache") => matches!(
                    op,
                    "delete-cache-cluster" | "delete-replication-group" | "delete-serverless-cache"
                ),
                Some("dsql") => matches!(op, "delete-cluster"),
                _ => false,
            };
            if deletes {
                let mut t = Vec::new();
                if let Some(pf) = flag_value(args, &["--profile"])
                    .map(String::from)
                    .or_else(|| e.var("AWS_PROFILE").map(|(v, _)| v.to_string()))
                {
                    if pf.to_ascii_lowercase().contains("prod") {
                        t.push(target::env_target(
                            &format!("AWS profile {pf}"),
                            "the command line",
                        ));
                    }
                }
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-403",
                        severity: crit,
                        title: format!(
                            "aws {} {op} deletes a database or its backups",
                            svc.unwrap_or("")
                        ),
                        fix: "Ask the user to do it, with a final snapshot.",
                    },
                    Kind::Platform,
                    t,
                );
            }
        }
        "gcloud" => {
            let s = ws.join(" ");
            if [
                "sql instances delete",
                "sql databases delete",
                "spanner databases delete",
                "spanner instances delete",
                "firestore databases delete",
                "alloydb clusters delete",
                "alloydb instances delete",
                "bigtable instances delete",
                "redis instances delete",
            ]
            .iter()
            .any(|p| s.contains(p))
            {
                let mut t = Vec::new();
                if let Some(pj) = flag_value(args, &["--project"]) {
                    if pj.to_ascii_lowercase().contains("prod") {
                        t.push(target::env_target(
                            &format!("GCP project {pj}"),
                            "the command line",
                        ));
                    }
                }
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-403",
                        severity: crit,
                        title: "gcloud deletes a database instance or database".into(),
                        fix: "Ask the user to do it, with a final backup.",
                    },
                    Kind::Platform,
                    t,
                );
            }
        }
        "az" => {
            let s = ws.join(" ");
            if [
                "sql db delete",
                "sql server delete",
                "sql mi delete",
                "postgres flexible-server delete",
                "postgres server delete",
                "mysql flexible-server delete",
                "mysql server delete",
                "cosmosdb delete",
                "cosmosdb sql database delete",
                "redis delete",
            ]
            .iter()
            .any(|p| s.contains(p))
            {
                push_with(
                    e,
                    out,
                    Hit {
                        code: "VG-403",
                        severity: crit,
                        title: "az deletes a database server or database".into(),
                        fix: "Ask the user to do it, with a final backup.",
                    },
                    Kind::Platform,
                    Vec::new(),
                );
            }
        }
        _ => {}
    }
}

// -------------------------------------------------------------------- MCP

/// SQL-carrying argument names.
const SQL_KEYS: &[&str] = &[
    "sql",
    "sql_query",
    "sqlquery",
    "sql_statement",
    "sqlstatements",
    "sql_statements",
    "rawsql",
    "raw_sql",
];
/// Argument names that carry SQL only on database tools.
const QUERY_KEYS: &[&str] = &[
    "query",
    "queries",
    "statement",
    "statements",
    "querystring",
    "query_string",
    "command",
];

/// Splits Claude/Codex MCP tool names (`mcp__server__tool`).
pub fn split_mcp_name(name: &str) -> Option<(&str, &str)> {
    let rest = name.strip_prefix("mcp__")?;
    let p = rest.rfind("__")?;
    Some((&rest[..p], &rest[p + 2..]))
}

fn snake(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else if c == '-' || c == ' ' || c == '.' {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    out
}

fn dbish(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [
        "sql",
        "postgres",
        "pg",
        "mysql",
        "maria",
        "supabase",
        "neon",
        "database",
        "db",
        "sqlite",
        "duckdb",
        "clickhouse",
        "mongo",
        "planetscale",
        "turso",
        "d1",
        "bigquery",
        "snowflake",
        "redshift",
        "cockroach",
        "mssql",
        "oracle",
        "prisma",
        "query",
        "dbhub",
        "tidb",
        "motherduck",
        "redis",
    ]
    .iter()
    .any(|k| l.contains(k))
}

fn mcp_dialect(s: &str) -> &'static str {
    let l = s.to_ascii_lowercase();
    if l.contains("mysql") || l.contains("maria") || l.contains("planetscale") || l.contains("tidb")
    {
        "mysql"
    } else if l.contains("sqlite")
        || l.contains("d1")
        || l.contains("turso")
        || l.contains("libsql")
    {
        "sqlite"
    } else if l.contains("mssql") || l.contains("sqlserver") || l.contains("azure_sql") {
        "mssql"
    } else if l.contains("snowflake") {
        "snowflake"
    } else if l.contains("oracle") {
        "oracle"
    } else {
        "postgres"
    }
}

/// An MCP tool call: `server` and `tool` as the agent names them, `input`
/// the arguments.
pub fn mcp(ctx: &Ctx, server: &str, tool: &str, input: &Value) -> Vec<Finding> {
    let mut out = Vec::new();
    if !ctx.cfg.checks.mcp {
        return out;
    }
    let shown = format!("{server} → {tool}");
    let label = format!("{server} {tool}");
    let db = dbish(&label);
    let dialect = {
        let d = input
            .get("dialect")
            .or_else(|| input.get("engine"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if d.is_empty() {
            mcp_dialect(&label)
        } else {
            mcp_dialect(d)
        }
    };
    // Targets: a production-looking server name or project/branch argument.
    let mut targets = Vec::new();
    let has_prod = |s: &str| target::classify(s, None, ctx.cfg) == Class::Prod;
    if has_prod(server) {
        targets.push(Target {
            host: format!("MCP server {server}"),
            database: None,
            class: Class::Prod,
            source: "the MCP server name".into(),
        });
    }
    if let Some(obj) = input.as_object() {
        for (k, v) in obj {
            let kl = k.to_ascii_lowercase();
            let Some(s) = v.as_str() else { continue };
            if [
                "project",
                "projectid",
                "project_id",
                "project_ref",
                "branch",
                "branchid",
                "branch_id",
                "database",
                "database_name",
                "databasename",
                "db",
                "environment",
                "env",
                "host",
                "instance",
            ]
            .contains(&kl.as_str())
                && has_prod(s)
            {
                targets.push(Target {
                    host: format!("{k} {s}"),
                    database: None,
                    class: Class::Prod,
                    source: "the tool arguments".into(),
                });
            }
            if [
                "connectionstring",
                "connection_string",
                "url",
                "database_url",
                "dsn",
                "uri",
            ]
            .contains(&kl.as_str())
            {
                targets.extend(target::conn_target(s, k, ctx.cfg));
            }
        }
    }
    // Destructive tools by name.
    let t = snake(tool);
    let crit_names = [
        "drop_database",
        "drop_db",
        "delete_database",
        "drop_collection",
        "delete_collection",
        "drop_table",
        "delete_table",
        "delete_project",
        "delete_instance",
        "truncate",
        "flush_all",
        "flushall",
        "flushdb",
        "flush_db",
        "reset_database",
        "reset_db",
        "wipe",
        "drop_schema",
    ];
    let med_names = [
        "delete_branch",
        "reset_branch",
        "drop_index",
        "pause_project",
        "reset_project",
        "delete_backup",
        "restore_backup",
        "restore_branch",
        "reset_from_parent",
    ];
    let mut push = |code: &str, severity: Severity, title: String, fix: &str, preset| {
        out.push(Finding {
            code: code.into(),
            severity,
            kind: Kind::Mcp,
            title,
            what: shown.clone(),
            fix: fix.into(),
            targets: targets.clone(),
            preset,
        });
    };
    if crit_names.iter().any(|n| t.contains(n)) {
        push(
            "VG-601",
            Severity::Critical,
            format!("MCP tool {tool} deletes a database, table, collection or project"),
            "Ask the user to do it themselves.",
            None,
        );
    } else if med_names.iter().any(|n| t.contains(n)) {
        push(
            "VG-602",
            Severity::Medium,
            format!("MCP tool {tool} deletes or resets a branch, index or project state"),
            "Confirm it is disposable, or ask the user.",
            None,
        );
    } else if (t.contains("delete_many") || t.contains("update_many")) && db {
        let filter = input.get("filter").or_else(|| input.get("query"));
        let empty = match filter {
            None => true,
            Some(Value::Object(m)) => m.is_empty(),
            Some(Value::String(s)) => s.trim().is_empty() || s.trim() == "{}",
            _ => false,
        };
        if empty {
            push(
                "VG-204",
                Severity::Critical,
                format!("MCP tool {tool} with an empty filter changes every document"),
                "Pass a filter that selects the documents you mean.",
                None,
            );
        }
    }
    // SQL arguments.
    if ctx.cfg.checks.sql {
        let mut sqls: Vec<String> = Vec::new();
        collect_sql(input, db, 0, &mut sqls);
        for s in sqls {
            let f = if db {
                sql::check(&s, dialect, false)
            } else {
                // Not a database tool: only SQL the engine parses counts.
                sql::check(&s, dialect, false).filter(|f| f.code.starts_with("VERICTO-"))
            };
            if let Some(f) = f {
                let preset = f.high.then_some(ctx.cfg.high_sql);
                push(
                    &f.code,
                    f.severity,
                    format!("{} in SQL sent to MCP tool {tool}: {}", f.title, f.preview),
                    &fix_text(&f.fix),
                    preset,
                );
            }
        }
    }
    out
}

fn collect_sql(v: &Value, db: bool, depth: usize, out: &mut Vec<String>) {
    if depth > 3 {
        return;
    }
    if let Value::Object(m) = v {
        for (k, val) in m {
            let kl = k.to_ascii_lowercase();
            let sqlish =
                SQL_KEYS.contains(&kl.as_str()) || (kl.contains("sql") && !kl.contains("type"));
            let queryish = QUERY_KEYS.contains(&kl.as_str());
            if sqlish || queryish {
                let starts_sql = |s: &str| {
                    let w = s
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase();
                    matches!(
                        w.as_str(),
                        "SELECT"
                            | "INSERT"
                            | "UPDATE"
                            | "DELETE"
                            | "DROP"
                            | "TRUNCATE"
                            | "ALTER"
                            | "CREATE"
                            | "WITH"
                            | "MERGE"
                            | "GRANT"
                            | "REVOKE"
                            | "COPY"
                            | "DO"
                            | "BEGIN"
                            | "REPLACE"
                            | "UPSERT"
                            | "SET"
                            | "CALL"
                            | "EXEC"
                            | "EXECUTE"
                            | "VACUUM"
                            | "ATTACH"
                            | "PRAGMA"
                    )
                };
                // `query` on a search tool is prose: only database tools'
                // `query` arguments are read as SQL.
                let take = |s: &str| sqlish || (queryish && db && starts_sql(s));
                match val {
                    Value::String(s) if take(s) => out.push(s.clone()),
                    Value::Array(a) => {
                        for x in a {
                            if let Some(s) = x.as_str() {
                                if take(s) {
                                    out.push(s.to_string());
                                }
                            } else {
                                collect_sql(x, db, depth + 1, out);
                            }
                        }
                    }
                    Value::Object(_) => collect_sql(val, db, depth + 1, out),
                    _ => {}
                }
            } else if val.is_object() || val.is_array() {
                collect_sql(val, db, depth + 1, out);
            }
        }
    } else if let Value::Array(a) = v {
        for x in a {
            collect_sql(x, db, depth + 1, out);
        }
    }
}
