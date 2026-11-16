// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Hard mode's edits to the agents' files:
//!
//! - the MCP server entry that runs `vericto-proxy mcp
//!   --database-url-keychain <name> --require-read-only` (Claude Code
//!   `.mcp.json` / `~/.claude.json`, Cursor `mcp.json`, Codex `config.toml`);
//! - Claude Code `permissions.deny` rules;
//! - taking a plaintext URL out of a file (`.env*`, an MCP server entry,
//!   `~/.pgpass`, `~/.my.cnf`), leaving a comment where the format has them.
//!
//! The same rules as `install`: other servers, settings and key order are
//! kept, our entries are recognised by what they run (so a second run changes
//! nothing and removal takes only ours), invalid files are never rewritten.

use std::path::{Path, PathBuf};

use super::exposure::{self, Place, Secret};
use super::hook::Agent;
use super::install::{obj, read_json, st, to_text, Plan, Scope, J};

/// Our server entry: `vericto-proxy` with `--database-url-keychain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// The key in the file (`vericto-db`).
    pub key: String,
    /// The keychain entry it reads.
    pub name: String,
    pub require_read_only: bool,
    pub command: String,
}

/// One credential to configure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    pub name: String,
    pub require_read_only: bool,
}

pub fn server_args(name: &str, require_read_only: bool) -> Vec<String> {
    let mut a = vec![
        "mcp".to_string(),
        "--database-url-keychain".to_string(),
        name.to_string(),
    ];
    if require_read_only {
        a.push("--require-read-only".into());
    }
    a
}

/// Whether `command` + `args` is ours; the keychain name and the flag.
pub fn ours(command: &str, args: &[String]) -> Option<(String, bool)> {
    let base = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    if base != "vericto-proxy" {
        return None;
    }
    let i = args.iter().position(|a| a == "--database-url-keychain")?;
    let name = args.get(i + 1)?.clone();
    Some((name, args.iter().any(|a| a == "--require-read-only")))
}

/// Where `agent` keeps MCP servers for `scope` (and whether it is TOML).
pub fn mcp_path(
    agent: Agent,
    scope: Scope,
    root: &Path,
    home: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> (PathBuf, bool) {
    let nonempty = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    match (agent, scope) {
        (Agent::Claude, Scope::Project) => (root.join(".mcp.json"), false),
        (Agent::Claude, Scope::User) => (
            nonempty("CLAUDE_CONFIG_DIR")
                .map(|d| d.join(".claude.json"))
                .unwrap_or_else(|| home.join(".claude.json")),
            false,
        ),
        (Agent::Cursor, Scope::Project) => (root.join(".cursor").join("mcp.json"), false),
        (Agent::Cursor, Scope::User) => (home.join(".cursor").join("mcp.json"), false),
        (Agent::Codex, Scope::Project) => (root.join(".codex").join("config.toml"), true),
        (Agent::Codex, Scope::User) => (
            nonempty("CODEX_HOME")
                .unwrap_or_else(|| home.join(".codex"))
                .join("config.toml"),
            true,
        ),
    }
}

fn str_list(j: Option<&J>) -> Vec<String> {
    match j {
        Some(J::Arr(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

fn json_servers(j: &J) -> Vec<Server> {
    let mut out = Vec::new();
    if let Some(J::Obj(m)) = j.get("mcpServers") {
        for (k, v) in m {
            let cmd = v.get("command").and_then(J::as_str).unwrap_or("");
            if let Some((name, ro)) = ours(cmd, &str_list(v.get("args"))) {
                out.push(Server {
                    key: k.clone(),
                    name,
                    require_read_only: ro,
                    command: cmd.to_string(),
                });
            }
        }
    }
    out
}

fn read_toml(path: &Path) -> Result<(Option<String>, toml::Value), String> {
    match std::fs::read_to_string(path) {
        Ok(t) => {
            let v: toml::Value = toml::from_str(&t).map_err(|e| {
                format!("{} is not valid TOML ({e}); fix it first, vericto guard does not rewrite a file it cannot read", path.display())
            })?;
            Ok((Some(t), v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok((None, toml::Value::Table(Default::default())))
        }
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn toml_servers(v: &toml::Value) -> Vec<Server> {
    let mut out = Vec::new();
    if let Some(m) = v.get("mcp_servers").and_then(toml::Value::as_table) {
        for (k, s) in m {
            let cmd = s.get("command").and_then(toml::Value::as_str).unwrap_or("");
            let args: Vec<String> = s
                .get("args")
                .and_then(toml::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if let Some((name, ro)) = ours(cmd, &args) {
                out.push(Server {
                    key: k.clone(),
                    name,
                    require_read_only: ro,
                    command: cmd.to_string(),
                });
            }
        }
    }
    out
}

/// Our servers in a file.
pub fn servers(path: &Path, is_toml: bool) -> Result<Vec<Server>, String> {
    if is_toml {
        Ok(toml_servers(&read_toml(path)?.1))
    } else {
        Ok(json_servers(&read_json(path)?.1))
    }
}

/// A server key the formats take bare (`[A-Za-z0-9_-]`).
fn key_for(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// The keys to use: an existing entry of ours for the same keychain name
/// keeps its key; otherwise `vericto-db` (one credential) or
/// `vericto-db-<name>` (several), never a key someone else uses.
fn choose_keys(
    existing_keys: &[String],
    ours: &[Server],
    wants: &[Want],
) -> Result<Vec<String>, String> {
    let mut used: Vec<String> = existing_keys.to_vec();
    let mut out = Vec::new();
    for w in wants {
        if let Some(s) = ours.iter().find(|s| s.name == w.name) {
            out.push(s.key.clone());
            continue;
        }
        let mut cands = Vec::new();
        if wants.len() == 1 {
            cands.push("vericto-db".to_string());
        }
        cands.push(format!("vericto-db-{}", key_for(&w.name)));
        let Some(k) = cands.into_iter().find(|k| !used.contains(k)) else {
            return Err(format!(
                "the MCP server key vericto-db-{} is taken by another server; rename it or pick another --name",
                key_for(&w.name)
            ));
        };
        used.push(k.clone());
        out.push(k);
    }
    Ok(out)
}

/// Adds (or updates) our server entries. Entries of ours for other keychain
/// names are kept.
pub fn plan_add(
    agent: Agent,
    path: &Path,
    is_toml: bool,
    proxy: &str,
    wants: &[Want],
) -> Result<Plan, String> {
    if is_toml {
        return plan_add_toml(path, proxy, wants);
    }
    let (before, mut j) = read_json(path)?;
    let mine = json_servers(&j);
    let keys: Vec<String> = match j.get("mcpServers") {
        Some(J::Obj(m)) => m.iter().map(|(k, _)| k.clone()).collect(),
        Some(_) => {
            return Err(format!(
                "{}: \"mcpServers\" is not an object; leaving it alone",
                path.display()
            ))
        }
        None => Vec::new(),
    };
    let chosen = choose_keys(&keys, &mine, wants)?;
    let servers = j.entry("mcpServers", J::Obj(Vec::new()))?;
    for (w, key) in wants.iter().zip(&chosen) {
        let args = J::Arr(
            server_args(&w.name, w.require_read_only)
                .iter()
                .map(|a| st(a))
                .collect(),
        );
        let mut fields = Vec::new();
        if agent == Agent::Claude {
            fields.push(("type", st("stdio")));
        }
        fields.push(("command", st(proxy)));
        fields.push(("args", args));
        if agent == Agent::Claude {
            fields.push(("env", J::Obj(Vec::new())));
        }
        let want = obj(fields);
        match servers.get_mut(key) {
            Some(cur) => {
                // Keep fields the user added (env for linked mode, …).
                if let (J::Obj(c), J::Obj(w)) = (cur, want) {
                    for (k, v) in w {
                        if k == "env" && c.iter().any(|(x, _)| x == "env") {
                            continue;
                        }
                        match c.iter_mut().find(|(x, _)| *x == k) {
                            Some(slot) => slot.1 = v,
                            None => c.push((k, v)),
                        }
                    }
                }
            }
            None => {
                if let J::Obj(m) = servers {
                    m.push((key.clone(), want));
                }
            }
        }
    }
    let after = to_text(&j);
    Ok(Plan {
        path: path.to_path_buf(),
        changed: before.as_deref() != Some(after.as_str()),
        before,
        after,
    })
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn toml_block(key: &str, proxy: &str, w: &Want) -> String {
    let args: Vec<String> = server_args(&w.name, w.require_read_only)
        .iter()
        .map(|a| toml_str(a))
        .collect();
    format!(
        "# vericto guard install --hard: the database through vericto-proxy (keychain entry {}).\n[mcp_servers.{key}]\ncommand = {}\nargs = [{}]\n",
        w.name,
        toml_str(proxy),
        args.join(", ")
    )
}

fn plan_add_toml(path: &Path, proxy: &str, wants: &[Want]) -> Result<Plan, String> {
    let (before, v) = read_toml(path)?;
    let mine = toml_servers(&v);
    let keys: Vec<String> = v
        .get("mcp_servers")
        .and_then(toml::Value::as_table)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let chosen = choose_keys(&keys, &mine, wants)?;
    let mut text = before.clone().unwrap_or_default();
    for (w, key) in wants.iter().zip(&chosen) {
        if let Some(cur) = mine.iter().find(|s| &s.key == key) {
            if cur.command == proxy
                && cur.require_read_only == w.require_read_only
                && cur.name == w.name
            {
                continue;
            }
            text = remove_toml_table(&text, key, None)?;
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&toml_block(key, proxy, w));
    }
    toml::from_str::<toml::Value>(&text).map_err(|e| {
        format!(
            "{}: the edit would not be valid TOML ({e}); leaving it alone",
            path.display()
        )
    })?;
    Ok(Plan {
        path: path.to_path_buf(),
        changed: before.as_deref() != Some(text.as_str()),
        before,
        after: text,
    })
}

/// A TOML header line's dotted key (`[mcp_servers."a b".env]` →
/// `["mcp_servers", "a b", "env"]`), `None` for other lines.
fn header_key(line: &str) -> Option<Vec<String>> {
    let t = line.trim();
    if t.starts_with("[[") {
        let inner = t.strip_prefix("[[")?.split("]]").next()?;
        return Some(split_dotted(inner));
    }
    let inner = t.strip_prefix('[')?.split(']').next()?;
    Some(split_dotted(inner))
}

fn split_dotted(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in s.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => quote = Some(c),
            (None, '.') => out.push(std::mem::take(&mut cur).trim().to_string()),
            (None, c) => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out
}

/// Removes the table `[mcp_servers.<key>]` and its sub-tables, replaced by
/// `comment` when given. Fails when the server is written another way
/// (inline), so the file is left for a human.
pub fn remove_toml_table(text: &str, key: &str, comment: Option<&str>) -> Result<String, String> {
    let mut out = String::new();
    let mut skipping = false;
    let mut done = false;
    for line in text.split_inclusive('\n') {
        if let Some(k) = header_key(line) {
            let mine = k.len() >= 2 && k[0] == "mcp_servers" && k[1] == key;
            if mine && !skipping {
                // Drop the comment line we wrote just above.
                if last_line(&out).starts_with("# vericto guard install --hard:") {
                    let cut = out
                        .trim_end_matches('\n')
                        .rfind('\n')
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    out.truncate(cut);
                }
                if let (Some(c), false) = (comment, done) {
                    out.push_str(c);
                    out.push('\n');
                }
                done = true;
            }
            skipping = mine;
        }
        if !skipping {
            out.push_str(line);
        }
    }
    let v: toml::Value =
        toml::from_str(&out).map_err(|e| format!("the edit would not be valid TOML ({e})"))?;
    if v.get("mcp_servers").and_then(|m| m.get(key)).is_some() {
        return Err(format!(
            "mcp_servers.{key} is not written as its own [mcp_servers.{key}] table; edit it by hand"
        ));
    }
    // Collapse the blank lines a removed block leaves.
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    Ok(out)
}

fn last_line(s: &str) -> &str {
    s.trim_end_matches('\n').rsplit('\n').next().unwrap_or("")
}

/// Removes our server entries (all, or the ones for `only` keychain names).
/// Returns the plan and the keychain names removed.
pub fn plan_remove(
    path: &Path,
    is_toml: bool,
    only: Option<&[String]>,
) -> Result<(Plan, Vec<String>), String> {
    let pick = |s: &Server| only.is_none_or(|o| o.contains(&s.name));
    if is_toml {
        let (before, v) = read_toml(path)?;
        let mut text = before.clone().unwrap_or_default();
        let mut names = Vec::new();
        for s in toml_servers(&v).iter().filter(|s| pick(s)) {
            text = remove_toml_table(&text, &s.key, None)?;
            names.push(s.name.clone());
        }
        let changed = !names.is_empty();
        return Ok((
            Plan {
                path: path.to_path_buf(),
                changed,
                before,
                after: text,
            },
            names,
        ));
    }
    let (before, mut j) = read_json(path)?;
    let mine: Vec<Server> = json_servers(&j).into_iter().filter(pick).collect();
    if mine.is_empty() {
        return Ok((
            Plan {
                path: path.to_path_buf(),
                after: before.clone().unwrap_or_default(),
                before,
                changed: false,
            },
            Vec::new(),
        ));
    }
    if let Some(m) = j.get_mut("mcpServers") {
        for s in &mine {
            m.remove(&s.key);
        }
    }
    if j.get("mcpServers").is_some_and(J::is_empty_container) {
        j.remove("mcpServers");
    }
    let after = to_text(&j);
    Ok((
        Plan {
            path: path.to_path_buf(),
            changed: true,
            before,
            after,
        },
        mine.into_iter().map(|s| s.name).collect(),
    ))
}

/// Claude Code `permissions.deny` rules hard mode adds: the direct database
/// clients, the credential files, the OS credential store, the keychain
/// entry and the guard's policy file.
pub fn deny_rules(backup_dir: Option<&Path>, home: &Path) -> Vec<String> {
    let mut v: Vec<String> = [
        "psql",
        "pg_dump",
        "pg_dumpall",
        "pg_restore",
        "pgcli",
        "mysql",
        "mariadb",
        "mysqldump",
        "mariadb-dump",
        "mysqlsh",
        "mycli",
        "sqlcmd",
        "usql",
    ]
    .iter()
    .map(|c| format!("Bash({c}:*)"))
    .collect();
    for r in [
        "Read(**/.env)",
        "Read(**/.env.*)",
        "Read(**/.envrc)",
        "Read(~/.pgpass)",
        "Read(**/pgpass.conf)",
        "Read(~/.my.cnf)",
        "Read(~/.mylogin.cnf)",
        "Read(~/.config/vericto/**)",
        "Read(**/*.vericto-backup-*)",
        "Bash(security find-generic-password:*)",
        "Bash(security find-internet-password:*)",
        "Bash(security dump-keychain:*)",
        "Bash(secret-tool:*)",
        "Bash(cmdkey:*)",
        "Bash(vericto-proxy mcp credential set:*)",
        "Bash(vericto-proxy mcp credential delete:*)",
        "Bash(vericto guard uninstall:*)",
        "Edit(**/.vericto.toml)",
        "Write(**/.vericto.toml)",
    ] {
        v.push(r.to_string());
    }
    if let Some(d) = backup_dir {
        let p = match d.strip_prefix(home) {
            Ok(r) => format!("~/{}", r.to_string_lossy().replace('\\', "/")),
            Err(_) => format!("/{}", d.to_string_lossy().replace('\\', "/")),
        };
        v.push(format!("Read({}/**)", p.trim_end_matches('/')));
    }
    v
}

/// Adds the missing `rules` to `permissions.deny`. Returns how many.
pub fn merge_deny(path: &Path, j: &mut J, rules: &[String]) -> Result<usize, String> {
    let perms = j.entry("permissions", J::Obj(Vec::new()))?;
    if !matches!(perms, J::Obj(_)) {
        return Err(format!(
            "{}: \"permissions\" is not an object; leaving it alone",
            path.display()
        ));
    }
    let deny = perms.entry("deny", J::Arr(Vec::new()))?;
    let J::Arr(a) = deny else {
        return Err(format!(
            "{}: permissions.deny is not an array; leaving it alone",
            path.display()
        ));
    };
    let mut n = 0;
    for r in rules {
        if !a.iter().any(|x| x.as_str() == Some(r)) {
            a.push(st(r));
            n += 1;
        }
    }
    Ok(n)
}

/// Removes `rules` from `permissions.deny`. Returns how many.
pub fn strip_deny(j: &mut J, rules: &[String]) -> usize {
    let mut n = 0;
    if let Some(perms) = j.get_mut("permissions") {
        if let Some(J::Arr(a)) = perms.get_mut("deny") {
            let before = a.len();
            a.retain(|x| !x.as_str().is_some_and(|s| rules.iter().any(|r| r == s)));
            n = before - a.len();
        }
        if perms.get("deny").is_some_and(J::is_empty_container) {
            perms.remove("deny");
        }
    }
    if j.get("permissions").is_some_and(J::is_empty_container) {
        j.remove("permissions");
    }
    n
}

/// How many of `rules` a parsed settings file holds.
pub fn deny_present(j: &J, rules: &[String]) -> usize {
    match j.get("permissions").and_then(|p| p.get("deny")) {
        Some(J::Arr(a)) => rules
            .iter()
            .filter(|r| a.iter().any(|x| x.as_str() == Some(r.as_str())))
            .count(),
        _ => 0,
    }
}

/// The comment left where a URL was.
pub fn moved_comment(what: &str, name: &str) -> String {
    format!(
        "# {what}moved to the OS keychain (vericto-proxy/{name}) by `vericto guard install --hard`; the agent reaches the database through the Vericto MCP server (docs/guard.md, Hard mode)."
    )
}

/// One file's plaintext removal: the plan and what it takes out.
#[derive(Debug, Clone)]
pub struct Removal {
    pub plan: Plan,
    pub what: Vec<String>,
}

/// Takes the plaintext credentials out of their files. `items` are
/// (place, the URL found there, the keychain name it moved to); places that
/// are not files (the environment) or not edited automatically (URL files,
/// `~/.mylogin.cnf`, backups) are skipped. One plan per file.
pub fn removals(items: &[(Place, Secret, String)]) -> Result<Vec<Removal>, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for (p, _, _) in items {
        if let (Some(f), true) = (p.file(), editable(p)) {
            if !files.iter().any(|x| x == f) {
                files.push(f.to_path_buf());
            }
        }
    }
    let mut out = Vec::new();
    for f in files {
        let here: Vec<&(Place, Secret, String)> = items
            .iter()
            .filter(|(p, _, _)| editable(p) && p.file() == Some(f.as_path()))
            .collect();
        let before =
            std::fs::read_to_string(&f).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        let mut what = Vec::new();
        let after = match &here[0].0 {
            Place::Mcp(m) if m.path.extension().is_some_and(|e| e == "toml") => {
                let mut t = before.clone();
                let mut servers: Vec<&str> = Vec::new();
                for (p, _, name) in &here {
                    if let Place::Mcp(m) = p {
                        if !servers.contains(&m.server.as_str()) {
                            servers.push(&m.server);
                            let c = moved_comment(
                                &format!("MCP server {}: its database URL was ", m.server),
                                name,
                            );
                            t = remove_toml_table(&t, &m.server, Some(&c))
                                .map_err(|e| format!("{}: {e}", f.display()))?;
                            what.push(format!("MCP server \"{}\"", m.server));
                        }
                    }
                }
                t
            }
            Place::Mcp(_) => {
                let (_, mut j) = read_json(&f)?;
                for (p, _, _) in &here {
                    if let Place::Mcp(m) = p {
                        if let Some(cur) = at_path(&mut j, &m.json_path) {
                            if cur.get(&m.server).is_some() {
                                cur.remove(&m.server);
                                what.push(format!("MCP server \"{}\"", m.server));
                            }
                        }
                    }
                }
                to_text(&j)
            }
            _ => {
                let mut lines: Vec<String> = before.lines().map(String::from).collect();
                for (p, url, name) in &here {
                    match p {
                        Place::EnvFile { var, .. } => {
                            for l in lines.iter_mut() {
                                let parsed = super::target::parse_env(l);
                                if let Some((k, v)) = parsed.first() {
                                    if k == var
                                        && exposure::find_urls(v)
                                            .iter()
                                            .any(|u| exposure::normalize(u) == url.expose())
                                    {
                                        *l = moved_comment(&format!("{var}: "), name);
                                        what.push(var.clone());
                                    }
                                }
                            }
                        }
                        Place::Pgpass { line, .. } => {
                            if let Some(l) = lines.get_mut(line - 1) {
                                let f = exposure::pgpass_fields(l.trim());
                                if f.len() == 5 {
                                    let label = format!("{}:{}:{}:{}: ", f[0], f[1], f[2], f[3]);
                                    *l = moved_comment(&label, name);
                                    what.push(format!("line {line}"));
                                }
                            }
                        }
                        Place::MyCnf { section, .. } => {
                            let mut cur = String::new();
                            for l in lines.iter_mut() {
                                let t = l.trim();
                                if let Some(s) =
                                    t.strip_prefix('[').and_then(|r| r.strip_suffix(']'))
                                {
                                    cur = s.trim().to_ascii_lowercase();
                                    continue;
                                }
                                let key = t
                                    .split('=')
                                    .next()
                                    .unwrap_or("")
                                    .trim()
                                    .to_ascii_lowercase();
                                if &cur == section && key == "password" {
                                    *l = moved_comment(&format!("[{section}] password: "), name);
                                    what.push(format!("[{section}] password"));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                let mut t = lines.join("\n");
                if before.ends_with('\n') {
                    t.push('\n');
                }
                t
            }
        };
        if what.is_empty() {
            continue;
        }
        out.push(Removal {
            plan: Plan {
                path: f.clone(),
                changed: before != after,
                before: Some(before),
                after,
            },
            what,
        });
    }
    Ok(out)
}

fn at_path<'a>(j: &'a mut J, path: &[String]) -> Option<&'a mut J> {
    match path.split_first() {
        None => Some(j),
        Some((k, rest)) => at_path(j.get_mut(k)?, rest),
    }
}

/// Whether `install --hard` edits this place itself.
pub fn editable(p: &Place) -> bool {
    matches!(
        p,
        Place::EnvFile { .. } | Place::Mcp(_) | Place::Pgpass { .. } | Place::MyCnf { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::exposure::McpPlace;

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }
    fn want(n: &str) -> Want {
        Want {
            name: n.into(),
            require_read_only: true,
        }
    }
    const PROXY: &str = "/opt/homebrew/bin/vericto-proxy";

    #[test]
    fn json_add_is_idempotent_and_keeps_other_servers() {
        let d = tempfile::tempdir().unwrap();
        for agent in [Agent::Claude, Agent::Cursor] {
            let p = d.path().join(format!("{}.json", agent.as_str()));
            let original = r#"{"theme": "dark", "mcpServers": {"github": {"command": "gh-mcp"}, "vericto-db": {"command": "someone-else"}}, "z": 1}"#;
            write(&p, original);
            let plan = plan_add(agent, &p, false, PROXY, &[want("shop")]).unwrap();
            assert!(plan.changed);
            super::super::install::apply(&plan).unwrap();
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            assert_eq!(v["mcpServers"]["github"]["command"], "gh-mcp");
            assert_eq!(v["mcpServers"]["vericto-db"]["command"], "someone-else");
            let ours = &v["mcpServers"]["vericto-db-shop"];
            assert_eq!(ours["command"], PROXY);
            assert_eq!(
                ours["args"],
                serde_json::json!([
                    "mcp",
                    "--database-url-keychain",
                    "shop",
                    "--require-read-only"
                ])
            );
            assert_eq!(ours.get("type").is_some(), agent == Agent::Claude);
            let after = std::fs::read_to_string(&p).unwrap();
            assert!(after.find("theme").unwrap() < after.find("mcpServers").unwrap());
            assert!(
                !plan_add(agent, &p, false, PROXY, &[want("shop")])
                    .unwrap()
                    .changed
            );
            // A new proxy path updates in place.
            let moved = plan_add(
                agent,
                &p,
                false,
                "/usr/local/bin/vericto-proxy",
                &[want("shop")],
            )
            .unwrap();
            assert!(moved.changed);
            super::super::install::apply(&moved).unwrap();
            let s = servers(&p, false).unwrap();
            assert_eq!(s.len(), 1);
            assert_eq!(s[0].command, "/usr/local/bin/vericto-proxy");
            let (rm, names) = plan_remove(&p, false, None).unwrap();
            assert_eq!(names, vec!["shop"]);
            super::super::install::apply(&rm).unwrap();
            let back: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            let orig: serde_json::Value = serde_json::from_str(original).unwrap();
            assert_eq!(back, orig);
            assert!(!plan_remove(&p, false, None).unwrap().0.changed);
        }
    }

    #[test]
    fn json_new_file_and_key_choice() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".mcp.json");
        let plan = plan_add(Agent::Claude, &p, false, PROXY, &[want("shop")]).unwrap();
        assert!(plan.before.is_none());
        super::super::install::apply(&plan).unwrap();
        assert_eq!(servers(&p, false).unwrap()[0].key, "vericto-db");
        let plan = plan_add(
            Agent::Claude,
            &p,
            false,
            PROXY,
            &[want("shop"), want("crm")],
        )
        .unwrap();
        super::super::install::apply(&plan).unwrap();
        let s = servers(&p, false).unwrap();
        assert_eq!(
            s.iter().map(|s| s.key.as_str()).collect::<Vec<_>>(),
            vec!["vericto-db", "vericto-db-crm"]
        );
        let (_, names) = plan_remove(&p, false, Some(&["crm".to_string()])).unwrap();
        assert_eq!(names, vec!["crm"]);
        write(&p, "{\"mcpServers\": [] }");
        assert!(plan_add(Agent::Claude, &p, false, PROXY, &[want("x")]).is_err());
        write(&p, "{ not json");
        assert!(plan_add(Agent::Claude, &p, false, PROXY, &[want("x")]).is_err());
    }

    #[test]
    fn codex_toml_add_and_remove() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("config.toml");
        let original = "model = \"o4\"\n\n[mcp_servers.github]\ncommand = \"gh\"\n\n[profiles.x]\nmodel = \"y\"\n";
        write(&p, original);
        let plan = plan_add(Agent::Codex, &p, true, PROXY, &[want("shop")]).unwrap();
        super::super::install::apply(&plan).unwrap();
        let t = std::fs::read_to_string(&p).unwrap();
        assert!(t.starts_with(original), "{t}");
        let v: toml::Value = toml::from_str(&t).unwrap();
        assert_eq!(
            v["mcp_servers"]["vericto-db"]["command"].as_str(),
            Some(PROXY)
        );
        assert_eq!(v["mcp_servers"]["github"]["command"].as_str(), Some("gh"));
        assert!(
            !plan_add(Agent::Codex, &p, true, PROXY, &[want("shop")])
                .unwrap()
                .changed
        );
        let ro_off = plan_add(
            Agent::Codex,
            &p,
            true,
            PROXY,
            &[Want {
                name: "shop".into(),
                require_read_only: false,
            }],
        )
        .unwrap();
        super::super::install::apply(&ro_off).unwrap();
        let s = servers(&p, true).unwrap();
        assert_eq!(s.len(), 1);
        assert!(!s[0].require_read_only);
        let (rm, names) = plan_remove(&p, true, None).unwrap();
        assert_eq!(names, vec!["shop"]);
        super::super::install::apply(&rm).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap().trim_end(),
            original.trim_end()
        );
        // An inline table is left for a human.
        assert!(
            remove_toml_table("mcp_servers = { a = { command = \"x\" } }\n", "a", None).is_err()
        );
    }

    #[test]
    fn deny_rules_merge_and_strip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        write(
            &p,
            r#"{"permissions": {"deny": ["Bash(rm -rf:*)", "Bash(psql:*)"], "allow": ["Bash(npm test)"]}}"#,
        );
        let (_, mut j) = read_json(&p).unwrap();
        let rules = deny_rules(
            Some(&d.path().join("h/state/vericto/guard-backups")),
            &d.path().join("h"),
        );
        let n = merge_deny(&p, &mut j, &rules).unwrap();
        assert_eq!(n, rules.len() - 1);
        assert_eq!(deny_present(&j, &rules), rules.len());
        assert!(rules
            .last()
            .unwrap()
            .starts_with("Read(~/state/vericto/guard-backups/**"));
        assert_eq!(merge_deny(&p, &mut j, &rules).unwrap(), 0);
        strip_deny(&mut j, &rules);
        let v: serde_json::Value = serde_json::from_str(&to_text(&j)).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"permissions": {"deny": ["Bash(rm -rf:*)"], "allow": ["Bash(npm test)"]}})
        );
    }

    #[test]
    fn plaintext_removal_leaves_no_secret() {
        let d = tempfile::tempdir().unwrap();
        let pw = "pa55-W0rd";
        let url = format!("postgresql://app:{pw}@db.acme.io:5432/shop");
        let env = d.path().join(".env");
        write(
            &env,
            &format!("PORT=1\nDATABASE_URL=\"{url}\"\nOTHER=postgres://keep@localhost/x\n"),
        );
        let mcp = d.path().join(".mcp.json");
        write(
            &mcp,
            &format!(
                r#"{{"mcpServers": {{"pg": {{"args": ["{url}"]}}, "gh": {{"command": "gh"}}}}}}"#
            ),
        );
        let toml_p = d.path().join("config.toml");
        write(&toml_p, &format!("[mcp_servers.pg]\ncommand = \"x\"\n[mcp_servers.pg.env]\nDATABASE_URL = \"{url}\"\n\n[mcp_servers.gh]\ncommand = \"gh\"\n"));
        let pgpass = d.path().join(".pgpass");
        write(
            &pgpass,
            &format!("# keep\ndb.acme.io:5432:shop:app:{pw}\nother:5432:x:y:z\n"),
        );
        let mycnf = d.path().join(".my.cnf");
        write(
            &mycnf,
            &format!("[mysqld]\npassword=srv\n[client]\nuser=root\npassword={pw}\n"),
        );
        let s = Secret::new(url.clone());
        let mp = |path: &Path, server: &str| {
            Place::Mcp(McpPlace {
                agent: Agent::Claude,
                path: path.to_path_buf(),
                json_path: if path.extension().is_some_and(|e| e == "toml") {
                    vec![]
                } else {
                    vec!["mcpServers".into()]
                },
                server: server.into(),
                field: "x".into(),
            })
        };
        let items = vec![
            (
                Place::EnvFile {
                    path: env.clone(),
                    var: "DATABASE_URL".into(),
                },
                s.clone(),
                "shop".to_string(),
            ),
            (mp(&mcp, "pg"), s.clone(), "shop".into()),
            (mp(&toml_p, "pg"), s.clone(), "shop".into()),
            (
                Place::Pgpass {
                    path: pgpass.clone(),
                    line: 2,
                },
                s.clone(),
                "shop".into(),
            ),
            (
                Place::MyCnf {
                    path: mycnf.clone(),
                    section: "client".into(),
                },
                s.clone(),
                "shop".into(),
            ),
            (
                Place::Environment {
                    var: "DATABASE_URL".into(),
                },
                s.clone(),
                "shop".into(),
            ),
        ];
        let rs = removals(&items).unwrap();
        assert_eq!(rs.len(), 5);
        for r in &rs {
            assert!(r.plan.changed);
            assert!(
                !r.plan.after.contains(pw),
                "{}: {}",
                r.plan.path.display(),
                r.plan.after
            );
            super::super::install::apply(&r.plan).unwrap();
        }
        let e = std::fs::read_to_string(&env).unwrap();
        assert!(
            e.contains("PORT=1")
                && e.contains("OTHER=postgres://keep@localhost/x")
                && e.contains("# DATABASE_URL: moved to the OS keychain (vericto-proxy/shop)"),
            "{e}"
        );
        let m: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mcp).unwrap()).unwrap();
        assert_eq!(
            m,
            serde_json::json!({"mcpServers": {"gh": {"command": "gh"}}})
        );
        let t: toml::Value = toml::from_str(&std::fs::read_to_string(&toml_p).unwrap()).unwrap();
        assert!(t["mcp_servers"].get("pg").is_none() && t["mcp_servers"].get("gh").is_some());
        let pg = std::fs::read_to_string(&pgpass).unwrap();
        assert!(
            pg.contains("# keep")
                && pg.contains("other:5432:x:y:z")
                && pg.contains("# db.acme.io:5432:shop:app: moved"),
            "{pg}"
        );
        let my = std::fs::read_to_string(&mycnf).unwrap();
        assert!(
            my.contains("password=srv") && my.contains("user=root"),
            "{my}"
        );
    }
}
