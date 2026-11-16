// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Where an agent can find a database credential: the project's `.env*`
//! files, the environment, the agents' MCP server configuration, `~/.pgpass`,
//! `~/.my.cnf`, and copies the guard itself left (`*.vericto-backup-*`).
//!
//! Only PostgreSQL, MySQL and MariaDB URLs are collected (what `vericto-proxy
//! mcp` serves). The URL itself is kept in a [`Secret`] whose `Debug` and
//! `Display` print `***`, and is only ever written to the proxy's stdin;
//! everything shown is [`DbUrl::redacted`]: scheme, user, host, port and
//! database, the password replaced by `***` and the query dropped.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::hook::Agent;

/// A database URL. `Debug` and `Display` never show it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Secret {
        Secret(s.into())
    }
    /// The URL itself: for the proxy's stdin and for comparisons only.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("***")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Mysql,
    Mariadb,
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Postgres => "PostgreSQL",
            Dialect::Mysql => "MySQL",
            Dialect::Mariadb => "MariaDB",
        }
    }
    fn from_scheme(s: &str) -> Option<Dialect> {
        match s.split('+').next()?.to_ascii_lowercase().as_str() {
            "postgres" | "postgresql" => Some(Dialect::Postgres),
            "mysql" => Some(Dialect::Mysql),
            "mariadb" => Some(Dialect::Mariadb),
            _ => None,
        }
    }
}

/// The parts of a database URL that may be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbUrl {
    pub dialect: Dialect,
    pub scheme: String,
    pub user: Option<String>,
    pub has_password: bool,
    pub host: String,
    pub port: Option<String>,
    pub database: Option<String>,
    /// Query parameters that are safe to show (`sslmode=require`), so two
    /// URLs that differ only there do not look the same.
    pub params: Vec<String>,
}

/// Query parameters shown as they are; any other is left out.
const SHOWN_PARAMS: &[&str] = &[
    "sslmode",
    "ssl-mode",
    "ssl_mode",
    "sslaccept",
    "connect_timeout",
    "application_name",
    "schema",
    "search_path",
    "target_session_attrs",
    "charset",
];

impl DbUrl {
    /// `postgresql://app:***@db.acme.io:5432/shop`.
    pub fn redacted(&self) -> String {
        let mut s = format!("{}://", self.scheme);
        if let Some(u) = &self.user {
            s.push_str(u);
            if self.has_password {
                s.push_str(":***");
            }
            s.push('@');
        } else if self.has_password {
            s.push_str("***@");
        }
        s.push_str(&self.host);
        if let Some(p) = &self.port {
            s.push(':');
            s.push_str(p);
        }
        if let Some(d) = &self.database {
            s.push('/');
            s.push_str(d);
        }
        if !self.params.is_empty() {
            s.push('?');
            s.push_str(&self.params.join("&"));
        }
        s
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes a URL user, password or database name.
pub fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A text that still holds a placeholder (`${DB_PASS}`, `<password>`,
/// `{{ .Values.db }}`), not a real credential.
fn placeholder(s: &str) -> bool {
    s.contains("${") || s.contains("$(") || s.contains("{{") || s.contains('<') || s.contains('>')
}

/// Reads a PostgreSQL / MySQL / MariaDB URL (`postgresql+psycopg://` too).
pub fn parse_db_url(s: &str) -> Option<DbUrl> {
    let (scheme, rest) = s.trim().split_once("://")?;
    let dialect = Dialect::from_scheme(scheme)?;
    if placeholder(s) {
        return None;
    }
    let (authority, path) = match rest.find(['/', '?']) {
        Some(p) => (&rest[..p], &rest[p..]),
        None => (rest, ""),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (user, mut has_password) = match userinfo {
        Some(u) => match u.split_once(':') {
            Some((name, pass)) => (Some(name.to_string()), !pass.is_empty()),
            None => (Some(u.to_string()), false),
        },
        None => (None, false),
    };
    let first = hostport.split(',').next().unwrap_or("");
    let (host, port) = if let Some(rest) = first.strip_prefix('[') {
        let (h, p) = rest.split_once(']').unwrap_or((rest, ""));
        (format!("[{h}]"), p.strip_prefix(':').map(String::from))
    } else {
        match first.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
                (h.to_string(), Some(p.to_string()))
            }
            _ => (first.to_string(), None),
        }
    };
    let mut host = pct_decode(&host);
    if hostport.contains(',') {
        host.push_str(",…");
    }
    let database = path
        .strip_prefix('/')
        .map(|p| pct_decode(p.split('?').next().unwrap_or("")))
        .filter(|d| !d.is_empty());
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut user = user;
    let mut params = Vec::new();
    for kv in query.split('&') {
        if let Some((k, _)) = kv.split_once('=') {
            if SHOWN_PARAMS.contains(&k.to_ascii_lowercase().as_str()) && !placeholder(kv) {
                params.push(kv.to_string());
            }
        }
        match kv.split_once('=') {
            Some(("password", v)) if !v.is_empty() => has_password = true,
            Some(("user", v)) if user.is_none() => user = Some(v.to_string()),
            Some(("host", v)) if host.is_empty() => host = pct_decode(v),
            _ => {}
        }
    }
    if host.is_empty() {
        host = "localhost".into();
    }
    Some(DbUrl {
        dialect,
        scheme: scheme
            .split('+')
            .next()
            .unwrap_or(scheme)
            .to_ascii_lowercase(),
        user,
        has_password,
        host,
        port,
        database,
        params,
    })
}

/// The URL the proxy is given: the scheme without a driver suffix
/// (`postgresql+asyncpg://` → `postgresql://`).
pub fn normalize(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            format!("{}://{rest}", scheme.split('+').next().unwrap_or(scheme))
        }
        None => url.to_string(),
    }
}

/// Every PostgreSQL / MySQL / MariaDB URL in a text (a value, an argument,
/// a whole file), as written.
pub fn find_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut from = 0;
    while let Some(p) = text[from..].find("://") {
        let at = from + p;
        let mut start = at;
        while start > 0 && {
            let c = b[start - 1];
            c.is_ascii_alphanumeric() || c == b'+' || c == b'.' || c == b'-'
        } {
            start -= 1;
        }
        let end = text[at..]
            .find(|c: char| c.is_whitespace() || "\"'`<>\\".contains(c))
            .map(|e| at + e)
            .unwrap_or(text.len());
        let jdbc = text[..start].ends_with("jdbc:");
        let cand = &text[start..end];
        if !jdbc && parse_db_url(cand).is_some() {
            out.push(cand.trim_end_matches([',', ';', ')']).to_string());
        }
        from = end.max(at + 3);
    }
    out
}

/// Which MCP configuration file and where in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpPlace {
    pub agent: Agent,
    pub path: PathBuf,
    /// The object holding the servers (`["mcpServers"]`, or `["projects",
    /// "/repo", "mcpServers"]` in `~/.claude.json`); empty for Codex TOML.
    pub json_path: Vec<String>,
    pub server: String,
    /// The field that holds it (`args[2]`, `env.DATABASE_URL`).
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    EnvFile {
        path: PathBuf,
        var: String,
    },
    Environment {
        var: String,
    },
    Mcp(McpPlace),
    /// The URL file a `--database-url-file` server reads.
    UrlFile {
        path: PathBuf,
        server: String,
    },
    Pgpass {
        path: PathBuf,
        line: usize,
    },
    MyCnf {
        path: PathBuf,
        section: String,
    },
    /// `~/.mylogin.cnf` (obfuscated, not encrypted; not read).
    MyLogin {
        path: PathBuf,
    },
    /// A `*.vericto-backup-*` copy that holds a URL.
    Backup {
        path: PathBuf,
    },
}

/// A path for messages: relative to the working directory when under it
/// (`.env`), `~/x` under the home directory, else as it is.
pub fn short(p: &Path, home: &Path) -> String {
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(r) = p.strip_prefix(&cwd) {
            if !r.as_os_str().is_empty() {
                return r.display().to_string();
            }
        }
    }
    match p.strip_prefix(home) {
        Ok(r) if !home.as_os_str().is_empty() => format!("~/{}", r.display()),
        _ => p.display().to_string(),
    }
}

impl Place {
    pub fn describe(&self, home: &Path) -> String {
        match self {
            Place::EnvFile { path, var } => format!("{var} in {}", short(path, home)),
            Place::Environment { var } => format!("{var} in the environment"),
            Place::Mcp(m) => format!(
                "MCP server \"{}\" ({}) in {}",
                m.server,
                m.field,
                short(&m.path, home)
            ),
            Place::UrlFile { path, server } => {
                format!("{} (read by MCP server \"{server}\")", short(path, home))
            }
            Place::Pgpass { path, line } => format!("line {line} of {}", short(path, home)),
            Place::MyCnf { path, section } => format!("[{section}] in {}", short(path, home)),
            Place::MyLogin { path } => format!(
                "{} (MySQL login paths, obfuscated, not encrypted)",
                short(path, home)
            ),
            Place::Backup { path } => format!("backup copy {}", short(path, home)),
        }
    }
    /// The file it is in (none for the environment).
    pub fn file(&self) -> Option<&Path> {
        match self {
            Place::EnvFile { path, .. }
            | Place::UrlFile { path, .. }
            | Place::Pgpass { path, .. }
            | Place::MyCnf { path, .. }
            | Place::MyLogin { path }
            | Place::Backup { path } => Some(path),
            Place::Mcp(m) => Some(&m.path),
            Place::Environment { .. } => None,
        }
    }
}

/// One place a credential was found.
#[derive(Debug, Clone)]
pub struct Exposure {
    pub place: Place,
    /// The URL (composed for `~/.pgpass` and `~/.my.cnf`); `None` when it
    /// cannot be moved as is (wildcards, `~/.mylogin.cnf`).
    pub url: Option<Secret>,
    pub info: Option<DbUrl>,
    /// Why it cannot be moved, when it cannot.
    pub note: Option<String>,
}

impl Exposure {
    pub fn shown(&self) -> String {
        self.info
            .as_ref()
            .map(DbUrl::redacted)
            .unwrap_or_else(|| "(not read)".into())
    }
}

/// Where to look.
#[derive(Debug, Clone)]
pub struct ScanCtx {
    pub cwd: PathBuf,
    pub root: PathBuf,
    pub home: PathBuf,
    /// The environment (name, value).
    pub env: Vec<(String, String)>,
    /// `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json` when set).
    pub claude_json: PathBuf,
    /// `~/.cursor`.
    pub cursor_dir: PathBuf,
    /// `$CODEX_HOME` or `~/.codex`.
    pub codex_home: PathBuf,
}

impl ScanCtx {
    pub fn new(cwd: PathBuf, root: PathBuf, home: PathBuf, env: Vec<(String, String)>) -> ScanCtx {
        let get = |k: &str| {
            env.iter()
                .find(|(n, v)| n == k && !v.is_empty())
                .map(|(_, v)| PathBuf::from(v))
        };
        let claude_json = get("CLAUDE_CONFIG_DIR")
            .map(|d| d.join(".claude.json"))
            .unwrap_or_else(|| home.join(".claude.json"));
        let codex_home = get("CODEX_HOME").unwrap_or_else(|| home.join(".codex"));
        ScanCtx {
            cursor_dir: home.join(".cursor"),
            cwd,
            root,
            home,
            env,
            claude_json,
            codex_home,
        }
    }
    fn var(&self, k: &str) -> Option<&str> {
        self.env
            .iter()
            .find(|(n, v)| n == k && !v.is_empty())
            .map(|(_, v)| v.as_str())
    }
    pub fn pgpass(&self) -> PathBuf {
        if let Some(p) = self.var("PGPASSFILE") {
            return PathBuf::from(p);
        }
        if cfg!(windows) {
            if let Some(a) = self.var("APPDATA") {
                return Path::new(a).join("postgresql").join("pgpass.conf");
            }
        }
        self.home.join(".pgpass")
    }
    /// The MCP configuration files: (agent, path, is TOML).
    pub fn mcp_files(&self) -> Vec<(Agent, PathBuf, bool)> {
        let mut v = vec![
            (Agent::Claude, self.root.join(".mcp.json"), false),
            (Agent::Claude, self.claude_json.clone(), false),
            (
                Agent::Cursor,
                self.root.join(".cursor").join("mcp.json"),
                false,
            ),
            (Agent::Cursor, self.cursor_dir.join("mcp.json"), false),
            (Agent::Codex, self.codex_home.join("config.toml"), true),
            (
                Agent::Codex,
                self.root.join(".codex").join("config.toml"),
                true,
            ),
        ];
        v.dedup_by(|a, b| a.1 == b.1);
        v
    }
    fn env_dirs(&self) -> Vec<PathBuf> {
        let mut d = vec![self.cwd.clone()];
        if self.root != self.cwd {
            d.push(self.root.clone());
        }
        d
    }
}

/// Largest file read.
const MAX_FILE: u64 = 4 * 1024 * 1024;

fn read_small(p: &Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    if !m.is_file() || m.len() > MAX_FILE {
        return None;
    }
    std::fs::read_to_string(p).ok()
}

fn exposure(place: Place, url: &str) -> Option<Exposure> {
    let info = parse_db_url(url)?;
    Some(Exposure {
        place,
        url: Some(Secret::new(normalize(url))),
        info: Some(info),
        note: None,
    })
}

/// The project's env files (`.env`, `.env.*` but templates, `.envrc`).
pub fn env_files(ctx: &ScanCtx) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for d in ctx.env_dirs() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        let mut names: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                let n = p.file_name().map(|n| n.to_string_lossy().into_owned());
                n.is_some_and(|n| {
                    (n == ".env" || n == ".envrc" || n.starts_with(".env."))
                        && !n.contains(".vericto-backup-")
                        && super::hard::credential_file(&n).is_some()
                }) && p.is_file()
            })
            .collect();
        names.sort();
        out.extend(names);
    }
    out
}

/// Every credential an agent could find.
pub fn scan(ctx: &ScanCtx) -> Vec<Exposure> {
    let mut out = Vec::new();
    // Env files.
    for p in env_files(ctx) {
        let Some(text) = read_small(&p) else {
            continue;
        };
        for (k, v) in super::target::parse_env(&text) {
            for u in find_urls(&v) {
                out.extend(exposure(
                    Place::EnvFile {
                        path: p.clone(),
                        var: k.clone(),
                    },
                    &u,
                ));
            }
        }
    }
    // The environment.
    let mut env: Vec<&(String, String)> = ctx.env.iter().collect();
    env.sort();
    for (k, v) in env {
        for u in find_urls(v) {
            out.extend(exposure(Place::Environment { var: k.clone() }, &u));
        }
    }
    // MCP servers.
    let mut seen_url_files: Vec<PathBuf> = Vec::new();
    for (agent, path, toml) in ctx.mcp_files() {
        let Some(text) = read_small(&path) else {
            continue;
        };
        let groups: Vec<(Vec<String>, Value)> = if toml {
            match toml::from_str::<toml::Value>(&text) {
                Ok(t) => t
                    .get("mcp_servers")
                    .and_then(|m| serde_json::to_value(m).ok())
                    .map(|v| vec![(Vec::new(), v)])
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            match serde_json::from_str::<Value>(&text) {
                Ok(v) => {
                    let mut g = Vec::new();
                    if let Some(m) = v.get("mcpServers") {
                        g.push((vec!["mcpServers".to_string()], m.clone()));
                    }
                    if path == ctx.claude_json {
                        if let Some(projects) = v.get("projects").and_then(Value::as_object) {
                            for (dir, pv) in projects {
                                let same = Path::new(dir) == ctx.root
                                    || std::fs::canonicalize(dir).ok()
                                        == std::fs::canonicalize(&ctx.root).ok();
                                if let (true, Some(m)) = (same, pv.get("mcpServers")) {
                                    g.push((
                                        vec![
                                            "projects".to_string(),
                                            dir.clone(),
                                            "mcpServers".to_string(),
                                        ],
                                        m.clone(),
                                    ));
                                }
                            }
                        }
                    }
                    g
                }
                Err(_) => Vec::new(),
            }
        };
        for (json_path, servers) in groups {
            let Some(servers) = servers.as_object() else {
                continue;
            };
            for (name, def) in servers {
                let mut strings = Vec::new();
                walk(def, String::new(), 0, &mut strings);
                for (field, s) in &strings {
                    for u in find_urls(s) {
                        out.extend(exposure(
                            Place::Mcp(McpPlace {
                                agent,
                                path: path.clone(),
                                json_path: json_path.clone(),
                                server: name.clone(),
                                field: field.clone(),
                            }),
                            &u,
                        ));
                    }
                }
                for f in url_files(def) {
                    let f = expand_home(&f, &ctx.home);
                    if seen_url_files.contains(&f) {
                        continue;
                    }
                    seen_url_files.push(f.clone());
                    if let Some(t) = read_small(&f) {
                        for u in find_urls(&t) {
                            out.extend(exposure(
                                Place::UrlFile {
                                    path: f.clone(),
                                    server: name.clone(),
                                },
                                &u,
                            ));
                        }
                    }
                }
            }
        }
    }
    // ~/.pgpass.
    let pg = ctx.pgpass();
    if let Some(text) = read_small(&pg) {
        out.extend(pgpass(&pg, &text));
    }
    // ~/.my.cnf, ~/.mylogin.cnf.
    let my = ctx.home.join(".my.cnf");
    if let Some(text) = read_small(&my) {
        out.extend(my_cnf(&my, &text));
    }
    let login = ctx.home.join(".mylogin.cnf");
    if login.is_file() {
        out.push(Exposure {
            place: Place::MyLogin { path: login },
            url: None,
            info: None,
            note: Some(
                "remove it with `mysql_config_editor remove --login-path=…` once hard mode works"
                    .into(),
            ),
        });
    }
    // Backup copies next to the files above.
    let mut dirs: Vec<PathBuf> = ctx.env_dirs();
    for (_, p, _) in ctx.mcp_files() {
        if let Some(d) = p.parent() {
            dirs.push(d.to_path_buf());
        }
    }
    dirs.push(ctx.home.clone());
    dirs.sort();
    dirs.dedup();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        let mut files: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().contains(".vericto-backup-"))
                    && p.is_file()
            })
            .collect();
        files.sort();
        for f in files {
            let Some(t) = read_small(&f) else {
                continue;
            };
            if let Some(u) = find_urls(&t)
                .into_iter()
                .find(|u| parse_db_url(u).is_some_and(|i| i.has_password))
            {
                out.push(Exposure {
                    place: Place::Backup { path: f.clone() },
                    url: None,
                    info: parse_db_url(&u),
                    note: Some("a copy vericto guard install left next to the file".into()),
                });
            }
        }
    }
    out
}

fn expand_home(p: &str, home: &Path) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(r) => home.join(r),
        None => PathBuf::from(p),
    }
}

/// Every string in a server definition with its field path.
fn walk(v: &Value, at: String, depth: usize, out: &mut Vec<(String, String)>) {
    if depth > 8 {
        return;
    }
    match v {
        Value::String(s) => out.push((at, s.clone())),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                walk(x, format!("{at}[{i}]"), depth + 1, out);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                let p = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                walk(x, p, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// `--database-url-file <path>` / `VERICTO_MCP_DATABASE_URL_FILE` of a
/// `vericto-proxy mcp` server.
fn url_files(def: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(args) = def.get("args").and_then(Value::as_array) {
        let a: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
        for (i, x) in a.iter().enumerate() {
            if *x == "--database-url-file" {
                if let Some(p) = a.get(i + 1) {
                    out.push(p.to_string());
                }
            } else if let Some(p) = x.strip_prefix("--database-url-file=") {
                out.push(p.to_string());
            }
        }
    }
    if let Some(p) = def
        .get("env")
        .and_then(|e| e.get("VERICTO_MCP_DATABASE_URL_FILE"))
        .and_then(Value::as_str)
    {
        out.push(p.to_string());
    }
    out
}

/// Splits a `.pgpass` line on unescaped `:` (`\:` and `\\` are escapes).
pub fn pgpass_fields(line: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(n) = chars.next() {
                    out.last_mut().expect("one field").push(n);
                }
            }
            ':' => out.push(String::new()),
            c => out.last_mut().expect("one field").push(c),
        }
    }
    out
}

fn pgpass(path: &Path, text: &str) -> Vec<Exposure> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let f = pgpass_fields(t);
        if f.len() != 5 || f[4].is_empty() {
            continue;
        }
        let (host, port, db, user, pass) = (&f[0], &f[1], &f[2], &f[3], &f[4]);
        let place = Place::Pgpass {
            path: path.to_path_buf(),
            line: i + 1,
        };
        let info = DbUrl {
            dialect: Dialect::Postgres,
            scheme: "postgresql".into(),
            user: Some(user.clone()),
            has_password: true,
            host: host.clone(),
            port: (port != "*").then(|| port.clone()),
            database: Some(db.clone()),
            params: Vec::new(),
        };
        if [host, db, user].iter().any(|x| x.as_str() == "*") || host.starts_with('/') {
            out.push(Exposure {
                place,
                url: None,
                info: Some(info),
                note: Some("a wildcard or socket line; store a URL for one database yourself with `vericto-proxy mcp credential set <name>`".into()),
            });
            continue;
        }
        let mut url = format!(
            "postgresql://{}:{}@{host}",
            pct_encode(user),
            pct_encode(pass)
        );
        if port != "*" {
            url.push(':');
            url.push_str(port);
        }
        url.push('/');
        url.push_str(&pct_encode(db));
        out.push(Exposure {
            place,
            url: Some(Secret::new(url)),
            info: Some(info),
            note: None,
        });
    }
    out
}

/// `[section]` → key/value lines of a MySQL option file.
pub fn cnf_sections(text: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') || t.starts_with('!') {
            continue;
        }
        if let Some(s) = t.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            out.push((s.trim().to_ascii_lowercase(), Vec::new()));
            continue;
        }
        let Some(cur) = out.last_mut() else {
            continue;
        };
        let (k, v) = t.split_once('=').unwrap_or((t, ""));
        let v = v.trim();
        let v = if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"'))
                || (v.starts_with('\'') && v.ends_with('\'')))
        {
            &v[1..v.len() - 1]
        } else {
            v
        };
        cur.1.push((
            k.trim().to_ascii_lowercase().replace('-', "_"),
            v.to_string(),
        ));
    }
    out
}

/// The client sections of `.my.cnf` that the MySQL clients read.
const CNF_CLIENT_SECTIONS: &[&str] = &[
    "client",
    "mysql",
    "mysqldump",
    "mysqladmin",
    "mysqlsh",
    "mariadb",
    "client-mariadb",
    "client-server",
    "mariadb-client",
];

fn my_cnf(path: &Path, text: &str) -> Vec<Exposure> {
    let mut out = Vec::new();
    for (section, kv) in cnf_sections(text) {
        if !CNF_CLIENT_SECTIONS.contains(&section.as_str()) {
            continue;
        }
        let get = |k: &str| {
            kv.iter()
                .rev()
                .find(|(x, _)| x == k)
                .map(|(_, v)| v.clone())
        };
        let Some(pass) = get("password").filter(|p| !p.is_empty()) else {
            continue;
        };
        let maria = section.contains("mariadb");
        let scheme = if maria { "mariadb" } else { "mysql" };
        let host = get("host").unwrap_or_else(|| "localhost".into());
        let port = get("port");
        let db = get("database");
        let user = get("user");
        let info = DbUrl {
            dialect: if maria {
                Dialect::Mariadb
            } else {
                Dialect::Mysql
            },
            scheme: scheme.into(),
            user: user.clone(),
            has_password: true,
            host: host.clone(),
            port: port.clone(),
            database: db.clone(),
            params: Vec::new(),
        };
        let place = Place::MyCnf {
            path: path.to_path_buf(),
            section: section.clone(),
        };
        let Some(user) = user else {
            out.push(Exposure {
                place,
                url: None,
                info: Some(info),
                note: Some("no `user` in the section; store a URL yourself with `vericto-proxy mcp credential set <name>`".into()),
            });
            continue;
        };
        let mut url = format!(
            "{scheme}://{}:{}@{host}",
            pct_encode(&user),
            pct_encode(&pass)
        );
        if let Some(p) = &port {
            url.push(':');
            url.push_str(p);
        }
        if let Some(d) = &db {
            url.push('/');
            url.push_str(&pct_encode(d));
        }
        out.push(Exposure {
            place,
            url: Some(Secret::new(url)),
            info: Some(info),
            note: None,
        });
    }
    out
}

/// One credential and every place it was found.
#[derive(Debug, Clone)]
pub struct Credential {
    pub url: Secret,
    pub info: DbUrl,
    pub places: Vec<Place>,
}

/// Groups movable exposures by URL (first-seen order); the rest are
/// returned as they are.
pub fn group(exps: &[Exposure]) -> (Vec<Credential>, Vec<Exposure>) {
    let mut creds: Vec<Credential> = Vec::new();
    let mut rest = Vec::new();
    for e in exps {
        match (&e.url, &e.info) {
            (Some(u), Some(i)) => {
                if let Some(c) = creds.iter_mut().find(|c| &c.url == u) {
                    c.places.push(e.place.clone());
                } else {
                    creds.push(Credential {
                        url: u.clone(),
                        info: i.clone(),
                        places: vec![e.place.clone()],
                    });
                }
            }
            _ => rest.push(e.clone()),
        }
    }
    (creds, rest)
}

/// A keychain entry name the proxy accepts (`[A-Za-z0-9._@:-]`, at most 128).
pub fn sanitize_name(s: &str) -> String {
    let n: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._@:-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    let n = n.trim_matches('-').to_string();
    n.chars().take(128).collect()
}

/// The suggested entry name: the database name, else the host's first label.
pub fn default_name(info: &DbUrl) -> String {
    let base = info
        .database
        .clone()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| info.host.split('.').next().unwrap_or("db").to_string());
    let n = sanitize_name(&base);
    if n.is_empty() {
        "db".into()
    } else {
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "s3cr3t-Pa55";

    fn ctx(dir: &Path) -> ScanCtx {
        let home = dir.join("home");
        let root = dir.join("repo");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        ScanCtx::new(root.clone(), root, home, Vec::new())
    }

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    /// Nothing derived for display may carry the password.
    fn assert_redacted(exps: &[Exposure], home: &Path) {
        for e in exps {
            let shown = format!(
                "{} {} {:?} {:?}",
                e.shown(),
                e.place.describe(home),
                e,
                e.url
            );
            assert!(!shown.contains(PW), "{shown}");
        }
    }

    #[test]
    fn urls_parse_and_redact() {
        let u = parse_db_url(&format!(
            "postgresql://app:{PW}@db.prod.acme.io:5432/shop?sslmode=require"
        ))
        .unwrap();
        assert_eq!(
            u.redacted(),
            "postgresql://app:***@db.prod.acme.io:5432/shop?sslmode=require"
        );
        let u = parse_db_url(&format!("mysql://root:{PW}@[::1]:3306/app")).unwrap();
        assert_eq!(u.redacted(), "mysql://root:***@[::1]:3306/app");
        assert_eq!(u.dialect, Dialect::Mysql);
        let u = parse_db_url(&format!("postgres://h1:5432,h2/app?user=x&password={PW}")).unwrap();
        assert_eq!(u.redacted(), "postgres://x:***@h1,…:5432/app");
        let u = parse_db_url("postgresql+asyncpg://u@localhost/db").unwrap();
        assert_eq!(u.redacted(), "postgresql://u@localhost/db");
        assert_eq!(
            normalize("postgresql+asyncpg://u@h/db"),
            "postgresql://u@h/db"
        );
        assert!(parse_db_url("mongodb://u:p@h/db").is_none());
        assert!(parse_db_url("postgres://u:${DB_PASS}@h/db").is_none());
        assert!(parse_db_url("mysql://<user>:<password>@host/db").is_none());
        assert_eq!(
            format!("{:?} {}", Secret::new(PW), Secret::new(PW)),
            "Secret(***) ***"
        );
    }

    #[test]
    fn finds_urls_in_text() {
        let t = format!(
            "--url=postgres://a:{PW}@h1/db1 \"mysql://b@h2:3306/x\" jdbc:postgresql://h3/db redis://h4 'mariadb://c:d@h5'"
        );
        let v = find_urls(&t);
        assert_eq!(v.len(), 3, "{v:?}");
        assert!(v[0].starts_with("postgres://a:"));
        assert_eq!(v[1], "mysql://b@h2:3306/x");
        assert_eq!(v[2], "mariadb://c:d@h5");
        assert!(find_urls("see https://example.com and postgres docs").is_empty());
    }

    #[test]
    fn scans_every_place_without_showing_secrets() {
        let d = tempfile::tempdir().unwrap();
        let c = ctx(d.path());
        let url = format!("postgresql://app:{PW}@db.prod.acme.io:5432/shop");
        write(
            &c.root.join(".env"),
            &format!("# c\nDATABASE_URL=\"{url}\"\nPORT=3000\n"),
        );
        write(
            &c.root.join(".env.local"),
            &format!("export DIRECT_URL={url}\n"),
        );
        write(
            &c.root.join(".env.example"),
            "DATABASE_URL=postgres://user:password@localhost/app\n",
        );
        write(
            &c.root.join(".mcp.json"),
            &format!(
                r#"{{"mcpServers": {{"pg": {{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", "{url}"]}}, "other": {{"command": "x"}}}}}}"#
            ),
        );
        write(
            &c.claude_json,
            &format!(
                r#"{{"projects": {{{}: {{"mcpServers": {{"local": {{"command": "x", "env": {{"DATABASE_URL": "mysql://root:{PW}@localhost:3306/app"}}}}}}}}, "/elsewhere": {{"mcpServers": {{"z": {{"args": ["postgres://z:{PW}@z/z"]}}}}}}}}}}"#,
                // A JSON string: Windows paths carry backslashes.
                serde_json::to_string(&c.root.display().to_string()).unwrap()
            ),
        );
        write(
            &c.cursor_dir.join("mcp.json"),
            r#"{"mcpServers": {"v": {"command": "/x/vericto-proxy", "args": ["mcp", "--database-url-file", "~/.config/vericto/shop.url"]}}}"#,
        );
        write(
            &c.home.join(".config/vericto/shop.url"),
            &format!("{url}\n"),
        );
        write(&c.codex_home.join("config.toml"), &format!("model = \"x\"\n[mcp_servers.db]\ncommand = \"uvx\"\nargs = [\"mcp-server-postgres\"]\n[mcp_servers.db.env]\nDATABASE_URL = \"postgres://codex:{PW}@pg.internal/app\"\n"));
        write(&c.home.join(".pgpass"), &format!("# comment\nlocalhost:5432:app:dev:{PW}\n*:*:*:postgres:{PW}\ndb.acme.io:5432:shop:u:p\\:w\n"));
        write(&c.home.join(".my.cnf"), &format!("[mysqld]\npassword=server\n[client]\nuser=root\npassword=\"{PW}\"\nhost=127.0.0.1\n"));
        write(&c.home.join(".mylogin.cnf"), "binary");
        write(
            &c.root.join(".mcp.json.vericto-backup-1"),
            &format!("{{\"x\": \"{url}\"}}"),
        );
        let mut c = c;
        c.env = vec![
            ("DATABASE_URL".into(), url.clone()),
            ("PATH".into(), "/bin".into()),
        ];
        let exps = scan(&c);
        assert_redacted(&exps, &c.home);
        let places: Vec<String> = exps.iter().map(|e| e.place.describe(&c.home)).collect();
        let has = |s: &str| places.iter().any(|p| p.contains(s));
        assert!(
            has("DATABASE_URL in ") && has(".env.local") && !has(".env.example"),
            "{places:?}"
        );
        assert!(has("DATABASE_URL in the environment"), "{places:?}");
        assert!(has("MCP server \"pg\" (args[2])"), "{places:?}");
        assert!(has("MCP server \"local\" (env.DATABASE_URL)"), "{places:?}");
        assert!(
            !has("\"z\""),
            "other projects are not this project's: {places:?}"
        );
        assert!(has("shop.url (read by MCP server \"v\")"), "{places:?}");
        assert!(has("MCP server \"db\" (env.DATABASE_URL)"), "{places:?}");
        assert!(
            has("line 2 of ~/.pgpass") && has("line 3 of ~/.pgpass") && has("line 4 of"),
            "{places:?}"
        );
        assert!(
            has("[client] in ~/.my.cnf") && !has("[mysqld]"),
            "{places:?}"
        );
        assert!(has(".mylogin.cnf") && has("backup copy"), "{places:?}");

        let (creds, rest) = group(&exps);
        // .env, .env.local, .mcp.json, the URL file and the environment are one credential.
        let main = creds.iter().find(|c| c.url.expose() == url).unwrap();
        assert_eq!(main.places.len(), 5, "{:?}", main.places);
        assert_eq!(default_name(&main.info), "shop");
        // pgpass: composed URL with escapes and percent-encoding.
        assert!(creds
            .iter()
            .any(|c| c.url.expose() == "postgresql://u:p%3Aw@db.acme.io:5432/shop"));
        assert!(creds
            .iter()
            .any(|c| c.url.expose() == format!("mysql://root:{PW}@127.0.0.1")));
        assert!(rest
            .iter()
            .any(|e| matches!(e.place, Place::Pgpass { line: 3, .. })));
        assert!(rest
            .iter()
            .any(|e| matches!(e.place, Place::MyLogin { .. })));
    }

    #[test]
    fn names() {
        let u = parse_db_url("postgres://u@h.acme.io/my shop").unwrap();
        assert_eq!(default_name(&u), "my-shop");
        let u = parse_db_url("mysql://u@db1.acme.io").unwrap();
        assert_eq!(default_name(&u), "db1");
        assert_eq!(sanitize_name("a/b c"), "a-b-c");
    }
}
