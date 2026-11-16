// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Which database a command points at, and whether it looks like production.
//!
//! A target is read from what the command says (a URL, `-h host`, `--env
//! production`), its environment prefix, the hook's environment, and the
//! project's `.env` files, in that order. Only the host, the database name and
//! where they came from are kept: user names and passwords are dropped as soon
//! as a URL is read, so nothing secret reaches a decision, a reason or the log.

use std::path::{Path, PathBuf};

use super::config::{glob_match, GuardConfig};

/// How a target is classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// localhost, a loopback address, a socket, a file, a `*.local` name, a
    /// single-label (docker compose service) name, or a `local_hosts` entry.
    Local,
    /// Nothing says local or production.
    Unknown,
    /// Some other host.
    Remote,
    /// Matches a production pattern (default or `prod_hosts`), or an
    /// environment name such as `RAILS_ENV=production`.
    Prod,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Local => "local",
            Class::Unknown => "unknown",
            Class::Remote => "remote",
            Class::Prod => "production",
        }
    }
}

/// One database (or environment) a command points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host, or file path, or a label (`linked Supabase project`). Never a
    /// credential.
    pub host: String,
    pub database: Option<String>,
    pub class: Class,
    /// Where it was read from (`--host`, `DATABASE_URL in .env`…).
    pub source: String,
}

impl Target {
    /// `host/db (production, from DATABASE_URL in .env)`.
    pub fn describe(&self) -> String {
        let mut s = self.host.clone();
        if let Some(db) = &self.database {
            s.push('/');
            s.push_str(db);
        }
        format!("{s} ({}, from {})", self.class.as_str(), self.source)
    }
}

/// Default production markers: a host label or database name token equal to
/// one of these (`db.prod.acme.io`, `prod-db`, `app_production`, `prod2`).
const PROD_TOKENS: &[&str] = &["prod", "production", "prd", "live"];

/// A host or database-name token says production.
fn has_prod_token(s: &str) -> bool {
    s.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| {
            PROD_TOKENS.contains(&t)
                || (t.starts_with("prod")
                    && t[4..].chars().all(|c| c.is_ascii_digit())
                    && t.len() > 4)
        })
}

/// An environment name (`production`, `prod`, `prd`, `live`).
pub fn is_prod_env_name(s: &str) -> bool {
    let s = s.trim().to_ascii_lowercase();
    PROD_TOKENS.contains(&s.as_str()) || s.ends_with(".production") || s.ends_with(".prod")
}

/// Classifies a host (and database name) under `cfg`.
pub fn classify(host: &str, database: Option<&str>, cfg: &GuardConfig) -> Class {
    let h = host
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if cfg
        .prod_hosts
        .iter()
        .any(|p| glob_match(&p.to_ascii_lowercase(), &h))
    {
        return Class::Prod;
    }
    if cfg
        .local_hosts
        .iter()
        .any(|p| glob_match(&p.to_ascii_lowercase(), &h))
    {
        return Class::Local;
    }
    if cfg.default_prod_patterns && (has_prod_token(&h) || database.is_some_and(has_prod_token)) {
        return Class::Prod;
    }
    if h.is_empty() || h.contains('$') || h.contains(super::shell::SUBST) {
        return Class::Unknown;
    }
    if is_local_host(&h) {
        return Class::Local;
    }
    Class::Remote
}

fn is_local_host(h: &str) -> bool {
    h == "localhost"
        || h.ends_with(".localhost")
        || h.ends_with(".local")
        || h.ends_with(".internal") && h.starts_with("host.docker")
        || h.starts_with("127.")
        || h == "::1"
        || h == "0.0.0.0"
        || h.starts_with('/') // unix socket directory
        || h.starts_with('@') // abstract socket
        // A single label with no dot is a docker compose / k8s service name
        // or a machine on the local network (`db`, `postgres`, `mysql`).
        || (!h.contains('.') && !h.contains(':') && !h.is_empty())
}

/// A parsed connection string: host and database, credentials dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub host: String,
    pub database: Option<String>,
}

/// Reads `scheme://[user[:pass]@]host[:port][,host2]/db?params`, a JDBC URL,
/// or a libpq key/value string (`host=x dbname=y`). `None` when `s` is none of
/// those.
pub fn parse_conn(s: &str) -> Option<Conn> {
    let s = s.trim();
    let s = s.strip_prefix("jdbc:").unwrap_or(s);
    if let Some((scheme, rest)) = s.split_once("://") {
        if scheme.is_empty()
            || !scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
        {
            return None;
        }
        let (authority, path) = match rest.find(['/', '?']) {
            Some(p) => (&rest[..p], &rest[p..]),
            None => (rest, ""),
        };
        // Credentials end at the last '@' of the authority.
        let hostport = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);
        let first = hostport.split(',').next().unwrap_or("");
        let host = strip_port(first);
        let mut database = path
            .strip_prefix('/')
            .map(|p| p.split(['?', ';']).next().unwrap_or("").to_string())
            .filter(|d| !d.is_empty());
        let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut host = host.to_string();
        for kv in query.split(['&', ';']) {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "host" if host.is_empty() => host = percent_decode(v),
                    "dbname" | "database" if database.is_none() => database = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        if scheme.starts_with("sqlite") || scheme == "file" {
            return Some(Conn {
                host: "local file".into(),
                database: None,
            });
        }
        return Some(Conn {
            host: percent_decode(&host),
            database,
        });
    }
    if s.contains("host=") || s.contains("dbname=") || s.contains("service=") {
        let mut host = String::new();
        let mut database = None;
        for kv in s.split_whitespace() {
            if let Some((k, v)) = kv.split_once('=') {
                let v = v.trim_matches('\'');
                match k {
                    "host" | "hostaddr" if host.is_empty() => host = v.to_string(),
                    "dbname" => database = Some(v.to_string()),
                    "service" if host.is_empty() => host = format!("service {v}"),
                    _ => {}
                }
            }
        }
        return Some(Conn { host, database });
    }
    None
}

fn strip_port(hp: &str) -> &str {
    if let Some(rest) = hp.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match hp.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => hp,
    }
}

fn percent_decode(s: &str) -> String {
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

/// Variables that name an environment.
pub const ENV_NAME_VARS: &[&str] = &[
    "RAILS_ENV",
    "RACK_ENV",
    "NODE_ENV",
    "APP_ENV",
    "MIX_ENV",
    "ENV",
    "ENVIRONMENT",
    "STAGE",
    "DJANGO_ENV",
    "FLASK_ENV",
    "ASPNETCORE_ENVIRONMENT",
    "DOTNET_ENVIRONMENT",
    "SPRING_PROFILES_ACTIVE",
    "DJANGO_SETTINGS_MODULE",
];

/// Variables that carry a connection URL ORMs and migration tools read.
pub const URL_VARS: &[&str] = &[
    "DATABASE_URL",
    "DIRECT_URL",
    "POSTGRES_URL",
    "POSTGRES_PRISMA_URL",
    "POSTGRES_URL_NON_POOLING",
    "MYSQL_URL",
    "SUPABASE_DB_URL",
    "MONGODB_URI",
    "MONGO_URL",
    "REDIS_URL",
    "FLYWAY_URL",
    "LIQUIBASE_COMMAND_URL",
    "GOOSE_DBSTRING",
    "MIKRO_ORM_CLIENT_URL",
];

/// Host variables (`DB_HOST`, `PGHOST`, `MYSQL_HOST`) with the database
/// variable that goes with each.
pub const HOST_VARS: &[(&str, &str)] = &[
    ("PGHOST", "PGDATABASE"),
    ("DB_HOST", "DB_DATABASE"),
    ("MYSQL_HOST", "MYSQL_DATABASE"),
];

/// A variable environment (`NAME=value` pairs) with where it came from.
#[derive(Debug, Clone, Default)]
pub struct EnvLayer {
    pub vars: Vec<(String, String)>,
    pub source: String,
    /// The file name itself says production (`.env.production`).
    pub prod_file: bool,
}

impl EnvLayer {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Largest `.env` file read.
const MAX_ENV_FILE: u64 = 256 * 1024;

/// Reads a dotenv file (`KEY=value`, `export KEY=value`, quotes, comments).
pub fn read_env_file(path: &Path) -> Option<Vec<(String, String)>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_ENV_FILE {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    Some(parse_env(&text))
}

pub fn parse_env(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if !super::shell::is_name(k) {
            continue;
        }
        let v = v.trim();
        let v = if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2)
            || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2)
        {
            v[1..v.len() - 1].to_string()
        } else {
            v.split(" #").next().unwrap_or(v).trim().to_string()
        };
        out.push((k.to_string(), v));
    }
    out
}

/// The project's dotenv files, highest precedence first: `.env.local` then
/// `.env`, in the working directory and then the project root.
pub fn project_env_layers(cwd: &Path, root: &Path) -> Vec<EnvLayer> {
    let mut dirs: Vec<PathBuf> = vec![cwd.to_path_buf()];
    if root != cwd {
        dirs.push(root.to_path_buf());
    }
    let mut out = Vec::new();
    for d in dirs {
        for name in [".env.local", ".env"] {
            let p = d.join(name);
            if let Some(vars) = read_env_file(&p) {
                out.push(EnvLayer {
                    vars,
                    source: name.to_string(),
                    prod_file: false,
                });
            }
        }
    }
    out
}

/// An env file the command names explicitly (`dotenv -e .env.production`).
pub fn named_env_layer(cwd: &Path, file: &str) -> EnvLayer {
    let p = if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        cwd.join(file)
    };
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.to_string());
    EnvLayer {
        vars: read_env_file(&p).unwrap_or_default(),
        prod_file: has_prod_token(&name),
        source: name,
    }
}

/// Targets read from an environment layer: URL variables, host variables
/// and environment names.
pub fn targets_from_layer(layer: &EnvLayer, cfg: &GuardConfig, url_vars: &[&str]) -> Vec<Target> {
    let mut out = Vec::new();
    for v in url_vars {
        if let Some(val) = layer.get(v) {
            if let Some(c) = parse_conn(val) {
                out.push(Target {
                    class: classify(&c.host, c.database.as_deref(), cfg),
                    host: c.host,
                    database: c.database,
                    source: format!("{v} in {}", layer.source),
                });
            }
        }
    }
    for (hv, dv) in HOST_VARS {
        if let Some(h) = layer.get(hv) {
            let db = layer.get(dv).map(String::from);
            out.push(Target {
                class: classify(h, db.as_deref(), cfg),
                host: h.to_string(),
                database: db,
                source: format!("{hv} in {}", layer.source),
            });
        }
    }
    for v in ENV_NAME_VARS {
        if let Some(val) = layer.get(v) {
            if is_prod_env_name(val) {
                out.push(env_target(&format!("{v}={val}"), &layer.source));
            }
        }
    }
    if layer.prod_file {
        out.push(env_target(&layer.source, "the env file name"));
    }
    out
}

/// A production environment named by a flag or variable.
pub fn env_target(what: &str, source: &str) -> Target {
    Target {
        host: format!("environment {what}"),
        database: None,
        class: Class::Prod,
        source: source.to_string(),
    }
}

/// A target from a connection string or host given in the command.
pub fn conn_target(value: &str, source: &str, cfg: &GuardConfig) -> Option<Target> {
    let c = parse_conn(value)?;
    Some(Target {
        class: classify(&c.host, c.database.as_deref(), cfg),
        host: c.host,
        database: c.database,
        source: source.to_string(),
    })
}

pub fn host_target(host: &str, database: Option<&str>, source: &str, cfg: &GuardConfig) -> Target {
    Target {
        class: classify(host, database, cfg),
        host: host.to_string(),
        database: database.map(String::from),
        source: source.to_string(),
    }
}

/// Removes secrets from a command line for the log and for messages:
/// passwords in URLs, `PASSWORD=`/`TOKEN=`/`SECRET=`/`KEY=` assignments,
/// `-p<password>` (mysql), `--password=…`, `-a <password>` (redis-cli).
pub fn redact(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    let mut rest = cmd;
    // URL credentials: scheme://user:pass@ → scheme://user:***@
    while let Some(p) = rest.find("://") {
        let (head, tail) = rest.split_at(p + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || c == '\'' || c == '"' || c == '/')
            .unwrap_or(tail.len());
        let authority = &tail[..end];
        if let Some(at) = authority.rfind('@') {
            let userinfo = &authority[..at];
            match userinfo.split_once(':') {
                Some((u, _)) => {
                    out.push_str(u);
                    out.push_str(":***");
                }
                None => out.push_str(userinfo),
            }
            out.push_str(&authority[at..]);
        } else {
            out.push_str(authority);
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    // Word-level secrets.
    let mut words: Vec<String> = Vec::new();
    let mut redact_next = false;
    for w in out.split(' ') {
        if redact_next && !w.is_empty() {
            words.push("***".into());
            redact_next = false;
            continue;
        }
        let lower = w.to_ascii_lowercase();
        if let Some((k, _)) = w.split_once('=') {
            let kl = k.to_ascii_lowercase();
            let key = kl.trim_start_matches('-');
            if [
                "pass",
                "secret",
                "token",
                "key",
                "pwd",
                "auth",
                "credential",
            ]
            .iter()
            .any(|s| key.contains(s))
            {
                words.push(format!("{k}=***"));
                continue;
            }
        }
        if w.len() > 2
            && w.starts_with("-p")
            && !w.starts_with("--")
            && !w[2..].chars().all(|c| c.is_ascii_digit())
        {
            // mysql -pSECRET (a bare -p prompts; -p5432 is psql's port).
            words.push("-p***".into());
            continue;
        }
        if matches!(lower.as_str(), "-a" | "--pass" | "--password" | "-P") || w == "-P" {
            words.push(w.to_string());
            redact_next = true;
            continue;
        }
        words.push(w.to_string());
    }
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GuardConfig {
        GuardConfig::default()
    }

    #[test]
    fn parses_urls_without_keeping_credentials() {
        let c =
            parse_conn("postgres://admin:s3cret@db.prod.acme.io:5432/app?sslmode=require").unwrap();
        assert_eq!(c.host, "db.prod.acme.io");
        assert_eq!(c.database.as_deref(), Some("app"));
        let c = parse_conn("jdbc:postgresql://pg1:5432,pg2/app").unwrap();
        assert_eq!(c.host, "pg1");
        let c = parse_conn("mysql://u@[::1]:3306/x").unwrap();
        assert_eq!(c.host, "::1");
        let c = parse_conn("postgresql:///app?host=/var/run/postgresql").unwrap();
        assert_eq!(c.host, "/var/run/postgresql");
        let c = parse_conn("host=10.0.0.5 dbname=app_production user=x").unwrap();
        assert_eq!(c.host, "10.0.0.5");
        assert_eq!(c.database.as_deref(), Some("app_production"));
        assert!(parse_conn("app").is_none());
        assert!(parse_conn("select 1").is_none());
    }

    #[test]
    fn classifies_hosts() {
        let c = cfg();
        assert_eq!(classify("localhost", None, &c), Class::Local);
        assert_eq!(classify("127.0.0.1", None, &c), Class::Local);
        assert_eq!(classify("db", None, &c), Class::Local);
        assert_eq!(classify("myapp.local", None, &c), Class::Local);
        assert_eq!(classify("host.docker.internal", None, &c), Class::Local);
        assert_eq!(classify("db.prod.acme.io", None, &c), Class::Prod);
        assert_eq!(classify("prod-db", None, &c), Class::Prod);
        assert_eq!(classify("pg-prd-01.acme.io", None, &c), Class::Prod);
        assert_eq!(classify("prod2.acme.io", None, &c), Class::Prod);
        assert_eq!(
            classify("localhost", Some("app_production"), &c),
            Class::Prod
        );
        assert_eq!(classify("staging.acme.io", None, &c), Class::Remote);
        assert_eq!(classify("product-db.acme.io", None, &c), Class::Remote);
        assert_eq!(classify("$PGHOST", None, &c), Class::Unknown);
        let mut c2 = cfg();
        c2.prod_hosts = vec!["*.rds.amazonaws.com".into()];
        c2.local_hosts = vec!["devbox.acme.io".into()];
        assert_eq!(
            classify("x.abc.us-east-1.rds.amazonaws.com", None, &c2),
            Class::Prod
        );
        assert_eq!(classify("devbox.acme.io", None, &c2), Class::Local);
        c2.default_prod_patterns = false;
        assert_eq!(classify("db.prod.acme.io", None, &c2), Class::Remote);
    }

    #[test]
    fn env_files() {
        let v = parse_env(
            "# c\nexport DATABASE_URL=\"postgres://u:p@h/db\"\nX='a b'\nY=1 # note\nbad line\n",
        );
        assert_eq!(v[0], ("DATABASE_URL".into(), "postgres://u:p@h/db".into()));
        assert_eq!(v[1], ("X".into(), "a b".into()));
        assert_eq!(v[2], ("Y".into(), "1".into()));
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn env_names() {
        assert!(is_prod_env_name("production"));
        assert!(is_prod_env_name("prod"));
        assert!(is_prod_env_name("myapp.settings.production"));
        assert!(!is_prod_env_name("development"));
        assert!(!is_prod_env_name("test"));
    }

    #[test]
    fn redacts_secrets() {
        let r = redact("PGPASSWORD=hunter2 psql postgres://admin:hunter2@db.prod/app -c 'x'");
        assert!(!r.contains("hunter2"), "{r}");
        assert!(r.contains("db.prod/app"));
        let r = redact("mysql -uroot -phunter2 -h db app");
        assert!(!r.contains("hunter2"), "{r}");
        let r = redact("redis-cli -a hunter2 FLUSHALL");
        assert!(!r.contains("hunter2"), "{r}");
        let r = redact("cmd --password=hunter2 API_TOKEN=abc");
        assert!(!r.contains("hunter2") && !r.contains("abc"), "{r}");
        assert_eq!(redact("psql -p 5432 -h x"), "psql -p 5432 -h x");
        assert_eq!(redact("psql -p5432"), "psql -p5432");
    }
}
