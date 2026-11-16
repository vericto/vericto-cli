// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto-proxy` for hard mode: finding it, checking its version, and its
//! `mcp credential set|test|delete` contract (one JSON object on stdout, a
//! sentence on stderr, exit codes 0 ok, 1 usage or store error, 2 no such
//! entry, 3 the role can write, 4 unreachable). The URL only ever goes to
//! the child's stdin, never to its argv.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::exposure::Secret;

/// The first release with `--database-url-keychain` and `mcp credential`.
pub const MIN_VERSION: (u64, u64, u64) = (5, 2, 0);

pub fn min_version() -> String {
    let (a, b, c) = MIN_VERSION;
    format!("{a}.{b}.{c}")
}

#[derive(Debug, Clone)]
pub struct Proxy {
    pub path: PathBuf,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocateError {
    Missing { searched: Vec<PathBuf> },
    TooOld { path: PathBuf, version: String },
    Broken { path: PathBuf, message: String },
}

impl LocateError {
    /// What to tell the user, with the commands that fix it (nothing is
    /// installed for them).
    pub fn message(&self) -> String {
        let min = min_version();
        let how = install_hint();
        match self {
            LocateError::Missing { .. } => format!(
                "hard mode needs vericto-proxy {min} or later, and it is not installed (not on PATH, not in Homebrew's or Cargo's bin directory).\nInstall it:\n{how}\nThen run this command again (or pass --proxy /path/to/vericto-proxy)."
            ),
            LocateError::TooOld { path, version } => format!(
                "hard mode needs vericto-proxy {min} or later (the version that ships --database-url-keychain); {} is {version}.\nUpgrade it:\n{}\nThen run this command again.",
                path.display(),
                upgrade_hint(path)
            ),
            LocateError::Broken { path, message } => format!(
                "cannot run {} --version ({message}); reinstall it:\n{how}",
                path.display()
            ),
        }
    }
}

pub fn install_hint() -> String {
    let v = min_version();
    if cfg!(windows) {
        format!("  download vericto-proxy-x86_64-pc-windows-msvc.zip from https://github.com/vericto/vericto-proxy/releases/tag/v{v}, check its .sha256, unpack it and put vericto-proxy.exe on PATH")
    } else {
        format!(
            "  brew install vericto/tap/vericto-proxy\n  or: curl --proto '=https' --tlsv1.2 -LsSf https://github.com/vericto/vericto-proxy/releases/download/v{v}/vericto-proxy-installer.sh | sh"
        )
    }
}

fn upgrade_hint(path: &Path) -> String {
    let p = path.to_string_lossy();
    if p.contains("/homebrew/") || p.contains("/linuxbrew/") || p.starts_with("/usr/local/") {
        "  brew upgrade vericto-proxy".into()
    } else {
        install_hint()
    }
}

/// `5.2.0`, `5.10.1-rc.1` → numbers and whether it is a pre-release.
pub fn parse_version(s: &str) -> Option<((u64, u64, u64), bool)> {
    let s = s.trim();
    let s = s.strip_prefix("vericto-proxy").unwrap_or(s).trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let word = s.split_whitespace().next()?;
    let (core, pre) = match word.split_once(['-', '+']) {
        Some((c, rest)) => (c, word.as_bytes()[c.len()] == b'-' && !rest.is_empty()),
        None => (word, false),
    };
    let mut it = core.split('.').map(|x| x.parse::<u64>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    Some((v, pre))
}

/// A pre-release of the minimum (`5.2.0-rc.1`) is older than it.
pub fn new_enough(v: &str) -> bool {
    match parse_version(v) {
        Some((n, pre)) => n > MIN_VERSION || (n == MIN_VERSION && !pre),
        None => false,
    }
}

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "vericto-proxy.exe"
    } else {
        "vericto-proxy"
    }
}

/// Where to look, in order: `PATH`, then Homebrew's and Cargo's bin
/// directories (a GUI-started agent's PATH often lacks them).
pub fn candidates(path_var: Option<&str>, home: &Path, cargo_home: Option<&str>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Some(p) = path_var {
        v.extend(std::env::split_paths(p).map(|d| d.join(exe_name())));
    }
    for d in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/home/linuxbrew/.linuxbrew/bin",
    ] {
        v.push(Path::new(d).join(exe_name()));
    }
    let cargo = cargo_home
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".cargo"));
    v.push(cargo.join("bin").join(exe_name()));
    let mut seen = Vec::new();
    v.retain(|p| {
        let new = !seen.contains(p);
        seen.push(p.clone());
        new
    });
    v
}

/// Finds a `vericto-proxy` new enough for hard mode. `explicit` (from
/// `--proxy`) is the only one tried when given.
pub fn locate(explicit: Option<&Path>, candidates: &[PathBuf]) -> Result<Proxy, LocateError> {
    let list: Vec<PathBuf> = match explicit {
        Some(p) => vec![p.to_path_buf()],
        None => candidates.to_vec(),
    };
    let Some(found) = list.iter().find(|p| p.is_file()) else {
        return Err(LocateError::Missing { searched: list });
    };
    let path = std::path::absolute(found).unwrap_or_else(|_| found.clone());
    let out = Command::new(&path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| LocateError::Broken {
            path: path.clone(),
            message: e.to_string(),
        })?;
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    let version = text
        .lines()
        .find(|l| l.trim_start().starts_with("vericto-proxy"))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("")
        .to_string();
    if version.is_empty() || parse_version(&version).is_none() {
        return Err(LocateError::Broken {
            path,
            message: "no version in its output".into(),
        });
    }
    if !new_enough(&version) {
        return Err(LocateError::TooOld { path, version });
    }
    Ok(Proxy { path, version })
}

/// What one `vericto-proxy mcp credential …` call answered.
#[derive(Debug, Clone)]
pub struct Answer {
    /// The exit code (`-1`: killed or timed out).
    pub code: i32,
    pub json: Value,
    /// The proxy's sentence (never holds the URL).
    pub stderr: String,
}

/// The role check of `credential test`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleState {
    ReadOnly,
    CanWrite,
    Unverified,
    Unreachable,
    NoEntry,
    Failed,
}

impl RoleState {
    pub fn as_str(self) -> &'static str {
        match self {
            RoleState::ReadOnly => "read-only (verified)",
            RoleState::CanWrite => "can write",
            RoleState::Unverified => "unverified",
            RoleState::Unreachable => "unreachable",
            RoleState::NoEntry => "no such keychain entry",
            RoleState::Failed => "check failed",
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            RoleState::ReadOnly => "read_only",
            RoleState::CanWrite => "can_write",
            RoleState::Unverified => "unverified",
            RoleState::Unreachable => "unreachable",
            RoleState::NoEntry => "no_entry",
            RoleState::Failed => "failed",
        }
    }
}

impl Answer {
    /// Reads `credential test` (exit codes 0, 2, 3, 4, else a failure).
    pub fn role(&self) -> RoleState {
        let role = &self.json["database_role"];
        match self.code {
            0 => match role["read_only"].as_bool() {
                Some(true) => RoleState::ReadOnly,
                Some(false) => RoleState::CanWrite,
                None => RoleState::Unverified,
            },
            3 => {
                if role["verified"].as_bool() == Some(false) || role["read_only"].is_null() {
                    RoleState::Unverified
                } else {
                    RoleState::CanWrite
                }
            }
            4 => RoleState::Unreachable,
            2 => RoleState::NoEntry,
            _ => RoleState::Failed,
        }
    }
    pub fn reasons(&self) -> Vec<String> {
        self.json["database_role"]["reasons"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default()
    }
    /// The proxy's message, for errors.
    pub fn message(&self) -> String {
        let s = self.stderr.trim();
        if !s.is_empty() {
            return s.to_string();
        }
        self.json["message"]
            .as_str()
            .or_else(|| self.json["error"].as_str())
            .unwrap_or("no message")
            .to_string()
    }
}

impl Proxy {
    fn run(&self, args: &[&str], stdin: Option<&Secret>, timeout: Option<Duration>) -> Answer {
        let mut cmd = Command::new(&self.path);
        cmd.arg("mcp")
            .arg("credential")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                return Answer {
                    code: -1,
                    json: Value::Null,
                    stderr: format!("cannot run {}: {e}", self.path.display()),
                }
            }
        };
        if let (Some(s), Some(mut w)) = (stdin, child.stdin.take()) {
            // One line; the pipe is closed when `w` drops.
            let _ = w.write_all(s.expose().as_bytes());
            let _ = w.write_all(b"\n");
        }
        if let Some(t) = timeout {
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if start.elapsed() < t => {
                        std::thread::sleep(Duration::from_millis(50))
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Answer {
                            code: -1,
                            json: Value::Null,
                            stderr: format!("no answer within {} s", t.as_secs()),
                        };
                    }
                }
            }
        }
        let out = match child.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                return Answer {
                    code: -1,
                    json: Value::Null,
                    stderr: e.to_string(),
                }
            }
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let json = stdout
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
            .unwrap_or(Value::Null);
        Answer {
            code: out.status.code().unwrap_or(-1),
            json,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// `credential set <name>` with the URL on stdin.
    pub fn set(&self, name: &str, url: &Secret) -> Answer {
        self.run(&["set", name], Some(url), None)
    }

    /// `credential test <name> [--require-read-only]`.
    pub fn test(&self, name: &str, require_read_only: bool, timeout: Option<Duration>) -> Answer {
        let mut a = vec!["test", name];
        if require_read_only {
            a.push("--require-read-only");
        }
        self.run(&a, None, timeout)
    }

    /// `credential delete <name>`.
    pub fn delete(&self, name: &str) -> Answer {
        self.run(&["delete", name], None, None)
    }
}

/// The SQL that creates a role the proxy accepts as read-only.
pub fn read_only_role_sql(dialect: &str, database: Option<&str>) -> String {
    let db = database.unwrap_or("app");
    match dialect {
        "mysql" | "mariadb" => format!(
            "CREATE USER 'vericto_agent_ro'@'%' IDENTIFIED BY '…' REQUIRE SSL;\n\
             GRANT SELECT, SHOW VIEW ON `{db}`.* TO 'vericto_agent_ro'@'%';\n\
             -- Nothing else: no INSERT/UPDATE/DELETE, no CREATE TEMPORARY TABLES, no EXECUTE.\n\
             -- Grant to the user itself, not through a role, so the check can verify it."
        ),
        _ => format!(
            "CREATE ROLE vericto_agent_ro LOGIN PASSWORD '…';\n\
             GRANT CONNECT ON DATABASE \"{db}\" TO vericto_agent_ro;\n\
             GRANT USAGE ON SCHEMA public TO vericto_agent_ro;\n\
             GRANT SELECT ON ALL TABLES IN SCHEMA public TO vericto_agent_ro;\n\
             ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO vericto_agent_ro;\n\
             -- PostgreSQL 14 and later, every table at once: GRANT pg_read_all_data TO vericto_agent_ro;"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(new_enough("5.2.0"));
        assert!(new_enough("vericto-proxy 5.2.1"));
        assert!(new_enough("5.10.0"));
        assert!(new_enough("6.0.0"));
        assert!(new_enough("5.2.0+build.1"));
        assert!(!new_enough("5.2.0-rc.1"));
        assert!(!new_enough("5.1.9"));
        assert!(!new_enough("4.99.0"));
        assert!(!new_enough("garbage"));
    }

    #[test]
    fn candidates_start_with_path() {
        let c = candidates(Some("/a:/b"), Path::new("/h"), None);
        if !cfg!(windows) {
            assert_eq!(c[0], Path::new("/a/vericto-proxy"));
            assert_eq!(c[1], Path::new("/b/vericto-proxy"));
            assert!(c.contains(&PathBuf::from("/h/.cargo/bin/vericto-proxy")));
            assert!(c.contains(&PathBuf::from("/opt/homebrew/bin/vericto-proxy")));
        }
    }

    #[test]
    fn missing_proxy_says_how_to_install() {
        let e = locate(Some(Path::new("/nonexistent/vericto-proxy")), &[]).unwrap_err();
        assert!(matches!(e, LocateError::Missing { .. }));
        let m = e.message();
        assert!(m.contains("5.2.0") && m.contains("vericto-proxy"), "{m}");
        let m = LocateError::TooOld {
            path: "/opt/homebrew/bin/vericto-proxy".into(),
            version: "5.1.0".into(),
        }
        .message();
        assert!(
            m.contains("brew upgrade vericto-proxy") && m.contains("5.1.0"),
            "{m}"
        );
    }

    #[test]
    fn role_states() {
        let a = |code, json: Value| Answer {
            code,
            json,
            stderr: String::new(),
        };
        let ro = serde_json::json!({"database_role": {"read_only": true, "verified": true}});
        let rw = serde_json::json!({"database_role": {"read_only": false, "verified": true, "reasons": ["superuser"]}});
        let unv = serde_json::json!({"database_role": {"read_only": null, "verified": false}});
        assert_eq!(a(0, ro).role(), RoleState::ReadOnly);
        assert_eq!(a(3, rw.clone()).role(), RoleState::CanWrite);
        assert_eq!(a(3, rw.clone()).reasons(), vec!["superuser"]);
        assert_eq!(a(3, unv).role(), RoleState::Unverified);
        assert_eq!(a(0, rw).role(), RoleState::CanWrite);
        assert_eq!(a(4, Value::Null).role(), RoleState::Unreachable);
        assert_eq!(a(2, Value::Null).role(), RoleState::NoEntry);
        assert_eq!(a(1, Value::Null).role(), RoleState::Failed);
    }

    #[test]
    fn role_sql() {
        assert!(read_only_role_sql("postgres", Some("shop"))
            .contains("GRANT CONNECT ON DATABASE \"shop\""));
        assert!(read_only_role_sql("mysql", Some("shop"))
            .contains("GRANT SELECT, SHOW VIEW ON `shop`.*"));
    }
}
