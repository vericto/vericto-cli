// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The `[guard]` section of `.vericto.toml`.
//!
//! ```toml
//! [guard]
//! mode = "block"            # block | ask | warn
//! high_sql = "ask"          # engine High findings: deny | ask | warn | allow
//! allow_local = false       # destructive ops whose every target is local: warn only
//! unverified_sql = "allow"  # SQL the guard cannot see (`gen | psql`): allow | ask | deny
//! prod_hosts = ["*.rds.amazonaws.com"]
//! local_hosts = ["devdb.internal"]
//! log_sql = "redacted"      # redacted | hash | none
//!
//! [guard.checks]
//! sql = true
//! mcp = true
//! orm = true
//! platform = true
//! prod_context = true
//!
//! [[guard.allow]]
//! rule = "VG-101"
//! command = "npx prisma migrate reset --force*"
//! reason = "the e2e suite resets its throwaway database"
//! ```
//!
//! Unknown keys are an error, so a typo does not silently turn a check off;
//! when the section cannot be read the hook falls back to the defaults (the
//! strictest reading) and says so.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// How strongly the guard acts on what it finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Critical findings are denied, medium ones asked (the default).
    #[default]
    Block,
    /// Everything is asked, except destructive operations on production.
    Ask,
    /// Everything is allowed with a warning, except destructive operations
    /// on production.
    Warn,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Block => "block",
            Mode::Ask => "ask",
            Mode::Warn => "warn",
        }
    }
}

/// An action a setting maps a finding to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Act {
    Deny,
    Ask,
    Warn,
    Allow,
}

/// What `log_sql` keeps of a command in the decision log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogSql {
    /// The command with secrets and string literals removed, truncated.
    #[default]
    Redacted,
    /// A SHA-256 of the command only.
    Hash,
    /// Neither (codes, verdict and targets are still logged).
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Checks {
    pub sql: bool,
    pub mcp: bool,
    pub orm: bool,
    pub platform: bool,
    pub prod_context: bool,
}

impl Default for Checks {
    fn default() -> Self {
        Checks {
            sql: true,
            mcp: true,
            orm: true,
            platform: true,
            prod_context: true,
        }
    }
}

/// One allow entry. `reason` is required; at least one of `rule` and
/// `command` must be set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// Rule code, `*` wildcards allowed (`VG-1*`, `VERICTO-015`).
    #[serde(default)]
    pub rule: Option<String>,
    /// The command as the agent wrote it, `*` wildcards allowed.
    #[serde(default)]
    pub command: Option<String>,
    pub reason: String,
    /// Also applies when the target looks like production (off by default:
    /// an allow entry never opens production unless it says so).
    #[serde(default)]
    pub prod: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GuardConfig {
    pub mode: Mode,
    pub high_sql: Act,
    pub allow_local: bool,
    pub unverified_sql: Act,
    pub prod_hosts: Vec<String>,
    pub local_hosts: Vec<String>,
    /// The built-in production markers (`prod`, `production`, `prd`, `live`
    /// as a host or database-name token).
    pub default_prod_patterns: bool,
    pub log: bool,
    pub log_sql: LogSql,
    pub log_path: Option<PathBuf>,
    pub checks: Checks,
    pub allow: Vec<AllowEntry>,
}

impl Default for GuardConfig {
    fn default() -> Self {
        GuardConfig {
            mode: Mode::Block,
            high_sql: Act::Ask,
            allow_local: false,
            unverified_sql: Act::Allow,
            prod_hosts: Vec::new(),
            local_hosts: Vec::new(),
            default_prod_patterns: true,
            log: true,
            log_sql: LogSql::Redacted,
            log_path: None,
            checks: Checks::default(),
            allow: Vec::new(),
        }
    }
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    guard: Option<GuardConfig>,
}

/// Where the configuration came from, for `status`, `test` and warnings.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: GuardConfig,
    /// The `.vericto.toml` read, if any.
    pub path: Option<PathBuf>,
    /// The project root: the directory holding `.vericto.toml`, else the
    /// nearest directory with `.git`, else the working directory.
    pub root: PathBuf,
    /// Why the file could not be used (the defaults apply instead).
    pub error: Option<String>,
    pub migration_paths: Vec<String>,
}

/// Finds and reads the project configuration for `cwd`: the nearest
/// `.vericto.toml` at or above it, stopping at the repository root.
pub fn load(cwd: &Path) -> Loaded {
    let mut dir = Some(cwd);
    let mut git_root: Option<PathBuf> = None;
    while let Some(d) = dir {
        let candidate = d.join(".vericto.toml");
        if candidate.is_file() {
            return read(&candidate, d.to_path_buf());
        }
        if d.join(".git").exists() {
            git_root = Some(d.to_path_buf());
            break;
        }
        dir = d.parent();
    }
    Loaded {
        config: GuardConfig::default(),
        path: None,
        root: git_root.unwrap_or_else(|| cwd.to_path_buf()),
        error: None,
        migration_paths: Vec::new(),
    }
}

fn read(path: &Path, root: PathBuf) -> Loaded {
    let mut out = Loaded {
        config: GuardConfig::default(),
        path: Some(path.to_path_buf()),
        root,
        error: None,
        migration_paths: Vec::new(),
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            out.error = Some(format!("cannot read {}: {e}", path.display()));
            return out;
        }
    };
    match parse(&text) {
        Ok(c) => out.config = c,
        Err(e) => out.error = Some(format!("{}: {e}", path.display())),
    }
    if let Ok(f) = toml::from_str::<MigrationPaths>(&text) {
        out.migration_paths = f.migration_paths;
    }
    out
}

#[derive(Deserialize)]
struct MigrationPaths {
    #[serde(default)]
    migration_paths: Vec<String>,
}

/// Parses the `[guard]` section of a `.vericto.toml` document.
pub fn parse(text: &str) -> Result<GuardConfig, String> {
    let file: File = toml::from_str(text).map_err(|e| format!("invalid [guard] section: {e}"))?;
    let cfg = file.guard.unwrap_or_default();
    for (i, a) in cfg.allow.iter().enumerate() {
        if a.reason.trim().is_empty() {
            return Err(format!(
                "[[guard.allow]] entry {} has an empty reason",
                i + 1
            ));
        }
        if a.rule.is_none() && a.command.is_none() {
            return Err(format!(
                "[[guard.allow]] entry {} needs `rule`, `command` or both",
                i + 1
            ));
        }
    }
    Ok(cfg)
}

/// `*` matches any run of characters (`?` one); everything else literally.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_without_section() {
        let c = parse("default_dialect = \"mysql\"\n").unwrap();
        assert_eq!(c.mode, Mode::Block);
        assert!(c.checks.sql && c.checks.orm && c.log);
    }

    #[test]
    fn full_section() {
        let c = parse(
            r#"
[guard]
mode = "ask"
high_sql = "deny"
allow_local = true
prod_hosts = ["*.rds.amazonaws.com"]
log_sql = "hash"
[guard.checks]
platform = false
[[guard.allow]]
rule = "VG-101"
reason = "e2e"
"#,
        )
        .unwrap();
        assert_eq!(c.mode, Mode::Ask);
        assert_eq!(c.high_sql, Act::Deny);
        assert!(c.allow_local);
        assert!(!c.checks.platform && c.checks.sql);
        assert_eq!(c.log_sql, LogSql::Hash);
        assert_eq!(c.allow[0].rule.as_deref(), Some("VG-101"));
    }

    #[test]
    fn rejects_typos_and_reasonless_allows() {
        assert!(parse("[guard]\nmdoe = \"warn\"\n").is_err());
        assert!(parse("[guard]\nmode = \"off\"\n").is_err());
        assert!(parse("[[guard.allow]]\nrule = \"VG-101\"\n").is_err());
        assert!(parse("[[guard.allow]]\nrule = \"VG-101\"\nreason = \"  \"\n").is_err());
        assert!(parse("[[guard.allow]]\nreason = \"x\"\n").is_err());
    }

    #[test]
    fn globs() {
        assert!(glob_match("VG-1*", "VG-101"));
        assert!(glob_match(
            "*prisma migrate reset*",
            "npx prisma migrate reset --force"
        ));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("VG-1*", "VG-201"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("abc", "abcd"));
    }

    #[test]
    fn finds_config_upwards() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".vericto.toml"), "[guard]\nmode = \"warn\"\n").unwrap();
        let sub = d.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        let l = load(&sub);
        assert_eq!(l.config.mode, Mode::Warn);
        assert_eq!(l.root, d.path());
        std::fs::write(d.path().join(".vericto.toml"), "[guard]\nmode = 1\n").unwrap();
        let l = load(&sub);
        assert!(l.error.is_some());
        assert_eq!(l.config.mode, Mode::Block);
    }
}
