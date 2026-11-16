// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto guard install | uninstall | status`: the agents' hook
//! configuration files, merged in place.
//!
//! | agent  | project scope            | user scope                                   |
//! |--------|--------------------------|----------------------------------------------|
//! | claude | `.claude/settings.json`  | `$CLAUDE_CONFIG_DIR` or `~/.claude/settings.json` |
//! | cursor | `.cursor/hooks.json`     | `~/.cursor/hooks.json`                       |
//! | codex  | `.codex/hooks.json`      | `$CODEX_HOME` or `~/.codex/hooks.json`       |
//!
//! Rules: the file's other content (other hooks, other settings, key order)
//! is kept as it is; the guard's own entry is recognised by its command
//! (`… guard hook --agent …`), so running install twice changes nothing and
//! uninstall removes only that entry. A file that is not valid JSON is never
//! rewritten. Before a file is changed it is copied to
//! `<file>.vericto-backup-<unix time>`. `--dry-run` prints the diff instead.

use std::path::{Path, PathBuf};

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use super::hook::Agent;

/// JSON with object keys kept in file order (serde_json's `Value` sorts them
/// unless its `preserve_order` feature is on, which would also reorder the
/// CLI's other JSON output).
#[derive(Debug, Clone, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(serde_json::Number),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, k: &str) -> Option<&J> {
        match self {
            J::Obj(m) => m.iter().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }
    fn get_mut(&mut self, k: &str) -> Option<&mut J> {
        match self {
            J::Obj(m) => m.iter_mut().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }
    /// The object member `k`, created as `default` when missing.
    fn entry(&mut self, k: &str, default: J) -> Result<&mut J, String> {
        let J::Obj(m) = self else {
            return Err("expected a JSON object".into());
        };
        if !m.iter().any(|(x, _)| x == k) {
            m.push((k.to_string(), default));
        }
        Ok(m.iter_mut()
            .find(|(x, _)| x == k)
            .map(|(_, v)| v)
            .expect("just inserted"))
    }
    fn remove(&mut self, k: &str) {
        if let J::Obj(m) = self {
            m.retain(|(x, _)| x != k);
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }
    fn is_empty_container(&self) -> bool {
        matches!(self, J::Arr(a) if a.is_empty()) || matches!(self, J::Obj(o) if o.is_empty())
    }
}

impl Serialize for J {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            J::Null => s.serialize_unit(),
            J::Bool(b) => s.serialize_bool(*b),
            J::Num(n) => n.serialize(s),
            J::Str(x) => s.serialize_str(x),
            J::Arr(a) => {
                let mut q = s.serialize_seq(Some(a.len()))?;
                for x in a {
                    q.serialize_element(x)?;
                }
                q.end()
            }
            J::Obj(o) => {
                let mut m = s.serialize_map(Some(o.len()))?;
                for (k, v) in o {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for J {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<J, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = J;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_unit<E>(self) -> Result<J, E> {
                Ok(J::Null)
            }
            fn visit_bool<E>(self, b: bool) -> Result<J, E> {
                Ok(J::Bool(b))
            }
            fn visit_i64<E>(self, n: i64) -> Result<J, E> {
                Ok(J::Num(n.into()))
            }
            fn visit_u64<E>(self, n: u64) -> Result<J, E> {
                Ok(J::Num(n.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, n: f64) -> Result<J, E> {
                serde_json::Number::from_f64(n)
                    .map(J::Num)
                    .ok_or_else(|| E::custom("bad number"))
            }
            fn visit_str<E>(self, s: &str) -> Result<J, E> {
                Ok(J::Str(s.to_string()))
            }
            fn visit_string<E>(self, s: String) -> Result<J, E> {
                Ok(J::Str(s))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element()? {
                    v.push(x);
                }
                Ok(J::Arr(v))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<J, A::Error> {
                let mut v: Vec<(String, J)> = Vec::new();
                while let Some((k, x)) = a.next_entry::<String, J>()? {
                    // A repeated key: the last one wins, as in serde_json.
                    v.retain(|(y, _)| *y != k);
                    v.push((k, x));
                }
                Ok(J::Obj(v))
            }
        }
        d.deserialize_any(V)
    }
}

fn obj(pairs: Vec<(&str, J)>) -> J {
    J::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn st(s: &str) -> J {
    J::Str(s.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Project,
    User,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Project => "project",
            Scope::User => "user",
        }
    }
}

/// The matcher the guard installs for Claude Code and Codex.
pub const MATCHER: &str = "Bash|mcp__.*";
/// Seconds an agent waits for the hook. The guard answers in milliseconds;
/// the margin covers a cold disk cache.
pub const TIMEOUT_SECS: u64 = 10;

/// The marker that identifies the guard's own entries.
pub fn is_ours(cmd: &str) -> bool {
    cmd.contains("guard hook --agent")
}

/// Where `agent` keeps hooks for `scope`.
pub fn config_path(
    agent: Agent,
    scope: Scope,
    root: &Path,
    home: &Path,
    env: &dyn Fn(&str) -> Option<String>,
) -> PathBuf {
    match (agent, scope) {
        (Agent::Claude, Scope::Project) => root.join(".claude").join("settings.json"),
        (Agent::Claude, Scope::User) => env("CLAUDE_CONFIG_DIR")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".claude"))
            .join("settings.json"),
        (Agent::Cursor, Scope::Project) => root.join(".cursor").join("hooks.json"),
        (Agent::Cursor, Scope::User) => home.join(".cursor").join("hooks.json"),
        (Agent::Codex, Scope::Project) => root.join(".codex").join("hooks.json"),
        (Agent::Codex, Scope::User) => env("CODEX_HOME")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"))
            .join("hooks.json"),
    }
}

/// The command an agent runs: `<bin> guard hook --agent <agent>`.
pub fn hook_command(bin: &str, agent: Agent) -> String {
    format!("{} guard hook --agent {}", quote_bin(bin), agent.as_str())
}

fn quote_bin(bin: &str) -> String {
    let b = if cfg!(windows) {
        bin.replace('\\', "/")
    } else {
        bin.to_string()
    };
    if b.chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:@+".contains(c))
    {
        b
    } else {
        format!("\"{}\"", b.replace('"', "\\\""))
    }
}

/// The binary to write into hook commands: the `vericto` on PATH when it is
/// this binary (a stable path such as `/opt/homebrew/bin/vericto` that
/// survives upgrades), else this binary's own path.
pub fn default_bin(env: &dyn Fn(&str) -> Option<String>) -> String {
    let exe = std::env::current_exe().ok();
    let exe_canon = exe.as_ref().and_then(|p| std::fs::canonicalize(p).ok());
    if let Some(path) = env("PATH") {
        let name = if cfg!(windows) {
            "vericto.exe"
        } else {
            "vericto"
        };
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(name);
            if cand.is_file() {
                if let (Ok(c), Some(e)) = (std::fs::canonicalize(&cand), exe_canon.as_ref()) {
                    if &c == e {
                        return cand.to_string_lossy().into_owned();
                    }
                }
                break;
            }
        }
    }
    exe.map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vericto".into())
}

/// A change to one file.
#[derive(Debug, Clone)]
pub struct Plan {
    pub path: PathBuf,
    pub before: Option<String>,
    pub after: String,
    pub changed: bool,
}

fn read_json(path: &Path) -> Result<(Option<String>, J), String> {
    match std::fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => Ok((Some(text), J::Obj(Vec::new()))),
        Ok(text) => {
            let j: J = serde_json::from_str(&text).map_err(|e| {
                format!("{} is not valid JSON ({e}); fix or move it first, vericto guard does not rewrite a file it cannot read", path.display())
            })?;
            if !matches!(j, J::Obj(_)) {
                return Err(format!(
                    "{} is not a JSON object; leaving it alone",
                    path.display()
                ));
            }
            Ok((Some(text), j))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((None, J::Obj(Vec::new()))),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn to_text(j: &J) -> String {
    let mut s = serde_json::to_string_pretty(j).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

/// The entry the guard adds (inside a matcher group for Claude and Codex).
fn our_entry(agent: Agent, cmd: &str, fail_open: bool) -> J {
    match agent {
        Agent::Claude => obj(vec![
            ("type", st("command")),
            ("command", st(cmd)),
            ("timeout", J::Num(TIMEOUT_SECS.into())),
        ]),
        Agent::Codex => obj(vec![
            ("type", st("command")),
            ("command", st(cmd)),
            ("timeout", J::Num(TIMEOUT_SECS.into())),
            (
                "statusMessage",
                st("vericto guard: checking database commands"),
            ),
        ]),
        Agent::Cursor => {
            let mut v = vec![
                ("command", st(cmd)),
                ("timeout", J::Num(TIMEOUT_SECS.into())),
            ];
            if !fail_open {
                v.push(("failClosed", J::Bool(true)));
            }
            obj(v)
        }
    }
}

fn entry_cmd(e: &J) -> Option<&str> {
    e.get("command").and_then(J::as_str)
}

/// Removes the guard's entries from a Claude/Codex event array (matcher
/// groups). Returns how many were removed.
fn strip_grouped(arr: &mut Vec<J>) -> usize {
    let mut removed = 0;
    for g in arr.iter_mut() {
        if let Some(J::Arr(hs)) = g.get_mut("hooks") {
            let n = hs.len();
            hs.retain(|h| !entry_cmd(h).is_some_and(is_ours));
            removed += n - hs.len();
        }
    }
    arr.retain(|g| !matches!(g.get("hooks"), Some(J::Arr(h)) if h.is_empty()));
    removed
}

fn strip_flat(arr: &mut Vec<J>) -> usize {
    let n = arr.len();
    arr.retain(|h| !entry_cmd(h).is_some_and(is_ours));
    n - arr.len()
}

/// The events the guard hooks per agent.
fn events(agent: Agent) -> &'static [&'static str] {
    match agent {
        Agent::Claude | Agent::Codex => &["PreToolUse"],
        Agent::Cursor => &["beforeShellExecution", "beforeMCPExecution"],
    }
}

/// Whether `j` already holds exactly the wanted entries.
fn already(agent: Agent, j: &J, want: &J) -> bool {
    let Some(hooks) = j.get("hooks") else {
        return false;
    };
    for ev in events(agent) {
        let Some(J::Arr(arr)) = hooks.get(ev) else {
            return false;
        };
        let ours: Vec<&J> = match agent {
            Agent::Cursor => arr
                .iter()
                .filter(|h| entry_cmd(h).is_some_and(is_ours))
                .collect(),
            _ => arr
                .iter()
                .filter(|g| g.get("matcher").and_then(J::as_str) == Some(MATCHER))
                .flat_map(|g| match g.get("hooks") {
                    Some(J::Arr(h)) => h.iter().collect::<Vec<_>>(),
                    _ => Vec::new(),
                })
                .filter(|h| entry_cmd(h).is_some_and(is_ours))
                .collect(),
        };
        let total: usize = match agent {
            Agent::Cursor => ours.len(),
            _ => arr
                .iter()
                .flat_map(|g| match g.get("hooks") {
                    Some(J::Arr(h)) => h.iter().collect::<Vec<_>>(),
                    _ => Vec::new(),
                })
                .filter(|h| entry_cmd(h).is_some_and(is_ours))
                .count(),
        };
        if ours.len() != 1 || total != 1 || ours[0] != want {
            return false;
        }
    }
    true
}

pub fn plan_install(agent: Agent, path: &Path, cmd: &str, fail_open: bool) -> Result<Plan, String> {
    let (before, mut j) = read_json(path)?;
    let want = our_entry(agent, cmd, fail_open);
    if already(agent, &j, &want) {
        return Ok(Plan {
            path: path.to_path_buf(),
            after: before.clone().unwrap_or_default(),
            before,
            changed: false,
        });
    }
    if agent == Agent::Cursor && j.get("version").is_none() {
        if let J::Obj(m) = &mut j {
            m.insert(0, ("version".into(), J::Num(1u64.into())));
        }
    }
    let hooks = j.entry("hooks", J::Obj(Vec::new()))?;
    if !matches!(hooks, J::Obj(_)) {
        return Err(format!(
            "{}: \"hooks\" is not an object; leaving it alone",
            path.display()
        ));
    }
    for ev in events(agent) {
        let arr = hooks.entry(ev, J::Arr(Vec::new()))?;
        let J::Arr(a) = arr else {
            return Err(format!(
                "{}: hooks.{ev} is not an array; leaving it alone",
                path.display()
            ));
        };
        match agent {
            Agent::Cursor => {
                strip_flat(a);
                a.push(want.clone());
            }
            _ => {
                strip_grouped(a);
                a.push(obj(vec![
                    ("matcher", st(MATCHER)),
                    ("hooks", J::Arr(vec![want.clone()])),
                ]));
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

pub fn plan_uninstall(agent: Agent, path: &Path) -> Result<Plan, String> {
    let (before, mut j) = read_json(path)?;
    let Some(text) = before.clone() else {
        return Ok(Plan {
            path: path.to_path_buf(),
            before: None,
            after: String::new(),
            changed: false,
        });
    };
    let mut removed = 0;
    if let Some(hooks) = j.get_mut("hooks") {
        for ev in events(agent) {
            if let Some(J::Arr(a)) = hooks.get_mut(ev) {
                removed += match agent {
                    Agent::Cursor => strip_flat(a),
                    _ => strip_grouped(a),
                };
            }
            if hooks.get(ev).is_some_and(J::is_empty_container) {
                hooks.remove(ev);
            }
        }
    }
    if removed == 0 {
        return Ok(Plan {
            path: path.to_path_buf(),
            after: text.clone(),
            before: Some(text),
            changed: false,
        });
    }
    if j.get("hooks").is_some_and(J::is_empty_container) {
        j.remove("hooks");
    }
    let after = to_text(&j);
    Ok(Plan {
        path: path.to_path_buf(),
        changed: true,
        before: Some(text),
        after,
    })
}

/// Writes a plan: backup first, then an atomic replace. Returns the backup.
pub fn apply(plan: &Plan) -> Result<Option<PathBuf>, String> {
    if !plan.changed {
        return Ok(None);
    }
    let dir = plan.path.parent().ok_or("no parent directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut backup = None;
    if plan.before.is_some() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut b = plan.path.clone().into_os_string();
        b.push(format!(".vericto-backup-{now}"));
        let b = PathBuf::from(b);
        std::fs::copy(&plan.path, &b)
            .map_err(|e| format!("cannot back up {}: {e}", plan.path.display()))?;
        backup = Some(b);
    }
    let mut tmp = plan.path.clone().into_os_string();
    tmp.push(".vericto-tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, &plan.after)
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &plan.path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot replace {}: {e}", plan.path.display())
    })?;
    Ok(backup)
}

/// What `status` reports for one file.
#[derive(Debug, Clone)]
pub struct Status {
    pub path: PathBuf,
    pub exists: bool,
    /// The guard's command(s) in the file.
    pub commands: Vec<String>,
    pub error: Option<String>,
}

pub fn status(agent: Agent, path: &Path) -> Status {
    let mut s = Status {
        path: path.to_path_buf(),
        exists: path.exists(),
        commands: Vec::new(),
        error: None,
    };
    match read_json(path) {
        Ok((_, j)) => {
            if let Some(hooks) = j.get("hooks") {
                for ev in events(agent) {
                    if let Some(J::Arr(a)) = hooks.get(ev) {
                        for x in a {
                            let mut push = |h: &J| {
                                if let Some(c) = entry_cmd(h).filter(|c| is_ours(c)) {
                                    if !s.commands.iter().any(|y| y == c) {
                                        s.commands.push(c.to_string());
                                    }
                                }
                            };
                            match (agent, x.get("hooks")) {
                                (Agent::Cursor, _) => push(x),
                                (_, Some(J::Arr(hs))) => hs.iter().for_each(&mut push),
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        Err(e) => s.error = Some(e),
    }
    s
}

/// The program a hook command runs (its first word).
pub fn command_program(cmd: &str) -> Option<String> {
    super::shell::parse(cmd, &|_| None)
        .cmds
        .into_iter()
        .next()
        .and_then(|c| c.argv.into_iter().next())
}

/// A unified-style line diff (`-` / `+`, three lines of context).
pub fn diff(before: &str, after: &str) -> String {
    let a: Vec<&str> = before.lines().collect();
    let b: Vec<&str> = after.lines().collect();
    if a.len() * b.len() > 4_000_000 {
        return after.lines().map(|l| format!("+{l}\n")).collect();
    }
    // LCS table.
    let (n, m) = (a.len(), b.len());
    let mut t = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            t[i][j] = if a[i] == b[j] {
                t[i + 1][j + 1] + 1
            } else {
                t[i + 1][j].max(t[i][j + 1])
            };
        }
    }
    let mut ops: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if i < n && (j == m || t[i + 1][j] >= t[i][j + 1]) {
            ops.push(('-', a[i]));
            i += 1;
        } else {
            ops.push(('+', b[j]));
            j += 1;
        }
    }
    let keep: Vec<bool> = (0..ops.len())
        .map(|k| {
            let lo = k.saturating_sub(3);
            let hi = (k + 3).min(ops.len() - 1);
            (lo..=hi).any(|x| ops[x].0 != ' ')
        })
        .collect();
    let mut out = String::new();
    let mut gap = false;
    for (k, (op, line)) in ops.iter().enumerate() {
        if keep[k] {
            if gap {
                out.push_str("…\n");
                gap = false;
            }
            out.push(*op);
            out.push_str(line);
            out.push('\n');
        } else {
            gap = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMD: &str = "/usr/local/bin/vericto guard hook --agent claude";

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    #[test]
    fn claude_install_keeps_other_settings_and_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".claude/settings.json");
        let original = r#"{
  "permissions": {"allow": ["Bash(npm test)"]},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}
    ],
    "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]
  },
  "model": "x"
}"#;
        write(&p, original);
        let plan = plan_install(Agent::Claude, &p, CMD, false).unwrap();
        assert!(plan.changed);
        let backup = apply(&plan).unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), original);
        let after = std::fs::read_to_string(&p).unwrap();
        // Key order kept; other hooks kept.
        let perm = after.find("permissions").unwrap();
        let hooks = after.find("\"hooks\"").unwrap();
        let model = after.find("model").unwrap();
        assert!(perm < hooks && hooks < model, "{after}");
        assert!(after.contains("my-linter") && after.contains("notify") && after.contains(CMD));
        // Second run: nothing to do.
        let again = plan_install(Agent::Claude, &p, CMD, false).unwrap();
        assert!(!again.changed);
        // A new binary path replaces the old entry instead of adding one.
        let moved = plan_install(
            Agent::Claude,
            &p,
            "/opt/vericto guard hook --agent claude",
            false,
        )
        .unwrap();
        assert!(moved.changed);
        apply(&moved).unwrap();
        let st = status(Agent::Claude, &p);
        assert_eq!(st.commands, vec!["/opt/vericto guard hook --agent claude"]);
        // Uninstall restores the original content (modulo formatting).
        let un = plan_uninstall(Agent::Claude, &p).unwrap();
        apply(&un).unwrap();
        let back: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let orig: serde_json::Value = serde_json::from_str(original).unwrap();
        assert_eq!(back, orig);
        assert!(!plan_uninstall(Agent::Claude, &p).unwrap().changed);
    }

    #[test]
    fn cursor_install_creates_versioned_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".cursor/hooks.json");
        let cmd = "vericto guard hook --agent cursor";
        let plan = plan_install(Agent::Cursor, &p, cmd, false).unwrap();
        assert!(plan.before.is_none() && plan.changed);
        assert!(apply(&plan).unwrap().is_none());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["hooks"]["beforeShellExecution"][0]["command"], cmd);
        assert_eq!(v["hooks"]["beforeShellExecution"][0]["failClosed"], true);
        assert_eq!(v["hooks"]["beforeMCPExecution"][0]["command"], cmd);
        assert!(!plan_install(Agent::Cursor, &p, cmd, false).unwrap().changed);
        let open = plan_install(Agent::Cursor, &p, cmd, true).unwrap();
        assert!(open.changed && !open.after.contains("failClosed"));
        let un = plan_uninstall(Agent::Cursor, &p).unwrap();
        apply(&un).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"version": 1}));
    }

    #[test]
    fn codex_install_uses_matcher_groups() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".codex/hooks.json");
        write(&p, "{\"description\": \"mine\", \"hooks\": {\"PreToolUse\": [{\"matcher\": \"^apply_patch$\", \"hooks\": [{\"type\": \"command\", \"command\": \"check-patch\"}]}]}}");
        let plan =
            plan_install(Agent::Codex, &p, "vericto guard hook --agent codex", false).unwrap();
        apply(&plan).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["description"], "mine");
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "check-patch"
        );
        assert_eq!(v["hooks"]["PreToolUse"][1]["matcher"], MATCHER);
        assert_eq!(
            v["hooks"]["PreToolUse"][1]["hooks"][0]["timeout"],
            TIMEOUT_SECS
        );
    }

    #[test]
    fn refuses_invalid_json() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("settings.json");
        write(&p, "{ \"hooks\": // comment\n }");
        assert!(plan_install(Agent::Claude, &p, CMD, false).is_err());
        write(&p, "[1]");
        assert!(plan_install(Agent::Claude, &p, CMD, false).is_err());
        write(&p, "{\"hooks\": []}");
        assert!(plan_install(Agent::Claude, &p, CMD, false).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"hooks\": []}");
    }

    #[test]
    fn paths_follow_agent_env() {
        let root = Path::new("/r");
        let home = Path::new("/h");
        let none = |_: &str| None;
        assert_eq!(
            config_path(Agent::Claude, Scope::User, root, home, &none),
            Path::new("/h/.claude/settings.json")
        );
        assert_eq!(
            config_path(Agent::Cursor, Scope::Project, root, home, &none),
            Path::new("/r/.cursor/hooks.json")
        );
        let env = |k: &str| (k == "CODEX_HOME").then(|| "/c".to_string());
        assert_eq!(
            config_path(Agent::Codex, Scope::User, root, home, &env),
            Path::new("/c/hooks.json")
        );
    }

    #[test]
    fn diffs() {
        let d = diff("a\nb\nc\n", "a\nB\nc\n");
        assert_eq!(d, " a\n-b\n+B\n c\n");
        assert_eq!(diff("", "x\n"), "+x\n");
    }

    #[test]
    fn quoting() {
        assert_eq!(
            hook_command("/usr/bin/vericto", Agent::Codex),
            "/usr/bin/vericto guard hook --agent codex"
        );
        assert_eq!(
            hook_command("/Applications/My Tools/vericto", Agent::Claude),
            "\"/Applications/My Tools/vericto\" guard hook --agent claude"
        );
        assert_eq!(
            command_program("\"/a b/vericto\" guard hook --agent claude").as_deref(),
            Some("/a b/vericto")
        );
    }
}
