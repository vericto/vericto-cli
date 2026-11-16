// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end tests of `vericto guard`: real hook JSON (fixtures from the
//! agents' docs) piped into the built binary, install / uninstall on a
//! temporary HOME, the decision log, and the hook's wall-clock time.

use assert_cmd::Command;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/guard")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

struct Env {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let e = Env {
            home: tempfile::tempdir().unwrap(),
            project: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir(e.project.path().join(".git")).unwrap();
        e
    }
    fn log(&self) -> PathBuf {
        self.home.path().join("guard.jsonl")
    }
    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("vericto").unwrap();
        c.current_dir(self.project.path())
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("VERICTO_GUARD_LOG", self.log())
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CODEX_HOME")
            .env_remove("CLAUDE_PROJECT_DIR")
            .env_remove("CURSOR_PROJECT_DIR");
        for v in [
            "DATABASE_URL",
            "PGHOST",
            "RAILS_ENV",
            "NODE_ENV",
            "MIX_ENV",
            "APP_ENV",
            "DIRECT_URL",
        ] {
            c.env_remove(v);
        }
        c
    }
    /// Runs the hook with `input`; returns (exit code, stdout, stderr).
    fn hook(&self, agent: &str, mut input: Value) -> (i32, String, String) {
        if input.get("cwd").is_some() {
            input["cwd"] = json!(self.project.path());
        }
        if input.get("workspace_roots").is_some() {
            input["workspace_roots"] = json!([self.project.path()]);
        }
        let out = self
            .cmd()
            .args(["guard", "hook", "--agent", agent])
            .write_stdin(input.to_string())
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

fn bash(cmd: &str) -> Value {
    let mut v = fixture("claude_pretooluse_bash.json");
    v["tool_input"]["command"] = json!(cmd);
    v
}

#[test]
fn claude_hook_end_to_end() {
    let e = Env::new();
    let (code, out, err) = e.hook("claude", bash("npm test"));
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    let (code, out, err) = e.hook("claude", bash("npx prisma migrate reset --force"));
    assert_eq!(code, 2, "{out}{err}");
    let j: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(j["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(err.contains("VG-101"));
    let (code, out, _) = e.hook("claude", bash("rails db:rollback"));
    assert_eq!(code, 0);
    assert_eq!(
        serde_json::from_str::<Value>(out.trim()).unwrap()["hookSpecificOutput"]
            ["permissionDecision"],
        "ask"
    );
    // The log has the deny, redacted.
    let (code, _, _) = e.hook("claude", bash("PGPASSWORD=hunter2 psql -h db.prod.acme.io -c \"DELETE FROM users WHERE email = 'x@y.z'\""));
    assert_eq!(code, 0, "a DELETE with WHERE is allowed");
    let (code, _, _) = e.hook("claude", bash("PGPASSWORD=hunter2 psql postgres://admin:s3cret@db.prod.acme.io/app -c 'TRUNCATE users'"));
    assert_eq!(code, 2);
    let log = std::fs::read_to_string(e.log()).unwrap();
    assert!(
        log.contains("VG-101") && log.contains("db.prod.acme.io"),
        "{log}"
    );
    assert!(!log.contains("hunter2") && !log.contains("s3cret"), "{log}");
    for line in log.lines() {
        let _: Value = serde_json::from_str(line).unwrap();
    }
    // `guard log` reads it back.
    let out = e.cmd().args(["guard", "log", "-n", "2"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("deny"), "{text}");
}

#[cfg(feature = "offline")]
#[test]
fn claude_mcp_end_to_end() {
    let e = Env::new();
    let (code, out, _) = e.hook("claude", fixture("claude_pretooluse_mcp.json"));
    assert_eq!(code, 2);
    assert!(out.contains("VERICTO-001"), "{out}");
}

#[test]
fn cursor_hook_end_to_end() {
    let e = Env::new();
    let (code, out, _) = e.hook("cursor", fixture("cursor_before_shell.json"));
    assert_eq!(code, 0);
    assert_eq!(
        serde_json::from_str::<Value>(out.trim()).unwrap(),
        json!({"permission": "allow"})
    );
    let mut v = fixture("cursor_before_shell.json");
    v["command"] = json!("supabase db reset --linked");
    let (code, out, _) = e.hook("cursor", v);
    assert_eq!(code, 0);
    let j: Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(j["permission"], "deny");
    assert!(j["agent_message"].as_str().unwrap().contains("VG-191"));
    #[cfg(feature = "offline")]
    {
        let (_, out, _) = e.hook("cursor", fixture("cursor_before_mcp.json"));
        assert_eq!(
            serde_json::from_str::<Value>(out.trim()).unwrap()["permission"],
            "deny"
        );
    }
}

#[test]
fn codex_hook_end_to_end() {
    let e = Env::new();
    let (code, out, err) = e.hook("codex", fixture("codex_pretooluse_bash.json"));
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    let mut v = fixture("codex_pretooluse_bash.json");
    v["tool_input"]["command"] = json!("php artisan migrate:fresh --force");
    let (code, out, err) = e.hook("codex", v);
    assert_eq!(code, 2);
    assert!(out.is_empty());
    assert!(err.contains("VG-126"), "{err}");
}

#[test]
fn hook_survives_garbage_input() {
    let e = Env::new();
    for agent in ["claude", "cursor", "codex"] {
        let out = e
            .cmd()
            .args(["guard", "hook", "--agent", agent])
            .write_stdin("not json")
            .output()
            .unwrap();
        let code = out.status.code().unwrap();
        assert_eq!(code, 0, "{agent}");
        let out = e
            .cmd()
            .args(["guard", "hook", "--agent", agent])
            .write_stdin("{\"tool_name\": \"Bash\", \"tool_input\": {\"command\": \"DROP TABLE x\"")
            .output()
            .unwrap();
        let code = out.status.code().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            code == 2 || stdout.contains("\"deny\""),
            "{agent}: {code} {stdout}"
        );
    }
}

#[test]
fn project_policy_is_read_from_cwd() {
    let e = Env::new();
    std::fs::write(
        e.project.path().join(".vericto.toml"),
        "[[guard.allow]]\nrule = \"VG-101\"\nreason = \"throwaway e2e database\"\n",
    )
    .unwrap();
    let (code, _, _) = e.hook("claude", bash("npx prisma migrate reset --force"));
    assert_eq!(code, 0);
    // A broken section falls back to the defaults and says so.
    std::fs::write(
        e.project.path().join(".vericto.toml"),
        "[guard]\nmode = \"off\"\n",
    )
    .unwrap();
    let (code, _, err) = e.hook("claude", bash("npx prisma migrate reset --force"));
    assert_eq!(code, 2);
    assert!(err.contains("default policy"), "{err}");
}

#[test]
fn test_subcommand() {
    let e = Env::new();
    let out = e
        .cmd()
        .args([
            "guard",
            "test",
            "npx prisma migrate reset",
            "--agent",
            "cursor",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.starts_with("DENY")
            && text.contains("VG-101")
            && text.contains("\"permission\": \"deny\""),
        "{text}"
    );
    let out = e
        .cmd()
        .args(["guard", "test", "npx prisma migrate dev"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let out = e
        .cmd()
        .args([
            "guard",
            "test",
            "--format",
            "json",
            "--mcp",
            "mongodb/drop-database",
            "{\"database\": \"app\"}",
        ])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verdict"], "deny");
    assert_eq!(v["findings"][0]["code"], "VG-601");
}

fn read(p: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn install_uninstall_on_temp_home() {
    let e = Env::new();
    let claude = e.home.path().join(".claude/settings.json");
    std::fs::create_dir_all(claude.parent().unwrap()).unwrap();
    std::fs::write(&claude, "{\"theme\": \"dark\", \"hooks\": {\"PreToolUse\": [{\"matcher\": \"Edit\", \"hooks\": [{\"type\": \"command\", \"command\": \"fmt\"}]}]}}\n").unwrap();
    // Dry run: prints a diff, writes nothing.
    let out = e
        .cmd()
        .args([
            "guard",
            "install",
            "--agent",
            "claude",
            "--dry-run",
            "--bin",
            "/opt/v/vericto",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("+") && text.contains("guard hook --agent claude"),
        "{text}"
    );
    assert!(!std::fs::read_to_string(&claude)
        .unwrap()
        .contains("guard hook"));
    // Install all three.
    let out = e
        .cmd()
        .args([
            "guard",
            "install",
            "--agent",
            "all",
            "--bin",
            "/opt/v/vericto",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = read(&claude);
    assert_eq!(v["theme"], "dark");
    assert_eq!(v["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "fmt");
    assert_eq!(
        v["hooks"]["PreToolUse"][1]["hooks"][0]["command"],
        "/opt/v/vericto guard hook --agent claude"
    );
    let cursor = read(&e.home.path().join(".cursor/hooks.json"));
    assert_eq!(
        cursor["hooks"]["beforeShellExecution"][0]["failClosed"],
        true
    );
    let codex = read(&e.home.path().join(".codex/hooks.json"));
    assert_eq!(codex["hooks"]["PreToolUse"][0]["matcher"], "Bash|mcp__.*");
    let backups: Vec<_> = std::fs::read_dir(claude.parent().unwrap())
        .unwrap()
        .filter_map(|x| x.ok())
        .filter(|x| x.file_name().to_string_lossy().contains("vericto-backup"))
        .collect();
    assert_eq!(backups.len(), 1);
    // Idempotent.
    let out = e
        .cmd()
        .args([
            "guard",
            "install",
            "--agent",
            "all",
            "--bin",
            "/opt/v/vericto",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.matches("already installed").count(), 3, "{text}");
    // Status sees them (the binary path does not exist here).
    let out = e
        .cmd()
        .args(["guard", "status", "--format", "json"])
        .output()
        .unwrap();
    let st: Value = serde_json::from_slice(&out.stdout).unwrap();
    let installed: Vec<&Value> = st["hooks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["installed"] == true)
        .collect();
    assert_eq!(installed.len(), 3);
    assert!(installed.iter().all(|h| h["binaries_found"] == false));
    // Project scope writes into the repository.
    let out = e
        .cmd()
        .args([
            "guard", "install", "--agent", "codex", "--scope", "project", "--bin", "vericto",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(e.project.path().join(".codex/hooks.json").is_file());
    // Uninstall removes only the guard.
    let out = e
        .cmd()
        .args(["guard", "uninstall", "--agent", "all"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v = read(&claude);
    assert_eq!(
        v,
        json!({"theme": "dark", "hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt"}]}]}})
    );
    assert_eq!(read(&e.home.path().join(".codex/hooks.json")), json!({}));
    let out = e
        .cmd()
        .args(["guard", "uninstall", "--agent", "all"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout)
            .matches("not installed")
            .count(),
        3
    );
}

#[test]
fn install_refuses_invalid_json() {
    let e = Env::new();
    let p = e.home.path().join(".cursor/hooks.json");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, "{ broken").unwrap();
    let out = e
        .cmd()
        .args(["guard", "install", "--agent", "cursor", "--bin", "vericto"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "{ broken");
}

#[test]
fn install_without_agents_found_asks_for_one() {
    let e = Env::new();
    let out = e.cmd().args(["guard", "install"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--agent"));
}

/// The hook's wall-clock time per call, process start included. Printed
/// for the report; the assertion is loose because CI machines vary.
#[test]
fn hook_latency() {
    let e = Env::new();
    let inputs = [
        bash("npm test"),
        bash("git status"),
        bash("psql -c \"SELECT * FROM users WHERE id = 1\""),
        bash("npx prisma migrate reset --force"),
        bash("cd api && pnpm prisma migrate dev --name add_users"),
        fixture("claude_pretooluse_mcp.json"),
    ];
    let mut times = Vec::new();
    for _ in 0..5 {
        for i in &inputs {
            let t = std::time::Instant::now();
            let _ = e.hook("claude", i.clone());
            times.push(t.elapsed());
        }
    }
    times.sort();
    let p95 = times[times.len() * 95 / 100];
    eprintln!(
        "guard hook wall clock: p50 {:?}, p95 {:?}",
        times[times.len() / 2],
        p95
    );
    assert!(p95 < std::time::Duration::from_secs(2), "p95 {p95:?}");
}
