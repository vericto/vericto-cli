// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end tests of `vericto guard install --hard`, `status` and
//! `uninstall --hard` against a stand-in `vericto-proxy`
//! (`tests/fixtures/guard/fake-vericto-proxy.sh`, the `mcp credential`
//! JSON and exit-code contract), on a temporary HOME with a clean
//! environment. Nothing touches the real keychain or the user's agent
//! configuration. Unix only (the stand-in is a shell script).
//!
//! With `VERICTO_TEST_REAL_PROXY=/path/to/vericto-proxy` (a debug build of
//! vericto-proxy 5.2.0, which reads `VERICTO_MCP_TEST_KEYCHAIN_FILE` instead
//! of the OS keychain) the last test runs the same flow against it.

#![cfg(unix)]

use assert_cmd::Command;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const PW: &str = "Hunter2-s3cret";

struct Env {
    home: tempfile::TempDir,
    project: tempfile::TempDir,
    stub: tempfile::TempDir,
}

impl Env {
    fn new() -> Env {
        let e = Env {
            home: tempfile::tempdir().unwrap(),
            project: tempfile::tempdir().unwrap(),
            stub: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir(e.project.path().join(".git")).unwrap();
        for d in [".claude", ".cursor", ".codex"] {
            std::fs::create_dir(e.home.path().join(d)).unwrap();
        }
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/guard/fake-vericto-proxy.sh");
        let dst = e.proxy();
        std::fs::copy(src, &dst).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
        e
    }
    fn proxy(&self) -> PathBuf {
        self.stub.path().join("vericto-proxy")
    }
    fn backups(&self) -> PathBuf {
        self.home.path().join("state/vericto/guard-backups")
    }
    fn h(&self, p: &str) -> PathBuf {
        self.home.path().join(p)
    }
    fn p(&self, p: &str) -> PathBuf {
        self.project.path().join(p)
    }
    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("vericto").unwrap();
        c.current_dir(self.project.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.home.path())
            .env("VERICTO_GUARD_LOG", self.h("guard.jsonl"))
            .env("VERICTO_GUARD_BACKUP_DIR", self.backups())
            .env("STUB_DIR", self.stub.path());
        c
    }
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        self.run_with(args, &[])
    }
    fn run_with(&self, args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
        let mut c = self.cmd();
        for (k, v) in envs {
            c.env(k, v);
        }
        let out = c.args(args).output().unwrap();
        let r = (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        assert!(
            !r.1.contains(PW) && !r.2.contains(PW),
            "a password was printed:\n{}\n{}",
            r.1,
            r.2
        );
        r
    }
    fn install(&self, extra: &[&str]) -> (i32, String, String) {
        let proxy = self.proxy();
        let mut a = vec![
            "guard",
            "install",
            "--hard",
            "--proxy",
            proxy.to_str().unwrap(),
        ];
        a.extend_from_slice(extra);
        if !extra.contains(&"--agent") {
            a.extend_from_slice(&["--agent", "all"]);
        }
        self.run(&a)
    }
    fn stored(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.stub.path().join("store").join(name)).ok()
    }
    fn argv_log(&self) -> String {
        std::fs::read_to_string(self.stub.path().join("argv.log")).unwrap_or_default()
    }
    fn json(&self, p: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }
    fn hook(&self, agent: &str, input: Value, hard: bool) -> i32 {
        let mut a = vec!["guard", "hook", "--agent", agent];
        if hard {
            a.push("--hard");
        }
        let out = self
            .cmd()
            .args(&a)
            .write_stdin(input.to_string())
            .output()
            .unwrap();
        out.status.code().unwrap_or(-1)
    }
}

fn write(p: &Path, s: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, s).unwrap();
}

fn url(host: &str) -> String {
    format!("postgresql://app:{PW}@{host}:5432/shop")
}

/// No file under `dir` (but the backups) holds the password.
fn assert_no_plaintext(dir: &Path, skip: &Path) {
    for e in walk(dir) {
        if e.starts_with(skip) {
            continue;
        }
        if let Ok(t) = std::fs::read_to_string(&e) {
            assert!(
                !t.contains(PW),
                "{} still holds the password:\n{t}",
                e.display()
            );
        }
    }
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn install_status_uninstall_round_trip() {
    let e = Env::new();
    let u = url("db.acme.io");
    write(&e.p(".env"), &format!("PORT=3000\nDATABASE_URL=\"{u}\"\n"));
    write(
        &e.p(".env.example"),
        "DATABASE_URL=postgres://user:password@localhost/app\n",
    );
    write(
        &e.p(".mcp.json"),
        &format!(
            r#"{{"mcpServers": {{"postgres": {{"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", "{u}"]}}, "github": {{"command": "gh-mcp"}}}}}}"#
        ),
    );
    write(
        &e.h(".claude/settings.json"),
        r#"{"permissions": {"allow": ["Bash(npm test)"]}, "model": "opus"}"#,
    );
    write(&e.h(".codex/config.toml"), "model = \"o4\"\n");

    // Without a terminal and without --yes, nothing happens.
    let (code, _, err) = e.install(&[]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--yes"), "{err}");

    // Dry run: shows, stores and writes nothing.
    let (code, out, err) = e.install(&["--dry-run"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        out.contains("postgresql://app:***@db.acme.io:5432/shop"),
        "{out}"
    );
    assert!(
        out.contains("DATABASE_URL in .env") && out.contains("MCP server \"postgres\" (args[2])"),
        "{out}"
    );
    assert!(!out.contains(".env.example"), "{out}");
    assert!(e.stored("shop").is_none());
    assert!(!e.h(".claude.json").exists());

    // The real thing.
    let (code, out, err) = e.install(&["--yes", "--remove-plaintext"]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(e.stored("shop").as_deref(), Some(u.as_str()));
    let log = e.argv_log();
    assert!(
        !log.contains(PW)
            && log.contains("mcp credential set shop")
            && log.contains("mcp credential test shop --require-read-only"),
        "{log}"
    );
    assert!(out.contains("the role is read-only"), "{out}");

    // MCP entries for the three agents, at the proxy's absolute path.
    let proxy = e.proxy().to_string_lossy().into_owned();
    let args = json!([
        "mcp",
        "--database-url-keychain",
        "shop",
        "--require-read-only"
    ]);
    let cj = e.json(&e.h(".claude.json"));
    assert_eq!(cj["mcpServers"]["vericto-db"]["command"], proxy);
    assert_eq!(cj["mcpServers"]["vericto-db"]["args"], args);
    let cu = e.json(&e.h(".cursor/mcp.json"));
    assert_eq!(cu["mcpServers"]["vericto-db"]["args"], args);
    let cx: toml::Value =
        toml::from_str(&std::fs::read_to_string(e.h(".codex/config.toml")).unwrap()).unwrap();
    assert_eq!(cx["model"].as_str(), Some("o4"));
    assert_eq!(
        cx["mcp_servers"]["vericto-db"]["command"].as_str(),
        Some(proxy.as_str())
    );

    // Hooks with --hard; Claude's deny rules next to the user's settings.
    let s = e.json(&e.h(".claude/settings.json"));
    assert_eq!(s["model"], "opus");
    assert_eq!(s["permissions"]["allow"], json!(["Bash(npm test)"]));
    let deny: Vec<&str> = s["permissions"]["deny"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        deny.contains(&"Bash(psql:*)")
            && deny.contains(&"Read(**/.env)")
            && deny.contains(&"Bash(security find-generic-password:*)"),
        "{deny:?}"
    );
    assert!(
        deny.iter()
            .any(|d| d.starts_with("Read(~/state/vericto/guard-backups")),
        "{deny:?}"
    );
    let hook = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(hook.ends_with("guard hook --agent claude --hard"), "{hook}");
    let ch = e.json(&e.h(".cursor/hooks.json"));
    assert!(ch["hooks"]["beforeReadFile"][0]["command"]
        .as_str()
        .unwrap()
        .ends_with("--agent cursor --hard"));

    // The plaintext is gone from the project and the agents' files; the
    // copies are in the private backup directory only.
    let env_text = std::fs::read_to_string(e.p(".env")).unwrap();
    assert!(
        env_text.contains("PORT=3000")
            && env_text.contains("# DATABASE_URL: moved to the OS keychain (vericto-proxy/shop)"),
        "{env_text}"
    );
    let mcp = e.json(&e.p(".mcp.json"));
    assert_eq!(
        mcp,
        json!({"mcpServers": {"github": {"command": "gh-mcp"}}})
    );
    assert_no_plaintext(e.project.path(), Path::new("/nonexistent"));
    assert_no_plaintext(e.home.path(), &e.backups());
    let backups = walk(&e.backups());
    assert!(
        backups
            .iter()
            .any(|b| std::fs::read_to_string(b).unwrap().contains(PW)),
        "{backups:?}"
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(e.backups()).unwrap().permissions().mode() & 0o777,
        0o700
    );

    // The hook now denies the bypasses, and the read of .env in Cursor.
    let bash = |c: &str| json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": c}, "cwd": e.project.path()});
    assert_eq!(e.hook("claude", bash("psql -h db.acme.io shop"), true), 2);
    assert_eq!(e.hook("claude", bash("cat .env"), true), 2);
    assert_eq!(e.hook("claude", bash("npm test"), true), 0);
    assert_eq!(e.hook("claude", bash("psql -h db.acme.io shop"), false), 0);
    assert_eq!(
        e.hook(
            "codex",
            bash("security find-generic-password -s vericto-proxy -w"),
            true
        ),
        2
    );
    let out = e
        .cmd()
        .args(["guard", "hook", "--agent", "cursor", "--hard"])
        .write_stdin(json!({"hook_event_name": "beforeReadFile", "file_path": e.p(".env"), "content": format!("X={PW}"), "workspace_roots": [e.project.path()]}).to_string())
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["permission"], "deny");
    assert!(v.get("agent_message").is_none());
    let log = std::fs::read_to_string(e.h("guard.jsonl")).unwrap();
    assert!(!log.contains(PW), "{log}");

    // Status.
    let (code, out, _) = e.run(&["guard", "status", "--format", "json"]);
    assert_eq!(code, 0);
    let st: Value = serde_json::from_str(&out).unwrap();
    let hard = &st["hard"];
    assert_eq!(hard["configured"], true);
    assert_eq!(hard["credentials"][0]["name"], "shop");
    assert_eq!(hard["credentials"][0]["state"], "read_only");
    assert!(hard["exposures"].as_array().unwrap().is_empty(), "{hard}");
    let claude_user = hard["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["agent"] == "claude" && r["scope"] == "user")
        .unwrap();
    assert_eq!(claude_user["hook_hard"], true);
    assert_eq!(
        claude_user["deny_rules"],
        claude_user["deny_rules_expected"]
    );
    let (_, text, _) = e.run(&["guard", "status"]);
    assert!(
        text.contains("credential vericto-proxy/shop: read-only (verified)")
            && text.contains("remaining exposures: none found"),
        "{text}"
    );

    // Again, with the entry that now exists: nothing changes.
    let (code, out, err) = e.install(&["--yes", "--name", "shop"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains("  wrote "), "{out}");

    // Uninstall --hard: entries and rules out, hook back to plain, the
    // keychain entry deleted on request, the plaintext not put back.
    let proxy_s = e.proxy();
    let (code, out, err) = e.run(&[
        "guard",
        "uninstall",
        "--hard",
        "--agent",
        "all",
        "--yes",
        "--delete-credential",
        "--proxy",
        proxy_s.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(e.stored("shop").is_none(), "{out}");
    assert!(e.json(&e.h(".claude.json")).get("mcpServers").is_none());
    let s = e.json(&e.h(".claude/settings.json"));
    assert_eq!(s["permissions"], json!({"allow": ["Bash(npm test)"]}));
    let hook = s["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap();
    assert!(hook.ends_with("guard hook --agent claude"), "{hook}");
    let ch = e.json(&e.h(".cursor/hooks.json"));
    assert!(ch["hooks"].get("beforeReadFile").is_none(), "{ch}");
    let cx: toml::Value =
        toml::from_str(&std::fs::read_to_string(e.h(".codex/config.toml")).unwrap()).unwrap();
    assert!(cx
        .get("mcp_servers")
        .and_then(|m| m.get("vericto-db"))
        .is_none());
    assert!(std::fs::read_to_string(e.p(".env"))
        .unwrap()
        .contains("# DATABASE_URL: moved"));
    assert!(out.contains("Nothing is put back automatically"), "{out}");
    let (_, text, _) = e.run(&["guard", "status"]);
    assert!(text.contains("hard mode: off"), "{text}");
}

#[test]
fn a_role_that_can_write_is_refused_unless_allowed() {
    let e = Env::new();
    write(
        &e.p(".env"),
        &format!("DATABASE_URL={}\n", url("rw.acme.io")),
    );
    let (code, out, err) = e.install(&["--yes", "--remove-plaintext"]);
    assert_eq!(code, 1, "{out}{err}");
    assert!(
        out.contains("can write")
            && out.contains("superuser")
            && out.contains("CREATE ROLE vericto_agent_ro"),
        "{out}"
    );
    assert!(
        e.stored("shop").is_none(),
        "the entry this run created is removed again"
    );
    assert!(!e.h(".claude.json").exists() && !e.h(".claude/settings.json").exists());
    assert!(
        std::fs::read_to_string(e.p(".env")).unwrap().contains(PW),
        "nothing removed"
    );

    let (code, out, err) = e.install(&["--yes", "--allow-write-role"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("NOT hard mode"), "{out}");
    let cj = e.json(&e.h(".claude.json"));
    assert_eq!(
        cj["mcpServers"]["vericto-db"]["args"],
        json!(["mcp", "--database-url-keychain", "shop"])
    );
    assert!(
        std::fs::read_to_string(e.p(".env")).unwrap().contains(PW),
        "no --remove-plaintext, no removal"
    );
    let (_, text, _) = e.run(&["guard", "status"]);
    assert!(
        text.contains("read-only NOT required")
            && text.contains("credential vericto-proxy/shop: can write"),
        "{text}"
    );
    assert!(
        text.contains("DATABASE_URL in .env"),
        "remaining exposure listed: {text}"
    );
}

#[test]
fn an_unverified_mysql_role_shows_the_mysql_sql() {
    let e = Env::new();
    write(
        &e.h(".my.cnf"),
        &format!("[client]\nuser=app\npassword={PW}\nhost=unv.acme.io\ndatabase=shop\n"),
    );
    let (code, out, _) = e.install(&["--yes"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("could not verify") && out.contains("GRANT SELECT, SHOW VIEW ON `shop`.*"),
        "{out}"
    );
    assert!(
        out.contains("mysql://app:***@unv.acme.io/shop") && out.contains("[client] in ~/.my.cnf"),
        "{out}"
    );
}

#[test]
fn an_unreachable_database_stops_unless_allowed() {
    let e = Env::new();
    write(
        &e.p(".env"),
        &format!("DATABASE_URL={}\n", url("down.acme.io")),
    );
    let (code, out, _) = e.install(&["--yes"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("unreachable") && out.contains("--allow-unreachable"),
        "{out}"
    );
    assert!(e.stored("shop").is_none());
    assert!(!e.h(".claude.json").exists());
    let (code, out, _) = e.install(&["--yes", "--allow-unreachable"]);
    assert_eq!(code, 0, "{out}");
    let cj = e.json(&e.h(".claude.json"));
    assert_eq!(
        cj["mcpServers"]["vericto-db"]["args"][3],
        "--require-read-only"
    );
}

#[test]
fn an_old_or_missing_proxy_stops_with_the_install_command() {
    let e = Env::new();
    write(
        &e.p(".env"),
        &format!("DATABASE_URL={}\n", url("db.acme.io")),
    );
    let proxy = e.proxy();
    let (code, _, err) = e.run_with(
        &[
            "guard",
            "install",
            "--hard",
            "--agent",
            "claude",
            "--yes",
            "--proxy",
            proxy.to_str().unwrap(),
        ],
        &[("STUB_VERSION", "5.1.0")],
    );
    assert_eq!(code, 2);
    assert!(
        err.contains("5.2.0") && err.contains("is 5.1.0") && err.contains("vericto-proxy"),
        "{err}"
    );
    let (code, _, err) = e.run(&[
        "guard",
        "install",
        "--hard",
        "--agent",
        "claude",
        "--yes",
        "--proxy",
        "/nonexistent/vericto-proxy",
    ]);
    assert_eq!(code, 2);
    assert!(
        err.contains("not installed") && err.contains("brew install vericto/tap/vericto-proxy"),
        "{err}"
    );
    assert!(e.stored("shop").is_none() && !e.h(".claude.json").exists());
}

#[test]
fn several_credentials_get_their_own_entries() {
    let e = Env::new();
    write(
        &e.p(".env"),
        &format!(
            "DATABASE_URL={}\nANALYTICS_URL=mysql://ro:{PW}@an.acme.io:3306/events\n",
            url("db.acme.io")
        ),
    );
    write(
        &e.h(".pgpass"),
        &format!("db2.acme.io:5432:crm:app:{PW}\n*:*:*:postgres:{PW}\n"),
    );
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(e.h(".pgpass"), std::fs::Permissions::from_mode(0o600)).unwrap();
    let (code, out, err) = e.install(&["--yes", "--remove-plaintext", "--agent", "cursor"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(
        e.stored("shop").is_some() && e.stored("events").is_some() && e.stored("crm").is_some(),
        "{out}"
    );
    assert_eq!(
        e.stored("crm").unwrap(),
        format!("postgresql://app:{PW}@db2.acme.io:5432/crm")
    );
    let cu = e.json(&e.h(".cursor/mcp.json"));
    let keys: Vec<&String> = cu["mcpServers"].as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 3, "{keys:?}");
    assert!(
        keys.iter().all(|k| k.starts_with("vericto-db-")),
        "{keys:?}"
    );
    // The wildcard line stays (it is not one database), the moved one is a comment; the mode is kept.
    let pg = std::fs::read_to_string(e.h(".pgpass")).unwrap();
    assert!(
        pg.contains("*:*:*:postgres:") && !pg.contains("db2.acme.io:5432:crm:app:H"),
        "{pg}"
    );
    assert_eq!(
        std::fs::metadata(e.h(".pgpass"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(out.contains("a wildcard or socket line"), "{out}");
}

/// The same flow against a real vericto-proxy debug build (its test-only
/// file store instead of the keychain). Skipped unless
/// `VERICTO_TEST_REAL_PROXY` names the binary.
#[test]
fn real_proxy_contract() {
    let Some(real) = std::env::var_os("VERICTO_TEST_REAL_PROXY") else {
        eprintln!("skipped: VERICTO_TEST_REAL_PROXY not set");
        return;
    };
    let e = Env::new();
    let store = e.stub.path().join("keychain.json");
    let db = std::env::var("VERICTO_TEST_REAL_DB_URL")
        .unwrap_or_else(|_| format!("postgresql://app:{PW}@127.0.0.1:1/shop?sslmode=disable"));
    write(&e.p(".env"), &format!("DATABASE_URL={db}\n"));
    let real = PathBuf::from(real);
    let mut args = vec![
        "guard",
        "install",
        "--hard",
        "--agent",
        "claude",
        "--yes",
        "--proxy",
        real.to_str().unwrap(),
    ];
    let reachable = std::env::var_os("VERICTO_TEST_REAL_DB_URL").is_some();
    if !reachable {
        args.push("--allow-unreachable");
    }
    let (code, out, err) = e.run_with(
        &args,
        &[("VERICTO_MCP_TEST_KEYCHAIN_FILE", store.to_str().unwrap())],
    );
    let expect = std::env::var("VERICTO_TEST_REAL_EXPECT").unwrap_or_else(|_| "0".into());
    assert_eq!(code.to_string(), expect, "{out}{err}");
    let kc = std::fs::read_to_string(&store).unwrap_or_default();
    if expect == "0" {
        assert!(kc.contains("shop"), "{kc}");
        let cj = e.json(&e.h(".claude.json"));
        assert_eq!(
            cj["mcpServers"]["vericto-db"]["command"],
            real.to_str().unwrap()
        );
        if !reachable {
            assert!(out.contains("unreachable"), "{out}");
        }
    } else {
        assert!(
            !kc.contains("shop"),
            "the entry this run created is removed again: {kc}"
        );
    }
    println!("{out}");
}
