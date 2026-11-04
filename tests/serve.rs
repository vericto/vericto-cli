// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto serve --stdio` end to end: spawn the built binary and talk JSON
//! Lines to it, as the SDKs do (docs/serve-protocol.md).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A running server. Dropping it kills and reaps the process, so a failing
/// test never leaves a `serve` behind.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(args: &[&str]) -> Server {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("vericto"));
    cmd.arg("serve")
        .args(args)
        // Nothing from the environment may change a verdict; run with none.
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(p) = std::env::var_os("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", p);
    }
    for var in ["SystemRoot", "windir", "SystemDrive"] {
        if let Some(v) = std::env::var_os(var) {
            cmd.env(var, v);
        }
    }
    let mut child = cmd.spawn().expect("spawn vericto serve");
    let stdin = child.stdin.take();
    let stdout = BufReader::new(child.stdout.take().unwrap());
    Server {
        child,
        stdin,
        stdout,
    }
}

// Without the engine only the usage-error tests run, which never send.
#[cfg_attr(not(feature = "offline"), allow(dead_code))]
impl Server {
    fn send(&mut self, line: &str) {
        let w = self.stdin.as_mut().expect("stdin open");
        w.write_all(line.as_bytes()).unwrap();
        w.write_all(b"\n").unwrap();
        w.flush().unwrap();
    }

    fn recv(&mut self) -> serde_json::Value {
        let mut line = String::new();
        let n = self.stdout.read_line(&mut line).unwrap();
        assert!(n > 0, "server closed stdout");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("not JSON ({e}): {line}"))
    }

    fn call(&mut self, req: serde_json::Value) -> serde_json::Value {
        self.send(&req.to_string());
        self.recv()
    }

    /// Closes stdin and returns the exit code and whatever stdout still held.
    fn finish(mut self) -> (Option<i32>, String) {
        drop(self.stdin.take());
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut self.stdout, &mut rest).unwrap();
        let code = self.child.wait().unwrap().code();
        (code, rest)
    }
}

/// Starts a server and reads its hello line.
#[cfg(feature = "offline")]
fn started() -> (Server, serde_json::Value) {
    let mut s = spawn(&["--stdio"]);
    let hello = s.recv();
    (s, hello)
}

#[cfg(feature = "offline")]
#[test]
fn hello_names_protocol_versions_and_profiles() {
    let (s, hello) = started();
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["protocol"], 1);
    assert_eq!(hello["cli_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(hello["engine_version"], "5.0.0");
    assert_eq!(hello["profiles"], serde_json::json!(["runtime", "ci"]));
    assert_eq!(hello["max_line_bytes"], 1024 * 1024);
    let (code, rest) = s.finish();
    assert_eq!((code, rest.as_str()), (Some(0), ""), "EOF exits 0");
}

/// `runtime` (the default) blocks a DROP TABLE; `ci` caps it at FLAGGED, and
/// its result is byte for byte what `check --offline --format json` prints.
#[cfg(feature = "offline")]
#[test]
fn check_runtime_vs_ci_on_drop_table() {
    let (mut s, _) = started();
    let sql = "DROP TABLE users;";
    for (profile, status, action, exit) in [
        (None, "BLOCKED", "block", 1),
        (Some("runtime"), "BLOCKED", "block", 1),
        (Some("ci"), "FLAGGED", "flag", 0),
    ] {
        let mut req =
            serde_json::json!({"id": "d", "op": "check", "sql": sql, "dialect": "postgres"});
        if let Some(p) = profile {
            req["profile"] = p.into();
        }
        let r = s.call(req);
        assert_eq!(r["id"], "d");
        assert_eq!(r["ok"], true, "{r}");
        let q = &r["result"]["queries"][0];
        assert_eq!(q["status"], status, "{profile:?}: {r}");
        assert_eq!(q["action"], action);
        assert_eq!(q["rule_code"], "VERICTO-010");
        assert_eq!(r["result"]["exit_code"], exit);
        assert_eq!(r["result"]["mode"], "offline");
        assert_eq!(
            r["result"]["summary"]["ruleset_version"],
            "standard@engine-5.0.0"
        );
    }

    // Parity with the CLI's own JSON for the ci profile.
    let r = s.call(serde_json::json!({"id": "p", "op": "check", "sql": sql, "profile": "ci"}));
    let out = Command::new(assert_cmd::cargo::cargo_bin("vericto"))
        .args(["check", "--offline", "--format", "json", "-"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(sql.as_bytes())?;
            c.wait_with_output()
        })
        .unwrap();
    let cli: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["result"], cli);
}

/// Several statements in one request are one input, reported like a file:
/// one result with the strongest finding (the WHERE-less UPDATE blocks even
/// though the DROP is only flagged under `ci`).
#[cfg(feature = "offline")]
#[test]
fn multi_statement_input_reports_the_strongest_finding() {
    let (mut s, _) = started();
    let r = s.call(serde_json::json!({
        "id": "m", "op": "check", "profile": "ci",
        "sql": "DROP TABLE a;\nUPDATE accounts SET balance = 0;\nSELECT 1;",
    }));
    assert_eq!(r["result"]["summary"]["total"], 1);
    assert_eq!(r["result"]["queries"][0]["status"], "BLOCKED");
    assert_eq!(r["result"]["queries"][0]["rule_code"], "VERICTO-030");
    let r = s.call(serde_json::json!({
        "id": "s", "op": "check", "dialect": "mysql",
        "sql": "SELECT id FROM `t` WHERE id = 1 LIMIT 1; SELECT id FROM `u` WHERE id = 2 LIMIT 1;",
    }));
    assert_eq!(r["result"]["queries"][0]["status"], "ALLOWED", "{r}");
}

/// Malformed lines get INVALID_REQUEST with a null id, and the server keeps
/// answering; an unknown dialect is UNSUPPORTED_DIALECT. Stderr never shows
/// the SQL.
#[cfg(feature = "offline")]
#[test]
fn malformed_lines_and_bad_fields_keep_the_server_running() {
    let (mut s, _) = started();
    s.send("{not json");
    let r = s.recv();
    assert_eq!(
        (&r["id"], &r["ok"], &r["error"]["code"]),
        (
            &serde_json::Value::Null,
            &serde_json::json!(false),
            &serde_json::json!("INVALID_REQUEST")
        )
    );
    let r =
        s.call(serde_json::json!({"id": "x", "op": "check", "sql": "SELECT 1", "dialect": "db2"}));
    assert_eq!(r["id"], "x");
    assert_eq!(r["error"]["code"], "UNSUPPORTED_DIALECT");
    let r = s.call(serde_json::json!({"id": "y", "op": "check", "sql": 5}));
    assert_eq!(r["error"]["code"], "INVALID_REQUEST");
    let r = s.call(serde_json::json!({"id": "z", "op": "ping"}));
    assert_eq!(r, serde_json::json!({"id": "z", "ok": true}));
    let secret = "SELECT secret_marker_4711 FROM t";
    s.call(serde_json::json!({"id": "q", "op": "check", "sql": secret}));
    let mut stderr = s.child.stderr.take().unwrap();
    let (code, _) = s.finish();
    assert_eq!(code, Some(0));
    let mut err = String::new();
    std::io::Read::read_to_string(&mut stderr, &mut err).unwrap();
    assert!(!err.contains("secret_marker_4711"), "{err}");
}

/// A line over --max-line-bytes is TOO_LARGE, and the next line is read
/// normally.
#[cfg(feature = "offline")]
#[test]
fn too_large_line_is_rejected_and_the_server_continues() {
    let mut s = spawn(&["--stdio", "--max-line-bytes", "2048"]);
    assert_eq!(s.recv()["max_line_bytes"], 2048);
    let big = format!(
        r#"{{"id":"big","op":"check","sql":"SELECT 1 -- {}"}}"#,
        "x".repeat(10_000)
    );
    s.send(&big);
    let r = s.recv();
    assert_eq!(r["ok"], false);
    assert_eq!(r["id"], serde_json::Value::Null);
    assert_eq!(r["error"]["code"], "TOO_LARGE");
    let r = s.call(serde_json::json!({"id": "after", "op": "ping"}));
    assert_eq!(r, serde_json::json!({"id": "after", "ok": true}));
    // Default limit: 1 MiB.
    let mut s = spawn(&["--stdio"]);
    s.recv();
    s.send(&format!(
        r#"{{"id":"b","op":"check","sql":"{}"}}"#,
        "x".repeat(1024 * 1024 + 1)
    ));
    assert_eq!(s.recv()["error"]["code"], "TOO_LARGE");
    // Outside the accepted range: a usage error before any output.
    let s = spawn(&["--stdio", "--max-line-bytes", "10"]);
    let (code, out) = s.finish();
    assert_eq!((code, out.as_str()), (Some(2), ""));
}

#[cfg(feature = "offline")]
#[test]
fn ping_and_shutdown() {
    let (mut s, _) = started();
    assert_eq!(
        s.call(serde_json::json!({"id": "1", "op": "ping"})),
        serde_json::json!({"id": "1", "ok": true})
    );
    // shutdown with an id is answered, then the server exits 0 without
    // reading further lines.
    s.send(r#"{"id":"bye","op":"shutdown"}"#);
    s.send(r#"{"id":"2","op":"ping"}"#);
    assert_eq!(s.recv(), serde_json::json!({"id": "bye", "ok": true}));
    let (code, rest) = s.finish();
    assert_eq!((code, rest.as_str()), (Some(0), ""));
    // Without an id: no answer, exit 0.
    let (mut s, _) = started();
    s.send(r#"{"op":"shutdown"}"#);
    let (code, rest) = s.finish();
    assert_eq!((code, rest.as_str()), (Some(0), ""));
}

/// 1,000 requests written without waiting are all answered, once each, in
/// request order. The writer runs on its own thread, as a client must, so
/// neither pipe fills up while the other side waits.
#[cfg(feature = "offline")]
#[test]
fn a_thousand_pipelined_requests_are_all_answered_in_order() {
    let (mut s, _) = started();
    let mut stdin = s.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        for i in 0..1000 {
            let req = match i % 3 {
                0 => {
                    serde_json::json!({"id": i.to_string(), "op": "check", "sql": "DELETE FROM users"})
                }
                1 => {
                    serde_json::json!({"id": i.to_string(), "op": "check", "sql": "DROP TABLE t", "profile": "ci"})
                }
                _ => serde_json::json!({"id": i.to_string(), "op": "ping"}),
            };
            writeln!(stdin, "{req}").unwrap();
        }
        // Dropping stdin is EOF: the server answers everything, then exits.
    });
    for i in 0..1000 {
        let r = s.recv();
        assert_eq!(r["id"], i.to_string());
        assert_eq!(r["ok"], true, "{r}");
        match i % 3 {
            0 => assert_eq!(r["result"]["queries"][0]["status"], "BLOCKED"),
            1 => assert_eq!(r["result"]["queries"][0]["status"], "FLAGGED"),
            _ => assert!(r.get("result").is_none()),
        }
    }
    writer.join().unwrap();
    let (code, rest) = s.finish();
    assert_eq!((code, rest.as_str()), (Some(0), ""));
}

/// `serve` without `--stdio` is a usage error with nothing on stdout.
#[test]
fn serve_needs_stdio() {
    let mut s = spawn(&[]);
    let mut stderr = s.child.stderr.take().unwrap();
    let (code, out) = s.finish();
    assert_eq!((code, out.as_str()), (Some(2), ""));
    let mut err = String::new();
    std::io::Read::read_to_string(&mut stderr, &mut err).unwrap();
    assert!(err.contains("--stdio"), "{err}");
}

/// Without the engine (a `--no-default-features` build) `serve --stdio`
/// prints a clear error and exits 2, writing nothing to stdout.
#[cfg(not(feature = "offline"))]
#[test]
fn serve_without_the_engine_exits_2() {
    let mut s = spawn(&["--stdio"]);
    let mut stderr = s.child.stderr.take().unwrap();
    let (code, out) = s.finish();
    assert_eq!((code, out.as_str()), (Some(2), ""));
    let mut err = String::new();
    std::io::Read::read_to_string(&mut stderr, &mut err).unwrap();
    assert!(err.contains("without the `offline` feature"), "{err}");
}
