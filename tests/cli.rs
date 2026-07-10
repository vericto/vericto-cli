//! End-to-end integration tests: spawn the built `vetro` binary against an
//! in-process mock backend. These exercise the `run_*` command paths in main.rs
//! (arg parsing, file/stdin handling, exit codes, sanitize/baseline/output)
//! that unit tests can't reach.

use assert_cmd::Command;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A check-key response body with the given per-line statuses.
fn check_body(statuses: &[&str]) -> serde_json::Value {
    let blocked = statuses.iter().filter(|s| **s == "BLOCKED").count() as u32;
    serde_json::json!({
        "summary": {
            "total": statuses.len(),
            "blocked": blocked,
            "allowed": statuses.iter().filter(|s| **s == "ALLOWED").count(),
            "flagged": statuses.iter().filter(|s| **s == "FLAGGED").count(),
            "monitored": 0, "parse_errors": 0, "ruleset_version": "v1"
        },
        "queries": statuses.iter().enumerate().map(|(i, s)| serde_json::json!({
            "line": i + 1,
            "sql_preview": "x",
            "status": s,
            "rule_code": if *s == "BLOCKED" { Some("VETRO-001") } else { None },
            "ast_node_path": "DeleteStmt > WhereClause = NULL",
            "severity": if *s == "BLOCKED" { Some("critical") } else { None },
        })).collect::<Vec<_>>(),
        "exit_code": if blocked > 0 { 1 } else { 0 },
        "ci_checks_remaining": 999,
        "telemetry_query_mode": "raw"
    })
}

fn config_body(mode: &str) -> serde_json::Value {
    serde_json::json!({
        "telemetry_query_mode": mode,
        "plan": "free",
        "ci_checks_remaining": 999,
        "ruleset_version": "v1"
    })
}

/// Mounts the config + check-key endpoints on a fresh mock server.
async fn mock_backend(check: serde_json::Value, mode: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(config_body(mode)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(check))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "api_version": "1.0.0", "min_cli_version": "0.1.0"
        })))
        .mount(&server)
        .await;
    server
}

fn vetro() -> Command {
    let mut c = Command::cargo_bin("vetro").unwrap();
    // Keep the ambient environment from leaking into the run (e.g. SSL_CERT_FILE
    // set by other tooling), but preserve coverage instrumentation so
    // cargo-llvm-cov attributes the spawned binary's execution.
    let profile = std::env::var_os("LLVM_PROFILE_FILE");
    let cov_dir = std::env::var_os("CARGO_LLVM_COV_TARGET_DIR");
    c.env_clear();
    if let Some(p) = profile {
        c.env("LLVM_PROFILE_FILE", p);
    }
    if let Some(d) = cov_dir {
        c.env("CARGO_LLVM_COV_TARGET_DIR", d);
    }
    c
}

#[tokio::test]
async fn check_blocked_exits_1() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    vetro()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(1);
}

#[tokio::test]
async fn check_allowed_exits_0() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("ok.sql");
    std::fs::write(&sql, "SELECT 1 LIMIT 1;").unwrap();

    vetro()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn check_monitor_forces_exit_0_on_blocked() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    vetro()
        .args(["check", sql.to_str().unwrap(), "--monitor", "--quiet"])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn check_json_output_to_stdout() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    let out = vetro()
        .args(["check", sql.to_str().unwrap(), "--format", "json"])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["summary"]["blocked"], 1);
}

#[tokio::test]
async fn check_from_stdin() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    vetro()
        .args(["check", "-", "--quiet"])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .write_stdin("DELETE FROM users;")
        .assert()
        .code(1);
}

#[tokio::test]
async fn missing_api_key_exits_3() {
    // No backend needed — fails before any request.
    vetro()
        .args(["check", "-", "--quiet"])
        .env("VETRO_API_URL", "http://127.0.0.1:1")
        .write_stdin("SELECT 1;")
        .assert()
        .code(3);
}

#[tokio::test]
async fn baseline_then_check_suppresses() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let bl = dir.path().join("baseline.json");

    // Record the baseline.
    vetro()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            bl.to_str().unwrap(),
        ])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(0);
    assert!(bl.exists());

    // Now the blocked finding is baselined → exit 0.
    vetro()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--baseline",
            bl.to_str().unwrap(),
            "--quiet",
        ])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn sanitized_mode_normalizes_before_send() {
    // Backend reports sanitized; the request body the CLI POSTs must carry
    // placeholders, not the literal. We assert via a body matcher.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(config_body("sanitized")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .and(wiremock::matchers::body_string_contains("$1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(check_body(&["ALLOWED"])))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("s.sql");
    std::fs::write(
        &sql,
        "SELECT * FROM t WHERE email = 'secret@x.com' LIMIT 1;",
    )
    .unwrap();

    // If the body didn't contain "$1" the mock wouldn't match → non-200 → exit 4.
    vetro()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn doctor_reports_ok_without_spending_check() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    vetro()
        .arg("doctor")
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn allow_degraded_exits_0_when_unreachable() {
    // Point at a dead port; --allow-degraded with a reason turns exit 4 into 0.
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    vetro()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--timeout",
            "1",
            "--allow-degraded",
            "vetro outage incident-1",
            "--quiet",
        ])
        .env("VETRO_API_KEY", "vtro_k")
        .env("VETRO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(0);
}

#[test]
fn login_logout_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    // Isolate the config dir via XDG_CONFIG_HOME.
    vetro()
        .args([
            "login",
            "--api-key",
            "vtro_stored",
            "--api-url",
            "https://x",
        ])
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .code(0);
    let cfg = dir.path().join("vetro/config.toml");
    assert!(cfg.exists());
    assert!(std::fs::read_to_string(&cfg)
        .unwrap()
        .contains("vtro_stored"));

    vetro()
        .arg("logout")
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .code(0);
    assert!(!std::fs::read_to_string(&cfg)
        .unwrap()
        .contains("vtro_stored"));
}

#[test]
fn init_github_scaffolds_workflow() {
    let dir = tempfile::tempdir().unwrap();
    vetro()
        .args(["init", "--target", "github", "--dialect", "postgres"])
        .current_dir(dir.path())
        .assert()
        .code(0);
    let wf = dir.path().join(".github/workflows/vetro.yml");
    assert!(wf.exists());
    let s = std::fs::read_to_string(&wf).unwrap();
    assert!(s.contains("Vetro SQL check"));
}
