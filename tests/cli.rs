//! End-to-end integration tests: spawn the built `vericto` binary against an
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
            "rule_code": if *s == "BLOCKED" { Some("VERICTO-001") } else { None },
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

// ── vericto login (browser flow) ─────────────────────────────────────────────

/// Runs `vericto login` with no `--api-key`/`--oidc` (the browser flow),
/// simulates the browser's callback by hitting the CLI's own loopback server
/// directly (bypassing the actual dashboard page — that's covered by the
/// backend's own tests), and returns the finished process's exit status.
///
/// This drives the real process end-to-end: spawns it, scrapes the printed
/// `.../cli-auth?state=...&port=...` URL from stdout for `state`/`port`, then
/// makes a plain HTTP GET to `http://127.0.0.1:<port>/callback?...` — exactly
/// what the dashboard's top-level navigation does — with a fixed `code` that
/// the mocked `/cli-login/exchange` endpoint is set up to accept.
async fn run_browser_login(
    api_url: &str,
    code: &str,
    config_dir: &std::path::Path,
) -> std::process::ExitStatus {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let bin = assert_cmd::cargo::cargo_bin("vericto");
    let mut child = Command::new(bin)
        .args([
            "login",
            "--api-url",
            api_url,
            // Any unreachable app_url is fine — open_browser fails silently
            // (a printed note, not fatal) and the URL is printed either way.
            "--app-url",
            "http://127.0.0.1:1",
        ])
        .env_clear()
        .env("HOME", config_dir)
        .env("XDG_CONFIG_HOME", config_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn vericto login");

    // Scrape the printed login URL for `state` and `port`.
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut state = String::new();
    let mut port: u16 = 0;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).unwrap_or(0);
        if n == 0 {
            break; // EOF without finding the URL — caller's assertions will fail loudly.
        }
        if let Some(idx) = line.find("state=") {
            let after = &line[idx + "state=".len()..];
            state = after.split('&').next().unwrap_or("").trim().to_string();
            let port_idx = line.find("port=").expect("URL missing port=");
            let after_port = &line[port_idx + "port=".len()..];
            port = after_port
                .trim()
                .trim_end_matches(char::is_whitespace)
                .parse()
                .expect("port should be numeric");
            break;
        }
    }
    assert!(
        !state.is_empty() && port != 0,
        "did not find the login URL in stdout"
    );

    // Simulate the dashboard's top-level navigation back to the CLI.
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))
        .expect("could not connect to the CLI's loopback server");
    use std::io::Write as _;
    write!(
        stream,
        "GET /callback?state={state}&code={code} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    )
    .unwrap();
    let mut discard = [0u8; 1024];
    let _ = std::io::Read::read(&mut stream, &mut discard);

    child.wait().expect("child process failed to run")
}

#[tokio::test]
async fn browser_login_saves_the_exchanged_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/cli-login/exchange"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "api_key": "vtro_from_browser_e2e"
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let status = run_browser_login(&server.uri(), "the-exchange-code", dir.path()).await;
    assert!(
        status.success(),
        "vericto login should exit 0, got {status}"
    );

    let cfg_path = dir.path().join("vericto/config.toml");
    let cfg = std::fs::read_to_string(&cfg_path).expect("config file should exist");
    assert!(cfg.contains("vtro_from_browser_e2e"));
}

#[tokio::test]
async fn browser_login_rejected_code_does_not_save() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/cli-login/exchange"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "message": "Código de autenticación inválido, expirado o ya utilizado." }
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let status = run_browser_login(&server.uri(), "a-stale-code", dir.path()).await;
    assert_eq!(status.code(), Some(3)); // exit::AUTH — see DESIGN §8

    let cfg_path = dir.path().join("vericto/config.toml");
    assert!(
        !cfg_path.exists(),
        "no config should be written for a rejected exchange"
    );
}

/// A `vericto` invocation with its own empty home, so a test never sees the
/// developer's real `~/.config/vericto/config.toml` (a stored API key, API URL
/// or dialect there changes exit codes). `env_clear()` alone is not enough:
/// with `HOME` unset, `dirs::home_dir()` falls back to the passwd entry, which
/// is the real home. `HOME` and `XDG_CONFIG_HOME` point at a per-test temp dir
/// instead (`config_path()` honors `XDG_CONFIG_HOME` on every Unix, macOS
/// included). A test that needs a config sets its own `XDG_CONFIG_HOME`, which
/// overrides this one. The temp dir lives as long as the command.
struct Vericto {
    cmd: Command,
    _home: tempfile::TempDir,
}

impl std::ops::Deref for Vericto {
    type Target = Command;
    fn deref(&self) -> &Command {
        &self.cmd
    }
}

impl std::ops::DerefMut for Vericto {
    fn deref_mut(&mut self) -> &mut Command {
        &mut self.cmd
    }
}

fn vericto() -> Vericto {
    let mut c = Command::cargo_bin("vericto").unwrap();
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
    let home = tempfile::tempdir().unwrap();
    c.env("HOME", home.path());
    c.env("XDG_CONFIG_HOME", home.path().join(".config"));
    Vericto {
        cmd: c,
        _home: home,
    }
}

#[tokio::test]
async fn check_blocked_exits_1() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    vericto()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(1);
}

#[tokio::test]
async fn check_allowed_exits_0() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("ok.sql");
    std::fs::write(&sql, "SELECT 1 LIMIT 1;").unwrap();

    vericto()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn check_inline_sql_blocked_exits_1() {
    // --sql evaluates a statement passed on the command line — no file needed.
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    vericto()
        .args(["check", "--sql", "DELETE FROM payments", "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(1);
}

#[tokio::test]
async fn check_inline_sql_short_flag_allowed_exits_0() {
    // -e is the short alias for --sql.
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    vericto()
        .args(["check", "-e", "SELECT 1 LIMIT 1", "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn check_inline_sql_rejects_file_combo() {
    // --sql is mutually exclusive with file selectors → usage error (exit 2),
    // before any network call (no mock server needed).
    vericto()
        .args(["check", "--sql", "SELECT 1", "some-file.sql", "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(2);
}

#[tokio::test]
async fn check_monitor_forces_exit_0_on_blocked() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    vericto()
        .args(["check", sql.to_str().unwrap(), "--monitor", "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn check_json_output_to_stdout() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    let out = vericto()
        .args(["check", sql.to_str().unwrap(), "--format", "json"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
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
    vericto()
        .args(["check", "-", "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .write_stdin("DELETE FROM users;")
        .assert()
        .code(1);
}

#[tokio::test]
async fn missing_api_key_exits_3() {
    // No backend needed — fails before any request. In CI: outside it, a run
    // with no credential at all checks offline instead (see the offline tests).
    vericto()
        .args(["check", "-", "--quiet"])
        .env("CI", "true")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
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
    vericto()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
    assert!(bl.exists());

    // Now the blocked finding is baselined → exit 0.
    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--baseline",
            bl.to_str().unwrap(),
            "--quiet",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
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
    vericto()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
}

/// A backend whose `/ci/config` answers `config_status`, with a check-key mock
/// that must be hit exactly `check_calls` times (verified on drop).
async fn backend_with_config_status(config_status: u16, check_calls: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(config_status))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(check_body(&["ALLOWED"])))
        .expect(check_calls)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn unreadable_config_fails_closed_without_sending_sql() {
    // The CLI can't tell whether the workspace requires sanitized mode, so it
    // must not send the raw literal: exit 4 and zero check-key calls.
    let server = backend_with_config_status(404, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("s.sql");
    std::fs::write(&sql, "SELECT * FROM t WHERE email = 'secret@x.com';").unwrap();

    let out = vericto()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("No SQL was sent"), "{stderr}");
}

#[tokio::test]
async fn unreadable_config_with_allow_unsanitized_sends_sql() {
    let server = backend_with_config_status(404, 1).await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("s.sql");
    std::fs::write(&sql, "SELECT 1 LIMIT 1;").unwrap();

    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--quiet",
            "--allow-unsanitized",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn baseline_unreadable_config_fails_closed() {
    let server = backend_with_config_status(404, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("s.sql");
    std::fs::write(&sql, "DELETE FROM t WHERE email = 'secret@x.com';").unwrap();
    let out = dir.path().join("bl.json");

    vericto()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(4);
    assert!(!out.exists());
}

#[tokio::test]
async fn exhausted_quota_exits_3() {
    // README/DESIGN exit codes: 3 = auth/config (plan not entitled), 4 =
    // backend/network. An exhausted monthly allowance is a plan limit → 3.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(config_body("raw")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
            "error": { "code": "QUOTA_EXCEEDED", "message": "Monthly SQL check quota reached (100/100)." }
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "SELECT 1;").unwrap();

    vericto()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(3);
}

#[tokio::test]
async fn doctor_reports_ok_without_spending_check() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    vericto()
        .arg("doctor")
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
}

#[tokio::test]
async fn allow_degraded_exits_0_when_unreachable() {
    // Point at a dead port; --allow-degraded with a reason turns exit 4 into 0.
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--timeout",
            "1",
            "--allow-degraded",
            "vericto outage incident-1",
            "--quiet",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(0);
}

#[tokio::test]
async fn login_logout_roundtrip() {
    // `login --api-key` now verifies against the backend before saving
    // (fail-closed — see login_with_key_unreachable_backend_does_not_save
    // below for the negative case), so the roundtrip needs a mock that
    // answers GET /api/v1/ci/config.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(config_body("raw")))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    // Isolate the config dir via XDG_CONFIG_HOME.
    vericto()
        .args([
            "login",
            "--api-key",
            "vtro_stored",
            "--api-url",
            &server.uri(),
        ])
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .code(0);
    let cfg = dir.path().join("vericto/config.toml");
    assert!(cfg.exists());
    assert!(std::fs::read_to_string(&cfg)
        .unwrap()
        .contains("vtro_stored"));

    vericto()
        .arg("logout")
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .code(0);
    assert!(!std::fs::read_to_string(&cfg)
        .unwrap()
        .contains("vtro_stored"));
}

#[tokio::test]
async fn login_with_key_unreachable_backend_does_not_save() {
    // Fail-closed: if the key can't be verified (backend unreachable here),
    // nothing is written and the command exits non-zero — never a silent
    // "trust it anyway".
    let dir = tempfile::tempdir().unwrap();
    vericto()
        .args([
            "login",
            "--api-key",
            "vtro_unverified",
            "--api-url",
            "http://127.0.0.1:1",
            "--timeout",
            "1",
        ])
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .code(4);
    let cfg = dir.path().join("vericto/config.toml");
    assert!(
        !cfg.exists(),
        "no config file should be written on a failed verification"
    );
}

#[tokio::test]
async fn login_with_key_invalid_key_does_not_save() {
    // A key the backend explicitly rejects (401) must not be saved either —
    // distinct exit code (3, auth) from an unreachable backend (4).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "message": "API key inválida." }
        })))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    vericto()
        .args(["login", "--api-key", "vtro_bad", "--api-url", &server.uri()])
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .code(3);
    let cfg = dir.path().join("vericto/config.toml");
    assert!(
        !cfg.exists(),
        "no config file should be written for a rejected key"
    );
}

/// Mounts an oidc-exchange endpoint that mints a key, plus config + check-key.
async fn mock_backend_with_oidc(check: serde_json::Value) -> MockServer {
    let server = mock_backend(check, "raw").await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/oidc-exchange"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "api_key": "vtro_minted",
            "expires_at": "2026-07-10T00:15:00Z",
            "scope": "ci_dryrun:execute",
            "policy_id": "pol_1"
        })))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn check_via_oidc_env_token_auto_fallback() {
    // No static key, but a pre-minted OIDC token in VERICTO_ID_TOKEN + a workspace:
    // the CLI exchanges it and runs the check, all with no key on disk.
    let server = mock_backend_with_oidc(check_body(&["BLOCKED"])).await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--workspace",
            "ws_1",
            "--quiet",
        ])
        .env("VERICTO_API_URL", server.uri())
        .env("VERICTO_ID_TOKEN", "gitlab.style.jwt")
        .assert()
        .code(1); // blocked finding
}

#[tokio::test]
async fn oidc_forced_without_token_exits_3() {
    // --oidc but no token available anywhere → auth error, before any request.
    vericto()
        .args(["check", "-", "--oidc", "--workspace", "ws_1", "--quiet"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .write_stdin("SELECT 1;")
        .assert()
        .code(3);
}

#[tokio::test]
async fn oidc_without_workspace_exits_3() {
    // A token is present but no workspace was configured → auth error.
    vericto()
        .args(["check", "-", "--oidc", "--quiet"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .env("VERICTO_ID_TOKEN", "some.jwt")
        .write_stdin("SELECT 1;")
        .assert()
        .code(3);
}

#[tokio::test]
async fn doctor_reports_oidc_auth_mode() {
    let server = mock_backend_with_oidc(check_body(&["ALLOWED"])).await;
    let out = vericto()
        .args(["doctor", "--workspace", "ws_1"])
        .env("VERICTO_API_URL", server.uri())
        .env("VERICTO_ID_TOKEN", "gitlab.style.jwt")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("OIDC workload-identity"), "doctor output: {s}");
}

#[test]
fn login_oidc_saves_workspace_no_secret() {
    let dir = tempfile::tempdir().unwrap();
    // Not in CI (no token) → saves config and exits 0 without verifying.
    vericto()
        .args([
            "login",
            "--oidc",
            "--workspace",
            "ws_42",
            "--audience",
            "vericto",
        ])
        .env("XDG_CONFIG_HOME", dir.path())
        .assert()
        .code(0);
    let cfg = dir.path().join("vericto/config.toml");
    let s = std::fs::read_to_string(&cfg).unwrap();
    assert!(s.contains("ws_42"));
    assert!(
        !s.contains("api_key"),
        "OIDC login must not store a key: {s}"
    );
}

// ── Signed run receipts (§7.1) ───────────────────────────────────────────────

/// Builds a check-key response that includes a properly-signed receipt, signed
/// with `signing_key` the same way the backend does (Ed25519 over the SHA-256
/// digest of the canonical, sorted-keys payload). Returns the response JSON.
fn check_body_with_receipt(signing: &ed25519_dalek::SigningKey, key_id: &str) -> serde_json::Value {
    use base64::Engine;
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let summary = serde_json::json!({
        "total": 1, "blocked": 1, "allowed": 0, "flagged": 0,
        "monitored": 0, "parse_errors": 0, "ruleset_version": "v1"
    });
    let queries = serde_json::json!([{
        "line": 1, "sql_preview": "DELETE FROM users", "status": "BLOCKED",
        "rule_code": "VERICTO-001", "severity": "critical"
    }]);
    // The exact payload shape the backend signs (ci-receipt.ts ReceiptPayload).
    let payload = serde_json::json!({
        "kind": "vericto-ci-receipt", "version": 1, "workspace_id": "ws_1",
        "file_name": "m.sql", "dialect": "postgres",
        "summary": summary, "queries": queries, "exit_code": 1,
        "provenance": null, "signed_at": "2026-07-10T00:00:00Z"
    });
    // Canonicalize the same way both sides do: serde_json::Value is sorted-key +
    // compact, matching the backend's canonicalJson.
    let canonical = serde_json::to_string(&payload).unwrap();
    let digest = Sha256::digest(canonical.as_bytes());
    let sig = signing.sign(&digest);
    let sha256_hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    serde_json::json!({
        "summary": summary,
        "queries": queries,
        "exit_code": 1,
        "ci_checks_remaining": 999,
        "telemetry_query_mode": "raw",
        "receipt": {
            "payload": payload,
            "scheme": "ed25519-sha256",
            "signature": base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
            "public_key_id": key_id,
            "sha256": sha256_hex
        }
    })
}

#[tokio::test]
async fn check_receipt_then_verify_roundtrip() {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let pub_pem = signing
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();

    let server = mock_backend(check_body_with_receipt(&signing, "test-key"), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let receipt_path = dir.path().join("receipt.json");
    let pem_path = dir.path().join("key.pem");
    std::fs::write(&pem_path, &pub_pem).unwrap();

    // check --receipt writes the signed receipt (finding is BLOCKED → exit 1).
    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--quiet",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(1);
    assert!(
        receipt_path.exists(),
        "receipt file should have been written"
    );

    // verify-receipt validates it offline against the published public key.
    vericto()
        .args([
            "verify-receipt",
            receipt_path.to_str().unwrap(),
            "--public-key",
            pem_path.to_str().unwrap(),
            "--show",
        ])
        .assert()
        .code(0);
}

#[tokio::test]
async fn verify_receipt_without_public_key_explains_how_to_get_it() {
    // No official key is bundled (pubkeys::BUNDLED_KEYS is empty), so without
    // --public-key verification can't succeed: exit 3, pointing at the endpoint.
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let body = check_body_with_receipt(&signing, "test-key");
    let dir = tempfile::tempdir().unwrap();
    let receipt_path = dir.path().join("receipt.json");
    std::fs::write(&receipt_path, body["receipt"].to_string()).unwrap();

    let out = vericto()
        .args(["verify-receipt", receipt_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--public-key"), "{stderr}");
    assert!(
        stderr.contains("/api/v1/meta/export-signing-key"),
        "{stderr}"
    );
}

#[tokio::test]
async fn verify_receipt_rejects_tampered_file() {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::SigningKey;

    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let pub_pem = signing
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    let body = check_body_with_receipt(&signing, "test-key");

    let dir = tempfile::tempdir().unwrap();
    let receipt_path = dir.path().join("receipt.json");
    // Tamper: flip exit_code in the payload so the digest no longer matches.
    let mut receipt = body["receipt"].clone();
    receipt["payload"]["exit_code"] = serde_json::json!(0);
    std::fs::write(
        &receipt_path,
        serde_json::to_string_pretty(&receipt).unwrap(),
    )
    .unwrap();
    let pem_path = dir.path().join("key.pem");
    std::fs::write(&pem_path, &pub_pem).unwrap();

    vericto()
        .args([
            "verify-receipt",
            receipt_path.to_str().unwrap(),
            "--public-key",
            pem_path.to_str().unwrap(),
        ])
        .assert()
        .code(3); // authenticity failure
}

// ── Minor items: version, --no-color, --stdin-file-list, degraded record ─────

#[test]
fn completions_generate_for_each_shell() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let out = vericto()
            .args(["completions", shell])
            .assert()
            .code(0)
            .get_output()
            .stdout
            .clone();
        let s = String::from_utf8_lossy(&out);
        assert!(!s.is_empty(), "{shell}: empty completion output");
        assert!(s.contains("vericto"), "{shell}: missing binary name");
    }
}

#[test]
fn completions_reject_unknown_shell() {
    vericto()
        .args(["completions", "notashell"])
        .assert()
        .code(2); // clap usage error
}

#[test]
fn version_subcommand_prints_version() {
    let out = vericto()
        .arg("version")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.starts_with("vericto "), "got: {s}");
}

#[tokio::test]
async fn no_color_produces_no_ansi() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    let out = vericto()
        .args(["check", sql.to_str().unwrap(), "--no-color"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    // No ANSI escape (0x1b) anywhere in the output.
    assert!(!out.contains(&0x1b), "output contained ANSI escapes");
}

#[tokio::test]
async fn stdin_file_list_checks_listed_files() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    // Pipe the file path (not SQL) on stdin.
    vericto()
        .args(["check", "--stdin-file-list", "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .write_stdin(format!("{}\n", sql.display()))
        .assert()
        .code(1);
}

#[tokio::test]
async fn stdin_file_list_empty_is_a_pass() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    vericto()
        .args(["check", "--stdin-file-list", "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .write_stdin("\n  \n")
        .assert()
        .code(0);
}

#[tokio::test]
async fn allow_degraded_writes_local_record() {
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();

    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--timeout",
            "1",
            "--allow-degraded",
            "vericto outage ticket-42",
            "--quiet",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .current_dir(dir.path())
        .assert()
        .code(0);

    // The break-glass leaves an auditable local record.
    let record = dir.path().join(".vericto/degraded-runs.jsonl");
    assert!(record.exists(), "degraded record not written");
    let body = std::fs::read_to_string(&record).unwrap();
    assert!(body.contains("vericto-degraded-run"));
    assert!(body.contains("vericto outage ticket-42"));
}

#[test]
fn init_github_scaffolds_workflow() {
    let dir = tempfile::tempdir().unwrap();
    vericto()
        .args(["init", "--target", "github", "--dialect", "postgres"])
        .current_dir(dir.path())
        .assert()
        .code(0);
    let wf = dir.path().join(".github/workflows/vericto.yml");
    assert!(wf.exists());
    let s = std::fs::read_to_string(&wf).unwrap();
    assert!(s.contains("Vericto SQL check"));
}

#[test]
fn init_github_oidc_scaffolds_workload_identity() {
    let dir = tempfile::tempdir().unwrap();
    vericto()
        .args([
            "init",
            "--target",
            "github",
            "--oidc",
            "--workspace",
            "ws_7",
        ])
        .current_dir(dir.path())
        .assert()
        .code(0);
    let wf = dir.path().join(".github/workflows/vericto.yml");
    let s = std::fs::read_to_string(&wf).unwrap();
    assert!(s.contains("id-token: write"));
    assert!(s.contains("--oidc --workspace ws_7"));
    assert!(!s.contains("VERICTO_API_KEY"));
}

#[test]
fn init_oidc_without_workspace_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    vericto()
        .args(["init", "--target", "github", "--oidc"])
        .current_dir(dir.path())
        .assert()
        .code(2);
}

// ── vericto rules list / show ────────────────────────────────────────────────

fn rules_list_body() -> serde_json::Value {
    serde_json::json!({
        "rules": [
            {
                "code": "VERICTO-001",
                "name": "DELETE without WHERE",
                "description": "Blocks DELETE with no WHERE clause",
                "severity": "critical",
                "dialect": "all",
                "rule_type": "standard",
                "is_active": true,
                "resolved_action": "block"
            },
            {
                "code": "CUSTOM-001",
                "name": "No UPDATE on payments",
                "description": null,
                "severity": "high",
                "dialect": "postgres",
                "rule_type": "custom",
                "is_active": false,
                "resolved_action": "flag"
            }
        ],
        "ruleset_version": "v1.0.0-20260711"
    })
}

fn rule_detail_body() -> serde_json::Value {
    serde_json::json!({
        "code": "VERICTO-001",
        "name": "DELETE without WHERE",
        "description": "Blocks DELETE with no WHERE clause",
        "severity": "critical",
        "dialect": "all",
        "rule_type": "standard",
        "is_active": true,
        "resolved_action": "block",
        "ast_condition_yaml": "node_type: DeleteStmt\nwhere_null: true",
        "ruleset_version": "v1.0.0-20260711"
    })
}

#[tokio::test]
async fn rules_list_text_shows_all_codes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rules_list_body()))
        .mount(&server)
        .await;

    let out = vericto()
        .args(["rules", "list"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("VERICTO-001"), "output: {s}");
    assert!(s.contains("CUSTOM-001"), "output: {s}");
    assert!(s.contains("2 rules"), "output: {s}");
}

#[tokio::test]
async fn rules_list_active_only_filters_inactive() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rules_list_body()))
        .mount(&server)
        .await;

    let out = vericto()
        .args(["rules", "list", "--active-only"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("VERICTO-001"), "output: {s}");
    assert!(!s.contains("CUSTOM-001"), "output: {s}"); // inactive, filtered out
}

#[tokio::test]
async fn rules_list_json_matches_backend_shape() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rules_list_body()))
        .mount(&server)
        .await;

    let out = vericto()
        .args(["rules", "list", "--format", "json"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["rules"].as_array().unwrap().len(), 2);
    assert_eq!(v["ruleset_version"], "v1.0.0-20260711");
}

#[tokio::test]
async fn rules_show_text_includes_condition() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/rules/VERICTO-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_detail_body()))
        .mount(&server)
        .await;

    let out = vericto()
        .args(["rules", "show", "VERICTO-001"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("VERICTO-001"), "output: {s}");
    assert!(s.contains("DeleteStmt"), "output: {s}");
}

#[tokio::test]
async fn rules_show_unknown_code_exits_2() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/rules/VERICTO-999"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": { "message": "Regla no encontrada: VERICTO-999" }
        })))
        .mount(&server)
        .await;

    vericto()
        .args(["rules", "show", "VERICTO-999"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(2);
}

#[tokio::test]
async fn rules_list_missing_api_key_exits_3() {
    vericto()
        .args(["rules", "list"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(3);
}

#[tokio::test]
async fn rules_list_auth_error_exits_3() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/rules"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "message": "API key inválida." }
        })))
        .mount(&server)
        .await;

    vericto()
        .args(["rules", "list"])
        .env("VERICTO_API_KEY", "vtro_bad")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(3);
}

// ── vericto keys list ────────────────────────────────────────────────────────

fn keys_list_body() -> serde_json::Value {
    serde_json::json!({
        "data": [
            {
                "key_id": "11111111-1111-1111-1111-111111111111",
                "name": "ci-primary",
                "scopes": ["ci_dryrun:execute"],
                "last_used_at": "2026-08-01T12:00:00Z",
                "expires_at": null,
                "revoked_at": null,
                "created_at": "2026-07-01T00:00:00Z",
                "is_active": true,
                "is_current": true
            },
            {
                "key_id": "22222222-2222-2222-2222-222222222222",
                "name": "old-laptop",
                "scopes": ["ci_dryrun:execute"],
                "last_used_at": null,
                "expires_at": null,
                "revoked_at": "2026-07-20T00:00:00Z",
                "created_at": "2026-06-01T00:00:00Z",
                "is_active": false,
                "is_current": false
            }
        ]
    })
}

#[tokio::test]
async fn keys_list_text_shows_names_and_marks_current() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(keys_list_body()))
        .mount(&server)
        .await;

    let out = vericto()
        .args(["keys", "list"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("ci-primary"), "output: {s}");
    assert!(s.contains("old-laptop"), "output: {s}");
    assert!(s.contains('*'), "should mark the current key: {s}");
    // Never leak a secret/hash — only metadata is returned.
    assert!(!s.contains("vtro_"), "must not echo a key secret: {s}");
    assert!(
        !s.to_lowercase().contains("hash"),
        "must not print a hash: {s}"
    );
}

#[tokio::test]
async fn keys_list_json_matches_backend_shape() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(keys_list_body()))
        .mount(&server)
        .await;

    let out = vericto()
        .args(["keys", "list", "--json"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["data"].as_array().unwrap().len(), 2);
    assert_eq!(v["data"][0]["name"], "ci-primary");
    assert_eq!(v["data"][0]["is_current"], true);
}

#[tokio::test]
async fn keys_list_empty_is_ok() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })))
        .mount(&server)
        .await;

    let out = vericto()
        .args(["keys", "list"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("No API keys"), "output: {s}");
}

#[tokio::test]
async fn keys_list_missing_api_key_exits_3() {
    vericto()
        .args(["keys", "list"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(3);
}

#[tokio::test]
async fn keys_list_auth_error_exits_3() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/keys"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": { "message": "Scope insuficiente." }
        })))
        .mount(&server)
        .await;

    vericto()
        .args(["keys", "list"])
        .env("VERICTO_API_KEY", "vtro_noscope")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(3);
}

// ── vericto docs ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn docs_list_shows_topics_grouped_with_base_url() {
    // No network, no auth — purely local URL building.
    let out = vericto()
        .args(["docs"])
        .env("VERICTO_APP_URL", "https://vericto.com")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    // Slugs are listed, grouped under category headings.
    assert!(s.contains("enforcement"), "output: {s}");
    assert!(s.contains("Getting started"), "output: {s}");
    assert!(s.contains("Security & privacy"), "output: {s}");
    // The base is in the header, and each topic shows its full URL on its own
    // line (piped output has no OSC 8 escapes, so the URL is plain text).
    assert!(s.contains("https://vericto.com/docs"), "output: {s}");
    assert!(
        s.contains("https://vericto.com/docs/enforcement"),
        "each topic should show its full URL: {s}"
    );
    assert!(s.contains("vericto docs <topic>"), "output: {s}");
}

#[tokio::test]
async fn docs_json_lists_every_topic() {
    let out = vericto()
        .args(["docs", "--json"])
        .env("VERICTO_APP_URL", "https://vericto.com")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let topics = v["topics"].as_array().unwrap();
    assert!(
        topics.len() >= 10,
        "expected the full catalogue: {}",
        topics.len()
    );
    assert!(topics.iter().any(|t| t["slug"] == "api-keys"));
    assert!(topics.iter().all(|t| t["url"]
        .as_str()
        .unwrap()
        .starts_with("https://vericto.com/docs/")));
    // Every topic carries a category (used to group the text output).
    assert!(topics
        .iter()
        .all(|t| t["category"].as_str().is_some_and(|c| !c.is_empty())));
}

#[tokio::test]
async fn docs_app_url_override_changes_base() {
    let out = vericto()
        .args([
            "docs",
            "--json",
            "--app-url",
            "https://staging.example.test/",
        ])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    // Trailing slash on the base must not double up in the URL.
    assert!(v["topics"][0]["url"]
        .as_str()
        .unwrap()
        .starts_with("https://staging.example.test/docs/"));
}

#[tokio::test]
async fn docs_unknown_topic_exits_2() {
    vericto().args(["docs", "does-not-exist"]).assert().code(2);
}

// ── vericto feedback ─────────────────────────────────────────────────────────

#[tokio::test]
async fn feedback_message_arg_is_sent_and_confirms() {
    use wiremock::matchers::body_partial_json;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/feedback"))
        // The category flag and message must reach the backend as JSON.
        .and(body_partial_json(
            serde_json::json!({ "category": "idea", "message": "the docs output looks great" }),
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "feedback_id": "fedfedfe-dfed-fedf-edfe-dfedfedfedfe",
            "created_at": "2026-08-02T00:00:00Z"
        })))
        .mount(&server)
        .await;

    let out = vericto()
        .args([
            "feedback",
            "--category",
            "idea",
            "the docs output looks great",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("Thanks"), "output: {s}");
}

#[tokio::test]
async fn feedback_reads_message_from_stdin() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/feedback"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "feedback_id": "fedfedfe-dfed-fedf-edfe-dfedfedfedfe"
        })))
        .mount(&server)
        .await;

    // No message argument → read from stdin (the piped path).
    vericto()
        .args(["feedback"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .write_stdin("piped feedback\n")
        .assert()
        .code(0);
}

#[tokio::test]
async fn feedback_empty_message_exits_2_without_calling_backend() {
    // No server needed — validation happens before any request.
    vericto()
        .args(["feedback", "   "])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(2);
}

#[tokio::test]
async fn feedback_missing_api_key_exits_3() {
    vericto()
        .args(["feedback", "hello"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(3);
}

#[tokio::test]
async fn feedback_auth_error_exits_3() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/feedback"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": { "message": "Scope insuficiente." }
        })))
        .mount(&server)
        .await;

    vericto()
        .args(["feedback", "hello"])
        .env("VERICTO_API_KEY", "vtro_noscope")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(3);
}

// ── vericto baseline prune ───────────────────────────────────────────────────

#[tokio::test]
async fn baseline_prune_removes_fixed_findings() {
    let server_before = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let bl = dir.path().join("baseline.json");

    // Record a baseline while the file is still unsafe.
    vericto()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server_before.uri())
        .assert()
        .code(0);
    let before: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&bl).unwrap()).unwrap();
    assert_eq!(before["entries"].as_array().unwrap().len(), 1);

    // The file is now fixed — a fresh mock server reports it ALLOWED.
    let server_after = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let out = vericto()
        .args([
            "baseline",
            "prune",
            sql.to_str().unwrap(),
            "--file",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server_after.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("Pruned 1 stale entry"), "output: {s}");

    let after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&bl).unwrap()).unwrap();
    assert_eq!(after["entries"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn baseline_prune_dry_run_does_not_modify_file() {
    let server_before = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let bl = dir.path().join("baseline.json");

    vericto()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server_before.uri())
        .assert()
        .code(0);
    let before_text = std::fs::read_to_string(&bl).unwrap();

    let server_after = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let out = vericto()
        .args([
            "baseline",
            "prune",
            sql.to_str().unwrap(),
            "--file",
            bl.to_str().unwrap(),
            "--dry-run",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server_after.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("Would prune 1 of 1"), "output: {s}");

    // --dry-run must not touch the file on disk.
    assert_eq!(std::fs::read_to_string(&bl).unwrap(), before_text);
}

#[tokio::test]
async fn baseline_prune_no_stale_entries_is_a_noop() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let bl = dir.path().join("baseline.json");

    vericto()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);

    // The same finding is still there — nothing to prune.
    let out = vericto()
        .args([
            "baseline",
            "prune",
            sql.to_str().unwrap(),
            "--file",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("up to date"), "output: {s}");
}

#[tokio::test]
async fn baseline_prune_missing_file_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "SELECT 1;").unwrap();

    vericto()
        .args([
            "baseline",
            "prune",
            sql.to_str().unwrap(),
            "--file",
            dir.path().join("nope.json").to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(2);
}

#[tokio::test]
async fn baseline_prune_empty_baseline_is_a_noop_without_network() {
    // An empty baseline short-circuits before any auth/network call — passing a
    // dead backend URL proves it never tries to reach it.
    let dir = tempfile::tempdir().unwrap();
    let bl = dir.path().join("baseline.json");
    std::fs::write(&bl, r#"{"version":1,"entries":[]}"#).unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "SELECT 1;").unwrap();

    let out = vericto()
        .args([
            "baseline",
            "prune",
            sql.to_str().unwrap(),
            "--file",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(s.contains("nothing to prune"), "output: {s}");
}

// ── per-statement results (backend capability `check_files`) ────────────────

/// Mounts a backend that advertises `check_files` and only answers check-key
/// requests that carry whole `files` — so a CLI still sending `queries` fails.
async fn mock_per_statement_backend(check: serde_json::Value) -> MockServer {
    let server = MockServer::start().await;
    let mut cfg = config_body("raw");
    cfg["capabilities"] = serde_json::json!(["check_files"]);
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cfg))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .and(wiremock::matchers::body_string_contains("\"files\""))
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

fn per_statement_body() -> serde_json::Value {
    // Two files; the backend reports each statement with its real line and the
    // (request-relative) file it came from.
    serde_json::json!({
        "summary": { "total": 3, "blocked": 1, "allowed": 2, "flagged": 0, "monitored": 0, "parse_errors": 0, "ruleset_version": "v1" },
        "queries": [
            { "line": 1, "file_index": 1, "sql_preview": "SELECT 1", "status": "ALLOWED" },
            { "line": 2, "file_index": 1, "sql_preview": "SELECT 2", "status": "ALLOWED" },
            { "line": 3, "file_index": 2, "sql_preview": "DELETE FROM users", "status": "BLOCKED",
              "action": "block", "rule_code": "VERICTO-001", "severity": "critical",
              "ast_node_path": "DeleteStmt > WhereClause = NULL" }
        ],
        "exit_code": 1,
        "ci_checks_remaining": 997,
        "telemetry_query_mode": "raw"
    })
}

#[tokio::test]
async fn check_per_statement_reports_the_real_file_and_line() {
    let server = mock_per_statement_backend(per_statement_body()).await;
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.sql");
    let b = dir.path().join("b.sql");
    std::fs::write(&a, "SELECT 1;\nSELECT 2;").unwrap();
    std::fs::write(&b, "-- cleanup\n\nDELETE FROM users;").unwrap();

    let out = vericto()
        .args([
            "check",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--no-color",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = format!("{}:3", b.to_str().unwrap());
    assert!(
        stdout.contains(&expected),
        "text output should point at {expected}:\n{stdout}"
    );

    let sarif_path = dir.path().join("out.sarif");
    vericto()
        .args([
            "check",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--format",
            "sarif",
            "--output",
            sarif_path.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(1);
    let sarif: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&sarif_path).unwrap()).unwrap();
    let loc = &sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(loc["artifactLocation"]["uri"], b.to_str().unwrap());
    assert_eq!(loc["region"]["startLine"], 3);
}

#[tokio::test]
async fn check_against_an_older_backend_keeps_sending_queries() {
    // No `capabilities` in /ci/config: the CLI must not send `files`.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(config_body("raw")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .and(wiremock::matchers::body_string_contains("\"queries\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(check_body(&["ALLOWED"])))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("ok.sql");
    std::fs::write(&sql, "SELECT 1 LIMIT 1;").unwrap();

    vericto()
        .args(["check", sql.to_str().unwrap(), "--quiet"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
}

// ── baseline privacy, per-statement baselines, statement-scoped ignores ─────

/// Mounts a sanitized-mode, per-statement backend whose check-key answers 418
/// to any body carrying the raw literal — so a client that skips sanitization
/// fails the test instead of passing it.
async fn mock_sanitized_backend(check: serde_json::Value, raw_literal: &str) -> MockServer {
    let server = MockServer::start().await;
    let mut cfg = config_body("sanitized");
    cfg["capabilities"] = serde_json::json!(["check_files"]);
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(cfg))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .and(wiremock::matchers::body_string_contains(raw_literal))
        .respond_with(ResponseTemplate::new(418))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(check))
        .with_priority(5)
        .mount(&server)
        .await;
    server
}

fn one_finding(line: u32, hash: &str) -> serde_json::Value {
    serde_json::json!({
        "summary": { "total": 1, "blocked": 1, "allowed": 0, "flagged": 0, "monitored": 0, "parse_errors": 0, "ruleset_version": "v1" },
        "queries": [{ "line": line, "file_index": 1, "statement_hash": hash, "sql_preview": "DELETE FROM users",
                      "status": "BLOCKED", "rule_code": "VERICTO-001", "severity": "critical",
                      "ast_node_path": "DeleteStmt > WhereClause = NULL" }],
        "exit_code": 1,
        "telemetry_query_mode": "sanitized"
    })
}

#[tokio::test]
async fn baseline_sanitizes_literals_like_check_does() {
    let server = mock_sanitized_backend(one_finding(1, "h1"), "alice@example.com").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(
        &sql,
        "DELETE FROM users WHERE email = 'alice@example.com' OR 1=1;",
    )
    .unwrap();
    let out = dir.path().join("baseline.json");

    vericto()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(written["version"], 2);
}

#[tokio::test]
async fn a_per_statement_baseline_does_not_hide_a_new_statement() {
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let bl = dir.path().join("baseline.json");

    // Baseline the existing DELETE (hash h1)…
    let server = mock_per_statement_backend(one_finding(1, "h1")).await;
    vericto()
        .args([
            "baseline",
            sql.to_str().unwrap(),
            "--out",
            bl.to_str().unwrap(),
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);

    // …the same statement still passes…
    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--baseline",
            bl.to_str().unwrap(),
            "--quiet",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);

    // …but a different DELETE without WHERE in the same file fails the run.
    let server = mock_per_statement_backend(one_finding(3, "h2")).await;
    vericto()
        .args([
            "check",
            sql.to_str().unwrap(),
            "--baseline",
            bl.to_str().unwrap(),
            "--quiet",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(1);
}

#[tokio::test]
async fn an_inline_ignore_covers_only_the_statement_below_it() {
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(
        &sql,
        "DELETE FROM sessions;\n-- vericto:ignore[VERICTO-001] approved purge, TICKET-42\nDELETE FROM orders;",
    )
    .unwrap();
    let both = serde_json::json!({
        "summary": { "total": 2, "blocked": 2, "allowed": 0, "flagged": 0, "monitored": 0, "parse_errors": 0, "ruleset_version": "v1" },
        "queries": [
            { "line": 1, "file_index": 1, "statement_hash": "s", "sql_preview": "DELETE FROM sessions", "status": "BLOCKED",
              "rule_code": "VERICTO-001", "severity": "critical", "ast_node_path": "DeleteStmt > WhereClause = NULL" },
            { "line": 3, "file_index": 1, "statement_hash": "o", "sql_preview": "DELETE FROM orders", "status": "BLOCKED",
              "rule_code": "VERICTO-001", "severity": "critical", "ast_node_path": "DeleteStmt > WhereClause = NULL" }
        ],
        "exit_code": 1
    });
    let server = mock_per_statement_backend(both).await;
    let out = vericto()
        .args(["check", sql.to_str().unwrap(), "--no-color"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .output()
        .unwrap();
    // The ignore covers line 3 only; line 1 still fails the run.
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("m.sql:3: VERICTO-001 suppressed inline"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("m.sql:1: VERICTO-001 suppressed inline"),
        "{stderr}"
    );
}

// ── vericto rules simulate ───────────────────────────────────────────────────

fn simulation_body(status: &str, verdict: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "simulation_id": "7f3c0000-0000-4000-8000-000000000001",
        "status": status,
        "summary": verdict.map(|v| serde_json::json!({
            "verdict": v,
            "headline": "Would have blocked 2 legitimate flows (9,442 executions) in the last 30 days.",
            "window": { "start": "2026-09-10T00:00:00Z", "end": "2026-10-10T00:00:00Z", "days": 30 },
            "events": 11355, "fingerprints": 8, "evaluated_statements": 10255, "budget": 200000,
            "coverage": { "ratio": 1.0, "evaluated_executions": 11355, "inferred_executions": 0, "not_replayable_executions": 0 },
            "categories": { "unchanged": { "fingerprints": 5, "executions": 1912 }, "drift": { "fingerprints": 3, "executions": 12 } },
            "candidates": [],
            "query_text_mode": "raw"
        })),
        "findings": []
    })
}

fn write_rule_file(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("deletes.yaml");
    std::fs::write(
        &p,
        "rules:\n  - name: no-physical-deletes\n    severity: high\n    dialect: postgres\n    ast_condition_yaml: |\n      rule: no-physical-deletes\n      node_type: DeleteStmt\n",
    )
    .unwrap();
    p
}

#[tokio::test]
async fn rules_simulate_waits_and_fails_on_legitimate_breakage() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/rules/simulate"))
        .and(wiremock::matchers::body_string_contains(
            "\"kind\":\"custom_new\"",
        ))
        .respond_with(
            ResponseTemplate::new(202)
                .insert_header("Retry-After", "1")
                .set_body_json(simulation_body("queued", None)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v1/ci/rules/simulations/7f3c0000-0000-4000-8000-000000000001",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(simulation_body("succeeded", Some("fail"))),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = write_rule_file(dir.path());
    let out = vericto()
        .args(["rules", "simulate", file.to_str().unwrap(), "--days", "30"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8_lossy(&out);
    assert!(
        s.contains("FAIL  Would have blocked 2 legitimate flows"),
        "output: {s}"
    );
}

#[tokio::test]
async fn rules_simulate_exit_codes_for_scope_and_bad_file() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/rules/simulate"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "error": { "code": "FORBIDDEN", "message": "This API key lacks the required scope: rules:simulate" }
        })))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = write_rule_file(dir.path());
    vericto()
        .args(["rules", "simulate", file.to_str().unwrap()])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(3);

    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "rules:\n  - name: x\n    sevrity: high\n").unwrap();
    vericto()
        .args(["rules", "simulate", bad.to_str().unwrap()])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(2);
}

#[tokio::test]
async fn rules_simulate_pass_exits_zero_and_json_is_the_api_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/rules/simulate"))
        .respond_with(
            ResponseTemplate::new(202)
                .insert_header("Retry-After", "1")
                .set_body_json(simulation_body("running", None)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v1/ci/rules/simulations/7f3c0000-0000-4000-8000-000000000001",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(simulation_body("succeeded", Some("warn"))),
        )
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = write_rule_file(dir.path());
    let out = vericto()
        .args([
            "rules",
            "simulate",
            file.to_str().unwrap(),
            "--format",
            "json",
        ])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["summary"]["verdict"], "warn");
}

// ── check: output formats, CI integration, exit codes, input boundaries ──────

/// Writes `body` to `dir/name` and returns the path as a string.
fn write_sql(dir: &std::path::Path, name: &str, body: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p.to_str().unwrap().to_string()
}

/// A `vericto check ...` against `api_url` with a static key.
fn check_against(api_url: &str, args: &[&str]) -> Vericto {
    let mut v = vericto();
    v.arg("check")
        .args(args)
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", api_url);
    v
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The JSON bodies the mock received on `POST /ci/check-key`.
async fn check_requests(server: &MockServer) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path() == "/api/v1/ci/check-key")
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .collect()
}

/// Every output format writes a parseable report to `--output`, nothing to
/// stdout, and the run still fails on the blocked finding with the reason on
/// stderr.
#[tokio::test]
async fn every_output_format_writes_its_report_and_keeps_the_exit_code() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "m.sql", "DELETE FROM users;");
    for format in ["text", "json", "sarif", "gitlab-codequality", "gitlab-sast"] {
        let report = dir.path().join(format!("report-{format}"));
        let out = check_against(
            &server.uri(),
            &[
                &sql,
                "--format",
                format,
                "--output",
                report.to_str().unwrap(),
                "--no-color",
            ],
        )
        .output()
        .unwrap();
        assert_eq!(out.status.code(), Some(1), "{format}: {}", stderr_of(&out));
        assert!(
            stdout_of(&out).is_empty(),
            "{format}: report goes to the file"
        );
        assert!(
            stderr_of(&out).contains("Vericto blocked 1 statement"),
            "{format}: {}",
            stderr_of(&out)
        );
        let body = std::fs::read_to_string(&report).unwrap();
        match format {
            "text" => assert!(body.contains("VERICTO-001"), "{body}"),
            _ => {
                let v: serde_json::Value = serde_json::from_str(&body)
                    .unwrap_or_else(|e| panic!("{format} is not JSON ({e}): {body}"));
                match format {
                    "json" => assert_eq!(v["summary"]["blocked"], 1),
                    "sarif" => {
                        assert_eq!(v["version"], "2.1.0");
                        assert_eq!(v["runs"][0]["results"][0]["ruleId"], "VERICTO-001");
                    }
                    "gitlab-codequality" => {
                        assert_eq!(v.as_array().map(Vec::len), Some(1), "{v}")
                    }
                    _ => assert!(v["vulnerabilities"].is_array(), "{v}"),
                }
            }
        }
    }
}

/// The default text report on stdout names the file and the rule.
#[tokio::test]
async fn text_report_names_the_file_and_the_rule() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "drop_users.sql", "DELETE FROM users;");
    let out = check_against(&server.uri(), &[&sql, "--no-color"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = stdout_of(&out);
    assert!(stdout.contains("drop_users.sql"), "{stdout}");
    assert!(stdout.contains("VERICTO-001"), "{stdout}");
    assert!(!stdout.contains('\u{1b}'), "--no-color: no ANSI escapes");
}

/// On GitHub Actions a failing run prints `::error` workflow commands, so the
/// finding shows up as an annotation on the PR, and the request carries the
/// run's provenance (never a credential).
#[tokio::test]
async fn on_github_actions_findings_become_annotations_and_provenance_is_sent() {
    let server = mock_backend(check_body(&["BLOCKED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "m.sql", "DELETE FROM users;");
    let out = check_against(&server.uri(), &["m.sql", "--no-color"])
        .current_dir(dir.path())
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_SERVER_URL", "https://github.com")
        .env("GITHUB_REPOSITORY", "acme/shop")
        .env("GITHUB_RUN_ID", "4242")
        .env("GITHUB_ACTOR", "octocat")
        .env("GITHUB_REF", "refs/pull/7/merge")
        .output()
        .unwrap();
    let _ = sql;
    assert_eq!(out.status.code(), Some(1));
    let stderr = stderr_of(&out);
    assert!(
        stderr.contains("::error file=m.sql,line=1,title=Vericto VERICTO-001 [BLOCKED]::"),
        "{stderr}"
    );

    let reqs = check_requests(&server).await;
    assert_eq!(reqs.len(), 1);
    let prov = &reqs[0]["provenance"];
    assert_eq!(prov["ci_provider"], "github");
    assert_eq!(
        prov["ci_run_url"],
        "https://github.com/acme/shop/actions/runs/4242"
    );
    assert_eq!(prov["actor"], "octocat");
    assert_eq!(prov["git_ref"], "refs/pull/7/merge");
    assert!(
        !reqs[0].to_string().contains("vtro_k"),
        "no key in the body"
    );
}

/// On GitLab the provenance names the job URL and the user.
#[tokio::test]
async fn on_gitlab_ci_the_provenance_names_the_job() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    write_sql(dir.path(), "ok.sql", "SELECT 1 LIMIT 1;");
    check_against(&server.uri(), &["ok.sql", "--quiet"])
        .current_dir(dir.path())
        .env("GITLAB_CI", "true")
        .env("CI_JOB_URL", "https://gitlab.com/acme/shop/-/jobs/9")
        .env("GITLAB_USER_LOGIN", "gluser")
        .env("CI_COMMIT_REF_NAME", "feature/x")
        .assert()
        .code(0);
    let reqs = check_requests(&server).await;
    let prov = &reqs[0]["provenance"];
    assert_eq!(prov["ci_provider"], "gitlab");
    assert_eq!(prov["ci_run_url"], "https://gitlab.com/acme/shop/-/jobs/9");
    assert_eq!(prov["actor"], "gluser");
    assert_eq!(prov["git_ref"], "feature/x");
}

/// `--fail-on` decides which findings fail the run: block (default) lets a
/// FLAGGED finding pass, flag fails it; any also fails on MONITORED.
#[tokio::test]
async fn fail_on_thresholds_set_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "q.sql", "SELECT * FROM users;");

    let flagged = mock_backend(check_body(&["FLAGGED"]), "raw").await;
    for (args, code) in [
        (vec![], 0),
        (vec!["--fail-on", "block"], 0),
        (vec!["--fail-on", "flag"], 1),
        (vec!["--fail-on", "any"], 1),
    ] {
        let mut all = vec![sql.as_str(), "--quiet"];
        all.extend(args.iter().copied());
        check_against(&flagged.uri(), &all).assert().code(code);
    }

    let monitored = mock_backend(check_body(&["MONITORED"]), "raw").await;
    check_against(&monitored.uri(), &[&sql, "--quiet", "--fail-on", "flag"])
        .assert()
        .code(0);
    check_against(&monitored.uri(), &[&sql, "--quiet", "--fail-on", "any"])
        .assert()
        .code(1);
}

/// `.vericto.toml` (the committed project config) sets the defaults a PR can
/// review: fail_on and the dialect sent to the backend. A flag still wins.
#[tokio::test]
async fn project_config_sets_fail_on_and_dialect() {
    let server = mock_backend(check_body(&["FLAGGED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    write_sql(dir.path(), "q.sql", "SELECT * FROM users;");
    std::fs::write(
        dir.path().join(".vericto.toml"),
        "fail_on = \"flag\"\ndefault_dialect = \"mysql\"\n",
    )
    .unwrap();
    check_against(&server.uri(), &["q.sql", "--quiet"])
        .current_dir(dir.path())
        .assert()
        .code(1);
    check_against(&server.uri(), &["q.sql", "--quiet", "--fail-on", "block"])
        .current_dir(dir.path())
        .assert()
        .code(0);
    let reqs = check_requests(&server).await;
    assert!(reqs.iter().all(|r| r["dialect"] == "mysql"), "{reqs:?}");
}

/// `.vericto.toml` is committed and reviewable, so it may not carry a secret or
/// the break-glass, and a malformed one is a hard usage error — never ignored.
#[tokio::test]
async fn an_unsafe_or_malformed_project_config_is_a_usage_error() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    for (body, needle) in [
        ("api_key = \"vtro_leaked\"\n", "must not contain api_key"),
        (
            "allow_degraded = \"outage\"\n",
            "must not set allow_degraded",
        ),
        ("fail_on = [unclosed\n", "invalid .vericto.toml"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        write_sql(dir.path(), "q.sql", "SELECT 1 LIMIT 1;");
        std::fs::write(dir.path().join(".vericto.toml"), body).unwrap();
        let out = check_against(&server.uri(), &["q.sql", "--quiet"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{body}");
        assert!(stderr_of(&out).contains(needle), "{}", stderr_of(&out));
        assert!(
            !stderr_of(&out).contains("vtro_leaked"),
            "the key is not echoed"
        );
    }
    assert!(check_requests(&server).await.is_empty(), "no SQL was sent");
}

/// A malformed user config file is a warning, not a failure: the run proceeds
/// with the key from the environment.
#[tokio::test]
async fn a_malformed_user_config_warns_and_the_run_proceeds() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "ok.sql", "SELECT 1 LIMIT 1;");
    let cfg_dir = dir.path().join("xdg/vericto");
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(cfg_dir.join("config.toml"), "api_key = = broken").unwrap();
    let out = check_against(&server.uri(), &[&sql, "--quiet"])
        .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("warning: invalid config at"),
        "{}",
        stderr_of(&out)
    );
}

/// Empty or missing input is a usage error (exit 2), before any SQL is sent.
#[tokio::test]
async fn empty_or_missing_input_is_a_usage_error() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let empty = write_sql(dir.path(), "empty.sql", "  \n\t\n");
    let missing = dir.path().join("missing.sql");
    let cases: Vec<(Vec<String>, Option<&str>, &str)> = vec![
        (vec![empty.clone()], None, "no SQL to check"),
        (vec!["-".into()], Some("   \n"), "no SQL to check"),
        (vec![missing.to_str().unwrap().into()], None, "cannot read"),
        (vec!["--sql".into(), "   ".into()], None, "--sql was empty"),
        (vec![], None, "no files given"),
        (
            vec!["--stdin-file-list".into(), empty.clone()],
            None,
            "--stdin-file-list can't be combined",
        ),
        (
            vec!["--since".into(), "origin/main".into(), empty.clone()],
            None,
            "not both",
        ),
    ];
    for (args, stdin, needle) in cases {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut cmd = check_against(&server.uri(), &args);
        if let Some(input) = stdin {
            cmd.write_stdin(input);
        }
        let out = cmd.output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr_of(&out));
        assert!(
            stderr_of(&out).contains(needle),
            "{args:?}: {}",
            stderr_of(&out)
        );
    }
    assert!(check_requests(&server).await.is_empty(), "no SQL was sent");
}

/// Several files in one run: one query per file, labelled by its path, and an
/// empty file among them is skipped rather than failing the run.
#[tokio::test]
async fn several_files_are_checked_in_one_request_and_empty_ones_skipped() {
    let server = mock_backend(check_body(&["ALLOWED", "ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let a = write_sql(dir.path(), "a.sql", "SELECT 1 LIMIT 1;");
    let empty = write_sql(dir.path(), "b.sql", "");
    let c = write_sql(dir.path(), "c.sql", "SELECT 2 LIMIT 1;");
    check_against(&server.uri(), &[&a, &empty, &c, "--quiet"])
        .assert()
        .code(0);
    let reqs = check_requests(&server).await;
    let queries = reqs[0]["queries"].as_array().unwrap();
    assert_eq!(queries.len(), 2);
    assert_eq!(queries[0]["line"], 1);
    assert_eq!(
        queries[1]["line"], 3,
        "the index of the file, not of the query"
    );
}

/// A report path that cannot be written is a usage error, not a silent pass.
#[tokio::test]
async fn an_unwritable_output_path_is_a_usage_error() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "ok.sql", "SELECT 1 LIMIT 1;");
    let report = dir.path().join("no/such/dir/report.json");
    let out = check_against(
        &server.uri(),
        &[
            &sql,
            "--format",
            "json",
            "--output",
            report.to_str().unwrap(),
        ],
    )
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr_of(&out).contains("could not write output"),
        "{}",
        stderr_of(&out)
    );
}

/// The backend's errors map to the documented exit codes: a rejected key is 3,
/// any other refusal is 4, and neither prints a report.
#[tokio::test]
async fn backend_refusals_map_to_exit_codes() {
    for (status, code) in [(401u16, 3), (403, 3), (400, 4), (404, 4)] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ci/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(config_body("raw")))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/ci/check-key"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "error": { "code": "X", "message": format!("refused with {status}") }
                })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let out = check_against(&server.uri(), &["-", "--quiet"])
            .write_stdin("SELECT 1;")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code), "HTTP {status}");
        assert!(
            stderr_of(&out).contains(&format!("refused with {status}")),
            "{}",
            stderr_of(&out)
        );
        assert!(stdout_of(&out).is_empty());
    }
}

/// A key rejected at the pre-flight fails with 3 before any SQL is sent.
#[tokio::test]
async fn a_key_rejected_at_preflight_exits_3_without_sending_sql() {
    let server = backend_with_config_status(401, 0).await;
    check_against(&server.uri(), &["-", "--quiet"])
        .write_stdin("SELECT 1;")
        .assert()
        .code(3);
}

/// Without `--allow-degraded`, an unreachable backend fails the build (4).
#[tokio::test]
async fn an_unreachable_backend_fails_closed_without_the_break_glass() {
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "m.sql", "DELETE FROM users;");
    let out = check_against("http://127.0.0.1:1", &[&sql, "--timeout", "1", "--quiet"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stderr_of(&out).contains("No SQL was sent"),
        "{}",
        stderr_of(&out)
    );
    assert!(!dir.path().join(".vericto").exists(), "no degraded record");
}

/// `--allow-degraded` needs a reason; an empty one is a usage error.
#[tokio::test]
async fn the_break_glass_requires_a_reason() {
    let dir = tempfile::tempdir().unwrap();
    let sql = write_sql(dir.path(), "m.sql", "DELETE FROM users;");
    check_against(
        "http://127.0.0.1:1",
        &[&sql, "--timeout", "1", "--allow-degraded", "  ", "--quiet"],
    )
    .current_dir(dir.path())
    .assert()
    .code(2);
}

/// A backend of another major API version may answer in a shape this CLI
/// misreads: the run fails (4) instead of reporting a guess.
#[tokio::test]
async fn an_incompatible_backend_major_version_fails_the_run() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(config_body("raw")))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("X-Vericto-Api-Version", "2.0.0")
                .set_body_json(check_body(&["ALLOWED"])),
        )
        .mount(&server)
        .await;
    let out = check_against(&server.uri(), &["-"])
        .write_stdin("SELECT 1;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stderr_of(&out).contains("incompatible backend api 2.0.0"),
        "{}",
        stderr_of(&out)
    );
}

/// Low allowance and an outdated CLI are nudged on stderr only, so a JSON
/// report on stdout stays parseable; neither changes the exit code.
#[tokio::test]
async fn quota_and_upgrade_nudges_go_to_stderr_only() {
    let mut body = check_body(&["ALLOWED"]);
    body["ci_checks_remaining"] = serde_json::json!(7);
    body["min_cli_version"] = serde_json::json!("999.0.0");
    let server = mock_backend(body, "raw").await;
    let out = check_against(&server.uri(), &["-", "--format", "json"])
        .write_stdin("SELECT 1;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stderr = stderr_of(&out);
    assert!(stderr.contains("7 CLI checks left this month"), "{stderr}");
    assert!(
        stderr.contains("older than the minimum supported 999.0.0"),
        "{stderr}"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(v["summary"]["total"], 1);
}

/// `--receipt` against a deployment that doesn't sign: a warning, no file, and
/// the check's own result stands.
#[tokio::test]
async fn a_receipt_requested_from_a_non_signing_backend_warns_and_writes_nothing() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let dir = tempfile::tempdir().unwrap();
    let receipt = dir.path().join("receipt.json");
    let out = check_against(
        &server.uri(),
        &["-", "--quiet", "--receipt", receipt.to_str().unwrap()],
    )
    .write_stdin("SELECT 1;")
    .output()
    .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stderr_of(&out).contains("returned no receipt"),
        "{}",
        stderr_of(&out)
    );
    assert!(!receipt.exists());
    let reqs = check_requests(&server).await;
    assert_eq!(reqs[0]["receipt"], true, "the receipt was requested");
}

// ── check --changed / --since (git diff selection) ───────────────────────────

/// Runs git in `dir` with a fixed identity; panics on failure.
fn git(dir: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.name=Vericto Test",
            "-c",
            "user.email=test@example.com",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git is installed");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repo with `main` holding a.sql, and a `feature` branch that changes a.sql,
/// adds b.sql and a non-SQL file, and deletes old.sql.
fn feature_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    git(d, &["init", "-q"]);
    std::fs::write(d.join("a.sql"), "SELECT 1 LIMIT 1;").unwrap();
    std::fs::write(d.join("old.sql"), "SELECT 0 LIMIT 1;").unwrap();
    git(d, &["add", "."]);
    git(d, &["commit", "-q", "-m", "base"]);
    git(d, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(d.join("a.sql"), "DELETE FROM users;").unwrap();
    std::fs::write(d.join("b.sql"), "SELECT 2 LIMIT 1;").unwrap();
    std::fs::write(d.join("notes.md"), "not SQL").unwrap();
    std::fs::remove_file(d.join("old.sql")).unwrap();
    git(d, &["add", "-A"]);
    git(d, &["commit", "-q", "-m", "feature"]);
    dir
}

/// A `check` in `dir` with PATH kept, so the CLI can run git.
fn check_in_repo(dir: &std::path::Path, api_url: &str, args: &[&str]) -> Vericto {
    let mut v = check_against(api_url, args);
    v.current_dir(dir)
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    v
}

/// `--since <ref>` checks only the .sql files changed vs the merge base:
/// modified and added ones, never deleted or non-SQL files.
#[tokio::test]
async fn since_checks_only_the_changed_sql_files() {
    let server = mock_backend(check_body(&["BLOCKED", "ALLOWED"]), "raw").await;
    let repo = feature_repo();
    check_in_repo(repo.path(), &server.uri(), &["--since", "main", "--quiet"])
        .assert()
        .code(1);
    let reqs = check_requests(&server).await;
    let sqls: Vec<&str> = reqs[0]["queries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|q| q["sql"].as_str().unwrap())
        .collect();
    assert_eq!(sqls, vec!["DELETE FROM users;", "SELECT 2 LIMIT 1;"]);
}

/// No changed SQL is a pass (0) with a message, and nothing is sent.
#[tokio::test]
async fn no_changed_sql_is_a_pass_without_a_request() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let repo = feature_repo();
    let out = check_in_repo(repo.path(), &server.uri(), &["--since", "feature"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stdout_of(&out).contains("No changed .sql files vs feature"),
        "{}",
        stdout_of(&out)
    );
    assert!(check_requests(&server).await.is_empty());
}

/// A base ref that does not exist, or no base to detect at all, is a usage
/// error naming the problem — never a silent "nothing to check".
#[tokio::test]
async fn an_unknown_or_undetectable_base_ref_is_a_usage_error() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let repo = feature_repo();

    let out = check_in_repo(repo.path(), &server.uri(), &["--since", "no-such-ref"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr_of(&out).contains("git diff against 'no-such-ref' failed"),
        "{}",
        stderr_of(&out)
    );

    // Locally, without an origin remote, --changed has no base to use.
    let out = check_in_repo(repo.path(), &server.uri(), &["--changed"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr_of(&out).contains("could not determine a base ref"),
        "{}",
        stderr_of(&out)
    );

    // On a GitHub pull request the base comes from GITHUB_BASE_REF.
    let out = check_in_repo(repo.path(), &server.uri(), &["--changed"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_BASE_REF", "main")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr_of(&out).contains("'origin/main'"),
        "{}",
        stderr_of(&out)
    );
    assert!(check_requests(&server).await.is_empty());
}

// ── OIDC (workload identity) failure modes ───────────────────────────────────

/// A JWT-shaped token in the GitLab variable but no workspace anywhere: exit 3
/// naming the missing workspace, before any request.
#[tokio::test]
async fn oidc_token_without_a_workspace_names_the_missing_workspace() {
    let out = vericto()
        .args(["check", "-", "--oidc", "--quiet"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .env("VERICTO_ID_TOKEN", "header.payload.signature")
        .write_stdin("SELECT 1;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stderr_of(&out).contains("needs a workspace"),
        "{}",
        stderr_of(&out)
    );
}

/// GitHub Actions: the token is fetched from the runner's endpoint with the
/// requested audience, exchanged, and the minted key is used for the check.
#[tokio::test]
async fn github_actions_oidc_token_is_fetched_exchanged_and_used() {
    use wiremock::matchers::{header, query_param};
    let server = mock_backend_with_oidc(check_body(&["ALLOWED"])).await;
    Mock::given(method("GET"))
        .and(path("/gh-token"))
        .and(query_param("audience", "vericto"))
        .and(header("Authorization", "Bearer runner-request-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": "gh.jwt.token" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    let out = vericto()
        .args(["check", "-", "--workspace", "ws_1", "--quiet"])
        .env("VERICTO_API_URL", server.uri())
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/gh-token", server.uri()),
        )
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-request-token")
        .write_stdin("SELECT 1;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains("authenticated via OIDC (github-actions)"),
        "{}",
        stderr_of(&out)
    );
    let used_minted = server.received_requests().await.unwrap().iter().any(|r| {
        r.url.path() == "/api/v1/ci/check-key"
            && r.headers.get("x-api-key").map(|v| v.as_bytes()) == Some(b"vtro_minted")
    });
    assert!(used_minted, "the check used the minted key");
}

/// A token endpoint that fails, or an exchange the backend refuses, is exit 3;
/// an exchange that fails for another reason is exit 4.
#[tokio::test]
async fn oidc_token_and_exchange_failures_map_to_exit_codes() {
    // Token endpoint refuses.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/gh-token"))
        .respond_with(ResponseTemplate::new(403).set_body_string("no id-token permission"))
        .mount(&server)
        .await;
    let out = vericto()
        .args(["check", "-", "--workspace", "ws_1", "--quiet"])
        .env("VERICTO_API_URL", server.uri())
        .env(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            format!("{}/gh-token", server.uri()),
        )
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t")
        .write_stdin("SELECT 1;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stderr_of(&out).contains("could not obtain an OIDC ID token"),
        "{}",
        stderr_of(&out)
    );

    // Exchange refused (no trust policy matched) → 3; exchange broken → 4.
    for (status, code) in [(403u16, 3), (500, 4)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/oidc-exchange"))
            .respond_with(ResponseTemplate::new(status).set_body_string("exchange says no"))
            .mount(&server)
            .await;
        let out = vericto()
            .args(["check", "-", "--workspace", "ws_1", "--quiet"])
            .env("VERICTO_API_URL", server.uri())
            .env("VERICTO_ID_TOKEN", "header.payload.signature")
            .write_stdin("SELECT 1;")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code), "exchange HTTP {status}");
        assert!(
            stderr_of(&out).contains("OIDC token exchange failed"),
            "{}",
            stderr_of(&out)
        );
    }
}

/// `login --oidc` inside CI verifies the exchange right away: success is 0, a
/// refused exchange is 3, and either way no secret is written.
#[tokio::test]
async fn login_oidc_in_ci_verifies_the_exchange() {
    for (status, code) in [(200u16, 0), (403, 3)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/oidc-exchange"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "api_key": "vtro_minted", "expires_at": "2026-10-18T00:15:00Z"
                })),
            )
            .mount(&server)
            .await;
        let home = tempfile::tempdir().unwrap();
        let out = vericto()
            .args([
                "login",
                "--oidc",
                "--workspace",
                "ws_9",
                "--audience",
                "vericto-ci",
                "--api-url",
                &server.uri(),
            ])
            .env("XDG_CONFIG_HOME", home.path())
            .env("VERICTO_ID_TOKEN", "header.payload.signature")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code), "{}", stderr_of(&out));
        let saved = std::fs::read_to_string(home.path().join("vericto/config.toml")).unwrap();
        assert!(
            saved.contains("ws_9") && saved.contains("vericto-ci"),
            "{saved}"
        );
        assert!(
            !saved.contains("vtro_minted"),
            "the minted key is never stored"
        );
    }
}

#[test]
fn login_oidc_requires_a_workspace() {
    let out = vericto().args(["login", "--oidc"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr_of(&out).contains("requires --workspace"),
        "{}",
        stderr_of(&out)
    );
}

// ── doctor, logout, init: the remaining branches ─────────────────────────────

/// `doctor` fails on a backend of another major version, and reports a
/// rejected key as an auth problem (3) without spending a check.
#[tokio::test]
async fn doctor_flags_an_incompatible_backend_and_a_rejected_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "api_version": "3.1.0"
        })))
        .mount(&server)
        .await;
    let out = vericto()
        .arg("doctor")
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stdout_of(&out).contains("incompatible backend"),
        "{}",
        stdout_of(&out)
    );

    // No /version (older backend) is not fatal; the auth probe decides.
    let server = backend_with_config_status(401, 0).await;
    let out = vericto()
        .arg("doctor")
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let stdout = stdout_of(&out);
    assert!(stdout.contains("version endpoint unavailable"), "{stdout}");
    assert!(stdout.contains("auth/entitlement failed"), "{stdout}");

    // A backend error other than auth is 4.
    let server = backend_with_config_status(404, 0).await;
    vericto()
        .arg("doctor")
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(4);
}

#[test]
fn doctor_without_any_credential_exits_3() {
    let out = vericto()
        .arg("doctor")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stdout_of(&out).contains("authentication unavailable"),
        "{}",
        stdout_of(&out)
    );
}

#[test]
fn logout_without_stored_credentials_is_a_no_op() {
    let home = tempfile::tempdir().unwrap();
    let logout = || {
        let out = vericto()
            .arg("logout")
            .env("XDG_CONFIG_HOME", home.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        stdout_of(&out)
    };
    assert!(logout().contains("No stored credentials."));

    // A config with preferences but no key keeps the file as it is.
    let cfg = home.path().join("vericto");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(cfg.join("config.toml"), "default_dialect = \"mysql\"\n").unwrap();
    assert!(logout().contains("No stored API key."));
    assert_eq!(
        std::fs::read_to_string(cfg.join("config.toml")).unwrap(),
        "default_dialect = \"mysql\"\n"
    );
}

/// GitLab scaffolding never touches `.gitlab-ci.yml`: it writes an include file
/// and says how to wire it; `--hook` adds an executable pre-commit hook.
/// Existing files are skipped unless `--force`.
#[test]
fn init_gitlab_with_hook_writes_the_include_and_the_hook() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();
    let out = vericto()
        .args(["init", "--target", "gitlab", "--hook", "--dialect", "mysql"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("- local: .vericto/gitlab-ci.yml"),
        "{stdout}"
    );
    assert!(stdout.contains("masked CI/CD variable"), "{stdout}");
    let job = std::fs::read_to_string(dir.path().join(".vericto/gitlab-ci.yml")).unwrap();
    assert!(job.contains("mysql"), "{job}");
    let hook = dir.path().join(".git/hooks/pre-commit");
    assert!(hook.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&hook).unwrap().permissions().mode();
        assert!(mode & 0o111 != 0, "the hook is executable: {mode:o}");
    }

    // A second run skips both; --force rewrites them.
    let again = vericto()
        .args(["init", "--target", "gitlab", "--hook"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(again.status.code(), Some(0));
    assert_eq!(stdout_of(&again).matches("exists, skipped").count(), 2);
    let forced = vericto()
        .args(["init", "--target", "gitlab", "--hook", "--force"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(stdout_of(&forced).matches("created").count(), 2);
}

#[test]
fn init_gitlab_oidc_explains_the_trust_policy() {
    let dir = tempfile::tempdir().unwrap();
    let out = vericto()
        .args([
            "init",
            "--target",
            "gitlab",
            "--oidc",
            "--workspace",
            "ws_3",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(
        stdout_of(&out).contains("issuer https://gitlab.com"),
        "{}",
        stdout_of(&out)
    );
    let job = std::fs::read_to_string(dir.path().join(".vericto/gitlab-ci.yml")).unwrap();
    assert!(job.contains("ws_3"), "{job}");
}

/// Without --target and nothing to detect the provider from, init refuses
/// rather than guessing.
#[test]
fn init_without_a_detectable_provider_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = vericto()
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr_of(&out).contains("--target github|gitlab"),
        "{}",
        stderr_of(&out)
    );
}

// ── check --offline (DESIGN §13) ─────────────────────────────────────────────

/// A mock that answers nothing (404) and records everything: pointed at by the
/// API URL, every proxy variable and the GitHub OIDC endpoint, so any request
/// the CLI makes, to any host, lands on it.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
fn tripwired(cmd: &mut Vericto, api: &MockServer, trip: &MockServer) {
    let t = trip.uri();
    cmd.env("VERICTO_API_URL", api.uri())
        .env("VERICTO_API_KEY", "vtro_k")
        .env("HTTP_PROXY", &t)
        .env("HTTPS_PROXY", &t)
        .env("ALL_PROXY", &t)
        .env("http_proxy", &t)
        .env("https_proxy", &t)
        .env("GITHUB_ACTIONS", "true")
        .env("ACTIONS_ID_TOKEN_REQUEST_URL", format!("{t}/token"))
        .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t");
}

/// The guarantee offline mode exists for: with a key, a reachable backend, a
/// proxy and an OIDC endpoint all configured, `--offline` makes no request at
/// all, in any output format, from files, stdin or `--sql`.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[tokio::test]
async fn offline_makes_no_network_request() {
    let api = mock_backend(check_body(&["ALLOWED"]), "sanitized").await;
    let trip = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let file = sql.to_str().unwrap();

    for format in ["text", "json", "sarif", "gitlab-codequality", "gitlab-sast"] {
        let mut cmd = vericto();
        tripwired(&mut cmd, &api, &trip);
        cmd.args(["check", "--offline", "--format", format, file])
            .assert()
            .code(1);
    }
    let mut cmd = vericto();
    tripwired(&mut cmd, &api, &trip);
    cmd.args(["check", "--offline", "-"])
        .write_stdin("DELETE FROM users;")
        .assert()
        .code(1);
    let mut cmd = vericto();
    tripwired(&mut cmd, &api, &trip);
    cmd.args(["check", "--offline", "--sql", "DELETE FROM users"])
        .assert()
        .code(1);

    let api_hits = api.received_requests().await.unwrap();
    let trip_hits = trip.received_requests().await.unwrap();
    assert!(api_hits.is_empty(), "backend was called: {api_hits:?}");
    assert!(trip_hits.is_empty(), "something went out: {trip_hits:?}");
}

/// Outside CI, no credential at all means offline, said on stderr and in the
/// report; in CI the same run stays exit 3 (`missing_api_key_exits_3`).
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn no_credential_outside_ci_checks_offline() {
    let out = vericto()
        .args(["check", "-", "--no-color"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .write_stdin("DELETE FROM users;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    assert!(stderr_of(&out).contains("no API key or login found"));
    let stdout = stdout_of(&out);
    assert!(
        stdout.contains("BLOCKED <stdin>  VERICTO-001 critical"),
        "{stdout}"
    );
    assert!(
        stdout.contains("mode: offline (engine 4.1.3, 42 standard rules"),
        "{stdout}"
    );
}

/// A key present without `--offline` keeps the online path: no silent switch.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[tokio::test]
async fn a_key_without_offline_stays_online_and_says_so() {
    let server = mock_backend(check_body(&["ALLOWED"]), "raw").await;
    let out = vericto()
        .args(["check", "-", "--format", "json"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .write_stdin("DELETE FROM users;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["mode"], "online");
    assert_eq!(v["engine_version"], serde_json::Value::Null);
    assert!(!server.received_requests().await.unwrap().is_empty());
}

#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn offline_json_names_mode_engine_and_ruleset() {
    let out = vericto()
        .args(["check", "--offline", "--format", "json", "-"])
        .write_stdin("DROP TABLE users;")
        .output()
        .unwrap();
    // DROP TABLE is FLAGGED in CI (schema-migration cap), so the default
    // --fail-on block passes.
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["mode"], "offline");
    assert_eq!(v["engine_version"], "4.1.3");
    assert_eq!(v["summary"]["ruleset_version"], "standard@engine-4.1.3");
    assert_eq!(v["queries"][0]["status"], "FLAGGED");
    assert_eq!(v["queries"][0]["rule_code"], "VERICTO-010");
}

/// One `--offline` run of `sql` from stdin in `format`: (exit code, stdout).
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
fn offline_run(format: &str, sql: &str) -> (Option<i32>, String) {
    let out = vericto()
        .args(["check", "--offline", "--no-color", "--format", format, "-"])
        .write_stdin(sql.to_string())
        .output()
        .unwrap();
    (out.status.code(), stdout_of(&out))
}

/// Every output format states the mode, the engine version and the ruleset
/// version.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn every_offline_format_names_mode_engine_and_ruleset() {
    let sql = "DELETE FROM users;";
    let (_, text) = offline_run("text", sql);
    assert!(
        text.contains(
            "(ruleset standard@engine-4.1.3 · mode: offline (engine 4.1.3, 42 standard rules"
        ),
        "{text}"
    );
    let (_, json) = offline_run("json", sql);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        (
            &v["mode"],
            &v["engine_version"],
            &v["summary"]["ruleset_version"]
        ),
        (
            &serde_json::json!("offline"),
            &serde_json::json!("4.1.3"),
            &serde_json::json!("standard@engine-4.1.3")
        )
    );
    let (_, sarif) = offline_run("sarif", sql);
    let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let props = &v["runs"][0]["properties"];
    assert_eq!(props["mode"], "offline");
    assert_eq!(props["engine_version"], "4.1.3");
    assert_eq!(props["ruleset_version"], "standard@engine-4.1.3");
    for (format, field) in [
        ("gitlab-codequality", "/0/description"),
        ("gitlab-sast", "/vulnerabilities/0/message"),
    ] {
        let (_, out) = offline_run(format, sql);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let msg = v
            .pointer(field)
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        assert!(
            msg.contains("mode: offline (engine 4.1.3")
                && msg.contains("ruleset standard@engine-4.1.3"),
            "{format}: {v}"
        );
    }
}

/// The strongest action decides, not the engine's severity-first winner: a
/// capped DROP TABLE (Critical, FLAG) must not hide the WHERE-less UPDATE
/// (Critical, BLOCK) after it. Every format reports BLOCKED and the run fails.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn offline_strongest_action_blocks_in_every_format() {
    let sql = "DROP TABLE a; UPDATE accounts SET balance = 0;";
    let (code, text) = offline_run("text", sql);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("BLOCKED <stdin>  VERICTO-030 critical"),
        "{text}"
    );
    assert!(text.contains("1 blocked · 0 allowed · 0 flagged"), "{text}");

    let (code, json) = offline_run("json", sql);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["queries"][0]["status"], "BLOCKED");
    assert_eq!(v["queries"][0]["action"], "block");
    assert_eq!(v["queries"][0]["rule_code"], "VERICTO-030");
    assert_eq!(v["summary"]["blocked"], 1);
    assert_eq!(v["summary"]["flagged"], 0);
    assert_eq!(v["exit_code"], 1);

    let (code, sarif) = offline_run("sarif", sql);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let r = &v["runs"][0]["results"][0];
    assert_eq!(r["ruleId"], "VERICTO-030");
    assert_eq!(r["level"], "error");

    let (code, cq) = offline_run("gitlab-codequality", sql);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(&cq).unwrap();
    assert_eq!(v.as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(v[0]["check_name"], "VERICTO-030");
    assert_eq!(v[0]["severity"], "blocker");

    let (code, sast) = offline_run("gitlab-sast", sql);
    assert_eq!(code, Some(1));
    let v: serde_json::Value = serde_json::from_str(&sast).unwrap();
    assert_eq!(v["vulnerabilities"][0]["name"], "VERICTO-030");
    assert_eq!(v["vulnerabilities"][0]["severity"], "Critical");

    // From a file too, and with --fail-on block named explicitly.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.sql");
    std::fs::write(&path, sql).unwrap();
    vericto()
        .args(["check", "--offline", "--quiet", "--fail-on", "block"])
        .arg(&path)
        .assert()
        .code(1);
}

/// `VERICTO_OFFLINE=1` is the same as `--offline`, also in CI with a key set.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn vericto_offline_env_selects_offline_mode() {
    let out = vericto()
        .args(["check", "--format", "json", "-"])
        .env("VERICTO_OFFLINE", "1")
        .env("CI", "true")
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .write_stdin("DELETE FROM users;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr_of(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["mode"], "offline");
    // A falsey value leaves it off: in CI without a key, exit 3 as before.
    vericto()
        .args(["check", "-", "--quiet"])
        .env("VERICTO_OFFLINE", "0")
        .env("CI", "true")
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .write_stdin("DELETE FROM users;")
        .assert()
        .code(3);
}

/// What an env-backed boolean reads each value as; `None` is a usage error.
const ENV_BOOL_CASES: [(&str, Option<bool>); 8] = [
    ("1", Some(true)),
    ("0", Some(false)),
    ("TRUE", Some(true)),
    ("yes", Some(true)),
    ("on", Some(true)),
    (" off ", Some(false)),
    ("", Some(false)),
    ("maybe", None),
];

/// `VERICTO_OFFLINE`: on selects offline mode (a build without the engine
/// exits 2 and says so); off and empty are the same as unset, so in CI with no
/// key the run is exit 3; anything else is exit 2 naming the variable.
#[test]
fn vericto_offline_env_reads_boolish_values() {
    let engine = cfg!(all(
        feature = "offline",
        any(not(windows), vericto_windows_offline)
    ));
    for (value, want) in ENV_BOOL_CASES {
        let out = vericto()
            .args(["check", "--format", "json", "-"])
            .env("VERICTO_OFFLINE", value)
            .env("CI", "true")
            .env("VERICTO_API_URL", "http://127.0.0.1:1")
            .write_stdin("DELETE FROM users;")
            .output()
            .unwrap();
        let err = stderr_of(&out);
        match want {
            Some(true) if engine => {
                assert_eq!(out.status.code(), Some(1), "{value:?}: {err}");
                let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                assert_eq!(v["mode"], "offline", "{value:?}");
            }
            Some(true) => {
                assert_eq!(out.status.code(), Some(2), "{value:?}: {err}");
                assert!(err.contains("online mode"), "{value:?}: {err}");
            }
            Some(false) => assert_eq!(out.status.code(), Some(3), "{value:?}: {err}"),
            None => {
                assert_eq!(out.status.code(), Some(2), "{value:?}: {err}");
                assert!(
                    err.contains("invalid value 'maybe' for VERICTO_OFFLINE"),
                    "{err}"
                );
            }
        }
    }
}

/// `VERICTO_ALLOW_UNSANITIZED` reads the same values in `check`, `baseline`
/// and `baseline prune`. With `/ci/config` unreadable, on sends the SQL as-is
/// (exit 0); off and empty are the same as unset and fail closed (exit 4);
/// anything else is exit 2 naming the variable.
#[tokio::test]
async fn vericto_allow_unsanitized_env_reads_boolish_values() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/ci/config"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/ci/check-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(check_body(&["BLOCKED"])))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("s.sql");
    std::fs::write(&sql, "DELETE FROM users;").unwrap();
    let sql = sql.to_str().unwrap();
    let recorded = dir.path().join("recorded.json");
    let recorded = recorded.to_str().unwrap();
    let out = dir.path().join("out.json");
    let out = out.to_str().unwrap();
    // A baseline with the finding in it: `baseline prune` returns early on an
    // empty one, and `check --baseline` passes with it.
    vericto()
        .args(["baseline", sql, "--out", recorded, "--allow-unsanitized"])
        .env("VERICTO_API_KEY", "vtro_k")
        .env("VERICTO_API_URL", server.uri())
        .assert()
        .code(0);

    let runs: [&[&str]; 3] = [
        &["check", sql, "--quiet", "--baseline", recorded],
        &["baseline", sql, "--out", out],
        &["baseline", "prune", sql, "--file", recorded, "--dry-run"],
    ];
    for args in runs {
        for (value, want) in ENV_BOOL_CASES {
            let run = vericto()
                .args(args)
                .env("VERICTO_ALLOW_UNSANITIZED", value)
                .env("VERICTO_API_KEY", "vtro_k")
                .env("VERICTO_API_URL", server.uri())
                .output()
                .unwrap();
            let err = stderr_of(&run);
            let code = match want {
                Some(true) => 0,
                Some(false) => 4,
                None => 2,
            };
            assert_eq!(run.status.code(), Some(code), "{args:?} {value:?}: {err}");
            if want.is_none() {
                assert!(
                    err.contains("invalid value 'maybe' for VERICTO_ALLOW_UNSANITIZED"),
                    "{args:?}: {err}"
                );
            }
        }
    }
}

/// In CI a run with no credential stays exit 3 and points at --offline.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn no_credential_in_ci_stays_exit_3_with_a_hint() {
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "TF_BUILD"] {
        let out = vericto()
            .args(["check", "-"])
            .env(var, "true")
            .env("VERICTO_API_URL", "http://127.0.0.1:1")
            .write_stdin("DELETE FROM users;")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{var}: {}", stderr_of(&out));
        assert!(stderr_of(&out).contains("pass --offline"), "{var}");
        assert!(out.stdout.is_empty(), "{var}: no verdict without a mode");
    }
}

/// Deep nesting is refused by the engine as a PARSE_ERROR, not a crash, and
/// the deepest nesting it accepts parses on the main thread. This is what the
/// windows-offline CI job checks against Windows' 1 MiB main-thread stack.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn offline_deep_nesting_does_not_crash() {
    let bomb = format!("SELECT 1 WHERE {}TRUE;", "NOT ".repeat(2000));
    let (code, json) = offline_run("json", &bomb);
    assert_eq!(code, Some(0), "{json}");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["queries"][0]["status"], "PARSE_ERROR");
    // The engine's limit is 200 levels.
    let deep = format!("SELECT {}1{};", "(".repeat(199), ")".repeat(199));
    let (code, json) = offline_run("json", &deep);
    assert_eq!(code, Some(0), "{json}");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_ne!(v["queries"][0]["status"], serde_json::Value::Null);
}

/// A committed `.vericto.toml` cannot turn offline mode on.
#[test]
fn vericto_toml_cannot_enable_offline_mode() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".vericto.toml"), "offline = true\n").unwrap();
    let out = vericto()
        .current_dir(dir.path())
        .args(["check", "--sql", "DELETE FROM users"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
    assert!(
        stderr_of(&out).contains(".vericto.toml must not set offline"),
        "{}",
        stderr_of(&out)
    );
}

/// Without the engine (the Windows build, or `--no-default-features`),
/// `--offline` and `VERICTO_OFFLINE=1` exit 2 with a clear message, and a run
/// without credentials never goes offline on its own.
#[cfg(not(all(feature = "offline", any(not(windows), vericto_windows_offline))))]
#[test]
fn offline_without_the_engine_exits_2() {
    let expected = if cfg!(windows) {
        "offline mode is not available on Windows yet"
    } else {
        "compiled without the `offline` feature"
    };
    for env in [None, Some(("VERICTO_OFFLINE", "1"))] {
        let mut cmd = vericto();
        cmd.args(["check", "-"]);
        match env {
            Some((k, v)) => cmd.env(k, v),
            None => cmd.arg("--offline"),
        };
        let out = cmd.write_stdin("DELETE FROM users;").output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{}", stderr_of(&out));
        let err = stderr_of(&out);
        assert!(
            err.contains(expected) && err.contains("online mode"),
            "{err}"
        );
    }
    let out = vericto()
        .args(["check", "-"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .write_stdin("SELECT 1;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", stderr_of(&out));
    assert!(
        !stderr_of(&out).contains("--offline"),
        "{}",
        stderr_of(&out)
    );
}

#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn offline_honors_fail_on_and_dialect() {
    let run = |args: &[&str], sql: &str| {
        vericto()
            .args(["check", "--offline", "--quiet"])
            .args(args)
            .arg("-")
            .write_stdin(sql.to_string())
            .output()
            .unwrap()
            .status
            .code()
    };
    // SELECT without LIMIT: FLAGGED (Medium).
    assert_eq!(run(&[], "SELECT * FROM t;"), Some(0));
    assert_eq!(run(&["--fail-on", "flag"], "SELECT * FROM t;"), Some(1));
    // INSERT without columns: MONITORED (Low).
    assert_eq!(
        run(&["--fail-on", "flag"], "INSERT INTO t VALUES (1);"),
        Some(0)
    );
    assert_eq!(
        run(&["--fail-on", "any"], "INSERT INTO t VALUES (1);"),
        Some(1)
    );
    // Backticks parse as MySQL only; a PARSE_ERROR does not fail the run.
    assert_eq!(run(&["--dialect", "mysql"], "DELETE FROM `t`;"), Some(1));
    assert_eq!(run(&["--dialect", "postgres"], "DELETE FROM `t`;"), Some(0));
    assert_eq!(run(&["--monitor"], "DELETE FROM t;"), Some(0));
    // Unknown dialect: usage error.
    assert_eq!(run(&["--dialect", "db2"], "SELECT 1;"), Some(2));
}

/// Inline suppression and the baseline are local, so they work offline.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn offline_honors_inline_suppression() {
    let dir = tempfile::tempdir().unwrap();
    let sql = dir.path().join("m.sql");
    std::fs::write(
        &sql,
        "DELETE FROM users; -- vericto:ignore[VERICTO-001] one-off backfill\n",
    )
    .unwrap();
    vericto()
        .args(["check", "--offline", "--quiet", sql.to_str().unwrap()])
        .assert()
        .code(0);
}

/// Options that need a workspace are refused, with exit 2 and a pointer to
/// online mode, never silently ignored.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn offline_refuses_workspace_options() {
    for (args, flag) in [
        (&["--receipt", "r.json"][..], "--receipt"),
        (&["--oidc"][..], "--oidc"),
        (&["--allow-degraded", "outage"][..], "--allow-degraded"),
        (&["--allow-unsanitized"][..], "--allow-unsanitized"),
    ] {
        let out = vericto()
            .args(["check", "--offline"])
            .args(args)
            .arg("-")
            .write_stdin("SELECT 1;")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{flag}: {}", stderr_of(&out));
        let err = stderr_of(&out);
        assert!(
            err.contains(&format!("{flag} needs online mode")) && err.contains("Drop --offline"),
            "{err}"
        );
    }
}

/// Asking for something online-only keeps a credential-less run from going
/// offline on its own: it fails as before (exit 3), it does not drop the flag.
#[cfg(all(feature = "offline", any(not(windows), vericto_windows_offline)))]
#[test]
fn online_only_option_without_credentials_does_not_go_offline() {
    let out = vericto()
        .args(["check", "--receipt", "r.json", "-"])
        .env("VERICTO_API_URL", "http://127.0.0.1:1")
        .write_stdin("SELECT 1;")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", stderr_of(&out));
}
