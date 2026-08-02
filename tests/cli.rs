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

fn vericto() -> Command {
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
    c
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
    // No backend needed — fails before any request.
    vericto()
        .args(["check", "-", "--quiet"])
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
    // The URL base is shown once in the header — not repeated per row.
    assert!(s.contains("https://vericto.com/docs"), "output: {s}");
    assert!(
        !s.contains("https://vericto.com/docs/enforcement"),
        "per-row URLs should be gone: {s}"
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
