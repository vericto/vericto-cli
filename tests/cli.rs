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

#[test]
fn login_logout_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    // Isolate the config dir via XDG_CONFIG_HOME.
    vericto()
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
