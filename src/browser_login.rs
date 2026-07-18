//! Browser-based login (§6, "verified login") — the interactive replacement
//! for pasting a `vtro_...` key by hand into `vericto login`.
//!
//! `--api-key`/env/prompted-secret login stays available for scripts and
//! headless environments; this module backs the *default* `vericto login`
//! (no `--api-key`, no `--oidc`) for a developer at a keyboard with a browser.
//!
//! Flow (loopback + one-time code — the same pattern `gcloud auth login` /
//! `aws sso login` / `gh auth login` use for local human login):
//!   1. `start_loopback_server` binds `127.0.0.1:0` (OS-assigned free port) and
//!      generates a random `state`.
//!   2. The caller opens the browser at
//!      `{app_url}/cli-auth?state=<state>&port=<port>`. The dashboard page is
//!      already authenticated via the user's normal session — no credential
//!      is typed here.
//!   3. The user picks a workspace and approves; the dashboard mints a scoped
//!      key server-side and does a top-level navigation back to
//!      `http://127.0.0.1:<port>/callback?state=...&code=...` — a one-time
//!      code, never the key itself.
//!   4. `wait_for_callback` accepts that single connection, parses the
//!      request line, and returns the `code` — but only after confirming
//!      `state` matches what THIS process generated (§ below on why that
//!      check lives here and nowhere else).
//!   5. The caller exchanges `code` for the actual key via
//!      `api::cli_login_exchange` (server-to-server, no browser involved).
//!
//! `state`'s job is narrower than it looks: it does not defend against a
//! malicious dashboard (the backend already scopes/expires the minted key,
//! and the code is single-use — see services/cli-login.ts) — it defends
//! against a *different* local process on this same machine hitting this
//! CLI's loopback port with an unrelated code while this `login` run is
//! waiting. The backend intentionally never inspects `state` (standard OAuth
//! convention); checking it is entirely this module's responsibility.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// How long `wait_for_callback` blocks for the browser round-trip before
/// giving up. Generous for a human clicking through a login page, including
/// an SSO redirect, but bounded so a `vericto login` a developer walks away
/// from doesn't hang the terminal forever.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Generates a random `state` value: 32 bytes from the OS CSPRNG, hex-encoded
/// (64 chars). Only needs to be unguessable and unique per `login` run — see
/// the module doc for what it does and does not defend against.
pub fn generate_state() -> Result<String, String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| format!("could not read OS randomness: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// A bound loopback listener, ready to accept the browser's callback. Split
/// from `wait_for_callback` so the caller can read `port` (to build the
/// browser URL) before blocking on the accept.
pub struct LoopbackServer {
    listener: TcpListener,
}

impl LoopbackServer {
    /// Binds `127.0.0.1:0` — the OS assigns a free ephemeral port, so this
    /// never collides with another `vericto login` running concurrently (or
    /// anything else on the machine).
    pub fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(Self { listener })
    }

    pub fn port(&self) -> std::io::Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }

    /// Blocks for a single browser callback request, validates its `state`
    /// against `expected_state`, and returns the `code` query parameter.
    /// Consumes `self` — this server exists for exactly one login attempt.
    pub fn wait_for_callback(self, expected_state: &str) -> Result<String, String> {
        self.listener
            .set_nonblocking(false)
            .map_err(|e| format!("loopback listener error: {e}"))?;

        // A single accept with an overall deadline: reject the whole wait past
        // CALLBACK_TIMEOUT rather than retrying forever on a slow/absent browser.
        let deadline = std::time::Instant::now() + CALLBACK_TIMEOUT;
        loop {
            // std's TcpListener has no accept-with-timeout, so poll accept
            // readiness is approximated by a short per-attempt read timeout on
            // the accepted stream instead — the accept itself is what actually
            // blocks the browser round-trip, which is the real wait here.
            let (mut stream, _addr) = self
                .listener
                .accept()
                .map_err(|e| format!("loopback accept failed: {e}"))?;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

            match handle_one_connection(&mut stream, expected_state) {
                Ok(Some(code)) => return Ok(code),
                Ok(None) => {
                    // A request that wasn't the callback we're waiting for
                    // (state mismatch, malformed, or a browser preflight-ish
                    // stray request e.g. /favicon.ico) — already responded to
                    // inside handle_one_connection. Keep waiting for the real
                    // callback, but still bounded by the overall deadline.
                    if std::time::Instant::now() >= deadline {
                        return Err(
                            "timed out waiting for the browser to complete login".to_string()
                        );
                    }
                    continue;
                }
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(
                            "timed out waiting for the browser to complete login".to_string()
                        );
                    }
                    eprintln!("note: loopback callback error (retrying): {e}");
                    continue;
                }
            }
        }
    }
}

/// Reads one HTTP request off `stream`, and if it's a `GET /callback` with a
/// matching `state`, writes a human-friendly HTML response and returns the
/// `code`. Any other request (wrong path, missing/mismatched state, a stray
/// `/favicon.ico`) gets a plain response and `Ok(None)` — the caller keeps
/// listening for the real callback.
fn handle_one_connection(
    stream: &mut TcpStream,
    expected_state: &str,
) -> Result<Option<String>, String> {
    let request_line = read_request_line(stream)?;
    let Some(path_and_query) = parse_get_target(&request_line) else {
        write_response(stream, 400, "Bad request.");
        return Ok(None);
    };

    let Some((path, query)) = path_and_query.split_once('?') else {
        write_response(stream, 404, "Not found.");
        return Ok(None);
    };
    if path != "/callback" {
        write_response(stream, 404, "Not found.");
        return Ok(None);
    }

    let params = parse_query(query);
    let (Some(state), Some(code)) = (params.get("state"), params.get("code")) else {
        write_response(
            stream,
            400,
            "Missing state or code — this link looks incomplete.",
        );
        return Ok(None);
    };

    if state != expected_state {
        // Deliberately vague to the browser (no reflection of the attempted
        // value) — this is either a stray/replayed hit or a different login
        // attempt's callback landing on the wrong port.
        write_response(
            stream,
            400,
            "This login link doesn't match the request that opened your browser. \
             Close this tab and run `vericto login` again.",
        );
        return Ok(None);
    }

    write_response(
        stream,
        200,
        "Login successful — you can close this tab and return to your terminal.",
    );
    Ok(Some(code.clone()))
}

/// Reads and returns just the HTTP request line (`GET /path HTTP/1.1`),
/// discarding headers/body — this server never needs them. Bounded read size
/// so a misbehaving/hostile connection can't make this allocate unbounded.
fn read_request_line(stream: &mut TcpStream) -> Result<String, String> {
    let mut buf = Vec::with_capacity(2048);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            return Err("request line too long".to_string());
        }
    }
    Ok(String::from_utf8_lossy(&buf)
        .trim_end_matches('\r')
        .to_string())
}

/// Extracts `/path?query` from a `GET /path?query HTTP/1.1` request line.
fn parse_get_target(request_line: &str) -> Option<String> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    if method != "GET" {
        return None;
    }
    let target = parts.next()?;
    Some(target.to_string())
}

/// Minimal `application/x-www-form-urlencoded`-style query parser: splits on
/// `&` and `=`, percent-decodes each side. Good enough for the two params
/// this server ever reads (`state`, `code`) — not a general URL library.
fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((percent_decode(k), percent_decode(v)))
        })
        .collect()
}

/// Decodes `%XX` escapes and `+` (space); the exchange code/state alphabet is
/// hex-only so in practice this is a no-op passthrough, but query params are
/// technically arbitrary, so decode properly rather than assume.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn write_response(stream: &mut TcpStream, status: u16, message: &str) {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Vericto CLI</title></head>\
         <body style=\"font-family:sans-serif;text-align:center;padding:4rem 1rem\">\
         <p>{}</p></body></html>",
        html_escape(message)
    );
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    // Best-effort: the browser already has what it needs (or the connection
    // is already gone) regardless of whether this write fully lands.
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Opens `url` in the user's default browser. Best-effort: a failure here
/// (headless box, unusual `$PATH`) is reported but never fatal — `login`
/// falls back to printing the URL for the user to open by hand.
pub fn open_browser(url: &str) -> Result<(), String> {
    let result = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).status()
    } else if cfg!(target_os = "windows") {
        // `cmd /c start "" <url>` — the empty title arg avoids `start`
        // misinterpreting a URL containing spaces/quotes as the window title.
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .status()
    } else {
        std::process::Command::new("xdg-open").arg(url).status()
    };

    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("browser launcher exited with {status}")),
        Err(e) => Err(format!("could not launch a browser: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_state_is_64_hex_chars_and_varies() {
        let a = generate_state().unwrap();
        let b = generate_state().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn parse_get_target_extracts_path_and_query() {
        assert_eq!(
            parse_get_target("GET /callback?state=abc&code=def HTTP/1.1"),
            Some("/callback?state=abc&code=def".to_string())
        );
        assert_eq!(parse_get_target("POST /callback HTTP/1.1"), None);
        assert_eq!(parse_get_target(""), None);
    }

    #[test]
    fn parse_query_decodes_pairs() {
        let params = parse_query("state=a%2Bb&code=deadbeef");
        assert_eq!(params.get("state").map(String::as_str), Some("a+b"));
        assert_eq!(params.get("code").map(String::as_str), Some("deadbeef"));
    }

    #[test]
    fn percent_decode_handles_escapes_and_plus() {
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
        // Malformed escape (not enough hex digits) is passed through literally
        // rather than panicking or truncating the string.
        assert_eq!(percent_decode("a%2"), "a%2");
    }

    #[test]
    fn loopback_server_binds_to_a_free_port() {
        let server = LoopbackServer::bind().unwrap();
        assert!(server.port().unwrap() > 0);
    }

    #[test]
    fn wait_for_callback_returns_code_on_matching_state() {
        let server = LoopbackServer::bind().unwrap();
        let port = server.port().unwrap();
        let state = "matching-state".to_string();

        let handle = std::thread::spawn(move || server.wait_for_callback(&state));

        // Give the server a moment to be in `accept()`.
        std::thread::sleep(Duration::from_millis(50));
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .write_all(
                b"GET /callback?state=matching-state&code=abc123 HTTP/1.1\r\nHost: x\r\n\r\n",
            )
            .unwrap();
        let mut buf = [0u8; 512];
        let _ = client.read(&mut buf); // drain the response so write completes

        let result = handle.join().unwrap();
        assert_eq!(result, Ok("abc123".to_string()));
    }

    #[test]
    fn wait_for_callback_ignores_mismatched_state_and_waits_for_the_real_one() {
        let server = LoopbackServer::bind().unwrap();
        let port = server.port().unwrap();
        let expected = "expected-state".to_string();

        let handle = std::thread::spawn(move || server.wait_for_callback(&expected));
        std::thread::sleep(Duration::from_millis(50));

        // First hit: wrong state — must be rejected, not accepted as the code.
        let mut bad = TcpStream::connect(("127.0.0.1", port)).unwrap();
        bad.write_all(b"GET /callback?state=wrong&code=nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut buf = [0u8; 512];
        let _ = bad.read(&mut buf);

        // Second hit: the real callback.
        let mut good = TcpStream::connect(("127.0.0.1", port)).unwrap();
        good.write_all(b"GET /callback?state=expected-state&code=real HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let _ = good.read(&mut buf);

        let result = handle.join().unwrap();
        assert_eq!(result, Ok("real".to_string()));
    }
}
