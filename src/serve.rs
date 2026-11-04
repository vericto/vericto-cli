// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto serve --stdio` (DESIGN §17, `docs/serve-protocol.md`): a
//! long-lived local evaluation server for the SDKs' offline mode.
//!
//! The SDKs are Apache-2.0 and the engine is AGPL-3.0-only, so an SDK does not
//! link the engine: it spawns this binary once and talks to it over JSON Lines
//! on stdin/stdout. Every `check` goes through `offline::check_with`, the code
//! path of `vericto check --offline`, and its `result` is the document
//! `--format json` prints (`output::json_document`), so the two cannot drift.
//!
//! Properties the SDKs rely on:
//! - stdout carries protocol lines only: the hello line, then one response
//!   per request line. Diagnostics go to stderr, and never contain SQL.
//! - Requests are read and answered one at a time, in order. Memory is bounded
//!   by `--max-line-bytes` (one line buffer, no queue): a client that pipelines
//!   is held back by the pipe, not buffered without limit.
//! - No network, no account, no config file, no environment variable read:
//!   the verdict depends on the request and the embedded engine only.

use std::io::{self, BufRead, BufReader, Write};
use std::panic::{self, AssertUnwindSafe};
use std::process::ExitCode;

use serde_json::{json, Map, Value};

use crate::api::QueryInput;
use crate::offline::{self, OfflineError, Profile};
use crate::output;

/// Protocol version announced in the hello line. A change a v1 client could
/// misread (a removed or retyped field, out-of-order responses) bumps it;
/// added fields and ops do not.
pub const PROTOCOL: u32 = 1;

/// Default `--max-line-bytes`: 1 MiB per request line.
pub const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;

/// Read buffer for stdin.
const READ_BUFFER: usize = 64 * 1024;

/// Error codes of a failed response (`error.code`).
mod code {
    pub const INVALID_REQUEST: &str = "INVALID_REQUEST";
    pub const UNSUPPORTED_DIALECT: &str = "UNSUPPORTED_DIALECT";
    pub const TOO_LARGE: &str = "TOO_LARGE";
    pub const INTERNAL: &str = "INTERNAL";
}

/// The hello line, written once before any request is read.
pub fn hello(max_line_bytes: usize) -> Value {
    json!({
        "type": "hello",
        "protocol": PROTOCOL,
        "cli_version": env!("CARGO_PKG_VERSION"),
        "engine_version": offline::ENGINE_VERSION,
        "profiles": [Profile::Runtime.as_str(), Profile::Ci.as_str()],
        "max_line_bytes": max_line_bytes,
    })
}

/// What a request line asks the loop to do after answering it.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    Continue,
    Exit,
}

fn ok(id: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("id".into(), Value::String(id.to_string()));
    m.insert("ok".into(), Value::Bool(true));
    m
}

/// A failed response. `id` is `null` when the request had no usable one (a
/// malformed or oversized line); responses are in request order, so the
/// client can still tell which line it answers.
fn error(id: Option<&str>, code: &str, message: impl Into<String>) -> Value {
    json!({
        "id": id,
        "ok": false,
        "error": { "code": code, "message": message.into() },
    })
}

/// Answers one request line (without its newline). `None` means nothing to
/// write (a blank line, or a `shutdown` without an id).
fn handle_line(line: &[u8]) -> (Option<Value>, Next) {
    let text = match std::str::from_utf8(line) {
        Ok(t) => t.trim(),
        Err(_) => {
            return (
                Some(error(
                    None,
                    code::INVALID_REQUEST,
                    "request is not valid UTF-8",
                )),
                Next::Continue,
            )
        }
    };
    if text.is_empty() {
        return (None, Next::Continue);
    }
    let req: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            // serde_json's message names a line/column, never the input.
            let msg = format!("malformed JSON: {e}");
            return (
                Some(error(None, code::INVALID_REQUEST, msg)),
                Next::Continue,
            );
        }
    };
    let Some(obj) = req.as_object() else {
        return (
            Some(error(
                None,
                code::INVALID_REQUEST,
                "a request is a JSON object",
            )),
            Next::Continue,
        );
    };
    let id = match obj.get("id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return (
                Some(error(None, code::INVALID_REQUEST, "`id` must be a string")),
                Next::Continue,
            )
        }
    };
    let op = match obj.get("op") {
        Some(Value::String(s)) => s.as_str(),
        None | Some(Value::Null) => {
            return (
                Some(error(id, code::INVALID_REQUEST, "missing `op`")),
                Next::Continue,
            )
        }
        Some(_) => {
            return (
                Some(error(id, code::INVALID_REQUEST, "`op` must be a string")),
                Next::Continue,
            )
        }
    };
    match op {
        "shutdown" => (id.map(|id| Value::Object(ok(id))), Next::Exit),
        "ping" | "check" => {
            let Some(id) = id else {
                return (
                    Some(error(
                        None,
                        code::INVALID_REQUEST,
                        format!("`{op}` needs a string `id`"),
                    )),
                    Next::Continue,
                );
            };
            if op == "ping" {
                return (Some(Value::Object(ok(id))), Next::Continue);
            }
            (Some(check(id, obj)), Next::Continue)
        }
        other => {
            // The op is echoed back only when it is short and printable, so a
            // response never carries a long or binary field verbatim.
            let shown: String = other.chars().take(32).filter(|c| !c.is_control()).collect();
            (
                Some(error(
                    id,
                    code::INVALID_REQUEST,
                    format!("unknown op '{shown}' (use check, ping or shutdown)"),
                )),
                Next::Continue,
            )
        }
    }
}

/// An optional string field: absent or `null` gives `default`.
fn str_field<'a>(
    obj: &'a Map<String, Value>,
    name: &str,
    default: &'a str,
) -> Result<&'a str, String> {
    match obj.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::String(s)) => Ok(s.as_str()),
        Some(_) => Err(format!("`{name}` must be a string")),
    }
}

/// `op: check`: evaluates `sql` under `profile` with `offline::check_with`,
/// as one input (one result for the whole text, its strongest finding, like a
/// file given to `check --offline`).
fn check(id: &str, obj: &Map<String, Value>) -> Value {
    let sql = match obj.get("sql") {
        Some(Value::String(s)) => s.as_str(),
        None | Some(Value::Null) => {
            return error(Some(id), code::INVALID_REQUEST, "missing `sql`");
        }
        Some(_) => return error(Some(id), code::INVALID_REQUEST, "`sql` must be a string"),
    };
    if sql.trim().is_empty() {
        return error(Some(id), code::INVALID_REQUEST, "`sql` is empty");
    }
    let dialect = match str_field(obj, "dialect", "postgres") {
        Ok(d) => d,
        Err(m) => return error(Some(id), code::INVALID_REQUEST, m),
    };
    let profile = match str_field(obj, "profile", Profile::Runtime.as_str()) {
        Ok(p) => match Profile::parse(p) {
            Some(p) => p,
            None => {
                return error(
                    Some(id),
                    code::INVALID_REQUEST,
                    "unknown `profile` (use runtime or ci)",
                )
            }
        },
        Err(m) => return error(Some(id), code::INVALID_REQUEST, m),
    };
    let queries = [QueryInput {
        line: 1,
        sql: sql.to_string(),
    }];
    // A panic in the engine answers this request with INTERNAL and keeps the
    // server running; the panic hook installed by `run` logs no payload.
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| {
        offline::check_with(&queries, dialect, profile)
    }));
    match outcome {
        Ok(Ok(resp)) => {
            let mut m = ok(id);
            m.insert("result".into(), output::json_document(&resp));
            Value::Object(m)
        }
        Ok(Err(e @ OfflineError::Dialect(_))) => {
            error(Some(id), code::UNSUPPORTED_DIALECT, e.to_string())
        }
        Ok(Err(e @ OfflineError::Unavailable)) => error(Some(id), code::INTERNAL, e.to_string()),
        Err(_) => error(
            Some(id),
            code::INTERNAL,
            "internal error while evaluating this request",
        ),
    }
}

/// One line read from the client.
#[derive(Debug, PartialEq, Eq)]
enum Line {
    /// A complete line is in the buffer (the last one may lack its newline).
    Complete,
    /// The line was longer than the limit; it was consumed and dropped.
    TooLarge,
    /// End of input.
    Eof,
}

/// Reads one line into `buf` (cleared first), keeping at most `max` bytes: a
/// longer line is read to its end and dropped, so memory stays bounded and
/// the next line is read normally. A trailing `\r` counts toward the limit
/// and is trimmed with the rest of the whitespace later.
fn read_line(reader: &mut impl BufRead, max: usize, buf: &mut Vec<u8>) -> io::Result<Line> {
    buf.clear();
    let mut over = false;
    let mut seen = false;
    loop {
        let avail = match reader.fill_buf() {
            Ok(a) => a,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if avail.is_empty() {
            return Ok(match (seen, over) {
                (false, _) => Line::Eof,
                (true, true) => Line::TooLarge,
                (true, false) => Line::Complete,
            });
        }
        seen = true;
        let (chunk, done) = match avail.iter().position(|&b| b == b'\n') {
            Some(i) => (&avail[..i], Some(i + 1)),
            None => (avail, None),
        };
        if !over {
            if buf.len() + chunk.len() <= max {
                buf.extend_from_slice(chunk);
            } else {
                over = true;
                buf.clear();
            }
        }
        let used = done.unwrap_or(avail.len());
        reader.consume(used);
        if done.is_some() {
            return Ok(if over { Line::TooLarge } else { Line::Complete });
        }
    }
}

fn write_line(out: &mut impl Write, v: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, v)?;
    out.write_all(b"\n")
}

/// The request loop over any reader and writer (the tests drive it in
/// memory). Returns when the input ends or a `shutdown` arrives.
pub fn serve<R: io::Read, W: Write>(input: R, output: W, max_line_bytes: usize) -> io::Result<()> {
    let mut reader = BufReader::with_capacity(READ_BUFFER, input);
    let mut out = io::BufWriter::new(output);
    write_line(&mut out, &hello(max_line_bytes))?;
    out.flush()?;
    let mut buf = Vec::new();
    loop {
        let (response, next) = match read_line(&mut reader, max_line_bytes, &mut buf)? {
            Line::Eof => break,
            Line::TooLarge => (
                Some(error(
                    None,
                    code::TOO_LARGE,
                    format!("request line is over {max_line_bytes} bytes (--max-line-bytes)"),
                )),
                Next::Continue,
            ),
            Line::Complete => handle_line(&buf),
        };
        if let Some(r) = response {
            write_line(&mut out, &r)?;
        }
        if next == Next::Exit {
            break;
        }
        // Flush once no further complete request is already buffered, so a
        // pipelined batch is answered in a few writes and a lone request at
        // once.
        if !reader.buffer().contains(&b'\n') {
            out.flush()?;
        }
        // Keep the line buffer from holding on to a large allocation.
        if buf.capacity() > READ_BUFFER {
            buf = Vec::new();
        }
    }
    out.flush()
}

/// `vericto serve --stdio` on the process's stdin and stdout. Exit 0 on EOF,
/// on `shutdown` and when the client closes stdout; 2 on any other I/O error.
pub fn run(max_line_bytes: usize) -> ExitCode {
    // A panic message could quote the SQL being evaluated; log where, not what.
    panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!(" at {}:{}", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!("vericto serve: internal error{at}; the request was answered with INTERNAL");
    }));
    let stdin = io::stdin();
    let stdout = io::stdout();
    match serve(stdin.lock(), stdout.lock(), max_line_bytes) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vericto serve: I/O error: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_lines(input: &str, max: usize) -> Vec<Value> {
        let mut out = Vec::new();
        serve(input.as_bytes(), &mut out, max).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn hello_comes_first_and_eof_ends() {
        let v = run_lines("", DEFAULT_MAX_LINE_BYTES);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["type"], "hello");
        assert_eq!(v[0]["protocol"], 1);
        assert_eq!(v[0]["engine_version"], offline::ENGINE_VERSION);
        assert_eq!(v[0]["profiles"], json!(["runtime", "ci"]));
    }

    #[test]
    fn read_line_bounds_and_recovers() {
        let mut r = BufReader::with_capacity(4, "abc\nabcdefgh\nxy\r\nlast".as_bytes());
        let mut buf = Vec::new();
        assert_eq!(read_line(&mut r, 5, &mut buf).unwrap(), Line::Complete);
        assert_eq!(buf, b"abc");
        assert_eq!(read_line(&mut r, 5, &mut buf).unwrap(), Line::TooLarge);
        assert!(buf.is_empty());
        assert_eq!(read_line(&mut r, 5, &mut buf).unwrap(), Line::Complete);
        assert_eq!(buf, b"xy\r");
        assert_eq!(read_line(&mut r, 5, &mut buf).unwrap(), Line::Complete);
        assert_eq!(buf, b"last");
        assert_eq!(read_line(&mut r, 5, &mut buf).unwrap(), Line::Eof);
    }

    #[test]
    fn errors_keep_the_server_running() {
        let input = concat!(
            "not json\n",
            "\n",
            "[1]\n",
            "{\"id\":7,\"op\":\"ping\"}\n",
            "{\"id\":\"a\"}\n",
            "{\"id\":\"b\",\"op\":\"nope\"}\n",
            "{\"id\":\"c\",\"op\":\"check\"}\n",
            "{\"id\":\"d\",\"op\":\"check\",\"sql\":\"  \"}\n",
            "{\"id\":\"e\",\"op\":\"check\",\"sql\":\"SELECT 1\",\"dialect\":\"db2\"}\n",
            "{\"id\":\"f\",\"op\":\"check\",\"sql\":\"SELECT 1\",\"profile\":\"prod\"}\n",
            "{\"op\":\"ping\"}\n",
            "{\"id\":\"z\",\"op\":\"ping\"}\n",
        );
        let v = run_lines(input, DEFAULT_MAX_LINE_BYTES);
        let codes: Vec<(Value, Value)> = v[1..]
            .iter()
            .map(|r| (r["id"].clone(), r["error"]["code"].clone()))
            .collect();
        assert_eq!(
            codes,
            vec![
                (Value::Null, json!("INVALID_REQUEST")),
                (Value::Null, json!("INVALID_REQUEST")),
                (Value::Null, json!("INVALID_REQUEST")),
                (json!("a"), json!("INVALID_REQUEST")),
                (json!("b"), json!("INVALID_REQUEST")),
                (json!("c"), json!("INVALID_REQUEST")),
                (json!("d"), json!("INVALID_REQUEST")),
                (json!("e"), json!("UNSUPPORTED_DIALECT")),
                (json!("f"), json!("INVALID_REQUEST")),
                (Value::Null, json!("INVALID_REQUEST")),
                (json!("z"), Value::Null),
            ]
        );
        assert_eq!(v.last().unwrap()["ok"], true);
    }

    #[test]
    fn shutdown_with_and_without_id() {
        let v = run_lines(
            "{\"id\":\"s\",\"op\":\"shutdown\"}\n{\"id\":\"x\",\"op\":\"ping\"}\n",
            1024,
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[1], json!({"id": "s", "ok": true}));
        let v = run_lines(
            "{\"op\":\"shutdown\"}\n{\"id\":\"x\",\"op\":\"ping\"}\n",
            1024,
        );
        assert_eq!(v.len(), 1);
    }

    /// The `result` of a check is the `--format json` document of the same
    /// input checked offline under the same profile.
    #[test]
    fn result_is_the_check_json_document() {
        let v = run_lines(
            "{\"id\":\"1\",\"op\":\"check\",\"sql\":\"DROP TABLE users\",\"profile\":\"ci\"}\n",
            1024,
        );
        let q = [QueryInput {
            line: 1,
            sql: "DROP TABLE users".into(),
        }];
        let doc = output::json_document(&offline::check(&q, "postgres").unwrap());
        assert_eq!(v[1]["result"], doc);
    }
}
