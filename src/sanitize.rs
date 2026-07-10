//! Client-side literal sanitization (§6.2).
//!
//! When a workspace is in `sanitized` telemetry mode, the CLI normalizes literal
//! values to `?` placeholders *before* sending, so raw values never leave the
//! machine. This is a conservative **lexical** pass — the engine still does the
//! real multi-statement parse server-side; our only job is to strip literal
//! payloads while preserving structure the rules care about.
//!
//! What it replaces with `?`:
//!   - single-quoted string literals `'...'` (with `''` escape handling)
//!   - numeric literals (integers/decimals, incl. a leading sign after an operator)
//!
//! What it deliberately leaves intact (conservative — matches the engine's
//! stance of flagging, not rewriting, opaque blocks):
//!   - dollar-quoted blocks: `$$ ... $$` and `$tag$ ... $tag$` (PL/pgSQL bodies)
//!   - identifiers, keywords, `"quoted identifiers"`, and backtick-quoted names
//!   - comments (`-- ...`, `/* ... */`) — left as-is
//!
//! Placeholder style is **dialect-aware** so the sanitized SQL still parses:
//! Postgres/Oracle/MSSQL use numbered params (`$1, $2, …`), MySQL uses `?`.
//! (A bare `?` is invalid Postgres syntax and would make the engine fail with a
//! parse error — that's the whole reason this is dialect-aware.)
//!
//! Dialect note: MySQL also accepts double-quoted strings, but treating `"..."`
//! as a string would corrupt Postgres identifiers. We only normalize the
//! portable, unambiguous cases (`'...'` and numbers); anything dialect-specific
//! and ambiguous is left untouched rather than risk mangling structure.

/// How to render a placeholder for the given dialect.
enum Placeholder {
    /// `$1, $2, …` — Postgres (also accepted by our Oracle/MSSQL handling).
    Numbered,
    /// `?` — MySQL.
    Question,
}

fn placeholder_style(dialect: &str) -> Placeholder {
    match dialect {
        "mysql" => Placeholder::Question,
        _ => Placeholder::Numbered, // postgres, oracle, mssql, unknown → safe default
    }
}

/// Returns the SQL with string and numeric literals replaced by dialect-correct
/// placeholders (`$N` for Postgres-family, `?` for MySQL).
pub fn sanitize(sql: &str, dialect: &str) -> String {
    let style = placeholder_style(dialect);
    let mut counter: u32 = 0;
    // Emits the next placeholder token, advancing the numbered counter.
    let mut next_placeholder = |out: &mut String| match style {
        Placeholder::Question => out.push('?'),
        Placeholder::Numbered => {
            counter += 1;
            out.push('$');
            out.push_str(&counter.to_string());
        }
    };

    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut i = 0;
    let n = bytes.len();

    while i < n {
        let c = bytes[i] as char;

        // Line comment: copy verbatim to end of line.
        if c == '-' && i + 1 < n && bytes[i + 1] == b'-' {
            let start = i;
            while i < n && bytes[i] != b'\n' {
                i += 1;
            }
            out.push_str(&sql[start..i]);
            continue;
        }

        // Block comment: copy verbatim to `*/`.
        if c == '/' && i + 1 < n && bytes[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < n && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(n);
            out.push_str(&sql[start..i]);
            continue;
        }

        // Dollar-quoted block ($$...$$ or $tag$...$tag$): copy verbatim. We do
        // NOT sanitize inside — consistent with the engine's conservative stance.
        if c == '$' {
            if let Some((tag_end, tag)) = dollar_tag(bytes, i) {
                // Find the matching closing tag.
                if let Some(close) = find_from(sql, tag_end, &tag) {
                    let end = close + tag.len();
                    out.push_str(&sql[i..end]);
                    i = end;
                    continue;
                }
            }
            // Not a valid dollar-quote opener — emit and move on.
            out.push('$');
            i += 1;
            continue;
        }

        // Double-quoted identifier / backtick identifier: copy verbatim.
        if c == '"' || c == '`' {
            let quote = bytes[i];
            let start = i;
            i += 1;
            while i < n {
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push_str(&sql[start..i]);
            continue;
        }

        // Single-quoted string literal → `?`. Handles the `''` escape.
        if c == '\'' {
            i += 1;
            while i < n {
                if bytes[i] == b'\'' {
                    if i + 1 < n && bytes[i + 1] == b'\'' {
                        i += 2; // escaped quote inside the string
                        continue;
                    }
                    i += 1; // closing quote
                    break;
                }
                i += 1;
            }
            next_placeholder(&mut out);
            continue;
        }

        // Numeric literal → `?`. Only when it starts a token (prev char isn't an
        // identifier char), so we don't clobber names like `col2` or `t1`.
        if c.is_ascii_digit() && prev_is_boundary(&out) {
            i += 1;
            while i < n {
                let d = bytes[i] as char;
                if d.is_ascii_digit() || d == '.' {
                    i += 1;
                } else {
                    break;
                }
            }
            next_placeholder(&mut out);
            continue;
        }

        out.push(c);
        i += 1;
    }

    out
}

/// Whether the char just emitted allows a numeric literal to start here (i.e.
/// we're at a token boundary, not in the middle of an identifier like `col2`).
fn prev_is_boundary(out: &str) -> bool {
    match out.chars().last() {
        None => true,
        Some(p) => !(p.is_ascii_alphanumeric() || p == '_'),
    }
}

/// If `bytes[start]` begins a dollar-quote tag (`$$` or `$tag$`), returns
/// `(index_after_tag, tag_string)`. A tag body is `[A-Za-z_][A-Za-z0-9_]*`.
fn dollar_tag(bytes: &[u8], start: usize) -> Option<(usize, String)> {
    debug_assert_eq!(bytes[start], b'$');
    let mut j = start + 1;
    while j < bytes.len() {
        let b = bytes[j];
        if b == b'$' {
            // tag = bytes[start..=j]
            let tag = String::from_utf8_lossy(&bytes[start..=j]).to_string();
            return Some((j + 1, tag));
        }
        let ok = b == b'_' || b.is_ascii_alphabetic() || (j > start + 1 && b.is_ascii_digit());
        if !ok {
            return None;
        }
        j += 1;
    }
    None
}

/// Finds `needle` in `hay` starting at byte index `from`, returning its start.
fn find_from(hay: &str, from: usize, needle: &str) -> Option<usize> {
    hay.get(from..)?.find(needle).map(|rel| from + rel)
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn strips_string_literals_postgres_numbered() {
        assert_eq!(
            sanitize("SELECT * FROM users WHERE email = 'a@b.com'", "postgres"),
            "SELECT * FROM users WHERE email = $1"
        );
    }

    #[test]
    fn mysql_uses_question_mark() {
        assert_eq!(
            sanitize("SELECT * FROM users WHERE email = 'a@b.com'", "mysql"),
            "SELECT * FROM users WHERE email = ?"
        );
    }

    #[test]
    fn numbered_placeholders_increment() {
        assert_eq!(
            sanitize("WHERE a = 'x' AND b = 'y' AND c = 5", "postgres"),
            "WHERE a = $1 AND b = $2 AND c = $3"
        );
    }

    #[test]
    fn handles_escaped_quotes() {
        assert_eq!(
            sanitize("WHERE name = 'O''Brien'", "postgres"),
            "WHERE name = $1"
        );
    }

    #[test]
    fn strips_numbers_but_not_identifiers() {
        assert_eq!(
            sanitize("WHERE id = 42 AND col2 = 7", "postgres"),
            "WHERE id = $1 AND col2 = $2"
        );
    }

    #[test]
    fn leaves_dollar_quoted_blocks_intact() {
        let sql = "DO $$ BEGIN PERFORM 'secret'; END $$";
        assert_eq!(sanitize(sql, "postgres"), sql);
    }

    #[test]
    fn leaves_quoted_identifiers_intact() {
        assert_eq!(
            sanitize(r#"SELECT "user's col" FROM t"#, "postgres"),
            r#"SELECT "user's col" FROM t"#
        );
    }

    #[test]
    fn preserves_comments() {
        let sql = "SELECT 1 -- note: keep 'this'\nFROM t";
        assert_eq!(
            sanitize(sql, "postgres"),
            "SELECT $1 -- note: keep 'this'\nFROM t"
        );
    }
}
