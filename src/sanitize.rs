//! Client-side literal sanitization (§6.2).
//!
//! When a workspace is in `sanitized` telemetry mode, the CLI replaces every
//! literal value with a placeholder *before* sending, so raw values never leave
//! the machine. This is a **lexical** pass: the engine still parses the
//! statement server-side. Our job is to find where each literal starts and ends
//! exactly as the dialect's own lexer would, replace it, and keep everything
//! else byte for byte.
//!
//! Replaced by a placeholder:
//!   - string literals: `'...'` (`''` escapes), with the dialect's prefixes
//!     (`E'...'`, `N'...'`, `U&'...'`, `B'...'`, `X'...'`, MySQL `_utf8mb4'...'`,
//!     Oracle `q'[...]'` / `nq'...'` with any delimiter), and MySQL `"..."`;
//!   - numbers in every form (`42`, `1.5`, `.5`, `1e10`, `0x1F`, `1_000`), with
//!     a unary sign (`= -3` becomes `= $1`), and MSSQL money (`$12.50`);
//!   - dollar-quoted strings (`$$...$$`, `$tag$...$tag$`). After `AS` or `DO`
//!     the text is a function or `DO` body: it becomes the empty body `$$$$`,
//!     so the statement still parses (the engine never reads a body).
//!
//! Kept as written: keywords, identifiers (also non-ASCII ones), quoted
//! identifiers (`"..."`, backticks, MSSQL and SQLite `[...]`), comments, and
//! the bind parameters the client already wrote (`$1`, `?`, `?1`, `:1`,
//! `:name`, `@p1`, `$name`, Snowflake's `$1` stage columns).
//!
//! Escapes follow each dialect. Snowflake always reads `\` as an escape inside
//! `'...'`; Postgres only in `E'...'`; Oracle, MSSQL and SQLite never. MySQL
//! does unless the server runs with `NO_BACKSLASH_ESCAPES`, which the client
//! cannot see, so a MySQL statement (and one in an unknown dialect) with a
//! backslash is read both ways, like the engine's MySQL lexer does. A reading
//! in which something is left unterminated is dropped (the text does not lex
//! that way); otherwise, if the two disagree, everything that is a literal in
//! either is replaced. Comments follow
//! the dialect too: `#` and `-- ` (with the space) in MySQL, `//` in Snowflake,
//! nested `/* */` in Postgres and MSSQL, and MySQL `/*! ... */` comments, which
//! the server executes, are sanitized inside.
//!
//! **Fail closed.** When the text cannot be tokenized with certainty (an
//! unterminated literal, quoted identifier, comment, dollar quote or q-quote, a
//! q-quote without a usable delimiter, a nested comment in MySQL, or a MySQL
//! comment form whose reading depends on the server), everything from there to
//! the end becomes one placeholder. Nothing is ever passed through on a guess.
//!
//! Placeholder style is **dialect-aware** so the sanitized SQL still parses:
//! Postgres, Oracle, MSSQL and unknown dialects use numbered params (`$1, $2,
//! …`), numbered after the highest `$N` (and Oracle `:N`) already in the
//! statement so they never collide with one, as libpg_query's normalization
//! does; MySQL, Snowflake and SQLite use `?`. (A bare `?` is invalid Postgres
//! syntax and would make the engine fail with a parse error.)
//!
//! Known limits, both settings the client cannot see: SQLite reads a `"..."`
//! that names no column as a string, and MSSQL does so with
//! `QUOTED_IDENTIFIER OFF`; here `"..."` is an identifier, as the engine reads
//! it. Postgres is read with `standard_conforming_strings` on (the default
//! since 9.1, and what the engine's parser assumes).

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Postgres,
    Mysql,
    Oracle,
    Mssql,
    Snowflake,
    Sqlite,
    /// Any other dialect: Postgres lexing, both backslash readings.
    Other,
}

impl Dialect {
    fn of(name: &str) -> Self {
        let name = name.trim_matches(|c: char| c.is_ascii() && is_space(c as u8));
        match name.to_ascii_lowercase().as_str() {
            "postgres" => Dialect::Postgres,
            "mysql" => Dialect::Mysql,
            "oracle" => Dialect::Oracle,
            "mssql" => Dialect::Mssql,
            "snowflake" => Dialect::Snowflake,
            "sqlite" => Dialect::Sqlite,
            _ => Dialect::Other,
        }
    }

    /// `?` placeholders: MySQL, Snowflake (where `$1` is a staged file's first
    /// column, not a parameter) and SQLite (its canonical bind form).
    fn question(self) -> bool {
        matches!(self, Dialect::Mysql | Dialect::Snowflake | Dialect::Sqlite)
    }

    fn pg_like(self) -> bool {
        matches!(self, Dialect::Postgres | Dialect::Other)
    }

    /// Whether a backslash inside a plain `'...'` may or may not be an escape,
    /// depending on a server setting: the text is read both ways.
    fn either_escapes(self) -> bool {
        matches!(self, Dialect::Mysql | Dialect::Other)
    }
}

/// A byte range of the input that is replaced in the output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Span {
    start: usize,
    end: usize,
    /// A function or `DO` body: rendered as `$$$$`, not as a placeholder.
    body: bool,
}

/// One reading of the text.
struct Lexed {
    spans: Vec<Span>,
    /// The highest numbered bind parameter already in the text.
    max_bind: Option<u32>,
    state: Reading,
}

/// How a reading of the text ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// Every token was read with certainty.
    Complete,
    /// Failed closed on something unterminated: the text does not lex this
    /// way, so no server reads it like this.
    Invalid,
    /// Failed closed on something the server may read either way. The
    /// reading stays possible.
    Ambiguous,
}

/// The previous significant token (comments and whitespace do not count).
#[derive(Clone, Copy)]
enum Prev {
    /// The start of the text, an operator or a separator: a sign that follows
    /// is unary.
    Op,
    /// A value: a literal, an identifier in quotes, a parameter, `)`.
    Operand,
    /// An unquoted word (keyword or name), as a byte range.
    Word(usize, usize),
}

/// What a word right before a `'` makes of the literal.
enum Prefix {
    /// The dialect's plain string (`N'...'`, `B'...'`, `X'...'`, `_utf8mb4'...'`).
    Plain,
    /// Postgres `E'...'`: backslash escapes.
    Escape,
    /// Oracle `q'[...]'` and `nq'[...]'`.
    QQuote,
}

/// A byte that continues an unquoted word in any dialect. Every non-ASCII
/// byte does, so a word never ends inside a UTF-8 character.
fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

fn word_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

struct Lexer<'a> {
    s: &'a str,
    b: &'a [u8],
    d: Dialect,
    /// The reading: whether `\` escapes inside a plain string where that
    /// depends on the server (MySQL and unknown dialects).
    backslash: bool,
    i: usize,
    prev: Prev,
    /// The start of the MySQL executable comment (`/*! ... */`) being read.
    exec: Option<usize>,
    /// Set when the failure being returned is an ambiguity, not an error.
    ambiguous: bool,
    spans: Vec<Span>,
    max_bind: Option<u32>,
}

impl<'a> Lexer<'a> {
    fn new(s: &'a str, d: Dialect, backslash: bool) -> Self {
        Lexer {
            s,
            b: s.as_bytes(),
            d,
            backslash,
            i: 0,
            prev: Prev::Op,
            exec: None,
            ambiguous: false,
            spans: Vec::new(),
            max_bind: None,
        }
    }

    /// Fail closed from `at` because the server may read the text there
    /// either way.
    fn unsure(&mut self, at: usize) -> Result<(), usize> {
        self.ambiguous = true;
        Err(at)
    }

    fn at(&self, k: usize) -> Option<u8> {
        self.b.get(k).copied()
    }

    fn digit_at(&self, k: usize) -> bool {
        self.at(k).is_some_and(|b| b.is_ascii_digit())
    }

    fn run(mut self) -> Lexed {
        while self.i < self.b.len() {
            if let Err(at) = self.step() {
                return self.fail(at);
            }
        }
        if let Some(at) = self.exec {
            return self.fail(at);
        }
        Lexed {
            spans: self.spans,
            max_bind: self.max_bind,
            state: Reading::Complete,
        }
    }

    /// Fail closed: everything from `at` (or from the executable comment it
    /// is in) to the end is one placeholder.
    fn fail(mut self, at: usize) -> Lexed {
        let at = self.exec.map_or(at, |e| e.min(at));
        while self.spans.last().is_some_and(|s| s.start >= at) {
            self.spans.pop();
        }
        self.spans.push(Span {
            start: at,
            end: self.b.len(),
            body: false,
        });
        Lexed {
            spans: self.spans,
            max_bind: self.max_bind,
            state: if self.ambiguous {
                Reading::Ambiguous
            } else {
                Reading::Invalid
            },
        }
    }

    /// Lexes one token at `self.i`. `Err(at)`: fail closed from `at`.
    fn step(&mut self) -> Result<(), usize> {
        let i = self.i;
        let c = self.b[i];
        let next = self.at(i + 1);
        if is_space(c) {
            self.i += 1;
            return Ok(());
        }
        if c == b'-' && next == Some(b'-') {
            // MySQL reads `--` as a comment only before whitespace or a control
            // character; whether a non-ASCII byte is one depends on the charset.
            let comment = self.d != Dialect::Mysql
                || match self.at(i + 2) {
                    None => true,
                    Some(x) if x >= 0x80 => return self.unsure(i),
                    Some(x) => x <= b' ' || x == 0x7f,
                };
            if comment {
                return self.line_comment(i);
            }
        }
        if (c == b'#' && self.d == Dialect::Mysql)
            || (c == b'/' && next == Some(b'/') && self.d == Dialect::Snowflake)
        {
            return self.line_comment(i);
        }
        if c == b'/' && next == Some(b'*') {
            return self.block_comment(i);
        }
        if c == b'*' && next == Some(b'/') && self.exec.is_some() {
            self.exec = None;
            self.i += 2;
            return Ok(());
        }
        match c {
            b'\'' => self.string(i, i, self.plain_backslash()),
            b'"' if self.d == Dialect::Mysql => self.string(i, i, self.backslash),
            b'"' | b'`' => self.quoted(i, c, true),
            b'[' if self.d == Dialect::Mssql => self.quoted(i, b']', true),
            b'[' if self.d == Dialect::Sqlite => self.quoted(i, b']', false),
            b'$' => self.dollar(i),
            b'?' => {
                let j = self.digits(i + 1);
                self.operand(j);
                Ok(())
            }
            b':' if next == Some(b':') => {
                self.prev = Prev::Op;
                self.i += 2;
                Ok(())
            }
            b':' if self.digit_at(i + 1)
                && matches!(
                    self.d,
                    Dialect::Oracle | Dialect::Snowflake | Dialect::Sqlite
                ) =>
            {
                let j = self.digits(i + 1);
                if self.d == Dialect::Oracle {
                    self.bind(i + 1, j);
                }
                self.operand(j);
                Ok(())
            }
            b'0'..=b'9' => self.number(i, i),
            b'.' if self.digit_at(i + 1) && !self.member_access(i) => self.number(i, i),
            b'-' | b'+'
                if matches!(self.prev, Prev::Op)
                    && (self.digit_at(i + 1) || (next == Some(b'.') && self.digit_at(i + 2))) =>
            {
                self.number(i, i + 1)
            }
            _ if word_start(c) => self.word(i),
            b')' | b']' | b'}' => {
                self.operand(i + 1);
                Ok(())
            }
            _ => {
                self.prev = Prev::Op;
                self.i += 1;
                Ok(())
            }
        }
    }

    /// Whether `\` escapes inside a plain `'...'` in this reading.
    fn plain_backslash(&self) -> bool {
        match self.d {
            Dialect::Snowflake => true,
            Dialect::Mysql | Dialect::Other => self.backslash,
            _ => false,
        }
    }

    fn operand(&mut self, end: usize) {
        self.prev = Prev::Operand;
        self.i = end;
    }

    fn literal(&mut self, start: usize, end: usize, body: bool) {
        self.spans.push(Span { start, end, body });
        self.operand(end);
    }

    fn digits(&self, mut j: usize) -> usize {
        while self.digit_at(j) {
            j += 1;
        }
        j
    }

    /// Records the bind parameter whose digits are `self.s[from..to]`. A value
    /// past `u32::MAX` is never reached by our numbering, so it is ignored.
    fn bind(&mut self, from: usize, to: usize) {
        if let Ok(v) = self.s[from..to].parse::<u32>() {
            self.max_bind = self.max_bind.max(Some(v));
        }
    }

    /// `t.5` is a member access, not the number `.5`.
    fn member_access(&self, i: usize) -> bool {
        i > 0 && {
            let p = self.b[i - 1];
            word_byte(p) || matches!(p, b'"' | b'`' | b']' | b')')
        }
    }

    fn line_comment(&mut self, i: usize) -> Result<(), usize> {
        if self.exec.is_some() {
            // A comment inside an executable comment: MySQL versions differ.
            return self.unsure(i);
        }
        self.i = self.s[i..].find('\n').map_or(self.b.len(), |p| i + p);
        Ok(())
    }

    fn block_comment(&mut self, i: usize) -> Result<(), usize> {
        if self.exec.is_some() {
            return self.unsure(i);
        }
        if self.d == Dialect::Mysql {
            let open = match (self.at(i + 2), self.at(i + 3)) {
                (Some(b'!'), _) => Some(i + 3),
                (Some(b'M'), Some(b'!')) => Some(i + 4),
                _ => None,
            };
            if let Some(j) = open {
                // Executed by the server: its content is code, lexed as such
                // up to the `*/` that closes it.
                self.exec = Some(i);
                self.i = self.digits(j);
                return Ok(());
            }
        }
        let nested = matches!(self.d, Dialect::Postgres | Dialect::Other | Dialect::Mssql);
        let mut depth = 1;
        let mut j = i + 2;
        loop {
            if j + 1 >= self.b.len() {
                return Err(i);
            }
            match (self.b[j], self.b[j + 1]) {
                (b'*', b'/') => {
                    j += 2;
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                (b'/', b'*') if nested => {
                    j += 2;
                    depth += 1;
                }
                // MySQL does not nest comments: what it makes of this is not
                // certain.
                (b'/', b'*') if self.d == Dialect::Mysql => return self.unsure(i),
                _ => j += 1,
            }
        }
        self.i = j;
        Ok(())
    }

    /// A string literal whose quote is at `quote`; the span starts at `start`
    /// (before its prefix, if any).
    fn string(&mut self, start: usize, quote: usize, backslash: bool) -> Result<(), usize> {
        let q = self.b[quote];
        let mut j = quote + 1;
        loop {
            let Some(x) = self.at(j) else {
                return Err(start);
            };
            if x == q {
                if self.at(j + 1) == Some(q) {
                    j += 2;
                    continue;
                }
                j += 1;
                break;
            }
            if x == b'\\' && backslash {
                if j + 1 >= self.b.len() {
                    return Err(start);
                }
                j += 2;
                continue;
            }
            j += 1;
        }
        self.closes_no_exec(start, j)?;
        self.literal(start, j, false);
        Ok(())
    }

    /// Whether a `*/` inside a quoted token closes the executable comment
    /// around it depends on whether the server executes the comment.
    fn closes_no_exec(&mut self, start: usize, end: usize) -> Result<(), usize> {
        if self.exec.is_some() && self.s[start..end].contains("*/") {
            return self.unsure(start);
        }
        Ok(())
    }

    /// A quoted identifier, copied as it is.
    fn quoted(&mut self, start: usize, close: u8, doubled: bool) -> Result<(), usize> {
        let mut j = start + 1;
        loop {
            let Some(x) = self.at(j) else {
                return Err(start);
            };
            j += 1;
            if x == close {
                if doubled && self.at(j) == Some(close) {
                    j += 1;
                    continue;
                }
                break;
            }
        }
        self.closes_no_exec(start, j)?;
        self.operand(j);
        Ok(())
    }

    /// Oracle `q'<delimiter>...<delimiter>'`; the quote is at `quote`.
    fn qquote(&mut self, start: usize, quote: usize) -> Result<(), usize> {
        let k = quote + 1;
        let Some(open) = self.s[k..].chars().next() else {
            return Err(start);
        };
        if matches!(open, ' ' | '\t' | '\n' | '\r') {
            return Err(start);
        }
        let mut close = String::with_capacity(5);
        close.push(match open {
            '[' => ']',
            '{' => '}',
            '(' => ')',
            '<' => '>',
            other => other,
        });
        close.push('\'');
        let from = k + open.len_utf8();
        match self.s[from..].find(&close) {
            Some(rel) => {
                self.literal(start, from + rel + close.len(), false);
                Ok(())
            }
            None => Err(start),
        }
    }

    fn number(&mut self, start: usize, from: usize) -> Result<(), usize> {
        let digits = |lx: &Self, mut j: usize| {
            while lx.at(j).is_some_and(|b| b.is_ascii_digit() || b == b'_') {
                j += 1;
            }
            j
        };
        let mut j = digits(self, from);
        if self.at(j) == Some(b'.') {
            j = digits(self, j + 1);
        }
        if matches!(self.at(j), Some(b'e' | b'E')) {
            let k = if matches!(self.at(j + 1), Some(b'+' | b'-')) {
                j + 2
            } else {
                j + 1
            };
            if self.digit_at(k) {
                j = self.digits(k);
            }
        }
        // Hex digits (`0x1F`), type suffixes (`1.5f`) and trailing junk: all
        // part of the same token.
        while self.at(j).is_some_and(word_byte) {
            j += 1;
        }
        self.literal(start, j, false);
        Ok(())
    }

    fn dollar(&mut self, i: usize) -> Result<(), usize> {
        let next = self.at(i + 1);
        if self.d.pg_like() {
            if self.digit_at(i + 1) {
                let j = self.digits(i + 1);
                self.bind(i + 1, j);
                self.operand(j);
                return Ok(());
            }
            // `$$` or `$tag$`, the tag an identifier without `$`.
            let mut j = i + 1;
            if next != Some(b'$') {
                if !next.is_some_and(word_start) {
                    self.prev = Prev::Op;
                    self.i += 1;
                    return Ok(());
                }
                while self.at(j).is_some_and(|b| b != b'$' && word_byte(b)) {
                    j += 1;
                }
                if self.at(j) != Some(b'$') {
                    self.prev = Prev::Op;
                    self.i += 1;
                    return Ok(());
                }
            }
            let s = self.s;
            let tag = &s[i..=j];
            return match s[j + 1..].find(tag) {
                Some(rel) => {
                    self.dollar_string(i, j + 1 + rel + tag.len());
                    Ok(())
                }
                None => Err(i),
            };
        }
        if self.d == Dialect::Snowflake && next == Some(b'$') {
            return match self.s[i + 2..].find("$$") {
                Some(rel) => {
                    self.dollar_string(i, i + 2 + rel + 2);
                    Ok(())
                }
                None => Err(i),
            };
        }
        if self.d == Dialect::Mssql
            && (self.digit_at(i + 1) || (next == Some(b'.') && self.digit_at(i + 2)))
        {
            return self.number(i, i + 1);
        }
        // `$name` / `$1`: a variable, a stage column or a bind parameter.
        let mut j = i + 1;
        while self.at(j).is_some_and(word_byte) {
            j += 1;
        }
        if self.d == Dialect::Oracle && j > i + 1 && self.b[i + 1..j].iter().all(u8::is_ascii_digit)
        {
            self.bind(i + 1, j);
        }
        self.operand(j);
        Ok(())
    }

    fn dollar_string(&mut self, start: usize, end: usize) {
        let body = matches!(self.prev, Prev::Word(a, b)
            if self.s[a..b].eq_ignore_ascii_case("as") || self.s[a..b].eq_ignore_ascii_case("do"));
        self.literal(start, end, body);
    }

    fn word(&mut self, i: usize) -> Result<(), usize> {
        let hash = matches!(self.d, Dialect::Oracle | Dialect::Mssql);
        let mut j = i;
        while self
            .at(j)
            .is_some_and(|b| word_byte(b) || (hash && b == b'#'))
        {
            j += 1;
        }
        match self.at(j) {
            Some(b'\'') => match self.prefix(&self.s[i..j]) {
                Some(Prefix::Plain) => return self.string(i, j, self.plain_backslash()),
                Some(Prefix::Escape) => return self.string(i, j, true),
                Some(Prefix::QQuote) => return self.qquote(i, j),
                None => {}
            },
            // Postgres `U&'...'`: no backslash escape for the quote.
            Some(b'&')
                if self.d.pg_like()
                    && self.at(j + 1) == Some(b'\'')
                    && self.s[i..j].eq_ignore_ascii_case("u") =>
            {
                return self.string(i, j + 1, false);
            }
            _ => {}
        }
        self.prev = Prev::Word(i, j);
        self.i = j;
        Ok(())
    }

    fn prefix(&self, word: &str) -> Option<Prefix> {
        let w = word.to_ascii_lowercase();
        match (self.d, w.as_str()) {
            (Dialect::Postgres | Dialect::Other, "e") => Some(Prefix::Escape),
            (Dialect::Postgres | Dialect::Other | Dialect::Mysql, "n" | "b" | "x") => {
                Some(Prefix::Plain)
            }
            (Dialect::Mysql, w) if w.len() > 1 && w.starts_with('_') => Some(Prefix::Plain),
            (Dialect::Oracle, "n") | (Dialect::Mssql, "n") => Some(Prefix::Plain),
            (Dialect::Oracle, "q" | "nq") => Some(Prefix::QQuote),
            (Dialect::Snowflake | Dialect::Sqlite, "x") => Some(Prefix::Plain),
            _ => None,
        }
    }
}

/// Merges the spans of two readings: every byte that is a literal in either
/// is replaced, overlapping spans as one placeholder.
fn union(a: &[Span], b: &[Span]) -> Vec<Span> {
    let mut all: Vec<Span> = a.iter().chain(b).copied().collect();
    all.sort_by_key(|s| (s.start, s.end));
    let mut out: Vec<Span> = Vec::with_capacity(all.len());
    for s in all {
        match out.last_mut() {
            Some(last) if s.start < last.end => last.end = last.end.max(s.end),
            _ => out.push(Span { body: false, ..s }),
        }
    }
    out
}

fn render(sql: &str, spans: &[Span], question: bool, max_bind: Option<u32>) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut next = max_bind.map_or(1, |m| u64::from(m) + 1);
    let mut pos = 0;
    for s in spans {
        out.push_str(&sql[pos..s.start]);
        // `ñ$1` or `typE$1` would read as one word: keep them apart.
        if out
            .as_bytes()
            .last()
            .is_some_and(|&b| word_byte(b) || b == b'?')
        {
            out.push(' ');
        }
        if s.body {
            out.push_str("$$$$");
        } else if question {
            out.push('?');
        } else {
            out.push('$');
            out.push_str(&next.to_string());
            next += 1;
        }
        pos = s.end;
    }
    out.push_str(&sql[pos..]);
    out
}

/// Returns the SQL with every literal replaced by a dialect-correct
/// placeholder (`$N` for Postgres, Oracle, MSSQL and unknown dialects, `?` for
/// MySQL, Snowflake and SQLite). See the module documentation for the rules.
pub fn sanitize(sql: &str, dialect: &str) -> String {
    let d = Dialect::of(dialect);
    let first = Lexer::new(sql, d, true).run();
    let (spans, max_bind) = if d.either_escapes() && sql.contains('\\') {
        let second = Lexer::new(sql, d, false).run();
        let max_bind = first.max_bind.max(second.max_bind);
        // A reading is dropped only when the text does not lex that way; an
        // ambiguous one stays possible, so both count.
        let spans = match (first.state, second.state) {
            _ if first.spans == second.spans => first.spans,
            (Reading::Complete, Reading::Invalid) => first.spans,
            (Reading::Invalid, Reading::Complete) => second.spans,
            _ => union(&first.spans, &second.spans),
        };
        (spans, max_bind)
    } else {
        (first.spans, first.max_bind)
    };
    render(sql, &spans, d.question(), max_bind)
}

#[cfg(test)]
mod tests {
    use super::sanitize;
    use serde_json::Value;

    /// The shared test vectors: `tests/fixtures/sanitize.json`. vericto-python
    /// runs the same file (as `tests/fixtures/sanitize/vericto-cli-<version>.json`)
    /// against its port, so the two cannot drift apart.
    const FIXTURE: &str = include_str!("../tests/fixtures/sanitize.json");

    fn vectors() -> Vec<(String, String, String, String)> {
        let v: Value = serde_json::from_str(FIXTURE).expect("fixture is JSON");
        v["vectors"]
            .as_array()
            .expect("vectors")
            .iter()
            .map(|t| {
                let field = |k: &str| t[k].as_str().expect(k).to_string();
                (
                    field("test"),
                    field("dialect"),
                    field("sql"),
                    field("expected"),
                )
            })
            .collect()
    }

    /// Runs every vector of the fixture group `name` (there must be one).
    fn group(name: &str) {
        let mut n = 0;
        for (test, dialect, sql, expected) in vectors() {
            if test == name {
                n += 1;
                assert_eq!(
                    sanitize(&sql, &dialect),
                    expected,
                    "{test} [{dialect}]: {sql:?}"
                );
            }
        }
        assert!(n > 0, "no fixture vector named {name}");
    }

    #[test]
    fn every_fixture_vector() {
        let all = vectors();
        assert!(all.len() >= 19);
        let failures: Vec<String> = all
            .iter()
            .filter(|(_, d, sql, expected)| sanitize(sql, d) != *expected)
            .map(|(t, d, sql, expected)| {
                format!(
                    "{t} [{d}]: {sql:?}\n  got  {:?}\n  want {expected:?}",
                    sanitize(sql, d)
                )
            })
            .collect();
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn every_fixture_group_has_a_test() {
        // Each group name in the fixture is also a #[test] below that runs it.
        for (test, ..) in vectors() {
            assert!(
                GROUPS.contains(&test.as_str()),
                "fixture group {test} has no #[test]"
            );
        }
    }

    macro_rules! groups {
        ($($name:ident),* $(,)?) => {
            const GROUPS: &[&str] = &[$(stringify!($name)),*];
            $(#[test] fn $name() { group(stringify!($name)); })*
        };
    }

    groups!(
        // vericto-cli 1.8.0's vectors.
        strips_string_literals_postgres_numbered,
        sqlite_uses_question_mark_and_keeps_its_identifiers,
        existing_bind_parameters_are_kept,
        snowflake_uses_question_mark,
        mysql_uses_question_mark,
        numbered_placeholders_increment,
        handles_escaped_quotes,
        strips_numbers_but_not_identifiers,
        dollar_quoted_body_is_emptied,
        leaves_quoted_identifiers_intact,
        mysql_backslash_escaped_quote_does_not_leak,
        mysql_escaped_backslash_before_closing_quote,
        postgres_e_string_backslash_escape_does_not_leak,
        postgres_standard_string_keeps_backslash_literal,
        identifier_ending_in_e_is_not_an_e_string,
        preserves_comments,
        // 1.8.2: one group per fixed leak and per checked construct.
        snowflake_backslash_escape_does_not_leak,
        mysql_reads_both_escape_modes,
        mysql_double_quoted_string_is_a_literal,
        oracle_q_quotes_are_literals,
        mssql_bracket_identifiers_are_kept,
        bind_parameters_are_kept_as_written,
        numbering_starts_after_existing_parameters,
        non_ascii_text_is_kept,
        dollar_quotes,
        nested_block_comments,
        mysql_comments,
        snowflake_line_comments,
        unicode_and_national_strings,
        hex_and_binary_literals,
        numeric_forms,
        fails_closed,
        dialect_cases,
        dialect_name_is_case_insensitive,
    );

    /// xorshift64*: a seeded generator, so a failure always reproduces.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }
        fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
            xs[self.below(xs.len())]
        }
    }

    const DIALECTS: [&str; 7] = [
        "postgres",
        "mysql",
        "oracle",
        "mssql",
        "snowflake",
        "sqlite",
        "bigquery",
    ];

    /// Text that may sit inside a string quoted with `quote` in `dialect`
    /// without ending it.
    fn string_piece(rng: &mut Rng, dialect: &str, backslash: bool, quote: char) -> String {
        let mut pieces = vec![
            " ", "''", "\"\"", "-- ", "/*", "*/", "$$", "ñ", "😀", "名", "]", "[", "#", "//", ":1",
            "$1", "?", "\n",
        ];
        pieces.push(if quote == '\'' { "\"" } else { "'" });
        pieces.push(if quote == '\'' { "q''[" } else { "q'[" });
        if backslash {
            pieces.extend(["\\'", "\\\"", "\\\\", "\\n"]);
        } else {
            pieces.push("\\");
        }
        if dialect == "mysql" {
            // Inside `/*! ... */` a literal never holds `*/`; keep it simple.
            pieces.retain(|p| *p != "*/");
        }
        let mut s = String::new();
        for _ in 0..rng.below(4) {
            s.push_str(rng.pick(&pieces));
        }
        s
    }

    /// A literal holding `marker`, of a kind `dialect` has.
    fn literal(rng: &mut Rng, dialect: &str, marker: &str, digits: &str, hex: &str) -> String {
        let plain_bs = matches!(dialect, "mysql" | "snowflake" | "bigquery");
        let mut p = |rng: &mut Rng, bs: bool| string_piece(rng, dialect, bs, '\'');
        let quoted = |rng: &mut Rng, p: &mut dyn FnMut(&mut Rng, bool) -> String, bs: bool| {
            format!("'{}{marker}{}'", p(rng, bs), p(rng, bs))
        };
        let dq = |rng: &mut Rng| string_piece(rng, dialect, true, '"');
        let mut kinds: Vec<String> = vec![
            quoted(rng, &mut p, plain_bs),
            digits.to_string(),
            format!("-{digits}"),
            format!("{digits}.{digits}"),
            format!(".{digits}"),
            format!("{digits}e1{}", rng.below(9)),
            format!("0x{hex}"),
        ];
        let safe = ["", " ", "'", "ñ", "😀", "x", "\"", "--", "/*"];
        let s = |rng: &mut Rng| format!("{}{}", rng.pick(&safe), rng.pick(&safe));
        match dialect {
            "postgres" | "bigquery" => {
                kinds.push(format!("E{}", quoted(rng, &mut p, true)));
                kinds.push(format!("N{}", quoted(rng, &mut p, plain_bs)));
                kinds.push(format!("U&{}", quoted(rng, &mut p, false)));
                kinds.push(format!("X'{hex}'"));
                kinds.push(format!("B'{}'", digits.replace(|c: char| c > '1', "1")));
                kinds.push(format!("$${}{marker}{}$$", s(rng), s(rng)));
                kinds.push(format!("$tg${}{marker}$ {}$tg$", s(rng), s(rng)));
                kinds.push(format!("AS $$ {marker} $$"));
                kinds.push(format!("DO $x$ BEGIN PERFORM '{marker}'; END $x$"));
            }
            "mysql" => {
                kinds.push(format!("\"{}{marker}\\\"{}\"", dq(rng), dq(rng)));
                kinds.push(format!("N{}", quoted(rng, &mut p, true)));
                kinds.push(format!("_utf8mb4{}", quoted(rng, &mut p, true)));
                kinds.push(format!("X'{hex}'"));
                kinds.push(format!("/*!50000 {} */", quoted(rng, &mut p, true)));
                kinds.push(format!("/*M!100100 {digits} */"));
            }
            "oracle" => {
                let body = |rng: &mut Rng| format!("{}{marker}{}", s(rng), s(rng));
                kinds.push(format!("q'[{}]'", body(rng)));
                kinds.push(format!("q'{{{}}}'", body(rng)));
                kinds.push(format!("q'({})'", body(rng)));
                kinds.push(format!("Q'<{}>'", body(rng)));
                kinds.push(format!("q'!{}!'", body(rng)));
                kinds.push(format!("nq'§{}§'", body(rng)));
                kinds.push(format!("N{}", quoted(rng, &mut p, false)));
            }
            "mssql" => {
                kinds.push(format!("N{}", quoted(rng, &mut p, false)));
                kinds.push(format!("${digits}.50"));
            }
            "snowflake" => {
                kinds.push(format!("$${}{marker}{}$$", s(rng), s(rng)));
                kinds.push(format!("AS $$ return \"{marker}\"; $$"));
                kinds.push(format!("X'{hex}'"));
            }
            _ => kinds.push(format!("X'{hex}'")),
        }
        kinds.swap_remove(rng.below(kinds.len()))
    }

    /// Code that holds no literal.
    fn filler(rng: &mut Rng, dialect: &str) -> &'static str {
        let mut xs = vec![
            "SELECT",
            "FROM",
            "WHERE",
            "AND",
            "AS",
            "DO",
            "a",
            "col2",
            "t.c",
            "ñandú",
            "名前",
            "😀",
            "=",
            "<>",
            "(",
            ")",
            ",",
            "+",
            "-",
            "*",
            "/",
            "||",
            "::",
            ";",
            "?",
            "@p1",
            "-- it's ñ 😀\n",
            "/* it's 名 */",
            "\"q 'id\"",
        ];
        match dialect {
            "postgres" | "bigquery" => {
                xs.extend(["$1", "$7", "/* a /* it's */ b' */", "a[1:2]", "U&\"x'\""])
            }
            "mysql" => xs.extend(["`it's`", "# it's\n", "/*+ BKA(t) */", "@v"]),
            "oracle" => xs.extend([":1", ":name", "$2", "a#b"]),
            "mssql" => xs.extend(["[it's 1]", "[a]]'b]", "/* a /* it's */ b' */", "#tmp"]),
            "snowflake" => xs.extend(["$1", ":1", "// it's\n", "@stage"]),
            "sqlite" => xs.extend(["[it's]", "`it's`", ":a", "$c", "?3"]),
            _ => {}
        }
        xs[rng.below(xs.len())]
    }

    #[test]
    fn no_marker_survives_in_any_literal_kind() {
        let mut rng = Rng(0x5eed_0018_2026_1018);
        for round in 0..30_000 {
            let dialect = DIALECTS[round % DIALECTS.len()];
            let mut sql = String::new();
            let mut markers = Vec::new();
            for _ in 0..=rng.below(10) {
                if rng.below(3) == 0 {
                    let marker = format!("SECRET{:08x}", rng.next_u64() as u32);
                    let digits = (7_000_000_000u64 + rng.next_u64() % 1_000_000_000).to_string();
                    let hex = format!("ABCDE{:06X}", rng.next_u64() & 0xff_ffff);
                    sql.push_str(&literal(&mut rng, dialect, &marker, &digits, &hex));
                    markers.extend([marker, digits, hex]);
                } else {
                    sql.push_str(filler(&mut rng, dialect));
                }
                sql.push_str(if rng.below(4) == 0 { "\n" } else { " " });
            }
            let out = sanitize(&sql, dialect);
            for m in &markers {
                assert!(
                    !out.contains(m.as_str()),
                    "[{dialect}] {m} leaked\n in:  {sql:?}\n out: {out:?}"
                );
            }
        }
    }

    #[test]
    fn arbitrary_text_never_panics_and_keeps_non_ascii() {
        let pool = [
            "'", "\"", "`", "[", "]", "$", "$$", "$a$", "\\", "-", "--", "#", "/", "*", "/*", "*/",
            "/*!", "//", ":", "::", "?", ".", "e", "E", "N", "q", "x", "U&", "&", "0", "7", " ",
            "\n", "ñ", "😀", "名", "§", "é", "AS", "DO", "_x", "{", "(", "<", "!", "+", ";",
        ];
        let mut rng = Rng(0xdead_beef_0018_0002);
        for round in 0..20_000 {
            let dialect = DIALECTS[round % DIALECTS.len()];
            let mut sql = String::new();
            for _ in 0..rng.below(40) {
                sql.push_str(rng.pick(&pool));
            }
            let out = sanitize(&sql, dialect);
            // Non-ASCII characters come out whole or not at all: never as bytes.
            for ch in out.chars().filter(|c| !c.is_ascii()) {
                assert!(
                    sql.contains(ch),
                    "[{dialect}] {ch:?} not in {sql:?} -> {out:?}"
                );
            }
        }
    }

    #[test]
    fn pathological_inputs_stay_linear() {
        // Each of these is quadratic for a scanner that re-searches from every
        // opening it sees; 200k bytes keep that well over any test timeout.
        let n = 200_000;
        let cases = [
            ("postgres", "$a".repeat(n / 2)),
            ("postgres", "/*".repeat(n / 2)),
            ("oracle", "q'[".repeat(n / 3)),
            ("mysql", "'\\'".repeat(n / 3)),
            ("snowflake", "$$ ".repeat(n / 3)),
            ("mssql", "[[".repeat(n / 2)),
            ("bigquery", "'\\' '".repeat(n / 5)),
        ];
        for (dialect, sql) in &cases {
            let out = sanitize(sql, dialect);
            assert!(out.len() < 4 * sql.len(), "{dialect}");
        }
    }
}
