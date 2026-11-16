// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! A small POSIX-shell reader for `vericto guard`: it turns the command line a
//! coding agent is about to run into the simple commands the shell would run,
//! with what each one reads on standard input.
//!
//! It is not a shell. It reads what decides which programs run and with which
//! arguments: quoting (`'…'`, `"…"`, `$'…'`, backslashes), variable references
//! (`$X`, `${X}`, `${X:-default}`, resolved from earlier assignments in the
//! same script and from the caller's lookup, kept as written otherwise),
//! command substitutions (`$(…)`, backticks, `<(…)`, returned as nested scripts
//! to read on their own), comments, the operators that separate commands
//! (`;`, `&`, `&&`, `||`, `|`, `|&`, newlines, `(`, `)`, `{`, `}`),
//! redirections (`<`, `>`, `>>`, `&>`, `2>&1`…), heredocs (`<<EOF`, `<<-EOF`,
//! `<<'EOF'`) and here-strings (`<<<`). A pipe's reader learns what it reads
//! when the writer is `echo`, `printf`, `cat` (files or a heredoc) or `tee`.
//!
//! What it gets wrong it gets wrong conservatively for the guard: an
//! unresolved reference stays in the word as written (`$DATABASE_URL`), and a
//! command whose arguments came from a substitution is marked `dynamic`.

use std::collections::HashMap;

/// Where a command's standard input comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Input {
    /// Known text: a heredoc, a here-string, or what `echo`/`printf` wrote.
    Text(String),
    /// A file (`< f.sql`, or `cat f.sql |`), relative to the working directory.
    File(String),
    /// Another program's output, which the guard cannot see (`gen | psql`).
    Unknown(String),
}

/// One simple command: its environment prefix, its words and its input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cmd {
    /// `NAME=value` words before the command name.
    pub assigns: Vec<(String, String)>,
    /// The command name and its arguments, quotes removed.
    pub argv: Vec<String>,
    /// Standard input, when redirected or piped.
    pub stdin: Option<Input>,
    /// Some word came from a command substitution, so the guard cannot know
    /// its value.
    pub dynamic: bool,
    /// Files this command writes to with `>` / `>>` (not used by detectors
    /// today; kept so tests can check redirections are not arguments).
    pub writes: Vec<String>,
}

/// The result of reading a script.
#[derive(Debug, Default)]
pub struct Script {
    pub cmds: Vec<Cmd>,
    /// Scripts found inside `$(…)`, backticks and `<(…)` / `>(…)`.
    pub nested: Vec<String>,
    /// Variables the script assigns at top level (`X=1; …`, `export X=1`),
    /// in their final value. Read by the guard to resolve `.env`-style
    /// sourcing and later references.
    pub vars: HashMap<String, String>,
    /// Files the script sources (`source .env.production`, `. ./env.sh`).
    pub sourced: Vec<String>,
}

/// Placeholder put in a word where a command substitution was. A character no
/// command line carries, so it never collides with real text.
pub const SUBST: &str = "\u{1}subst\u{1}";

/// Reads `src`. `lookup` resolves a variable the script itself did not set
/// (the caller's environment); `None` keeps the reference as written.
pub fn parse(src: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Script {
    let mut p = Parser {
        s: src.chars().collect(),
        i: 0,
        lookup,
        out: Script::default(),
        pending_heredocs: Vec::new(),
        pipe_from: Vec::new(),
    };
    p.run();
    p.finish()
}

struct PendingHeredoc {
    cmd: usize,
    delim: String,
    strip_tabs: bool,
    expand: bool,
}

struct Parser<'a> {
    s: Vec<char>,
    i: usize,
    lookup: &'a dyn Fn(&str) -> Option<String>,
    out: Script,
    pending_heredocs: Vec<PendingHeredoc>,
    /// `pipe_from[k] = Some(j)`: command `k` reads command `j`'s output.
    pipe_from: Vec<Option<usize>>,
}

/// A word being built, plus whether it was quoted at all (an empty quoted
/// word `''` is still a word) and whether it is a plain assignment.
#[derive(Default)]
struct Word {
    text: String,
    quoted: bool,
    any: bool,
    dynamic: bool,
    /// The text before the first `=` was unquoted and a valid name.
    assign_eq: Option<usize>,
}

const RESERVED_PREFIX: &[&str] = &[
    "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "time", "{", "}",
];

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn peek_at(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    fn run(&mut self) {
        // The command being built and whether the next command reads it.
        let mut cur = Cmd::default();
        let mut cur_has_heredoc_target = false;
        let mut piped_from: Option<usize> = None;
        loop {
            self.skip_blanks();
            let Some(c) = self.peek() else { break };
            match c {
                '#' => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.i += 1;
                    }
                }
                '\n' => {
                    self.i += 1;
                    self.end_cmd(&mut cur, &mut piped_from, false);
                    cur_has_heredoc_target = false;
                    self.read_heredoc_bodies();
                }
                ';' | '&' | '|' | '(' | ')' => {
                    let mut pipe = false;
                    if c == '|' {
                        if self.peek_at(1) == Some('|') {
                            self.i += 2;
                        } else {
                            self.i += if self.peek_at(1) == Some('&') { 2 } else { 1 };
                            pipe = true;
                        }
                    } else if c == '&' {
                        if self.peek_at(1) == Some('>') {
                            // `&>file` / `&>>file`: a redirection, not an operator.
                            self.i += 1;
                            self.redirect_out(&mut cur);
                            continue;
                        }
                        self.i += if self.peek_at(1) == Some('&') { 2 } else { 1 };
                    } else if c == ';' {
                        self.i += if self.peek_at(1) == Some(';') { 2 } else { 1 };
                    } else {
                        self.i += 1;
                    }
                    self.end_cmd(&mut cur, &mut piped_from, pipe);
                    cur_has_heredoc_target = false;
                }
                '<' | '>' => self.redirect(&mut cur, None, &mut cur_has_heredoc_target),
                _ => {
                    // A word, or a fd number glued to a redirection (`2>`).
                    let start = self.i;
                    let w = self.word();
                    if !w.quoted
                        && !w.text.is_empty()
                        && w.text.chars().all(|c| c.is_ascii_digit())
                        && matches!(self.peek(), Some('<' | '>'))
                        && self.i == start + w.text.chars().count()
                    {
                        let fd = w.text.parse::<u32>().ok();
                        self.redirect(&mut cur, fd, &mut cur_has_heredoc_target);
                        continue;
                    }
                    if !w.any {
                        // Nothing readable here (a stray character): skip it so
                        // the loop always advances.
                        if self.i == start {
                            self.i += 1;
                        }
                        continue;
                    }
                    if w.dynamic {
                        cur.dynamic = true;
                    }
                    if cur.argv.is_empty() {
                        if let Some(eq) = w.assign_eq {
                            let name = w.text[..eq].to_string();
                            let value = w.text[eq + 1..].to_string();
                            cur.assigns.push((name, value));
                            continue;
                        }
                        if !w.quoted && RESERVED_PREFIX.contains(&w.text.as_str()) {
                            continue;
                        }
                    }
                    cur.argv.push(w.text);
                }
            }
        }
        self.end_cmd(&mut cur, &mut piped_from, false);
        // A heredoc whose body never ended takes the rest of the text, which
        // `read_heredoc_bodies` already consumed; nothing pending remains.
        self.read_heredoc_bodies();
    }

    fn skip_blanks(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' {
                self.i += 1;
            } else if c == '\\' && self.peek_at(1) == Some('\n') {
                self.i += 2;
            } else {
                break;
            }
        }
    }

    fn end_cmd(&mut self, cur: &mut Cmd, piped_from: &mut Option<usize>, pipe_next: bool) {
        let cmd = std::mem::take(cur);
        let empty = cmd.argv.is_empty() && cmd.assigns.is_empty() && cmd.stdin.is_none();
        if empty {
            if !pipe_next {
                *piped_from = None;
            }
            return;
        }
        // Top-level assignments with no command set script variables.
        if cmd.argv.is_empty() {
            for (k, v) in &cmd.assigns {
                self.out.vars.insert(k.clone(), v.clone());
            }
        } else if cmd.argv[0] == "export" || cmd.argv[0] == "declare" || cmd.argv[0] == "local" {
            for a in &cmd.argv[1..] {
                if let Some((k, v)) = a.split_once('=') {
                    if is_name(k) {
                        self.out.vars.insert(k.to_string(), v.to_string());
                    }
                }
            }
        } else if (cmd.argv[0] == "source" || cmd.argv[0] == ".") && cmd.argv.len() > 1 {
            self.out.sourced.push(cmd.argv[1].clone());
        }
        let idx = self.out.cmds.len();
        self.out.cmds.push(cmd);
        self.pipe_from.push(piped_from.take());
        if pipe_next {
            *piped_from = Some(idx);
        }
    }

    fn redirect(&mut self, cur: &mut Cmd, fd: Option<u32>, heredoc_target: &mut bool) {
        let c = self.peek().unwrap_or(' ');
        if c == '<' {
            if self.peek_at(1) == Some('<') && self.peek_at(2) == Some('<') {
                self.i += 3;
                self.skip_blanks();
                let w = self.word();
                if w.dynamic {
                    cur.dynamic = true;
                }
                cur.stdin = Some(Input::Text(format!("{}\n", w.text)));
                return;
            }
            if self.peek_at(1) == Some('<') {
                self.i += 2;
                let strip_tabs = if self.peek() == Some('-') {
                    self.i += 1;
                    true
                } else {
                    false
                };
                self.skip_blanks();
                let w = self.word();
                // The body is attached to this command when the line ends; the
                // command is pushed by then, at the index it will get.
                self.pending_heredocs.push(PendingHeredoc {
                    cmd: self.out.cmds.len(),
                    delim: w.text,
                    strip_tabs,
                    expand: !w.quoted,
                });
                *heredoc_target = true;
                cur.stdin = Some(Input::Text(String::new()));
                return;
            }
            self.i += 1;
            // `<&` dup, `<>` read-write, `<(` process substitution.
            if self.peek() == Some('(') {
                self.i += 1;
                let inner = self.balanced(')');
                self.out.nested.push(inner);
                cur.argv.push(SUBST.to_string());
                cur.dynamic = true;
                return;
            }
            if matches!(self.peek(), Some('&' | '>')) {
                self.i += 1;
            }
            self.skip_blanks();
            let w = self.word();
            if fd.unwrap_or(0) == 0 && !w.text.is_empty() && !w.text.starts_with('-') {
                cur.stdin = Some(Input::File(w.text));
            }
            return;
        }
        // '>'
        self.i += 1;
        if self.peek() == Some('(') {
            self.i += 1;
            let inner = self.balanced(')');
            self.out.nested.push(inner);
            cur.argv.push(SUBST.to_string());
            return;
        }
        self.i -= 1;
        self.redirect_out(cur);
    }

    /// At a `>` (or after `&` of `&>`): `>`, `>>`, `>|`, `>&N`, then a target.
    fn redirect_out(&mut self, cur: &mut Cmd) {
        if self.peek() == Some('>') {
            self.i += 1;
        }
        if matches!(self.peek(), Some('>' | '|')) {
            self.i += 1;
        }
        if self.peek() == Some('&') {
            self.i += 1;
            // `>&2`, `>&-`
            self.skip_blanks();
            let _ = self.word();
            return;
        }
        self.skip_blanks();
        let w = self.word();
        if !w.text.is_empty() {
            cur.writes.push(w.text);
        }
    }

    fn read_heredoc_bodies(&mut self) {
        let pending = std::mem::take(&mut self.pending_heredocs);
        for h in pending {
            let mut body = String::new();
            loop {
                if self.i >= self.s.len() {
                    break;
                }
                let start = self.i;
                while self.i < self.s.len() && self.s[self.i] != '\n' {
                    self.i += 1;
                }
                let line: String = self.s[start..self.i].iter().collect();
                if self.i < self.s.len() {
                    self.i += 1; // the newline
                }
                let cmp = if h.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if cmp.trim_end_matches('\r') == h.delim {
                    break;
                }
                body.push_str(if h.strip_tabs { cmp } else { &line });
                body.push('\n');
            }
            let text = if h.expand {
                self.expand_text(&body)
            } else {
                body
            };
            if let Some(cmd) = self.out.cmds.get_mut(h.cmd) {
                cmd.stdin = Some(Input::Text(text));
            }
        }
    }

    /// Expands `$X` / `${X}` in heredoc text (unquoted delimiter).
    fn expand_text(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut k = 0;
        while k < chars.len() {
            if chars[k] == '\\' && k + 1 < chars.len() && matches!(chars[k + 1], '$' | '`' | '\\') {
                out.push(chars[k + 1]);
                k += 2;
                continue;
            }
            if chars[k] == '$' {
                let (consumed, value) = self.read_var(&chars[k + 1..]);
                if consumed > 0 {
                    match value {
                        Some(v) => out.push_str(&v),
                        None => out.extend(&chars[k..k + 1 + consumed]),
                    }
                    k += 1 + consumed;
                    continue;
                }
            }
            out.push(chars[k]);
            k += 1;
        }
        out
    }

    /// Reads a variable reference after `$` (`NAME`, `{NAME}`, `{NAME:-x}`,
    /// `1`, `@`…). Returns how many characters it used and its value.
    fn read_var(&self, rest: &[char]) -> (usize, Option<String>) {
        match rest.first() {
            Some('{') => {
                let Some(end) = rest.iter().position(|&c| c == '}') else {
                    return (0, None);
                };
                let inner: String = rest[1..end].iter().collect();
                let (name, default) = match inner.find(":-").or_else(|| inner.find('-')) {
                    Some(p) if is_name(&inner[..p]) => {
                        let skip = if inner[p..].starts_with(":-") { 2 } else { 1 };
                        (inner[..p].to_string(), Some(inner[p + skip..].to_string()))
                    }
                    _ => (inner.clone(), None),
                };
                if !is_name(&name) {
                    return (end + 1, None);
                }
                let v = self.var(&name).or(default);
                (end + 1, v)
            }
            Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
                let n = rest
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                    .count();
                let name: String = rest[..n].iter().collect();
                (n, self.var(&name))
            }
            Some(c) if c.is_ascii_digit() || matches!(c, '@' | '*' | '#' | '?' | '$' | '!') => {
                (1, None)
            }
            _ => (0, None),
        }
    }

    fn var(&self, name: &str) -> Option<String> {
        self.out
            .vars
            .get(name)
            .cloned()
            .or_else(|| (self.lookup)(name))
    }

    /// Reads up to the matching `close`, honouring quotes and nesting; the
    /// cursor ends after `close`.
    fn balanced(&mut self, close: char) -> String {
        let open = if close == ')' { '(' } else { close };
        let start = self.i;
        let mut depth = 1usize;
        while let Some(c) = self.peek() {
            match c {
                '\\' => self.i += 2,
                '\'' => {
                    self.i += 1;
                    while let Some(c) = self.peek() {
                        self.i += 1;
                        if c == '\'' {
                            break;
                        }
                    }
                }
                '"' => {
                    self.i += 1;
                    while let Some(c) = self.peek() {
                        if c == '\\' {
                            self.i += 2;
                            continue;
                        }
                        self.i += 1;
                        if c == '"' {
                            break;
                        }
                    }
                }
                _ if c == close && open != close => {
                    depth -= 1;
                    self.i += 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ if c == open => {
                    depth += 1;
                    self.i += 1;
                }
                _ => self.i += 1,
            }
        }
        let end = self.i.min(self.s.len());
        let stop = if end > start && self.s.get(end - 1) == Some(&close) {
            end - 1
        } else {
            end
        };
        self.s[start..stop].iter().collect()
    }

    /// Reads one word at the cursor.
    fn word(&mut self) -> Word {
        let mut w = Word::default();
        let mut name_ok = true; // the unquoted prefix so far is a valid name
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')' => break,
                '\\' => {
                    self.i += 1;
                    match self.peek() {
                        Some('\n') => self.i += 1,
                        Some(n) => {
                            w.text.push(n);
                            w.any = true;
                            self.i += 1;
                            name_ok = false;
                        }
                        None => {}
                    }
                }
                '\'' => {
                    self.i += 1;
                    w.quoted = true;
                    w.any = true;
                    name_ok = false;
                    while let Some(c) = self.peek() {
                        self.i += 1;
                        if c == '\'' {
                            break;
                        }
                        w.text.push(c);
                    }
                }
                '"' => {
                    self.i += 1;
                    w.quoted = true;
                    w.any = true;
                    name_ok = false;
                    self.double_quoted(&mut w);
                }
                '`' => {
                    self.i += 1;
                    let start = self.i;
                    while let Some(c) = self.peek() {
                        if c == '\\' {
                            self.i += 2;
                            continue;
                        }
                        if c == '`' {
                            break;
                        }
                        self.i += 1;
                    }
                    let end = self.i.min(self.s.len());
                    let inner: String = self.s[start..end].iter().collect();
                    self.i = (self.i + 1).min(self.s.len());
                    self.out.nested.push(inner);
                    w.text.push_str(SUBST);
                    w.dynamic = true;
                    w.any = true;
                    name_ok = false;
                }
                '$' => {
                    w.any = true;
                    name_ok = false;
                    self.dollar(&mut w);
                }
                '=' if name_ok && w.assign_eq.is_none() && !w.text.is_empty() => {
                    if is_name(&w.text) {
                        w.assign_eq = Some(w.text.len());
                    }
                    w.text.push('=');
                    w.any = true;
                    self.i += 1;
                    name_ok = false;
                }
                _ => {
                    if !(c.is_ascii_alphanumeric() || c == '_') {
                        name_ok = false;
                    }
                    w.text.push(c);
                    w.any = true;
                    self.i += 1;
                }
            }
        }
        // `{` / `}` glued to text is part of the word; alone they are reserved.
        w
    }

    fn double_quoted(&mut self, w: &mut Word) {
        while let Some(c) = self.peek() {
            match c {
                '"' => {
                    self.i += 1;
                    return;
                }
                '\\' => {
                    self.i += 1;
                    match self.peek() {
                        Some(n @ ('$' | '`' | '"' | '\\')) => {
                            w.text.push(n);
                            self.i += 1;
                        }
                        Some('\n') => self.i += 1,
                        Some(_) => w.text.push('\\'),
                        None => {}
                    }
                }
                '$' => self.dollar(w),
                '`' => {
                    self.i += 1;
                    let start = self.i;
                    while let Some(c) = self.peek() {
                        if c == '\\' {
                            self.i += 2;
                            continue;
                        }
                        if c == '`' {
                            break;
                        }
                        self.i += 1;
                    }
                    let end = self.i.min(self.s.len());
                    let inner: String = self.s[start..end].iter().collect();
                    self.i = (self.i + 1).min(self.s.len());
                    self.out.nested.push(inner);
                    w.text.push_str(SUBST);
                    w.dynamic = true;
                }
                _ => {
                    w.text.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// At a `$`: a substitution, an ANSI-C string, or a variable reference.
    fn dollar(&mut self, w: &mut Word) {
        self.i += 1;
        match self.peek() {
            Some('(') => {
                self.i += 1;
                if self.peek() == Some('(') {
                    // $(( arithmetic ))
                    self.i += 1;
                    let _ = self.balanced(')');
                    if self.peek() == Some(')') {
                        self.i += 1;
                    }
                    w.text.push('0');
                    return;
                }
                let inner = self.balanced(')');
                self.out.nested.push(inner);
                w.text.push_str(SUBST);
                w.dynamic = true;
            }
            Some('\'') => {
                self.i += 1;
                w.quoted = true;
                while let Some(c) = self.peek() {
                    self.i += 1;
                    match c {
                        '\'' => break,
                        '\\' => {
                            let n = self.peek().unwrap_or('\\');
                            self.i += 1;
                            w.text.push(match n {
                                'n' => '\n',
                                't' => '\t',
                                'r' => '\r',
                                '0' => '\0',
                                other => other,
                            });
                        }
                        _ => w.text.push(c),
                    }
                }
            }
            _ => {
                let rest: Vec<char> = self.s[self.i..].iter().take(256).copied().collect();
                let (n, value) = self.read_var(&rest);
                if n == 0 {
                    w.text.push('$');
                    return;
                }
                match value {
                    Some(v) => w.text.push_str(&v),
                    None => {
                        w.text.push('$');
                        w.text.extend(&self.s[self.i..self.i + n]);
                    }
                }
                self.i += n;
            }
        }
    }

    fn finish(mut self) -> Script {
        // Resolve what each piped command reads, writer by writer.
        for k in 0..self.out.cmds.len() {
            if self.out.cmds[k].stdin.is_some() {
                continue;
            }
            if let Some(j) = self.pipe_from[k] {
                let input = producer_output(&self.out.cmds, &self.pipe_from, j, 0);
                self.out.cmds[k].stdin = Some(input);
            }
        }
        self.out
    }
}

/// What command `j` writes to stdout, as far as the guard can tell.
fn producer_output(cmds: &[Cmd], pipe_from: &[Option<usize>], j: usize, depth: usize) -> Input {
    let cmd = &cmds[j];
    let name = cmd
        .argv
        .first()
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_string())
        .unwrap_or_default();
    let passthrough = |cmds: &[Cmd]| -> Input {
        if let Some(s) = &cmds[j].stdin {
            return s.clone();
        }
        match pipe_from[j] {
            Some(i) if depth < 16 => producer_output(cmds, pipe_from, i, depth + 1),
            _ => Input::Unknown(name.clone()),
        }
    };
    match name.as_str() {
        "echo" => {
            let mut args = &cmd.argv[1..];
            while let Some(a) = args.first() {
                if a.len() > 1 && a.starts_with('-') && a[1..].chars().all(|c| "neE".contains(c)) {
                    args = &args[1..];
                } else {
                    break;
                }
            }
            let mut s = args.join(" ");
            s.push('\n');
            Input::Text(unescape_printf(&s))
        }
        "printf" => {
            let args = &cmd.argv[1..];
            let Some(fmt) = args.first() else {
                return Input::Text(String::new());
            };
            let mut rest = args[1..].iter();
            let mut out = String::new();
            let mut it = fmt.chars().peekable();
            while let Some(c) = it.next() {
                if c == '%' {
                    match it.next() {
                        Some('%') => out.push('%'),
                        Some(_) => out.push_str(rest.next().map(String::as_str).unwrap_or("")),
                        None => out.push('%'),
                    }
                } else {
                    out.push(c);
                }
            }
            for extra in rest {
                out.push_str(extra);
            }
            Input::Text(unescape_printf(&out))
        }
        "cat" => {
            let files: Vec<&String> = cmd.argv[1..]
                .iter()
                .filter(|a| !a.starts_with('-') || a.as_str() == "-")
                .collect();
            match files.as_slice() {
                [] => passthrough(cmds),
                [f] if f.as_str() == "-" => passthrough(cmds),
                [f] => Input::File((*f).clone()),
                _ => Input::Unknown("cat".into()),
            }
        }
        "tee" => passthrough(cmds),
        _ => Input::Unknown(name),
    }
}

fn unescape_printf(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some('n') => {
                    out.push('\n');
                    it.next();
                }
                Some('t') => {
                    out.push('\t');
                    it.next();
                }
                Some('\\') => {
                    out.push('\\');
                    it.next();
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A shell variable name.
pub fn is_name(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && it.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Splits a string into words the way `sh -c` would, without operators:
/// used for strings that are an argv already (`ssh host 'psql -c …'`).
#[cfg(test)]
pub fn words(src: &str) -> Vec<String> {
    parse(src, &|_| None)
        .cmds
        .into_iter()
        .flat_map(|c| c.argv)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(src: &str) -> Script {
        parse(src, &|_| None)
    }

    fn argvs(src: &str) -> Vec<Vec<String>> {
        p(src).cmds.into_iter().map(|c| c.argv).collect()
    }

    #[test]
    fn splits_operators() {
        assert_eq!(
            argvs("a 1 && b 2 || c; d & e | f |& g"),
            vec![
                vec!["a", "1"],
                vec!["b", "2"],
                vec!["c"],
                vec!["d"],
                vec!["e"],
                vec!["f"],
                vec!["g"]
            ]
        );
    }

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(
            words(r#"psql -c "DROP TABLE \"x\"" 'a b' c\ d $'e\nf'"#),
            vec!["psql", "-c", "DROP TABLE \"x\"", "a b", "c d", "e\nf"]
        );
    }

    #[test]
    fn env_prefix_and_reserved_words() {
        let s = p("PGPASSWORD=x PGHOST=db.prod psql -c 'select 1'");
        assert_eq!(
            s.cmds[0].assigns,
            vec![
                ("PGPASSWORD".into(), "x".into()),
                ("PGHOST".into(), "db.prod".into())
            ]
        );
        assert_eq!(s.cmds[0].argv, vec!["psql", "-c", "select 1"]);
        assert_eq!(
            argvs("if psql -c x; then echo ok; fi")[0],
            vec!["psql", "-c", "x"]
        );
        assert_eq!(argvs("time rails db:drop")[0], vec!["rails", "db:drop"]);
    }

    #[test]
    fn comments_are_skipped() {
        assert_eq!(
            argvs("echo hi # psql -c 'DROP TABLE x'"),
            vec![vec!["echo", "hi"]]
        );
        assert_eq!(argvs("echo a#b"), vec![vec!["echo", "a#b"]]);
    }

    #[test]
    fn heredoc_feeds_stdin() {
        let s = p("psql \"$URL\" <<'SQL'\nDROP TABLE users;\nSQL\necho done");
        assert_eq!(
            s.cmds[0].stdin,
            Some(Input::Text("DROP TABLE users;\n".into()))
        );
        assert_eq!(s.cmds[1].argv, vec!["echo", "done"]);
        let s = p("psql <<-EOF\n\tTRUNCATE t;\n\tEOF\n");
        assert_eq!(s.cmds[0].stdin, Some(Input::Text("TRUNCATE t;\n".into())));
    }

    #[test]
    fn heredoc_through_cat_pipe() {
        let s = p("cat <<EOF | psql\nDELETE FROM t;\nEOF");
        assert_eq!(
            s.cmds[1].stdin,
            Some(Input::Text("DELETE FROM t;\n".into()))
        );
    }

    #[test]
    fn pipes_from_echo_printf_cat() {
        let s = p("echo 'DROP TABLE x' | psql");
        assert_eq!(s.cmds[1].stdin, Some(Input::Text("DROP TABLE x\n".into())));
        let s = p("printf '%s;\\n' 'TRUNCATE a' | mysql");
        assert_eq!(s.cmds[1].stdin, Some(Input::Text("TRUNCATE a;\n".into())));
        let s = p("cat drop.sql | psql");
        assert_eq!(s.cmds[1].stdin, Some(Input::File("drop.sql".into())));
        let s = p("pg_dump src | psql dst");
        assert_eq!(s.cmds[1].stdin, Some(Input::Unknown("pg_dump".into())));
    }

    #[test]
    fn redirections() {
        let s = p("mysql app < dump.sql > out.txt 2>&1");
        assert_eq!(s.cmds[0].argv, vec!["mysql", "app"]);
        assert_eq!(s.cmds[0].stdin, Some(Input::File("dump.sql".into())));
        assert_eq!(s.cmds[0].writes, vec!["out.txt"]);
        let s = p("redis-cli <<< FLUSHALL");
        assert_eq!(s.cmds[0].stdin, Some(Input::Text("FLUSHALL\n".into())));
        let s = p("cmd &>log");
        assert_eq!(s.cmds[0].argv, vec!["cmd"]);
    }

    #[test]
    fn substitutions_are_nested() {
        let s = p("echo $(psql -c 'DROP TABLE a') `rails db:drop` x");
        assert_eq!(s.nested, vec!["psql -c 'DROP TABLE a'", "rails db:drop"]);
        assert!(s.cmds[0].dynamic);
        let s = p("diff <(psql -c 'select 1') b");
        assert_eq!(s.nested, vec!["psql -c 'select 1'"]);
    }

    #[test]
    fn variables_resolve_from_script_then_lookup() {
        let s = parse(
            "U=postgres://db.prod/app; psql \"$U\" -c \"$Q\" ${H:-local}",
            &|n| (n == "Q").then(|| "select 1".to_string()),
        );
        assert_eq!(
            s.cmds.last().unwrap().argv,
            vec!["psql", "postgres://db.prod/app", "-c", "select 1", "local"]
        );
        let s = p("psql $DATABASE_URL");
        assert_eq!(s.cmds[0].argv, vec!["psql", "$DATABASE_URL"]);
        let s = p("export A=1 B=2; source .env.production && x");
        assert_eq!(s.vars.get("B").map(String::as_str), Some("2"));
        assert_eq!(s.sourced, vec![".env.production"]);
    }

    #[test]
    fn subshells_and_groups() {
        assert_eq!(
            argvs("(cd app && npx prisma migrate reset) ; { rails db:drop; }"),
            vec![
                vec!["cd", "app"],
                vec!["npx", "prisma", "migrate", "reset"],
                vec!["rails", "db:drop"]
            ]
        );
    }

    #[test]
    fn line_continuation() {
        assert_eq!(argvs("psql \\\n  -c 'x'"), vec![vec!["psql", "-c", "x"]]);
    }

    #[test]
    fn unterminated_input_does_not_hang() {
        let _ = p("psql -c \"DROP");
        let _ = p("echo $(");
        let _ = p("cat <<EOF\nno end");
        let _ = p("a ${X");
        let _ = p("\\");
        let _ = p("`unterminated");
    }
}
