// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! Hard mode's deny rules (`VG-7xx`): with the database URL moved into the
//! OS keychain and the agent given `vericto-proxy mcp` instead, these close
//! the obvious ways around it.
//!
//! - `VG-701` a direct database client (`psql`, `mysql`, `pg_dump`, …);
//! - `VG-702` reading a credential file (`.env*`, `~/.pgpass`, `~/.my.cnf`,
//!   the proxy's URL files, the guard's backups);
//! - `VG-703` reading the OS credential store (`security
//!   find-generic-password`, `secret-tool`, `cmdkey`, PowerShell credential
//!   cmdlets);
//! - `VG-704` changing the credential store or the guard itself
//!   (`vericto-proxy mcp credential set|delete`, `vericto guard uninstall`,
//!   writing `.vericto.toml` or the agents' hook and MCP files from a shell).
//!
//! They apply when `[guard] hard = true` or the hook runs with `--hard`
//! (what `vericto guard install --hard` writes), and they are denied in every
//! `mode`: only a `[[guard.allow]]` entry with a reason opens one.

use serde_json::Value;

use super::{Finding, Kind, Severity};

fn finding(code: &str, title: String, what: &str, fix: &str) -> Finding {
    Finding {
        code: code.to_string(),
        severity: Severity::Critical,
        kind: Kind::Hard,
        title,
        what: super::target::redact(what),
        fix: fix.to_string(),
        targets: Vec::new(),
        preset: None,
    }
}

const FIX_MCP: &str = "Hard mode is on: query the database through the Vericto MCP server's execute_sql tool (it holds the credential and checks every statement). If the user needs this command, let them run it themselves.";
const FIX_FILE: &str = "Hard mode is on: this file holds database credentials the agent must not read. Use the Vericto MCP server for the database; for other settings, ask the user.";
const FIX_STORE: &str = "Hard mode is on: the OS credential store holds the database URL the Vericto MCP server uses; the agent does not read or change it. Ask the user.";

/// Database clients that connect with a credential of their own.
const DB_CLIENTS: &[&str] = &[
    "psql",
    "pg_dump",
    "pg_dumpall",
    "pg_restore",
    "pg_basebackup",
    "pgcli",
    "mysql",
    "mariadb",
    "mysqldump",
    "mariadb-dump",
    "mysqlpump",
    "mysqlsh",
    "mysqlimport",
    "mariadb-import",
    "mysqladmin",
    "mariadb-admin",
    "mycli",
    "sqlcmd",
    "usql",
];

/// Template files that hold placeholders, not secrets.
const TEMPLATE_SUFFIXES: &[&str] = &[
    "example", "sample", "template", "dist", "defaults", "schema", "tmpl", "tpl",
];

/// What kind of credential file `path` is, if it is one (matched on the file
/// name and a few directories, so `~/.pgpass`, `$HOME/.pgpass` and
/// `/Users/me/.pgpass` all match).
pub fn credential_file(path: &str) -> Option<&'static str> {
    let p = path.trim().replace('\\', "/");
    let p = p.trim_end_matches('/');
    if p.contains("/.config/vericto/") || p.starts_with(".config/vericto/") {
        return Some("a Vericto configuration or URL file");
    }
    if p.starts_with("/run/secrets/") {
        return Some("a secret file");
    }
    if p.contains("/vericto/guard-backups/") {
        return Some("a vericto guard backup");
    }
    let name = p.rsplit('/').next().unwrap_or(p);
    if name.contains(".vericto-backup-") {
        return Some("a vericto guard backup");
    }
    if name.contains(['*', '?', '[']) {
        // A glob: `.env*` matches `.env` (globs skip dot files unless the
        // pattern starts with a dot).
        if !name.starts_with('.') {
            return None;
        }
        return [
            ".env",
            ".env.local",
            ".env.production",
            ".envrc",
            ".pgpass",
            ".my.cnf",
        ]
        .iter()
        .find(|c| super::config::glob_match(name, c))
        .and_then(|c| credential_file(c));
    }
    match name {
        ".env" | ".envrc" => Some("an env file"),
        ".pgpass" | "pgpass.conf" => Some("a PostgreSQL password file"),
        ".my.cnf" | ".mylogin.cnf" => Some("a MySQL option file"),
        _ => {
            let rest = name.strip_prefix(".env.")?;
            let last = rest.rsplit('.').next().unwrap_or(rest);
            if rest.is_empty() || TEMPLATE_SUFFIXES.contains(&last.to_ascii_lowercase().as_str()) {
                None
            } else {
                Some("an env file")
            }
        }
    }
}

/// Programs whose arguments may name a credential file without printing or
/// copying it (listing, permissions, deleting, `.gitignore` lines), and
/// launchers that load an env file into a program, as the application itself
/// would.
const SAFE_WITH_FILES: &[&str] = &[
    "ls",
    "stat",
    "test",
    "[",
    "[[",
    "file",
    "touch",
    "chmod",
    "chown",
    "chgrp",
    "rm",
    "unlink",
    "echo",
    "printf",
    "mkdir",
    "which",
    "type",
    "du",
    "realpath",
    "readlink",
    "basename",
    "dirname",
    "wc",
    "find",
    "fd",
    "dotenv",
    "dotenvx",
    "env-cmd",
    "direnv",
    "docker",
    "podman",
    "docker-compose",
    "code",
    "cursor",
    "open",
    "vericto",
];

/// Files the agent must not change from a shell in hard mode (the guard's
/// policy and the agents' hook and MCP configuration).
const PROTECTED: &[&str] = &[
    ".vericto.toml",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude.json",
    ".mcp.json",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    ".codex/hooks.json",
    ".codex/config.toml",
];

fn protected(path: &str) -> Option<&'static str> {
    let p = path.trim().replace('\\', "/");
    PROTECTED
        .iter()
        .find(|s| p == **s || p.ends_with(&format!("/{s}")))
        .copied()
}

/// The values an argument can carry a path in: itself, and what follows `=`
/// (`--env-file=.env`) or `:` (`HEAD:.env`); `-e.env` is not split.
fn arg_paths(a: &str) -> Vec<&str> {
    let mut v = vec![a];
    if let Some((_, val)) = a.split_once('=') {
        v.push(val);
    }
    // `git show HEAD:.env`, `scp host:.pgpass .`
    if !a.contains("://") {
        if let Some((_, val)) = a.rsplit_once(':') {
            v.push(val);
        }
    }
    v
}

/// The hard-mode rules for one command after its launchers were unwrapped
/// (or at each launcher level: `sudo psql` is seen as `sudo …` then `psql`).
pub fn exec(argv: &[String], stdin_file: Option<&str>, prog: &str, out: &mut Vec<Finding>) {
    let shown = argv.join(" ");
    let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    let only_info = !args.is_empty()
        && args
            .iter()
            .all(|a| matches!(*a, "--version" | "-V" | "--help" | "-?" | "--usage"));
    if DB_CLIENTS.contains(&prog) && !only_info {
        out.push(finding(
            "VG-701",
            format!("Direct database client `{prog}` (hard mode)"),
            &shown,
            FIX_MCP,
        ));
        return;
    }
    // OS credential stores.
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .copied()
        .unwrap_or("");
    let store = match prog {
        "security" => {
            sub.contains("password")
                || matches!(
                    sub,
                    "dump-keychain" | "export" | "set-key-partition-list" | "find-certificate"
                )
        }
        "secret-tool" | "cmdkey" | "vaultcmd" | "kwallet-query" | "kwalletcli" => true,
        "keyring" => matches!(sub, "get" | "set" | "del"),
        "powershell" | "pwsh" => {
            let l = shown.to_ascii_lowercase();
            [
                "get-storedcredential",
                "passwordvault",
                "credread",
                "credentialmanager",
                "get-secret",
                "vaultcmd",
                "cmdkey",
            ]
            .iter()
            .any(|k| l.contains(k))
        }
        _ => false,
    };
    if store && !only_info {
        out.push(finding(
            "VG-703",
            format!("Reads or changes the OS credential store (`{prog} {sub}`, hard mode)"),
            &shown,
            FIX_STORE,
        ));
        return;
    }
    // The keychain entry and the guard itself.
    if prog == "vericto-proxy" {
        let w: Vec<&str> = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .copied()
            .collect();
        if w.len() >= 3 && w[0] == "mcp" && w[1] == "credential" && matches!(w[2], "set" | "delete")
        {
            out.push(finding(
                "VG-704",
                format!(
                    "Changes the keychain entry of the Vericto MCP server (`credential {}`, hard mode)",
                    w[2]
                ),
                &shown,
                FIX_STORE,
            ));
            return;
        }
    }
    if prog == "vericto" {
        let w: Vec<&str> = args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .copied()
            .collect();
        if w.len() >= 2 && w[0] == "guard" && w[1] == "uninstall" {
            out.push(finding(
                "VG-704",
                "Removes vericto guard (hard mode)".to_string(),
                &shown,
                "Hard mode is on: only the user removes the guard. Ask them.",
            ));
            return;
        }
    }
    // Writes to the policy or the agents' configuration through a program.
    let writes_files = match prog {
        "tee" | "cp" | "mv" | "install" | "truncate" | "ln" | "rm" | "dd" => true,
        "sed" | "perl" | "gsed" => args
            .iter()
            .any(|a| a.starts_with("-i") || *a == "--in-place"),
        _ => false,
    };
    if writes_files {
        if let Some(p) = args.iter().flat_map(|a| arg_paths(a)).find_map(protected) {
            out.push(protected_finding(p, &shown));
            return;
        }
    }
    // Credential files.
    if let Some(f) = stdin_file {
        if let Some(what) = credential_file(f) {
            out.push(file_finding(what, f, &shown));
            return;
        }
    }
    if SAFE_WITH_FILES.contains(&prog) {
        return;
    }
    if prog == "git"
        && matches!(
            sub,
            "check-ignore" | "status" | "ls-files" | "rm" | "mv" | "add" | "restore" | "clean"
        )
    {
        return;
    }
    if let Some((f, what)) = args
        .iter()
        .flat_map(|a| arg_paths(a))
        .find_map(|p| credential_file(p).map(|w| (p, w)))
    {
        out.push(file_finding(what, f, &shown));
    }
}

fn file_finding(what: &str, file: &str, shown: &str) -> Finding {
    finding(
        "VG-702",
        format!("Reads {what} (`{file}`, hard mode)"),
        shown,
        FIX_FILE,
    )
}

fn protected_finding(p: &str, shown: &str) -> Finding {
    finding(
        "VG-704",
        format!("Changes `{p}` from a shell (hard mode)"),
        shown,
        "Hard mode is on: the guard's policy and the agents' hook and MCP configuration are changed by the user, not the agent. Ask them.",
    )
}

/// Redirections: `> .vericto.toml`, `>> ~/.claude/settings.json`.
pub fn writes(writes: &[String], shown: &str, out: &mut Vec<Finding>) {
    if let Some(p) = writes.iter().find_map(|w| protected(w)) {
        out.push(protected_finding(p, shown));
    }
}

/// A file the agent's read tool is about to open (Cursor `beforeReadFile`).
pub fn read(path: &str, out: &mut Vec<Finding>) {
    if let Some(what) = credential_file(path) {
        out.push(file_finding(what, path, &format!("read {path}")));
    }
}

/// MCP tool arguments that name a credential file (`read_file {"path":
/// ".env"}` on a filesystem server).
pub fn mcp(server: &str, tool: &str, input: &Value, out: &mut Vec<Finding>) {
    fn walk(v: &Value, depth: usize, hits: &mut Vec<String>) {
        if depth > 8 {
            return;
        }
        match v {
            Value::String(s) if s.len() < 4096 => {
                let p = s.strip_prefix("file://").unwrap_or(s);
                if credential_file(p).is_some() {
                    hits.push(p.to_string());
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, depth + 1, hits)),
            Value::Object(o) => o.values().for_each(|x| walk(x, depth + 1, hits)),
            _ => {}
        }
    }
    let mut hits = Vec::new();
    walk(input, 0, &mut hits);
    if let Some(p) = hits.first() {
        let what = credential_file(p).unwrap_or("a credential file");
        out.push(file_finding(what, p, &format!("mcp:{server}/{tool}")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_files() {
        for p in [
            ".env",
            "./.env",
            "/srv/app/.env.local",
            ".env.production",
            ".env.development.local",
            ".envrc",
            "~/.pgpass",
            "/Users/me/.pgpass",
            "C:\\Users\\me\\AppData\\Roaming\\postgresql\\pgpass.conf",
            "$HOME/.my.cnf",
            "/home/me/.mylogin.cnf",
            "/Users/me/.config/vericto/shop.url",
            "/run/secrets/db.url",
            ".env*",
            ".env.vericto-backup-1700000000",
            ".mcp.json.vericto-backup-1700000000",
            "/Users/me/Library/Application Support/vericto/guard-backups/x",
        ] {
            assert!(credential_file(p).is_some(), "{p}");
        }
        for p in [
            ".env.example",
            ".env.sample",
            ".env.local.example",
            ".env.template",
            "env.ts",
            "src/env.rs",
            ".environment",
            "README.md",
            "*",
            "*.sql",
            "my.cnf.d",
            ".envoy.yaml",
        ] {
            assert!(credential_file(p).is_none(), "{p}");
        }
    }
}
