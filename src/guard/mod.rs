// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto guard`: checks the shell commands and MCP tool calls a coding
//! agent (Claude Code, Cursor, Codex) is about to run, and denies the
//! destructive database ones before they run. See `docs/guard.md`.
//!
//! The pieces:
//! - `shell` reads a command line into simple commands;
//! - `detect` finds SQL, ORM / migration, database-CLI and platform
//!   operations in them, and in MCP tool arguments;
//! - `sql` checks SQL with the embedded engine (offline, no network);
//! - `target` works out which database a command points at and whether it
//!   looks like production;
//! - this module turns findings into one verdict under `.vericto.toml`'s
//!   `[guard]` policy;
//! - `hook` speaks each agent's hook protocol, `install` writes the agents'
//!   hook configuration, `log` keeps the local decision log.
//!
//! A hook is a guardrail inside the agent's own process tree, not a
//! security boundary: see "Limits" in `docs/guard.md`.

pub mod cli;
pub mod config;
pub mod detect;
pub mod hook;
pub mod install;
pub mod log;
pub mod shell;
pub mod sql;
pub mod target;

use std::path::Path;

use serde_json::Value;

use config::{Act, GuardConfig, Loaded, Mode};
use target::{Class, Target};

/// How dangerous a finding is on its own, before the target and the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Harmless on a development database, worth a confirmation on
    /// production (applying migrations, SQL the guard cannot read).
    Sensitive,
    /// Can lose data (reverting migrations, dropping a column): asked.
    Medium,
    /// Loses data by design (DROP, TRUNCATE, DELETE without WHERE, ORM
    /// resets): denied.
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Sensitive => "sensitive",
            Severity::Medium => "medium",
            Severity::Critical => "critical",
        }
    }
}

/// Which pack produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Sql,
    Orm,
    Platform,
    Mcp,
    Internal,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Sql => "sql",
            Kind::Orm => "orm",
            Kind::Platform => "platform",
            Kind::Mcp => "mcp",
            Kind::Internal => "internal",
        }
    }
}

/// One thing the detectors found.
#[derive(Debug, Clone)]
pub struct Finding {
    /// `VERICTO-NNN` (engine rule) or `VG-NNN` (guard rule).
    pub code: String,
    pub severity: Severity,
    pub kind: Kind,
    /// What it does, in one line.
    pub title: String,
    /// The command it was found in (secrets removed).
    pub what: String,
    /// What to do instead.
    pub fix: String,
    pub targets: Vec<Target>,
    /// A setting that decides this finding's action (`high_sql`,
    /// `unverified_sql`) instead of its severity.
    pub preset: Option<Act>,
}

/// The guard's answer, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Allow,
    /// Allowed, with a message.
    Warn,
    /// A human confirms (where the agent supports it).
    Ask,
    Deny,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Warn => "warn",
            Verdict::Ask => "ask",
            Verdict::Deny => "deny",
        }
    }
}

/// A finding with the verdict the policy gave it.
#[derive(Debug, Clone)]
pub struct Applied {
    pub finding: Finding,
    pub verdict: Verdict,
    /// Some target looks like production.
    pub prod: bool,
    /// The `[[guard.allow]]` reason that allowed it.
    pub allowed_by: Option<String>,
}

/// The decision on one agent action.
#[derive(Debug, Clone)]
pub struct Decision {
    pub verdict: Verdict,
    pub applied: Vec<Applied>,
}

/// What the agent is about to do.
#[derive(Debug, Clone)]
pub enum Action {
    Shell(String),
    Mcp {
        server: String,
        tool: String,
        input: Value,
    },
}

impl Action {
    /// The text allow entries' `command` patterns are matched against.
    pub fn text(&self) -> String {
        match self {
            Action::Shell(c) => c.clone(),
            Action::Mcp {
                server,
                tool,
                input,
            } => format!("mcp:{server}/{tool} {input}"),
        }
    }
}

/// Runs the detectors on `action` (no decision yet).
pub fn analyze(
    action: &Action,
    cwd: &Path,
    loaded: &Loaded,
    env: &dyn Fn(&str) -> Option<String>,
) -> Vec<Finding> {
    let ctx = detect::Ctx::new(
        cwd.to_path_buf(),
        loaded.root.clone(),
        &loaded.config,
        &loaded.migration_paths,
        env,
    );
    match action {
        Action::Shell(c) => {
            if c.len() > 4 * 1024 * 1024 {
                // Too large to read reliably: the keyword reading only.
                return sql::keyword_check(c)
                    .map(|f| Finding {
                        code: f.code,
                        severity: f.severity,
                        kind: Kind::Internal,
                        title: format!("{} in a command too large to read in full", f.title),
                        what: "(command over 4 MiB)".into(),
                        fix: f.fix,
                        targets: Vec::new(),
                        preset: None,
                    })
                    .into_iter()
                    .collect();
            }
            detect::shell(&ctx, c)
        }
        Action::Mcp {
            server,
            tool,
            input,
        } => detect::mcp(&ctx, server, tool, input),
    }
}

/// Applies the policy to `findings`.
pub fn decide(findings: Vec<Finding>, cfg: &GuardConfig, action_text: &str) -> Decision {
    let mut applied = Vec::new();
    for f in findings {
        let prod = cfg.checks.prod_context && f.targets.iter().any(|t| t.class == Class::Prod);
        let all_local = !f.targets.is_empty() && f.targets.iter().all(|t| t.class == Class::Local);
        let mut v = match f.preset {
            Some(Act::Deny) => Verdict::Deny,
            Some(Act::Ask) => Verdict::Ask,
            Some(Act::Warn) => Verdict::Warn,
            Some(Act::Allow) => Verdict::Allow,
            None => match f.severity {
                Severity::Critical => Verdict::Deny,
                Severity::Medium => Verdict::Ask,
                Severity::Sensitive => Verdict::Allow,
            },
        };
        // Production: anything that can lose data is denied whatever the
        // mode; what only matters on production is asked.
        let floor = prod && f.severity >= Severity::Medium;
        if prod {
            v = if floor {
                Verdict::Deny
            } else {
                v.max(Verdict::Ask)
            };
        } else if cfg.allow_local && all_local && v >= Verdict::Ask {
            v = Verdict::Warn;
        }
        if !floor {
            v = match (cfg.mode, v) {
                (Mode::Ask, Verdict::Deny) => Verdict::Ask,
                (Mode::Warn, Verdict::Deny | Verdict::Ask) => Verdict::Warn,
                (_, v) => v,
            };
        }
        let mut allowed_by = None;
        if v > Verdict::Allow {
            if let Some(a) = cfg.allow.iter().find(|a| {
                (!prod || a.prod)
                    && a.rule
                        .as_deref()
                        .map(|r| config::glob_match(r, &f.code))
                        .unwrap_or(true)
                    && a.command
                        .as_deref()
                        .map(|c| config::glob_match(c, action_text.trim()))
                        .unwrap_or(true)
            }) {
                v = Verdict::Allow;
                allowed_by = Some(a.reason.clone());
            }
        }
        applied.push(Applied {
            finding: f,
            verdict: v,
            prod,
            allowed_by,
        });
    }
    let verdict = applied
        .iter()
        .map(|a| a.verdict)
        .max()
        .unwrap_or(Verdict::Allow);
    Decision { verdict, applied }
}

/// Analyze and decide.
pub fn evaluate(
    action: &Action,
    cwd: &Path,
    loaded: &Loaded,
    env: &dyn Fn(&str) -> Option<String>,
) -> Decision {
    let findings = analyze(action, cwd, loaded, env);
    decide(findings, &loaded.config, &action.text())
}

impl Decision {
    /// The findings that decided the verdict, strongest first.
    pub fn deciding(&self) -> Vec<&Applied> {
        let mut v: Vec<&Applied> = self
            .applied
            .iter()
            .filter(|a| a.verdict == self.verdict && a.verdict > Verdict::Allow)
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.finding.severity));
        v
    }

    /// The message the agent reads: what, why, the rule code and the fix,
    /// so it can correct itself. At most three findings.
    pub fn agent_message(&self, verdict: Verdict) -> String {
        let head = match verdict {
            Verdict::Deny => "vericto guard blocked this command",
            Verdict::Ask => "vericto guard wants a human to confirm this command",
            _ => "vericto guard warning",
        };
        let mut s = format!("{head}:");
        let deciding = self.deciding();
        for a in deciding.iter().take(3) {
            let f = &a.finding;
            s.push_str(&format!(
                "\n- [{}] {}.",
                f.code,
                f.title.trim_end_matches('.')
            ));
            if let Some(t) = f.targets.iter().max_by_key(|t| t.class) {
                if t.class != Class::Unknown {
                    s.push_str(&format!(" Target: {}.", t.describe()));
                }
            }
            if !f.fix.is_empty() {
                s.push_str(&format!(" Fix: {}", f.fix));
            }
        }
        if deciding.len() > 3 {
            s.push_str(&format!("\n- and {} more", deciding.len() - 3));
        }
        if verdict == Verdict::Deny {
            s.push_str("\nIf the fix fits what the user asked for, use it. Do not retry the same operation in another form (another tool, a script, a different spelling); if the user wants it run as is, tell them what it does and let them run it themselves.");
        }
        s
    }

    /// The short line the user sees.
    pub fn user_message(&self, verdict: Verdict) -> String {
        let codes: Vec<String> = self
            .deciding()
            .iter()
            .map(|a| a.finding.code.clone())
            .collect();
        let prod = self.deciding().iter().any(|a| a.prod);
        let first = self
            .deciding()
            .first()
            .map(|a| a.finding.title.clone())
            .unwrap_or_default();
        let what = match verdict {
            Verdict::Deny => "blocked",
            Verdict::Ask => "asks about",
            _ => "warns about",
        };
        let mut s = format!("vericto guard {what} [{}] {first}", codes.join(", "));
        if prod {
            s.push_str(" (production target)");
        }
        if verdict == Verdict::Deny {
            s.push_str(". To allow it on purpose, add a [[guard.allow]] entry with a reason to .vericto.toml; `vericto guard log` shows recent decisions.");
        }
        s
    }
}

#[cfg(test)]
mod tests;
