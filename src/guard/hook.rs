// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The three agents' hook protocols (checked against their docs on
//! 2026-11-15; see `docs/guard.md` for the sources).
//!
//! - **Claude Code** `PreToolUse` (matcher `Bash|mcp__.*`): JSON on stdin with
//!   `tool_name`, `tool_input`, `cwd`, `permission_mode`. Deny: a
//!   `hookSpecificOutput` with `permissionDecision: "deny"` and the reason on
//!   stdout, the reason on stderr, exit 2 (a block even if the JSON were not
//!   read; the JSON's reason is the one Claude sees). Ask: the same object
//!   with `"ask"`, exit 0. Allow: nothing, exit 0, so Claude's own permission
//!   rules still apply (the guard never answers `allow`).
//! - **Cursor** `beforeShellExecution` / `beforeMCPExecution`: `command` /
//!   `tool_name` + `tool_input` (a JSON string) + `mcp_server_name`. Always
//!   answers `{"permission": …}` with `agent_message` / `user_message`, exit 0
//!   (Cursor reads no output as a failure). `beforeReadFile` (hard mode
//!   only): `file_path`; answered with `permission` and `user_message`.
//! - **Codex** `PreToolUse` (matcher `Bash|mcp__.*`): like Claude's input.
//!   Deny: the reason on stderr, exit 2. Codex does not support `ask` in
//!   PreToolUse yet (it treats it as a failed hook and runs the tool), so an
//!   ask is a deny that says a human must run it.

use serde_json::{json, Value};

use super::{Action, Decision, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Cursor,
    Codex,
}

impl Agent {
    pub fn as_str(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Cursor => "cursor",
            Agent::Codex => "codex",
        }
    }
}

/// What a hook input asks about.
#[derive(Debug, Clone)]
pub struct HookInput {
    /// `None`: a tool the guard does not check (Read, Edit…): allowed.
    pub action: Option<Action>,
    pub cwd: Option<String>,
    /// Nobody can answer a prompt (Claude `bypassPermissions` / `dontAsk`):
    /// an ask becomes a deny.
    pub unattended: bool,
    pub session: Option<String>,
    pub event: String,
    pub tool: String,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(String::from)
}

/// A shell command given as a string or as an argv array.
fn command_of(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(c) => Some(c.clone()),
        Value::Array(a) => {
            let words: Vec<String> = a
                .iter()
                .filter_map(|x| x.as_str().map(super::detect::shell_quote))
                .collect();
            Some(words.join(" "))
        }
        _ => None,
    }
}

/// Reads an agent's hook input.
pub fn parse_input(agent: Agent, v: &Value) -> Result<HookInput, String> {
    if !v.is_object() {
        return Err("hook input is not a JSON object".into());
    }
    let event = s(v, "hook_event_name").unwrap_or_default();
    let tool = s(v, "tool_name").unwrap_or_default();
    let mut out = HookInput {
        action: None,
        cwd: s(v, "cwd").filter(|c| !c.is_empty()),
        unattended: false,
        session: s(v, "session_id").or_else(|| s(v, "conversation_id")),
        event: event.clone(),
        tool: tool.clone(),
    };
    match agent {
        Agent::Claude | Agent::Codex => {
            let mode = s(v, "permission_mode").unwrap_or_default();
            out.unattended = matches!(mode.as_str(), "bypassPermissions" | "dontAsk");
            let input = v.get("tool_input").cloned().unwrap_or(Value::Null);
            if matches!(
                tool.as_str(),
                "Bash"
                    | "shell"
                    | "exec_command"
                    | "local_shell"
                    | "container.exec"
                    | "unified_exec"
            ) {
                let cmd = command_of(input.get("command").or_else(|| input.get("cmd")))
                    .ok_or_else(|| format!("{tool} input has no command"))?;
                out.action = Some(Action::Shell(cmd));
                if let Some(wd) = s(&input, "workdir").or_else(|| s(&input, "cwd")) {
                    out.cwd = Some(wd);
                }
            } else if let Some((server, t)) = super::detect::split_mcp_name(&tool) {
                let server = v
                    .get("mcp_server")
                    .and_then(|m| m.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or(server)
                    .to_string();
                out.action = Some(Action::Mcp {
                    server,
                    tool: t.to_string(),
                    input,
                });
            }
        }
        Agent::Cursor => {
            if out.cwd.is_none() {
                out.cwd = v
                    .get("workspace_roots")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .map(String::from);
            }
            match event.as_str() {
                "beforeShellExecution" => {
                    let cmd = s(v, "command").ok_or("beforeShellExecution input has no command")?;
                    out.action = Some(Action::Shell(cmd));
                }
                "beforeMCPExecution" => {
                    let input = match v.get("tool_input") {
                        Some(Value::String(t)) => {
                            serde_json::from_str(t).unwrap_or(Value::String(t.clone()))
                        }
                        Some(other) => other.clone(),
                        None => Value::Null,
                    };
                    let server = s(v, "mcp_server_name")
                        .or_else(|| s(v, "url"))
                        .or_else(|| s(v, "command"))
                        .unwrap_or_default();
                    out.action = Some(Action::Mcp {
                        server,
                        tool: tool.clone(),
                        input,
                    });
                }
                "beforeReadFile" => {
                    // `content` (the whole file) is never kept.
                    let path = s(v, "file_path").ok_or("beforeReadFile input has no file_path")?;
                    out.action = Some(Action::ReadFile(path));
                }
                "preToolUse" => {
                    let input = v.get("tool_input").cloned().unwrap_or(Value::Null);
                    if tool == "Shell" {
                        if let Some(c) = command_of(input.get("command")) {
                            out.action = Some(Action::Shell(c));
                        }
                        if let Some(wd) = s(&input, "working_directory") {
                            out.cwd = Some(wd);
                        }
                    } else if let Some(t) = tool.strip_prefix("MCP:") {
                        out.action = Some(Action::Mcp {
                            server: String::new(),
                            tool: t.to_string(),
                            input,
                        });
                    }
                }
                _ => {}
            }
        }
    }
    Ok(out)
}

/// The verdict the agent can act on: an ask where nobody can answer, or
/// where the agent has no ask, is a deny.
pub fn effective(agent: Agent, verdict: Verdict, input: &HookInput) -> Verdict {
    match verdict {
        Verdict::Ask if agent == Agent::Codex || input.unattended => Verdict::Deny,
        Verdict::Ask if agent == Agent::Cursor && input.event == "preToolUse" => Verdict::Deny,
        v => v,
    }
}

/// What the hook prints and its exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit: u8,
}

/// Renders a decision in `agent`'s format. `asked_as_deny`: an ask turned
/// into a deny by `effective` (the message says a human must run it).
pub fn render(agent: Agent, d: &Decision, verdict: Verdict, original: Verdict) -> Output {
    let mut agent_msg = d.agent_message(verdict);
    if verdict == Verdict::Deny && original == Verdict::Ask {
        agent_msg = d.agent_message(Verdict::Ask).replace(
            "wants a human to confirm this command",
            "blocked this command because it needs a human to confirm it and this agent cannot ask",
        );
        agent_msg.push_str("\nTell the user what the command does and let them run it themselves.");
    }
    let user_msg = d.user_message(verdict);
    match agent {
        Agent::Claude => match verdict {
            Verdict::Allow => Output { stdout: None, stderr: None, exit: 0 },
            Verdict::Warn => Output {
                stdout: Some(
                    json!({
                        "systemMessage": user_msg,
                        "hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": agent_msg}
                    })
                    .to_string(),
                ),
                stderr: None,
                exit: 0,
            },
            Verdict::Ask => Output {
                stdout: Some(
                    json!({
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "ask",
                            "permissionDecisionReason": agent_msg
                        }
                    })
                    .to_string(),
                ),
                stderr: None,
                exit: 0,
            },
            Verdict::Deny => Output {
                stdout: Some(
                    json!({
                        "systemMessage": user_msg,
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": agent_msg
                        }
                    })
                    .to_string(),
                ),
                stderr: Some(agent_msg),
                exit: 2,
            },
        },
        Agent::Cursor => {
            let v = match verdict {
                Verdict::Allow => json!({"permission": "allow"}),
                Verdict::Warn => json!({"permission": "allow", "user_message": user_msg, "agent_message": agent_msg}),
                Verdict::Ask => json!({"permission": "ask", "user_message": user_msg, "agent_message": agent_msg}),
                Verdict::Deny => json!({"permission": "deny", "user_message": user_msg, "agent_message": agent_msg}),
            };
            Output { stdout: Some(v.to_string()), stderr: None, exit: 0 }
        }
        Agent::Codex => match verdict {
            Verdict::Allow | Verdict::Warn => Output { stdout: None, stderr: None, exit: 0 },
            // Ask never reaches here (effective), but stay safe.
            Verdict::Ask | Verdict::Deny => Output { stdout: None, stderr: Some(agent_msg), exit: 2 },
        },
    }
}

/// The answer when the input itself cannot be read: deny if the raw text
/// carries an obviously destructive statement, allow otherwise (an agent
/// update that changes the schema must not block every command).
pub fn render_unreadable(agent: Agent, raw: &str, err: &str) -> (Output, Verdict) {
    let destructive = {
        let l = raw
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        ["drop table", "drop database", "drop schema", "truncate "]
            .iter()
            .any(|k| l.contains(k))
            || [
                "migrate reset",
                "db:drop",
                "db:reset",
                "migrate:fresh",
                "db:wipe",
                "flushall",
                "dropdb ",
                "--force-reset",
                "schema:drop",
                "downgrade base",
                "flyway clean",
                "drop-all",
                "dropall",
            ]
            .iter()
            .any(|k| l.contains(k))
    };
    let msg = format!("vericto guard could not read the hook input ({err})");
    if destructive {
        let reason = format!("{msg}, and it contains a destructive database operation [VG-901], so it is blocked. Tell the user.");
        let out = match agent {
            Agent::Claude => Output {
                stdout: Some(json!({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}).to_string()),
                stderr: Some(reason),
                exit: 2,
            },
            Agent::Cursor => Output { stdout: Some(json!({"permission": "deny", "user_message": reason, "agent_message": reason}).to_string()), stderr: None, exit: 0 },
            Agent::Codex => Output { stdout: None, stderr: Some(reason), exit: 2 },
        };
        (out, Verdict::Deny)
    } else {
        let note = format!("{msg}; allowed. Run `vericto guard status`.");
        let out = match agent {
            Agent::Claude => Output {
                stdout: Some(json!({"systemMessage": note}).to_string()),
                stderr: None,
                exit: 0,
            },
            Agent::Cursor => Output {
                stdout: Some(json!({"permission": "allow", "user_message": note}).to_string()),
                stderr: None,
                exit: 0,
            },
            Agent::Codex => Output {
                stdout: None,
                stderr: Some(note),
                exit: 0,
            },
        };
        (out, Verdict::Allow)
    }
}
