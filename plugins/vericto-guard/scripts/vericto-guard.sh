#!/bin/sh
# SPDX-FileCopyrightText: 2026 Vericto S.A.S.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Claude Code PreToolUse hook of the vericto-guard plugin. It runs
# `vericto guard hook --agent claude`, which reads the hook JSON on stdin and
# answers in Claude Code's format (see docs/guard.md).
#
# When the vericto CLI is missing (or too old to have `guard`), the hook lets
# the tool call through and shows a warning on every checked call, so
# installing the plugin before the CLI does not stop Claude from working.
# Set VERICTO_GUARD_REQUIRE_CLI=1 to block instead (fail closed).
# VERICTO_BIN points at a specific binary.

bin="${VERICTO_BIN:-}"
if [ -z "$bin" ]; then
  bin=$(command -v vericto 2>/dev/null || true)
fi
if [ -z "$bin" ]; then
  for c in "$HOME/.cargo/bin/vericto" /opt/homebrew/bin/vericto /usr/local/bin/vericto \
           "$HOME/.local/bin/vericto" "$HOME/.npm-global/bin/vericto" "$HOME/.volta/bin/vericto"; do
    if [ -x "$c" ]; then
      bin=$c
      break
    fi
  done
fi

problem=""
if [ -z "$bin" ]; then
  problem="the vericto CLI is not installed"
elif ! "$bin" guard hook --help >/dev/null 2>&1; then
  problem="the installed vericto CLI ($bin) is older than 2.4.0 and has no guard command"
fi

if [ -z "$problem" ]; then
  exec "$bin" guard hook --agent claude
fi

msg="vericto guard: $problem, so database commands are NOT being checked. Install or upgrade it: npm install -g @vericto/vericto-cli | brew install vericto/tap/vericto | scoop install vericto/vericto (then start a new session)."
if [ "${VERICTO_GUARD_REQUIRE_CLI:-0}" = "1" ]; then
  printf '%s\n' "$msg (VERICTO_GUARD_REQUIRE_CLI=1 blocks every checked call until then.)" >&2
  exit 2
fi
printf '{"systemMessage":"%s"}\n' "$msg"
exit 0
