// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The one-time "connect your workspace" tip after an offline check.
//!
//! After an interactive `vericto check` that ran offline without any
//! credential and produced a result, the CLI prints one line on stderr
//! pointing at the free workspace signup, once per user on this machine. A
//! marker file next to the config file (`<config dir>/vericto/connect-nudge-shown`)
//! remembers it was shown.
//!
//! It makes no network request and sends nothing anywhere: the link carries
//! UTM parameters and the CLI version, and only the person who opens it in a
//! browser tells the site anything. Stdout and the exit code are untouched,
//! and a marker that cannot be written is ignored (the tip is then skipped,
//! so a read-only config directory never makes it repeat on every run).
//!
//! Every input the decision reads (environment, terminal, flags) goes through
//! [`Context`], so the decision is tested without a real terminal.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The marker file's name, in the config directory.
pub const STATE_FILE: &str = "connect-nudge-shown";

/// Where the tip sends people. `vericto.com/connect` does not exist;
/// `vericto.com/register` redirects here.
pub const SIGNUP_URL: &str = "https://app.vericto.com/register";

/// CI providers not in `offline::CI_ENV_VARS` (most of them also set `CI`).
const EXTRA_CI_ENV_VARS: &[&str] = &[
    "TRAVIS",
    "APPVEYOR",
    "DRONE",
    "SEMAPHORE",
    "BITRISE_IO",
    "CIRRUS_CI",
    "HARNESS_BUILD_ID",
];

/// What the decision depends on, gathered by the caller.
pub struct Context<'a> {
    /// Whether stderr, where the tip goes, is a terminal.
    pub stderr_is_terminal: bool,
    /// Whether the run used the default `--format text`.
    pub text_format: bool,
    /// `--quiet`.
    pub quiet: bool,
    /// Any credential present: an API key (flag, env or `vericto login`), an
    /// OIDC setup or token, or a workspace id.
    pub authenticated: bool,
    /// Reads an environment variable (`std::env::var_os` outside tests).
    pub var: &'a dyn Fn(&str) -> Option<OsString>,
}

/// The tip's text for this CLI version.
pub fn message(version: &str) -> String {
    format!(
        "Tip: connect a free Vericto workspace to keep a history of checks and share rules \
         with your team: {SIGNUP_URL}?utm_source=cli&utm_medium=nudge&utm_campaign=first-check&v={version}"
    )
}

/// A variable is set when it is present and not empty, `0` or `false`.
fn flag_set(ctx: &Context, name: &str) -> bool {
    match (ctx.var)(name) {
        Some(v) => {
            let v = v.to_string_lossy();
            let v = v.trim();
            !(v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false"))
        }
        None => false,
    }
}

/// Whether this run may show the tip, before looking at the marker file.
pub fn allowed(ctx: &Context) -> bool {
    if !ctx.stderr_is_terminal || !ctx.text_format || ctx.quiet || ctx.authenticated {
        return false;
    }
    if flag_set(ctx, "VERICTO_NO_NUDGE") || flag_set(ctx, "DO_NOT_TRACK") {
        return false;
    }
    // Any CI marker: the list that keeps a CI job without credentials from
    // going offline on its own, plus a few providers that only matter here.
    !crate::offline::CI_ENV_VARS
        .iter()
        .chain(EXTRA_CI_ENV_VARS)
        .any(|v| (ctx.var)(v).is_some_and(|x| !x.is_empty()))
}

/// The marker file's path: next to `config.toml`. None if no config
/// directory resolves.
pub fn state_path() -> Option<PathBuf> {
    Some(crate::config::config_path()?.parent()?.join(STATE_FILE))
}

/// Records that the tip is shown: creates the marker, failing if it already
/// exists, so two runs at once cannot both show it.
fn claim(path: &Path, version: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        crate::config::create_private_dir(dir)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    writeln!(f, "shown_by = \"vericto {version}\"")
}

/// Shows the tip on `out` if `ctx` allows it and the marker at `state` can be
/// created now. Returns whether it was shown. Never fails: a write error just
/// means no tip.
pub fn maybe_show(ctx: &Context, state: Option<&Path>, version: &str, out: &mut dyn Write) -> bool {
    if !allowed(ctx) {
        return false;
    }
    let Some(path) = state else {
        return false;
    };
    if claim(path, version).is_err() {
        return false;
    }
    writeln!(out, "{}", message(version)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const VERSION: &str = "9.9.9";

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, OsString> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect()
    }

    /// An interactive, unauthenticated, text-format run with `vars` set.
    fn run(vars: &HashMap<String, OsString>, tweak: impl FnOnce(&mut Context)) -> bool {
        let get = |k: &str| vars.get(k).cloned();
        let mut ctx = Context {
            stderr_is_terminal: true,
            text_format: true,
            quiet: false,
            authenticated: false,
            var: &get,
        };
        tweak(&mut ctx);
        allowed(&ctx)
    }

    #[test]
    fn allowed_on_an_interactive_offline_run() {
        assert!(run(&env(&[]), |_| {}));
        // Opt-outs set to a false value do not opt out.
        assert!(run(
            &env(&[("VERICTO_NO_NUDGE", "0"), ("DO_NOT_TRACK", "false")]),
            |_| {}
        ));
        // An empty CI variable is not CI.
        assert!(run(&env(&[("CI", "")]), |_| {}));
    }

    #[test]
    fn suppressed_in_ci() {
        for var in crate::offline::CI_ENV_VARS.iter().chain(EXTRA_CI_ENV_VARS) {
            assert!(!run(&env(&[(var, "true")]), |_| {}), "{var}");
        }
    }

    #[test]
    fn suppressed_when_stderr_is_not_a_terminal() {
        assert!(!run(&env(&[]), |c| c.stderr_is_terminal = false));
    }

    #[test]
    fn suppressed_for_machine_formats() {
        assert!(!run(&env(&[]), |c| c.text_format = false));
    }

    #[test]
    fn suppressed_with_quiet() {
        assert!(!run(&env(&[]), |c| c.quiet = true));
    }

    #[test]
    fn suppressed_when_authenticated() {
        assert!(!run(&env(&[]), |c| c.authenticated = true));
    }

    #[test]
    fn suppressed_by_vericto_no_nudge() {
        assert!(!run(&env(&[("VERICTO_NO_NUDGE", "1")]), |_| {}));
        assert!(!run(&env(&[("VERICTO_NO_NUDGE", "true")]), |_| {}));
    }

    #[test]
    fn suppressed_by_do_not_track() {
        assert!(!run(&env(&[("DO_NOT_TRACK", "1")]), |_| {}));
    }

    fn interactive(get: &dyn Fn(&str) -> Option<OsString>) -> Context<'_> {
        Context {
            stderr_is_terminal: true,
            text_format: true,
            quiet: false,
            authenticated: false,
            var: get,
        }
    }

    #[test]
    fn shown_once_then_remembered_in_the_state_file() {
        let dir = tempfile::tempdir().unwrap();
        // The config directory does not exist yet: it is created.
        let state = dir.path().join("vericto").join(STATE_FILE);
        let none = |_: &str| None;
        let ctx = interactive(&none);

        let mut out = Vec::new();
        assert!(maybe_show(&ctx, Some(&state), VERSION, &mut out));
        assert_eq!(String::from_utf8(out).unwrap(), message(VERSION) + "\n");
        let recorded = std::fs::read_to_string(&state).unwrap();
        assert_eq!(recorded, "shown_by = \"vericto 9.9.9\"\n");

        let mut again = Vec::new();
        assert!(!maybe_show(&ctx, Some(&state), VERSION, &mut again));
        assert!(again.is_empty());
    }

    #[test]
    fn an_existing_state_file_is_respected_whatever_it_holds() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(STATE_FILE);
        std::fs::write(&state, "").unwrap();
        let none = |_: &str| None;
        let mut out = Vec::new();
        assert!(!maybe_show(
            &interactive(&none),
            Some(&state),
            VERSION,
            &mut out
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn a_suppressed_run_writes_no_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(STATE_FILE);
        let ci = |k: &str| (k == "CI").then(|| OsString::from("1"));
        let mut out = Vec::new();
        assert!(!maybe_show(
            &interactive(&ci),
            Some(&state),
            VERSION,
            &mut out
        ));
        assert!(out.is_empty());
        assert!(!state.exists());
    }

    #[test]
    fn an_unwritable_state_file_is_ignored_silently() {
        let dir = tempfile::tempdir().unwrap();
        // A regular file where the config directory should be: creating the
        // marker under it fails on every platform.
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, "").unwrap();
        let state = blocker.join(STATE_FILE);
        let none = |_: &str| None;
        let mut out = Vec::new();
        assert!(!maybe_show(
            &interactive(&none),
            Some(&state),
            VERSION,
            &mut out
        ));
        assert!(out.is_empty());
        // No resolvable config directory: no tip either.
        assert!(!maybe_show(&interactive(&none), None, VERSION, &mut out));
    }

    #[test]
    fn message_text_and_link() {
        let m = message("2.2.0");
        assert_eq!(
            m,
            "Tip: connect a free Vericto workspace to keep a history of checks and share rules \
             with your team: https://app.vericto.com/register?utm_source=cli&utm_medium=nudge\
             &utm_campaign=first-check&v=2.2.0"
        );
        let prose = m.split("https://").next().unwrap().to_lowercase();
        for banned in ["firewall", "first", "price", "pricing", "plan"] {
            assert!(!prose.contains(banned), "{banned}");
        }
    }
}
