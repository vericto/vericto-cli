//! CI environment detection: provider, base ref, and git provenance.
//!
//! One place resolves "where are we running and against what base", reused by
//! both `--changed` (§10) and the `provenance` object sent on every check
//! (§2.1). All detection is best-effort — a missing var yields `None`, never an
//! error, so the CLI works identically on a laptop and in CI.

use std::process::Command;

/// Which CI provider (if any) we're running under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    GitHub,
    GitLab,
    Local,
}

impl Provider {
    /// The wire value sent in `provenance.ci_provider`.
    pub fn as_str(self) -> &'static str {
        match self {
            Provider::GitHub => "github",
            Provider::GitLab => "gitlab",
            Provider::Local => "local",
        }
    }

    /// Detects the provider from environment variables.
    pub fn detect() -> Provider {
        if env_present("GITHUB_ACTIONS") {
            Provider::GitHub
        } else if env_present("GITLAB_CI") {
            Provider::GitLab
        } else {
            Provider::Local
        }
    }
}

/// Git + CI provenance for a run. Every field is optional; serialized fields
/// with `None` are omitted (see `api::Provenance`).
#[derive(Debug, Default, Clone)]
pub struct Provenance {
    pub git_sha: Option<String>,
    pub git_ref: Option<String>,
    pub ci_provider: &'static str,
    pub ci_run_url: Option<String>,
    pub actor: Option<String>,
}

/// Reads a non-empty environment variable, trimmed.
fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| {
        let t = v.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

/// Whether an environment variable is present and non-empty.
fn env_present(key: &str) -> bool {
    env_var(key).is_some()
}

/// Runs `git <args>` in the current directory and returns trimmed stdout, or
/// `None` if git is absent, errors, or prints nothing. Never panics.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// The base ref to diff against for `--changed`, auto-detected per provider.
/// Falls back to the repo's default branch guess (`origin/HEAD`) so it does
/// something sensible when run locally on a feature branch.
pub fn detected_base_ref(provider: Provider) -> Option<String> {
    match provider {
        // GITHUB_BASE_REF is set on pull_request events (the PR target branch).
        Provider::GitHub => env_var("GITHUB_BASE_REF").map(|b| format!("origin/{b}")),
        // GitLab sets the MR target branch name on merge-request pipelines.
        Provider::GitLab => {
            env_var("CI_MERGE_REQUEST_TARGET_BRANCH_NAME").map(|b| format!("origin/{b}"))
        }
        Provider::Local => None,
    }
    // Fall back to the remote's default branch (e.g. origin/main) if the
    // provider var wasn't set (push builds, local runs).
    .or_else(default_branch_ref)
}

/// Lists `.sql` files changed vs `base` (a ref like `origin/main`), excluding
/// deletions (`--diff-filter=d`) so we don't try to check a file that's gone.
/// Uses the three-dot form (`base...HEAD`) so it compares against the merge
/// base, matching what a PR/MR diff shows. Returns an error string on git
/// failure so the caller can surface it as a usage error rather than silently
/// checking nothing.
pub fn changed_sql_files(base: &str) -> Result<Vec<String>, String> {
    let range = format!("{base}...HEAD");
    let out = Command::new("git")
        .args([
            "diff",
            "--name-only",
            "--diff-filter=d",
            &range,
            "--",
            "*.sql",
        ])
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "git diff against '{base}' failed: {}",
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Best-effort default branch, e.g. `origin/main`, from `origin/HEAD`.
fn default_branch_ref() -> Option<String> {
    // `git symbolic-ref refs/remotes/origin/HEAD` → `refs/remotes/origin/main`
    let full = git(&["symbolic-ref", "refs/remotes/origin/HEAD"])?;
    let branch = full.rsplit('/').next()?;
    Some(format!("origin/{branch}"))
}

/// Collects provenance from git + the detected provider's environment.
pub fn collect_provenance() -> Provenance {
    let provider = Provider::detect();
    Provenance {
        git_sha: git(&["rev-parse", "HEAD"]),
        git_ref: git_ref(provider),
        ci_provider: provider.as_str(),
        ci_run_url: run_url(provider),
        actor: actor(provider),
    }
}

/// The branch/ref name. Prefers the provider's env var (accurate on detached
/// CI checkouts), falling back to `git symbolic-ref` for local runs.
fn git_ref(provider: Provider) -> Option<String> {
    match provider {
        Provider::GitHub => env_var("GITHUB_REF"),
        Provider::GitLab => env_var("CI_COMMIT_REF_NAME"),
        Provider::Local => None,
    }
    .or_else(|| git(&["symbolic-ref", "--quiet", "HEAD"]))
}

/// The username that triggered the run, as reported by the provider (never a
/// credential).
fn actor(provider: Provider) -> Option<String> {
    match provider {
        Provider::GitHub => env_var("GITHUB_ACTOR"),
        Provider::GitLab => env_var("GITLAB_USER_LOGIN"),
        Provider::Local => None,
    }
}

/// A URL pointing at the CI run, for the audit record.
fn run_url(provider: Provider) -> Option<String> {
    match provider {
        // GitHub doesn't expose the run URL directly; assemble it.
        Provider::GitHub => {
            let server = env_var("GITHUB_SERVER_URL")?;
            let repo = env_var("GITHUB_REPOSITORY")?;
            let run_id = env_var("GITHUB_RUN_ID")?;
            Some(format!("{server}/{repo}/actions/runs/{run_id}"))
        }
        // GitLab provides the job URL directly.
        Provider::GitLab => env_var("CI_JOB_URL"),
        Provider::Local => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_as_str_values() {
        assert_eq!(Provider::GitHub.as_str(), "github");
        assert_eq!(Provider::GitLab.as_str(), "gitlab");
        assert_eq!(Provider::Local.as_str(), "local");
    }

    // Env-var-driven detection is exercised in one serial test to avoid races
    // with other tests that read the process environment.
    #[test]
    fn detect_and_provenance_from_env() {
        // Snapshot the vars we touch, so we can restore them.
        let keys = [
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "GITHUB_REF",
            "GITHUB_ACTOR",
            "GITHUB_SERVER_URL",
            "GITHUB_REPOSITORY",
            "GITHUB_RUN_ID",
            "CI_JOB_URL",
            "CI_COMMIT_REF_NAME",
            "GITLAB_USER_LOGIN",
        ];
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        for k in keys {
            std::env::remove_var(k);
        }

        // No CI vars → Local.
        assert_eq!(Provider::detect(), Provider::Local);

        // GitHub.
        std::env::set_var("GITHUB_ACTIONS", "true");
        std::env::set_var("GITHUB_SERVER_URL", "https://github.com");
        std::env::set_var("GITHUB_REPOSITORY", "org/repo");
        std::env::set_var("GITHUB_RUN_ID", "42");
        std::env::set_var("GITHUB_ACTOR", "octocat");
        assert_eq!(Provider::detect(), Provider::GitHub);
        assert_eq!(
            run_url(Provider::GitHub).as_deref(),
            Some("https://github.com/org/repo/actions/runs/42")
        );
        assert_eq!(actor(Provider::GitHub).as_deref(), Some("octocat"));

        // GitLab (takes precedence check: remove GH marker first).
        std::env::remove_var("GITHUB_ACTIONS");
        std::env::set_var("GITLAB_CI", "true");
        std::env::set_var("CI_JOB_URL", "https://gitlab.com/org/repo/-/jobs/9");
        std::env::set_var("GITLAB_USER_LOGIN", "gluser");
        assert_eq!(Provider::detect(), Provider::GitLab);
        assert_eq!(
            run_url(Provider::GitLab).as_deref(),
            Some("https://gitlab.com/org/repo/-/jobs/9")
        );
        assert_eq!(actor(Provider::GitLab).as_deref(), Some("gluser"));

        // Restore.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
