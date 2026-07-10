//! `vetro init` — scaffold CI workflows and a git pre-commit hook (§10).
//!
//! Templates are generated here; the orchestration (which targets, overwrite
//! policy) lives in `main`. Nothing is overwritten without `--force`, and a
//! GitLab pipeline that already exists is never clobbered — we write a separate
//! include file and print how to wire it.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Which CI provider to scaffold for, detected from the repo when not forced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiTarget {
    GitHub,
    GitLab,
    Unknown,
}

/// Detects the provider from the `origin` remote URL (github.com / gitlab.com),
/// then from existing files, falling back to Unknown.
pub fn detect_target() -> CiTarget {
    if let Some(url) = git_remote_url() {
        let u = url.to_ascii_lowercase();
        if u.contains("github.com") {
            return CiTarget::GitHub;
        }
        if u.contains("gitlab") {
            return CiTarget::GitLab;
        }
    }
    if Path::new(".github").is_dir() {
        return CiTarget::GitHub;
    }
    if Path::new(".gitlab-ci.yml").exists() {
        return CiTarget::GitLab;
    }
    CiTarget::Unknown
}

fn git_remote_url() -> Option<String> {
    let out = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
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

/// The result of attempting to write one scaffold file.
pub enum Written {
    Created(PathBuf),
    Skipped(PathBuf),
}

/// Writes `body` to `path` unless it exists and `force` is false. Creates parent
/// dirs. When `executable`, sets the file mode to 0755 (Unix) for git hooks.
pub fn write_file(
    path: &Path,
    body: &str,
    force: bool,
    executable: bool,
) -> std::io::Result<Written> {
    if path.exists() && !force {
        return Ok(Written::Skipped(path.to_path_buf()));
    }
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    std::fs::write(path, body)?;
    if executable {
        set_executable(path)?;
    }
    Ok(Written::Created(path.to_path_buf()))
}

#[cfg(unix)]
fn set_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

// ── Templates ────────────────────────────────────────────────────────────────

/// GitHub Actions workflow: run `vetro check --changed` on PRs touching SQL,
/// emit SARIF, upload to Code Scanning so findings show as PR annotations.
pub fn github_workflow(dialect: &str) -> String {
    format!(
        r#"# Managed by `vetro init`. Validates SQL changed in a PR against your
# Vetro workspace rules and surfaces findings as PR annotations (Code Scanning).
name: Vetro SQL check

on:
  pull_request:
    paths:
      - "**/*.sql"

permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning

jobs:
  vetro:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history so --changed can diff the merge base

      - name: Install vetro
        run: curl -fsSL https://github.com/donkan168/vetro-cli/releases/latest/download/vetro-installer.sh | sh

      - name: Vetro check
        run: vetro check --changed --dialect {dialect} --format sarif --output vetro.sarif
        env:
          VETRO_API_KEY: ${{{{ secrets.VETRO_API_KEY }}}}

      - name: Upload SARIF
        if: always()   # upload even when the check fails, so annotations appear
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vetro.sarif
"#
    )
}

/// GitLab CI job: run `vetro check --changed` on MRs touching SQL, emit a Code
/// Quality report so findings show as inline MR annotations + the CQ widget.
pub fn gitlab_job(dialect: &str) -> String {
    format!(
        r#"# Managed by `vetro init`. Validates SQL changed in a merge request against
# your Vetro workspace rules and surfaces findings as MR annotations.
vetro-sql-check:
  image: ghcr.io/donkan168/vetro-cli:latest
  script:
    - vetro check --changed --dialect {dialect} --format gitlab-codequality --output gl-code-quality.json
  artifacts:
    reports:
      codequality: gl-code-quality.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "**/*.sql"
  # Set VETRO_API_KEY as a masked CI/CD variable in project settings.
"#
    )
}

/// Git pre-commit hook: check staged `*.sql` before a commit. Non-blocking if
/// `vetro` isn't installed (so a missing binary doesn't wedge every commit);
/// blocks the commit when a staged file is BLOCKED.
pub fn precommit_hook(dialect: &str) -> String {
    format!(
        r#"#!/bin/sh
# Managed by `vetro init`. Blocks a commit if staged SQL trips a Vetro rule.
# Bypass once with:  git commit --no-verify
set -e

if ! command -v vetro >/dev/null 2>&1; then
  echo "vetro not found on PATH — skipping SQL check (install: https://github.com/donkan168/vetro-cli)" >&2
  exit 0
fi

staged=$(git diff --cached --name-only --diff-filter=d -- '*.sql')
[ -z "$staged" ] && exit 0

# shellcheck disable=SC2086
echo "$staged" | xargs vetro check --dialect {dialect}
"#
    )
}
