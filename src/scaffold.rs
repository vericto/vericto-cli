//! `vericto init` — scaffold CI workflows and a git pre-commit hook (§10).
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

/// How the scaffolded CI job authenticates to Vericto.
#[derive(Debug, Clone)]
pub enum AuthStyle {
    /// A static `vtro_...` key from a CI secret named `VERICTO_API_KEY`.
    StaticKey,
    /// OIDC / workload-identity (§6.1): no long-lived secret, a short-lived key
    /// minted per run against `workspace_id`.
    Oidc { workspace_id: String },
}

/// GitHub Actions workflow: run `vericto check --changed` on PRs touching SQL,
/// emit SARIF, upload to Code Scanning so findings show as PR annotations.
/// With [`AuthStyle::Oidc`] it requests an ID token (no `VERICTO_API_KEY` secret).
pub fn github_workflow(dialect: &str, auth: &AuthStyle) -> String {
    // OIDC needs `id-token: write` and passes --oidc/--workspace instead of a key.
    let (id_token_perm, check_line, check_env) = match auth {
        AuthStyle::StaticKey => (
            "",
            format!("vericto check --changed --dialect {dialect} --format sarif --output vericto.sarif"),
            "\n        env:\n          VERICTO_API_KEY: ${{ secrets.VERICTO_API_KEY }}".to_string(),
        ),
        AuthStyle::Oidc { workspace_id } => (
            "\n  id-token: write          # mint an OIDC token for workload-identity login (§6.1)",
            format!(
                "vericto check --changed --dialect {dialect} --oidc --workspace {workspace_id} --format sarif --output vericto.sarif"
            ),
            String::new(),
        ),
    };
    format!(
        r#"# Managed by `vericto init`. Validates SQL changed in a PR against your
# Vericto workspace rules and surfaces findings as PR annotations (Code Scanning).
name: Vericto SQL check

on:
  pull_request:
    paths:
      - "**/*.sql"

permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning{id_token_perm}

jobs:
  vericto:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history so --changed can diff the merge base

      - name: Install vericto
        run: curl -fsSL https://github.com/vericto/vericto-cli/releases/latest/download/vericto-cli-installer.sh | sh

      - name: Vericto check
        run: {check_line}{check_env}

      - name: Upload SARIF
        if: always()   # upload even when the check fails, so annotations appear
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vericto.sarif
"#
    )
}

/// GitLab CI job: run `vericto check --changed` on MRs touching SQL, emit a Code
/// Quality report so findings show as inline MR annotations + the CQ widget.
/// With [`AuthStyle::Oidc`] it mints an `id_tokens:` JWT (no `VERICTO_API_KEY`).
pub fn gitlab_job(dialect: &str, auth: &AuthStyle) -> String {
    match auth {
        AuthStyle::StaticKey => format!(
            r#"# Managed by `vericto init`. Validates SQL changed in a merge request against
# your Vericto workspace rules and surfaces findings as MR annotations.
vericto-sql-check:
  image: ghcr.io/vericto/vericto-cli:latest
  script:
    - vericto check --changed --dialect {dialect} --format gitlab-codequality --output gl-code-quality.json
  artifacts:
    reports:
      codequality: gl-code-quality.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "**/*.sql"
  # Set VERICTO_API_KEY as a masked CI/CD variable in project settings.
"#
        ),
        AuthStyle::Oidc { workspace_id } => format!(
            r#"# Managed by `vericto init`. Validates SQL changed in a merge request against
# your Vericto workspace rules and surfaces findings as MR annotations.
# Uses OIDC / workload-identity (§6.1): no long-lived VERICTO_API_KEY secret.
vericto-sql-check:
  image: ghcr.io/vericto/vericto-cli:latest
  id_tokens:
    VERICTO_ID_TOKEN:
      aud: vericto          # must match the workspace's OIDC trust policy audience
  script:
    - vericto check --changed --dialect {dialect} --oidc --workspace {workspace_id} --format gitlab-codequality --output gl-code-quality.json
  artifacts:
    reports:
      codequality: gl-code-quality.json
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes:
        - "**/*.sql"
"#
        ),
    }
}

/// Git pre-commit hook: check staged `*.sql` before a commit. Non-blocking if
/// `vericto` isn't installed (so a missing binary doesn't wedge every commit);
/// blocks the commit when a staged file is BLOCKED.
///
/// It checks the **staged** blob (`git show :path`, piped as stdin), not the
/// working-tree file: after a partial `git add` the two differ, and the commit
/// contains the staged one. Each file is one `vericto check -`, labelled by an
/// echo since stdin has no name; the hook exits with the highest exit code.
pub fn precommit_hook(dialect: &str) -> String {
    format!(
        r#"#!/bin/sh
# Managed by `vericto init`. Blocks a commit if staged SQL trips a Vericto rule.
# Bypass once with:  git commit --no-verify
set -e

if ! command -v vericto >/dev/null 2>&1; then
  echo "vericto not found on PATH — skipping SQL check (install: https://github.com/vericto/vericto-cli)" >&2
  exit 0
fi

staged=$(git diff --cached --name-only --diff-filter=d -- '*.sql')
[ -z "$staged" ] && exit 0

# Check the staged content (what the commit will contain), not the working tree.
rc=0
while IFS= read -r f; do
  echo "vericto: $f" >&2
  s=0
  git show ":$f" | vericto check --dialect {dialect} - || s=$?
  if [ "$s" -gt "$rc" ]; then rc=$s; fi
done <<EOF
$staged
EOF
exit "$rc"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_workflow_has_key_pieces() {
        let w = github_workflow("mysql", &AuthStyle::StaticKey);
        assert!(w.contains("name: Vericto SQL check"));
        assert!(w.contains("--dialect mysql"));
        assert!(w.contains("--format sarif"));
        assert!(w.contains("upload-sarif"));
        assert!(w.contains("secrets.VERICTO_API_KEY"));
        assert!(!w.contains("id-token: write")); // static key needs no OIDC perm
    }

    #[test]
    fn github_workflow_oidc_variant() {
        let w = github_workflow(
            "postgres",
            &AuthStyle::Oidc {
                workspace_id: "ws_9".into(),
            },
        );
        assert!(w.contains("id-token: write"));
        assert!(w.contains("--oidc --workspace ws_9"));
        assert!(!w.contains("VERICTO_API_KEY")); // no static secret in OIDC mode
    }

    #[test]
    fn gitlab_job_has_codequality_report() {
        let j = gitlab_job("postgres", &AuthStyle::StaticKey);
        assert!(j.contains("gitlab-codequality"));
        assert!(j.contains("artifacts:"));
        assert!(j.contains("codequality:"));
        assert!(j.contains("merge_request_event"));
        assert!(!j.contains("id_tokens:"));
    }

    #[test]
    fn gitlab_job_oidc_variant() {
        let j = gitlab_job(
            "postgres",
            &AuthStyle::Oidc {
                workspace_id: "ws_9".into(),
            },
        );
        assert!(j.contains("id_tokens:"));
        assert!(j.contains("VERICTO_ID_TOKEN"));
        assert!(j.contains("--oidc --workspace ws_9"));
    }

    #[test]
    fn precommit_hook_is_shell_and_dialect_aware() {
        let h = precommit_hook("oracle");
        assert!(h.starts_with("#!/bin/sh"));
        assert!(h.contains("--diff-filter=d"));
        assert!(h.contains(r#"git show ":$f" | vericto check --dialect oracle -"#));
        assert!(!h.contains("xargs")); // not the working-tree paths
        assert!(h.contains("--dialect oracle"));
        assert!(h.contains("command -v vericto")); // no-op when vericto absent
    }

    /// Runs the generated hook in a real repo where the staged and working-tree
    /// versions of a file differ, with a stub `vericto` that records its stdin:
    /// the hook must send the staged content.
    #[cfg(unix)]
    #[test]
    fn precommit_hook_checks_staged_blob_not_working_tree() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("vericto-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let repo = dir.join("repo");
        let bin = dir.join("bin");
        std::fs::create_dir_all(repo.join("db")).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let seen = dir.join("seen.sql");
        // Stub: record stdin, exit 1 (as if BLOCKED) so the exit code is checked.
        write_file(
            &bin.join("vericto"),
            &format!("#!/bin/sh\ncat >> '{}'\nexit 1\n", seen.display()),
            false,
            true,
        )
        .unwrap();
        let git = |args: &[&str]| {
            let ok = Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {args:?} failed");
        };
        git(&["init", "-q"]);
        // A space in the path: the old `xargs` hook split it into two args.
        let file = repo.join("db/my migration.sql");
        std::fs::write(&file, "DELETE FROM users;\n").unwrap();
        git(&["add", "db/my migration.sql"]);
        // Unstaged edit: the working tree now looks harmless.
        std::fs::write(&file, "SELECT 1;\n").unwrap();

        let hook = dir.join("pre-commit");
        write_file(&hook, &precommit_hook("postgres"), false, true).unwrap();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let status = Command::new(&hook)
            .current_dir(&repo)
            .env("PATH", path)
            .status()
            .unwrap();

        assert_eq!(status.code(), Some(1), "hook must propagate the block");
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            "DELETE FROM users;\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_file_creates_skips_and_forces() {
        let dir = std::env::temp_dir().join(format!("vericto-scaffold-{}", std::process::id()));
        let path = dir.join("nested/out.yml");
        // First write creates.
        match write_file(&path, "hello", false, false).unwrap() {
            Written::Created(p) => assert_eq!(p, path),
            Written::Skipped(_) => panic!("expected Created"),
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
        // Second write without force skips (content unchanged).
        match write_file(&path, "changed", false, false).unwrap() {
            Written::Skipped(_) => {}
            Written::Created(_) => panic!("expected Skipped"),
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
        // With force it overwrites.
        matches!(
            write_file(&path, "changed", true, false).unwrap(),
            Written::Created(_)
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "changed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_file_sets_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vericto-scaffold-x-{}", std::process::id()));
        let path = dir.join("hook");
        write_file(&path, "#!/bin/sh\n", false, true).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
