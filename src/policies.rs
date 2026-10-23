// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Business policy documents in the repository (business policy rules,
//! Phase 1, M3): `vericto rules test` and `vericto policies apply`.
//!
//! A policy document is a custom-rule YAML file, one per file:
//!
//! ```text
//! .vericto/policies/no-bulk-refunds.yaml        the document
//! .vericto/policies/tests/no-bulk-refunds.yaml  extra fixtures (optional)
//! ```
//!
//! This module only finds the files, checks the request limits and renders
//! the backend's answers. Nothing here parses or evaluates a policy: the CLI
//! stays a thin client (DESIGN §13), the fixtures run in the backend's
//! evaluator, and the checker there is the only implementation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Where policy documents live when no path is given, relative to the
/// repository root (the directory `vericto` runs in, like `.vericto.toml`).
pub const DEFAULT_POLICY_DIR: &str = ".vericto/policies";

/// The fixtures of `<dir>/<stem>.yaml` live in `<dir>/tests/<stem>.yaml`.
const TESTS_DIR: &str = "tests";

/// Documents per `POST /ci/rules/test` request (the evaluator's limit).
pub const MAX_DOCUMENTS_PER_REQUEST: usize = 50;

/// Fixtures per `POST /ci/rules/test` request, over every document.
pub const MAX_FIXTURES_PER_REQUEST: usize = 500;

/// Bytes per policy document and per fixtures file (the evaluator reads at
/// most this much of either, the same 64 KiB as a query).
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// One policy document read from disk.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyFile {
    /// The path as reported and sent: relative to the repository root with
    /// `/` separators when the file is inside it, else the path as given.
    pub path: String,
    /// Whether `path` is relative to the repository root.
    pub in_repo: bool,
    pub document: String,
    /// The fixtures file paired with this document, if any.
    pub tests: Option<FixturesFile>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FixturesFile {
    pub path: String,
    pub content: String,
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
}

/// `path` relative to `root` with `/` separators, or None when it is outside.
/// Both must already be canonical.
fn relative_to(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Some(parts.join("/"))
}

fn display(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn read(path: &Path) -> Result<String, String> {
    crate::text::read_file(path).map_err(|e| format!("cannot read {}: {e}", display(path)))
}

/// The YAML files directly in `dir` (not recursive), sorted by name.
fn yaml_files_in(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", display(dir)))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read {}: {e}", display(dir)))?;
        let path = entry.path();
        if path.is_file() && is_yaml(&path) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn stem(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The fixtures file of `policy`: `tests/<stem>.yaml` or `tests/<stem>.yml`
/// next to it. Both existing is ambiguous and refused.
fn fixtures_path_for(policy: &Path) -> Result<Option<PathBuf>, String> {
    let dir = policy.parent().unwrap_or(Path::new("."));
    let stem = stem(policy);
    let found: Vec<PathBuf> = ["yaml", "yml"]
        .iter()
        .map(|ext| dir.join(TESTS_DIR).join(format!("{stem}.{ext}")))
        .filter(|p| p.is_file())
        .collect();
    match found.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one.clone())),
        _ => Err(format!(
            "both {} and {} exist; keep one fixtures file per policy",
            display(&found[0]),
            display(&found[1])
        )),
    }
}

/// In a scanned directory, every fixtures file must belong to a document and
/// no two documents may share a stem; otherwise fixtures would silently not run.
fn check_pairing(dir: &Path, policies: &[PathBuf]) -> Result<(), String> {
    let mut stems = HashSet::new();
    for p in policies {
        if !stems.insert(stem(p)) {
            return Err(format!(
                "{} has two policy documents named {} (.yaml and .yml); their fixtures \
                 in {TESTS_DIR}/ would be ambiguous",
                display(dir),
                stem(p)
            ));
        }
    }
    let tests = dir.join(TESTS_DIR);
    if !tests.is_dir() {
        return Ok(());
    }
    for f in yaml_files_in(&tests)? {
        if !stems.contains(&stem(&f)) {
            return Err(format!(
                "{} has no policy document {}.yaml in {}; its fixtures would never run \
                 (rename it after its policy, or remove it)",
                display(&f),
                stem(&f),
                display(dir)
            ));
        }
    }
    Ok(())
}

/// Finds the policy documents named by `paths` (files or directories; none
/// means `DEFAULT_POLICY_DIR`), relative to `root`. A directory contributes
/// its `*.yaml`/`*.yml` files, not recursively. With `with_tests`, each
/// document's fixtures file is read too. Duplicates are dropped, first
/// occurrence wins. No documents at all is an error.
pub fn discover(
    root: &Path,
    paths: &[PathBuf],
    with_tests: bool,
) -> Result<Vec<PolicyFile>, String> {
    let root = root
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", display(root)))?;
    let defaulted = paths.is_empty();
    let inputs: Vec<PathBuf> = if defaulted {
        let dir = root.join(DEFAULT_POLICY_DIR);
        if !dir.is_dir() {
            return Err(format!(
                "no {DEFAULT_POLICY_DIR}/ directory here; run vericto from the repository root, \
                 or pass the policy files or directories to use"
            ));
        }
        vec![dir]
    } else {
        paths.to_vec()
    };

    let mut files: Vec<PathBuf> = Vec::new();
    for input in &inputs {
        let path = if input.is_absolute() {
            input.clone()
        } else {
            root.join(input)
        };
        if path.is_dir() {
            let found = yaml_files_in(&path)?;
            if found.is_empty() {
                return Err(format!(
                    "no policy documents (*.yaml, *.yml) in {}",
                    display(input)
                ));
            }
            if with_tests {
                check_pairing(&path, &found)?;
            }
            files.extend(found);
        } else if path.is_file() {
            if !is_yaml(&path) {
                return Err(format!(
                    "{} is not a policy document (expected a .yaml or .yml file)",
                    display(input)
                ));
            }
            files.push(path);
        } else {
            return Err(format!("{}: no such file or directory", display(input)));
        }
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for file in files {
        let canonical = file
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", display(&file)))?;
        if !seen.insert(canonical.clone()) {
            continue;
        }
        let (path, in_repo) = match relative_to(&root, &canonical) {
            Some(rel) => (rel, true),
            None => (display(&file), false),
        };
        let tests = if with_tests {
            match fixtures_path_for(&canonical)? {
                Some(t) => {
                    let t = t
                        .canonicalize()
                        .map_err(|e| format!("cannot resolve {}: {e}", display(&t)))?;
                    Some(FixturesFile {
                        path: relative_to(&root, &t).unwrap_or_else(|| display(&t)),
                        content: read(&t)?,
                    })
                }
                None => None,
            }
        } else {
            None
        };
        out.push(PolicyFile {
            path,
            in_repo,
            document: read(&canonical)?,
            tests,
        });
    }
    Ok(out)
}

/// The number of fixtures in a YAML text that is either a mapping with a
/// top-level `tests:` block list, or (when `bare_list` is set, a fixtures file)
/// a top-level block list. Line-based and a lower bound: a flow list
/// (`tests: [...]`) counts as 0. It only feeds the local limit check, so it can
/// refuse an oversized request early; the evaluator counts exactly and still
/// enforces the limit.
pub fn count_fixtures(yaml: &str, bare_list: bool) -> usize {
    let lines: Vec<&str> = yaml.lines().collect();
    let indent = |l: &str| l.len() - l.trim_start_matches(' ').len();
    let is_item = |t: &str| t == "-" || t.starts_with("- ");
    let content = |l: &str| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#')
    };
    // Where the list starts: after a top-level `tests:` line with nothing else on it.
    let start = lines.iter().position(|l| {
        let rest = l.strip_prefix("tests:");
        rest.is_some_and(|r| {
            let r = r.trim();
            r.is_empty() || r.starts_with('#')
        })
    });
    let start = match start {
        Some(i) => i + 1,
        None if bare_list && !lines.iter().any(|l| l.starts_with("tests:")) => 0,
        None => return 0,
    };
    let mut seq_indent: Option<usize> = None;
    let mut n = 0;
    for l in &lines[start..] {
        if !content(l) {
            continue;
        }
        let i = indent(l);
        let t = l.trim_start_matches(' ');
        match seq_indent {
            None if is_item(t) => {
                seq_indent = Some(i);
                n += 1;
            }
            None => return 0,
            Some(s) if i < s || (i == s && !is_item(t)) => break,
            Some(s) if i == s => n += 1,
            Some(_) => {}
        }
    }
    n
}

/// Refuses, before anything is sent, a `rules test` request the evaluator
/// would refuse: too many documents or fixtures, or a file over 64 KiB.
pub fn check_test_limits(files: &[PolicyFile]) -> Result<(), String> {
    if files.len() > MAX_DOCUMENTS_PER_REQUEST {
        return Err(format!(
            "{} policy documents; at most {MAX_DOCUMENTS_PER_REQUEST} per run (pass fewer paths \
             and run it more than once)",
            files.len()
        ));
    }
    let mut fixtures = 0;
    for f in files {
        check_document_size(f)?;
        fixtures += count_fixtures(&f.document, false);
        if let Some(t) = &f.tests {
            if t.content.len() > MAX_DOCUMENT_BYTES {
                return Err(format!(
                    "{} is {} bytes; at most {MAX_DOCUMENT_BYTES} bytes per fixtures file",
                    t.path,
                    t.content.len()
                ));
            }
            fixtures += count_fixtures(&t.content, true);
        }
    }
    if fixtures > MAX_FIXTURES_PER_REQUEST {
        return Err(format!(
            "{fixtures} fixtures; at most {MAX_FIXTURES_PER_REQUEST} per run (pass fewer paths \
             and run it more than once)"
        ));
    }
    Ok(())
}

/// A document over 64 KiB is refused by the checker; refuse it here first.
pub fn check_document_size(f: &PolicyFile) -> Result<(), String> {
    if f.document.len() > MAX_DOCUMENT_BYTES {
        return Err(format!(
            "{} is {} bytes; at most {MAX_DOCUMENT_BYTES} bytes per policy document",
            f.path,
            f.document.len()
        ));
    }
    Ok(())
}

/// Every document of `policies apply` must be inside the repository: the
/// path it is stored under is relative to the repository root.
pub fn check_apply_paths(files: &[PolicyFile]) -> Result<(), String> {
    match files.iter().find(|f| !f.in_repo) {
        Some(f) => Err(format!(
            "{} is outside the repository root (the current directory); policies are \
             applied with their path in the repository, so run vericto from its root",
            f.path
        )),
        None => Ok(()),
    }
}

/// The body of `POST /api/v1/ci/rules/test`. Each document's `id` is its path.
pub fn test_request_body(dialect: &str, files: &[PolicyFile]) -> Value {
    let documents: Vec<Value> = files
        .iter()
        .map(|f| {
            let mut d = json!({ "id": f.path, "document": f.document });
            if let Some(t) = &f.tests {
                d["tests"] = Value::String(t.content.clone());
            }
            d
        })
        .collect();
    json!({ "dialect": dialect, "documents": documents })
}

/// The body of `PUT /api/v1/ci/policies`.
pub fn apply_request_body(files: &[PolicyFile], dry_run: bool) -> Value {
    let policies: Vec<Value> = files
        .iter()
        .map(|f| json!({ "path": f.path, "document": f.document }))
        .collect();
    json!({ "dry_run": dry_run, "policies": policies })
}

// ── responses ────────────────────────────────────────────────────────────────

/// One error or warning of the policy checker.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Issue {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub message: String,
}

/// The checker's report (only the fields the CLI renders).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CheckReport {
    #[serde(default)]
    pub valid: bool,
    #[serde(default)]
    pub errors: Vec<Issue>,
    #[serde(default)]
    pub warnings: Vec<Issue>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FixtureResult {
    pub name: String,
    pub passed: bool,
    /// Why the fixture was not run.
    #[serde(default)]
    pub skipped: Option<String>,
    #[serde(default)]
    pub expected: String,
    #[serde(default)]
    pub actual: String,
    #[serde(default)]
    pub expected_reason: Option<String>,
    #[serde(default)]
    pub actual_reason: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DocumentResult {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub check: Option<CheckReport>,
    /// Why the fixtures did not run.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub fixtures: Vec<FixtureResult>,
    #[serde(default)]
    pub passed: usize,
    #[serde(default)]
    pub failed: usize,
    #[serde(default)]
    pub skipped: usize,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TestSummary {
    pub documents: usize,
    pub errored: usize,
    pub fixtures: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub ok: bool,
}

/// The answer of `POST /api/v1/ci/rules/test`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TestResponse {
    #[serde(default)]
    pub results: Vec<DocumentResult>,
    #[serde(default)]
    pub summary: TestSummary,
    /// A refusal of the whole request; `results` is empty then.
    #[serde(default)]
    pub error: Option<String>,
}

/// The exit code of a `rules test` run: 2 when the request was refused as a
/// whole, 1 when a document errored or a fixture failed, 0 otherwise.
/// Skipped fixtures (they need a later phase) do not fail the run.
pub fn test_exit(resp: &TestResponse) -> u8 {
    if resp.error.is_some() {
        2
    } else if resp.summary.ok
        && resp
            .results
            .iter()
            .all(|r| r.error.is_none() && r.failed == 0)
    {
        0
    } else {
        1
    }
}

fn issue_line(kind: &str, i: &Issue) -> String {
    let at = match (i.key.is_empty(), i.offset) {
        (true, None) => String::new(),
        (true, Some(o)) => format!(" at offset {o}"),
        (false, None) => format!(" at `{}`", i.key),
        (false, Some(o)) => format!(" at `{}` offset {o}", i.key),
    };
    format!("{kind}{at}: {}", i.message)
}

fn with_reason(outcome: &str, reason: Option<&str>) -> String {
    match reason {
        Some(r) if !r.is_empty() => format!("{outcome} (reason: {r})"),
        _ => outcome.to_string(),
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The text report of a `rules test` run. `paths` names the documents in the
/// order they were sent, for results that do not echo their id.
pub fn render_test_text(resp: &TestResponse, paths: &[String]) -> String {
    let mut out = String::new();
    if let Some(e) = &resp.error {
        out.push_str(&format!("The request was refused: {e}\n"));
        return out;
    }
    for (i, r) in resp.results.iter().enumerate() {
        let name =
            r.id.clone()
                .or_else(|| paths.get(i).cloned())
                .unwrap_or_else(|| format!("document {}", i + 1));
        out.push_str(&format!("{name}\n"));
        if let Some(c) = &r.check {
            for e in &c.errors {
                out.push_str(&format!("  {}\n", issue_line("check error", e)));
            }
            for w in &c.warnings {
                out.push_str(&format!("  {}\n", issue_line("check warning", w)));
            }
        }
        if let Some(e) = &r.error {
            out.push_str(&format!("  ERROR  fixtures not run: {e}\n"));
        }
        for f in &r.fixtures {
            if let Some(why) = &f.skipped {
                out.push_str(&format!("  SKIP   {}: {why}\n", f.name));
            } else if f.passed {
                out.push_str(&format!("  PASS   {}\n", f.name));
            } else {
                out.push_str(&format!("  FAIL   {}\n", f.name));
                out.push_str(&format!(
                    "         expected: {}\n",
                    with_reason(&f.expected, f.expected_reason.as_deref())
                ));
                out.push_str(&format!(
                    "         actual:   {}\n",
                    with_reason(&f.actual, f.actual_reason.as_deref())
                ));
                if let Some(d) = &f.detail {
                    out.push_str(&format!("         detail:   {d}\n"));
                }
            }
        }
        if r.error.is_none() && r.fixtures.is_empty() {
            out.push_str("  (no fixtures)\n");
        }
    }
    let s = &resp.summary;
    let verdict = if test_exit(resp) == 0 {
        "PASSED"
    } else {
        "FAILED"
    };
    out.push_str(&format!(
        "\n{verdict}  {} ({} errored), {}: {} passed, {} failed, {} skipped\n",
        plural(s.documents, "document", "documents"),
        s.errored,
        plural(s.fixtures, "fixture", "fixtures"),
        s.passed,
        s.failed,
        s.skipped
    ));
    out
}

/// One applied policy in the answer of `PUT /api/v1/ci/policies`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Applied {
    #[serde(default)]
    pub path: Option<String>,
    pub name: String,
    pub code: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    /// `created`, `updated` or `unchanged`.
    pub result: String,
    #[serde(default)]
    pub version: Option<Value>,
}

/// The success answer of `PUT /api/v1/ci/policies`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApplyResponse {
    pub dry_run: bool,
    pub applied: Vec<Applied>,
}

/// One invalid policy in a `400 INVALID_POLICIES` answer (`error.details`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PolicyError {
    /// `policies[<i>]`, the index in the request.
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub check: Option<CheckReport>,
}

fn version_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => format!(" v{s}"),
        Some(Value::Null) | None => String::new(),
        Some(other) => format!(" v{other}"),
    }
}

/// The text report of a successful `policies apply`.
pub fn render_apply_text(resp: &ApplyResponse) -> String {
    let mut out = String::new();
    if resp.dry_run {
        out.push_str(
            "Dry run: nothing was written. This is what `vericto policies apply` would do:\n",
        );
    }
    let (mut created, mut updated, mut unchanged) = (0, 0, 0);
    for a in &resp.applied {
        match a.result.as_str() {
            "created" => created += 1,
            "updated" => updated += 1,
            "unchanged" => unchanged += 1,
            _ => {}
        }
        let path = a
            .path
            .as_deref()
            .map(|p| format!("  ({p})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "  {:<9}  {}{}  {}{path}\n",
            a.result,
            a.code,
            version_text(a.version.as_ref()),
            a.name
        ));
    }
    out.push_str(&format!(
        "\n{}: {created} created, {updated} updated, {unchanged} unchanged{}\n",
        plural(resp.applied.len(), "policy", "policies"),
        if resp.dry_run {
            " (dry run, nothing was written)"
        } else {
            ""
        }
    ));
    out
}

/// The text report of a `400 INVALID_POLICIES` answer.
pub fn render_apply_errors(errors: &[PolicyError]) -> String {
    let mut out = format!(
        "{} invalid; nothing was written:\n",
        plural(errors.len(), "policy is", "policies are")
    );
    for e in errors {
        let what = match (e.path.as_deref(), e.name.as_deref()) {
            (Some(p), Some(n)) => format!("{p} ({n})"),
            (Some(p), None) => p.to_string(),
            (None, Some(n)) => n.to_string(),
            (None, None) => e
                .field
                .clone()
                .unwrap_or_else(|| "(unnamed policy)".to_string()),
        };
        out.push_str(&format!("  {what}: {}\n", e.message));
        if let Some(c) = &e.check {
            for i in &c.errors {
                out.push_str(&format!("    {}\n", issue_line("check error", i)));
            }
            for i in &c.warnings {
                out.push_str(&format!("    {}\n", issue_line("check warning", i)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn discovers_the_default_dir_with_paired_fixtures() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), ".vericto/policies/b.yml", "rule: b\n");
        write(root.path(), ".vericto/policies/a.yaml", "rule: a\n");
        write(root.path(), ".vericto/policies/notes.md", "ignored");
        write(root.path(), ".vericto/policies/tests/a.yml", "- name: x\n");
        let files = discover(root.path(), &[], true).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [".vericto/policies/a.yaml", ".vericto/policies/b.yml"]
        );
        assert!(files.iter().all(|f| f.in_repo));
        let t = files[0].tests.as_ref().unwrap();
        assert_eq!(t.path, ".vericto/policies/tests/a.yml");
        assert_eq!(t.content, "- name: x\n");
        assert!(files[1].tests.is_none());
        // Without fixtures (apply), tests/ is not read.
        assert!(discover(root.path(), &[], false)
            .unwrap()
            .iter()
            .all(|f| f.tests.is_none()));
    }

    #[test]
    fn explicit_paths_are_files_or_dirs_and_deduplicated() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "pol/a.yaml", "rule: a\n");
        write(root.path(), "pol/tests/a.yaml", "tests: []\n");
        write(root.path(), "other/c.yaml", "rule: c\n");
        let files = discover(
            root.path(),
            &[
                PathBuf::from("pol/a.yaml"),
                PathBuf::from("pol"),
                root.path().join("other/c.yaml"),
            ],
            true,
        )
        .unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["pol/a.yaml", "other/c.yaml"]);
        assert_eq!(files[0].tests.as_ref().unwrap().path, "pol/tests/a.yaml");
    }

    #[test]
    fn discovery_errors_are_explicit() {
        let root = tempfile::tempdir().unwrap();
        let err = discover(root.path(), &[], true).unwrap_err();
        assert!(err.contains("no .vericto/policies/ directory"), "{err}");
        write(root.path(), "empty/readme.txt", "x");
        let err = discover(root.path(), &[PathBuf::from("empty")], true).unwrap_err();
        assert!(err.contains("no policy documents"), "{err}");
        let err = discover(root.path(), &[PathBuf::from("missing.yaml")], true).unwrap_err();
        assert!(err.contains("no such file or directory"), "{err}");
        let err = discover(root.path(), &[PathBuf::from("empty/readme.txt")], true).unwrap_err();
        assert!(err.contains("not a policy document"), "{err}");
    }

    #[test]
    fn orphan_and_ambiguous_fixtures_are_refused() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "p/a.yaml", "rule: a\n");
        write(root.path(), "p/tests/typo.yaml", "- name: x\n");
        let err = discover(root.path(), &[PathBuf::from("p")], true).unwrap_err();
        assert!(
            err.contains("p/tests/typo.yaml has no policy document typo.yaml"),
            "{err}"
        );
        // apply does not read fixtures, so an orphan does not stop it.
        assert_eq!(
            discover(root.path(), &[PathBuf::from("p")], false)
                .unwrap()
                .len(),
            1
        );

        let root = tempfile::tempdir().unwrap();
        write(root.path(), "p/a.yaml", "rule: a\n");
        write(root.path(), "p/tests/a.yaml", "- name: x\n");
        write(root.path(), "p/tests/a.yml", "- name: y\n");
        let err = discover(root.path(), &[PathBuf::from("p/a.yaml")], true).unwrap_err();
        assert!(err.contains("keep one fixtures file per policy"), "{err}");

        let root = tempfile::tempdir().unwrap();
        write(root.path(), "p/a.yaml", "rule: a\n");
        write(root.path(), "p/a.yml", "rule: a2\n");
        let err = discover(root.path(), &[PathBuf::from("p")], true).unwrap_err();
        assert!(err.contains("two policy documents named a"), "{err}");
    }

    #[test]
    fn a_file_outside_the_repo_keeps_its_path_and_cannot_be_applied() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        write(elsewhere.path(), "x.yaml", "rule: x\n");
        let files = discover(root.path(), &[elsewhere.path().join("x.yaml")], true).unwrap();
        assert!(!files[0].in_repo);
        assert!(files[0].path.ends_with("x.yaml"));
        let err = check_apply_paths(&files).unwrap_err();
        assert!(err.contains("outside the repository root"), "{err}");
    }

    #[test]
    fn counts_block_list_fixtures() {
        let doc = "rule: r\ndeny_if: 'x'\ntests:\n  - name: a\n    sql: |\n      - not an item\n    expect: deny\n  # comment\n  - name: b\n    expect: allow\nseverity: high\n";
        assert_eq!(count_fixtures(doc, false), 2);
        // Indentless sequence under tests:.
        assert_eq!(
            count_fixtures("tests:\n- name: a\n- name: b\nrule: r\n", false),
            2
        );
        // A bare list file, and a file with a tests: mapping.
        assert_eq!(count_fixtures("- name: a\n  sql: x\n- name: b\n", true), 2);
        assert_eq!(count_fixtures("tests:\n  - name: a\n", true), 1);
        // A flow list and no tests are a lower bound of 0.
        assert_eq!(count_fixtures("tests: [{name: a}]\n", false), 0);
        assert_eq!(count_fixtures("rule: r\n", false), 0);
        // A document is not a bare list.
        assert_eq!(count_fixtures("- name: a\n", false), 0);
    }

    fn file(path: &str, document: String, tests: Option<String>) -> PolicyFile {
        PolicyFile {
            path: path.into(),
            in_repo: true,
            document,
            tests: tests.map(|content| FixturesFile {
                path: format!("tests/{path}"),
                content,
            }),
        }
    }

    #[test]
    fn limits_are_checked_before_sending() {
        let ok = vec![file(
            "a.yaml",
            "rule: a\n".into(),
            Some("- name: x\n".into()),
        )];
        assert!(check_test_limits(&ok).is_ok());

        let many: Vec<PolicyFile> = (0..=MAX_DOCUMENTS_PER_REQUEST)
            .map(|i| file(&format!("{i}.yaml"), "rule: a\n".into(), None))
            .collect();
        let err = check_test_limits(&many).unwrap_err();
        assert!(err.contains("51 policy documents; at most 50"), "{err}");

        let big = vec![file("big.yaml", "x".repeat(MAX_DOCUMENT_BYTES + 1), None)];
        let err = check_test_limits(&big).unwrap_err();
        assert!(err.contains("big.yaml is 65537 bytes"), "{err}");

        let big_tests = vec![file(
            "a.yaml",
            "rule: a\n".into(),
            Some("x".repeat(MAX_DOCUMENT_BYTES + 1)),
        )];
        let err = check_test_limits(&big_tests).unwrap_err();
        assert!(err.contains("per fixtures file"), "{err}");

        let fixtures = "- name: f\n".repeat(MAX_FIXTURES_PER_REQUEST / 2 + 1);
        let two = vec![
            file("a.yaml", "rule: a\n".into(), Some(fixtures.clone())),
            file("b.yaml", "rule: b\n".into(), Some(fixtures)),
        ];
        let err = check_test_limits(&two).unwrap_err();
        assert!(err.contains("502 fixtures; at most 500"), "{err}");
    }

    #[test]
    fn request_bodies_carry_path_document_and_tests() {
        let files = vec![
            file("a.yaml", "rule: a\n".into(), Some("- name: x\n".into())),
            file("b.yaml", "rule: b\n".into(), None),
        ];
        let body = test_request_body("mysql", &files);
        assert_eq!(body["dialect"], "mysql");
        assert_eq!(body["documents"][0]["id"], "a.yaml");
        assert_eq!(body["documents"][0]["tests"], "- name: x\n");
        assert!(body["documents"][1].get("tests").is_none());
        let body = apply_request_body(&files, true);
        assert_eq!(body["dry_run"], true);
        assert_eq!(
            body["policies"][1],
            json!({ "path": "b.yaml", "document": "rule: b\n" })
        );
    }

    fn test_response(v: Value) -> TestResponse {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn renders_failures_skips_and_check_errors() {
        let resp = test_response(json!({
            "results": [
                { "id": "a.yaml", "check": { "valid": true, "errors": [], "warnings": [] },
                  "fixtures": [
                    { "name": "allows reads", "passed": true, "expected": "allow", "actual": "allow" },
                    { "name": "denies bulk", "passed": false, "expected": "deny", "actual": "allow",
                      "expected_reason": "bulk refund", "detail": "UpdateStmt" },
                    { "name": "runtime only", "passed": false, "skipped": "needs the runtime phase",
                      "expected": "deny", "actual": "" }
                  ], "passed": 1, "failed": 1, "skipped": 1 },
                { "check": { "valid": false,
                             "errors": [{ "key": "deny_if", "offset": 7, "message": "unknown field" }],
                             "warnings": [{ "key": "", "message": "no tests" }] },
                  "error": "the document does not pass the check",
                  "fixtures": [], "passed": 0, "failed": 0, "skipped": 0 }
            ],
            "summary": { "documents": 2, "errored": 1, "fixtures": 3, "passed": 1, "failed": 1, "skipped": 1, "ok": false }
        }));
        let text = render_test_text(&resp, &["a.yaml".into(), "b.yaml".into()]);
        assert!(text.contains("a.yaml\n  PASS   allows reads\n"), "{text}");
        assert!(text.contains("  FAIL   denies bulk\n         expected: deny (reason: bulk refund)\n         actual:   allow\n         detail:   UpdateStmt\n"), "{text}");
        assert!(
            text.contains("  SKIP   runtime only: needs the runtime phase\n"),
            "{text}"
        );
        // The second result has no id: named after the path sent in that position.
        assert!(text.contains("b.yaml\n  check error at `deny_if` offset 7: unknown field\n  check warning: no tests\n  ERROR  fixtures not run: the document does not pass the check\n"), "{text}");
        assert!(
            text.contains(
                "FAILED  2 documents (1 errored), 3 fixtures: 1 passed, 1 failed, 1 skipped"
            ),
            "{text}"
        );
        assert_eq!(test_exit(&resp), 1);
    }

    #[test]
    fn a_clean_run_passes_and_skips_do_not_fail_it() {
        let resp = test_response(json!({
            "results": [{ "id": "a.yaml", "fixtures": [
                { "name": "later", "passed": false, "skipped": "phase 2", "expected": "deny", "actual": "" }
            ], "passed": 0, "failed": 0, "skipped": 1 }],
            "summary": { "documents": 1, "errored": 0, "fixtures": 1, "passed": 0, "failed": 0, "skipped": 1, "ok": true }
        }));
        assert_eq!(test_exit(&resp), 0);
        assert!(render_test_text(&resp, &[]).contains("PASSED  1 document (0 errored), 1 fixture"));
        let refused = test_response(json!({ "results": [], "error": "unknown dialect `x`" }));
        assert_eq!(test_exit(&refused), 2);
        assert_eq!(
            render_test_text(&refused, &[]),
            "The request was refused: unknown dialect `x`\n"
        );
    }

    #[test]
    fn renders_apply_results_and_errors() {
        let resp: ApplyResponse = serde_json::from_value(json!({
            "dry_run": true,
            "applied": [
                { "path": "a.yaml", "name": "no-bulk-refunds", "code": "CUSTOM-007", "rule_id": "r1", "result": "created", "version": 1 },
                { "name": "b", "code": "CUSTOM-002", "rule_id": "r2", "result": "unchanged", "version": 4 }
            ]
        }))
        .unwrap();
        let text = render_apply_text(&resp);
        assert!(text.starts_with("Dry run: nothing was written."), "{text}");
        assert!(
            text.contains("  created    CUSTOM-007 v1  no-bulk-refunds  (a.yaml)\n"),
            "{text}"
        );
        assert!(text.contains("  unchanged  CUSTOM-002 v4  b\n"), "{text}");
        assert!(
            text.contains(
                "2 policies: 1 created, 0 updated, 1 unchanged (dry run, nothing was written)"
            ),
            "{text}"
        );

        let errors: Vec<PolicyError> = serde_json::from_value(json!([
            { "field": "policies[0]", "path": "a.yaml", "name": "x", "message": "the document does not pass the check",
              "check": { "valid": false, "errors": [{ "key": "when", "offset": 3, "message": "bad CEL" }] } },
            { "field": "policies[1]", "message": "name is required" }
        ]))
        .unwrap();
        let text = render_apply_errors(&errors);
        assert!(
            text.starts_with("2 policies are invalid; nothing was written:\n"),
            "{text}"
        );
        assert!(text.contains("  a.yaml (x): the document does not pass the check\n    check error at `when` offset 3: bad CEL\n"), "{text}");
        assert!(text.contains("  policies[1]: name is required\n"), "{text}");
    }
}
