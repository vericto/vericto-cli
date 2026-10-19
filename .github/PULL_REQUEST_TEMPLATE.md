## What does this PR change?

<!-- A clear, concise description of the change. -->

## Why?

<!-- Context: a CLI bug, a CI integration need, an installer or packaging issue, a new flag or format. A wrong verdict for a statement, a rule or SQL parsing belong in vericto-engine. -->

## Type of change

- [ ] Command or flag (`check`, `login`, `doctor`, `init`, ...)
- [ ] Report format or CI annotations
- [ ] Authentication (API key, config file, OIDC)
- [ ] File selection or sanitized mode
- [ ] Distribution (cargo-dist, npm installer, Docker image, Homebrew formula)
- [ ] Bug fix
- [ ] Documentation
- [ ] Dependencies

## Tests

- [ ] Added or updated tests that cover the change (exit codes included)
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --locked` passes
- [ ] `npm test` in `npm-installer/` passes (if the npm installer changed)
- [ ] `cargo deny --locked check` and `cargo audit --deny warnings` pass (if dependencies changed)

## Checklist

- [ ] No `unwrap()` / `expect()` on runtime paths
- [ ] Commits follow Conventional Commits
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (if a user can see the change)
- [ ] New or changed flags, environment variables or exit codes documented in `README.md`
- [ ] `release.yml` regenerated with `dist generate`, not edited by hand (if `dist-workspace.toml` changed)
- [ ] I have signed the Vericto Contributor License Agreement in `CLA.md` (on your first pull request, comment `I have read the CLA Document and I hereby sign the CLA`; comment `recheck` if the `CLA` check does not rerun)
