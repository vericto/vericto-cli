---
name: Bug report
about: Something the vericto command gets wrong, in a terminal, a hook or CI, or an installer that fails
title: "[BUG] "
labels: bug
---

<!--
Security vulnerabilities: do not open an issue. Report them privately, see
https://github.com/vericto/vericto-cli/security/policy

The CLI does not evaluate SQL itself. If a specific statement got the wrong
verdict, you can report it here or in vericto-engine; we move issues to the right
repository.
-->

**What happened**
A clear description of what went wrong, and what you expected instead.

**Command**
The exact command line, with the API key removed.
```bash
vericto check ...
```

**Exit code and output**
The exit code (`echo $?`) and the output. With `--format json`, `sarif` or a
GitLab format, the relevant part of the report.
```
paste relevant output here
```

**Dialect**
- [ ] postgres
- [ ] mysql
- [ ] oracle
- [ ] mssql
- [ ] snowflake
- [ ] sqlite

**SQL statement (if the problem depends on the input)**
```sql
-- the smallest input that reproduces it
```

**Environment**
- `vericto --version`:
- Installed with: Homebrew / npm / shell installer / Docker image / prebuilt binary / `cargo install`
- OS and architecture (for example macOS 15 arm64, Ubuntu 24.04 x86_64, Windows 11):
- Where it runs: terminal / pre-commit hook / GitHub Actions / GitLab CI / other CI:
- Authentication: API key / OIDC
- `vericto doctor` output (remove anything sensitive):
