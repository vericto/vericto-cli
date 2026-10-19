# SPDX-FileCopyrightText: 2026 Vericto S.A.S.
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Write THIRD_PARTY_LICENSES for the vericto binary.

usage (from the repository root):
    python3 third-party/notices.py           # rewrite THIRD_PARTY_LICENSES
    python3 third-party/notices.py --check   # fail if it is out of date

The file lists every crate compiled into the release binaries (normal
dependencies only, for each target in dist-workspace.toml; build and dev
dependencies do not ship) with its version and license expression, then each
distinct license or notice file those crates carry, once, with the crates that
carry it. third-party/pg_query-bundled.txt, which covers the C code pg_query
compiles in, is appended; the script stops when that file describes a different
pg_query version than Cargo.lock.

It needs only Python 3.11+ and cargo (`cargo metadata --locked`), so CI and a
contributor run the same thing. cargo-dist ships the file in every release
archive (`include` in dist-workspace.toml); CI runs `--check`.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

OUT = Path("THIRD_PARTY_LICENSES")
BUNDLED = Path("third-party/pg_query-bundled.txt")
HEADER = Path("third-party/header.txt")
# Top-level files (or files in a top-level LICENSES/ directory) that hold a
# license text or a notice the license asks to keep.
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense)([-_.].*)?$", re.IGNORECASE)
RULE = "=" * 80
# Crates whose package carries no license file; their notices are in BUNDLED.
TEXTS_IN_BUNDLED = {"pg_query"}


def cargo_metadata(target: str) -> dict:
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", target],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return json.loads(out)


def shipped_packages(meta: dict) -> set[str]:
    """Package ids reachable from the root through normal dependencies."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = meta["resolve"]["root"]
    seen: set[str] = set()
    stack = [root]
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]):
                stack.append(dep["pkg"])
    seen.discard(root)
    return seen


def license_files(pkg: dict) -> list[Path]:
    root = Path(pkg["manifest_path"]).parent
    found: set[Path] = set()
    if pkg.get("license_file"):
        found.add(root / pkg["license_file"])
    for entry in root.iterdir():
        if entry.is_file() and LICENSE_FILE.match(entry.name):
            found.add(entry)
    licenses_dir = root / "LICENSES"
    if licenses_dir.is_dir():
        found.update(p for p in licenses_dir.iterdir() if p.is_file())
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def normalize(text: str) -> str:
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines) + "\n"


def locked_version(name: str) -> str | None:
    lock = tomllib.loads(Path("Cargo.lock").read_text(encoding="utf-8"))
    versions = [p["version"] for p in lock.get("package", []) if p["name"] == name]
    return versions[0] if len(versions) == 1 else None


def render() -> str:
    targets = tomllib.loads(Path("dist-workspace.toml").read_text(encoding="utf-8"))["dist"]["targets"]
    packages: dict[str, dict] = {}
    for target in targets:
        meta = cargo_metadata(target)
        by_id = {p["id"]: p for p in meta["packages"]}
        for pid in shipped_packages(meta):
            packages[pid] = by_id[pid]

    crates = sorted(packages.values(), key=lambda p: (p["name"], p["version"]))
    missing = []
    texts: dict[str, dict] = {}
    for pkg in crates:
        files = license_files(pkg)
        if not files and pkg["name"] not in TEXTS_IN_BUNDLED:
            missing.append(f"{pkg['name']} {pkg['version']}")
        root = Path(pkg["manifest_path"]).parent
        for f in files:
            body = normalize(f.read_text(encoding="utf-8", errors="replace"))
            key = hashlib.sha256(body.encode()).hexdigest()
            entry = texts.setdefault(key, {"text": body, "used_by": []})
            entry["used_by"].append(f"{pkg['name']} {pkg['version']} ({f.relative_to(root).as_posix()})")
    if missing:
        sys.exit("notices: no license file in these crates; add their texts by hand before shipping: " + ", ".join(missing))

    pg_query = locked_version("pg_query")
    bundled = BUNDLED.read_text(encoding="utf-8")
    recorded = re.search(r"^pg_query version: (\S+)$", bundled, re.MULTILINE)
    if pg_query and (not recorded or recorded.group(1) != pg_query):
        sys.exit(
            f"notices: {BUNDLED} describes pg_query '{recorded.group(1) if recorded else '?'}' but Cargo.lock has "
            f"'{pg_query}'. Update its license texts and version line for the new release."
        )

    by_license: dict[str, int] = {}
    for pkg in crates:
        expr = pkg.get("license") or "see license file"
        by_license[expr] = by_license.get(expr, 0) + 1

    out = [HEADER.read_text(encoding="utf-8").rstrip("\n"), "", "Summary (crates per declared license):"]
    out += [f"  - {expr}: {n} crate(s)" for expr, n in sorted(by_license.items(), key=lambda kv: (-kv[1], kv[0]))]
    out += ["", RULE, "CRATES", "", "Name, version and declared license (SPDX expression) of each crate:", ""]
    out += [f"  - {p['name']} {p['version']}: {p.get('license') or 'see license file'}" for p in crates]
    blocks = sorted(texts.values(), key=lambda e: e["used_by"][0])
    for entry in blocks:
        out += ["", RULE, "Used by:"]
        out += [f"  - {u}" for u in entry["used_by"]]
        out += ["", entry["text"].rstrip("\n")]
    out += [""]
    return "\n".join(out) + "\n" + bundled


def main() -> int:
    content = render()
    if sys.argv[1:] == ["--check"]:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != content:
            print(f"{OUT} is out of date: run `python3 third-party/notices.py` and commit the result.", file=sys.stderr)
            return 1
        print(f"{OUT} is up to date.")
        return 0
    if sys.argv[1:]:
        print(__doc__, file=sys.stderr)
        return 2
    OUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
