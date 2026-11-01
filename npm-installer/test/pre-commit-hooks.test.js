// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

// Checks the pre-commit framework hooks (.pre-commit-hooks.yaml at the repo
// root) against the release they ship with (node --test, no dependencies).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..", "..");
const read = (name) => fs.readFileSync(path.join(ROOT, name), "utf8");

// `version` in Cargo.toml's [package] table: the release being cut.
function crateVersion() {
  const pkg = read("Cargo.toml").split(/^\[/m).find((t) => t.startsWith("package]"));
  const m = pkg && pkg.match(/^version\s*=\s*"([^"]+)"/m);
  assert.ok(m, "no version in Cargo.toml [package]");
  return m[1];
}

// The manifest is a flat list of hooks with scalar keys and one-line flow
// lists; this reads exactly that shape, so a reformatted file fails loudly
// here instead of being half-read.
function hooks() {
  const out = [];
  for (const raw of read(".pre-commit-hooks.yaml").split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "");
    if (/^\s*(#.*)?$/.test(line)) continue;
    const item = line.match(/^- (\w+): (.*)$/);
    const key = line.match(/^ {2}(\w+): (.*)$/);
    const cont = line.match(/^ {4}(.*)$/);
    if (item) {
      out.push({ [item[1]]: item[2] });
    } else if (key && out.length) {
      out[out.length - 1][key[1]] = key[2];
      out[out.length - 1].__last = key[1];
    } else if (cont && out.length) {
      const h = out[out.length - 1];
      h[h.__last] = `${h[h.__last]} ${cont[1]}`.trim();
    } else {
      assert.fail(`unexpected line in .pre-commit-hooks.yaml: ${raw}`);
    }
  }
  return out;
}

test("both hook ids exist", () => {
  assert.deepEqual(
    hooks().map((h) => h.id),
    ["vericto-check", "vericto-check-online"],
  );
});

test("every hook installs the npm package of this release", () => {
  const want = `["@vericto/vericto-cli@${crateVersion()}"]`;
  for (const h of hooks()) {
    assert.equal(h.language, "node", h.id);
    assert.equal(
      h.additional_dependencies,
      want,
      `${h.id}: pin the release in Cargo.toml (bump it with the version)`,
    );
  }
});

test("the hooks run vericto check on SQL files and show non-blocking findings", () => {
  const [offline, online] = hooks();
  assert.equal(offline.entry, "vericto check --offline");
  assert.equal(online.entry, "vericto check");
  for (const h of hooks()) {
    assert.equal(h.types, "[sql]", h.id);
    assert.equal(h.verbose, "true", `${h.id}: FLAGGED findings exit 0 and need verbose to show`);
    assert.equal(h.args, undefined, `${h.id}: args are the user's (e.g. --dialect)`);
  }
});

test("the root package.json only lets pre-commit pack the repo", () => {
  const pkg = JSON.parse(read("package.json"));
  assert.equal(pkg.private, true);
  for (const k of ["dependencies", "devDependencies", "bin", "scripts"]) {
    assert.equal(pkg[k], undefined, `package.json must not declare ${k}`);
  }
});

test("the README's example pins this release", () => {
  const m = read("README.md").match(/^ {4}rev: (v\S+)/m);
  assert.ok(m, "no `rev:` in the README's pre-commit example");
  assert.equal(m[1], `v${crateVersion()}`, "update the README's pre-commit `rev:` with the version");
});
