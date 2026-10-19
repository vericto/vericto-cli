#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

// Hardens the npm package cargo-dist builds before it is published:
//
//   1. writes each platform archive's SHA-256, taken from the checksums the
//      release publishes (sha256.sum and the per-file .sha256), into
//      package.json as `supportedPlatforms.<target>.sha256`;
//   2. replaces the generated binary-install.js with npm-installer/binary-install.js,
//      which refuses to install an archive whose SHA-256 does not match.
//
// It fails, and so stops the publish, when an archive has no checksum, when the
// package does not carry the LICENSE (cargo-dist copies it in from the repo
// root, as it does README.md and CHANGELOG.md), or when
// cargo-dist generated a binary-install.js other than the one ours was derived
// from (then review the new upstream file, port its changes, and update
// UPSTREAM_INSTALLER_SHA256).
//
// usage: node npm-installer/harden-package.js <npm-package.tar.gz> <artifacts dir>
// The tarball is rewritten in place.

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

// SHA-256 of the binary-install.js cargo-dist 0.32.0 generates.
const UPSTREAM_INSTALLER_SHA256 =
  "f9cd1e11d9fdbbcaec5cf0a52145a0495d109967ac60363ced9e2bb6f28472dd";

const OUR_INSTALLER = path.join(__dirname, "binary-install.js");

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function run(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: "utf8" });
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed: ${r.stderr || r.error}`);
  }
}

// Reads "<hex>  <name>" / "<hex> *<name>" lines from sha256.sum and *.sha256.
function readChecksums(dir) {
  const sums = new Map();
  for (const file of fs.readdirSync(dir)) {
    if (file !== "sha256.sum" && !file.endsWith(".sha256")) continue;
    for (const line of fs.readFileSync(path.join(dir, file), "utf8").split("\n")) {
      const m = line.trim().match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
      if (!m) continue;
      const name = path.basename(m[2].trim());
      const hex = m[1].toLowerCase();
      if (sums.has(name) && sums.get(name) !== hex) {
        throw new Error(`conflicting checksums for ${name}`);
      }
      sums.set(name, hex);
    }
  }
  return sums;
}

function harden(tarball, artifactsDir, options = {}) {
  const upstreamSha = options.upstreamInstallerSha256 || UPSTREAM_INSTALLER_SHA256;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "vericto-npm-"));
  try {
    run("tar", ["-xzf", tarball, "-C", work]);
    const pkgDir = path.join(work, "package");
    const pkgJsonPath = path.join(pkgDir, "package.json");
    const generated = path.join(pkgDir, "binary-install.js");

    const generatedSha = sha256(fs.readFileSync(generated));
    if (generatedSha !== upstreamSha) {
      throw new Error(
        `cargo-dist generated a different binary-install.js (sha256 ${generatedSha}); ` +
          "port its changes to npm-installer/binary-install.js and update UPSTREAM_INSTALLER_SHA256",
      );
    }

    if (!fs.existsSync(path.join(pkgDir, "LICENSE"))) {
      throw new Error("the npm package has no LICENSE file");
    }

    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
    const sums = readChecksums(artifactsDir);
    const platforms = pkg.supportedPlatforms || {};
    if (Object.keys(platforms).length === 0) {
      throw new Error("package.json lists no supportedPlatforms");
    }
    for (const [target, platform] of Object.entries(platforms)) {
      const sum = sums.get(platform.artifactName);
      if (!sum) {
        throw new Error(`no published SHA-256 for ${platform.artifactName} (${target})`);
      }
      platform.sha256 = sum;
    }

    fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + "\n");
    fs.copyFileSync(OUR_INSTALLER, generated);
    run("tar", ["-czf", tarball, "-C", work, "package"]);
    return pkg;
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

module.exports = { harden, readChecksums, UPSTREAM_INSTALLER_SHA256 };

if (require.main === module) {
  const [tarball, artifactsDir] = process.argv.slice(2);
  if (!tarball || !artifactsDir) {
    console.error("usage: harden-package.js <npm-package.tar.gz> <artifacts dir>");
    process.exit(2);
  }
  try {
    const pkg = harden(tarball, artifactsDir);
    console.log(
      `hardened ${pkg.name}@${pkg.version}: ${Object.keys(pkg.supportedPlatforms).length} platforms pinned by SHA-256`,
    );
  } catch (e) {
    console.error(`harden-package: ${e.message}`);
    process.exit(1);
  }
}
