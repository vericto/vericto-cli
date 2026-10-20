// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

// Tests for the npm installer's integrity checks (node --test, no dependencies).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawnSync, spawn } = require("node:child_process");

const INSTALLER_DIR = path.join(__dirname, "..");
const { isAllowedDownloadUrl } = require("../binary-install.js");
const { harden, readChecksums } = require("../harden-package.js");

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function tmpdir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vericto-npm-test-${tag}-`));
}

function tar(args) {
  const r = spawnSync("tar", args, { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
}

// A release archive laid out like cargo-dist's: one leading directory, the
// binary inside it.
function makeArchive(dir) {
  const root = path.join(dir, "root");
  fs.mkdirSync(path.join(root, "vericto-cli-test"), { recursive: true });
  fs.writeFileSync(path.join(root, "vericto-cli-test", "vericto"), "#!/bin/sh\necho ok\n", {
    mode: 0o755,
  });
  const archive = path.join(dir, "vericto-cli-test.tar.gz");
  tar(["-czf", archive, "-C", root, "vericto-cli-test"]);
  return archive;
}

// Serves `file` at /<name> on 127.0.0.1.
async function serve(file) {
  const server = http.createServer((req, res) => {
    res.writeHead(200);
    res.end(fs.readFileSync(file));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

// Runs Package.install() in a child process (it exits on failure) from a copy
// of the installer, so the install directory is a temporary one.
function runInstall(url, platform) {
  const dir = tmpdir("install");
  fs.copyFileSync(path.join(INSTALLER_DIR, "binary-install.js"), path.join(dir, "binary-install.js"));
  const script = `
    const { Package } = require(${JSON.stringify(path.join(dir, "binary-install.js"))});
    const platform = ${JSON.stringify(platform)};
    new Package(platform, "vericto-test", ${JSON.stringify(url)}, platform.artifactName, ".tar.gz", { vericto: "vericto" })
      .install(true);
  `;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ["-e", script], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => {
      const installed = fs.existsSync(path.join(dir, "node_modules", ".bin_real", "vericto"));
      fs.rmSync(dir, { recursive: true, force: true });
      resolve({ code, stderr, installed });
    });
  });
}

test("download URLs must be https, except loopback http", () => {
  assert.ok(isAllowedDownloadUrl("https://github.com/vericto/vericto-cli/releases/download/v1/x"));
  assert.ok(isAllowedDownloadUrl("http://127.0.0.1:8080/x"));
  assert.ok(isAllowedDownloadUrl("http://localhost/x"));
  assert.ok(isAllowedDownloadUrl("http://[::1]/x"));
  assert.ok(!isAllowedDownloadUrl("http://objects.githubusercontent.com/x"));
  assert.ok(!isAllowedDownloadUrl("ftp://example.com/x"));
  assert.ok(!isAllowedDownloadUrl("not a url"));
});

test("an archive whose SHA-256 matches is installed", async () => {
  const dir = tmpdir("ok");
  const archive = makeArchive(dir);
  const { server, base } = await serve(archive);
  try {
    const platform = { artifactName: "vericto-cli-test.tar.gz", zipExt: ".tar.gz", sha256: sha256(fs.readFileSync(archive)) };
    const r = await runInstall(`${base}/vericto-cli-test.tar.gz`, platform);
    assert.equal(r.code, 0, r.stderr);
    assert.ok(r.installed);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an archive whose SHA-256 does not match is refused and not extracted", async () => {
  const dir = tmpdir("bad");
  const archive = makeArchive(dir);
  const { server, base } = await serve(archive);
  try {
    const platform = { artifactName: "vericto-cli-test.tar.gz", zipExt: ".tar.gz", sha256: "0".repeat(64) };
    const r = await runInstall(`${base}/vericto-cli-test.tar.gz`, platform);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /SHA-256 mismatch/);
    assert.ok(!r.installed);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a package without a checksum installs nothing", async () => {
  const r = await runInstall("http://127.0.0.1:9/never-fetched.tar.gz", {
    artifactName: "vericto-cli-test.tar.gz",
    zipExt: ".tar.gz",
  });
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /no SHA-256/);
  assert.ok(!r.installed);
});

// A tarball shaped like cargo-dist's npm package, with the given installer.
function makeNpmPackage(dir, installerSource, { license = true } = {}) {
  const pkgDir = path.join(dir, "src", "package");
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, "binary-install.js"), installerSource);
  if (license) {
    fs.writeFileSync(path.join(pkgDir, "LICENSE"), "# Functional Source License, Version 1.1, ALv2 Future License\n");
  }
  fs.writeFileSync(
    path.join(pkgDir, "package.json"),
    JSON.stringify({
      name: "@vericto/vericto-cli",
      version: "0.0.0-test",
      supportedPlatforms: {
        "x86_64-unknown-linux-gnu": { artifactName: "vericto-cli-x86_64-unknown-linux-musl.tar.xz" },
        "x86_64-unknown-linux-musl-static": { artifactName: "vericto-cli-x86_64-unknown-linux-musl.tar.xz" },
        "aarch64-apple-darwin": { artifactName: "vericto-cli-aarch64-apple-darwin.tar.xz" },
      },
    }),
  );
  const tarball = path.join(dir, "vericto-cli-npm-package.tar.gz");
  tar(["-czf", tarball, "-C", path.join(dir, "src"), "package"]);
  return tarball;
}

test("harden-package pins every platform archive and swaps the installer", () => {
  const dir = tmpdir("harden");
  try {
    const upstream = "// generated installer\n";
    const tarball = makeNpmPackage(dir, upstream);
    const artifacts = path.join(dir, "artifacts");
    fs.mkdirSync(artifacts);
    const linux = "a".repeat(64);
    const mac = "b".repeat(64);
    fs.writeFileSync(
      path.join(artifacts, "sha256.sum"),
      `${linux}  vericto-cli-x86_64-unknown-linux-musl.tar.xz\n${mac} *vericto-cli-aarch64-apple-darwin.tar.xz\n`,
    );
    fs.writeFileSync(path.join(artifacts, "vericto-cli-aarch64-apple-darwin.tar.xz.sha256"), `${mac}  vericto-cli-aarch64-apple-darwin.tar.xz\n`);

    harden(tarball, artifacts, { upstreamInstallerSha256: sha256(Buffer.from(upstream)) });

    const out = path.join(dir, "out");
    fs.mkdirSync(out);
    tar(["-xzf", tarball, "-C", out]);
    const pkg = JSON.parse(fs.readFileSync(path.join(out, "package", "package.json"), "utf8"));
    assert.equal(pkg.supportedPlatforms["x86_64-unknown-linux-gnu"].sha256, linux);
    assert.equal(pkg.supportedPlatforms["x86_64-unknown-linux-musl-static"].sha256, linux);
    assert.equal(pkg.supportedPlatforms["aarch64-apple-darwin"].sha256, mac);
    assert.equal(
      fs.readFileSync(path.join(out, "package", "binary-install.js"), "utf8"),
      fs.readFileSync(path.join(INSTALLER_DIR, "binary-install.js"), "utf8"),
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("harden-package refuses a missing checksum", () => {
  const dir = tmpdir("missing");
  try {
    const upstream = "// generated installer\n";
    const tarball = makeNpmPackage(dir, upstream);
    const artifacts = path.join(dir, "artifacts");
    fs.mkdirSync(artifacts);
    fs.writeFileSync(path.join(artifacts, "sha256.sum"), `${"a".repeat(64)}  vericto-cli-x86_64-unknown-linux-musl.tar.xz\n`);
    assert.throws(
      () => harden(tarball, artifacts, { upstreamInstallerSha256: sha256(Buffer.from(upstream)) }),
      /no published SHA-256 for vericto-cli-aarch64-apple-darwin/,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("harden-package refuses a package without the LICENSE", () => {
  const dir = tmpdir("nolicense");
  try {
    const upstream = "// generated installer\n";
    const tarball = makeNpmPackage(dir, upstream, { license: false });
    const artifacts = path.join(dir, "artifacts");
    fs.mkdirSync(artifacts);
    assert.throws(
      () => harden(tarball, artifacts, { upstreamInstallerSha256: sha256(Buffer.from(upstream)) }),
      /no LICENSE file/,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("harden-package refuses an installer cargo-dist changed", () => {
  const dir = tmpdir("changed");
  try {
    const tarball = makeNpmPackage(dir, "// a newer generated installer\n");
    const artifacts = path.join(dir, "artifacts");
    fs.mkdirSync(artifacts);
    assert.throws(() => harden(tarball, artifacts), /generated a different binary-install.js/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("conflicting checksums for one archive are an error", () => {
  const dir = tmpdir("conflict");
  try {
    fs.writeFileSync(path.join(dir, "sha256.sum"), `${"a".repeat(64)}  x.tar.xz\n`);
    fs.writeFileSync(path.join(dir, "x.tar.xz.sha256"), `${"b".repeat(64)}  x.tar.xz\n`);
    assert.throws(() => readChecksums(dir), /conflicting checksums/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ── Windows: the .zip archive and `npx @vericto/vericto-cli ...` ────────────
//
// What `npx @vericto/vericto-cli <args>` runs on Windows: the package's run
// script calls Package.run, which installs the .zip archive (unpacked with
// PowerShell's Expand-Archive, since Windows has no `unzip`) on first use and
// then runs vericto.exe with the arguments, exiting with its exit code. The
// binary here is a renamed copy of cmd.exe, a real executable whose arguments
// and exit code are easy to control.
const onWindows = process.platform === "win32";

function makeWindowsZip(dir) {
  const content = path.join(dir, "content");
  fs.mkdirSync(content);
  fs.copyFileSync(path.join(process.env.SystemRoot, "System32", "cmd.exe"), path.join(content, "vericto.exe"));
  fs.writeFileSync(path.join(content, "README.md"), "readme\n");
  const zip = path.join(dir, "vericto-cli-x86_64-pc-windows-msvc.zip");
  const r = spawnSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", "Compress-Archive -Path (Join-Path $env:SRC '*') -DestinationPath $env:DST"],
    { env: { ...process.env, SRC: content, DST: zip }, encoding: "utf8" },
  );
  assert.equal(r.status, 0, r.stderr);
  return zip;
}

// Runs `node run.js <args>` the way the package's bin shim does.
function runPackage(dir, url, platform, args) {
  fs.copyFileSync(path.join(INSTALLER_DIR, "binary-install.js"), path.join(dir, "binary-install.js"));
  fs.writeFileSync(
    path.join(dir, "run.js"),
    `const { Package } = require(${JSON.stringify(path.join(dir, "binary-install.js"))});
     const platform = ${JSON.stringify(platform)};
     new Package(platform, "vericto-test", ${JSON.stringify(url)}, platform.artifactName, ".zip", { vericto: "vericto.exe" })
       .run("vericto");`,
  );
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(dir, "run.js"), ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("Windows: the .zip installs on first run, and arguments and exit codes pass through", { skip: !onWindows }, async () => {
  const dir = tmpdir("win");
  const zip = makeWindowsZip(dir);
  const { server, base } = await serve(zip);
  try {
    const platform = {
      artifactName: "vericto-cli-x86_64-pc-windows-msvc.zip",
      zipExt: ".zip",
      sha256: sha256(fs.readFileSync(zip)),
    };
    const url = `${base}/vericto-cli-x86_64-pc-windows-msvc.zip`;
    const first = await runPackage(dir, url, platform, ["/d", "/c", "echo vericto-ok"]);
    assert.equal(first.code, 0, first.stderr);
    assert.match(first.stdout, /vericto-ok/);
    assert.ok(fs.existsSync(path.join(dir, "node_modules", ".bin_real", "vericto.exe")));
    // Installed now: the second run uses it as is, and keeps the exit code.
    const second = await runPackage(dir, url, platform, ["/d", "/c", "exit 3"]);
    assert.equal(second.code, 3, second.stderr);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Windows: a .zip whose SHA-256 does not match is not unpacked", { skip: !onWindows }, async () => {
  const dir = tmpdir("winbad");
  const zip = makeWindowsZip(dir);
  const { server, base } = await serve(zip);
  try {
    const platform = { artifactName: "vericto-cli-x86_64-pc-windows-msvc.zip", zipExt: ".zip", sha256: "0".repeat(64) };
    const r = await runPackage(dir, `${base}/vericto-cli-x86_64-pc-windows-msvc.zip`, platform, ["/c", "exit 0"]);
    assert.notEqual(r.code, 0);
    assert.match(r.stderr, /SHA-256 mismatch/);
    assert.ok(!fs.existsSync(path.join(dir, "node_modules", ".bin_real", "vericto.exe")));
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
