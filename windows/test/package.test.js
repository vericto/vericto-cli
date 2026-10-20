// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

// Tests for the Windows packaging (node --test, no dependencies). The
// installer tests at the end run the rendered PowerShell installer for real,
// and only on Windows.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const {
  ARCHIVES,
  UPSTREAM_CARGO_DIST_VERSION,
  configuredCargoDistVersion,
  renderInstaller,
  scoopManifest,
  wingetManifests,
} = require("../package.js");

const ROOT = path.join(__dirname, "..", "..");
const TEMPLATE = fs.readFileSync(path.join(__dirname, "..", "installer.ps1"), "utf8");
const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const X64 = "vericto-cli-x86_64-pc-windows-msvc.zip";
const ARM64 = "vericto-cli-aarch64-pc-windows-msvc.zip";
const SUMS = new Map([
  [X64, "a".repeat(64)],
  [ARM64, "b".repeat(64)],
]);

function tmpdir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vericto-win-test-${tag}-`));
}

test("dist-workspace.toml builds with the cargo-dist the installer is derived from", () => {
  const config = fs.readFileSync(path.join(ROOT, "dist-workspace.toml"), "utf8");
  assert.equal(configuredCargoDistVersion(config), UPSTREAM_CARGO_DIST_VERSION);
});

test("the installer is rendered with the version and every archive's SHA-256", () => {
  const out = renderInstaller(TEMPLATE, "1.11.0", SUMS);
  assert.match(out, /\$app_version = '1\.11\.0'/);
  assert.match(out, /releases\/download\/v1\.11\.0"\)/);
  assert.equal(out.split(`"sha256" = "${"a".repeat(64)}"`).length - 1, 2); // x64 msvc + gnu
  assert.equal(out.split(`"sha256" = "${"b".repeat(64)}"`).length - 1, 2); // arm64 msvc + gnu
  assert.doesNotMatch(out, /@VERSION@|@SHA256:/);
  // The check itself, before anything is unpacked.
  const check = out.indexOf("Get-FileHash -Algorithm SHA256 -LiteralPath $dir_path");
  assert.ok(check > 0 && check < out.indexOf("Expand-Archive -Path $dir_path"));
  assert.match(out, /refusing to install an unverified binary/);
});

test("the installer is not rendered without a checksum, a version or the right cargo-dist", () => {
  assert.throws(() => renderInstaller(TEMPLATE, "1.11.0", new Map([[X64, "a".repeat(64)]])), /no published SHA-256 for vericto-cli-aarch64/);
  assert.throws(() => renderInstaller(TEMPLATE, "v1.11.0", SUMS), /not a release version/);
  assert.throws(() => renderInstaller(TEMPLATE, "1.11.0", SUMS, "0.33.0"), /port the new upstream installer/);
  assert.throws(() => renderInstaller(TEMPLATE + "\n# caf\u00e9\n", "1.11.0", SUMS), /must be ASCII/);
});

test("the Scoop manifest pins both architectures and updates from the release", () => {
  const m = scoopManifest("1.11.0", SUMS);
  assert.equal(m.version, "1.11.0");
  assert.equal(m.bin, "vericto.exe");
  assert.equal(m.license.identifier, "FSL-1.1-ALv2");
  assert.deepEqual(m.architecture["64bit"], {
    url: `https://github.com/vericto/vericto-cli/releases/download/v1.11.0/${X64}`,
    hash: "a".repeat(64),
  });
  assert.equal(m.architecture.arm64.hash, "b".repeat(64));
  assert.equal(m.autoupdate.architecture["64bit"].url, `https://github.com/vericto/vericto-cli/releases/download/v$version/${X64}`);
  assert.deepEqual(m.autoupdate.architecture.arm64.hash, { url: "$url.sha256" });
  assert.throws(() => scoopManifest("1.11.0", new Map()), /no published SHA-256/);
});

test("the winget manifests are a zip with a portable vericto.exe, x64 and arm64", () => {
  const files = wingetManifests("1.11.0", SUMS);
  assert.deepEqual(Object.keys(files).sort(), [
    "Vericto.VerictoCLI.installer.yaml",
    "Vericto.VerictoCLI.locale.en-US.yaml",
    "Vericto.VerictoCLI.yaml",
  ]);
  const inst = files["Vericto.VerictoCLI.installer.yaml"];
  assert.match(inst, /^InstallerType: zip$/m);
  assert.match(inst, /^NestedInstallerType: portable$/m);
  assert.match(inst, /^  PortableCommandAlias: vericto$/m);
  assert.match(inst, new RegExp(`Architecture: x64\\n  InstallerUrl: \\S+/v1\\.11\\.0/${X64}\\n  InstallerSha256: ${"A".repeat(64)}`));
  assert.match(inst, new RegExp(`Architecture: arm64\\n  InstallerUrl: \\S+/${ARM64}\\n  InstallerSha256: ${"B".repeat(64)}`));
  for (const [name, text] of Object.entries(files)) {
    assert.match(text, /^PackageIdentifier: Vericto\.VerictoCLI$/m, name);
    assert.match(text, /^PackageVersion: 1\.11\.0$/m, name);
    assert.match(text, /^ManifestVersion: 1\.10\.0$/m, name);
  }
  assert.match(files["Vericto.VerictoCLI.locale.en-US.yaml"], /^License: FSL-1\.1-ALv2$/m);
  assert.equal(ARCHIVES.length, 2);
});

// ── The rendered installer, run by Windows PowerShell (Windows only) ────────

const onWindows = process.platform === "win32";

// The environment for a child Windows PowerShell 5.1. When the test runs under
// PowerShell 7 (the GitHub Actions default shell on Windows), PSModulePath
// lists PowerShell 7's module folders, and 5.1 then fails to load its own
// Microsoft.PowerShell.Security module ("Get-ExecutionPolicy ... could not be
// loaded"). Without the variable, 5.1 builds its default module path.
function windowsPowerShellEnv() {
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.toUpperCase() === "PSMODULEPATH") delete env[key];
  }
  return env;
}

// A release archive laid out like cargo-dist's Windows zip: the files at the
// root. The "binary" is a marker, never run.
function makeZip(dir, name) {
  const content = path.join(dir, `${name}-content`);
  fs.mkdirSync(content);
  fs.writeFileSync(path.join(content, "vericto.exe"), `fake vericto from ${name}\n`);
  fs.writeFileSync(path.join(content, "README.md"), "readme\n");
  const zip = path.join(dir, name);
  const r = spawnSync("powershell.exe", [
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Compress-Archive -Path (Join-Path $env:SRC '*') -DestinationPath $env:DST",
  ], { env: { ...windowsPowerShellEnv(), SRC: content, DST: zip }, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return zip;
}

async function serve(dir) {
  const server = http.createServer((req, res) => {
    const file = path.join(dir, path.basename(decodeURIComponent(req.url)));
    if (!fs.existsSync(file)) {
      res.writeHead(404);
      return res.end();
    }
    res.writeHead(200);
    res.end(fs.readFileSync(file));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

function runInstaller(script, base, home) {
  return new Promise((resolve) => {
    const child = spawn(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script],
      {
        env: {
          ...windowsPowerShellEnv(),
          VERICTO_CLI_DOWNLOAD_URL: base,
          CARGO_HOME: path.join(home, "cargo"),
          XDG_CONFIG_HOME: path.join(home, "config"),
          VERICTO_CLI_NO_MODIFY_PATH: "1",
          VERICTO_CLI_DISABLE_UPDATE: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let output = "";
    child.stdout.on("data", (d) => (output += d));
    child.stderr.on("data", (d) => (output += d));
    child.on("close", (code) => resolve({ code, output }));
  });
}

test("the installer installs an archive whose SHA-256 matches", { skip: !onWindows }, async () => {
  const dir = tmpdir("ps-ok");
  const { server, base } = await serve(dir);
  try {
    const sums = new Map();
    for (const name of [X64, ARM64]) sums.set(name, sha256(fs.readFileSync(makeZip(dir, name))));
    const script = path.join(dir, "vericto-cli-installer.ps1");
    fs.writeFileSync(script, renderInstaller(TEMPLATE, "1.11.0", sums));
    const r = await runInstaller(script, base, dir);
    assert.equal(r.code, 0, r.output);
    assert.match(r.output, /verified vericto-cli-(x86_64|aarch64)-pc-windows-msvc\.zip/);
    const installed = fs.readFileSync(path.join(dir, "cargo", "bin", "vericto.exe"), "utf8");
    assert.match(installed, /^fake vericto from vericto-cli-(x86_64|aarch64)-pc-windows-msvc\.zip/);
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the installer refuses an archive whose SHA-256 does not match", { skip: !onWindows }, async () => {
  const dir = tmpdir("ps-bad");
  const { server, base } = await serve(dir);
  try {
    for (const name of [X64, ARM64]) makeZip(dir, name);
    const script = path.join(dir, "vericto-cli-installer.ps1");
    fs.writeFileSync(script, renderInstaller(TEMPLATE, "1.11.0", SUMS)); // a..., b...: wrong
    const r = await runInstaller(script, base, dir);
    assert.notEqual(r.code, 0, r.output);
    assert.match(r.output, /SHA-256 mismatch for vericto-cli-/);
    assert.ok(!fs.existsSync(path.join(dir, "cargo", "bin", "vericto.exe")));
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
