// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: FSL-1.1-ALv2

//! Persisted config and credential resolution.
//!
//! The CLI resolves settings from several sources, first match wins (DESIGN §6):
//!   1. command-line flags
//!   2. environment (`VERICTO_API_KEY`, `VERICTO_API_URL`)
//!   3. project config `.vericto.toml` at the repo root — behavior defaults only,
//!      never credentials (§6.3, `ProjectConfig`)
//!   4. user config file `~/.config/vericto/config.toml` (written by `vericto login`)
//!
//! The config file holds the API key, so it is written owner-only and never
//! logged: `0600` (directory `0700`) on Unix, and on Windows a protected DACL
//! that grants the current user alone, with no inherited entries.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

/// The default backend when nothing overrides it.
pub const DEFAULT_API_URL: &str = "https://api.vericto.com";

/// The default dashboard origin `vericto login`'s browser flow opens (§6,
/// "verified login") — distinct from `DEFAULT_API_URL`: the dashboard's own
/// public origin, which reverse-proxies to the Next.js app, vs. the API's.
/// Not persisted to the config file — only `login` itself needs it, to know
/// where to point the browser; every other command talks to `api_url`.
pub const DEFAULT_APP_URL: &str = "https://vericto.com";

/// The default OIDC audience requested in the ID token when none is configured
/// (§6.1). Trust policies are created against this by convention.
pub const DEFAULT_OIDC_AUDIENCE: &str = "vericto";

/// On-disk config. Every field is optional so a partial file still parses.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_dialect: Option<String>,
    /// Workspace to authenticate against when using OIDC/workload-identity login
    /// (§6.1). Not a secret — it only identifies the tenant whose trust policy
    /// authorizes the exchange. Written by `vericto login --oidc --workspace <id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// OIDC audience to request in the ID token (must match a trust policy). Not
    /// a secret. Defaults to `DEFAULT_OIDC_AUDIENCE` when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_audience: Option<String>,
}

/// Returns the config file path (DESIGN §6): `$XDG_CONFIG_HOME/vericto/config.toml`
/// when the env var is set, otherwise `~/.config/vericto/config.toml` on Unix
/// and `%APPDATA%\vericto\config.toml` on Windows. We follow the XDG convention
/// on every Unix (including macOS) so the path is predictable and overridable
/// in tests/CI, rather than `dirs`' platform-specific default
/// (`~/Library/Application Support` on macOS). Windows keeps the platform's
/// own per-user location (the roaming AppData folder), and `XDG_CONFIG_HOME`
/// overrides it there too. None if no home is resolvable.
pub fn config_path() -> Option<PathBuf> {
    config_path_in(std::env::var_os("XDG_CONFIG_HOME"))
}

/// `config_path` for a given `XDG_CONFIG_HOME` value (tests pass it in instead
/// of changing the process environment, which other tests read concurrently).
fn config_path_in(xdg: Option<std::ffi::OsString>) -> Option<PathBuf> {
    // An empty value is the same as unset (until 1.11.0 it meant
    // `~/.config` on Windows too, instead of `%APPDATA%`).
    let base = match xdg.filter(|x| !x.is_empty()) {
        Some(xdg) => PathBuf::from(xdg),
        None if cfg!(unix) => dirs::home_dir()?.join(".config"),
        None => dirs::config_dir()?,
    };
    Some(base.join("vericto").join("config.toml"))
}

impl Config {
    /// Loads the config file if it exists. A missing file is not an error
    /// (returns default); a malformed file is surfaced so the user can fix it.
    pub fn load() -> io::Result<Config> {
        let Some(path) = config_path() else {
            return Ok(Config::default());
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid config at {}: {e}", path.display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes the config to disk, creating the directory as needed. The file is
    /// created/truncated with `0600` so the stored API key isn't world-readable.
    pub fn save(&self) -> io::Result<PathBuf> {
        let path = config_path().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "could not resolve a config directory",
            )
        })?;
        if let Some(dir) = path.parent() {
            create_private_dir(dir)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        write_private(&path, &text)?;
        Ok(path)
    }
}

/// Creates the config directory (and missing parents) owner-only, so a
/// directory the CLI creates is not listable by other users: `0700` on Unix,
/// and on Windows a protected DACL for the current user, inherited by what is
/// created inside it. An existing directory is left as it is on both.
fn create_private_dir(dir: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(windows)]
    {
        if dir.is_dir() {
            return Ok(());
        }
        std::fs::create_dir_all(dir)?;
        win_acl::restrict_to_owner(dir, true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Writes `contents` to `path` owner-only: `0600` on Unix, a protected DACL
/// granting the current user alone on Windows (the ACL equivalent of `0600`:
/// no entry inherited from the parent, so a key written under a shared
/// `XDG_CONFIG_HOME` is not readable by the other users that folder grants).
///
/// An existing file (written by hand, or by an older version) loses its
/// broader permissions before the key is written: on Unix it is narrowed
/// first, on Windows a new owner-only file replaces it.
fn write_private(path: &std::path::Path, contents: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(contents.as_bytes())?;
        Ok(())
    }
    #[cfg(windows)]
    {
        win_acl::write_owner_only(path, contents)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(path, contents)
    }
}

/// Owner-only access on Windows, without `unsafe` (the crate forbids it): the
/// current user's SID from `whoami /user`, and `icacls` to replace the
/// object's DACL with a protected one (`/inheritance:r`: no inherited
/// entries) holding a single entry, full access for that user. Both tools
/// ship with every Windows since Vista and are run from the system directory.
/// Administrators can still take ownership, as root can read a `0600` file.
#[cfg(windows)]
mod win_acl {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// `%SystemRoot%\System32\<exe>`, so a same-named program elsewhere on
    /// `PATH` is never run instead.
    fn system_tool(exe: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join("System32").join(exe)
    }

    fn run(cmd: &mut Command, what: &str) -> io::Result<String> {
        let out = cmd
            .output()
            .map_err(|e| io::Error::other(format!("could not run {what}: {e}")))?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "{what} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// The SID of the user the process runs as (`S-1-5-21-...`).
    pub(super) fn current_user_sid() -> io::Result<String> {
        let out = run(
            Command::new(system_tool("whoami.exe")).args(["/user", "/fo", "csv", "/nh"]),
            "whoami /user",
        )?;
        parse_whoami_sid(&out).ok_or_else(|| {
            io::Error::other(format!("unexpected `whoami /user` output: {}", out.trim()))
        })
    }

    /// The SID in `whoami /user /fo csv /nh` output: `"host\name","S-1-5-..."`.
    pub(super) fn parse_whoami_sid(out: &str) -> Option<String> {
        let sid = out.trim().rsplit(',').next()?.trim().trim_matches('"');
        (sid.starts_with("S-1-") && sid[4..].chars().all(|c| c.is_ascii_digit() || c == '-'))
            .then(|| sid.to_string())
    }

    /// Sets `path`'s DACL to a protected one granting the current user full
    /// access and nobody else anything. Entries `path` carries explicitly
    /// (not inherited) are kept, so it is only applied to objects the CLI has
    /// just created, which have none. `inherit`: for a directory, the entry
    /// is inherited by the files and directories created inside it.
    pub(super) fn restrict_to_owner(path: &Path, inherit: bool) -> io::Result<()> {
        let sid = current_user_sid()?;
        let grant = if inherit {
            format!("*{sid}:(OI)(CI)F")
        } else {
            format!("*{sid}:F")
        };
        run(
            Command::new(system_tool("icacls.exe")).arg(path).args([
                "/inheritance:r",
                "/grant:r",
                &grant,
                "/q",
            ]),
            "icacls",
        )
        .map(|_| ())
    }

    /// Writes `contents` to `path` owner-only: into a new file next to it,
    /// restricted before anything is written, then renamed over `path`. The
    /// rename keeps the new file's DACL, so whatever entries an existing
    /// `path` had are gone with it.
    pub(super) fn write_owner_only(path: &Path, contents: &str) -> io::Result<()> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
        let mut tmp_name = name.to_os_string();
        tmp_name.push(format!(".{}.tmp", std::process::id()));
        let tmp = path.with_file_name(tmp_name);
        let result = (|| {
            std::fs::File::create_new(&tmp)?;
            restrict_to_owner(&tmp, false)?;
            std::fs::write(&tmp, contents)?;
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// For tests: whether `path`'s DACL is protected, and the SID of each of
    /// its access entries (PowerShell's `Get-Acl`, which does not depend on
    /// the display language).
    #[cfg(test)]
    pub(super) fn dacl_of(path: &Path) -> io::Result<(bool, Vec<String>)> {
        let script = "$a = Get-Acl -LiteralPath $env:VERICTO_ACL_PATH; \
                      [string]$a.AreAccessRulesProtected; \
                      $a.Access | ForEach-Object { \
                        $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }";
        let out = run(
            Command::new(system_tool(r"WindowsPowerShell\v1.0\powershell.exe"))
                .args(["-NoProfile", "-NonInteractive", "-Command", script])
                .env("VERICTO_ACL_PATH", path),
            "Get-Acl",
        )?;
        let mut lines = out.lines().map(str::trim).filter(|l| !l.is_empty());
        let protected = lines.next() == Some("True");
        Ok((protected, lines.map(String::from).collect()))
    }
}

/// Project-level config from `.vericto.toml` at the repo root (§6.3). Committed
/// and PR-reviewable, so it holds *defaults for behavior* — never credentials.
/// Flags and env still override these.
#[derive(Debug, Default, Deserialize)]
pub struct ProjectConfig {
    #[serde(default)]
    pub default_dialect: Option<String>,
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub baseline: Option<String>,
    /// Workspace to authenticate against for OIDC login (§6.1). Safe to commit —
    /// it's a tenant identifier, not a credential; the trust policy on the server
    /// side is what actually authorizes the exchange.
    #[serde(default)]
    pub workspace_id: Option<String>,
    /// OIDC audience to request (must match the workspace trust policy). Safe to
    /// commit.
    #[serde(default)]
    pub oidc_audience: Option<String>,
    /// Name of the env var holding a pre-minted OIDC ID token (GitLab-style). The
    /// token itself lives only in the CI env, never in this file.
    #[serde(default)]
    pub oidc_token_env: Option<String>,
    // Trap fields: present only to detect and reject secrets/decisions that must
    // not live in a committed file (see load_project's validation).
    #[serde(default)]
    pub api_key: Option<toml::Value>,
    #[serde(default)]
    pub allow_degraded: Option<toml::Value>,
    /// Offline mode (§13) swaps the workspace's policy for the standard rules.
    /// A committed file must not be able to do that for every run, CI included.
    #[serde(default)]
    pub offline: Option<toml::Value>,
}

/// Loads `.vericto.toml` from the current directory (repo root). Missing file →
/// default. A file that carries `api_key`, `allow_degraded` or `offline` is
/// rejected: a secret, a per-run safety decision and a per-run choice of rule
/// set, none of which belongs in a committed, PR-reviewable file (§6.3, §13).
pub fn load_project() -> io::Result<ProjectConfig> {
    let path = std::path::Path::new(".vericto.toml");
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let cfg: ProjectConfig = toml::from_str(&text).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid .vericto.toml: {e}"),
                )
            })?;
            if cfg.api_key.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ".vericto.toml must not contain api_key — use `vericto login`, VERICTO_API_KEY, or --api-key.",
                ));
            }
            if cfg.allow_degraded.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ".vericto.toml must not set allow_degraded — pass --allow-degraded per run so the bypass is visible in the pipeline.",
                ));
            }
            if cfg.offline.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ".vericto.toml must not set offline — pass --offline or VERICTO_OFFLINE=1 per run, so a switch to the standard rules is visible in the pipeline.",
                ));
            }
            Ok(cfg)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ProjectConfig::default()),
        Err(e) => Err(e),
    }
}

/// The fully-resolved settings a command runs with, plus where the key came
/// from (for `doctor` to report without leaking the value).
pub struct Resolved {
    pub api_url: String,
    pub api_key: Option<String>,
    pub key_source: KeySource,
}

/// Where the effective API key was resolved from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Flag,
    Env,
    ConfigFile,
    None,
}

impl KeySource {
    pub fn label(self) -> &'static str {
        match self {
            KeySource::Flag => "--api-key flag",
            KeySource::Env => "VERICTO_API_KEY env",
            KeySource::ConfigFile => "config file",
            KeySource::None => "none",
        }
    }
}

/// Resolves api_url + api_key with the documented precedence. `flag_*` are the
/// values clap parsed (flags already fold in env via clap's `env` feature, so
/// we distinguish "came from a flag/env" from "came from the file" by checking
/// the raw env var ourselves).
pub fn resolve(
    flag_api_url: &str,
    flag_api_url_is_default: bool,
    flag_api_key: Option<&str>,
    file: &Config,
) -> Resolved {
    // api_url: an explicitly-passed flag/env beats the file beats the default.
    let api_url = if !flag_api_url_is_default {
        flag_api_url.to_string()
    } else if let Some(u) = file.api_url.as_deref() {
        u.to_string()
    } else {
        flag_api_url.to_string()
    };

    // api_key: flag/env (clap already merged them) beats the file.
    let (api_key, key_source) = if let Some(k) = flag_api_key {
        let src = if std::env::var_os("VERICTO_API_KEY").is_some() {
            KeySource::Env
        } else {
            KeySource::Flag
        };
        (Some(k.to_string()), src)
    } else if let Some(k) = file.api_key.as_deref() {
        (Some(k.to_string()), KeySource::ConfigFile)
    } else {
        (None, KeySource::None)
    };

    Resolved {
        api_url,
        api_key,
        key_source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_narrows_an_existing_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vericto").join("config.toml");
        create_private_dir(path.parent().unwrap()).unwrap();
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);

        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, "api_key = \"vtro_x\"").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "api_key = \"vtro_x\""
        );
    }

    /// The Windows equivalent of the test above: the directory the CLI creates
    /// and a config file written over an existing one end up with a protected
    /// DACL whose only entry is the current user's, in place of the entries
    /// they would inherit from the temp directory (which also grant SYSTEM and
    /// Administrators).
    #[cfg(windows)]
    #[test]
    fn write_private_leaves_only_the_current_user_in_the_dacl() {
        let me = win_acl::current_user_sid().unwrap();
        let owner_only = (true, vec![me.clone()]);
        let dir = tempfile::tempdir().unwrap();
        let (_, inherited) = win_acl::dacl_of(dir.path()).unwrap();
        assert!(
            inherited.len() > 1,
            "the temp dir grants more than the user: {inherited:?}"
        );

        let config_dir = dir.path().join("vericto");
        create_private_dir(&config_dir).unwrap();
        assert_eq!(win_acl::dacl_of(&config_dir).unwrap(), owner_only);

        let path = config_dir.join("config.toml");
        std::fs::write(&path, "old").unwrap();
        write_private(&path, "api_key = \"vtro_x\"").unwrap();
        assert_eq!(win_acl::dacl_of(&path).unwrap(), owner_only);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "api_key = \"vtro_x\""
        );

        // A file outside a private directory, inheriting broader entries, is
        // replaced by an owner-only one; no temporary file is left behind.
        let loose = dir.path().join("loose.toml");
        std::fs::write(&loose, "old").unwrap();
        assert!(win_acl::dacl_of(&loose).unwrap().1.len() > 1);
        write_private(&loose, "x").unwrap();
        assert_eq!(win_acl::dacl_of(&loose).unwrap(), owner_only);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
    }

    #[cfg(windows)]
    #[test]
    fn parses_the_sid_from_whoami() {
        assert_eq!(
            win_acl::parse_whoami_sid("\"desktop-1\\runner admin\",\"S-1-5-21-1-2-3-500\"\r\n"),
            Some("S-1-5-21-1-2-3-500".into())
        );
        assert_eq!(win_acl::parse_whoami_sid("\"x\",\"not a sid\""), None);
        assert_eq!(win_acl::parse_whoami_sid(""), None);
    }

    #[test]
    fn key_source_labels() {
        assert_eq!(KeySource::Flag.label(), "--api-key flag");
        assert_eq!(KeySource::Env.label(), "VERICTO_API_KEY env");
        assert_eq!(KeySource::ConfigFile.label(), "config file");
        assert_eq!(KeySource::None.label(), "none");
    }

    #[test]
    fn resolve_prefers_flag_url_over_file_over_default() {
        let file = Config {
            api_url: Some("https://file.example".into()),
            ..Default::default()
        };
        // Explicit flag (not default) wins.
        let r = resolve("https://flag.example", false, None, &file);
        assert_eq!(r.api_url, "https://flag.example");
        // Flag left at default → file wins.
        let r = resolve(DEFAULT_API_URL, true, None, &file);
        assert_eq!(r.api_url, "https://file.example");
        // No file → default.
        let r = resolve(DEFAULT_API_URL, true, None, &Config::default());
        assert_eq!(r.api_url, DEFAULT_API_URL);
    }

    #[test]
    fn resolve_api_key_precedence_and_source() {
        let file = Config {
            api_key: Some("vtro_from_file".into()),
            ..Default::default()
        };
        // Flag/env value beats the file. (No VERICTO_API_KEY set in this test env
        // → source is Flag.)
        let r = resolve(DEFAULT_API_URL, true, Some("vtro_flag"), &file);
        assert_eq!(r.api_key.as_deref(), Some("vtro_flag"));
        assert_eq!(r.key_source, KeySource::Flag);
        // No flag → file, source ConfigFile.
        let r = resolve(DEFAULT_API_URL, true, None, &file);
        assert_eq!(r.api_key.as_deref(), Some("vtro_from_file"));
        assert_eq!(r.key_source, KeySource::ConfigFile);
        // Nothing → None.
        let r = resolve(DEFAULT_API_URL, true, None, &Config::default());
        assert!(r.api_key.is_none());
        assert_eq!(r.key_source, KeySource::None);
    }

    #[test]
    fn config_path_honors_xdg() {
        let p = config_path_in(Some("/tmp/xdg-test".into())).unwrap();
        assert!(p.ends_with("vericto/config.toml"));
        assert!(p.starts_with("/tmp/xdg-test"));
        // An empty value is the same as unset on Unix: ~/.config.
        #[cfg(unix)]
        assert_eq!(
            config_path_in(Some("".into())).unwrap(),
            dirs::home_dir()
                .unwrap()
                .join(".config/vericto/config.toml")
        );
    }

    /// Without `XDG_CONFIG_HOME`, Windows uses the roaming AppData folder
    /// (`%APPDATA%`), the platform's per-user config location.
    #[cfg(windows)]
    #[test]
    fn config_path_defaults_to_appdata_on_windows() {
        let p = config_path_in(None).unwrap();
        assert_eq!(
            p,
            dirs::config_dir()
                .unwrap()
                .join("vericto")
                .join("config.toml")
        );
        assert!(
            p.ends_with(r"AppData\Roaming\vericto\config.toml"),
            "{}",
            p.display()
        );
        assert_eq!(config_path_in(Some("".into())), Some(p));
    }

    #[test]
    fn project_config_parses_behavior_fields() {
        let cfg: ProjectConfig = toml::from_str(
            "default_dialect = \"mysql\"\nfail_on = \"flag\"\nbaseline = \".b.json\"",
        )
        .unwrap();
        assert_eq!(cfg.default_dialect.as_deref(), Some("mysql"));
        assert_eq!(cfg.fail_on.as_deref(), Some("flag"));
        assert_eq!(cfg.baseline.as_deref(), Some(".b.json"));
        assert!(cfg.api_key.is_none());
    }

    #[test]
    fn project_config_detects_forbidden_credentials() {
        // The trap fields deserialize so load_project can reject them.
        let cfg: ProjectConfig = toml::from_str("api_key = \"vtro_x\"").unwrap();
        assert!(cfg.api_key.is_some());
        let cfg: ProjectConfig = toml::from_str("allow_degraded = true").unwrap();
        assert!(cfg.allow_degraded.is_some());
        let cfg: ProjectConfig = toml::from_str("offline = true").unwrap();
        assert!(cfg.offline.is_some());
    }
}
