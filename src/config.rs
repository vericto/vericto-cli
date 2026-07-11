//! Persisted config and credential resolution.
//!
//! The CLI resolves settings from several sources, first match wins (DESIGN §6):
//!   1. command-line flags
//!   2. environment (`VETRO_API_KEY`, `VETRO_API_URL`)
//!   3. project config `.vetro.toml` at the repo root — behavior defaults only,
//!      never credentials (§6.3, `ProjectConfig`)
//!   4. user config file `~/.config/vetro/config.toml` (written by `vetro login`)
//!
//! The config file holds the API key, so it is written with `0600` permissions
//! and never logged.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

/// The default backend when nothing overrides it.
pub const DEFAULT_API_URL: &str = "https://api.vetro.dev";

/// The default OIDC audience requested in the ID token when none is configured
/// (§6.1). Trust policies are created against this by convention.
pub const DEFAULT_OIDC_AUDIENCE: &str = "vetro";

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
    /// authorizes the exchange. Written by `vetro login --oidc --workspace <id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// OIDC audience to request in the ID token (must match a trust policy). Not
    /// a secret. Defaults to `DEFAULT_OIDC_AUDIENCE` when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_audience: Option<String>,
}

/// Returns the config file path (DESIGN §6): `$XDG_CONFIG_HOME/vetro/config.toml`
/// when the env var is set, otherwise `~/.config/vetro/config.toml`. We follow
/// the XDG convention on every Unix (including macOS) so the path is predictable
/// and overridable in tests/CI, rather than `dirs`' platform-specific default
/// (`~/Library/Application Support` on macOS). None if no home is resolvable.
pub fn config_path() -> Option<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            PathBuf::from(xdg)
        } else {
            dirs::home_dir()?.join(".config")
        }
    } else if cfg!(unix) {
        dirs::home_dir()?.join(".config")
    } else {
        dirs::config_dir()?
    };
    Some(base.join("vetro").join("config.toml"))
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
            std::fs::create_dir_all(dir)?;
        }
        let text = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        write_private(&path, &text)?;
        Ok(path)
    }
}

/// Writes `contents` to `path` with owner-only (`0600`) permissions on Unix.
/// On other platforms it writes normally (ACLs are the platform's concern).
fn write_private(path: &std::path::Path, contents: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(contents.as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// Project-level config from `.vetro.toml` at the repo root (§6.3). Committed
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
}

/// Loads `.vetro.toml` from the current directory (repo root). Missing file →
/// default. A file that carries `api_key` or `allow_degraded` is rejected: those
/// are a secret and a per-run safety decision respectively, neither of which
/// belongs in a committed, PR-reviewable file (§6.3).
pub fn load_project() -> io::Result<ProjectConfig> {
    let path = std::path::Path::new(".vetro.toml");
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let cfg: ProjectConfig = toml::from_str(&text).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid .vetro.toml: {e}"),
                )
            })?;
            if cfg.api_key.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ".vetro.toml must not contain api_key — use `vetro login`, VETRO_API_KEY, or --api-key.",
                ));
            }
            if cfg.allow_degraded.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    ".vetro.toml must not set allow_degraded — pass --allow-degraded per run so the bypass is visible in the pipeline.",
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
            KeySource::Env => "VETRO_API_KEY env",
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
        let src = if std::env::var_os("VETRO_API_KEY").is_some() {
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

    #[test]
    fn key_source_labels() {
        assert_eq!(KeySource::Flag.label(), "--api-key flag");
        assert_eq!(KeySource::Env.label(), "VETRO_API_KEY env");
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
        // Flag/env value beats the file. (No VETRO_API_KEY set in this test env
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
        // config_path reads XDG_CONFIG_HOME; set it for a deterministic result.
        let prev = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/xdg-test");
        let p = config_path().unwrap();
        assert!(p.ends_with("vetro/config.toml"));
        assert!(p.starts_with("/tmp/xdg-test"));
        match prev {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
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
    }
}
