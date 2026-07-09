//! Persisted config and credential resolution.
//!
//! The CLI resolves `api_url`, `api_key` and `default_dialect` from three
//! sources, first match wins (see DESIGN §6):
//!   1. command-line flags
//!   2. environment (`VETRO_API_KEY`, `VETRO_API_URL`)
//!   3. config file `~/.config/vetro/config.toml` (written by `vetro login`)
//!
//! The config file holds the API key, so it is written with `0600` permissions
//! and never logged.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

/// The default backend when nothing overrides it.
pub const DEFAULT_API_URL: &str = "https://api.vetro.dev";

/// On-disk config. Every field is optional so a partial file still parses.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_dialect: Option<String>,
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
