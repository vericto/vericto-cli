//! CI workload-identity (OIDC) login (§6.1).
//!
//! Instead of a long-lived `vtro_...` key sitting in a CI secret, a job can prove
//! its identity with a short-lived, provider-signed OIDC ID token. This module
//! obtains that token from the CI provider; the backend
//! (`POST /api/v1/auth/oidc-exchange`) validates it against the workspace's trust
//! policies and mints a short-lived, `ci_dryrun:execute`-only key. That minted
//! key lives in memory for the process only — it is never written to disk.
//!
//! Detection is best-effort. **GitHub Actions** exposes a token endpoint via
//! `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN` (needs
//! `permissions: id-token: write`); it is fetched with the requested audience,
//! reading `{ "value": "<jwt>" }`. **GitLab CI** mints the token at
//! pipeline-config time via `id_tokens:` and hands it to the job as an
//! environment variable whose name the user chose; the CLI reads that variable
//! (default `VETRO_ID_TOKEN`, overridable).
//!
//! `availability()` returns `None` when no OIDC signal is present, so the caller
//! silently falls back to a static key rather than failing.

use crate::api::{ApiError, Transport};

/// The GitLab env var the CLI reads for a pre-minted ID token by default. Users
/// name it in their `id_tokens:` block; this is the name our `vetro init`
/// GitLab template uses, and a sensible convention when unspecified.
pub const DEFAULT_GITLAB_TOKEN_ENV: &str = "VETRO_ID_TOKEN";

/// How the CLI can obtain an OIDC ID token in the current environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// GitHub Actions token endpoint (URL + bearer request token).
    GitHubEndpoint { url: String, request_token: String },
    /// A pre-minted token already sitting in an environment variable (GitLab, or
    /// any provider the user wired a token env var for). Carries the var name so
    /// diagnostics can say where it came from.
    EnvToken { var: String, token: String },
}

/// Reads a non-empty, trimmed environment variable.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| {
        let t = v.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

/// Detects whether an OIDC ID token can be obtained here, and how. `token_env`
/// is the env var name to check for a pre-minted token (GitLab-style); pass the
/// user's configured name or [`DEFAULT_GITLAB_TOKEN_ENV`].
///
/// GitHub's request endpoint takes precedence when both are somehow present,
/// since it yields a fresh token with the exact audience we ask for.
pub fn availability(token_env: &str) -> Option<Availability> {
    if let (Some(url), Some(request_token)) = (
        env_nonempty("ACTIONS_ID_TOKEN_REQUEST_URL"),
        env_nonempty("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) {
        return Some(Availability::GitHubEndpoint { url, request_token });
    }
    if let Some(token) = env_nonempty(token_env) {
        return Some(Availability::EnvToken {
            var: token_env.to_string(),
            token,
        });
    }
    None
}

/// Obtains an OIDC ID token for `audience`, given a detected [`Availability`].
///
/// For [`Availability::GitHubEndpoint`] it calls the token endpoint (honoring the
/// same transport/CA/proxy settings as every other request) and extracts the JWT
/// from the `{ "value": ... }` body. `audience` is passed through so GitHub mints
/// a token whose `aud` claim matches the workspace's trust policy. For a
/// pre-minted [`Availability::EnvToken`], the audience was fixed when the token
/// was minted, so `audience` is unused and the stored token is returned as-is.
pub async fn fetch_token(
    avail: &Availability,
    audience: Option<&str>,
    transport: &Transport,
) -> Result<String, ApiError> {
    match avail {
        Availability::EnvToken { token, .. } => Ok(token.clone()),
        Availability::GitHubEndpoint { url, request_token } => {
            let client = crate::api::build_client(transport)?;
            let mut req = client
                .get(url)
                .header("Authorization", format!("Bearer {request_token}"))
                .header("Accept", "application/json");
            // GitHub uses the `audience` query param to set the token's `aud`
            // claim. Omit it to let GitHub use its default audience.
            if let Some(aud) = audience {
                req = req.query(&[("audience", aud)]);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| ApiError::Transport(e.to_string()))?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(ApiError::Backend {
                    status: status.as_u16(),
                    message: format!("GitHub OIDC token request failed: {}", body.trim()),
                });
            }
            let body: GitHubTokenBody = resp.json().await.map_err(|e| ApiError::Backend {
                status: status.as_u16(),
                message: format!("invalid GitHub OIDC token body: {e}"),
            })?;
            let token = body.value.trim().to_string();
            if token.is_empty() {
                return Err(ApiError::Backend {
                    status: status.as_u16(),
                    message: "GitHub OIDC token endpoint returned an empty value".to_string(),
                });
            }
            Ok(token)
        }
    }
}

/// Body of GitHub's ID-token endpoint: `{ "value": "<jwt>" }`.
#[derive(serde::Deserialize)]
struct GitHubTokenBody {
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OIDC-detection vars, snapshotted/cleared so these tests don't race
    /// with the ambient environment.
    const KEYS: [&str; 3] = [
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "VETRO_ID_TOKEN",
    ];

    fn with_clean_env<T>(f: impl FnOnce() -> T) -> T {
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            KEYS.iter().map(|k| (*k, std::env::var_os(k))).collect();
        for k in KEYS {
            std::env::remove_var(k);
        }
        let out = f();
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        out
    }

    #[test]
    fn availability_none_without_signals() {
        with_clean_env(|| {
            assert_eq!(availability(DEFAULT_GITLAB_TOKEN_ENV), None);
        });
    }

    #[test]
    fn availability_detects_github_endpoint() {
        with_clean_env(|| {
            std::env::set_var(
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "https://gh/token?api-version=2.0",
            );
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-tok");
            match availability(DEFAULT_GITLAB_TOKEN_ENV) {
                Some(Availability::GitHubEndpoint { url, request_token }) => {
                    assert!(url.contains("api-version"));
                    assert_eq!(request_token, "req-tok");
                }
                other => panic!("expected GitHubEndpoint, got {other:?}"),
            }
        });
    }

    #[test]
    fn availability_detects_env_token() {
        with_clean_env(|| {
            std::env::set_var("VETRO_ID_TOKEN", "  jwt.body.sig  ");
            match availability("VETRO_ID_TOKEN") {
                Some(Availability::EnvToken { var, token }) => {
                    assert_eq!(var, "VETRO_ID_TOKEN");
                    assert_eq!(token, "jwt.body.sig"); // trimmed
                }
                other => panic!("expected EnvToken, got {other:?}"),
            }
        });
    }

    #[test]
    fn github_endpoint_takes_precedence_over_env_token() {
        with_clean_env(|| {
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", "https://gh/token");
            std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-tok");
            std::env::set_var("VETRO_ID_TOKEN", "env-jwt");
            assert!(matches!(
                availability("VETRO_ID_TOKEN"),
                Some(Availability::GitHubEndpoint { .. })
            ));
        });
    }

    /// A transport with a real timeout — `Transport::default()` has a zero
    /// timeout, which reqwest treats as "time out immediately".
    fn test_transport() -> Transport {
        Transport {
            timeout: std::time::Duration::from_secs(5),
            ca_bundle: None,
        }
    }

    #[tokio::test]
    async fn fetch_token_returns_env_token_verbatim() {
        let avail = Availability::EnvToken {
            var: "VETRO_ID_TOKEN".into(),
            token: "env-jwt".into(),
        };
        let tok = fetch_token(&avail, Some("vetro"), &test_transport())
            .await
            .unwrap();
        assert_eq!(tok, "env-jwt");
    }

    #[tokio::test]
    async fn fetch_token_reads_github_value_field() {
        use wiremock::matchers::{header, method, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("authorization", "Bearer req-tok"))
            .and(query_param("audience", "vetro"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": "gh.jwt.token" })),
            )
            .mount(&server)
            .await;
        let avail = Availability::GitHubEndpoint {
            url: server.uri(),
            request_token: "req-tok".into(),
        };
        let tok = fetch_token(&avail, Some("vetro"), &test_transport())
            .await
            .unwrap();
        assert_eq!(tok, "gh.jwt.token");
    }
}
