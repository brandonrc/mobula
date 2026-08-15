//! OIDC/JWT identity for Mobula (Phase 2, ADR-0003).
//!
//! Mobula owns bearer-token validation in BOTH Nebari-native and
//! standalone modes: NebariApp/SecurityPolicy auth is browser-only, and
//! `ray job submit` speaks Bearer. Any compliant IdP works — the contract
//! is OIDC discovery + JWKS + RS256.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

/// Fixed v0 roles, ordered by privilege (ADR-0003; custom roles later).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Viewer,
    Developer,
    Admin,
}

impl Role {
    pub fn permits(self, required: Role) -> bool {
        self >= required
    }
}

/// Authenticated caller, attached to requests after validation.
#[derive(Debug, Clone)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub role: Option<Role>,
}

/// Mapping from IdP group names to Mobula roles. `"*"` matches any
/// authenticated caller (e.g. `viewer = ["*"]`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoleMappings {
    #[serde(default)]
    pub admin: Vec<String>,
    #[serde(default)]
    pub developer: Vec<String>,
    #[serde(default)]
    pub viewer: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// OIDC issuer URL; `{issuer}/.well-known/openid-configuration` must
    /// resolve. Trailing slash insignificant.
    pub issuer: String,
    /// Required `aud` claim value.
    pub audience: String,
    /// Claim carrying group memberships (array of strings, or one
    /// space-delimited string). Keycloak default: "groups".
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub roles: RoleMappings,
}

fn default_groups_claim() -> String {
    "groups".into()
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("JWKS fetch failed: {0}")]
    Jwks(String),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("token key id not found in JWKS")]
    UnknownKeyId,
}

#[derive(Deserialize)]
struct DiscoveryDoc {
    jwks_uri: String,
}

#[derive(Deserialize)]
struct JwksDoc {
    keys: Vec<serde_json::Value>,
}

/// Validates Bearer JWTs against the issuer's JWKS.
///
/// Keys are cached; an unknown `kid` triggers at most one JWKS refresh
/// per [`REFRESH_COOLDOWN`] so key rotation works without letting a
/// garbage token drive request floods at the IdP.
pub struct Validator {
    config: AuthConfig,
    client: reqwest::Client,
    jwks_uri: String,
    keys: RwLock<Arc<HashMap<String, DecodingKey>>>,
    last_refresh: Mutex<Instant>,
}

const REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

impl Validator {
    /// Run OIDC discovery and the initial JWKS fetch. Fails fast — a
    /// control plane that cannot validate tokens must not start serving.
    pub async fn discover(config: AuthConfig, client: reqwest::Client) -> Result<Self, AuthError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let doc: DiscoveryDoc = client
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| AuthError::Discovery(e.without_url().to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Discovery(e.without_url().to_string()))?;

        let validator = Self {
            config,
            client,
            jwks_uri: doc.jwks_uri,
            keys: RwLock::new(Arc::new(HashMap::new())),
            last_refresh: Mutex::new(Instant::now() - REFRESH_COOLDOWN),
        };
        validator.refresh_jwks().await?;
        Ok(validator)
    }

    async fn refresh_jwks(&self) -> Result<(), AuthError> {
        // Cooldown check under the lock so concurrent unknown-kid storms
        // collapse into one upstream fetch.
        let mut last = self.last_refresh.lock().await;
        if last.elapsed() < REFRESH_COOLDOWN && !self.keys.read().await.is_empty() {
            return Ok(());
        }
        let doc: JwksDoc = self
            .client
            .get(&self.jwks_uri)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| AuthError::Jwks(e.without_url().to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Jwks(e.without_url().to_string()))?;

        let mut keys = HashMap::new();
        for key in doc.keys {
            let kid = key.get("kid").and_then(|k| k.as_str()).map(String::from);
            let jwk: Result<jsonwebtoken::jwk::Jwk, _> = serde_json::from_value(key);
            if let (Some(kid), Ok(jwk)) = (kid, jwk) {
                if let Ok(decoding) = DecodingKey::from_jwk(&jwk) {
                    keys.insert(kid, decoding);
                }
            }
        }
        tracing::info!(keys = keys.len(), "JWKS refreshed");
        *self.keys.write().await = Arc::new(keys);
        *last = Instant::now();
        Ok(())
    }

    /// Validate a Bearer token: RS256 signature against JWKS, `iss`,
    /// `aud`, `exp`/`nbf`. Returns the mapped identity.
    pub async fn validate(&self, token: &str) -> Result<Identity, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        if header.alg != Algorithm::RS256 {
            return Err(AuthError::InvalidToken(format!(
                "unsupported alg {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("missing kid".into()))?;

        let mut key = self.keys.read().await.get(&kid).cloned();
        if key.is_none() {
            self.refresh_jwks().await?;
            key = self.keys.read().await.get(&kid).cloned();
        }
        let key = key.ok_or(AuthError::UnknownKeyId)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.audience]);
        validation.set_issuer(&[self.config.issuer.trim_end_matches('/')]);
        let data = decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        Ok(self.identity_from_claims(&data.claims))
    }

    fn identity_from_claims(&self, claims: &serde_json::Value) -> Identity {
        let groups = match claims.get(&self.config.groups_claim) {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
            Some(serde_json::Value::String(s)) => s.split_whitespace().map(String::from).collect(),
            _ => Vec::new(),
        };
        let role = self.config.roles.resolve(&groups);
        Identity {
            subject: claims
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(String::from),
            groups,
            role,
        }
    }
}

impl RoleMappings {
    /// Highest role whose mapping matches a group (or `"*"`).
    pub fn resolve(&self, groups: &[String]) -> Option<Role> {
        let matches = |patterns: &[String]| {
            patterns
                .iter()
                .any(|p| p == "*" || groups.iter().any(|g| g == p))
        };
        if matches(&self.admin) {
            Some(Role::Admin)
        } else if matches(&self.developer) {
            Some(Role::Developer)
        } else if matches(&self.viewer) {
            Some(Role::Viewer)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mappings() -> RoleMappings {
        RoleMappings {
            admin: vec!["/platform-admins".into()],
            developer: vec!["/ml-eng".into(), "/data-sci".into()],
            viewer: vec!["*".into()],
        }
    }

    #[test]
    fn role_ordering_and_permits() {
        assert!(Role::Admin.permits(Role::Viewer));
        assert!(Role::Developer.permits(Role::Developer));
        assert!(!Role::Viewer.permits(Role::Developer));
        assert!(!Role::Developer.permits(Role::Admin));
    }

    #[test]
    fn highest_matching_role_wins() {
        let m = mappings();
        assert_eq!(
            m.resolve(&["/ml-eng".into(), "/platform-admins".into()]),
            Some(Role::Admin)
        );
        assert_eq!(m.resolve(&["/ml-eng".into()]), Some(Role::Developer));
        assert_eq!(
            m.resolve(&["/random".into()]),
            Some(Role::Viewer),
            "wildcard"
        );
        assert_eq!(
            m.resolve(&[]),
            Some(Role::Viewer),
            "wildcard matches no-groups"
        );
    }

    #[test]
    fn no_wildcard_means_deny_by_default() {
        let m = RoleMappings {
            viewer: vec!["/readers".into()],
            ..RoleMappings::default()
        };
        assert_eq!(m.resolve(&["/unrelated".into()]), None);
    }

    #[test]
    fn auth_config_parses_with_defaults() {
        let cfg: AuthConfig = toml_from(
            r#"
            issuer = "https://kc.example.com/realms/nebari"
            audience = "mobula"
            [roles]
            developer = ["/ml-eng"]
        "#,
        );
        assert_eq!(cfg.groups_claim, "groups");
        assert!(cfg.roles.admin.is_empty());
    }

    fn toml_from(s: &str) -> AuthConfig {
        // toml isn't a dep of this crate; round-trip through serde_json
        // shaped by a tiny hand parser is overkill — use serde_json from
        // a JSON literal equivalent instead where needed. For the TOML
        // path we lean on serde's Deserialize derive being format-
        // agnostic; the CLI test covers real TOML. Here: JSON.
        let _ = s;
        serde_json::from_value(serde_json::json!({
            "issuer": "https://kc.example.com/realms/nebari",
            "audience": "mobula",
            "roles": {"developer": ["/ml-eng"]}
        }))
        .unwrap()
    }
}
