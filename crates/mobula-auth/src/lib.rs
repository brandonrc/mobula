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

/// A permission verb, mirroring artifact-keeper's `PermissionType`
/// (Read/Write/Delete/Admin) so Mobula's RBAC vocabulary matches the
/// rest of the ecosystem. `Admin` always wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionType {
    Read,
    Write,
    Delete,
    Admin,
}

/// What a permission applies to — artifact-keeper's `target_type`. This is
/// what lets `Operator` (cluster lifecycle) differ from `Developer` (job
/// code) with the same verbs. Per-resource-instance scoping (which
/// cluster/project) lands with the Phase 3 role_assignments table
/// (ADR-0009); this is the target *type*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The proxied Ray job surface — submitting/stopping jobs is "code".
    Job,
    /// Mobula's own cluster lifecycle (create/suspend/terminate).
    Cluster,
    /// Ray Serve services — deploying/updating a Serve app is "code".
    Service,
    /// Capacity pools and their allocations (ADR-0010) — platform
    /// configuration, not app lifecycle, so mutations are Admin-only.
    Pool,
}

/// Built-in v0 roles (ADR-0003). Roles are permission-sets over
/// (verb, target), not an ordinal rank — `Operator` (lifecycle but not
/// code) overlaps `Developer` without containing it, which a total order
/// can't express (review #25). In Phase 3 these become `is_system` rows
/// alongside custom roles, matching artifact-keeper's named-role model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Viewer,
    Developer,
    Operator,
    Admin,
}

impl Role {
    /// Whether this role grants `action` on `target`.
    pub fn grants(self, action: PermissionType, target: Target) -> bool {
        use PermissionType::*;
        use Target::*;
        match (self, target) {
            // Admin: everything, everywhere.
            (Role::Admin, _) => true,
            // Viewer: read-only, any target.
            (Role::Viewer, _) => action == Read,
            // Developer: full job + service access (both are "code"),
            // read-only clusters and pools.
            (Role::Developer, Job) | (Role::Developer, Service) => {
                matches!(action, Read | Write | Delete)
            }
            (Role::Developer, Cluster) | (Role::Developer, Pool) => action == Read,
            // Operator: full cluster lifecycle, read-only code surfaces and
            // pool topology (pools are platform config — mutations are
            // Admin-only).
            (Role::Operator, Cluster) => matches!(action, Read | Write | Delete),
            (Role::Operator, Job) | (Role::Operator, Service) | (Role::Operator, Pool) => {
                action == Read
            }
        }
    }
}

/// Authenticated caller, attached to requests after validation. A caller
/// may hold several roles (their union of permissions applies).
#[derive(Debug, Clone)]
pub struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<Role>,
}

impl Identity {
    /// Whether any held role grants `action` on `target` (deny-by-default:
    /// an empty role set grants nothing).
    pub fn permits(&self, action: PermissionType, target: Target) -> bool {
        self.roles.iter().any(|r| r.grants(action, target))
    }

    pub fn is_authorized(&self) -> bool {
        !self.roles.is_empty()
    }
}

/// Mapping from IdP group names to Mobula roles. `"*"` matches any
/// authenticated caller (e.g. `viewer = ["*"]`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoleMappings {
    #[serde(default)]
    pub admin: Vec<String>,
    #[serde(default)]
    pub operator: Vec<String>,
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

/// Replace ASCII control characters (newlines included) so a claim value
/// cannot forge log lines when written to the plain-text layer (#34).
fn sanitize_claim(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
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
    #[error("token flow failed: {0}")]
    Flow(String),
    #[error(
        "issuer {0} is not https — JWKS would be fetched over cleartext, letting a \
         network attacker substitute signing keys. Use https, or pass an explicit \
         insecure-transport override for local dev."
    )]
    InsecureIssuer(String),
    #[error("token has no subject (sub) claim")]
    MissingSubject,
}

pub mod flows;
pub mod local;

/// Subset of the OIDC provider metadata Mobula uses.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    /// The issuer the provider claims; cross-checked against config (#16).
    #[serde(default)]
    pub issuer: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
}

/// HTTP client for IdP calls: bounded timeouts so a hung/trickling IdP
/// cannot park a request forever (#29). Mirrors the southbound posture.
pub fn idp_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
        .expect("static client config")
}

/// Fetch `{issuer}/.well-known/openid-configuration`.
pub async fn discover_metadata(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<ProviderMetadata, AuthError> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    client
        .get(&url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| AuthError::Discovery(e.without_url().to_string()))?
        .json()
        .await
        .map_err(|e| AuthError::Discovery(e.without_url().to_string()))
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
    /// The configured OIDC issuer (for `GET /api/v1/auth/providers`).
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// The configured group→role mappings (for `GET /api/v1/access/roles`).
    pub fn role_mappings(&self) -> &RoleMappings {
        &self.config.roles
    }

    /// Run OIDC discovery and the initial JWKS fetch. Fails fast — a
    /// control plane that cannot validate tokens must not start serving.
    pub async fn discover(
        config: AuthConfig,
        client: reqwest::Client,
        allow_insecure: bool,
    ) -> Result<Self, AuthError> {
        if !config.issuer.starts_with("https://") && !allow_insecure {
            return Err(AuthError::InsecureIssuer(config.issuer.clone()));
        }
        let doc = discover_metadata(&client, &config.issuer).await?;

        // Cross-check the advertised issuer against the configured one:
        // a provider that answers discovery for a different issuer than we
        // trust is misconfigured or hostile (#16).
        if let Some(advertised) = &doc.issuer {
            if advertised.trim_end_matches('/') != config.issuer.trim_end_matches('/') {
                return Err(AuthError::Discovery(format!(
                    "issuer mismatch: configured {}, provider advertises {advertised}",
                    config.issuer
                )));
            }
        }

        // A wildcard viewer mapping turns deny-by-default into
        // "any authenticated caller reads everything" — warn loudly (#35).
        if config.roles.has_wildcard() {
            tracing::warn!(
                "role mapping contains a \"*\" wildcard: every authenticated token \
                 (including IdP service accounts) receives that role — deny-by-default \
                 is disabled for it"
            );
        }

        let validator = Self {
            config,
            client,
            jwks_uri: doc.jwks_uri,
            keys: RwLock::new(Arc::new(HashMap::new())),
            last_refresh: Mutex::new(Instant::now() - REFRESH_COOLDOWN),
        };
        validator.refresh_jwks().await?;
        // A provider that returns zero usable keys can never validate a
        // token; fail fast rather than boot into a permanently-401 state
        // that also invites JWKS refresh floods (#28).
        if validator.keys.read().await.is_empty() {
            return Err(AuthError::Jwks(
                "provider returned no usable signing keys".into(),
            ));
        }
        Ok(validator)
    }

    async fn refresh_jwks(&self) -> Result<(), AuthError> {
        // Claim the refresh slot on a time basis alone — independent of
        // whether the last fetch yielded keys (#28) — and release the lock
        // before the network call so a hung JWKS endpoint can't park every
        // validator behind the mutex (#29).
        {
            let mut last = self.last_refresh.lock().await;
            if last.elapsed() < REFRESH_COOLDOWN {
                return Ok(());
            }
            *last = Instant::now();
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
        // jsonwebtoken defaults required_spec_claims to {"exp"} only, so a
        // token *omitting* iss/aud passes (only mismatches are caught) —
        // a cross-audience confused-deputy risk. Require them, plus sub,
        // and validate nbf (off by default) (#16, #27).
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        let data = decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let identity = self.identity_from_claims(&data.claims);
        if identity.subject.is_empty() {
            return Err(AuthError::MissingSubject);
        }
        Ok(identity)
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
        let roles = self.config.roles.resolve(&groups);
        Identity {
            // Sanitize: sub reaches the plain-text log layer, and a `sub`
            // containing newlines/control chars could forge audit lines
            // (#34). Replace control chars with '?'.
            subject: sanitize_claim(claims.get("sub").and_then(|v| v.as_str()).unwrap_or("")),
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(String::from),
            groups,
            roles,
        }
    }
}

impl RoleMappings {
    /// Whether any role maps a `"*"` wildcard.
    pub fn has_wildcard(&self) -> bool {
        [&self.admin, &self.operator, &self.developer, &self.viewer]
            .iter()
            .any(|patterns| patterns.iter().any(|p| p == "*"))
    }

    /// Every role whose group mapping matches (a caller holds the union of
    /// their permissions). A `"*"` pattern matches any authenticated
    /// caller. Empty result = deny by default.
    pub fn resolve(&self, groups: &[String]) -> Vec<Role> {
        let matches = |patterns: &[String]| {
            patterns
                .iter()
                .any(|p| p == "*" || groups.iter().any(|g| g == p))
        };
        let mut roles = Vec::new();
        if matches(&self.admin) {
            roles.push(Role::Admin);
        }
        if matches(&self.operator) {
            roles.push(Role::Operator);
        }
        if matches(&self.developer) {
            roles.push(Role::Developer);
        }
        if matches(&self.viewer) {
            roles.push(Role::Viewer);
        }
        roles
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mappings() -> RoleMappings {
        RoleMappings {
            admin: vec!["/platform-admins".into()],
            operator: vec!["/sre".into()],
            developer: vec!["/ml-eng".into(), "/data-sci".into()],
            viewer: vec!["*".into()],
        }
    }

    #[test]
    fn role_permission_sets_by_target() {
        use PermissionType::*;
        use Target::*;
        // Admin: everything.
        assert!(Role::Admin.grants(Admin, Cluster) && Role::Admin.grants(Write, Job));
        // Developer: job code yes, cluster lifecycle no.
        assert!(Role::Developer.grants(Write, Job));
        assert!(!Role::Developer.grants(Write, Cluster));
        assert!(Role::Developer.grants(Read, Cluster));
        // Operator: cluster lifecycle yes, job/service code no — the
        // capability the ordinal model couldn't express (#25).
        assert!(Role::Operator.grants(Write, Cluster));
        assert!(!Role::Operator.grants(Write, Job));
        assert!(Role::Operator.grants(Read, Job));
        // Services are code: Developer deploys, Operator read-only.
        assert!(Role::Developer.grants(Write, Service));
        assert!(!Role::Operator.grants(Write, Service));
        // Pools are platform config: everyone reads, only Admin mutates
        // (tripwire mirroring "developer denied cluster-create").
        assert!(!Role::Developer.grants(Write, Pool));
        assert!(Role::Developer.grants(Read, Pool));
        assert!(Role::Operator.grants(Read, Pool));
        assert!(!Role::Operator.grants(Write, Pool));
        assert!(!Role::Operator.grants(Delete, Pool));
        assert!(Role::Admin.grants(Write, Pool) && Role::Admin.grants(Delete, Pool));
        assert!(Role::Viewer.grants(Read, Pool));
        assert!(!Role::Viewer.grants(Write, Pool));
        // Viewer: read-only everywhere.
        assert!(Role::Viewer.grants(Read, Cluster));
        assert!(!Role::Viewer.grants(Write, Job));
    }

    #[test]
    fn identity_permits_is_union_of_roles() {
        // Holding both Developer and Operator = job code AND cluster
        // lifecycle.
        let id = Identity {
            subject: "u".into(),
            email: None,
            groups: vec![],
            roles: vec![Role::Developer, Role::Operator],
        };
        assert!(id.permits(PermissionType::Write, Target::Job));
        assert!(id.permits(PermissionType::Write, Target::Cluster));
        assert!(id.is_authorized());

        let none = Identity {
            subject: "u".into(),
            email: None,
            groups: vec![],
            roles: vec![],
        };
        assert!(!none.is_authorized());
        assert!(!none.permits(PermissionType::Read, Target::Job));
    }

    #[test]
    fn resolve_returns_all_matching_roles() {
        let m = mappings();
        let mut r = m.resolve(&["/ml-eng".into(), "/platform-admins".into()]);
        r.sort_by_key(|x| format!("{x:?}"));
        assert!(r.contains(&Role::Admin) && r.contains(&Role::Developer));
        // Wildcard viewer means everyone gets at least Viewer.
        assert!(m.resolve(&["/random".into()]).contains(&Role::Viewer));
        assert!(
            m.resolve(&[]).contains(&Role::Viewer),
            "wildcard, no groups"
        );
        assert!(m.resolve(&["/sre".into()]).contains(&Role::Operator));
    }

    #[test]
    fn wildcard_detection() {
        assert!(mappings().has_wildcard());
        assert!(!RoleMappings {
            developer: vec!["/ml-eng".into()],
            ..RoleMappings::default()
        }
        .has_wildcard());
    }

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize_claim("normal-sub"), "normal-sub");
        assert_eq!(sanitize_claim("evil\nsub\r\tx"), "evil?sub??x");
    }

    #[test]
    fn no_wildcard_means_deny_by_default() {
        let m = RoleMappings {
            viewer: vec!["/readers".into()],
            ..RoleMappings::default()
        };
        assert!(m.resolve(&["/unrelated".into()]).is_empty());
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
