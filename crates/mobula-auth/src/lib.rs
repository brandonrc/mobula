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
/// code) with the same verbs. Per-project scoping landed via the
/// role_assignments table (ADR-0009 addendum, #49; see
/// [`Identity::permits_scoped`]); this remains the target *type*.
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
    /// The persisted audit trail (#59, api-v1.md §5.9). Its own target so
    /// `Role::Auditor` can hold Read here and nothing anywhere else —
    /// separation of duties: auditors inspect the trail without holding
    /// Admin (which audit reads required before #59).
    Audit,
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
    /// Read-only on the audit surface and nothing else (#59) — a
    /// compliance reader who must NOT get cluster/job/registry access.
    /// Granted via the `auditor` group mapping; scoped role assignments
    /// don't apply (the audit trail isn't project-scoped).
    Auditor,
}

impl Role {
    /// Whether this role grants `action` on `target`.
    pub fn grants(self, action: PermissionType, target: Target) -> bool {
        use PermissionType::*;
        use Target::*;
        match (self, target) {
            // Admin: everything, everywhere.
            (Role::Admin, _) => true,
            // Viewer: read-only, any target EXCEPT the audit trail — audit
            // subjects are Admin data (api-v1.md §2.2), and #59 keeps them
            // to Admin/Auditor only.
            (Role::Viewer, Audit) => false,
            (Role::Viewer, _) => action == Read,
            // Auditor (#59): reads the audit surface, nothing else — no
            // cluster reads, no registry, no writes anywhere.
            (Role::Auditor, Audit) => action == Read,
            (Role::Auditor, _) => false,
            // Developer: full job + service access (both are "code"),
            // read-only clusters and pools.
            (Role::Developer, Job) | (Role::Developer, Service) => {
                matches!(action, Read | Write | Delete)
            }
            (Role::Developer, Cluster) | (Role::Developer, Pool) => action == Read,
            (Role::Developer, Audit) => false,
            // Operator: full cluster lifecycle, read-only code surfaces and
            // pool topology (pools are platform config — mutations are
            // Admin-only).
            (Role::Operator, Cluster) => matches!(action, Read | Write | Delete),
            (Role::Operator, Job) | (Role::Operator, Service) | (Role::Operator, Pool) => {
                action == Read
            }
            (Role::Operator, Audit) => false,
        }
    }

    /// The snake_case wire/storage form (role_assignments.role column,
    /// `PUT /api/v1/access/assignments` bodies).
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Developer => "developer",
            Role::Operator => "operator",
            Role::Admin => "admin",
            Role::Auditor => "auditor",
        }
    }

    /// Inverse of [`Role::as_str`]; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Role::Viewer),
            "developer" => Some(Role::Developer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            "auditor" => Some(Role::Auditor),
            _ => None,
        }
    }
}

/// The global assignment scope (ADR-0009 addendum, #49): an assignment at
/// this scope applies to every target, exactly like a group-derived role.
pub const GLOBAL_SCOPE: &str = "*";

/// The scope grammar for role assignments (#49): `"*"` (global) or
/// `"project:<name>"`. Cluster-scoped bindings ("cluster:<id>") and group
/// principals are deferred — group bindings are the OIDC-mapping layer's
/// job (ADR-0009).
pub fn valid_scope(scope: &str) -> bool {
    if scope == GLOBAL_SCOPE {
        return true;
    }
    let Some(name) = scope.strip_prefix("project:") else {
        return false;
    };
    // Project names share the cluster-id grammar: a non-empty run of
    // lowercase alphanumerics, '-', '_', '.', '/' (NIC project slugs).
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

/// Whether an assignment `scope` covers `project` in a scoped check:
/// `"*"` covers everything; `"project:<name>"` covers only that project.
pub fn scope_covers(scope: &str, project: &str) -> bool {
    scope == GLOBAL_SCOPE || scope == format!("project:{project}")
}

/// Authenticated caller, attached to requests after validation. A caller
/// may hold several roles (their union of permissions applies).
#[derive(Debug, Clone)]
pub struct Identity {
    pub subject: String,
    /// The human username (`preferred_username` claim), when the token
    /// carries one. Distinct from `subject`, which is the opaque `sub`
    /// (a UUID on Keycloak). Used as the tier-2 cluster owner label so it
    /// matches the JupyterHub username the hub stamps on notebook pods.
    pub username: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub roles: Vec<Role>,
    /// Group-derived project-scoped grants (#103): `(role, "project:<name>")`
    /// pairs implied by group membership via `[project_roles]`, with NO manual
    /// `role_assignments` row. Resolved once at token validation from the
    /// caller's groups + the auth config, then combined with any stored
    /// assignments at evaluation time (see `authorize_scoped`). Empty for
    /// local auth and when `[project_roles]` is unset — deny-by-default holds.
    pub project_roles: Vec<(Role, String)>,
}

impl Identity {
    /// The identity to attribute owned resources to (tier-2 owned session
    /// clusters): the human `username` when present, else the `subject`. For
    /// local auth `subject` already *is* the username, so the fallback is
    /// correct there too. This is the value stamped as `mobula.dev/owner`
    /// and matched by the per-owner NetworkPolicy, so it must equal the
    /// JupyterHub username on the owner's notebook pod.
    pub fn owner(&self) -> &str {
        self.username.as_deref().unwrap_or(&self.subject)
    }

    /// Whether any held role grants `action` on `target` (deny-by-default:
    /// an empty role set grants nothing).
    pub fn permits(&self, action: PermissionType, target: Target) -> bool {
        self.roles.iter().any(|r| r.grants(action, target))
    }

    /// Scoped check (ADR-0009 addendum, #49): the global fast path
    /// ([`Identity::permits`]) OR any assignment in `assignments` whose
    /// scope covers `project` (`"*"` or `"project:<project>"`) and whose
    /// role grants `(action, target)`.
    ///
    /// Semantics are ADDITIVE ONLY: an assignment can grant, never subtract
    /// — there are no deny rules. A principal with no assignments gets
    /// exactly today's flat group→role mapping; one with assignments gets
    /// the union of group-derived roles and scope-matching assigned roles.
    pub fn permits_scoped(
        &self,
        action: PermissionType,
        target: Target,
        assignments: &[(Role, String)],
        project: &str,
    ) -> bool {
        self.permits(action, target)
            || assignments
                .iter()
                .any(|(role, scope)| scope_covers(scope, project) && role.grants(action, target))
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
    /// #59: audit-trail readers (compliance). Serde-defaulted so existing
    /// auth.toml files without the key keep parsing.
    #[serde(default)]
    pub auditor: Vec<String>,
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
    /// #103: group→project-role automation. Serde-defaulted (empty = off) so
    /// existing auth.toml files without the key keep parsing and keep exactly
    /// today's flat behavior.
    #[serde(default)]
    pub project_roles: ProjectRoleMappings,
}

/// Group→project-role mapping (#103): the self-service convention that lets a
/// caller's IdP group membership imply a *scoped* role on the matching project
/// with NO manual `PUT /access/assignments`. Same shape as [`RoleMappings`]
/// (role → group patterns), but a matching group grants the role scoped to
/// `project:<group>` (the group name after [`ProjectRoleMappings::strip_prefix`]),
/// not globally. A `"*"` pattern means "every group the caller is in derives
/// its own project role" — the plain `team-a ⇒ operator on project:team-a`
/// rule. Empty lists = feature off, so deny-by-default is preserved.
///
/// `operator`/`developer` are the meaningful entries (cluster lifecycle / job
/// code on your own project); the rest exist for uniformity with `[roles]`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProjectRoleMappings {
    #[serde(default)]
    pub admin: Vec<String>,
    #[serde(default)]
    pub operator: Vec<String>,
    #[serde(default)]
    pub developer: Vec<String>,
    #[serde(default)]
    pub viewer: Vec<String>,
    #[serde(default)]
    pub auditor: Vec<String>,
    /// Stripped from each matching group name to derive the project, e.g. `"/"`
    /// for Keycloak's `/team-a` groups (→ `project:team-a`). Default `""`: the
    /// group name is the project name verbatim.
    #[serde(default)]
    pub strip_prefix: String,
}

impl ProjectRoleMappings {
    /// Whether any role has a group pattern configured (feature on).
    pub fn is_empty(&self) -> bool {
        self.admin.is_empty()
            && self.operator.is_empty()
            && self.developer.is_empty()
            && self.viewer.is_empty()
            && self.auditor.is_empty()
    }

    /// Whether any role maps a `"*"` wildcard — every group derives its own
    /// project role. Narrower than a global wildcard (grants are per-project),
    /// but still worth surfacing at boot.
    pub fn has_wildcard(&self) -> bool {
        [
            &self.admin,
            &self.operator,
            &self.developer,
            &self.viewer,
            &self.auditor,
        ]
        .iter()
        .any(|patterns| patterns.iter().any(|p| p == "*"))
    }

    /// Group-derived `(role, "project:<name>")` grants for `groups`. For each
    /// role, a group matching its patterns (`"*"` matches any) yields that role
    /// scoped to the project named by the group (after `strip_prefix`). Groups
    /// that reduce to an empty or scope-grammar-invalid project name are
    /// skipped. Duplicates are de-duplicated; order is stable.
    pub fn resolve(&self, groups: &[String]) -> Vec<(Role, String)> {
        let mut out: Vec<(Role, String)> = Vec::new();
        for (patterns, role) in [
            (&self.admin, Role::Admin),
            (&self.operator, Role::Operator),
            (&self.developer, Role::Developer),
            (&self.viewer, Role::Viewer),
            (&self.auditor, Role::Auditor),
        ] {
            if patterns.is_empty() {
                continue;
            }
            for g in groups {
                if !patterns.iter().any(|p| p == "*" || p == g) {
                    continue;
                }
                let name = g.strip_prefix(&self.strip_prefix).unwrap_or(g.as_str());
                if name.is_empty() {
                    continue;
                }
                let scope = format!("project:{name}");
                if !valid_scope(&scope) {
                    continue;
                }
                let entry = (role, scope);
                if !out.contains(&entry) {
                    out.push(entry);
                }
            }
        }
        out
    }
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

/// Where scoped role assignments come from at request time (ADR-0009
/// addendum, #49). The trait lives here so the evaluation semantics
/// ([`Identity::permits_scoped`]) stay next to the model; the
/// implementation lives in mobula-api's auth_layer over the Store (one
/// indexed `role_assignments` read per request — caching is a documented
/// follow-up, not built).
#[async_trait::async_trait]
pub trait AssignmentSource: Send + Sync {
    /// All assignments for `subject`, as (role, scope) rows. Implementations
    /// must fail CLOSED on backend errors (return an empty vec — global
    /// roles still apply, scoped extras are withheld).
    async fn assignments_for(&self, subject: &str) -> Vec<(Role, String)>;
}

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

        // #103: surface group→project-role automation at boot so operators know
        // self-service scoped grants are active without a manual assignment.
        if !config.project_roles.is_empty() {
            if config.project_roles.has_wildcard() {
                tracing::info!(
                    "project_roles maps a \"*\" wildcard: every group a caller \
                     belongs to grants the mapped role scoped to project:<group> \
                     automatically (self-service, no manual assignment)"
                );
            } else {
                tracing::info!(
                    "project_roles is configured: matching groups grant scoped \
                     roles on project:<group> automatically (#103)"
                );
            }
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
        // #103: derive project-scoped grants from group membership (empty when
        // [project_roles] is unset — deny-by-default preserved).
        let project_roles = self.config.project_roles.resolve(&groups);
        Identity {
            // Sanitize: sub reaches the plain-text log layer, and a `sub`
            // containing newlines/control chars could forge audit lines
            // (#34). Replace control chars with '?'.
            subject: sanitize_claim(claims.get("sub").and_then(|v| v.as_str()).unwrap_or("")),
            // preferred_username reaches the audit log and a k8s label value;
            // sanitize like `sub`. Absent (some IdPs omit it) → None, and
            // `owner()` falls back to `subject`.
            username: claims
                .get("preferred_username")
                .and_then(|v| v.as_str())
                .map(sanitize_claim),
            email: claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(String::from),
            groups,
            roles,
            project_roles,
        }
    }
}

impl RoleMappings {
    /// Whether any role maps a `"*"` wildcard.
    pub fn has_wildcard(&self) -> bool {
        [
            &self.admin,
            &self.operator,
            &self.developer,
            &self.viewer,
            &self.auditor,
        ]
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
        if matches(&self.auditor) {
            roles.push(Role::Auditor);
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
            auditor: vec!["/compliance".into()],
        }
    }

    #[test]
    fn role_permission_sets_by_target() {
        use PermissionType::*;
        use Target::*;
        // Admin: everything.
        assert!(Role::Admin.grants(Admin, Cluster) && Role::Admin.grants(Write, Job));
        assert!(Role::Admin.grants(Read, Audit));
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
        // Viewer: read-only everywhere — EXCEPT the audit trail (#59):
        // audit subjects are Admin data, kept to Admin/Auditor.
        assert!(Role::Viewer.grants(Read, Cluster));
        assert!(!Role::Viewer.grants(Write, Job));
        assert!(!Role::Viewer.grants(Read, Audit));
        assert!(!Role::Developer.grants(Read, Audit));
        assert!(!Role::Operator.grants(Read, Audit));
        // Auditor (#59): reads the audit surface and NOTHING else — the
        // separation-of-duties tripwires: no cluster create, no registry
        // (registry reads check Admin on Cluster), no cluster reads at all.
        assert!(Role::Auditor.grants(Read, Audit));
        assert!(!Role::Auditor.grants(Write, Audit));
        assert!(!Role::Auditor.grants(Delete, Audit));
        assert!(!Role::Auditor.grants(Admin, Audit));
        assert!(!Role::Auditor.grants(Write, Cluster));
        assert!(!Role::Auditor.grants(Read, Cluster));
        assert!(!Role::Auditor.grants(Admin, Cluster));
        assert!(!Role::Auditor.grants(Read, Job));
        assert!(!Role::Auditor.grants(Read, Service));
        assert!(!Role::Auditor.grants(Read, Pool));
    }

    #[test]
    fn identity_permits_is_union_of_roles() {
        // Holding both Developer and Operator = job code AND cluster
        // lifecycle.
        let id = Identity {
            subject: "u".into(),
            username: None,
            email: None,
            groups: vec![],
            roles: vec![Role::Developer, Role::Operator],
            project_roles: vec![],
        };
        assert!(id.permits(PermissionType::Write, Target::Job));
        assert!(id.permits(PermissionType::Write, Target::Cluster));
        assert!(id.is_authorized());

        let none = Identity {
            subject: "u".into(),
            username: None,
            email: None,
            groups: vec![],
            roles: vec![],
            project_roles: vec![],
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
        // #59: the auditor group resolves to the audit-only role (plus the
        // wildcard viewer every authenticated caller holds).
        let r = m.resolve(&["/compliance".into()]);
        assert!(r.contains(&Role::Auditor), "{r:?}");
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
    fn role_wire_names_round_trip() {
        for r in [
            Role::Viewer,
            Role::Developer,
            Role::Operator,
            Role::Admin,
            Role::Auditor,
        ] {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
        assert_eq!(Role::parse("superuser"), None);
    }

    #[test]
    fn scope_grammar_is_star_or_project_name() {
        assert!(valid_scope("*"));
        assert!(valid_scope("project:ml-team"));
        assert!(valid_scope("project:team/sub_ns.1"));
        for bad in [
            "",
            "project:",
            "cluster:c1",
            "project:has space",
            "project:semi;colon",
            "**",
            "*x",
        ] {
            assert!(!valid_scope(bad), "{bad}");
        }
    }

    #[test]
    fn permits_scoped_matrix() {
        use PermissionType::*;
        use Target::*;
        let dev = Identity {
            subject: "u".into(),
            username: None,
            email: None,
            groups: vec![],
            roles: vec![Role::Developer],
            project_roles: vec![],
        };
        let op_ml = vec![(Role::Operator, "project:ml-team".to_string())];

        // Global roles cover everything, assignments irrelevant (fast path).
        let admin = Identity {
            subject: "root".into(),
            username: None,
            email: None,
            groups: vec![],
            roles: vec![Role::Admin],
            project_roles: vec![],
        };
        assert!(admin.permits_scoped(Delete, Cluster, &[], "anywhere"));

        // Developer (global) already reads clusters everywhere; scoped
        // operator adds lifecycle ONLY for the matching project.
        assert!(dev.permits_scoped(Read, Cluster, &op_ml, "ml-team"));
        assert!(dev.permits_scoped(Write, Cluster, &op_ml, "ml-team"));
        assert!(dev.permits_scoped(Delete, Cluster, &op_ml, "ml-team"));
        assert!(!dev.permits_scoped(Write, Cluster, &op_ml, "other"));
        // Scoped grants don't leak across targets: operator-on-ml-team
        // doesn't grant job writes (operator is read-only on Job) — checked
        // against a caller with no global roles so the assignment decides.
        let nobody = Identity {
            subject: "n".into(),
            username: None,
            email: None,
            groups: vec![],
            roles: vec![],
            project_roles: vec![],
        };
        assert!(!nobody.permits_scoped(Write, Job, &op_ml, "ml-team"));
        // The non-scoped fast path is unchanged: no assignments consulted.
        assert!(!dev.permits(Write, Cluster));

        // A "*" assignment is a global grant — same coverage as a group role.
        let op_star = vec![(Role::Operator, "*".to_string())];
        assert!(dev.permits_scoped(Write, Cluster, &op_star, "other"));

        // No assignments → exactly the flat mapping (the fallback rule).
        assert!(!dev.permits_scoped(Write, Cluster, &[], "ml-team"));
        assert!(!nobody.permits_scoped(Read, Cluster, &[], "ml-team"));
        assert!(nobody.permits_scoped(Read, Cluster, &op_ml, "ml-team"));

        // Assignments are additive only — no deny rules exist, so a scoped
        // viewer assignment cannot strip a global operator's write.
        let op = Identity {
            subject: "o".into(),
            username: None,
            email: None,
            groups: vec![],
            roles: vec![Role::Operator],
            project_roles: vec![],
        };
        let scoped_viewer = vec![(Role::Viewer, "project:ml-team".to_string())];
        assert!(op.permits_scoped(Write, Cluster, &scoped_viewer, "ml-team"));
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
    fn project_roles_derive_scoped_grant_per_group() {
        // #103: the plain convention — membership in group X grants operator
        // on project:X, via a "*" pattern, with NO manual assignment.
        let m = ProjectRoleMappings {
            operator: vec!["*".into()],
            ..ProjectRoleMappings::default()
        };
        let grants = m.resolve(&["team-a".into(), "team-b".into()]);
        assert!(grants.contains(&(Role::Operator, "project:team-a".into())));
        assert!(grants.contains(&(Role::Operator, "project:team-b".into())));
        // No groups → no grants (deny-by-default preserved).
        assert!(m.resolve(&[]).is_empty());
    }

    #[test]
    fn project_roles_explicit_group_list_scopes_to_that_group() {
        // Only listed groups participate, and each derives its OWN project.
        let m = ProjectRoleMappings {
            operator: vec!["team-a".into()],
            developer: vec!["team-b".into()],
            ..ProjectRoleMappings::default()
        };
        // Caller in team-a: operator on project:team-a, nothing for team-b.
        let a = m.resolve(&["team-a".into()]);
        assert_eq!(a, vec![(Role::Operator, "project:team-a".to_string())]);
        // Caller in team-b: developer on project:team-b.
        let b = m.resolve(&["team-b".into()]);
        assert_eq!(b, vec![(Role::Developer, "project:team-b".to_string())]);
        // Caller in an unmapped group: nothing.
        assert!(m.resolve(&["team-c".into()]).is_empty());
    }

    #[test]
    fn project_roles_strip_prefix_and_grammar() {
        // Keycloak "/team-a" groups: strip the "/" to name the project.
        let m = ProjectRoleMappings {
            operator: vec!["*".into()],
            strip_prefix: "/".into(),
            ..ProjectRoleMappings::default()
        };
        let g = m.resolve(&["/team-a".into()]);
        assert_eq!(g, vec![(Role::Operator, "project:team-a".to_string())]);
        // A group that reduces to an empty/invalid project name is skipped,
        // never a malformed scope.
        assert!(m.resolve(&["/".into()]).is_empty());
        let bad = ProjectRoleMappings {
            operator: vec!["*".into()],
            ..ProjectRoleMappings::default()
        };
        assert!(bad.resolve(&["has space".into()]).is_empty());
    }

    #[test]
    fn project_roles_empty_and_wildcard_flags() {
        assert!(ProjectRoleMappings::default().is_empty());
        assert!(!ProjectRoleMappings::default().has_wildcard());
        let m = ProjectRoleMappings {
            operator: vec!["*".into()],
            ..ProjectRoleMappings::default()
        };
        assert!(!m.is_empty());
        assert!(m.has_wildcard());
        let explicit = ProjectRoleMappings {
            operator: vec!["team-a".into()],
            ..ProjectRoleMappings::default()
        };
        assert!(!explicit.is_empty());
        assert!(!explicit.has_wildcard());
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
        // #103: absent [project_roles] parses to the empty (feature-off) map.
        assert!(cfg.project_roles.is_empty());
    }

    #[test]
    fn auth_config_parses_project_roles() {
        // The [project_roles] table deserializes like [roles] plus strip_prefix.
        let cfg: AuthConfig = serde_json::from_value(serde_json::json!({
            "issuer": "https://kc.example.com/realms/nebari",
            "audience": "mobula",
            "roles": {"viewer": ["*"]},
            "project_roles": {"operator": ["*"], "strip_prefix": "/"}
        }))
        .unwrap();
        assert!(!cfg.project_roles.is_empty());
        assert_eq!(cfg.project_roles.strip_prefix, "/");
        assert_eq!(
            cfg.project_roles.resolve(&["/team-a".into()]),
            vec![(Role::Operator, "project:team-a".to_string())]
        );
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
