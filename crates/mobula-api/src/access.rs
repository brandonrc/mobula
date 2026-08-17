//! Identity & access read surface (api-v1.md §5.8).
//!
//! `GET /api/v1/identity` is "who am I" for the shell's identity chip and
//! role-gated rendering; `GET /api/v1/access/roles` exposes the effective
//! group→role mappings for the access page. Both mount unconditionally —
//! every deployment has an identity, and in dev mode (no validator, no
//! local auth) `/identity` returns the specced dev identity so the
//! unauthenticated dev loop renders the full console.
//!
//! Roles are group→role mappings only when an OIDC validator is
//! configured. In a pure local-auth deployment (ADR-0011) roles are a
//! column on the user row, so `mappings` is `null` with `source: "local"`
//! — an additive deviation from the spec's exact shape, documented in
//! api-v1.md §5.8.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, RoleMappings, Target, Validator};
use mobula_controller::Store;
use serde::Serialize;
use utoipa::ToSchema;

use crate::audit::role_str;
use crate::auth_layer::authorize;

#[derive(Clone)]
pub struct AccessApiState {
    /// The OIDC validator, when configured — carries the `RoleMappings`.
    pub validator: Option<Arc<Validator>>,
    /// Audit persistence for authorization denials; `None` stays trace-only.
    pub store: Option<Arc<dyn Store>>,
}

/// `GET /api/v1/identity` response: the caller's resolved identity.
#[derive(Serialize, ToSchema)]
pub struct IdentityResponse {
    pub subject: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    /// Snake_case role names ("viewer", "developer", "operator", "admin").
    pub roles: Vec<String>,
}

impl From<&Identity> for IdentityResponse {
    fn from(id: &Identity) -> Self {
        IdentityResponse {
            subject: id.subject.clone(),
            email: id.email.clone(),
            groups: id.groups.clone(),
            roles: id.roles.iter().map(role_str).collect(),
        }
    }
}

/// Group→role mappings from the OIDC auth config; shape mirrors
/// `mobula_auth::RoleMappings` (a wire twin so `mobula-auth` stays free of
/// serialization/api deps).
#[derive(Serialize, ToSchema)]
pub struct RoleMappingsView {
    pub admin: Vec<String>,
    pub operator: Vec<String>,
    pub developer: Vec<String>,
    pub viewer: Vec<String>,
}

impl From<&RoleMappings> for RoleMappingsView {
    fn from(m: &RoleMappings) -> Self {
        RoleMappingsView {
            admin: m.admin.clone(),
            operator: m.operator.clone(),
            developer: m.developer.clone(),
            viewer: m.viewer.clone(),
        }
    }
}

/// `GET /api/v1/access/roles` response. `mappings` is null when no OIDC
/// validator is configured (local-auth or dev mode): group→role mappings
/// are meaningless there — local users carry their role as a column.
#[derive(Serialize, ToSchema)]
pub struct RolesResponse {
    pub mappings: Option<RoleMappingsView>,
    /// "file" (mappings from the OIDC auth config) or "local" (no OIDC
    /// validator; roles live on the local user rows).
    #[schema(example = "file")]
    pub source: &'static str,
    /// Always false in v1 — editing stays in the config file + restart.
    pub editable: bool,
}

/// "Who am I": the resolved identity for any authenticated caller. In dev
/// mode (no validator AND no local auth) the auth middleware attaches no
/// identity, and this returns the specced dev identity so the
/// unauthenticated dev loop renders the full console.
#[utoipa::path(
    get, path = "/api/v1/identity", tag = "access",
    responses(
        (status = 200, description = "The caller's identity (the dev identity when auth is disabled)", body = IdentityResponse),
        (status = 401, description = "No/invalid token (only when auth is configured)"),
    ),
    security(("bearer" = []))
)]
async fn identity(identity: Option<Extension<Identity>>) -> Json<IdentityResponse> {
    match identity {
        Some(Extension(id)) => Json(IdentityResponse::from(&id)),
        // Dev mode: no auth configured, so no identity was attached.
        None => Json(IdentityResponse {
            subject: "dev".into(),
            email: None,
            groups: vec![],
            roles: vec!["admin".into()],
        }),
    }
}

/// Effective role mappings for the access page. Admin-only. v1 is
/// read-only: with an OIDC validator the mappings come from the auth
/// config file; without one (local auth) `mappings` is null and roles are
/// managed per-user via `/api/v1/auth/users`.
#[utoipa::path(
    get, path = "/api/v1/access/roles", tag = "access",
    responses(
        (status = 200, description = "Role mappings and their source", body = RolesResponse),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin only — access-control surface (api-v1.md §2.2)"),
    ),
    security(("bearer" = []))
)]
async fn list_roles(
    State(st): State<AccessApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    // Admin-only, same pattern as the registry/audit routes: `Admin` on any
    // target is granted only to Role::Admin; Target::Cluster because
    // access-control surfaces are classified with them (api-v1.md §2.2).
    if let Some(deny) = authorize(
        st.store.as_ref(),
        identity.as_ref().map(|e| &e.0),
        PermissionType::Admin,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    match &st.validator {
        Some(v) => Json(RolesResponse {
            mappings: Some(RoleMappingsView::from(v.role_mappings())),
            source: "file",
            editable: false,
        })
        .into_response(),
        None => Json(RolesResponse {
            mappings: None,
            source: "local",
            editable: false,
        })
        .into_response(),
    }
}

/// The identity/access route bundle, mounted unconditionally — every
/// deployment has an identity (dev mode included).
pub fn router(validator: Option<Arc<Validator>>, store: Option<Arc<dyn Store>>) -> Router {
    Router::new()
        .route("/api/v1/identity", get(identity))
        .route("/api/v1/access/roles", get(list_roles))
        .with_state(AccessApiState { validator, store })
}
