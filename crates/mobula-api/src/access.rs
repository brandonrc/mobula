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

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{valid_scope, Identity, PermissionType, Role, RoleMappings, Target, Validator};
use mobula_controller::{now_unix, RoleAssignment, Store};
use mobula_core::{AuditDecision, AuditEvent};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::audit::{emit, role_str};
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
        .route("/api/v1/access/assignments", get(list_assignments))
        .route(
            "/api/v1/access/assignments/{principal}",
            axum::routing::put(upsert_assignment).delete(delete_assignment),
        )
        .with_state(AccessApiState { validator, store })
}

// --- Scoped role bindings (ADR-0009 addendum, #49) ---
//
// Assignments grant `role` to `principal` at `scope` ("*" or
// "project:<name>"), additively on top of the group-derived roles. All
// three routes are Admin-only and store-backed (503 without a store), and
// every mutation is audited.

/// One assignment as the wire sees it.
#[derive(Serialize, ToSchema)]
pub struct AssignmentView {
    /// The Identity `subject` the assignment applies to.
    pub principal: String,
    /// "viewer" | "developer" | "operator" | "admin".
    pub role: String,
    /// "*" (global) or "project:<name>".
    pub scope: String,
    /// Unix seconds when the assignment was first written.
    pub created_at: u64,
}

impl From<RoleAssignment> for AssignmentView {
    fn from(a: RoleAssignment) -> Self {
        AssignmentView {
            principal: a.principal,
            role: a.role,
            scope: a.scope,
            created_at: a.created_at,
        }
    }
}

/// Body of `PUT /api/v1/access/assignments/{principal}`.
#[derive(Deserialize, ToSchema)]
pub struct UpsertAssignment {
    /// "viewer" | "developer" | "operator" | "admin".
    pub role: String,
    /// "*" (global) or "project:<name>".
    pub scope: String,
}

/// Query of `DELETE /api/v1/access/assignments/{principal}`.
#[derive(Deserialize, IntoParams)]
pub struct DeleteAssignmentQuery {
    pub role: String,
    pub scope: String,
}

fn store_err(e: mobula_controller::StoreError) -> Response {
    tracing::warn!(error = %e, "access store error");
    (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
}

/// The store backing the assignments routes, or 503 in store-less
/// (gateway-only) deployments. A macro, not a helper fn returning
/// `Result<_, Response>` — `Response` is 128+ bytes and trips
/// clippy::result_large_err.
macro_rules! require_store {
    ($st:expr) => {
        match $st.store.as_ref() {
            Some(s) => s,
            None => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "role assignments require a configured store",
                )
                    .into_response()
            }
        }
    };
}

/// Admin gate shared by the assignments routes: access-control surfaces are
/// Admin-only (api-v1.md §2.2), classified with Target::Cluster.
async fn require_admin(
    st: &AccessApiState,
    identity: &Option<Extension<Identity>>,
) -> Option<Response> {
    authorize(
        st.store.as_ref(),
        identity.as_ref().map(|e| &e.0),
        PermissionType::Admin,
        Target::Cluster,
    )
    .await
}

/// List every scoped role assignment, Admin-only.
#[utoipa::path(
    get, path = "/api/v1/access/assignments", tag = "access",
    responses(
        (status = 200, description = "All role assignments", body = [AssignmentView]),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin only — access-control surface (api-v1.md §2.2)"),
        (status = 503, description = "No store configured (gateway-only deployment)"),
    ),
    security(("bearer" = []))
)]
async fn list_assignments(
    State(st): State<AccessApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    if let Some(deny) = require_admin(&st, &identity).await {
        return deny;
    }
    let store = require_store!(&st);
    match store.list_role_assignments(None).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(AssignmentView::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => store_err(e),
    }
}

/// Create or replace one assignment, Admin-only. The role and scope grammar
/// are validated here — the store is dumb persistence.
#[utoipa::path(
    put, path = "/api/v1/access/assignments/{principal}", tag = "access",
    params(("principal" = String, Path, description = "The Identity subject to bind")),
    request_body = UpsertAssignment,
    responses(
        (status = 200, description = "Assignment stored", body = AssignmentView),
        (status = 400, description = "Unknown role or invalid scope grammar"),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin only"),
        (status = 503, description = "No store configured"),
    ),
    security(("bearer" = []))
)]
async fn upsert_assignment(
    State(st): State<AccessApiState>,
    identity: Option<Extension<Identity>>,
    Path(principal): Path<String>,
    Json(body): Json<UpsertAssignment>,
) -> Response {
    if let Some(deny) = require_admin(&st, &identity).await {
        return deny;
    }
    if principal.is_empty() {
        return (StatusCode::BAD_REQUEST, "principal must not be empty").into_response();
    }
    if Role::parse(&body.role).is_none() {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "unknown role {:?} (viewer|developer|operator|admin)",
                body.role
            ),
        )
            .into_response();
    }
    if !valid_scope(&body.scope) {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "invalid scope {:?} (\"*\" or \"project:<name>\")",
                body.scope
            ),
        )
            .into_response();
    }
    let store = require_store!(&st);
    if let Err(e) = store
        .upsert_role_assignment(&principal, &body.role, &body.scope)
        .await
    {
        return store_err(e);
    }
    emit(
        Some(store),
        AuditEvent {
            ts: now_unix(),
            subject: identity.as_ref().map(|e| e.0.subject.clone()),
            decision: AuditDecision::Allow,
            action: Some("upsert_assignment".into()),
            method: Some("PUT".into()),
            path: Some(format!("/api/v1/access/assignments/{principal}")),
            status: Some(StatusCode::OK.as_u16()),
            ..Default::default()
        },
    )
    .await;
    let view = match store.list_role_assignments(Some(&principal)).await {
        Ok(rows) => rows
            .into_iter()
            .find(|a| a.role == body.role && a.scope == body.scope)
            .map(AssignmentView::from),
        Err(e) => return store_err(e),
    };
    match view {
        Some(v) => Json(v).into_response(),
        None => store_err(mobula_controller::StoreError::Backend(
            "assignment vanished after upsert".into(),
        )),
    }
}

/// Remove one assignment, Admin-only; 404 when the triple doesn't exist.
#[utoipa::path(
    delete, path = "/api/v1/access/assignments/{principal}", tag = "access",
    params(
        ("principal" = String, Path, description = "The Identity subject"),
        DeleteAssignmentQuery,
    ),
    responses(
        (status = 204, description = "Assignment removed"),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin only"),
        (status = 404, description = "No such assignment"),
        (status = 503, description = "No store configured"),
    ),
    security(("bearer" = []))
)]
async fn delete_assignment(
    State(st): State<AccessApiState>,
    identity: Option<Extension<Identity>>,
    Path(principal): Path<String>,
    Query(q): Query<DeleteAssignmentQuery>,
) -> Response {
    if let Some(deny) = require_admin(&st, &identity).await {
        return deny;
    }
    let store = require_store!(&st);
    match store
        .delete_role_assignment(&principal, &q.role, &q.scope)
        .await
    {
        Ok(()) => {
            emit(
                Some(store),
                AuditEvent {
                    ts: now_unix(),
                    subject: identity.as_ref().map(|e| e.0.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("delete_assignment".into()),
                    method: Some("DELETE".into()),
                    path: Some(format!("/api/v1/access/assignments/{principal}")),
                    status: Some(StatusCode::NO_CONTENT.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(mobula_controller::StoreError::Backend(m)) if m.contains("no such assignment") => {
            (StatusCode::NOT_FOUND, "no such assignment").into_response()
        }
        Err(e) => store_err(e),
    }
}
