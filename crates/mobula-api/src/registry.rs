//! Gateway registry read API: exposes the effective routing table the job
//! gateway uses (ADR-0002). This is the credential-routing table, so it is
//! Admin-only (api-v1.md §2.2) even for reads — and the static Ray tokens
//! are never serialized, only their presence (`token_set`).
//!
//! The registry is static config today (Phase 1); managed clusters from the
//! Store do not get routing entries automatically — dynamic registration is
//! a deliberate follow-up (security review #2 treats the dynamic registry
//! as an SSRF surface that needs its own guardrails).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, Target};
use mobula_core::ClusterRegistry;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth_layer::authorize;

#[derive(Clone)]
pub struct RegistryApiState {
    pub registry: Arc<ClusterRegistry>,
}

/// A gateway routing entry as the control plane may show it: where a
/// cluster is exposed and where its dashboard head lives, but never the
/// token itself (ADR-0003, security issue #4).
#[derive(Serialize, ToSchema)]
pub struct RegistryEntryView {
    pub id: String,
    pub hostname: String,
    pub api_base_url: String,
    /// Whether the gateway holds a static Ray token for this cluster.
    pub token_set: bool,
    /// Reserved for per-entry validation/reachability checks. Always null
    /// today: registry validation is fail-fast at startup, so every served
    /// entry is valid by construction.
    pub validation: Option<RegistryValidation>,
}

/// Placeholder shape for future per-entry health/validation results.
#[derive(Serialize, ToSchema)]
pub struct RegistryValidation {
    pub ok: bool,
    pub message: Option<String>,
    pub checked_at: Option<String>,
}

#[utoipa::path(
    get, path = "/api/v1/registry/clusters", tag = "registry",
    responses((status = 200, description = "The gateway's routing table", body = [RegistryEntryView]),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Admin only — the registry is the credential-routing table")),
    security(("bearer" = []))
)]
async fn list_registry(
    State(st): State<RegistryApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    // Admin-only: `Admin` on any target is granted only to Role::Admin
    // (mobula-auth grants matrix), and api-v1.md §2.2 classifies registry
    // surfaces as Admin. Target::Cluster because registry entries describe
    // cluster routing.
    if let Some(deny) = authorize(
        identity.as_ref().map(|e| &e.0),
        PermissionType::Admin,
        Target::Cluster,
    ) {
        return deny;
    }
    let entries: Vec<RegistryEntryView> = st
        .registry
        .clusters
        .iter()
        .map(|c| RegistryEntryView {
            id: c.id.to_string(),
            hostname: c.hostname.clone(),
            api_base_url: c.api_base_url.clone(),
            token_set: c.auth_token.is_some(),
            validation: None,
        })
        .collect();
    (StatusCode::OK, Json(entries)).into_response()
}

pub fn router(registry: Arc<ClusterRegistry>) -> Router {
    Router::new()
        .route("/api/v1/registry/clusters", get(list_registry))
        .with_state(RegistryApiState { registry })
}
