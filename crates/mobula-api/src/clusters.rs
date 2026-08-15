//! Cluster lifecycle API (Phase 3). These are Mobula's own routes (not the
//! proxied Ray surface), so they enforce permissions against
//! `Target::Cluster` per route (#26): reads need `Read`, create/terminate
//! need `Write` — which `Operator`/`Admin` have and `Developer` does not.
//!
//! Handlers only manipulate *desired* state in the [`Store`]; the reconcile
//! engine converges the actual KubeRay resources.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, Target};
use mobula_controller::{DesiredState, Store};
use mobula_core::{ClusterId, ClusterSpec};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth_layer::authorize;

#[derive(Clone)]
pub struct ClusterApiState {
    pub store: Arc<dyn Store>,
}

/// Request body for creating/updating a managed cluster.
#[derive(Deserialize, ToSchema)]
pub struct CreateCluster {
    /// Stable cluster id (also the gateway routing key / RayCluster name).
    pub id: String,
    pub spec: ClusterSpec,
}

/// A cluster as the control plane sees it: desired spec metadata plus the
/// last observed state (reconstructed from the provisioner, ADR-0006).
#[derive(Serialize, ToSchema)]
pub struct ClusterView {
    pub id: String,
    /// Bumps when the spec changes; drives the reconcile idempotency key.
    pub generation: u64,
    /// "running" | "terminated" — the operator's intent.
    pub desired: String,
    /// Observed lifecycle state, if the cluster has been reconciled.
    pub observed_state: Option<String>,
    pub observed_generation: u64,
    pub project: String,
    pub ray_version: String,
}

impl ClusterView {
    fn from_stored(c: mobula_controller::StoredCluster) -> Self {
        Self {
            id: c.id.to_string(),
            generation: c.generation,
            desired: match c.desired {
                DesiredState::Running => "running".into(),
                DesiredState::Terminated => "terminated".into(),
            },
            observed_state: c
                .observed_state
                .map(|s| serde_json::to_value(s).ok())
                .and_then(|v| v.and_then(|v| v.as_str().map(String::from))),
            observed_generation: c.observed_generation,
            project: c.spec.project.clone(),
            ray_version: c.spec.ray_version.clone(),
        }
    }
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

fn store_err(e: mobula_controller::StoreError) -> Response {
    tracing::warn!(error = %e, "cluster store error");
    (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
}

#[utoipa::path(
    get, path = "/api/v1/clusters", tag = "clusters",
    responses((status = 200, description = "All managed clusters", body = [ClusterView]),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on cluster")),
    security(("bearer" = []))
)]
async fn list_clusters(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Read, Target::Cluster) {
        return deny;
    }
    match st.store.list().await {
        Ok(clusters) => {
            let views: Vec<_> = clusters.into_iter().map(ClusterView::from_stored).collect();
            Json(views).into_response()
        }
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses((status = 200, description = "The cluster", body = ClusterView),
              (status = 404, description = "No such cluster")),
    security(("bearer" = []))
)]
async fn get_cluster(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Read, Target::Cluster) {
        return deny;
    }
    match st.store.get(&ClusterId(id)).await {
        Ok(Some(c)) => Json(ClusterView::from_stored(c)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such cluster").into_response(),
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    post, path = "/api/v1/clusters", tag = "clusters",
    request_body = CreateCluster,
    responses((status = 201, description = "Desired state recorded; reconciler will converge"),
              (status = 403, description = "Missing Write on cluster (Operator/Admin only)")),
    security(("bearer" = []))
)]
async fn create_cluster(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
    Json(body): Json<CreateCluster>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Write, Target::Cluster) {
        return deny;
    }
    let id = ClusterId(body.id);
    match st.store.upsert_desired(&id, body.spec).await {
        Ok(generation) => {
            tracing::info!(
                target: "mobula::audit",
                decision = "allow",
                subject = ident(&identity).map(|i| i.subject.as_str()).unwrap_or("-"),
                action = "create_cluster", cluster = %id, generation,
                "cluster upserted"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "id": id.0, "generation": generation })),
            )
                .into_response()
        }
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    delete, path = "/api/v1/clusters/{id}", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses((status = 202, description = "Marked for termination; reconciler tears it down"),
              (status = 404, description = "No such cluster")),
    security(("bearer" = []))
)]
async fn delete_cluster(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Write, Target::Cluster) {
        return deny;
    }
    let id = ClusterId(id);
    // Desired = Terminated; the reconciler tears down the backing resources.
    match st.store.set_desired(&id, DesiredState::Terminated).await {
        Ok(()) => {
            tracing::info!(
                target: "mobula::audit",
                decision = "allow",
                subject = ident(&identity).map(|i| i.subject.as_str()).unwrap_or("-"),
                action = "delete_cluster", cluster = %id,
                "cluster marked for termination"
            );
            StatusCode::ACCEPTED.into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "no such cluster").into_response(),
    }
}

pub fn router(store: Arc<dyn Store>) -> Router {
    Router::new()
        .route("/api/v1/clusters", get(list_clusters).post(create_cluster))
        .route(
            "/api/v1/clusters/{id}",
            get(get_cluster).delete(delete_cluster),
        )
        .with_state(ClusterApiState { store })
}
