//! Ray Serve service API (Phase 4). Unlike clusters, there is no Mobula
//! desired-state store or reconcile loop here: KubeRay's RayService
//! controller owns convergence and zero-downtime (canary) upgrades, so
//! Mobula is a thin authenticated CRUD proxy over the live provisioner.
//!
//! Permissions are against `Target::Service` (#26): deploying/updating a
//! Serve app is "code", so `Developer` (and `Admin`) may write; `Operator`
//! and `Viewer` are read-only.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, Target};
use mobula_core::ServiceSpec;
use mobula_provision::{ObservedService, ServiceProvisioner};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth_layer::authorize;

#[derive(Clone)]
pub struct ServiceApiState {
    pub provisioner: Arc<dyn ServiceProvisioner>,
}

/// Request body to deploy or update a service.
#[derive(Deserialize, ToSchema)]
pub struct DeployService {
    /// Stable service name (the RayService name).
    pub name: String,
    pub spec: ServiceSpec,
}

#[derive(Serialize, ToSchema)]
pub struct ServiceView {
    pub name: String,
    /// Observed lifecycle state: provisioning | running | updating | ...
    pub state: String,
    /// External Serve endpoint base URL, when ready.
    pub url: Option<String>,
}

impl From<ObservedService> for ServiceView {
    fn from(o: ObservedService) -> Self {
        ServiceView {
            name: o.name,
            state: serde_json::to_value(o.state)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            url: o.url,
        }
    }
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

fn prov_err(e: mobula_provision::ProvisionError) -> Response {
    tracing::warn!(error = %e, "service provisioner error");
    (StatusCode::BAD_GATEWAY, "service backend error").into_response()
}

#[utoipa::path(
    get, path = "/api/v1/services", tag = "services",
    responses((status = 200, description = "All managed services", body = [ServiceView]),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on service")),
    security(("bearer" = []))
)]
async fn list_services(
    State(st): State<ServiceApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Read, Target::Service) {
        return deny;
    }
    match st.provisioner.list().await {
        Ok(svcs) => {
            Json(svcs.into_iter().map(ServiceView::from).collect::<Vec<_>>()).into_response()
        }
        Err(e) => prov_err(e),
    }
}

#[utoipa::path(
    get, path = "/api/v1/services/{name}", tag = "services",
    params(("name" = String, Path, description = "Service name")),
    responses((status = 200, description = "The service", body = ServiceView),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on service"),
              (status = 404, description = "No such service")),
    security(("bearer" = []))
)]
async fn get_service(
    State(st): State<ServiceApiState>,
    identity: Option<Extension<Identity>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Read, Target::Service) {
        return deny;
    }
    match st.provisioner.get(&name).await {
        Ok(Some(s)) => Json(ServiceView::from(s)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such service").into_response(),
        Err(e) => prov_err(e),
    }
}

#[utoipa::path(
    post, path = "/api/v1/services", tag = "services",
    request_body = DeployService,
    responses((status = 202, description = "Deploy accepted; KubeRay rolls it out"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Write on service (Developer/Admin only)"),
              (status = 502, description = "Service backend error")),
    security(("bearer" = []))
)]
async fn deploy_service(
    State(st): State<ServiceApiState>,
    identity: Option<Extension<Identity>>,
    Json(body): Json<DeployService>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Write, Target::Service) {
        return deny;
    }
    match st.provisioner.deploy(&body.name, &body.spec).await {
        Ok(()) => {
            tracing::info!(
                target: "mobula::audit",
                decision = "allow",
                subject = ident(&identity).map(|i| i.subject.as_str()).unwrap_or("-"),
                action = "deploy_service", service = %body.name,
                upgrade = ?body.spec.upgrade, "service deployed"
            );
            StatusCode::ACCEPTED.into_response()
        }
        Err(e) => prov_err(e),
    }
}

#[utoipa::path(
    delete, path = "/api/v1/services/{name}", tag = "services",
    params(("name" = String, Path, description = "Service name")),
    responses((status = 202, description = "Teardown accepted"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Write on service (Developer/Admin only)")),
    security(("bearer" = []))
)]
async fn delete_service(
    State(st): State<ServiceApiState>,
    identity: Option<Extension<Identity>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Write, Target::Service) {
        return deny;
    }
    match st.provisioner.delete(&name).await {
        Ok(()) => {
            tracing::info!(
                target: "mobula::audit",
                decision = "allow",
                subject = ident(&identity).map(|i| i.subject.as_str()).unwrap_or("-"),
                action = "delete_service", service = %name, "service deleted"
            );
            StatusCode::ACCEPTED.into_response()
        }
        Err(e) => prov_err(e),
    }
}

pub fn router(provisioner: Arc<dyn ServiceProvisioner>) -> Router {
    Router::new()
        .route("/api/v1/services", get(list_services).post(deploy_service))
        .route(
            "/api/v1/services/{name}",
            get(get_service).delete(delete_service),
        )
        .with_state(ServiceApiState { provisioner })
}
