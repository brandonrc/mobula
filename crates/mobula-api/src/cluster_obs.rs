//! Per-cluster observability endpoints for the cluster drill-down tabs
//! (Milestone C):
//!
//! - `GET /api/v1/clusters/{id}/nodes` (api-v1.md §5.3) — the head +
//!   per-worker-group node breakdown, read from Kubernetes (the RayCluster
//!   and the pods KubeRay owns), NOT the Ray dashboard, so it answers even
//!   when the dashboard is unreachable. Observability only (decision D2):
//!   there is no per-node mutation; scale is group-level.
//!
//! - `GET /api/v1/clusters/{id}/jobs` (api-v1.md §5.6) — the browser-
//!   consumable, path-based proxy to the cluster's Ray Job Submission API
//!   (`GET /api/jobs/`). This is the *same* southbound discipline as the
//!   federating gateway (`gateway::proxy`, ADR-0002/0003): the outbound
//!   request is built from scratch — no inbound header (so the caller's JWT
//!   never leaks southbound) — and the only credential injected is the
//!   cluster's static Ray token. The browser never constructs cluster
//!   hostnames; it reaches jobs by cluster id through the control plane.
//!   The list is normalized to a stable Mobula shape (a refinement of §5.6's
//!   opaque passthrough) so the UI codes against one schema across Ray minors.
//!
//! Both routes require the same read-scoped authorization as the other
//! cluster reads (#49): a developer sees only their project's clusters,
//! Admin sees all; an out-of-scope cluster is 404 (never leaks existence).

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use futures::StreamExt;
use mobula_auth::{Identity, PermissionType, Target};
use mobula_controller::Store;
use mobula_core::{ClusterId, ClusterRegistry};
use mobula_provision::{ProvisionError, Provisioner};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth_layer::{authorize, authorize_scoped};
use crate::clusters::read_scope;

/// Southbound connect timeout: a wedged head must not hang the request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Southbound total-request timeout for the jobs list.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on the proxied jobs body: a cluster with thousands of jobs could emit
/// a large list; a misconfigured head must not stream unbounded memory into
/// the control plane (mirrors the gateway's body cap, #30).
const MAX_JOBS_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Cap on concurrent southbound jobs proxies (mirrors the gateway's inflight
/// cap, #30/#31): excess requests are refused with 503 rather than piling up.
const MAX_INFLIGHT: usize = 64;

#[derive(Clone)]
pub struct ObsApiState {
    /// Authz + read-scoping (`Read` on `Target::Cluster`/`Target::Job`, #49)
    /// and the cluster's project lookup.
    pub store: Arc<dyn Store>,
    /// The gateway's routing table — source of a registered cluster's
    /// `api_base_url` + static token.
    pub registry: Arc<ClusterRegistry>,
    /// `None` on deployments with no cluster backend (gateway-only): the
    /// nodes route answers 404 `nodes unavailable`, and jobs falls back to
    /// the registry.
    pub provisioner: Option<Arc<dyn Provisioner>>,
    client: reqwest::Client,
    /// Bounds concurrent southbound jobs proxies (#30/#31).
    inflight: Arc<tokio::sync::Semaphore>,
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

/// The visibility a caller has to a cluster for a read: either a store-backed
/// cluster with a project (scoping applies) or a registry-only cluster (no
/// project — only global reads see it).
enum ClusterScope {
    /// Lifecycle-managed cluster in the store; authorize scoped to `project`.
    Project(String),
    /// Externally-registered cluster (registry only, no project).
    Registered,
}

/// Resolve a cluster for a read, applying read-scoping (#49): a caller
/// narrowed by project-scoped assignments gets 404 (not 403) for a cluster
/// outside their projects — the list hides it, so a by-name read must not
/// leak its existence. The `Err` is a small `(status, message)` the caller
/// turns into a response (kept small so the `Result` stays cheap to move).
async fn scope_for_read(
    st: &ObsApiState,
    identity: &Option<Extension<Identity>>,
    id: &ClusterId,
) -> Result<ClusterScope, (StatusCode, &'static str)> {
    match st.store.get(id).await {
        Ok(Some(c)) => {
            let (_, narrowed) = read_scope(&st.store, ident(identity)).await;
            if narrowed.is_some_and(|projects| !projects.contains(&c.spec.project)) {
                return Err((StatusCode::NOT_FOUND, "no such cluster"));
            }
            Ok(ClusterScope::Project(c.spec.project.clone()))
        }
        Ok(None) => {
            // Not in the store: only an externally-registered cluster can be
            // read here. A project-narrowed caller can't see a cluster with
            // no project, so it 404s exactly as a hidden one would.
            if st.registry.by_id(id).is_none() {
                return Err((StatusCode::NOT_FOUND, "no such cluster"));
            }
            let (_, narrowed) = read_scope(&st.store, ident(identity)).await;
            if narrowed.is_some() {
                return Err((StatusCode::NOT_FOUND, "no such cluster"));
            }
            Ok(ClusterScope::Registered)
        }
        Err(e) => {
            tracing::warn!(error = %e, "cluster obs store error");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "store error"))
        }
    }
}

// ---------------------------------------------------------------------------
// Nodes (§5.3)
// ---------------------------------------------------------------------------

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}/nodes", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses(
        (status = 200, description = "Head + per-worker-group node breakdown, sourced from Kubernetes", body = mobula_core::ClusterNodes),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Read on cluster"),
        (status = 404, description = "No such cluster, or the backend exposes no node breakdown"),
        (status = 503, description = "The node source (Kubernetes) could not be reached")),
    security(("bearer" = []))
)]
async fn cluster_nodes(
    State(st): State<ObsApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    let id = ClusterId(id);
    let scope = match scope_for_read(&st, &identity, &id).await {
        Ok(s) => s,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    // Nodes read like cluster data: Read on Target::Cluster (Viewer+).
    let deny = match &scope {
        ClusterScope::Project(project) => {
            authorize_scoped(
                Some(&st.store),
                ident(&identity),
                PermissionType::Read,
                Target::Cluster,
                project,
            )
            .await
        }
        ClusterScope::Registered => {
            authorize(
                Some(&st.store),
                ident(&identity),
                PermissionType::Read,
                Target::Cluster,
            )
            .await
        }
    };
    if let Some(deny) = deny {
        return deny;
    }

    let Some(provisioner) = st.provisioner.as_ref() else {
        return (StatusCode::NOT_FOUND, "nodes unavailable").into_response();
    };
    match provisioner.cluster_nodes(&id).await {
        Ok(Some(nodes)) => Json(nodes).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "nodes unavailable").into_response(),
        Err(ProvisionError::NotFound(_)) => {
            (StatusCode::NOT_FOUND, "no such cluster").into_response()
        }
        Err(e) => {
            // The node source is Kubernetes, not the Ray dashboard; a backend
            // failure here means the control plane can't reach its own
            // cluster API. Answer 503 gracefully rather than 500-ing.
            tracing::warn!(cluster = %id.0, error = %e, "node breakdown backend error");
            (StatusCode::SERVICE_UNAVAILABLE, "node source unavailable").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Jobs proxy (§5.6)
// ---------------------------------------------------------------------------

/// A Ray job normalized to a stable Mobula shape (api-v1.md §5.6). Every
/// field is optional: Ray's own records vary by version and by whether the
/// job has started/finished. `status` is Ray's vocabulary verbatim
/// (`PENDING | RUNNING | SUCCEEDED | FAILED | STOPPED`) — not snake_cased,
/// per §5.7. `start_time`/`end_time` are Ray's unix-millis timestamps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RayJobSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submission_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
    /// Ray's `start_time` (unix millis); `None` before the job starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<u64>,
    /// Ray's `end_time` (unix millis); `None` while the job runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Normalize the Ray `GET /api/jobs/` body into a stable list. Ray returns a
/// JSON array of job records; some older versions return an object keyed by
/// submission id. Both are accepted; anything else yields an empty list.
fn normalize_jobs(raw: &serde_json::Value) -> Vec<RayJobSummary> {
    let items: Vec<&serde_json::Value> = match raw {
        serde_json::Value::Array(a) => a.iter().collect(),
        serde_json::Value::Object(m) => m.values().collect(),
        _ => Vec::new(),
    };
    items
        .into_iter()
        .map(|j| {
            let s = |k: &str| j.get(k).and_then(|v| v.as_str()).map(String::from);
            RayJobSummary {
                job_id: s("job_id"),
                submission_id: s("submission_id"),
                status: s("status"),
                entrypoint: s("entrypoint"),
                start_time: j.get("start_time").and_then(|v| v.as_u64()),
                end_time: j.get("end_time").and_then(|v| v.as_u64()),
                message: s("message"),
            }
        })
        .collect()
}

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}/jobs", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses(
        (status = 200, description = "Normalized list of Ray jobs on the cluster", body = [RayJobSummary]),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Read on job"),
        (status = 404, description = "No such cluster, or no reachable Ray endpoint for it"),
        (status = 503, description = "The cluster's Ray Job API could not be reached")),
    security(("bearer" = []))
)]
async fn cluster_jobs(
    State(st): State<ObsApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    let id = ClusterId(id);
    let scope = match scope_for_read(&st, &identity, &id).await {
        Ok(s) => s,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    // Listing jobs is a Read on Target::Job (§5.6), scoped to the cluster's
    // project when it has one.
    let deny = match &scope {
        ClusterScope::Project(project) => {
            authorize_scoped(
                Some(&st.store),
                ident(&identity),
                PermissionType::Read,
                Target::Job,
                project,
            )
            .await
        }
        ClusterScope::Registered => {
            authorize(
                Some(&st.store),
                ident(&identity),
                PermissionType::Read,
                Target::Job,
            )
            .await
        }
    };
    if let Some(deny) = deny {
        return deny;
    }

    // Resolve the southbound base URL + token: a registered cluster's from
    // the registry (explicit token), else a lifecycle-managed cluster's
    // head-service dashboard from the provisioner (no token — the in-cluster
    // Ray dashboard is reached over the tenant network).
    let (base, token) = if let Some(ep) = st.registry.by_id(&id) {
        (ep.api_base_url.clone(), ep.auth_token.clone())
    } else if let Some(base) = st
        .provisioner
        .as_ref()
        .and_then(|p| p.dashboard_api_base(&id))
    {
        (base, None)
    } else {
        return (StatusCode::NOT_FOUND, "jobs unavailable").into_response();
    };
    let url = format!("{}/api/jobs/", base.trim_end_matches('/'));

    // One permit per proxied request bounds fan-out and buffered memory
    // (#30/#31); excess is refused with 503 rather than queued.
    let _permit = match st.inflight.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway busy: too many inflight proxied requests",
            )
                .into_response()
        }
    };

    let mut req = st.client.get(&url);
    if let Some(token) = &token {
        match HeaderValue::from_str(&format!("Bearer {token}")) {
            Ok(v) => req = req.header(header::AUTHORIZATION, v),
            Err(_) => {
                tracing::warn!(cluster = %id.0, "registry token is not a legal header value");
                return (StatusCode::INTERNAL_SERVER_ERROR, "invalid cluster token")
                    .into_response();
            }
        }
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // without_url(): reqwest error strings can embed the southbound
            // URL — keep internal topology out of logs (#5). A transport
            // failure is a graceful 503 (task: not a 502 crash) — the UI
            // renders it as the "backend unreachable" empty state.
            tracing::warn!(cluster = %id.0, error = %e.without_url(), "jobs upstream error");
            return (StatusCode::SERVICE_UNAVAILABLE, "cluster unreachable").into_response();
        }
    };
    let status = upstream.status();

    // Buffer with a hard cap rather than streaming.
    let mut body = Vec::new();
    let mut stream = upstream.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if body.len() + bytes.len() > MAX_JOBS_BODY_BYTES {
                    tracing::warn!(cluster = %id.0, cap = MAX_JOBS_BODY_BYTES, "jobs response exceeded the size cap");
                    return (StatusCode::SERVICE_UNAVAILABLE, "jobs response too large")
                        .into_response();
                }
                body.extend_from_slice(&bytes);
            }
            Err(e) => {
                tracing::warn!(cluster = %id.0, error = %e.without_url(), "jobs stream error");
                return (StatusCode::SERVICE_UNAVAILABLE, "cluster unreachable").into_response();
            }
        }
    }

    // A non-success upstream status is Ray's own answer — pass it through with
    // its body (§2.6: Ray's errors are not re-wrapped), rather than pretending
    // an empty list.
    if !status.is_success() {
        return (status, body).into_response();
    }

    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(raw) => Json(normalize_jobs(&raw)).into_response(),
        Err(e) => {
            tracing::warn!(cluster = %id.0, error = %e, "jobs response was not valid JSON");
            (StatusCode::SERVICE_UNAVAILABLE, "invalid jobs response").into_response()
        }
    }
}

pub fn router(
    store: Arc<dyn Store>,
    registry: Arc<ClusterRegistry>,
    provisioner: Option<Arc<dyn Provisioner>>,
) -> Router {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(READ_TIMEOUT)
        // Redirects are never followed southbound (same posture as the
        // gateway): a 3xx Location would carry internal service names/IPs.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("static client config builds");
    Router::new()
        .route("/api/v1/clusters/{id}/nodes", get(cluster_nodes))
        .route("/api/v1/clusters/{id}/jobs", get(cluster_jobs))
        .with_state(ObsApiState {
            store,
            registry,
            provisioner,
            client,
            inflight: Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT)),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_jobs_from_array() {
        let raw = json!([
            {
                "job_id": "01000000",
                "submission_id": "raysubmit_abc",
                "status": "SUCCEEDED",
                "entrypoint": "python train.py",
                "start_time": 1_755_280_010_000u64,
                "end_time": 1_755_281_900_000u64,
                "message": "Job finished successfully."
            },
            {
                "submission_id": "raysubmit_def",
                "status": "RUNNING",
                "entrypoint": "serve run app:main",
                "start_time": 1_755_282_000_000u64
            }
        ]);
        let jobs = normalize_jobs(&raw);
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].job_id.as_deref(), Some("01000000"));
        assert_eq!(jobs[0].submission_id.as_deref(), Some("raysubmit_abc"));
        assert_eq!(jobs[0].status.as_deref(), Some("SUCCEEDED"));
        assert_eq!(jobs[0].end_time, Some(1_755_281_900_000));
        // Running job: no end_time, no job_id yet.
        assert_eq!(jobs[1].job_id, None);
        assert_eq!(jobs[1].status.as_deref(), Some("RUNNING"));
        assert_eq!(jobs[1].end_time, None);
    }

    #[test]
    fn normalize_jobs_from_object_map() {
        // Older Ray keyed the response by submission id.
        let raw = json!({
            "raysubmit_abc": { "submission_id": "raysubmit_abc", "status": "FAILED" }
        });
        let jobs = normalize_jobs(&raw);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].status.as_deref(), Some("FAILED"));
    }

    #[test]
    fn normalize_jobs_tolerates_garbage() {
        assert!(normalize_jobs(&json!("nope")).is_empty());
        assert!(normalize_jobs(&json!(42)).is_empty());
        assert!(normalize_jobs(&json!([])).is_empty());
    }
}
