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

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use futures::StreamExt;
use mobula_auth::{Identity, PermissionType, Target};
use mobula_controller::Store;
use mobula_core::{ClusterId, ClusterMetrics, ClusterRegistry, ResourceStat};
use mobula_provision::{ProvisionError, Provisioner};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

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
/// Cap on a proxied metrics body (`/api/v0/nodes`, `/api/cluster_status`):
/// both are small, but a misconfigured head must not stream unbounded memory.
const MAX_STATUS_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Default log tail when the caller names none.
const DEFAULT_LOG_TAIL: usize = 200;
/// Hard cap on the log tail a caller may request (bounds the K8s log fetch and
/// the response body).
const MAX_LOG_TAIL: usize = 5_000;

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

    // Multi-engine: the batch job gateway is a Ray-only surface (there is no
    // Ray-Jobs-REST equivalent on a Dask scheduler). Reject a job request
    // against a Dask cluster with a clear 400 rather than a generic 404.
    if let Ok(Some(c)) = st.store.get(&id).await {
        if c.spec.engine == mobula_core::Engine::Dask {
            return (
                StatusCode::BAD_REQUEST,
                "job submission is not supported for engine=dask (batch is a Ray-only surface)",
            )
                .into_response();
        }
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

// ---------------------------------------------------------------------------
// Shared read authorization
// ---------------------------------------------------------------------------

/// Authorize a cluster read (`Read` on `Target::Cluster`, Viewer+), scoped to
/// the cluster's project when it has one. Returns the deny response, or `None`
/// when allowed. Shared by the events/metrics/logs reads, which — like nodes —
/// read as cluster data.
async fn deny_cluster_read(
    st: &ObsApiState,
    identity: &Option<Extension<Identity>>,
    scope: &ClusterScope,
) -> Option<Response> {
    match scope {
        ClusterScope::Project(project) => {
            authorize_scoped(
                Some(&st.store),
                ident(identity),
                PermissionType::Read,
                Target::Cluster,
                project,
            )
            .await
        }
        ClusterScope::Registered => {
            authorize(
                Some(&st.store),
                ident(identity),
                PermissionType::Read,
                Target::Cluster,
            )
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Events (§5.8)
// ---------------------------------------------------------------------------

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}/events", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses(
        (status = 200, description = "Kubernetes Events for the cluster's objects, newest first (capped)", body = mobula_core::ClusterEvents),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Read on cluster"),
        (status = 404, description = "No such cluster, or the backend exposes no events"),
        (status = 503, description = "The event source (Kubernetes) could not be reached")),
    security(("bearer" = []))
)]
async fn cluster_events(
    State(st): State<ObsApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    let id = ClusterId(id);
    let scope = match scope_for_read(&st, &identity, &id).await {
        Ok(s) => s,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    if let Some(deny) = deny_cluster_read(&st, &identity, &scope).await {
        return deny;
    }

    let Some(provisioner) = st.provisioner.as_ref() else {
        return (StatusCode::NOT_FOUND, "events unavailable").into_response();
    };
    match provisioner.cluster_events(&id).await {
        Ok(Some(events)) => Json(events).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "events unavailable").into_response(),
        Err(ProvisionError::NotFound(_)) => {
            (StatusCode::NOT_FOUND, "no such cluster").into_response()
        }
        Err(e) => {
            // The event source is Kubernetes; a failure means the control plane
            // can't reach its own cluster API. 503, not 500.
            tracing::warn!(cluster = %id.0, error = %e, "events backend error");
            (StatusCode::SERVICE_UNAVAILABLE, "event source unavailable").into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics (§5.x resource summary)
// ---------------------------------------------------------------------------

/// The Ray state-API node list (`GET /api/v0/nodes`): the resource capacity
/// the cluster actually reports, node-by-node, and node liveness. Unlike
/// `/api/cluster_status` (autoscaler-only — `null` on a static KubeRay
/// cluster), this answers on every live Ray, autoscaler or not. Returns the
/// summed capacity per resource (across ALIVE nodes) and live node counts.
struct StateNodesSummary {
    cpu: Option<f64>,
    gpu: Option<f64>,
    memory: Option<f64>,
    object_store_memory: Option<f64>,
    active_nodes: u64,
    dead_nodes: u64,
}

/// The rows of the state API's `/api/v0/nodes` response (`data.result.result`).
fn state_node_rows(raw: &serde_json::Value) -> &[serde_json::Value] {
    raw.get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.get("result"))
        .and_then(|r| r.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Sum `resources_total` across ALIVE nodes and count node liveness.
fn summarize_state_nodes(raw: &serde_json::Value) -> StateNodesSummary {
    let mut cpu = 0.0;
    let mut gpu = 0.0;
    let mut memory = 0.0;
    let mut oss = 0.0;
    let (mut have_cpu, mut have_gpu, mut have_mem, mut have_oss) = (false, false, false, false);
    let mut active = 0u64;
    let mut dead = 0u64;
    for node in state_node_rows(raw) {
        let alive = node.get("state").and_then(|v| v.as_str()) == Some("ALIVE");
        if alive {
            active += 1;
        } else {
            dead += 1;
            continue; // only ALIVE nodes contribute capacity
        }
        let Some(res) = node.get("resources_total").and_then(|v| v.as_object()) else {
            continue;
        };
        if let Some(v) = res.get("CPU").and_then(|v| v.as_f64()) {
            cpu += v;
            have_cpu = true;
        }
        if let Some(v) = res.get("GPU").and_then(|v| v.as_f64()) {
            gpu += v;
            have_gpu = true;
        }
        if let Some(v) = res.get("memory").and_then(|v| v.as_f64()) {
            memory += v;
            have_mem = true;
        }
        if let Some(v) = res.get("object_store_memory").and_then(|v| v.as_f64()) {
            oss += v;
            have_oss = true;
        }
    }
    StateNodesSummary {
        cpu: have_cpu.then_some(cpu),
        gpu: have_gpu.then_some(gpu),
        memory: have_mem.then_some(memory),
        object_store_memory: have_oss.then_some(oss),
        active_nodes: active,
        dead_nodes: dead,
    }
}

/// Read the used amount for `key` from an autoscaler `loadMetricsReport.usage`
/// map (`{ key: [used, total] }`). `None` when absent — the common case on a
/// non-autoscaling cluster, where `/api/cluster_status` carries no report.
fn usage_used(usage: Option<&serde_json::Value>, key: &str) -> Option<f64> {
    usage?
        .get(key)?
        .as_array()?
        .first()
        .and_then(|v| v.as_f64())
}

/// Build the normalized resource summary (api-v1.md §5.x) from the state-API
/// node list (capacity + node counts — always available on a live Ray) and,
/// when present, the autoscaler's load-metrics `usage` map (for the `used`
/// half of each stat). `used` stays `None` when no report is available, so the
/// tile shows capacity only rather than a misleading meter.
fn summarize_metrics(
    cluster_id: &str,
    nodes_raw: &serde_json::Value,
    status_raw: Option<&serde_json::Value>,
) -> ClusterMetrics {
    let s = summarize_state_nodes(nodes_raw);
    // Locate the autoscaler usage map when a cluster_status report exists.
    let usage = status_raw.and_then(|raw| {
        raw.get("data")
            .and_then(|d| d.get("clusterStatus"))
            .or_else(|| raw.get("clusterStatus"))
            .and_then(|cs| cs.get("loadMetricsReport"))
            .and_then(|r| r.get("usage"))
            .cloned()
    });
    let stat = |total: Option<f64>, key: &str| {
        total.map(|total| ResourceStat {
            used: usage_used(usage.as_ref(), key),
            total,
        })
    };
    ClusterMetrics {
        cluster_id: cluster_id.to_string(),
        cpu: stat(s.cpu, "CPU"),
        gpu: stat(s.gpu, "GPU"),
        memory: stat(s.memory, "memory"),
        object_store_memory: stat(s.object_store_memory, "object_store_memory"),
        active_nodes: Some(s.active_nodes),
        pending_nodes: None, // the state API does not surface pending pods
        failed_nodes: (s.dead_nodes > 0).then_some(s.dead_nodes),
    }
}

/// Fetch and JSON-parse a southbound dashboard endpoint with the shared body
/// cap. `Err(())` on any transport / status / parse failure — the caller
/// decides whether that is a hard 503 (the primary source) or a soft skip (the
/// best-effort usage enrichment).
async fn fetch_dashboard_json(
    st: &ObsApiState,
    url: &str,
    bearer: Option<&HeaderValue>,
    id: &ClusterId,
) -> Result<serde_json::Value, ()> {
    let mut req = st.client.get(url);
    if let Some(v) = bearer {
        req = req.header(header::AUTHORIZATION, v.clone());
    }
    let upstream = req.send().await.map_err(|e| {
        tracing::warn!(cluster = %id.0, error = %e.without_url(), "metrics upstream error");
    })?;
    if !upstream.status().is_success() {
        tracing::warn!(cluster = %id.0, status = %upstream.status(), "metrics upstream non-success");
        return Err(());
    }
    let mut body = Vec::new();
    let mut stream = upstream.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(|e| {
            tracing::warn!(cluster = %id.0, error = %e.without_url(), "metrics stream error");
        })?;
        if body.len() + bytes.len() > MAX_STATUS_BODY_BYTES {
            tracing::warn!(cluster = %id.0, cap = MAX_STATUS_BODY_BYTES, "metrics response exceeded the size cap");
            return Err(());
        }
        body.extend_from_slice(&bytes);
    }
    serde_json::from_slice(&body).map_err(|e| {
        tracing::warn!(cluster = %id.0, error = %e, "metrics response was not valid JSON");
    })
}

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}/metrics", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses(
        (status = 200, description = "Normalized cluster resource-usage summary (CPU/GPU/mem used vs total + node counts)", body = mobula_core::ClusterMetrics),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Read on cluster"),
        (status = 404, description = "No such cluster, or no reachable Ray dashboard for it"),
        (status = 503, description = "The cluster's Ray dashboard could not be reached")),
    security(("bearer" = []))
)]
async fn cluster_metrics(
    State(st): State<ObsApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    let id = ClusterId(id);
    let scope = match scope_for_read(&st, &identity, &id).await {
        Ok(s) => s,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    if let Some(deny) = deny_cluster_read(&st, &identity, &scope).await {
        return deny;
    }

    // Resolve the southbound dashboard base + token, exactly as the jobs proxy
    // does: registered cluster from the registry (explicit token), else the
    // lifecycle-managed head-service dashboard (no token, in-cluster).
    let (base, token) = if let Some(ep) = st.registry.by_id(&id) {
        (ep.api_base_url.clone(), ep.auth_token.clone())
    } else if let Some(base) = st
        .provisioner
        .as_ref()
        .and_then(|p| p.dashboard_api_base(&id))
    {
        (base, None)
    } else {
        return (StatusCode::NOT_FOUND, "metrics unavailable").into_response();
    };
    let base = base.trim_end_matches('/').to_string();

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

    // Build the southbound bearer once (a token that isn't a legal header value
    // is a config error → fail closed, not scrape unauthenticated).
    let bearer = match &token {
        Some(t) => match HeaderValue::from_str(&format!("Bearer {t}")) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!(cluster = %id.0, "registry token is not a legal header value");
                return (StatusCode::INTERNAL_SERVER_ERROR, "invalid cluster token")
                    .into_response();
            }
        },
        None => None,
    };

    // Primary source: the Ray state API `/api/v0/nodes` — the cluster's actual
    // resource capacity + node liveness, present on every live Ray (autoscaler
    // or not). Unreachable / non-2xx / unparseable → clean 503 (never a
    // 502/panic); the UI renders the cluster-unreachable state.
    let nodes_url = format!("{base}/api/v0/nodes");
    let Ok(nodes_raw) = fetch_dashboard_json(&st, &nodes_url, bearer.as_ref(), &id).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, "cluster unreachable").into_response();
    };

    // Best-effort enrichment: the autoscaler's `/api/cluster_status` carries
    // live `used` per resource. It is `null` on a static (non-autoscaling)
    // cluster, so a failure here is NOT fatal — `used` simply stays absent and
    // the tiles show capacity only.
    let status_url = format!("{base}/api/cluster_status");
    let status_raw = fetch_dashboard_json(&st, &status_url, bearer.as_ref(), &id)
        .await
        .ok();

    Json(summarize_metrics(&id.0, &nodes_raw, status_raw.as_ref())).into_response()
}

// ---------------------------------------------------------------------------
// Logs (§5.6, non-streaming first cut)
// ---------------------------------------------------------------------------

/// Query params for the log tail: which pod, and how many lines.
#[derive(Debug, Deserialize, IntoParams)]
pub struct LogsQuery {
    /// Pod to tail (one of the cluster's pods); defaults to the head pod.
    pub node: Option<String>,
    /// Number of trailing lines to return (default 200, capped at 5000).
    pub tail: Option<usize>,
}

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}/logs", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id"), LogsQuery),
    responses(
        (status = 200, description = "Recent (tail-capped) pod logs plus the list of tailable pods", body = mobula_core::ClusterLogs),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Read on cluster"),
        (status = 404, description = "No such cluster/pod, or the backend exposes no logs"),
        (status = 503, description = "The log source (Kubernetes) could not be reached")),
    security(("bearer" = []))
)]
async fn cluster_logs(
    State(st): State<ObsApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Response {
    let id = ClusterId(id);
    let scope = match scope_for_read(&st, &identity, &id).await {
        Ok(s) => s,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    if let Some(deny) = deny_cluster_read(&st, &identity, &scope).await {
        return deny;
    }

    let tail = q.tail.unwrap_or(DEFAULT_LOG_TAIL).clamp(1, MAX_LOG_TAIL);

    let Some(provisioner) = st.provisioner.as_ref() else {
        return (StatusCode::NOT_FOUND, "logs unavailable").into_response();
    };
    match provisioner.cluster_logs(&id, q.node.as_deref(), tail).await {
        Ok(Some(logs)) => Json(logs).into_response(),
        // A named pod that is not part of this cluster (or no log source).
        Ok(None) => (StatusCode::NOT_FOUND, "no such pod for this cluster").into_response(),
        Err(ProvisionError::NotFound(_)) => {
            (StatusCode::NOT_FOUND, "no such cluster").into_response()
        }
        Err(e) => {
            tracing::warn!(cluster = %id.0, error = %e, "logs backend error");
            (StatusCode::SERVICE_UNAVAILABLE, "log source unavailable").into_response()
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
        .route("/api/v1/clusters/{id}/events", get(cluster_events))
        .route("/api/v1/clusters/{id}/metrics", get(cluster_metrics))
        .route("/api/v1/clusters/{id}/logs", get(cluster_logs))
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

    /// The real `/api/v0/nodes` shape (Ray 2.56, static KubeRay cluster): a
    /// head + a worker, each with `resources_total`, and no autoscaler report.
    fn state_nodes_sample() -> serde_json::Value {
        json!({
            "result": true,
            "data": { "result": { "total": 2, "result": [
                {
                    "state": "ALIVE", "is_head_node": false,
                    "resources_total": {
                        "CPU": 1.0, "memory": 3221225472.0,
                        "object_store_memory": 927966412.0, "node:10.1.213.197": 1.0
                    }
                },
                {
                    "state": "ALIVE", "is_head_node": true,
                    "resources_total": {
                        "CPU": 1.0, "memory": 3221225472.0,
                        "object_store_memory": 682360012.0,
                        "node:__internal_head__": 1.0, "node:10.1.213.216": 1.0
                    }
                }
            ] } }
        })
    }

    #[test]
    fn metrics_capacity_from_state_api_no_autoscaler() {
        // No cluster_status report (static cluster): capacity + node counts
        // from the state API, `used` absent (tiles show capacity only).
        let m = summarize_metrics("team-b-scoring", &state_nodes_sample(), None);
        assert_eq!(m.cluster_id, "team-b-scoring");
        assert_eq!(
            m.cpu,
            Some(ResourceStat {
                used: None,
                total: 2.0
            })
        );
        assert_eq!(
            m.memory,
            Some(ResourceStat {
                used: None,
                total: 6442450944.0
            })
        );
        assert!(m.object_store_memory.is_some());
        assert_eq!(m.gpu, None, "no GPU resource reported → no tile");
        assert_eq!(m.active_nodes, Some(2));
        assert_eq!(m.failed_nodes, None);
        assert_eq!(m.pending_nodes, None);
    }

    #[test]
    fn metrics_used_enriched_from_autoscaler_report() {
        // When the autoscaler cluster_status carries a usage map, `used` fills
        // in against the state-API capacity.
        let status = json!({
            "data": { "clusterStatus": { "loadMetricsReport": { "usage": {
                "CPU": [1.5, 2.0],
                "memory": [1000.0, 6442450944.0]
            } } } }
        });
        let m = summarize_metrics("c", &state_nodes_sample(), Some(&status));
        assert_eq!(
            m.cpu,
            Some(ResourceStat {
                used: Some(1.5),
                total: 2.0
            })
        );
        assert_eq!(m.memory.unwrap().used, Some(1000.0));
        // object_store has capacity but no usage entry → used stays None.
        assert_eq!(m.object_store_memory.unwrap().used, None);
    }

    #[test]
    fn metrics_counts_dead_nodes_and_tolerates_garbage() {
        let with_dead = json!({
            "data": { "result": { "result": [
                { "state": "ALIVE", "resources_total": { "CPU": 4.0 } },
                { "state": "DEAD", "resources_total": { "CPU": 4.0 } }
            ] } }
        });
        let m = summarize_metrics("c", &with_dead, None);
        // Only the ALIVE node contributes capacity.
        assert_eq!(
            m.cpu,
            Some(ResourceStat {
                used: None,
                total: 4.0
            })
        );
        assert_eq!(m.active_nodes, Some(1));
        assert_eq!(m.failed_nodes, Some(1));

        // No usable node list: a well-formed empty summary, never a panic.
        let empty = summarize_metrics("c", &json!({ "result": false }), None);
        assert_eq!(empty.cpu, None);
        assert_eq!(empty.active_nodes, Some(0));
    }
}
