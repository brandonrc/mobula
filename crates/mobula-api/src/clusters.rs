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
use mobula_controller::{now_unix, DesiredState, Store};
use mobula_core::{AuditDecision, AuditEvent, ClusterId, ClusterSpec};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use mobula_policy::{admit, cluster_demand, PriceSheet, ResourceMap};
use std::collections::HashMap;

use crate::audit::emit;
use crate::auth_layer::authorize;
use crate::settings::{config_from_stored, effective_policy};

/// Governance config for the cluster API (Phase 4): an optional price
/// sheet for cost estimates, and per-project quota limits for admission.
/// Empty = no cost shown, no quota enforced (unlimited).
///
/// This is the BOOT-TIME SEED shape (the `--policy` TOML file). The
/// effective policy lives in the store and is read per request via
/// [`crate::settings::effective_policy`]; this value is consulted only
/// until the store holds a policy row (api-v1.md §5.16 precedence).
#[derive(Clone, Default)]
pub struct PolicyConfig {
    pub prices: Option<PriceSheet>,
    pub quotas: HashMap<String, ResourceMap>,
}

#[derive(Clone)]
pub struct ClusterApiState {
    pub store: Arc<dyn Store>,
    /// Boot-time policy seed (`--policy` file), NOT the effective policy:
    /// handlers load the effective (store-backed) policy per request via
    /// [`crate::settings::effective_policy`].
    pub policy: Arc<PolicyConfig>,
    /// Per-project admission locks (#44). Quota admission is a non-atomic
    /// read-check-write (list -> admit -> upsert) with `.await` points and
    /// the new cluster not yet in the store, so two concurrent creates for
    /// the same project can both observe pre-insert usage and both admit,
    /// over-committing the quota permanently. Holding a per-project lock
    /// across that section serializes same-project creates (the second then
    /// sees the first's committed row and is correctly 409'd) while leaving
    /// different projects concurrent.
    ///
    /// FOLLOW-UP: this is in-process only. A multi-replica / Postgres
    /// deployment needs the check-and-commit in a single store transaction
    /// (a `Store` method); tracked separately, not implemented here.
    pub admit_locks: Arc<std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
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
    /// Drift/health alarm raised by the reconcile engine (ADR-0004, #41/#47):
    /// "spec_drift" (out-of-band edit) or "degraded". `None` when converging
    /// normally. Distinct from `observed_state`.
    pub condition: Option<String>,
    pub project: String,
    pub ray_version: String,
    /// Estimated $/hr at min size, if a price sheet is configured.
    pub est_min_hourly: Option<f64>,
    /// Estimated $/hr at max (fully scaled) size.
    pub est_max_hourly: Option<f64>,
}

impl ClusterView {
    fn from_stored(c: mobula_controller::StoredCluster, prices: Option<&PriceSheet>) -> Self {
        let cost = prices.and_then(|p| p.estimate(&c.spec).ok());
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
            condition: c.condition.and_then(|cond| {
                serde_json::to_value(cond)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
            }),
            project: c.spec.project.clone(),
            ray_version: c.spec.ray_version.clone(),
            est_min_hourly: cost.map(|c| c.min_hourly),
            est_max_hourly: cost.map(|c| c.max_hourly),
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
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Read,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    match st.store.list().await {
        Ok(clusters) => {
            // Effective policy is store-backed and read per request, so
            // settings edits apply without a restart.
            let policy = match effective_policy(&st.store, &st.policy).await {
                Ok(p) => p.map(|p| config_from_stored(&p)).unwrap_or_default(),
                Err(e) => return store_err(e),
            };
            let prices = policy.prices.as_ref();
            let views: Vec<_> = clusters
                .into_iter()
                .map(|c| ClusterView::from_stored(c, prices))
                .collect();
            Json(views).into_response()
        }
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses((status = 200, description = "The cluster", body = ClusterView),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on cluster"),
              (status = 404, description = "No such cluster")),
    security(("bearer" = []))
)]
async fn get_cluster(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Read,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    match st.store.get(&ClusterId(id)).await {
        Ok(Some(c)) => {
            let policy = match effective_policy(&st.store, &st.policy).await {
                Ok(p) => p.map(|p| config_from_stored(&p)).unwrap_or_default(),
                Err(e) => return store_err(e),
            };
            Json(ClusterView::from_stored(c, policy.prices.as_ref())).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "no such cluster").into_response(),
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    post, path = "/api/v1/clusters", tag = "clusters",
    request_body = CreateCluster,
    responses(
        (status = 201, description = "Desired state recorded; reconciler will converge"),
        (status = 400, description = "Invalid spec (bad quantity, min>max)"),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Write on cluster (Operator/Admin only)"),
        (status = 409, description = "Project quota exceeded"),
        (status = 500, description = "Store/quota-accounting failure"),
    ),
    security(("bearer" = []))
)]
async fn create_cluster(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
    Json(body): Json<CreateCluster>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Write,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    let id = ClusterId(body.id);

    // Quota admission (Borg: quota is admission control). Only enforced for
    // projects with a configured limit; unconfigured projects are
    // unlimited in v0. Checked against max-demand of the project's other
    // live clusters plus this request. The effective limits come from the
    // store-backed policy (read per request — settings edits apply
    // immediately).
    let project = body.spec.project.clone();
    let policy = match effective_policy(&st.store, &st.policy).await {
        Ok(p) => p.map(|p| config_from_stored(&p)).unwrap_or_default(),
        Err(e) => return store_err(e),
    };
    // When a quota applies, serialize concurrent same-project creates by
    // holding a per-project lock across the whole read-check-write section
    // (list -> admit -> upsert) so the TOCTOU window can't over-admit (#44).
    // The guard is an OwnedMutexGuard so it stays alive past the `if let`,
    // covering the `upsert_desired` below; it drops at end of function.
    // Projects without a quota skip the lock entirely and stay concurrent.
    let _admit_guard = if let Some(limit) = policy.quotas.get(&project).cloned() {
        // Fetch-or-insert this project's lock (brief std::Mutex hold, never
        // across an await), then acquire it.
        let lock = {
            let mut locks = st.admit_locks.lock().unwrap();
            locks.entry(project.clone()).or_default().clone()
        };
        let guard = lock.lock_owned().await;
        let requested = match cluster_demand(&body.spec) {
            Ok((_, max)) => max,
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("invalid spec: {e}")).into_response()
            }
        };
        // Sum the project's other live clusters' max-demand. A stored spec
        // that fails to parse must FAIL CLOSED (error out), never contribute
        // zero — zeroing would undercount usage and admit past the limit
        // (review R2#2).
        let in_use = match st.store.list().await {
            Ok(clusters) => {
                let mut acc = ResourceMap::default();
                for c in clusters.iter().filter(|c| {
                    c.spec.project == project && c.id != id && c.desired == DesiredState::Running
                }) {
                    match cluster_demand(&c.spec) {
                        Ok((_, m)) => acc = acc + m,
                        Err(e) => {
                            tracing::error!(cluster = %c.id, error = %e, "unparseable stored spec blocks quota accounting");
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "quota accounting failed: an existing cluster has an invalid spec",
                            )
                                .into_response();
                        }
                    }
                }
                acc
            }
            Err(e) => return store_err(e),
        };
        if let Err(exceeded) = admit(&project, limit, in_use, requested) {
            emit(
                Some(&st.store),
                AuditEvent {
                    ts: now_unix(),
                    subject: ident(&identity).map(|i| i.subject.clone()),
                    decision: AuditDecision::Deny,
                    reason: Some("quota_exceeded".into()),
                    action: Some("create_cluster".into()),
                    cluster: Some(id.to_string()),
                    status: Some(StatusCode::CONFLICT.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            return (StatusCode::CONFLICT, exceeded.to_string()).into_response();
        }
        // Keep the lock held across the upsert below.
        Some(guard)
    } else {
        None
    };

    match st.store.upsert_desired(&id, body.spec).await {
        Ok(generation) => {
            emit(
                Some(&st.store),
                AuditEvent {
                    ts: now_unix(),
                    subject: ident(&identity).map(|i| i.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("create_cluster".into()),
                    cluster: Some(id.to_string()),
                    status: Some(StatusCode::CREATED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            // Pool admission (ADR-0010): resolve the project's Kueue queue
            // assignment from the allocations in the store and record it in
            // the audit log. The reconcile loop re-derives the assignment
            // from the store at apply time (the store is the transport, so
            // ClusterSpec's serialized form stays free of it); a project
            // with no allocation creates a queue-free cluster, unchanged
            // from before pools existed.
            match mobula_controller::queue_assignment_for_project(st.store.as_ref(), &project).await
            {
                Ok(Some(q)) => {
                    // The queue name/project aren't AuditEvent fields
                    // (api-v1.md §5.9); keep them in the trace stream.
                    tracing::info!(
                        target: "mobula::audit",
                        decision = "allow",
                        subject = ?ident(&identity).map(|i| i.subject.as_str()),
                        action = "queue_assign", cluster = %id, project = %project,
                        queue = %q.queue_name, elastic = q.elastic,
                        "cluster admitted to pool queue"
                    );
                    emit(
                        Some(&st.store),
                        AuditEvent {
                            ts: now_unix(),
                            subject: ident(&identity).map(|i| i.subject.clone()),
                            decision: AuditDecision::Allow,
                            action: Some("queue_assign".into()),
                            cluster: Some(id.to_string()),
                            ..Default::default()
                        },
                    )
                    .await;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(error = %e, cluster = %id, "queue assignment lookup failed")
                }
            }
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
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Write on cluster (Operator/Admin only)"),
              (status = 404, description = "No such cluster")),
    security(("bearer" = []))
)]
async fn delete_cluster(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Write,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    let id = ClusterId(id);
    // Desired = Terminated; the reconciler tears down the backing resources.
    match st.store.set_desired(&id, DesiredState::Terminated).await {
        Ok(()) => {
            emit(
                Some(&st.store),
                AuditEvent {
                    ts: now_unix(),
                    subject: ident(&identity).map(|i| i.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("delete_cluster".into()),
                    cluster: Some(id.to_string()),
                    status: Some(StatusCode::ACCEPTED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            StatusCode::ACCEPTED.into_response()
        }
        // Distinguish "not found" from a real store failure (review R3#6):
        // the store returns a Backend error naming the missing id vs a
        // genuine backend fault.
        Err(mobula_controller::StoreError::Backend(m)) if m.contains("no such cluster") => {
            (StatusCode::NOT_FOUND, "no such cluster").into_response()
        }
        Err(e) => store_err(e),
    }
}

/// A job in the persistent, cross-cluster history (Phase 3, spec §5.5).
#[derive(Serialize, ToSchema)]
pub struct JobView {
    pub id: String,
    pub cluster: String,
    pub submitter: String,
    /// Ray job status (PENDING | RUNNING | SUCCEEDED | FAILED | STOPPED).
    pub status: String,
    /// Wall-clock seconds once terminal; null while running.
    pub duration_secs: Option<u64>,
    pub submitted_at: u64,
}

impl From<mobula_core::JobRecord> for JobView {
    fn from(j: mobula_core::JobRecord) -> Self {
        Self {
            id: j.id,
            cluster: j.cluster,
            submitter: j.submitter,
            status: j.status,
            duration_secs: j.duration_secs,
            submitted_at: j.submitted_at,
        }
    }
}

#[utoipa::path(
    get, path = "/api/v1/jobs", tag = "jobs",
    responses((status = 200, description = "Persistent job history, newest first", body = [JobView]),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on job")),
    security(("bearer" = []))
)]
async fn list_jobs(
    State(st): State<ClusterApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Read,
        Target::Job,
    )
    .await
    {
        return deny;
    }
    match st.store.list_jobs().await {
        Ok(jobs) => Json(jobs.into_iter().map(JobView::from).collect::<Vec<_>>()).into_response(),
        Err(e) => store_err(e),
    }
}

pub fn router(store: Arc<dyn Store>, policy: Arc<PolicyConfig>) -> Router {
    Router::new()
        .route("/api/v1/clusters", get(list_clusters).post(create_cluster))
        .route(
            "/api/v1/clusters/{id}",
            get(get_cluster).delete(delete_cluster),
        )
        .route("/api/v1/jobs", get(list_jobs))
        .with_state(ClusterApiState {
            store,
            policy,
            admit_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
}
