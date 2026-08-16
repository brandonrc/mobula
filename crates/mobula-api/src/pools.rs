//! Capacity-pool API (ADR-0010, Slice 2). Pools are platform configuration
//! (flavors + cohort + per-project allocations), not app lifecycle, so
//! permissions are checked against `Target::Pool` per route: reads need
//! `Read` (Viewer+), mutations need `Write`/`Delete` — which only `Admin`
//! holds.
//!
//! Handlers only manipulate *desired* state in the [`Store`] (ADR-0004: the
//! store is truth); the pool reconcile loop in mobula-controller
//! (`PoolReconciler`) actuates the ResourceFlavor / ClusterQueue /
//! LocalQueue objects through Kueue and records status observations back
//! onto the pool rows.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, Target};
use mobula_controller::{now_unix, Store, StoreError, StoredPool};
use mobula_core::{AllocationSpec, AuditDecision, AuditEvent, FlavorSpec, PoolSpec};
use mobula_provision::PoolObservation;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::audit::emit;
use crate::auth_layer::authorize;

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

fn store_err(e: StoreError) -> Response {
    tracing::warn!(error = %e, "pool store error");
    (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
}

/// Request body for creating a pool.
#[derive(Deserialize, ToSchema)]
pub struct CreatePool {
    pub spec: PoolSpec,
}

/// A pool as the control plane serves it: the stored spec metadata plus
/// `total_nominal`, the per-resource sum of all flavors' nominal quotas.
#[derive(Serialize, ToSchema)]
pub struct PoolView {
    pub name: String,
    /// Bumps when the spec changes (same convention as clusters).
    pub generation: u64,
    pub created_at: u64,
    pub flavors: Vec<FlavorSpec>,
    pub cohort: String,
    pub fair_sharing_weight: f64,
    pub elastic: bool,
    /// Resource key → summed nominal quota across flavors, as a string.
    /// A resource key whose quantity fails to parse on ANY flavor is
    /// omitted entirely (a partial sum would misreport capacity); the
    /// failure is logged. Display math only — the spec stays authoritative.
    pub total_nominal: BTreeMap<String, String>,
}

/// Render a summed quantity back to a string: integral values without a
/// decimal point ("128"), fractional values as-is ("0.5").
fn format_quantity(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

impl PoolView {
    fn from_stored(p: StoredPool) -> Self {
        let mut sums: BTreeMap<String, f64> = BTreeMap::new();
        let mut unparseable: BTreeSet<String> = BTreeSet::new();
        for f in &p.spec.flavors {
            for (k, v) in &f.resources {
                match mobula_policy::quantity::parse_quantity(v) {
                    Ok(q) => *sums.entry(k.clone()).or_insert(0.0) += q,
                    Err(e) => {
                        // Fail-soft: pools are admin-managed config, so a bad
                        // quantity omits the key from the display sum (unlike
                        // cluster quota accounting, which fails closed).
                        tracing::warn!(
                            pool = %p.name, flavor = %f.name, resource = %k, error = %e,
                            "unparseable flavor quantity omitted from total_nominal"
                        );
                        unparseable.insert(k.clone());
                    }
                }
            }
        }
        let total_nominal = sums
            .into_iter()
            .filter(|(k, _)| !unparseable.contains(k))
            .map(|(k, v)| (k, format_quantity(v)))
            .collect();
        Self {
            name: p.name,
            generation: p.generation,
            created_at: p.created_at,
            flavors: p.spec.flavors,
            cohort: p.spec.cohort,
            fair_sharing_weight: p.spec.fair_sharing_weight,
            elastic: p.spec.elastic,
            total_nominal,
        }
    }
}

/// Every resource quantity in the spec must parse (core validates shape,
/// never quantity syntax — parseability is checked here, at the edge).
fn validate_quantities(spec: &PoolSpec) -> Result<(), String> {
    for f in &spec.flavors {
        for (k, v) in &f.resources {
            mobula_policy::quantity::parse_quantity(v)
                .map_err(|e| format!("flavor {} resource {k}: {e}", f.name))?;
        }
    }
    Ok(())
}

/// Request body for putting an allocation: `AllocationSpec` minus
/// `pool`/`project`, which come from the path. If the body still carries
/// them, they must match the path or the request is rejected.
#[derive(Deserialize, ToSchema)]
pub struct PutAllocation {
    pub pool: Option<String>,
    pub project: Option<String>,
    pub namespace: String,
    pub nominal: BTreeMap<String, String>,
    pub borrowing_limit: BTreeMap<String, String>,
    pub lending_limit: BTreeMap<String, String>,
}

#[utoipa::path(
    get, path = "/api/v1/pools", tag = "pools",
    responses((status = 200, description = "All capacity pools", body = [PoolView]),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on pool")),
    security(("bearer" = []))
)]
async fn list_pools(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Read,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    match st.list_pools().await {
        Ok(pools) => Json(
            pools
                .into_iter()
                .map(PoolView::from_stored)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    post, path = "/api/v1/pools", tag = "pools",
    request_body = CreatePool,
    responses(
        (status = 201, description = "Pool created"),
        (status = 400, description = "Invalid spec (bad name, no flavors, unparseable quantity)"),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Write on pool (Admin only)"),
        (status = 409, description = "Pool already exists (create-only in v0; spec update lands with a later PATCH)"),
    ),
    security(("bearer" = []))
)]
async fn create_pool(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
    Json(body): Json<CreatePool>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Write,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    if let Err(e) = body.spec.validate() {
        return (StatusCode::BAD_REQUEST, format!("invalid spec: {e}")).into_response();
    }
    if let Err(e) = validate_quantities(&body.spec) {
        return (StatusCode::BAD_REQUEST, format!("invalid spec: {e}")).into_response();
    }
    let name = body.spec.name.clone();
    // Create-only in v0: upsert-with-bump is for updates via a later PATCH.
    match st.get_pool(&name).await {
        Ok(Some(_)) => {
            return (StatusCode::CONFLICT, format!("pool {name} already exists")).into_response()
        }
        Ok(None) => {}
        Err(e) => return store_err(e),
    }
    match st.upsert_pool(&name, body.spec).await {
        Ok(generation) => {
            // The pool name isn't an AuditEvent field (api-v1.md §5.9);
            // the action string carries the pool scope.
            emit(
                Some(&st),
                AuditEvent {
                    ts: now_unix(),
                    subject: ident(&identity).map(|i| i.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("create_pool".into()),
                    status: Some(StatusCode::CREATED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "name": name, "generation": generation })),
            )
                .into_response()
        }
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    get, path = "/api/v1/pools/{name}", tag = "pools",
    params(("name" = String, Path, description = "Pool name")),
    responses((status = 200, description = "The pool", body = PoolView),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on pool"),
              (status = 404, description = "No such pool")),
    security(("bearer" = []))
)]
async fn get_pool(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Read,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    match st.get_pool(&name).await {
        Ok(Some(p)) => Json(PoolView::from_stored(p)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no such pool").into_response(),
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    delete, path = "/api/v1/pools/{name}", tag = "pools",
    params(("name" = String, Path, description = "Pool name")),
    responses((status = 202, description = "Pool deleted"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Delete on pool (Admin only)"),
              (status = 404, description = "No such pool")),
    security(("bearer" = []))
)]
async fn delete_pool(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Delete,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    match st.delete_pool(&name).await {
        Ok(()) => {
            emit(
                Some(&st),
                AuditEvent {
                    ts: now_unix(),
                    subject: ident(&identity).map(|i| i.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("delete_pool".into()),
                    status: Some(StatusCode::ACCEPTED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            StatusCode::ACCEPTED.into_response()
        }
        // Mirror delete_cluster: the store distinguishes "not found" from a
        // genuine backend fault by naming the missing pool.
        Err(StoreError::Backend(m)) if m.contains("no such pool") => {
            (StatusCode::NOT_FOUND, "no such pool").into_response()
        }
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    put, path = "/api/v1/pools/{name}/allocations/{project}", tag = "pools",
    params(
        ("name" = String, Path, description = "Pool name"),
        ("project" = String, Path, description = "Project name"),
    ),
    request_body = PutAllocation,
    responses(
        (status = 200, description = "Allocation recorded"),
        (status = 400, description = "Invalid allocation, or body pool/project mismatches the path"),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Missing Write on pool (Admin only)"),
        (status = 404, description = "No such pool"),
    ),
    security(("bearer" = []))
)]
async fn put_allocation(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
    Path((name, project)): Path<(String, String)>,
    Json(body): Json<PutAllocation>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Write,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    // Path params win; a contradicting body is a client error.
    if body.pool.as_deref().is_some_and(|p| p != name)
        || body.project.as_deref().is_some_and(|p| p != project)
    {
        return (
            StatusCode::BAD_REQUEST,
            "body pool/project must match the path (or be omitted)",
        )
            .into_response();
    }
    match st.get_pool(&name).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "no such pool").into_response(),
        Err(e) => return store_err(e),
    }
    let alloc = AllocationSpec {
        pool: name.clone(),
        project: project.clone(),
        namespace: body.namespace,
        nominal: body.nominal,
        borrowing_limit: body.borrowing_limit,
        lending_limit: body.lending_limit,
    };
    if let Err(e) = alloc.validate() {
        return (StatusCode::BAD_REQUEST, format!("invalid allocation: {e}")).into_response();
    }
    match st.upsert_allocation(alloc).await {
        Ok(()) => {
            emit(
                Some(&st),
                AuditEvent {
                    ts: now_unix(),
                    subject: ident(&identity).map(|i| i.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("put_allocation".into()),
                    status: Some(StatusCode::OK.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            Json(serde_json::json!({ "pool": name, "project": project })).into_response()
        }
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    get, path = "/api/v1/pools/{name}/allocations", tag = "pools",
    params(("name" = String, Path, description = "Pool name")),
    responses((status = 200, description = "The pool's allocations", body = [AllocationSpec]),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on pool")),
    security(("bearer" = []))
)]
async fn list_allocations(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Read,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    match st.list_allocations(&name).await {
        Ok(allocs) => Json(allocs).into_response(),
        Err(e) => store_err(e),
    }
}

#[utoipa::path(
    delete, path = "/api/v1/pools/{name}/allocations/{project}", tag = "pools",
    params(
        ("name" = String, Path, description = "Pool name"),
        ("project" = String, Path, description = "Project name"),
    ),
    responses((status = 202, description = "Allocation deleted"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Delete on pool (Admin only)"),
              (status = 404, description = "No such allocation")),
    security(("bearer" = []))
)]
async fn delete_allocation(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
    Path((name, project)): Path<(String, String)>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Delete,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    match st.delete_allocation(&name, &project).await {
        Ok(()) => {
            emit(
                Some(&st),
                AuditEvent {
                    ts: now_unix(),
                    subject: ident(&identity).map(|i| i.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("delete_allocation".into()),
                    status: Some(StatusCode::ACCEPTED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            StatusCode::ACCEPTED.into_response()
        }
        Err(StoreError::Backend(m)) if m.contains("no such allocation") => {
            (StatusCode::NOT_FOUND, "no such allocation").into_response()
        }
        Err(e) => store_err(e),
    }
}

/// One resource's live utilization within a pool: `allocated` is the Kueue
/// reservation-ledger total (summed across flavors from the latest
/// ClusterQueue observation), `nominal` the summed flavor quotas from the
/// spec, `pct` = allocated / nominal × 100 (0 when nominal is 0 — a
/// percentage of nothing is undefined, and 0 keeps the type non-optional).
#[derive(Serialize, ToSchema)]
pub struct ResourceUtilization {
    pub allocated: f64,
    pub nominal: f64,
    pub pct: f64,
}

/// Live point-in-time usage of one pool (Slice 4): built from the pool's
/// latest stored ClusterQueue/LocalQueue observation plus the spec's
/// nominal quotas. NOT a timeseries — for history use `GET /api/v1/usage`.
/// `projects` is the per-LocalQueue (per-project) attribution; empty when
/// the observation predates per-LQ status or none exists.
#[derive(Serialize, ToSchema)]
pub struct PoolUsageView {
    pub pool: String,
    /// When the observation was recorded (unix seconds); `null` until the
    /// pool reconcile loop has observed this pool.
    pub sampled_at: Option<u64>,
    pub utilization: BTreeMap<String, ResourceUtilization>,
    /// project → resource → allocated quantity.
    pub projects: BTreeMap<String, BTreeMap<String, f64>>,
}

/// Sum a quantity-string map into f64, skipping unparseable values with a
/// warning (fail-soft display math, same convention as `PoolView`).
fn sum_quantities(
    pool: &str,
    origin: &str,
    resources: &BTreeMap<String, String>,
    into: &mut BTreeMap<String, f64>,
) {
    for (k, v) in resources {
        match mobula_policy::quantity::parse_quantity(v) {
            Ok(q) => *into.entry(k.clone()).or_insert(0.0) += q,
            Err(e) => tracing::warn!(
                pool = %pool, origin = %origin, resource = %k, error = %e,
                "unparseable usage quantity omitted"
            ),
        }
    }
}

#[utoipa::path(
    get, path = "/api/v1/pools/{name}/usage", tag = "pools",
    params(("name" = String, Path, description = "Pool name")),
    responses((status = 200, description = "Live pool utilization (latest observation)", body = PoolUsageView),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on pool"),
              (status = 404, description = "No such pool")),
    security(("bearer" = []))
)]
async fn pool_usage(
    State(st): State<Arc<dyn Store>>,
    identity: Option<Extension<Identity>>,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st),
        ident(&identity),
        PermissionType::Read,
        Target::Pool,
    )
    .await
    {
        return deny;
    }
    let p = match st.get_pool(&name).await {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such pool").into_response(),
        Err(e) => return store_err(e),
    };

    // Allocated: the latest observation's flavorsUsage summed across flavors
    // (Kueue's reservation ledger, ADR-0010's documented divergence — this
    // is what was admitted, not measured consumption). projects: per-LQ
    // attribution from LocalQueue statuses.
    let mut allocated: BTreeMap<String, f64> = BTreeMap::new();
    let mut projects: BTreeMap<String, BTreeMap<String, f64>> = BTreeMap::new();
    if let Some(json) = &p.observed_json {
        match serde_json::from_str::<PoolObservation>(json) {
            Ok(obs) => {
                for (flavor, resources) in &obs.flavors_usage {
                    sum_quantities(&name, flavor, resources, &mut allocated);
                }
                for (lq, resources) in &obs.queues_usage {
                    let mut per_project = BTreeMap::new();
                    sum_quantities(&name, lq, resources, &mut per_project);
                    projects.insert(lq.clone(), per_project);
                }
            }
            Err(e) => {
                tracing::warn!(pool = %name, error = %e, "stored pool observation did not parse; treating as unobserved")
            }
        }
    }

    // Nominal: summed flavor quotas from the spec. A key unparseable on ANY
    // flavor is omitted (a partial sum would misreport capacity) — same rule
    // as PoolView::total_nominal.
    let mut nominal: BTreeMap<String, f64> = BTreeMap::new();
    let mut unparseable: BTreeSet<String> = BTreeSet::new();
    for f in &p.spec.flavors {
        for (k, v) in &f.resources {
            match mobula_policy::quantity::parse_quantity(v) {
                Ok(q) => *nominal.entry(k.clone()).or_insert(0.0) += q,
                Err(e) => {
                    tracing::warn!(pool = %name, flavor = %f.name, resource = %k, error = %e, "unparseable flavor quantity omitted from nominal");
                    unparseable.insert(k.clone());
                }
            }
        }
    }
    // Utilization keyed by the union of allocated and nominal resource keys.
    let keys: BTreeSet<String> = nominal
        .keys()
        .filter(|k| !unparseable.contains(*k))
        .chain(allocated.keys())
        .cloned()
        .collect();
    let utilization = keys
        .into_iter()
        .map(|k| {
            let a = allocated.get(&k).copied().unwrap_or(0.0);
            let n = nominal.get(&k).copied().unwrap_or(0.0);
            (
                k,
                ResourceUtilization {
                    allocated: a,
                    nominal: n,
                    pct: if n > 0.0 { a / n * 100.0 } else { 0.0 },
                },
            )
        })
        .collect();

    Json(PoolUsageView {
        pool: name,
        sampled_at: p.observed_at,
        utilization,
        projects,
    })
    .into_response()
}

pub fn router(store: Arc<dyn Store>) -> Router {
    Router::new()
        .route("/api/v1/pools", get(list_pools).post(create_pool))
        .route("/api/v1/pools/{name}", get(get_pool).delete(delete_pool))
        .route("/api/v1/pools/{name}/usage", get(pool_usage))
        .route("/api/v1/pools/{name}/allocations", get(list_allocations))
        .route(
            "/api/v1/pools/{name}/allocations/{project}",
            axum::routing::put(put_allocation).delete(delete_allocation),
        )
        .with_state(store)
}
