//! Usage reporting API (Slice 4): the timeseries read path for the samples
//! the metering loop (`mobula_controller::Metering`) appends, plus a
//! Prometheus text-format gauge for scraping.
//!
//! `GET /api/v1/usage` is consumption *reporting*, not pool topology, so it
//! checks `Read` on `Target::Cluster` (Viewer+) — the same permission as
//! reading cluster costs — rather than `Target::Pool`. The choice is
//! deliberate and documented here. The metrics endpoint shares it: usage
//! data is no more sensitive than the report API, and scrape tokens are just
//! Bearer JWTs.
//!
//! Aggregation semantics live in `mobula_policy::usage` (step function with
//! carry-in). Grouping is by (`project`, `pool`); the pool-level aggregate
//! rows the Kueue path writes carry `project = ""` and OVERLAP the
//! per-project rows — consumers must not sum across project boundaries.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, Target};
use mobula_controller::{now_unix, Store};
use mobula_policy::ResourceMap;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth_layer::authorize;
use crate::clusters::PolicyConfig;
use crate::settings::{config_from_stored, effective_policy};

#[derive(Clone)]
pub struct UsageApiState {
    pub store: Arc<dyn Store>,
    /// Boot-time policy seed (`--policy` file), NOT the effective policy:
    /// the cost roll-up loads the effective (store-backed) price sheet per
    /// request via [`effective_policy`].
    pub policy: Arc<PolicyConfig>,
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

fn store_err(e: mobula_controller::StoreError) -> Response {
    tracing::warn!(error = %e, "usage store error");
    (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
}

/// A project's cumulative windowed consumption in resource-hours (#77),
/// computed from the metering `usage_samples` the [`mobula_controller::Metering`]
/// loop persists. Samples are read from `0` (not `from`) so a reading before
/// the window sets the level entering it (carry-in — see
/// [`mobula_policy::usage::resource_hours`]), then grouped by `(pool,
/// resource)` and integrated over `[from, to]`.
///
/// Shared by budget admission (`clusters.rs`) and the usage report so the two
/// never drift. Pool-aggregate rows (`project = ""`) are excluded by the
/// `Some(project)` filter, so there is no double counting.
pub(crate) async fn windowed_consumption(
    store: &Arc<dyn Store>,
    project: &str,
    from: u64,
    to: u64,
) -> Result<ResourceMap, mobula_controller::StoreError> {
    let samples = store.usage_samples(Some(project), None, 0, to).await?;
    let mut by_pool_resource: BTreeMap<(String, String), Vec<(u64, f64)>> = BTreeMap::new();
    for s in samples {
        by_pool_resource
            .entry((s.pool, s.resource))
            .or_default()
            .push((s.ts, s.quantity));
    }
    Ok(mobula_policy::usage::windowed_resource_hours(
        &by_pool_resource,
        from,
        to,
    ))
}

/// Query for `GET /api/v1/usage`. `to` defaults to now, `from` to
/// `to - 86400` (last 24h).
#[derive(Deserialize, IntoParams)]
pub struct UsageQuery {
    /// Filter to one project.
    pub project: Option<String>,
    /// Filter to one pool.
    pub pool: Option<String>,
    /// Window start, unix seconds (default: `to - 86400`).
    pub from: Option<u64>,
    /// Window end, unix seconds (default: now).
    pub to: Option<u64>,
}

/// One (project, pool) group of the usage report.
#[derive(Serialize, ToSchema)]
pub struct UsageGroup {
    /// Empty string = the pool-level aggregate row (Kueue path only).
    pub project: String,
    /// Empty string = the project has no allocation.
    pub pool: String,
    /// resource → resource-hours over the window.
    pub resource_hours: BTreeMap<String, f64>,
    /// Total cost in USD; `null` when no price sheet is configured.
    pub cost_usd: Option<f64>,
}

/// A configured project's time-windowed budget status (#77): the cap, what
/// has been consumed over the trailing window (ending at the report's `to`),
/// and what remains. Distinct from `UsageGroup` — this reflects the
/// `[budgets]` policy, not the raw sample roll-up.
#[derive(Serialize, ToSchema)]
pub struct BudgetStatus {
    pub project: String,
    /// Trailing window length in seconds.
    pub window_secs: u64,
    /// resource → resource-hours allowed over the window.
    pub limit: BTreeMap<String, f64>,
    /// resource → resource-hours consumed over the trailing window.
    pub consumed: BTreeMap<String, f64>,
    /// resource → resource-hours remaining (`limit − consumed`, floored at 0)
    /// for each capped resource.
    pub remaining: BTreeMap<String, f64>,
    /// True once consumption has reached or passed the cap on any capped
    /// resource — a create for this project would be 409'd.
    pub exhausted: bool,
}

/// Response of `GET /api/v1/usage`.
#[derive(Serialize, ToSchema)]
pub struct UsageReport {
    pub from: u64,
    pub to: u64,
    pub groups: Vec<UsageGroup>,
    /// Time-windowed budget status per configured project (#77). Empty when
    /// no `[budgets]` are configured. When the report is filtered to one
    /// `project`, only that project's budget appears.
    pub budgets: Vec<BudgetStatus>,
}

#[utoipa::path(
    get, path = "/api/v1/usage", tag = "usage",
    params(UsageQuery),
    responses((status = 200, description = "Resource-hours (and cost when priced) by project and pool", body = UsageReport),
              (status = 400, description = "from must be before to"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on cluster")),
    security(("bearer" = []))
)]
async fn usage_report(
    State(st): State<UsageApiState>,
    identity: Option<Extension<Identity>>,
    Query(q): Query<UsageQuery>,
) -> Response {
    // Consumption reporting reads like cluster data, not pool topology.
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
    let to = q.to.unwrap_or_else(now_unix);
    let from = q.from.unwrap_or_else(|| to.saturating_sub(86_400));
    if from >= to {
        return (StatusCode::BAD_REQUEST, "from must be before to").into_response();
    }

    // Query from 0, not `from`: a sample BEFORE the window sets the level
    // entering it (carry-in — see mobula_policy::usage::resource_hours).
    let samples = match st
        .store
        .usage_samples(q.project.as_deref(), q.pool.as_deref(), 0, to)
        .await
    {
        Ok(s) => s,
        Err(e) => return store_err(e),
    };

    // (project, pool) → resource → (ts, qty) series.
    type Grouped = BTreeMap<(String, String), BTreeMap<String, Vec<(u64, f64)>>>;
    let mut grouped: Grouped = BTreeMap::new();
    for s in samples {
        grouped
            .entry((s.project, s.pool))
            .or_default()
            .entry(s.resource)
            .or_default()
            .push((s.ts, s.quantity));
    }

    // The effective price sheet is store-backed, read per request, so a
    // settings edit applies to the very next report.
    let policy = match effective_policy(&st.store, &st.policy).await {
        Ok(p) => p.map(|p| config_from_stored(&p)).unwrap_or_default(),
        Err(e) => return store_err(e),
    };
    let groups = grouped
        .into_iter()
        .map(|((project, pool), by_resource)| {
            let resource_hours: BTreeMap<String, f64> = by_resource
                .into_iter()
                .map(|(r, pts)| (r, mobula_policy::usage::resource_hours(&pts, from, to)))
                .collect();
            let cost_usd = policy.prices.as_ref().map(|sheet| {
                mobula_policy::usage::cost(
                    &ResourceMap(resource_hours.clone().into_iter().collect()),
                    sheet,
                )
            });
            UsageGroup {
                project,
                pool,
                resource_hours,
                cost_usd,
            }
        })
        .collect();

    // Budget status (#77): for each configured project (filtered to
    // `q.project` when set), compute consumption over the budget's OWN
    // trailing window ending at `to` — independent of the report's from/to,
    // which the client controls freely.
    let mut budgets = Vec::new();
    let mut budget_projects: Vec<_> = policy.budgets.keys().cloned().collect();
    budget_projects.sort();
    for bp in budget_projects {
        if let Some(filter) = q.project.as_deref() {
            if filter != bp {
                continue;
            }
        }
        let budget = &policy.budgets[&bp];
        let b_from = to.saturating_sub(budget.window_secs);
        let consumed = match windowed_consumption(&st.store, &bp, b_from, to).await {
            Ok(c) => c,
            Err(e) => return store_err(e),
        };
        let remaining: BTreeMap<String, f64> = budget
            .limits
            .iter()
            .map(|(r, cap)| {
                let used = consumed.0.get(r).copied().unwrap_or(0.0);
                (r.clone(), (cap - used).max(0.0))
            })
            .collect();
        let exhausted = mobula_policy::admit_budget(&bp, budget, &consumed).is_err();
        budgets.push(BudgetStatus {
            project: bp,
            window_secs: budget.window_secs,
            limit: budget.limits.clone(),
            consumed: consumed.0,
            remaining,
            exhausted,
        });
    }

    Json(UsageReport {
        from,
        to,
        groups,
        budgets,
    })
    .into_response()
}

/// Escape a Prometheus label value (`\`, `"`, newline).
fn prom_escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Label value for a cluster's observed state. `ClusterState` serializes
/// snake_case; reuse the serde mapping instead of a parallel match that
/// could drift from the enum.
fn state_label(s: mobula_core::ClusterState) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// Render cluster-fleet gauges from the store at scrape time (#52):
/// `mobula_clusters_total{state}` counts by observed state (`unknown` until
/// the reconcile engine's first observation lands) and
/// `mobula_clusters_by_project{project}` counts per spec project. Both
/// reflect the store as it is — Terminated rows count until the store reaps
/// them.
fn render_cluster_gauges(clusters: &[mobula_controller::StoredCluster]) -> String {
    use std::fmt::Write;
    let mut by_state: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_project: BTreeMap<&str, u64> = BTreeMap::new();
    for c in clusters {
        let state = c
            .observed_state
            .map(state_label)
            .unwrap_or_else(|| "unknown".into());
        *by_state.entry(state).or_insert(0) += 1;
        *by_project.entry(c.spec.project.as_str()).or_insert(0) += 1;
    }
    let mut out = String::from(
        "# HELP mobula_clusters_total Managed clusters by observed state \
         ('unknown' before the reconcile engine's first observation).\n\
         # TYPE mobula_clusters_total gauge\n",
    );
    for (state, n) in by_state {
        let _ = writeln!(
            out,
            "mobula_clusters_total{{state=\"{}\"}} {}",
            prom_escape(&state),
            n
        );
    }
    let _ = write!(
        out,
        "# HELP mobula_clusters_by_project Managed clusters per project.\n\
         # TYPE mobula_clusters_by_project gauge\n"
    );
    for (project, n) in by_project {
        let _ = writeln!(
            out,
            "mobula_clusters_by_project{{project=\"{}\"}} {}",
            prom_escape(project),
            n
        );
    }
    out
}

/// Render `mobula_pool_nominal{pool,resource}` (#52): each pool's nominal
/// quota, summed across flavors with `parse_quantity` — the same math as
/// `pools::PoolView::total_nominal`, including its fail-soft policy: a
/// resource key that fails to parse on ANY flavor is omitted entirely (a
/// partial sum would misreport capacity) and logged.
fn render_pool_nominal_gauge(pools: &[mobula_controller::StoredPool]) -> String {
    use std::fmt::Write;
    let mut out = String::from(
        "# HELP mobula_pool_nominal Pool nominal quota per resource, summed \
         across the pool's flavor specs.\n\
         # TYPE mobula_pool_nominal gauge\n",
    );
    for p in pools {
        let mut sums: BTreeMap<&str, f64> = BTreeMap::new();
        let mut unparseable: std::collections::BTreeSet<&str> = Default::default();
        for f in &p.spec.flavors {
            for (k, v) in &f.resources {
                match mobula_policy::quantity::parse_quantity(v) {
                    Ok(q) => *sums.entry(k.as_str()).or_insert(0.0) += q,
                    Err(e) => {
                        tracing::warn!(
                            pool = %p.name, flavor = %f.name, resource = %k, error = %e,
                            "unparseable flavor quantity omitted from mobula_pool_nominal"
                        );
                        unparseable.insert(k.as_str());
                    }
                }
            }
        }
        for (k, total) in sums {
            if unparseable.contains(k) {
                continue;
            }
            let _ = writeln!(
                out,
                "mobula_pool_nominal{{pool=\"{}\",resource=\"{}\"}} {}",
                prom_escape(&p.name),
                prom_escape(k),
                total
            );
        }
    }
    out
}

/// Render the latest usage sample per (pool, project, resource) as
/// Prometheus text exposition. Hand-rolled on purpose: the workspace has no
/// metrics dependency, the text format for one gauge is a dozen lines, and
/// `deny.toml` keeps dependency additions deliberate — adding the
/// `prometheus` crate for one gauge is not worth the supply-chain weight.
fn render_usage_gauge(samples: &[mobula_controller::UsageSample]) -> String {
    use std::fmt::Write;
    // Latest sample per label set (samples arrive ts-ordered; last wins).
    let mut latest: BTreeMap<(&str, &str, &str), f64> = BTreeMap::new();
    for s in samples {
        latest.insert((&s.pool, &s.project, &s.resource), s.quantity);
    }
    let mut out = String::from(
        "# HELP mobula_pool_resource_usage Latest metered resource usage \
         (Kueue reservation ledger or observed-spec estimate).\n\
         # TYPE mobula_pool_resource_usage gauge\n",
    );
    for ((pool, project, resource), qty) in latest {
        let _ = writeln!(
            out,
            "mobula_pool_resource_usage{{pool=\"{}\",project=\"{}\",resource=\"{}\"}} {}",
            prom_escape(pool),
            prom_escape(project),
            prom_escape(resource),
            qty
        );
    }
    out
}

#[utoipa::path(
    get, path = "/api/v1/metrics", tag = "usage",
    responses((status = 200, description = "Prometheus text exposition of usage and control-plane gauges", body = String, content_type = "text/plain"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on cluster")),
    security(("bearer" = []))
)]
async fn metrics(
    State(st): State<UsageApiState>,
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
    let samples = match st.store.usage_samples(None, None, 0, now_unix()).await {
        Ok(s) => s,
        Err(e) => return store_err(e),
    };
    // Control-plane gauges (#52): cluster fleet and pool capacity, computed
    // from the store at scrape time — no sampling loop involved.
    let clusters = match st.store.list().await {
        Ok(c) => c,
        Err(e) => return store_err(e),
    };
    let pools = match st.store.list_pools().await {
        Ok(p) => p,
        Err(e) => return store_err(e),
    };
    let text = format!(
        "{}{}{}",
        render_usage_gauge(&samples),
        render_cluster_gauges(&clusters),
        render_pool_nominal_gauge(&pools)
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        text,
    )
        .into_response()
}

pub fn router(store: Arc<dyn Store>, policy: Arc<PolicyConfig>) -> Router {
    Router::new()
        .route("/api/v1/usage", get(usage_report))
        .route("/api/v1/metrics", get(metrics))
        .with_state(UsageApiState { store, policy })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_controller::{DesiredState, StoredCluster, StoredPool, UsageSample, UsageSource};

    fn sample(ts: u64, pool: &str, project: &str, resource: &str, qty: f64) -> UsageSample {
        UsageSample {
            ts,
            project: project.into(),
            pool: pool.into(),
            resource: resource.into(),
            quantity: qty,
            source: UsageSource::ObservedSpec,
        }
    }

    #[test]
    fn gauge_renders_latest_sample_per_label_set() {
        let text = render_usage_gauge(&[
            sample(100, "gpu", "proj-a", "cpu", 4.0),
            sample(200, "gpu", "proj-a", "cpu", 8.0), // newer wins
            sample(150, "gpu", "", "cpu", 16.0),
        ]);
        assert!(text.contains("# TYPE mobula_pool_resource_usage gauge"));
        assert!(text.contains(
            "mobula_pool_resource_usage{pool=\"gpu\",project=\"proj-a\",resource=\"cpu\"} 8"
        ));
        assert!(text
            .contains("mobula_pool_resource_usage{pool=\"gpu\",project=\"\",resource=\"cpu\"} 16"));
        assert_eq!(
            text.matches("proj-a").count(),
            1,
            "stale sample overwritten"
        );
    }

    #[test]
    fn gauge_escapes_label_values() {
        assert_eq!(prom_escape("a\"b\nc\\d"), "a\\\"b\\nc\\\\d");
    }

    #[test]
    fn gauge_empty_when_no_samples() {
        let text = render_usage_gauge(&[]);
        assert!(text.contains("# HELP"));
        assert!(!text.contains("mobula_pool_resource_usage{"));
    }

    fn stored_cluster(project: &str, observed: Option<mobula_core::ClusterState>) -> StoredCluster {
        StoredCluster {
            id: mobula_core::ClusterId(format!("c-{}", project.len())),
            spec: mobula_core::ClusterSpec {
                engine: Default::default(),
                name: "c".into(),
                project: project.into(),
                ray_version: "2.57.0".into(),
                image: "img".into(),
                head_cpu: "1".into(),
                head_memory: "2Gi".into(),
                worker_groups: vec![],
                ttl_seconds: None,
                idle_timeout_secs: None,
                owner: None,
            },
            generation: 1,
            desired: DesiredState::Running,
            observed_state: observed,
            observed_generation: 0,
            condition: None,
            failure_count: 0,
            next_attempt_at: 0,
            created_at: 0,
            terminated_at: None,
        }
    }

    #[test]
    fn cluster_gauges_count_by_state_and_project() {
        use mobula_core::ClusterState;
        let text = render_cluster_gauges(&[
            stored_cluster("proj-a", Some(ClusterState::Running)),
            stored_cluster("proj-a", Some(ClusterState::Suspended)),
            stored_cluster("proj-b", None),
        ]);
        assert!(text.contains("# TYPE mobula_clusters_total gauge"));
        assert!(text.contains("mobula_clusters_total{state=\"running\"} 1"));
        assert!(text.contains("mobula_clusters_total{state=\"suspended\"} 1"));
        assert!(
            text.contains("mobula_clusters_total{state=\"unknown\"} 1"),
            "unobserved clusters count as unknown: {text}"
        );
        assert!(text.contains("# TYPE mobula_clusters_by_project gauge"));
        assert!(text.contains("mobula_clusters_by_project{project=\"proj-a\"} 2"));
        assert!(text.contains("mobula_clusters_by_project{project=\"proj-b\"} 1"));
    }

    #[test]
    fn pool_nominal_gauge_sums_flavors_and_omits_unparseable() {
        let pool = |name: &str, resources: BTreeMap<String, String>| StoredPool {
            name: name.into(),
            spec: mobula_core::PoolSpec {
                name: name.into(),
                flavors: vec![mobula_core::FlavorSpec {
                    name: "f".into(),
                    resources,
                    node_labels: BTreeMap::new(),
                    taints: vec![],
                }],
                cohort: "c".into(),
                fair_sharing_weight: 1.0,
                elastic: false,
                gpu_sharing: None,
            },
            generation: 1,
            observed_json: None,
            observed_at: None,
            created_at: 0,
        };
        let text = render_pool_nominal_gauge(&[
            pool(
                "gpu",
                BTreeMap::from([
                    ("cpu".to_string(), "64".to_string()),
                    ("memory".to_string(), "256Gi".to_string()),
                ]),
            ),
            pool(
                "bad",
                BTreeMap::from([("cpu".to_string(), "not-a-quantity".to_string())]),
            ),
        ]);
        assert!(text.contains("# TYPE mobula_pool_nominal gauge"));
        assert!(text.contains("mobula_pool_nominal{pool=\"gpu\",resource=\"cpu\"} 64"));
        let gib = 256.0 * 1024.0 * 1024.0 * 1024.0;
        assert!(
            text.contains(&format!(
                "mobula_pool_nominal{{pool=\"gpu\",resource=\"memory\"}} {gib}"
            )),
            "{text}"
        );
        assert!(
            !text.contains("pool=\"bad\""),
            "unparseable quantity omits the resource: {text}"
        );
    }
}
