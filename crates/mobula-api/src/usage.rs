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

#[derive(Clone)]
pub struct UsageApiState {
    pub store: Arc<dyn Store>,
    pub policy: Arc<PolicyConfig>,
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

fn store_err(e: mobula_controller::StoreError) -> Response {
    tracing::warn!(error = %e, "usage store error");
    (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
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

/// Response of `GET /api/v1/usage`.
#[derive(Serialize, ToSchema)]
pub struct UsageReport {
    pub from: u64,
    pub to: u64,
    pub groups: Vec<UsageGroup>,
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
    if let Some(deny) = authorize(ident(&identity), PermissionType::Read, Target::Cluster) {
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

    let groups = grouped
        .into_iter()
        .map(|((project, pool), by_resource)| {
            let resource_hours: BTreeMap<String, f64> = by_resource
                .into_iter()
                .map(|(r, pts)| (r, mobula_policy::usage::resource_hours(&pts, from, to)))
                .collect();
            let cost_usd = st.policy.prices.as_ref().map(|sheet| {
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

    Json(UsageReport { from, to, groups }).into_response()
}

/// Escape a Prometheus label value (`\`, `"`, newline).
fn prom_escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
    responses((status = 200, description = "Prometheus text exposition of usage gauges", body = String, content_type = "text/plain"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on cluster")),
    security(("bearer" = []))
)]
async fn metrics(
    State(st): State<UsageApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    if let Some(deny) = authorize(ident(&identity), PermissionType::Read, Target::Cluster) {
        return deny;
    }
    let samples = match st.store.usage_samples(None, None, 0, now_unix()).await {
        Ok(s) => s,
        Err(e) => return store_err(e),
    };
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        render_usage_gauge(&samples),
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
    use mobula_controller::{UsageSample, UsageSource};

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
}
