//! Usage API tests (Slice 4): the `/api/v1/usage` timeseries report, the
//! `/api/v1/pools/{name}/usage` live view, and the Prometheus gauge —
//! including RBAC tripwires (Viewer can read all three).

mod common;
use common::{authed_app_with_policy, authed_app_with_store, get, idp_token, spawn_idp};

use axum::http::StatusCode;
use mobula_controller::{InMemoryStore, Store, UsageSample, UsageSource};
use mobula_core::{AllocationSpec, PoolSpec};
use mobula_policy::PriceSheet;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tower::ServiceExt;

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_text(res: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn sample(ts: u64, project: &str, pool: &str, resource: &str, qty: f64) -> UsageSample {
    UsageSample {
        ts,
        project: project.into(),
        pool: pool.into(),
        resource: resource.into(),
        quantity: qty,
        source: UsageSource::KueueLedger,
    }
}

fn priced_policy() -> mobula_api::clusters::PolicyConfig {
    mobula_api::clusters::PolicyConfig {
        prices: Some(PriceSheet(BTreeMap::from([
            ("cpu".to_string(), 0.04),
            ("memory".to_string(), 0.005),
        ]))),
        quotas: HashMap::new(),
    }
}

/// Seed: proj-a/gpu cpu steps 4 → 8 cores at t=1800; proj-a also holds 32Gi
/// memory flat; proj-b/gpu uses 2 cores flat. A carry-in sample at t=600
/// (before the window) sets proj-a's cpu level entering it.
async fn seed_samples(store: &InMemoryStore) {
    store
        .record_usage_samples(&[
            sample(600, "proj-a", "gpu", "cpu", 4.0),
            sample(1800, "proj-a", "gpu", "cpu", 8.0),
            sample(600, "proj-a", "gpu", "memory", 32.0),
            sample(600, "proj-b", "gpu", "cpu", 2.0),
        ])
        .await
        .unwrap();
}

#[tokio::test]
async fn usage_report_aggregates_step_changes_and_prices() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_samples(&store).await;
    let app = authed_app_with_policy(&idp, store, priced_policy()).await;
    let viewer = idp_token(&idp, &["/observers"]);

    // Window [1200, 3600): proj-a cpu enters at 4 (carry-in from t=600),
    // steps to 8 at t=1800: 4×600s + 8×1800s = 16800 core-seconds = 4.6667h.
    let res = app
        .oneshot(get(
            "/api/v1/usage?from=1200&to=3600",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["from"], 1200);
    assert_eq!(body["to"], 3600);
    let groups = body["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2);

    let a = groups
        .iter()
        .find(|g| g["project"] == "proj-a")
        .expect("proj-a group");
    let cpu_h = a["resource_hours"]["cpu"].as_f64().unwrap();
    assert!(
        (cpu_h - 16800.0 / 3600.0).abs() < 1e-9,
        "cpu hours: {cpu_h}"
    );
    // memory: 32Gi flat over 2400s.
    let mem_h = a["resource_hours"]["memory"].as_f64().unwrap();
    assert!(
        (mem_h - 32.0 * 2400.0 / 3600.0).abs() < 1e-9,
        "mem hours: {mem_h}"
    );
    // cost = cpu_h×0.04 + mem_h×0.005.
    let expect_cost = cpu_h * 0.04 + mem_h * 0.005;
    let cost = a["cost_usd"].as_f64().unwrap();
    assert!(
        (cost - expect_cost).abs() < 1e-9,
        "cost: {cost} vs {expect_cost}"
    );

    let b = groups
        .iter()
        .find(|g| g["project"] == "proj-b")
        .expect("proj-b group");
    let b_cpu = b["resource_hours"]["cpu"].as_f64().unwrap();
    assert!((b_cpu - 2.0 * 2400.0 / 3600.0).abs() < 1e-9);
}

#[tokio::test]
async fn usage_report_filters_and_defaults() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_samples(&store).await;
    let app = authed_app_with_policy(&idp, store, priced_policy()).await;
    let viewer = idp_token(&idp, &["/observers"]);

    // Project filter.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/usage?project=proj-b&from=1200&to=3600",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    let body = body_json(res).await;
    let groups = body["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["project"], "proj-b");

    // Pool filter with a pool that has no samples → empty groups.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/usage?pool=ghost&from=0&to=3600",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(body_json(res).await["groups"].as_array().unwrap().len(), 0);

    // from >= to → 400.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/usage?from=3600&to=1200",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Defaults: no from/to → to=now, from=to-86400 (the seeded samples at
    // t≤1800 are far outside; groups is empty but the window is sane).
    let res = app
        .oneshot(get("/api/v1/usage", "mobula.example.com", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let to = body["to"].as_u64().unwrap();
    let from = body["from"].as_u64().unwrap();
    assert_eq!(to - from, 86_400);
}

#[tokio::test]
async fn usage_report_cost_is_null_without_a_price_sheet() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_samples(&store).await;
    // Default PolicyConfig: no prices.
    let app = authed_app_with_store(&idp, store).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/usage?from=1200&to=3600",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    let body = body_json(res).await;
    assert!(body["groups"][0]["cost_usd"].is_null());
    // Hours are still reported without prices.
    assert!(body["groups"][0]["resource_hours"]["cpu"].is_f64());
}

#[tokio::test]
async fn usage_report_rbac_viewer_reads_unauthenticated_401() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;

    // Viewer (lowest role) can read usage.
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/usage?from=0&to=10",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // No token → 401.
    let res = app
        .oneshot(get(
            "/api/v1/usage?from=0&to=10",
            "mobula.example.com",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

fn pool_spec(name: &str) -> PoolSpec {
    PoolSpec {
        name: name.into(),
        flavors: vec![mobula_core::FlavorSpec {
            name: "a100".into(),
            resources: BTreeMap::from([
                ("cpu".to_string(), "64".to_string()),
                ("memory".to_string(), "256Gi".to_string()),
            ]),
            node_labels: BTreeMap::new(),
            taints: vec![],
        }],
        cohort: "research".into(),
        fair_sharing_weight: 1.0,
        elastic: true,
    }
}

#[tokio::test]
async fn pool_usage_view_live_allocation() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    store.upsert_pool("gpu", pool_spec("gpu")).await.unwrap();
    store
        .upsert_allocation(AllocationSpec {
            pool: "gpu".into(),
            project: "proj-a".into(),
            namespace: "proj-a".into(),
            nominal: BTreeMap::new(),
            borrowing_limit: BTreeMap::new(),
            lending_limit: BTreeMap::new(),
        })
        .await
        .unwrap();
    // The observation the pool reconcile loop would have recorded.
    let obs = serde_json::json!({
        "admitted_workloads": 2,
        "reserving_workloads": 2,
        "pending_workloads": 0,
        "flavors_usage": {
            "a100": { "cpu": "16", "memory": "64Gi" }
        },
        "queues_usage": {
            "proj-a": { "cpu": "10" }
        }
    });
    store
        .record_pool_observation("gpu", &obs.to_string())
        .await
        .unwrap();

    let app = authed_app_with_store(&idp, store).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/pools/gpu/usage",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["pool"], "gpu");
    assert!(body["sampled_at"].is_u64());
    // cpu: 16 allocated of 64 nominal = 25%.
    assert_eq!(body["utilization"]["cpu"]["allocated"], 16.0);
    assert_eq!(body["utilization"]["cpu"]["nominal"], 64.0);
    assert_eq!(body["utilization"]["cpu"]["pct"], 25.0);
    // memory: 64Gi allocated of 256Gi nominal = 25%.
    let gib = 1024.0 * 1024.0 * 1024.0;
    assert_eq!(body["utilization"]["memory"]["allocated"], 64.0 * gib);
    assert_eq!(body["utilization"]["memory"]["nominal"], 256.0 * gib);
    assert_eq!(body["utilization"]["memory"]["pct"], 25.0);
    // Per-project attribution from the LQ status.
    assert_eq!(body["projects"]["proj-a"]["cpu"], 10.0);
}

#[tokio::test]
async fn pool_usage_404_on_unknown_pool() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/pools/ghost/usage",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_endpoint_renders_prometheus_text() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_samples(&store).await;
    let app = authed_app_with_store(&idp, store).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get("/api/v1/metrics", "mobula.example.com", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;
    assert!(text.contains("# TYPE mobula_pool_resource_usage gauge"));
    // Latest sample wins: proj-a cpu is 8 (t=1800), not 4 (t=600).
    assert!(
        text.contains(
            "mobula_pool_resource_usage{pool=\"gpu\",project=\"proj-a\",resource=\"cpu\"} 8"
        ),
        "{text}"
    );
    assert!(
        !text.contains("} 4\n"),
        "stale sample must not render: {text}"
    );
}

#[tokio::test]
async fn roleless_token_is_403_on_usage_and_metrics() {
    // A valid token whose groups map to no role is denied at the handler.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let nobody = idp_token(&idp, &["/no-such-group"]);

    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/usage?from=0&to=10",
            "mobula.example.com",
            Some(&nobody),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = app
        .oneshot(get("/api/v1/metrics", "mobula.example.com", Some(&nobody)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn usage_store_failures_are_500() {
    use common::FailingStore;
    let idp = spawn_idp().await;
    let viewer = idp_token(&idp, &["/observers"]);

    for path in ["/api/v1/usage?from=0&to=10", "/api/v1/metrics"] {
        let store = Arc::new(FailingStore::new());
        store.fail("usage_samples");
        let app = authed_app_with_store(&idp, store).await;
        let res = app
            .oneshot(get(path, "mobula.example.com", Some(&viewer)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR, "{path}");
    }
}
