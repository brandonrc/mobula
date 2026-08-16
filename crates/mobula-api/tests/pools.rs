//! Capacity-pool API tests (ADR-0010, Slice 2), including the per-target
//! RBAC tripwire: pool mutations are Admin-only (Developer gets 403), reads
//! are open to Viewer+.

mod common;
use common::{authed_app_with_store, get, idp_token, post_json, spawn_idp};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use mobula_controller::{InMemoryStore, Store};

fn pool_body(name: &str) -> serde_json::Value {
    serde_json::json!({
        "spec": {
            "name": name,
            "flavors": [{
                "name": "a100",
                "resources": { "cpu": "64", "memory": "256Gi", "nvidia.com/gpu": "8" },
                "node_labels": {},
                "taints": []
            }],
            "cohort": "research",
            "fair_sharing_weight": 1.0,
            "elastic": true
        }
    })
}

fn alloc_body(namespace: &str) -> serde_json::Value {
    serde_json::json!({
        "namespace": namespace,
        "nominal": { "cpu": "16" },
        "borrowing_limit": {},
        "lending_limit": {}
    })
}

fn put_json(path: &str, host: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::put(path)
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn delete(path: &str, host: &str, token: &str) -> Request<Body> {
    Request::delete(path)
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn create_list_get_round_trip() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Create → 201 with name + generation.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let v = body_json(res).await;
    assert_eq!(v["name"], "gpu-pool");
    assert_eq!(v["generation"], 1);

    // List → one pool, total_nominal summed across flavors.
    let res = app
        .clone()
        .oneshot(get("/api/v1/pools", "mobula.example.com", Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["name"], "gpu-pool");
    assert_eq!(v[0]["total_nominal"]["cpu"], "64");
    assert_eq!(v[0]["total_nominal"]["nvidia.com/gpu"], "8");
    assert_eq!(v[0]["cohort"], "research");

    // Get → same view.
    let res = app
        .oneshot(get(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    assert_eq!(v["name"], "gpu-pool");
    assert_eq!(v["generation"], 1);
    assert!(v["created_at"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn invalid_spec_is_400() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // No flavors → shape validation rejects.
    let mut bad = pool_body("bad-pool");
    bad["spec"]["flavors"] = serde_json::json!([]);
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            bad,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Unparseable quantity → rejected at the edge (core validates shape only).
    let mut bad = pool_body("bad-qty");
    bad["spec"]["flavors"][0]["resources"]["cpu"] = serde_json::json!("banana");
    let res = app
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            bad,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn duplicate_create_is_409() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Create-only in v0: the second POST conflicts even with an identical spec.
    let res = app
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn unknown_pool_get_and_delete_are_404() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/pools/ghost",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    let res = app
        .oneshot(delete("/api/v1/pools/ghost", "mobula.example.com", &admin))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_pool_round_trip() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    app.clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();

    let res = app
        .clone()
        .oneshot(delete(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let res = app
        .oneshot(get(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn allocation_put_list_delete() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Allocation against a missing pool → 404.
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/pools/ghost/allocations/proj-a",
            "mobula.example.com",
            &admin,
            alloc_body("proj-a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    app.clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();

    // Body pool/project contradicting the path → 400.
    let mut mismatched = alloc_body("proj-a");
    mismatched["project"] = serde_json::json!("someone-else");
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
            mismatched,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Put → 200 {pool, project}.
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
            alloc_body("proj-a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    assert_eq!(v["pool"], "gpu-pool");
    assert_eq!(v["project"], "proj-a");

    // List → the allocation round-trips with path-derived pool/project.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/pools/gpu-pool/allocations",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    let allocs = v.as_array().unwrap();
    assert_eq!(allocs.len(), 1);
    assert_eq!(allocs[0]["pool"], "gpu-pool");
    assert_eq!(allocs[0]["project"], "proj-a");
    assert_eq!(allocs[0]["namespace"], "proj-a");
    assert_eq!(allocs[0]["nominal"]["cpu"], "16");

    // Delete → 202; deleting again → 404.
    let res = app
        .clone()
        .oneshot(delete(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let res = app
        .oneshot(delete(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pool_rbac_admin_mutates_developer_denied_viewer_reads() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;

    let admin = idp_token(&idp, &["/platform-admins"]);
    let developer = idp_token(&idp, &["/ml-eng"]);
    let viewer = idp_token(&idp, &["/observers"]);

    // Developer (app code, not platform config) is denied pool create.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &developer,
            pool_body("dev-attempt"),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "developer cannot create pools"
    );

    // Admin creates.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Viewer reads.
    let res = app
        .clone()
        .oneshot(get("/api/v1/pools", "mobula.example.com", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Developer is also denied allocation mutations.
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &developer,
            alloc_body("proj-a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // …and pool delete.
    let res = app
        .oneshot(delete(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            &developer,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn authenticated_role_without_pool_permission_is_403_on_reads() {
    // A valid token whose groups map to no role reaches the handler and is
    // denied there (403), on every pool route including reads.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let nobody = idp_token(&idp, &["/no-such-group"]);

    for req in [
        get("/api/v1/pools", "mobula.example.com", Some(&nobody)),
        get(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            Some(&nobody),
        ),
        get(
            "/api/v1/pools/gpu-pool/usage",
            "mobula.example.com",
            Some(&nobody),
        ),
        get(
            "/api/v1/pools/gpu-pool/allocations",
            "mobula.example.com",
            Some(&nobody),
        ),
        delete(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &nobody,
        ),
    ] {
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn store_failures_are_500_not_panics() {
    use common::FailingStore;
    let idp = spawn_idp().await;
    let store = Arc::new(FailingStore::new());
    let admin = idp_token(&idp, &["/platform-admins"]);

    // list_pools failure.
    store.fail("list_pools");
    let app = authed_app_with_store(&idp, store.clone()).await;
    let res = app
        .clone()
        .oneshot(get("/api/v1/pools", "mobula.example.com", Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // get_pool failure (GET one pool, and PUT allocation's existence check).
    let store = Arc::new(FailingStore::new());
    store.fail("get_pool");
    let app = authed_app_with_store(&idp, store.clone()).await;
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
            alloc_body("proj-a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // upsert_pool failure on create (get_pool reports None first).
    let store = Arc::new(FailingStore::new());
    store.fail("upsert_pool");
    let app = authed_app_with_store(&idp, store.clone()).await;
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // delete_pool backend failure (not a "no such pool" message).
    let store = Arc::new(FailingStore::new());
    store
        .upsert_pool("gpu-pool", pool_spec_typed("gpu-pool"))
        .await
        .unwrap();
    store.fail("delete_pool");
    let app = authed_app_with_store(&idp, store.clone()).await;
    let res = app
        .clone()
        .oneshot(delete(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // list_allocations failure.
    let store = Arc::new(FailingStore::new());
    store.fail("list_allocations");
    let app = authed_app_with_store(&idp, store.clone()).await;
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/pools/gpu-pool/allocations",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // delete_allocation backend failure.
    let store = Arc::new(FailingStore::new());
    store.fail("delete_allocation");
    let app = authed_app_with_store(&idp, store.clone()).await;
    let res = app
        .clone()
        .oneshot(delete(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // upsert_allocation failure (pool exists, allocation is valid).
    let store = Arc::new(FailingStore::new());
    store
        .upsert_pool("gpu-pool", pool_spec_typed("gpu-pool"))
        .await
        .unwrap();
    store.fail("upsert_allocation");
    let app = authed_app_with_store(&idp, store.clone()).await;
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
            alloc_body("proj-a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// A pool spec with an unparseable flavor quantity, for seeding the store
/// directly (the API validates quantities at create; the fail-soft display
/// paths only trigger when a bad quantity lands in the store anyway).
fn pool_spec_bad_quantity(name: &str) -> mobula_core::PoolSpec {
    let mut spec = pool_spec_typed(name);
    spec.flavors[0]
        .resources
        .insert("cpu".to_string(), "banana".to_string());
    spec
}

fn pool_spec_typed(name: &str) -> mobula_core::PoolSpec {
    mobula_core::PoolSpec {
        name: name.into(),
        flavors: vec![mobula_core::FlavorSpec {
            name: "a100".into(),
            resources: std::collections::BTreeMap::from([
                ("cpu".to_string(), "64".to_string()),
                ("nvidia.com/gpu".to_string(), "8".to_string()),
            ]),
            node_labels: std::collections::BTreeMap::new(),
            taints: vec![],
        }],
        cohort: "research".into(),
        fair_sharing_weight: 1.0,
        elastic: true,
    }
}

#[tokio::test]
async fn invalid_allocation_shape_is_400() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    app.clone()
        .oneshot(post_json(
            "/api/v1/pools",
            "mobula.example.com",
            &admin,
            pool_body("gpu-pool"),
        ))
        .await
        .unwrap();

    // A namespace that isn't a valid Kubernetes name is rejected.
    let res = app
        .oneshot(put_json(
            "/api/v1/pools/gpu-pool/allocations/proj-a",
            "mobula.example.com",
            &admin,
            alloc_body("Not_A_Namespace"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn fractional_quantities_sum_and_render_without_decimals_loss() {
    // "500m" cpu quotas sum to a fractional total; total_nominal renders
    // fractional values as-is ("0.5"), integral values without a point.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let mut spec = pool_spec_typed("milli-pool");
    spec.flavors[0]
        .resources
        .insert("cpu".to_string(), "500m".to_string());
    store.upsert_pool("milli-pool", spec).await.unwrap();
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(get(
            "/api/v1/pools/milli-pool",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    assert_eq!(v["total_nominal"]["cpu"], "0.5");
    assert_eq!(v["total_nominal"]["nvidia.com/gpu"], "8");
}

#[tokio::test]
async fn unparseable_stored_quantities_are_omitted_from_views() {
    // Fail-soft display math: a resource key whose quantity fails to parse
    // on ANY flavor is omitted from total_nominal (a partial sum would
    // misreport capacity) — the pool itself still serves fine.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_pool("gpu-pool", pool_spec_bad_quantity("gpu-pool"))
        .await
        .unwrap();
    let app = authed_app_with_store(&idp, store.clone()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/pools/gpu-pool",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    assert!(v["total_nominal"].get("cpu").is_none());
    assert_eq!(v["total_nominal"]["nvidia.com/gpu"], "8");

    // The live-usage view applies the same rule to nominal, and skips
    // unparseable quantities in the observation ledger.
    store
        .record_pool_observation(
            "gpu-pool",
            &serde_json::json!({
                "admitted_workloads": 1,
                "reserving_workloads": 1,
                "pending_workloads": 0,
                "flavors_usage": { "a100": { "cpu": "banana", "nvidia.com/gpu": "4" } },
                "queues_usage": { "proj-a": { "nvidia.com/gpu": "2" } }
            })
            .to_string(),
        )
        .await
        .unwrap();
    let res = app
        .oneshot(get(
            "/api/v1/pools/gpu-pool/usage",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    // cpu is unparseable in BOTH spec and ledger → no utilization row.
    assert!(v["utilization"].get("cpu").is_none());
    // gpu: allocated 4 (ledger), nominal 8 (spec) → 50%.
    assert_eq!(v["utilization"]["nvidia.com/gpu"]["allocated"], 4.0);
    assert_eq!(v["utilization"]["nvidia.com/gpu"]["nominal"], 8.0);
    assert_eq!(v["utilization"]["nvidia.com/gpu"]["pct"], 50.0);
    assert_eq!(v["projects"]["proj-a"]["nvidia.com/gpu"], 2.0);
}

#[tokio::test]
async fn unparsable_stored_observation_is_treated_as_unobserved() {
    // A corrupt observed_json (not a PoolObservation) must not 500 the
    // usage view: it's logged and the pool renders spec-only utilization.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_pool("gpu-pool", pool_spec_typed("gpu-pool"))
        .await
        .unwrap();
    store
        .record_pool_observation("gpu-pool", "not a pool observation")
        .await
        .unwrap();
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(get(
            "/api/v1/pools/gpu-pool/usage",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    assert_eq!(v["utilization"]["cpu"]["allocated"], 0.0);
    assert_eq!(v["utilization"]["cpu"]["nominal"], 64.0);
    assert_eq!(v["utilization"]["cpu"]["pct"], 0.0);
    assert!(v["projects"].as_object().unwrap().is_empty());
}
