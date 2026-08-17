//! Settings API tests (api-v1.md §5.16): the store-backed, API-editable
//! governance policy. Covers provenance (`source`: none/file/store), the
//! section-replace PUT semantics (incl. explicit-null clears), RBAC
//! (Admin-only), validation, and that consumers (quota admission, cost
//! estimates) read the EDITED policy without a restart.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use mobula_api::clusters::PolicyConfig;
use mobula_controller::InMemoryStore;
use mobula_policy::{PriceSheet, ResourceMap};
use tower::ServiceExt;

use common::{
    authed_app_with_policy, authed_app_with_store, get, idp_token, post_json, put_json, spawn_idp,
};

const HOST: &str = "mobula.example.com";

async fn body_json(res: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// head 1 + `replicas` × `cpu` workers, in `project`.
fn create_body_sized(id: &str, project: &str, cpu: &str, replicas: u32) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "spec": {
            "name": id, "project": project, "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0", "head_cpu": "1", "head_memory": "2Gi",
            "worker_groups": [{
                "name": "w", "cpu": cpu, "memory": "1Gi", "gpu": null,
                "min_replicas": replicas, "max_replicas": replicas, "replicas": replicas
            }],
            "ttl_seconds": null
        }
    })
}

fn seeded_policy() -> PolicyConfig {
    PolicyConfig {
        prices: Some(PriceSheet(BTreeMap::from([("cpu".to_string(), 0.048)]))),
        quotas: HashMap::from([(
            "demo".to_string(),
            ResourceMap(BTreeMap::from([
                ("cpu".to_string(), 5.0),
                ("memory".to_string(), 100.0),
            ])),
        )]),
    }
}

#[tokio::test]
async fn unset_policy_reports_none() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["source"], "none");
    assert!(body["prices"].is_null());
    assert_eq!(body["quotas"], serde_json::json!({}));
    assert_eq!(body["editable"], true);
}

#[tokio::test]
async fn seeded_policy_reports_file_and_drives_cost_estimates() {
    let idp = spawn_idp().await;
    let app = authed_app_with_policy(&idp, Arc::new(InMemoryStore::new()), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["source"], "file", "untouched boot seed reports file");
    assert_eq!(body["prices"]["cpu"], 0.048);
    assert_eq!(body["quotas"]["demo"]["cpu"], 5.0);

    // The seeded price sheet drives ClusterView cost estimates.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("a", "demo", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = app
        .oneshot(get("/api/v1/clusters", HOST, Some(&admin)))
        .await
        .unwrap();
    let clusters = body_json(res).await;
    // head 1 + 3×1cpu = 4 cores × $0.048 = $0.192/hr at min AND max.
    assert_eq!(clusters[0]["est_min_hourly"], 0.192);
    assert_eq!(clusters[0]["est_max_hourly"], 0.192);
}

#[tokio::test]
async fn put_prices_then_get_and_estimates_reflect_store() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": { "cpu": 0.1 } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["source"], "store");
    assert_eq!(body["prices"]["cpu"], 0.1);

    // GET reflects the edit.
    let res = app
        .clone()
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let body = body_json(res).await;
    assert_eq!(body["source"], "store");
    assert_eq!(body["prices"]["cpu"], 0.1);

    // A cluster created after the edit shows cost estimates.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("a", "demo", "2", 2),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters/a", HOST, Some(&admin)))
        .await
        .unwrap();
    let cluster = body_json(res).await;
    // head 1 + 2×2cpu = 5 cores × $0.1 = $0.5/hr.
    assert_eq!(cluster["est_min_hourly"], 0.5);

    // Absent keys are untouched: a quotas-only PUT keeps the price sheet.
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "quotas": { "demo": { "cpu": 50 } } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["prices"]["cpu"], 0.1, "absent prices key untouched");
    assert_eq!(body["quotas"]["demo"]["cpu"], 50.0);
}

#[tokio::test]
async fn put_quotas_replaces_file_quotas_for_admission() {
    let idp = spawn_idp().await;
    let app = authed_app_with_policy(&idp, Arc::new(InMemoryStore::new()), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Replace the whole quota section: demo's file quota (cpu 5) is gone,
    // project "q2" is now capped at 2 CPU.
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "quotas": { "q2": { "cpu": 2 } } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // The OLD file quota no longer applies: demo's create needs head 1 +
    // 3×2 = 7 CPU > the old 5-CPU cap, and must now be admitted.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("big", "demo", "2", 3),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "replaced file quota must no longer gate demo"
    );

    // The NEW quota gates q2: head 1 + 3×1 = 4 CPU > 2 → 409.
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("over", "q2", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "store-edited quota must gate admission"
    );
}

#[tokio::test]
async fn clear_prices_with_explicit_null() {
    let idp = spawn_idp().await;
    let app = authed_app_with_policy(&idp, Arc::new(InMemoryStore::new()), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": null }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body["prices"].is_null(), "null clears the price sheet");
    assert_eq!(body["quotas"]["demo"]["cpu"], 5.0, "quotas untouched");
    assert_eq!(body["source"], "store");

    // Cost estimates disappear once the sheet is cleared.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("a", "demo", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = app
        .oneshot(get("/api/v1/clusters/a", HOST, Some(&admin)))
        .await
        .unwrap();
    let cluster = body_json(res).await;
    assert!(cluster["est_min_hourly"].is_null());
    assert!(cluster["est_max_hourly"].is_null());
}

#[tokio::test]
async fn viewer_is_forbidden_on_get_and_put() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let viewer = idp_token(&idp, &["/observers"]);

    let res = app
        .clone()
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = app
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &viewer,
            serde_json::json!({ "prices": { "cpu": 0.1 } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_values_are_400() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    for body in [
        serde_json::json!({ "prices": { "cpu": -0.5 } }),
        serde_json::json!({ "quotas": { "demo": { "cpu": -1 } } }),
    ] {
        let res = app
            .clone()
            .oneshot(put_json("/api/v1/settings/policy", HOST, &admin, body))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let text = String::from_utf8(
            axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("non-negative finite"), "{text}");
    }

    // A rejected PUT must not have written anything.
    let res = app
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let body = body_json(res).await;
    assert_eq!(body["source"], "none");
}

#[tokio::test]
async fn update_policy_is_audited() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": { "cpu": 0.1 } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .oneshot(get("/api/v1/audit", HOST, Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let actions: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"update_policy"),
        "expected an update_policy audit row, got {actions:?}"
    );
}
