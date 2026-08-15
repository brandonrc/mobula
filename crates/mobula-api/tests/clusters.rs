//! Cluster lifecycle API tests, including the per-target RBAC tripwire
//! (#26): Operator can manage cluster lifecycle but Developer cannot, and
//! vice-versa on the job surface.

mod common;
use common::{authed_app_with_store, get, idp_token, post_json, spawn_idp};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use mobula_controller::{InMemoryStore, Store};
use mobula_core::ClusterId;

fn create_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "spec": {
            "name": id,
            "project": "demo",
            "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0",
            "head_cpu": "1",
            "head_memory": "2Gi",
            "worker_groups": [],
            "ttl_seconds": null
        }
    })
}

#[tokio::test]
async fn operator_manages_lifecycle_developer_cannot() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store.clone()).await;

    let operator = idp_token(&idp, &["/sre"]);
    let developer = idp_token(&idp, &["/ml-eng"]);

    // Developer (job code, not cluster lifecycle) is denied create.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &developer,
            create_body("dev-attempt"),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "developer cannot create clusters"
    );

    // Operator creates it.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &operator,
            create_body("c1"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(store.get(&ClusterId("c1".into())).await.unwrap().is_some());

    // Developer CAN read (Read on cluster target).
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters",
            "mobula.example.com",
            Some(&developer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Operator deletes (marks terminated).
    let res = app
        .oneshot(
            Request::delete("/api/v1/clusters/c1")
                .header(header::HOST, "mobula.example.com")
                .header(header::AUTHORIZATION, format!("Bearer {operator}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let stored = store.get(&ClusterId("c1".into())).await.unwrap().unwrap();
    assert_eq!(stored.desired, mobula_controller::DesiredState::Terminated);
}

#[tokio::test]
async fn get_single_cluster_and_not_found() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Create via API, then read it back.
    app.clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body("c9"),
        ))
        .await
        .unwrap();

    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters/c9",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["id"], "c9");
    assert_eq!(v["desired"], "running");
    assert_eq!(v["generation"], 1);

    // Missing cluster → 404.
    let res = app
        .oneshot(get(
            "/api/v1/clusters/ghost",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unauthenticated_and_unmapped_are_denied_on_cluster_routes() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;

    // No token → 401.
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters", "mobula.example.com", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Valid token, unmapped groups → 403 (deny by default).
    let stranger = idp_token(&idp, &["/nobody"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters",
            "mobula.example.com",
            Some(&stranger),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
