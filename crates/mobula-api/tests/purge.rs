//! Truthful Console tombstone-purge tests.
//!
//! `DELETE /api/v1/clusters/{id}?purge=true` hard-deletes a terminated,
//! observed-gone cluster row so it stops lingering in `GET /api/v1/clusters`.
//! It must refuse a live (or still-terminating) cluster, and the plain DELETE
//! (no purge) must still only flip desired state.

mod common;
use common::{authed_app_with_store, idp_token, spawn_idp};

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use mobula_controller::{DesiredState, InMemoryStore, Store};
use mobula_core::{ClusterId, ClusterSpec, ClusterState};
use tower::ServiceExt;

fn spec() -> ClusterSpec {
    ClusterSpec {
        name: "c".into(),
        project: "demo".into(),
        ray_version: "2.57.0".into(),
        image: "rayproject/ray:2.57.0".into(),
        head_cpu: "1".into(),
        head_memory: "2Gi".into(),
        worker_groups: vec![],
        ttl_seconds: None,
        owner: None,
    }
}

fn delete(path: &str, host: &str, token: &str) -> Request<Body> {
    Request::delete(path)
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn purge_removes_a_terminated_gone_tombstone() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let id = ClusterId("dead".into());
    store.upsert_desired(&id, spec()).await.unwrap();
    // Terminated and observed gone (Terminated) → a genuine tombstone.
    store
        .set_desired(&id, DesiredState::Terminated)
        .await
        .unwrap();
    store
        .record_observation(&id, Some(ClusterState::Terminated), 1)
        .await
        .unwrap();

    let app = authed_app_with_store(&idp, store.clone()).await;
    let operator = idp_token(&idp, &["/sre"]);

    let res = app
        .oneshot(delete(
            "/api/v1/clusters/dead?purge=true",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // Row is gone from the store entirely.
    assert!(store.get(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn purge_refuses_a_live_cluster() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let id = ClusterId("live".into());
    store.upsert_desired(&id, spec()).await.unwrap();
    store
        .record_observation(&id, Some(ClusterState::Running), 1)
        .await
        .unwrap();

    let app = authed_app_with_store(&idp, store.clone()).await;
    let operator = idp_token(&idp, &["/sre"]);

    let res = app
        .oneshot(delete(
            "/api/v1/clusters/live?purge=true",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    // Still present — a live cluster is never purged.
    assert!(store.get(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn purge_refuses_a_still_terminating_cluster() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let id = ClusterId("tearing".into());
    store.upsert_desired(&id, spec()).await.unwrap();
    store
        .set_desired(&id, DesiredState::Terminated)
        .await
        .unwrap();
    // Desired Terminated but the backing cluster is still observed alive:
    // teardown in flight, not yet a dead tombstone.
    store
        .record_observation(&id, Some(ClusterState::Terminating), 1)
        .await
        .unwrap();

    let app = authed_app_with_store(&idp, store.clone()).await;
    let operator = idp_token(&idp, &["/sre"]);

    let res = app
        .oneshot(delete(
            "/api/v1/clusters/tearing?purge=true",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    assert!(store.get(&id).await.unwrap().is_some());
}

#[tokio::test]
async fn plain_delete_only_flips_desired_state() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let id = ClusterId("keep".into());
    store.upsert_desired(&id, spec()).await.unwrap();

    let app = authed_app_with_store(&idp, store.clone()).await;
    let operator = idp_token(&idp, &["/sre"]);

    let res = app
        .oneshot(delete(
            "/api/v1/clusters/keep",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    // Row remains, now desired=Terminated (the reconciler tears it down).
    let got = store.get(&id).await.unwrap().unwrap();
    assert_eq!(got.desired, DesiredState::Terminated);
}

#[tokio::test]
async fn purge_of_unknown_cluster_is_404() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let operator = idp_token(&idp, &["/sre"]);

    let res = app
        .oneshot(delete(
            "/api/v1/clusters/ghost?purge=true",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
