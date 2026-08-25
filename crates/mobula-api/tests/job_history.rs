//! Truthful Console job-history tests (#89).
//!
//! A job submitted through the federating gateway must be recorded into the
//! store and appear in `GET /api/v1/jobs` attributed to the authenticated
//! caller; the background refresher must advance a non-terminal record to its
//! terminal state (and compute its duration) from the cluster's Ray Job API.
//! Only the southbound hop touches the network.

mod common;
use common::{idp_token, idp_token_sub, spawn_idp, Idp};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::{Json, Router};
use mobula_auth::{AuthConfig, RoleMappings, Validator};
use mobula_controller::{InMemoryStore, Store};
use mobula_core::{ClusterEndpoint, ClusterId, ClusterRegistry, JobRecord};
use serde_json::json;
use tower::ServiceExt;

async fn validator_for(idp: &Idp) -> Arc<Validator> {
    let config = AuthConfig {
        issuer: idp.issuer.clone(),
        audience: "mobula".into(),
        groups_claim: "groups".into(),
        project_roles: Default::default(),
        roles: RoleMappings {
            admin: vec!["/platform-admins".into()],
            operator: vec!["/sre".into()],
            developer: vec!["/ml-eng".into()],
            viewer: vec!["/observers".into()],
            auditor: vec![],
        },
    };
    Arc::new(
        Validator::discover(config, reqwest::Client::new(), true)
            .await
            .unwrap(),
    )
}

async fn body_json(res: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 22)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Mock Ray head. `POST /api/jobs/` replies with a submission id; `GET
/// /api/jobs/` replies with `get_body` (the refresher's status source).
async fn spawn_ray_head(get_body: serde_json::Value) -> SocketAddr {
    let get_body = Arc::new(get_body);
    let app = Router::new().route(
        "/api/jobs/",
        axum::routing::post(|| async { Json(json!({ "submission_id": "raysubmit_test" })) }).get(
            move || {
                let b = (*get_body).clone();
                async move { Json(b) }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn registry_for(addr: SocketAddr) -> ClusterRegistry {
    ClusterRegistry {
        clusters: vec![ClusterEndpoint {
            id: ClusterId("demo".into()),
            hostname: "demo.ray.test".into(),
            api_base_url: format!("http://{addr}"),
            auth_token: None,
            auth_token_env: None,
        }],
    }
}

#[tokio::test]
async fn gateway_submission_is_recorded_and_listed_for_the_caller() {
    let idp = spawn_idp().await;
    let addr = spawn_ray_head(json!([])).await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = mobula_api::build_app_full(
        registry_for(addr),
        Some(validator_for(&idp).await),
        Some(store.clone()),
        Default::default(),
    );

    // Submitting a job is a Write on Job — Developer/Admin only. The caller's
    // subject ("user-123") is what must be attributed to the record.
    let developer = idp_token(&idp, &["/ml-eng"]);
    // Admin reads the history (Read on Job).
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Submit a job through the gateway (Host-routed to the registered cluster).
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .header(header::AUTHORIZATION, format!("Bearer {developer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"entrypoint":"python train.py"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // The proxied submit reply is returned to the caller unchanged.
    let submit = body_json(res).await;
    assert_eq!(submit["submission_id"], "raysubmit_test");

    // It now appears in the persistent history, attributed to the real caller.
    let res = app
        .oneshot(
            Request::get("/api/v1/jobs")
                .header(header::HOST, "mobula.example.com")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let jobs = body_json(res).await;
    assert_eq!(jobs.as_array().unwrap().len(), 1);
    assert_eq!(jobs[0]["id"], "raysubmit_test");
    assert_eq!(jobs[0]["cluster"], "demo");
    assert_eq!(jobs[0]["submitter"], "user-123");
    assert_eq!(jobs[0]["status"], "PENDING");
    assert!(jobs[0]["duration_secs"].is_null());
}

/// #102 / checkmaite-frontend#25: the architectural fix for the `created_by`
/// spoof. A service (checkmaite api) submitting a job on a human's behalf uses
/// RFC 8693 token exchange to obtain a token whose `sub` is the USER (audience
/// mobula). Mobula validates it as any other bearer and the gateway records
/// the token's subject as the submitter — so the job attributes to the human,
/// NOT the service account. This test proves both directions: an exchanged
/// user token records the user, while the service's own token would record the
/// service. The exchange itself (service token + user token -> user token) is
/// exercised in mobula-auth's `token_exchange_swaps_subject_and_targets_audience`;
/// here we assert the attribution end-to-end on a token shaped like the
/// exchange's output (sub = the real user, aud = mobula).
#[tokio::test]
async fn exchanged_user_token_attributes_job_to_the_user_not_the_service() {
    let idp = spawn_idp().await;
    let addr = spawn_ray_head(json!([])).await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = mobula_api::build_app_full(
        registry_for(addr),
        Some(validator_for(&idp).await),
        Some(store.clone()),
        Default::default(),
    );
    let admin = idp_token(&idp, &["/platform-admins"]);

    // The output of token exchange: aud=mobula, sub = the real human. The
    // service account never appears as the subject here.
    let exchanged_user = idp_token_sub(&idp, "alice-human", &["/ml-eng"]);
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .header(header::AUTHORIZATION, format!("Bearer {exchanged_user}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"entrypoint":"python train.py"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Contrast: a job submitted under the service's OWN token (the pre-#102
    // behaviour) records the service account, demonstrating exactly what the
    // exchange changes. Distinct submission id so both records coexist.
    let service = idp_token_sub(&idp, "checkmaite-svc", &["/ml-eng"]);
    // The mock Ray head returns a fixed submission id, so records with the
    // same id would collide; assert the service path against its own record by
    // reading history after each submit instead.
    let jobs = list_jobs(&app, &admin).await;
    assert_eq!(jobs.as_array().unwrap().len(), 1);
    assert_eq!(
        jobs[0]["submitter"], "alice-human",
        "exchanged token must attribute the job to the human, not the service"
    );
    assert_ne!(jobs[0]["submitter"], "checkmaite-svc");

    // Prove the service token would record the service (same id overwrites the
    // record's submitter to the service subject).
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .header(header::AUTHORIZATION, format!("Bearer {service}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"entrypoint":"python train.py"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let jobs = list_jobs(&app, &admin).await;
    assert_eq!(
        jobs[0]["submitter"], "checkmaite-svc",
        "without exchange, the shared service account is recorded — the spoof #102 closes"
    );
}

async fn list_jobs(app: &axum::Router, admin: &str) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(
            Request::get("/api/v1/jobs")
                .header(header::HOST, "mobula.example.com")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await
}

#[tokio::test]
async fn refresher_advances_status_and_computes_duration() {
    // A non-terminal record already in the store (as if recorded at submit).
    let store = Arc::new(InMemoryStore::new());
    store
        .record_job(JobRecord {
            id: "raysubmit_test".into(),
            cluster: "demo".into(),
            submitter: "alice".into(),
            status: "PENDING".into(),
            duration_secs: None,
            submitted_at: 100,
        })
        .await
        .unwrap();

    // The cluster's Ray Job API now reports it finished.
    let addr = spawn_ray_head(json!([
        {
            "submission_id": "raysubmit_test",
            "status": "SUCCEEDED",
            "start_time": 1_000_000u64,
            "end_time": 1_005_000u64
        }
    ]))
    .await;

    let refresher = mobula_api::job_history::JobRefresher::new(
        store.clone(),
        Arc::new(registry_for(addr)),
        reqwest::Client::new(),
        Duration::from_secs(30),
    );
    let updated = refresher.refresh_once().await.unwrap();
    assert_eq!(updated, 1);

    let jobs = store.list_jobs().await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "SUCCEEDED");
    // (end - start) / 1000 = 5 seconds; submitter/submitted_at preserved.
    assert_eq!(jobs[0].duration_secs, Some(5));
    assert_eq!(jobs[0].submitter, "alice");
    assert_eq!(jobs[0].submitted_at, 100);
}

#[tokio::test]
async fn refresher_leaves_jobs_on_unregistered_clusters_untouched() {
    let store = Arc::new(InMemoryStore::new());
    store
        .record_job(JobRecord {
            id: "raysubmit_gone".into(),
            cluster: "purged".into(),
            submitter: "alice".into(),
            status: "RUNNING".into(),
            duration_secs: None,
            submitted_at: 100,
        })
        .await
        .unwrap();

    // Registry knows only "demo", not "purged".
    let addr = spawn_ray_head(json!([])).await;
    let refresher = mobula_api::job_history::JobRefresher::new(
        store.clone(),
        Arc::new(registry_for(addr)),
        reqwest::Client::new(),
        Duration::from_secs(30),
    );
    assert_eq!(refresher.refresh_once().await.unwrap(), 0);
    // The record is left exactly as it was — we can't refresh what we can't reach.
    let jobs = store.list_jobs().await.unwrap();
    assert_eq!(jobs[0].status, "RUNNING");
}
