//! Gateway integration tests against a mock Ray head.
//!
//! The mock stands in for a cluster's native dashboard/job API: it records
//! every request it receives (method, path, auth header, body) and answers
//! with canned JSON. The gateway router is exercised in-process via
//! `tower::ServiceExt::oneshot`; only the southbound hop uses the network.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{Request as AxumRequest, State};
use axum::http::{header, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use mobula_core::{ClusterEndpoint, ClusterId, ClusterRegistry};
use tower::ServiceExt;

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Bytes,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

async fn record(State(log): State<SeenLog>, req: AxumRequest) -> impl IntoResponse {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    log.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        path: parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_default(),
        authorization: parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(String::from),
        body,
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"mock":"ray-head"}"#,
    )
}

/// Spawn the mock Ray head on an ephemeral port; returns its address and
/// the request log.
async fn spawn_mock_ray_head() -> (SocketAddr, SeenLog) {
    let log: SeenLog = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().fallback(record).with_state(log.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, log)
}

fn app_with_cluster(addr: SocketAddr, token: Option<&str>) -> Router {
    mobula_api::build_app(ClusterRegistry {
        clusters: vec![ClusterEndpoint {
            id: ClusterId("demo".into()),
            hostname: "demo.ray.test".into(),
            api_base_url: format!("http://{addr}"),
            auth_token: token.map(String::from),
        }],
    })
}

#[tokio::test]
async fn cluster_host_proxies_to_ray_head_with_token_injected() {
    let (addr, log) = spawn_mock_ray_head().await;
    let app = app_with_cluster(addr, Some("ray-static-token"));

    let res = app
        .oneshot(
            Request::get("/api/jobs/?filter=running")
                .header(header::HOST, "demo.ray.test:8484")
                // A caller's own bearer token must never reach the cluster.
                .header(header::AUTHORIZATION, "Bearer user-oidc-jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(&body[..], br#"{"mock":"ray-head"}"#);

    let seen = log.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].path, "/api/jobs/?filter=running");
    assert_eq!(
        seen[0].authorization.as_deref(),
        Some("Bearer ray-static-token"),
        "gateway must swap caller credentials for the cluster's Ray token"
    );
}

#[tokio::test]
async fn post_bodies_pass_through_unchanged() {
    let (addr, log) = spawn_mock_ray_head().await;
    let app = app_with_cluster(addr, None);

    let payload = r#"{"entrypoint":"python train.py","runtime_env":{}}"#;
    let res = app
        .oneshot(
            Request::post("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let seen = log.lock().unwrap();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(&seen[0].body[..], payload.as_bytes());
    assert_eq!(
        seen[0].authorization, None,
        "no token configured means no Authorization header southbound"
    );
}

#[tokio::test]
async fn cluster_host_wins_even_on_control_plane_paths() {
    let (addr, log) = spawn_mock_ray_head().await;
    let app = app_with_cluster(addr, None);

    // Ray's own version-negotiation endpoint must reach the cluster, not
    // any Mobula route, when addressed to a cluster hostname.
    let res = app
        .oneshot(
            Request::get("/healthz")
                .header(header::HOST, "demo.ray.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(
        &body[..],
        br#"{"mock":"ray-head"}"#,
        "should be the mock's answer"
    );
    assert_eq!(log.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn unknown_host_falls_through_to_control_plane() {
    let (addr, log) = spawn_mock_ray_head().await;
    let app = app_with_cluster(addr, None);

    let res = app
        .oneshot(
            Request::get("/healthz")
                .header(header::HOST, "mobula.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
    assert!(log.lock().unwrap().is_empty(), "mock must not be touched");
}

#[tokio::test]
async fn unreachable_cluster_returns_bad_gateway() {
    // Reserve a port, then drop the listener so nothing answers there.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let app = app_with_cluster(addr, None);
    let res = app
        .oneshot(
            Request::get("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}
