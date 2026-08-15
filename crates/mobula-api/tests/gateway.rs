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
    mobula_api::build_app(
        ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("demo".into()),
                hostname: "demo.ray.test".into(),
                api_base_url: format!("http://{addr}"),
                auth_token: token.map(String::from),
            }],
        },
        None,
    )
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

mod websocket {
    use super::*;
    use axum::extract::ws::{Message as AxMessage, WebSocket, WebSocketUpgrade};
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::protocol::Message as TsMessage;

    /// Mock Ray head websocket endpoint: records the Authorization header,
    /// streams three log lines, echoes one client frame, then closes.
    async fn ws_tail(
        State(log): State<SeenLog>,
        req_headers: axum::http::HeaderMap,
        upgrade: WebSocketUpgrade,
    ) -> impl IntoResponse {
        log.lock().unwrap().push(Seen {
            method: "WS".into(),
            path: "/api/jobs/x/logs/tail".into(),
            authorization: req_headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(String::from),
            body: Bytes::new(),
        });
        upgrade.on_upgrade(|mut socket: WebSocket| async move {
            for line in ["line-1", "line-2", "line-3"] {
                socket.send(AxMessage::Text(line.into())).await.unwrap();
            }
            if let Some(Ok(AxMessage::Text(t))) = socket.recv().await {
                socket
                    .send(AxMessage::Text(format!("echo:{t}").into()))
                    .await
                    .unwrap();
            }
            let _ = socket.close().await;
        })
    }

    async fn spawn_mock_ws_head() -> (SocketAddr, SeenLog) {
        let log: SeenLog = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/api/jobs/x/logs/tail", axum::routing::any(ws_tail))
            .with_state(log.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (addr, log)
    }

    /// Serve the gateway on a real port; websockets can't go through
    /// `oneshot`. Registry hostname "127.0.0.1" matches the loopback Host
    /// header the ws client sends.
    async fn spawn_gateway(head: SocketAddr, token: Option<&str>) -> SocketAddr {
        let app = mobula_api::build_app(
            ClusterRegistry {
                clusters: vec![ClusterEndpoint {
                    id: ClusterId("demo".into()),
                    hostname: "127.0.0.1".into(),
                    api_base_url: format!("http://{head}"),
                    auth_token: token.map(String::from),
                }],
            },
            None,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn log_tail_bridges_frames_and_swaps_credentials() {
        let (head, log) = spawn_mock_ws_head().await;
        let gw = spawn_gateway(head, Some("ray-ws-token")).await;

        let mut req = format!("ws://{gw}/api/jobs/x/logs/tail")
            .into_client_request()
            .unwrap();
        // The caller's own credential must be stripped at the gateway.
        req.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer user-oidc-jwt".parse().unwrap(),
        );
        let (mut ws, _resp) = tokio_tungstenite::connect_async(req).await.unwrap();

        let mut lines = Vec::new();
        for _ in 0..3 {
            match ws.next().await.unwrap().unwrap() {
                TsMessage::Text(t) => lines.push(t.as_str().to_string()),
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert_eq!(lines, ["line-1", "line-2", "line-3"]);

        // Southbound direction: client frame reaches the mock and echoes.
        ws.send(TsMessage::Text("hello".into())).await.unwrap();
        match ws.next().await.unwrap().unwrap() {
            TsMessage::Text(t) => assert_eq!(t.as_str(), "echo:hello"),
            other => panic!("unexpected frame: {other:?}"),
        }

        let seen = log.lock().unwrap();
        assert_eq!(seen[0].method, "WS");
        assert_eq!(
            seen[0].authorization.as_deref(),
            Some("Bearer ray-ws-token"),
            "gateway must inject the cluster token on the ws handshake"
        );
    }

    #[tokio::test]
    async fn ws_to_unreachable_cluster_fails_handshake_with_502() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = listener.local_addr().unwrap();
        drop(listener);
        let gw = spawn_gateway(dead, None).await;

        let req = format!("ws://{gw}/api/jobs/x/logs/tail")
            .into_client_request()
            .unwrap();
        let err = tokio_tungstenite::connect_async(req).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("502"),
            "expected 502 handshake rejection, got: {msg}"
        );
    }
}

#[tokio::test]
async fn malformed_cluster_token_is_500_not_leak() {
    let (addr, log) = spawn_mock_ray_head().await;
    // A token with a newline can't become a header value; the gateway must
    // fail closed rather than forward the request unauthenticated.
    let app = app_with_cluster(addr, Some("bad\ntoken"));

    let res = app
        .oneshot(
            Request::get("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        log.lock().unwrap().is_empty(),
        "request must not reach the cluster"
    );
}

#[tokio::test]
async fn connection_nominated_headers_are_not_smuggled() {
    // RFC 9110 §7.6.1: headers named in Connection are hop-by-hop. A
    // static denylist alone lets `Connection: x-secret` smuggle headers.
    let log: SeenLog = Arc::new(Mutex::new(Vec::new()));
    let log_clone = log.clone();
    let app = Router::new().fallback(move |req: AxumRequest| {
        let log = log_clone.clone();
        async move {
            let smuggled = req.headers().get("x-internal-secret").is_some();
            log.lock().unwrap().push(Seen {
                method: smuggled.to_string(),
                path: String::new(),
                authorization: None,
                body: Bytes::new(),
            });
            "ok"
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let gw = app_with_cluster(addr, None);
    let res = gw
        .oneshot(
            Request::get("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .header(header::CONNECTION, "x-internal-secret")
                .header("x-internal-secret", "sensitive")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let seen = log.lock().unwrap();
    assert_eq!(
        seen[0].method, "false",
        "Connection-nominated header must be stripped southbound"
    );
}

#[tokio::test]
async fn southbound_redirects_are_not_followed() {
    // A 302 from the cluster must pass through raw — following it would
    // make the gateway an SSRF amplifier.
    let app = Router::new().fallback(|| async {
        (
            StatusCode::FOUND,
            [(header::LOCATION, "http://169.254.169.254/latest/meta-data/")],
            "",
        )
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let gw = app_with_cluster(addr, None);
    let res = gw
        .oneshot(
            Request::get("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FOUND, "3xx must pass through");
    assert!(res.headers().get(header::LOCATION).is_some());
}
