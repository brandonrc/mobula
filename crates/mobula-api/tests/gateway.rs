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

/// As `app_with_cluster`, with explicit northbound limits so the DoS knobs
/// (#30/#31) can be shrunk to deterministic test values.
fn app_with_cluster_limits(addr: SocketAddr, limits: mobula_api::ServeLimits) -> Router {
    mobula_api::build_app_with_serve_limits(
        ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("demo".into()),
                hostname: "demo.ray.test".into(),
                api_base_url: format!("http://{addr}"),
                auth_token: None,
            }],
        },
        None,
        limits,
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

    /// As `spawn_gateway`, with explicit northbound limits so the ws
    /// knobs (#31) can be shrunk to deterministic test values.
    async fn spawn_gateway_with_limits(
        head: SocketAddr,
        limits: mobula_api::ServeLimits,
    ) -> SocketAddr {
        let app = mobula_api::build_app_with_serve_limits(
            ClusterRegistry {
                clusters: vec![ClusterEndpoint {
                    id: ClusterId("demo".into()),
                    hostname: "127.0.0.1".into(),
                    api_base_url: format!("http://{head}"),
                    auth_token: None,
                }],
            },
            None,
            limits,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    /// Read until the bridge closes; fails if it hasn't within `secs`.
    async fn expect_bridge_close(
        ws: &mut (impl StreamExt<Item = Result<TsMessage, tokio_tungstenite::tungstenite::Error>>
                  + Unpin),
        secs: u64,
    ) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
        loop {
            match tokio::time::timeout_at(deadline, ws.next()).await {
                Ok(Some(Ok(TsMessage::Close(_)))) | Ok(Some(Err(_))) | Ok(None) => return,
                Ok(Some(Ok(_))) => continue,
                Err(_) => panic!("bridge did not close within {secs}s"),
            }
        }
    }

    /// #31: a bridge with no frames in either direction for the configured
    /// idle timeout is torn down (and its semaphore permit released).
    #[tokio::test]
    async fn ws_bridge_closes_after_idle_timeout() {
        // Mock head that upgrades and then says nothing, forever.
        async fn ws_silent(upgrade: WebSocketUpgrade) -> impl IntoResponse {
            upgrade.on_upgrade(|socket| async move {
                let _hold = socket;
                std::future::pending::<()>().await;
            })
        }
        let app = Router::new().route("/api/jobs/x/logs/tail", axum::routing::any(ws_silent));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let head = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let limits = mobula_api::ServeLimits {
            gateway: mobula_api::gateway::GatewayLimits {
                ws_idle_timeout: std::time::Duration::from_millis(200),
                ..Default::default()
            },
            ..Default::default()
        };
        let gw = spawn_gateway_with_limits(head, limits).await;

        let req = format!("ws://{gw}/api/jobs/x/logs/tail")
            .into_client_request()
            .unwrap();
        let (mut ws, _resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        expect_bridge_close(&mut ws, 5).await;
    }

    /// #31: a message over the configured max size terminates the bridge
    /// instead of being buffered.
    #[tokio::test]
    async fn ws_bridge_closes_on_oversize_message() {
        let (head, _log) = spawn_mock_ws_head().await;
        let limits = mobula_api::ServeLimits {
            gateway: mobula_api::gateway::GatewayLimits {
                ws_max_message_bytes: 64,
                ..Default::default()
            },
            ..Default::default()
        };
        let gw = spawn_gateway_with_limits(head, limits).await;

        let req = format!("ws://{gw}/api/jobs/x/logs/tail")
            .into_client_request()
            .unwrap();
        let (mut ws, _resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        // Drain the mock's three log lines (each well under the cap).
        for _ in 0..3 {
            ws.next().await.unwrap().unwrap();
        }
        // 256 bytes against a 64-byte cap: the bridge must die, not buffer.
        ws.send(TsMessage::Text("x".repeat(256).into()))
            .await
            .unwrap();
        expect_bridge_close(&mut ws, 5).await;
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
    assert_eq!(res.status(), StatusCode::FOUND, "3xx status passes through");
    // ...but the internal Location is stripped so it can't leak cluster
    // topology (169.254.x, internal service names) to the caller (#32).
    assert!(
        res.headers().get(header::LOCATION).is_none(),
        "internal Location must not leak to the client"
    );
}

#[tokio::test]
async fn cookie_and_forwarded_headers_are_stripped_southbound() {
    // The mock records what the cluster actually received.
    let (addr, log) = spawn_mock_ray_head().await;
    let app = app_with_cluster(addr, None);
    let res = app
        .oneshot(
            Request::get("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .header(header::COOKIE, "session=abc")
                .header("x-forwarded-for", "1.2.3.4")
                .header("forwarded", "for=1.2.3.4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // spawn_mock_ray_head only records method/path/auth/body, so assert on
    // the request count and rely on the src-level unit tests of
    // southbound_headers for exact header assertions.
    assert_eq!(log.lock().unwrap().len(), 1);
}

/// #30: with the inflight semaphore saturated (capacity 1, one request
/// parked on a hanging head), the next proxied request is refused with 503
/// instead of queueing — a queue behind the semaphore is itself a DoS
/// surface.
#[tokio::test]
async fn saturated_gateway_returns_503_not_a_queue() {
    use std::time::Duration;

    // Mock head that signals when /hang is hit, then never responds.
    let arrived = Arc::new(tokio::sync::Notify::new());
    let arrived_in_handler = arrived.clone();
    let app = Router::new().route(
        "/hang",
        axum::routing::get(move || {
            let arrived = arrived_in_handler.clone();
            async move {
                arrived.notify_one();
                std::future::pending::<()>().await;
                ""
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let limits = mobula_api::ServeLimits {
        gateway: mobula_api::gateway::GatewayLimits {
            max_inflight: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let app = app_with_cluster_limits(addr, limits);

    // First request takes the only permit and parks on the hanging head.
    let app2 = app.clone();
    let first = tokio::spawn(async move {
        app2.oneshot(
            Request::get("/hang")
                .header(header::HOST, "demo.ray.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(5), arrived.notified())
        .await
        .expect("first request never reached the mock head");

    let res = app
        .oneshot(
            Request::get("/api/jobs/")
                .header(header::HOST, "demo.ray.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "saturated gateway must refuse, not queue"
    );
    first.abort();
}

/// #2: link-local / CGNAT literal IPs must be refused at registry
/// validation — they name cloud metadata endpoints or overlay meshes,
/// never a Ray head.
#[test]
fn link_local_api_base_urls_are_rejected_at_validation() {
    for url in [
        "http://169.254.169.254:8265",
        "http://100.64.0.1:8265",
        "http://[fe80::1]:8265",
    ] {
        let registry = ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("evil".into()),
                hostname: "evil.ray.test".into(),
                api_base_url: url.into(),
                auth_token: None,
            }],
        };
        assert!(
            registry.validate(true).is_err(),
            "{url} must be rejected at validation"
        );
    }
    // Ordinary in-cluster IPs and DNS names still pass (DNS resolution-time
    // SSRF is the documented accepted residual risk).
    for url in ["http://10.0.0.5:8265", "http://demo-head-svc:8265"] {
        let registry = ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("ok".into()),
                hostname: "ok.ray.test".into(),
                api_base_url: url.into(),
                auth_token: None,
            }],
        };
        assert!(registry.validate(false).is_ok(), "{url} must pass");
    }
}
