//! HTTP API surface of the Mobula control plane.
//!
//! Everything the UI/CLI can do goes through this versioned API — no hidden
//! admin paths. The Ray Jobs gateway (Phase 1) mounts here as well, one base
//! path per cluster.

pub mod gateway;

use axum::{routing::get, Json, Router};
use mobula_core::ClusterRegistry;
use serde::Serialize;

#[derive(Serialize)]
struct VersionInfo {
    name: &'static str,
    version: &'static str,
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        name: "mobula",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Build the control-plane router with no gateway clusters registered.
pub fn build_router() -> Router {
    build_app(ClusterRegistry::default())
}

/// Build the full app: control-plane routes plus the federating job
/// gateway. Host-based dispatch runs before route matching, so requests
/// addressed to a registered cluster hostname are proxied even if their
/// path collides with a control-plane route.
pub fn build_app(registry: ClusterRegistry) -> Router {
    let gw = gateway::GatewayState::new(registry);
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version))
        // Fallback is registered before the layer so gateway dispatch also
        // wraps unmatched paths — cluster traffic like /api/jobs/ has no
        // control-plane route and must still hit the middleware.
        .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(
            gw,
            gateway::host_gateway,
        ))
}

/// Serve the API until ctrl-c.
pub async fn serve(addr: std::net::SocketAddr, registry: ClusterRegistry) -> std::io::Result<()> {
    serve_with_shutdown(addr, registry, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serve the API until `shutdown` resolves. Split from [`serve`] so tests
/// (and future embedders) control the lifecycle.
pub async fn serve_with_shutdown(
    addr: std::net::SocketAddr,
    registry: ClusterRegistry,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "mobula-api listening");
    axum::serve(listener, build_app(registry))
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_ok() {
        let res = build_router()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn serve_with_shutdown_binds_answers_and_stops() {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        // Port 0 picks an ephemeral port; rebind to discover it first.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let server = tokio::spawn(super::serve_with_shutdown(
            addr,
            ClusterRegistry::default(),
            async {
                let _ = rx.await;
            },
        ));

        // Wait for the listener, then hit /healthz over real TCP.
        let mut ok = false;
        for _ in 0..50 {
            if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                stream
                    .write_all(b"GET /healthz HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
                    .await
                    .unwrap();
                let mut buf = String::new();
                stream.read_to_string(&mut buf).await.unwrap();
                assert!(buf.starts_with("HTTP/1.1 200"), "{buf}");
                ok = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ok, "server never came up");

        tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unmatched_path_is_404() {
        let res = build_router()
            .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn version_reports_package_version() {
        let res = build_router()
            .oneshot(Request::get("/api/v1/version").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["name"], "mobula");
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }
}
