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

/// Serve the API until shutdown signal.
pub async fn serve(addr: std::net::SocketAddr, registry: ClusterRegistry) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "mobula-api listening");
    axum::serve(listener, build_app(registry))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
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
