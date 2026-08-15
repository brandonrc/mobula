//! HTTP API surface of the Mobula control plane.
//!
//! Everything the UI/CLI can do goes through this versioned API — no hidden
//! admin paths. The Ray Jobs gateway (Phase 1) mounts here as well, one base
//! path per cluster.

pub mod auth_layer;
pub mod gateway;

use std::sync::Arc;

use axum::{routing::any, routing::get, Json, Router};
use mobula_auth::Validator;
use mobula_core::ClusterRegistry;
use serde::Serialize;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

/// OpenAPI document, aggregated from `#[utoipa::path]` decorators on the
/// handlers below. Every new control-plane endpoint MUST carry the
/// decorator and register here — /docs and /api/v1/openapi.json are the
/// API contract users see.
#[derive(OpenApi)]
#[openapi(
    paths(healthz, version),
    components(schemas(VersionInfo)),
    info(
        title = "Mobula",
        description = "FOSS control plane for Ray clusters. Cluster-bound \
        traffic (the Ray Jobs API) is served by hostname, not documented \
        here: each registered cluster's hostname exposes Ray's own \
        /api/jobs/ surface through the federating gateway.",
        license(name = "Apache-2.0")
    )
)]
struct ApiDoc;

#[derive(Serialize, ToSchema)]
struct VersionInfo {
    /// Always "mobula".
    #[schema(example = "mobula")]
    name: &'static str,
    /// Control-plane semver.
    #[schema(example = "0.0.1")]
    version: &'static str,
}

/// Liveness/readiness probe.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "system",
    responses((status = 200, description = "Control plane is up", body = str))
)]
async fn healthz() -> &'static str {
    "ok"
}

/// Control-plane identity and version.
#[utoipa::path(
    get,
    path = "/api/v1/version",
    tag = "system",
    responses((status = 200, description = "Name and semver", body = VersionInfo))
)]
async fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        name: "mobula",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Build the control-plane router with no gateway clusters and no authn
/// (dev/test convenience).
pub fn build_router() -> Router {
    build_app(ClusterRegistry::default(), None)
}

/// Build the full app: control-plane routes plus the federating job
/// gateway. Layer order matters and is enforced here:
/// 1. auth middleware (outermost) — deny-by-default when a validator is
///    configured; cluster hosts are never public (ADR-0003),
/// 2. gateway host dispatch — runs before route matching so a cluster
///    hostname can't be shadowed by a control-plane path,
/// 3. routes + fallback.
pub fn build_app(registry: ClusterRegistry, validator: Option<Arc<Validator>>) -> Router {
    let registry = Arc::new(registry);
    let gw = gateway::GatewayState::new(registry.clone());
    let auth = auth_layer::AuthState {
        validator,
        registry,
    };
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/api/v1/openapi.json", ApiDoc::openapi()))
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version))
        .route("/api/v1/authz/check", any(auth_layer::authz_check))
        // Fallback is registered before the layers so gateway dispatch
        // also wraps unmatched paths — cluster traffic like /api/jobs/
        // has no control-plane route and must still hit the middleware.
        .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(
            gw,
            gateway::host_gateway,
        ))
        .layer(axum::middleware::from_fn_with_state(
            auth.clone(),
            auth_layer::require_auth,
        ))
        .with_state(auth)
}

/// Serve the API until ctrl-c.
pub async fn serve(
    addr: std::net::SocketAddr,
    registry: ClusterRegistry,
    validator: Option<Arc<Validator>>,
) -> std::io::Result<()> {
    serve_with_shutdown(addr, registry, validator, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serve the API until `shutdown` resolves. Split from [`serve`] so tests
/// (and future embedders) control the lifecycle.
pub async fn serve_with_shutdown(
    addr: std::net::SocketAddr,
    registry: ClusterRegistry,
    validator: Option<Arc<Validator>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "mobula-api listening");
    axum::serve(listener, build_app(registry, validator))
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
            None,
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
    async fn openapi_document_covers_registered_paths() {
        let res = build_router()
            .oneshot(
                Request::get("/api/v1/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(doc["info"]["title"], "Mobula");
        assert!(doc["paths"]["/healthz"].is_object());
        assert!(doc["paths"]["/api/v1/version"].is_object());
        assert!(doc["components"]["schemas"]["VersionInfo"].is_object());
    }

    #[tokio::test]
    async fn swagger_ui_is_served() {
        let res = build_router()
            .oneshot(Request::get("/docs/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
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
