//! HTTP API surface of the Mobula control plane.
//!
//! Everything the UI/CLI can do goes through this versioned API — no hidden
//! admin paths. The Ray Jobs gateway (Phase 1) mounts here as well, one base
//! path per cluster.

pub mod auth_layer;
pub mod clusters;
pub mod gateway;
pub mod pools;
pub mod services;
pub mod usage;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
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
    paths(
        healthz,
        version,
        clusters::list_clusters,
        clusters::get_cluster,
        clusters::create_cluster,
        clusters::delete_cluster,
        clusters::list_jobs,
        pools::list_pools,
        pools::get_pool,
        pools::create_pool,
        pools::delete_pool,
        pools::pool_usage,
        pools::put_allocation,
        pools::list_allocations,
        pools::delete_allocation,
        usage::usage_report,
        usage::metrics,
        services::list_services,
        services::get_service,
        services::deploy_service,
        services::delete_service,
    ),
    components(
        schemas(
            VersionInfo,
            clusters::CreateCluster,
            clusters::ClusterView,
            clusters::JobView,
            pools::CreatePool,
            pools::PoolView,
            pools::PoolUsageView,
            pools::ResourceUtilization,
            pools::PutAllocation,
            usage::UsageReport,
            usage::UsageGroup,
            services::DeployService,
            services::ServiceView,
            mobula_core::ClusterSpec,
            mobula_core::WorkerGroup,
            mobula_core::ClusterState,
            mobula_core::ServiceSpec,
            mobula_core::UpgradeStrategy,
            mobula_core::PoolSpec,
            mobula_core::FlavorSpec,
            mobula_core::TaintSpec,
            mobula_core::AllocationSpec,
        )
    ),
    modifiers(&BearerAuth),
    tags(
        (name = "system", description = "Health and version probes."),
        (name = "clusters", description = "Cluster lifecycle. Reads need any \
         authenticated role; create/terminate need Write on the cluster \
         target (Operator or Admin). Mounted only when the lifecycle \
         controller is enabled (`serve --kuberay-namespace`)."),
        (name = "services", description = "Ray Serve services (RayService). \
         Deploy/update/delete need Write on the service target \
         (Developer or Admin — deploying is code); reads are open to any \
         authenticated role. KubeRay handles zero-downtime canary rollout."),
        (name = "pools", description = "Capacity pools and per-project \
         allocations (ADR-0010): platform configuration, not app lifecycle. \
         Reads need any authenticated role; create/delete/allocation \
         mutations are Admin-only. Mounted only when a store is configured."),
        (name = "usage", description = "Usage metering (Slice 4): \
         resource-hours reports and the Prometheus gauge over the metered \
         samples. Reads need Read on the cluster target (Viewer+) — \
         consumption reporting is cluster data, not pool topology. Mounted \
         only when a store is configured."),
    ),
    info(
        title = "Mobula",
        description = "FOSS control plane for Ray clusters. All endpoints \
        take a Bearer JWT (OIDC). Note: the Ray Jobs API is NOT documented \
        here — it is served by hostname, each registered cluster's hostname \
        proxying Ray's own /api/jobs/ surface through the federating \
        gateway. This spec covers Mobula's own control-plane routes.",
        license(name = "Apache-2.0")
    )
)]
struct ApiDoc;

/// Adds the `bearer` HTTP security scheme so generated clients know every
/// route expects `Authorization: Bearer <jwt>`.
struct BearerAuth;

impl utoipa::Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

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
///
/// Gated behind `test-util`/`test`: it defaults `validator = None`, which
/// bypasses auth, so it must never be reachable in a production build. Use
/// [`serve`]/[`serve_with_shutdown`], which carry the fail-closed guards
/// (#45).
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
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
///
/// Gated behind `test-util`/`test`: `validator = None` bypasses auth (#45).
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub fn build_app(registry: ClusterRegistry, validator: Option<Arc<Validator>>) -> Router {
    build_app_full(registry, validator, None, Default::default())
}

/// Build the full app. When a `store` is provided, the cluster lifecycle
/// routes (`/api/v1/clusters`) are mounted (Phase 3). Layer order matters:
/// 1. auth middleware (outermost) — attaches identity, enforces the Job
///    permission for proxied cluster-host traffic (ADR-0003),
/// 2. gateway host dispatch — before route matching so a cluster hostname
///    can't be shadowed by a control-plane path,
/// 3. routes + fallback.
///
/// Gated behind `test-util`/`test`: `validator = None` bypasses auth (#45).
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub fn build_app_full(
    registry: ClusterRegistry,
    validator: Option<Arc<Validator>>,
    store: Option<Arc<dyn mobula_controller::Store>>,
    policy: clusters::PolicyConfig,
) -> Router {
    build_app_full_svc(registry, validator, store, policy, None)
}

/// As [`build_app_full`], plus an optional Serve-service provisioner; when
/// present, the `/api/v1/services` routes are mounted.
///
/// Gated behind `test-util`/`test`: it defaults `allow_unauthenticated = true`
/// so it never installs the fail-closed guard, which is wrong for production.
/// Production goes through [`serve_with_shutdown`] →
/// [`build_app_full_svc_inner`] with the caller's real `allow_unauthenticated`
/// (#45).
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn build_app_full_svc(
    registry: ClusterRegistry,
    validator: Option<Arc<Validator>>,
    store: Option<Arc<dyn mobula_controller::Store>>,
    policy: clusters::PolicyConfig,
    services: Option<Arc<dyn mobula_provision::ServiceProvisioner>>,
) -> Router {
    build_app_full_svc_inner(registry, validator, store, policy, services, true)
}

/// Router-level fail-closed guard (#45, moving #36's invariant into the
/// router): when no validator is configured, refuse any request whose peer
/// isn't loopback so a direct `axum::serve(build_...())` also fails closed
/// for remote clients, regardless of bind address. If connect-info is absent
/// we cannot prove the peer is loopback, so we refuse — this is the outermost
/// layer.
async fn refuse_non_loopback(req: Request, next: Next) -> Response {
    let is_loopback = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);
    if !is_loopback {
        tracing::warn!(
            target: "mobula::audit",
            decision = "deny", reason = "unauthenticated_non_loopback",
            "refusing non-loopback request: no authentication is configured"
        );
        return (
            StatusCode::FORBIDDEN,
            "no authentication is configured; non-loopback access is refused",
        )
            .into_response();
    }
    next.run(req).await
}

/// The real router builder. `allow_unauthenticated` decides whether the
/// fail-closed guard is installed: when a validator is present it is never
/// needed; when absent and NOT explicitly allowed, the outermost
/// [`refuse_non_loopback`] layer keeps the control plane closed to remote
/// peers even if an embedder `axum::serve`s this router directly.
#[allow(clippy::too_many_arguments)]
fn build_app_full_svc_inner(
    registry: ClusterRegistry,
    validator: Option<Arc<Validator>>,
    store: Option<Arc<dyn mobula_controller::Store>>,
    policy: clusters::PolicyConfig,
    services: Option<Arc<dyn mobula_provision::ServiceProvisioner>>,
    allow_unauthenticated: bool,
) -> Router {
    let registry = Arc::new(registry);
    let gw = gateway::GatewayState::new(registry.clone());
    let fail_closed = validator.is_none() && !allow_unauthenticated;
    let auth = auth_layer::AuthState {
        validator,
        registry,
    };
    // Resolve each sub-router's own state before merging (they differ:
    // AuthState vs ClusterApiState), then apply the shared layers to the
    // state-complete router.
    let mut app = Router::new()
        .merge(SwaggerUi::new("/docs").url("/api/v1/openapi.json", ApiDoc::openapi()))
        .route("/healthz", get(healthz))
        .route("/api/v1/version", get(version))
        .route("/api/v1/authz/check", any(auth_layer::authz_check))
        .with_state(auth.clone());
    if let Some(store) = store {
        let policy = Arc::new(policy);
        app = app
            .merge(clusters::router(store.clone(), policy.clone()))
            .merge(pools::router(store.clone()))
            .merge(usage::router(store, policy));
    }
    if let Some(services) = services {
        app = app.merge(services::router(services));
    }
    let app = app
        // Fallback is registered before the layers so gateway dispatch
        // also wraps unmatched paths — cluster traffic like /api/jobs/
        // has no control-plane route and must still hit the middleware.
        .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(
            gw,
            gateway::host_gateway,
        ))
        .layer(axum::middleware::from_fn_with_state(
            auth,
            auth_layer::require_auth,
        ));
    // Outermost when installed: applied last so it wraps auth + gateway.
    if fail_closed {
        app.layer(axum::middleware::from_fn(refuse_non_loopback))
    } else {
        app
    }
}

/// Everything [`serve`] needs, including the fail-closed switches. Kept in
/// one struct so the invariants live in the library, not only the CLI —
/// any embedder (or the Phase 3 lifecycle controller) calling `serve` gets
/// the same guards (#36).
pub struct ServeOptions {
    pub registry: ClusterRegistry,
    pub validator: Option<Arc<Validator>>,
    /// Permit binding a non-loopback address with no validator configured.
    pub allow_unauthenticated: bool,
    /// Permit cluster tokens over cleartext http:// (registry validation).
    pub allow_insecure_transport: bool,
    /// Desired-state store; when present, the cluster lifecycle routes
    /// (`/api/v1/clusters`) and capacity-pool routes (`/api/v1/pools`) are
    /// mounted. The caller owns the reconcile loop.
    pub store: Option<Arc<dyn mobula_controller::Store>>,
    /// Cost/quota governance for the cluster routes (Phase 4). Default =
    /// no cost shown, no quota enforced.
    pub policy: clusters::PolicyConfig,
    /// Serve-service provisioner; when present, the `/api/v1/services`
    /// routes are mounted (Phase 4).
    pub services: Option<Arc<dyn mobula_provision::ServiceProvisioner>>,
}

/// Serve the API until ctrl-c.
pub async fn serve(addr: std::net::SocketAddr, opts: ServeOptions) -> std::io::Result<()> {
    serve_with_shutdown(addr, opts, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serve the API until `shutdown` resolves. Enforces the fail-closed
/// invariants (#36) before binding: registry validation, and a refusal to
/// expose an unauthenticated gateway on a non-loopback address.
pub async fn serve_with_shutdown(
    addr: std::net::SocketAddr,
    opts: ServeOptions,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    opts.registry
        .validate(opts.allow_insecure_transport)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    if opts.validator.is_none() && !addr.ip().is_loopback() && !opts.allow_unauthenticated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to bind {addr}: no authentication is configured, so a \
                 non-loopback bind exposes every registered cluster to unauthenticated \
                 code execution. Configure a validator, or set allow_unauthenticated."
            ),
        ));
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "mobula-api listening");
    // ConnectInfo must be populated for the router-level fail-closed guard
    // (#45) to distinguish loopback from remote peers.
    let app = build_app_full_svc_inner(
        opts.registry,
        opts.validator,
        opts.store,
        opts.policy,
        opts.services,
        opts.allow_unauthenticated,
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
            super::ServeOptions {
                registry: ClusterRegistry::default(),
                validator: None,
                allow_unauthenticated: true,
                allow_insecure_transport: true,
                store: None,
                policy: Default::default(),
                services: None,
            },
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
        // The cluster lifecycle contract the UI generates against.
        assert!(doc["paths"]["/api/v1/clusters"]["get"].is_object());
        assert!(doc["paths"]["/api/v1/clusters"]["post"].is_object());
        assert!(doc["paths"]["/api/v1/clusters/{id}"]["delete"].is_object());
        assert!(doc["components"]["schemas"]["ClusterView"].is_object());
        assert!(doc["components"]["schemas"]["ClusterSpec"].is_object());
        assert!(doc["components"]["schemas"]["WorkerGroup"].is_object());
        // The capacity-pool contract (ADR-0010).
        assert!(doc["paths"]["/api/v1/pools"]["get"].is_object());
        assert!(doc["paths"]["/api/v1/pools"]["post"].is_object());
        assert!(doc["paths"]["/api/v1/pools/{name}"]["delete"].is_object());
        assert!(doc["paths"]["/api/v1/pools/{name}/allocations/{project}"]["put"].is_object());
        assert!(doc["components"]["schemas"]["PoolView"].is_object());
        assert!(doc["components"]["schemas"]["PoolSpec"].is_object());
        // The usage/metering contract (Slice 4).
        assert!(doc["paths"]["/api/v1/pools/{name}/usage"]["get"].is_object());
        assert!(doc["paths"]["/api/v1/usage"]["get"].is_object());
        assert!(doc["paths"]["/api/v1/metrics"]["get"].is_object());
        assert!(doc["components"]["schemas"]["UsageReport"].is_object());
        assert!(doc["components"]["schemas"]["PoolUsageView"].is_object());
        // Bearer security scheme is advertised for client codegen.
        assert_eq!(
            doc["components"]["securitySchemes"]["bearer"]["scheme"],
            "bearer"
        );
    }

    /// Emit the OpenAPI document to `openapi.json` at the repo root so
    /// mobula-ui (and its codegen) can vendor a committed contract without
    /// running the server. Run with `cargo test -p mobula-api export_openapi`.
    #[test]
    fn export_openapi() {
        let json = serde_json::to_string_pretty(&ApiDoc::openapi()).unwrap();
        // CARGO_MANIFEST_DIR = crates/mobula-api; write to the workspace root.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        std::fs::write(root.join("openapi.json"), json + "\n").unwrap();
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

    /// A well-formed cluster create body (passes deserialization so the
    /// request reaches the guard/handler rather than 400-ing on parse).
    fn cluster_create_body() -> String {
        serde_json::json!({
            "id": "c1",
            "spec": {
                "name": "c1", "project": "demo", "ray_version": "2.57.0",
                "image": "rayproject/ray:2.57.0", "head_cpu": "1",
                "head_memory": "2Gi", "worker_groups": [], "ttl_seconds": null
            }
        })
        .to_string()
    }

    fn with_peer(mut req: Request<Body>, ip: &str) -> Request<Body> {
        let addr: SocketAddr = format!("{ip}:40000").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    /// #45: the PRODUCTION router path (inner builder, validator=None, not
    /// allow_unauthenticated) must fail closed for a non-loopback peer even
    /// on a protected route with a well-formed body.
    #[tokio::test]
    async fn no_validator_router_denies_protected_route() {
        let store = Arc::new(mobula_controller::InMemoryStore::new());
        let app = build_app_full_svc_inner(
            ClusterRegistry::default(),
            None,
            Some(store),
            Default::default(),
            None,
            false,
        );
        let req = with_peer(
            Request::post("/api/v1/clusters")
                .header("content-type", "application/json")
                .body(Body::from(cluster_create_body()))
                .unwrap(),
            "203.0.113.7",
        );
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// #45: a non-loopback peer with no validator is refused (connect-info
    /// present, remote IP).
    #[tokio::test]
    async fn no_validator_non_loopback_peer_is_refused() {
        let app = build_app_full_svc_inner(
            ClusterRegistry::default(),
            None,
            None,
            Default::default(),
            None,
            false,
        );
        let req = with_peer(
            Request::get("/healthz").body(Body::empty()).unwrap(),
            "203.0.113.9",
        );
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    /// #45: a loopback peer is still served with no validator — guards
    /// against the guard false-positiving on legitimate local traffic.
    #[tokio::test]
    async fn no_validator_loopback_peer_still_served() {
        let app = build_app_full_svc_inner(
            ClusterRegistry::default(),
            None,
            None,
            Default::default(),
            None,
            false,
        );
        let req = with_peer(
            Request::get("/healthz").body(Body::empty()).unwrap(),
            "127.0.0.1",
        );
        let res = app.oneshot(req).await.unwrap();
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
