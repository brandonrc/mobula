//! Per-cluster Ray metrics passthrough (#52, first slice).
//!
//! `GET /api/v1/clusters/{id}/metrics` proxies the Ray head's Prometheus
//! exposition (`/metrics` on the dashboard port) through the control plane
//! with the gateway's credential discipline (ADR-0003, `gateway::proxy`):
//! the outbound request is built from scratch — no inbound header is
//! forwarded, so the caller's JWT can never leak southbound — and the only
//! credential injected is the cluster's static token from the registry.
//!
//! The head URL comes from
//! [`mobula_provision::Provisioner::metrics_endpoint`] — a
//! control-plane-computed service DNS name, not user input, so the route
//! inherits the registry's SSRF posture rather than adding a new attack
//! surface. A backend that can't name an endpoint (the demo provisioner)
//! yields a clean 404 `metrics unavailable`.
//!
//! Deliberately out of scope for this slice (the #52 epic's future work):
//! SSE/event streaming and OpenTelemetry export.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use futures::StreamExt;
use mobula_auth::{Identity, PermissionType, Target};
use mobula_controller::Store;
use mobula_core::{ClusterId, ClusterRegistry};
use mobula_provision::Provisioner;

use crate::auth_layer::authorize;

/// Southbound connect timeout: a wedged head must not hang a scrape.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Southbound total-request timeout (effectively the read cap for a GET).
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on the proxied exposition body: a Ray head can emit megabytes of
/// per-task/per-actor series, and a misconfigured one must not stream
/// unbounded memory into the control plane.
const MAX_METRICS_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct MetricsApiState {
    /// For the authz check (`Read` on `Target::Cluster`, Viewer+).
    pub store: Arc<dyn Store>,
    /// The gateway's routing table — source of the cluster's static token.
    pub registry: Arc<ClusterRegistry>,
    /// `None` on deployments with no cluster backend (gateway-only): the
    /// route stays mounted and answers 404 `metrics unavailable`.
    pub provisioner: Option<Arc<dyn Provisioner>>,
    client: reqwest::Client,
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

#[utoipa::path(
    get, path = "/api/v1/clusters/{id}/metrics", tag = "clusters",
    params(("id" = String, Path, description = "Cluster id")),
    responses((status = 200, description = "The Ray head's Prometheus exposition, proxied verbatim", body = String, content_type = "text/plain"),
              (status = 401, description = "No/invalid token"),
              (status = 403, description = "Missing Read on cluster"),
              (status = 404, description = "Metrics unavailable: the backend exposes no metrics endpoint for this cluster"),
              (status = 502, description = "The Ray head could not be reached or its response exceeded the 4MiB cap")),
    security(("bearer" = []))
)]
async fn cluster_metrics(
    State(st): State<MetricsApiState>,
    identity: Option<Extension<Identity>>,
    Path(id): Path<String>,
) -> Response {
    // Metrics of a cluster read like cluster data: Read on Target::Cluster
    // (Viewer+), the same permission as the cluster itself.
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Read,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    let id = ClusterId(id);
    let url = st
        .provisioner
        .as_ref()
        .and_then(|p| p.metrics_endpoint(&id));
    let Some(url) = url else {
        return (StatusCode::NOT_FOUND, "metrics unavailable").into_response();
    };

    let mut req = st.client.get(&url);
    if let Some(token) = st.registry.by_id(&id).and_then(|e| e.auth_token.as_ref()) {
        match HeaderValue::from_str(&format!("Bearer {token}")) {
            Ok(v) => req = req.header(header::AUTHORIZATION, v),
            // A token that isn't a legal header value is a config error,
            // not a cluster problem — fail closed rather than scrape
            // unauthenticated.
            Err(_) => {
                tracing::warn!(cluster = %id.0, "registry token is not a legal header value");
                return (StatusCode::INTERNAL_SERVER_ERROR, "invalid cluster token")
                    .into_response();
            }
        }
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            // without_url(): reqwest error strings can embed the full
            // southbound URL — keep internal topology out of logs (#5).
            tracing::warn!(cluster = %id.0, error = %e.without_url(), "metrics upstream error");
            return (StatusCode::BAD_GATEWAY, "metrics upstream error").into_response();
        }
    };
    let status = upstream.status();

    // Buffer with a hard cap rather than streaming: the exposition is
    // bounded in practice and the cap turns an unbounded one into a 502.
    let mut body = Vec::new();
    let mut stream = upstream.bytes_stream();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if body.len() + bytes.len() > MAX_METRICS_BYTES {
                    tracing::warn!(
                        cluster = %id.0,
                        cap = MAX_METRICS_BYTES,
                        "metrics response exceeded the size cap"
                    );
                    return (StatusCode::BAD_GATEWAY, "metrics response too large").into_response();
                }
                body.extend_from_slice(&bytes);
            }
            Err(e) => {
                tracing::warn!(cluster = %id.0, error = %e.without_url(), "metrics stream error");
                return (StatusCode::BAD_GATEWAY, "metrics upstream error").into_response();
            }
        }
    }

    (
        status,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

pub fn router(
    store: Arc<dyn Store>,
    registry: Arc<ClusterRegistry>,
    provisioner: Option<Arc<dyn Provisioner>>,
) -> Router {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(READ_TIMEOUT)
        // Redirects are never followed southbound (same posture as the
        // gateway): a 3xx Location would carry internal service names/IPs.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("static client config builds");
    Router::new()
        .route("/api/v1/clusters/{id}/metrics", get(cluster_metrics))
        .with_state(MetricsApiState {
            store,
            registry,
            provisioner,
            client,
        })
}
