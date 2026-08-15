//! Federating job gateway (Phase 1, ADR-0002).
//!
//! Requests whose Host header matches a registered cluster are proxied to
//! that cluster's native Ray dashboard/job API, with the cluster's static
//! Ray token injected southbound (ADR-0003). Everything else falls through
//! to the control-plane routes. Host matching runs as middleware *before*
//! route matching so a cluster hostname can never be shadowed by a
//! control-plane path.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use mobula_core::{ClusterEndpoint, ClusterRegistry};

/// Request bodies are buffered before forwarding; job submissions are tiny
/// and runtime-env package uploads are capped by Ray itself. Streaming
/// upload passthrough is a follow-up.
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Header carrying the cluster's static Ray token (Ray >= 2.52 token
/// auth). Pinned by the contract-test suite against each supported Ray
/// minor; if Ray renames it, the matrix job fails, not production.
const RAY_AUTH_HEADER: header::HeaderName = header::AUTHORIZATION;

#[derive(Clone)]
pub struct GatewayState {
    registry: Arc<ClusterRegistry>,
    client: reqwest::Client,
}

impl GatewayState {
    pub fn new(registry: ClusterRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            client: reqwest::Client::new(),
        }
    }
}

/// Middleware: route by Host header, proxying registered cluster hosts.
pub async fn host_gateway(State(gw): State<GatewayState>, req: Request, next: Next) -> Response {
    let cluster = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| gw.registry.by_hostname(h))
        .cloned();

    match cluster {
        Some(cluster) => proxy(&gw, &cluster, req).await.into_response(),
        None => next.run(req).await,
    }
}

async fn proxy(
    gw: &GatewayState,
    cluster: &ClusterEndpoint,
    req: Request,
) -> Result<Response, GatewayError> {
    let (parts, body) = req.into_parts();

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!(
        "{}{}",
        cluster.api_base_url.trim_end_matches('/'),
        path_and_query
    );

    let body = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| GatewayError::BodyTooLarge)?;

    let mut headers = southbound_headers(&parts.headers);
    if let Some(token) = &cluster.auth_token {
        let value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| GatewayError::BadToken)?;
        headers.insert(RAY_AUTH_HEADER, value);
    }

    let upstream = gw
        .client
        .request(parts.method, &url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|e| GatewayError::Upstream(cluster.id.to_string(), e.to_string()))?;

    let status = upstream.status();
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream.headers() {
        if !is_hop_by_hop(name) {
            response_headers.insert(name.clone(), value.clone());
        }
    }

    let mut response = Response::builder()
        .status(status)
        .body(Body::from_stream(upstream.bytes_stream()))
        .expect("valid response");
    *response.headers_mut() = response_headers;
    Ok(response)
}

/// Copy client headers southbound, dropping hop-by-hop headers, the
/// northbound Host, and any inbound Authorization — the caller's identity
/// must never reach the cluster; only the injected Ray token does.
fn southbound_headers(inbound: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in inbound {
        if is_hop_by_hop(name)
            || name == header::HOST
            || name == header::AUTHORIZATION
            || name == header::CONTENT_LENGTH
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    headers
}

fn is_hop_by_hop(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

enum GatewayError {
    BodyTooLarge,
    BadToken,
    Upstream(String, String),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        match self {
            GatewayError::BodyTooLarge => {
                (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response()
            }
            GatewayError::BadToken => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "cluster auth token is not a valid header value",
            )
                .into_response(),
            GatewayError::Upstream(cluster, err) => {
                tracing::warn!(%cluster, error = %err, "upstream request failed");
                (StatusCode::BAD_GATEWAY, "cluster unreachable").into_response()
            }
        }
    }
}
