//! Identity-aware proxy (Phase 2, ADR-0003).
//!
//! Two enforcement paths, decided in ADR-0003:
//! - Nebari mode: Envoy `ext_authz` calls a stateless authz endpoint served
//!   by `mobula-api`; no second proxy hop in the Serve data path.
//! - Standalone mode: this crate is the inline proxy, deployed separately
//!   from the control plane so control-plane deploys can't interrupt
//!   inference traffic. It fronts ONE data-plane surface (a Ray dashboard
//!   or Serve endpoint) per instance: the caller's Bearer JWT is validated
//!   in-process (mobula-auth `Validator`), mapped identity→permission, and
//!   only then is the request reverse-proxied upstream — so "a dashboard
//!   URL is not a bypass" (REQUIREMENTS §3.7).
//!
//! The core exchange in both paths: Mobula holds each cluster's static Ray
//! token (Ray >= 2.52) and brokers per-user, SSO-authenticated,
//! RBAC-checked access on top of it. Here that exchange is the optional
//! `inject_header` (e.g. `authorization: Bearer <ray-token>`) applied
//! southbound after the caller's credential has been stripped.
//!
//! Scope discipline: this is a thin single-upstream proxy, NOT a second
//! gateway — multi-upstream host routing is the control plane's job
//! (`mobula-api::gateway`). The crate is library-only; the CLI/binary
//! wiring (`mobula proxy …`) is a deliberate follow-up.
//!
//! v0 exclusions (deliberate):
//! - No websocket support: any `Upgrade` request is refused with 501.
//!   Ray's job log tail is a websocket; standalone users needing it stay
//!   on the control-plane gateway until bridging lands here.
//! - Bodies are buffered (bounded by `max_body_bytes`), not streamed.

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Router};
use mobula_auth::{AuthConfig, AuthError, Identity, PermissionType, Target, Validator};

/// Default request-body cap: bodies are buffered before forwarding, so the
/// cap bounds per-request memory (64 MiB, mirroring the gateway).
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Southbound connect timeout: a black-holing upstream must not pin the
/// caller's connection forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Southbound read timeout — per read, so long responses (log streams)
/// stay alive as long as bytes flow.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Configuration for one proxy instance fronting ONE upstream.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the proxy listens on.
    pub listen: SocketAddr,
    /// Base URL of the single upstream surface (e.g. a Ray dashboard
    /// `http://ray-head:8265`); the request path+query is appended.
    pub upstream: String,
    /// OIDC issuer/audience/role mappings (mobula-auth).
    pub auth: AuthConfig,
    /// The permission every proxied request requires: `identity.permits`
    /// against this (verb, target) or the caller gets 403.
    pub required: (PermissionType, Target),
    /// Optional header injected southbound after the caller's credential
    /// is stripped — the token-to-identity exchange (ADR-0003): callers
    /// present SSO JWTs, the upstream sees only this (e.g. the cluster's
    /// static Ray token).
    pub inject_header: Option<(String, String)>,
    /// Permit `http://` OIDC issuers (cleartext JWKS fetch). Dev/test only —
    /// mirrors `Validator::discover`'s insecure-transport override.
    pub allow_insecure: bool,
    /// Buffered request-body cap; [`DEFAULT_MAX_BODY_BYTES`] in production.
    /// Tests shrink it to exercise the 413 path deterministically.
    pub max_body_bytes: usize,
}

/// Errors building the proxy (before it can serve).
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// OIDC discovery / initial JWKS fetch failed — fail fast, never boot
    /// into a state where tokens can't be validated.
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// `inject_header` name or value is not a valid HTTP header.
    #[error("inject_header is not a valid HTTP header: {0}")]
    InvalidInjectHeader(String),
}

#[derive(Clone)]
struct ProxyState {
    validator: Arc<Validator>,
    client: reqwest::Client,
    /// `config.upstream` with any trailing slash trimmed.
    upstream: String,
    required: (PermissionType, Target),
    inject: Option<(HeaderName, HeaderValue)>,
    max_body_bytes: usize,
}

/// Build the proxy router: runs OIDC discovery + initial JWKS fetch
/// (fails fast), then returns a `Router` with exactly one public route
/// (`GET /healthz`) and an authenticated fallback that proxies everything
/// else to the configured upstream.
pub async fn router(config: &ProxyConfig) -> Result<Router, ProxyError> {
    // Reverse-proxy posture (mirrors the gateway's discipline): never
    // follow redirects southbound (SSRF amplifier — a 3xx passes through
    // to the caller untouched) and bound how long a hung upstream can pin
    // a connection.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .build()
        .expect("static client config");

    let validator = Validator::discover(
        config.auth.clone(),
        mobula_auth::idp_client(),
        config.allow_insecure,
    )
    .await?;

    let inject = match &config.inject_header {
        Some((name, value)) => {
            let name = HeaderName::from_str(name)
                .map_err(|e| ProxyError::InvalidInjectHeader(e.to_string()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|e| ProxyError::InvalidInjectHeader(e.to_string()))?;
            Some((name, value))
        }
        None => None,
    };

    let state = ProxyState {
        validator: Arc::new(validator),
        client,
        upstream: config.upstream.trim_end_matches('/').to_string(),
        required: config.required,
        inject,
        max_body_bytes: config.max_body_bytes,
    };

    // Everything except the explicit healthz route lands on the protected
    // fallback: deny by default, no public path carving beyond the probe.
    let protected = Router::new()
        .fallback(proxy_request)
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Ok(Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .with_state(state))
}

/// Bind `config.listen` and serve until `shutdown` resolves (graceful).
pub async fn serve_proxy(
    config: ProxyConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let listen = config.listen;
    let upstream = config.upstream.clone();
    let app = router(&config).await.map_err(io::Error::other)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, %upstream, "mobula-proxy listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

async fn healthz() -> &'static str {
    "ok"
}

fn bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Northbound enforcement: Bearer required, validated in-process, and the
/// mapped identity must permit `state.required`. No token → 401; valid
/// token without the permission → 403.
async fn require_auth(State(st): State<ProxyState>, mut req: Request, next: Next) -> Response {
    let Some(token) = bearer(&req) else {
        return unauthorized("missing bearer token");
    };
    let identity = match st.validator.validate(token).await {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!(error = %e, "token validation failed");
            return unauthorized("invalid token");
        }
    };
    let (action, target) = st.required;
    if !identity.permits(action, target) {
        tracing::info!(
            subject = %identity.subject,
            path = %req.uri().path(),
            "proxy denied: insufficient permission"
        );
        return (StatusCode::FORBIDDEN, "insufficient permission").into_response();
    }
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn unauthorized(msg: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        msg,
    )
        .into_response()
}

/// Authenticated fallback: forward method/path/query/headers/body to the
/// single configured upstream, with the caller's credential swapped for
/// the injected southbound one.
async fn proxy_request(State(st): State<ProxyState>, req: Request) -> Response {
    // v0: no websocket support. Refuse upgrades explicitly rather than
    // forwarding a half-bridged connection; Ray's log tail needs this and
    // is a documented follow-up.
    if req.headers().contains_key(header::UPGRADE) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            "websocket upgrades are not supported by this proxy (v0)",
        )
            .into_response();
    }

    let subject = req
        .extensions()
        .get::<Identity>()
        .map(|i| i.subject.clone());
    let (parts, body) = req.into_parts();

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", st.upstream, path_and_query);

    let body = match to_bytes(body, st.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
    };

    let mut headers = southbound_headers(&parts.headers);
    // The exchange: the caller's Authorization never crosses; only the
    // injected credential (e.g. the static Ray token) does.
    if let Some((name, value)) = &st.inject {
        headers.insert(name.clone(), value.clone());
    }

    let upstream = match st
        .client
        .request(parts.method.clone(), &url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            // without_url(): reqwest error strings can embed the full
            // upstream URL incl. query — keep topology out of logs.
            tracing::warn!(error = %e.without_url(), "upstream request failed");
            return (StatusCode::BAD_GATEWAY, "upstream unreachable").into_response();
        }
    };

    let status = upstream.status();
    tracing::debug!(
        subject = subject.as_deref().unwrap_or(""),
        method = %parts.method,
        path = %parts.uri.path(),
        status = status.as_u16(),
        "proxied"
    );
    let nominated = connection_nominated(upstream.headers());
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream.headers() {
        // Drop hop-by-hop, Connection-nominated, and headers that leak
        // internal topology (Location on a 3xx carries internal service
        // names; Server advertises upstream versions).
        if is_hop_by_hop(name)
            || nominated.contains(name.as_str())
            || name == header::LOCATION
            || name == header::SERVER
        {
            continue;
        }
        response_headers.insert(name.clone(), value.clone());
    }

    let mut response = Response::builder()
        .status(status)
        .body(Body::from_stream(upstream.bytes_stream()))
        .expect("valid response");
    *response.headers_mut() = response_headers;
    response
}

/// Headers nominated by the `Connection` header are hop-by-hop per
/// RFC 9110 §7.6.1 and must not be forwarded — a static denylist alone
/// leaves a smuggling channel (`Connection: x-secret`).
fn connection_nominated(headers: &HeaderMap) -> HashSet<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Copy client headers southbound, dropping hop-by-hop headers (static
/// set plus Connection-nominated names), the northbound Host, the caller's
/// Authorization (never crosses), and headers that would smuggle a session
/// cookie or spoof source identity upstream.
fn southbound_headers(inbound: &HeaderMap) -> HeaderMap {
    let nominated = connection_nominated(inbound);
    let mut headers = HeaderMap::new();
    for (name, value) in inbound {
        if is_hop_by_hop(name)
            || nominated.contains(name.as_str())
            || name == header::HOST
            || name == header::AUTHORIZATION
            || name == header::CONTENT_LENGTH
            || name == header::COOKIE
            || name == header::FORWARDED
            || is_forwarded(name)
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    headers
}

fn is_forwarded(name: &HeaderName) -> bool {
    let n = name.as_str();
    n == "x-forwarded-for" || n == "x-forwarded-host" || n == "x-forwarded-proto"
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                k.parse::<HeaderName>().unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn southbound_strips_credential_and_hop_by_hop() {
        let inbound = headers(&[
            ("host", "dash.ray.test"),
            ("authorization", "Bearer user-jwt"),
            ("connection", "keep-alive, x-secret"),
            ("x-secret", "smuggled"),
            ("transfer-encoding", "chunked"),
            ("content-length", "42"),
            ("cookie", "session=abc"),
            ("x-forwarded-for", "1.2.3.4"),
            ("forwarded", "for=1.2.3.4"),
            ("content-type", "application/json"),
            ("x-request-id", "abc123"),
        ]);
        let out = southbound_headers(&inbound);
        for stripped in [
            "host",
            "authorization",
            "connection",
            "x-secret", // Connection-nominated smuggling channel.
            "transfer-encoding",
            "content-length",
            "cookie",
            "x-forwarded-for",
            "forwarded",
        ] {
            assert!(out.get(stripped).is_none(), "{stripped}");
        }
        assert_eq!(out.get(header::CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(out.get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn hop_by_hop_classification() {
        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(
                is_hop_by_hop(&name.parse::<HeaderName>().unwrap()),
                "{name}"
            );
        }
        for name in ["content-type", "accept", "x-anything"] {
            assert!(
                !is_hop_by_hop(&name.parse::<HeaderName>().unwrap()),
                "{name}"
            );
        }
    }
}
