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
use mobula_controller::{now_unix, Store};
use mobula_core::{AuditDecision, AuditEvent, ClusterEndpoint, ClusterRegistry};

use crate::audit::emit;

/// Default request-body cap for proxied calls (see `GatewayLimits`).
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Default cap on concurrent proxied requests (see `GatewayLimits`).
const MAX_INFLIGHT: usize = 64;

/// Default southbound websocket connect timeout (see `GatewayLimits`).
const WS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Default websocket idle timeout: a bridge with no frames in either
/// direction for this long is torn down (see `GatewayLimits`).
const WS_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Default max websocket frame size, both directions (see `GatewayLimits`).
const WS_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// Default max websocket message size, both directions (see `GatewayLimits`).
const WS_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Gateway hardening knobs (issues #30/#31), with production-safe defaults.
/// `Default` is the production posture; tests shrink the values to exercise
/// the limits deterministically. Plumb them in via
/// `crate::serve_with_shutdown_and_limits`.
#[derive(Debug, Clone)]
pub struct GatewayLimits {
    /// Request bodies are buffered before forwarding; job submissions are
    /// tiny and runtime-env package uploads are modest. Bounded (with
    /// `max_inflight`) so N concurrent uploads can't OOM the gateway (#30).
    /// Streaming passthrough is a follow-up. Default: 64 MiB.
    pub max_body_bytes: usize,
    /// Max concurrent proxied requests (HTTP + websocket bridges share the
    /// semaphore). Caps peak buffered-body memory at roughly
    /// `max_inflight × max_body_bytes` and bounds upstream fan-out (#30).
    /// Excess requests are refused with 503 rather than piling up. A
    /// websocket bridge holds its permit for the bridge's whole lifetime
    /// (#31). Default: 64.
    pub max_inflight: usize,
    /// Bound on the southbound websocket connect: a black-holing cluster
    /// must not pin the client's half-open upgrade indefinitely (#31).
    /// Default: 15s.
    pub ws_connect_timeout: std::time::Duration,
    /// A websocket bridge with no frames in either direction for this long
    /// is closed — an idle tail must not hold a semaphore permit (and the
    /// memory/sockets behind it) forever (#31). Generous by default so a
    /// quiet-but-running job's log tail survives. Default: 300s.
    pub ws_idle_timeout: std::time::Duration,
    /// Max websocket frame size accepted on either hop; oversize frames
    /// terminate the bridge (#31). Default: 4 MiB.
    pub ws_max_frame_bytes: usize,
    /// Max websocket message size accepted on either hop; oversize messages
    /// terminate the bridge (#31). Default: 16 MiB.
    pub ws_max_message_bytes: usize,
    /// Extra CA bundle (PEM) trusted for southbound cluster endpoints, so
    /// self-signed cluster TLS can be verified instead of disabled (#2).
    /// `None` = system/webpki roots only.
    pub southbound_ca_bundle: Option<std::path::PathBuf>,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_BODY_BYTES,
            max_inflight: MAX_INFLIGHT,
            ws_connect_timeout: WS_CONNECT_TIMEOUT,
            ws_idle_timeout: WS_IDLE_TIMEOUT,
            ws_max_frame_bytes: WS_MAX_FRAME_BYTES,
            ws_max_message_bytes: WS_MAX_MESSAGE_BYTES,
            southbound_ca_bundle: None,
        }
    }
}

/// Header carrying the cluster's static Ray token (Ray >= 2.52 token
/// auth). Pinned by the contract-test suite against each supported Ray
/// minor; if Ray renames it, the matrix job fails, not production.
const RAY_AUTH_HEADER: header::HeaderName = header::AUTHORIZATION;

#[derive(Clone)]
pub struct GatewayState {
    registry: Arc<ClusterRegistry>,
    client: reqwest::Client,
    /// Bounds concurrent proxied requests so buffered bodies can't OOM the
    /// gateway (#30). Shared across HTTP and websocket paths (#31).
    inflight: Arc<tokio::sync::Semaphore>,
    limits: GatewayLimits,
    /// Audit persistence for the per-request trail (api-v1.md §5.9);
    /// `None` in gateway-only mode — events stay trace-only there.
    store: Option<Arc<dyn Store>>,
}

impl GatewayState {
    pub fn new(registry: Arc<ClusterRegistry>, store: Option<Arc<dyn Store>>) -> Self {
        // Default limits carry no CA bundle, so this is infallible.
        Self::try_with_limits(registry, store, GatewayLimits::default())
            .expect("default gateway limits contain no CA bundle")
    }

    /// As [`GatewayState::new`] with explicit [`GatewayLimits`]. Fails when
    /// `limits.southbound_ca_bundle` can't be read or parsed (#2).
    pub fn try_with_limits(
        registry: Arc<ClusterRegistry>,
        store: Option<Arc<dyn Store>>,
        limits: GatewayLimits,
    ) -> std::io::Result<Self> {
        let client = build_southbound_client(limits.southbound_ca_bundle.as_deref())?;
        Ok(Self {
            registry,
            store,
            inflight: Arc::new(tokio::sync::Semaphore::new(limits.max_inflight)),
            client,
            limits,
        })
    }

    /// A clone of the southbound HTTP client, for background southbound
    /// callers (e.g. the job-history refresher) that share the gateway's
    /// reverse-proxy posture and pinned CA roots.
    pub fn southbound_client(&self) -> reqwest::Client {
        self.client.clone()
    }
}

/// Build the shared southbound HTTP client (reverse-proxy posture, security
/// issues #2/#3/#5): never follow redirects (a 3xx is an SSRF amplifier and is
/// passed through untouched), bound connect/read timeouts so a hung head can't
/// pin a connection, and pin the operator's extra CA bundle when given so
/// self-signed cluster TLS verifies instead of being disabled. Fails when the
/// CA bundle can't be read or parsed (#2).
pub(crate) fn build_southbound_client(
    ca_bundle: Option<&std::path::Path>,
) -> std::io::Result<reqwest::Client> {
    let mut client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(10))
        .read_timeout(std::time::Duration::from_secs(120));
    if let Some(bundle) = ca_bundle {
        let pem = std::fs::read(bundle)?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("southbound CA bundle {}: {e}", bundle.display()),
            )
        })?;
        for cert in certs {
            client = client.add_root_certificate(cert);
        }
    }
    Ok(client.build().expect("static client config"))
}

/// Middleware: route by Host header, proxying registered cluster hosts.
pub async fn host_gateway(State(gw): State<GatewayState>, req: Request, next: Next) -> Response {
    let cluster = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| gw.registry.by_hostname(h))
        .cloned();
    let Some(cluster) = cluster else {
        // Not a cluster host → control-plane routes.
        return next.run(req).await;
    };
    // One permit per proxied request bounds peak buffered-body memory and
    // upstream fan-out (#30); shared with websocket bridges (#31). Excess
    // requests are refused with 503 rather than queueing unboundedly — a
    // queue behind the semaphore is itself a DoS surface.
    let permit = match gw.inflight.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "gateway busy: too many inflight proxied requests",
            )
                .into_response()
        }
    };
    if is_websocket_upgrade(req.headers()) {
        ws::proxy_upgrade(gw.store.as_ref(), &cluster, &gw.limits, permit, req).await
    } else {
        proxy(&gw, &cluster, req).await.into_response()
    }
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

async fn proxy(
    gw: &GatewayState,
    cluster: &ClusterEndpoint,
    req: Request,
) -> Result<Response, GatewayError> {
    let started = std::time::Instant::now();
    // `None` only in dev-unauthenticated mode; the audit row's subject
    // stays null there rather than inventing a placeholder.
    let subject = req
        .extensions()
        .get::<mobula_auth::Identity>()
        .map(|i| i.subject.clone());
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
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();

    let body = axum::body::to_bytes(body, gw.limits.max_body_bytes)
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
        // without_url(): reqwest error strings can embed the full
        // southbound URL incl. query — keep topology out of logs (#5).
        .map_err(|e| GatewayError::Upstream(cluster.id.to_string(), e.without_url().to_string()))?;

    let status = upstream.status();
    let nominated = connection_nominated(upstream.headers());
    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream.headers() {
        // Drop hop-by-hop, Connection-nominated, and headers that leak
        // internal topology: a 3xx `Location` carries internal service
        // names/IPs, and `Server` advertises the Ray/dashboard version
        // (#32). Redirects aren't followed, so the client doesn't need
        // the internal Location.
        if is_hop_by_hop(name)
            || nominated.contains(name.as_str())
            || name == header::LOCATION
            || name == header::SERVER
        {
            continue;
        }
        response_headers.insert(name.clone(), value.clone());
    }

    // Append-only audit trail (issue #8, api-v1.md §5.9): every proxied
    // request, one row. Gateway rows are always decision=allow — a request
    // Mobula refuses never reaches here (auth_layer emits the deny row);
    // an upstream 4xx/5xx is the cluster's answer and lives in `status`.
    emit(
        gw.store.as_ref(),
        AuditEvent {
            ts: now_unix(),
            subject: subject.clone(),
            decision: AuditDecision::Allow,
            cluster: Some(cluster.id.to_string()),
            method: Some(method.to_string()),
            path: Some(path.clone()),
            status: Some(status.as_u16()),
            latency_ms: Some(started.elapsed().as_millis() as u64),
            ..Default::default()
        },
    )
    .await;

    // Truthful Console (#89): a successful Ray job submission is recorded into
    // the store so it appears in GET /api/v1/jobs attributed to the caller.
    // The submit reply is a tiny JSON `{"submission_id": ...}`, so buffer it
    // (bounded) instead of streaming; every other response streams unchanged.
    // Ray-only by construction: only `POST /api/jobs/` is matched, and Dask
    // clusters expose no such endpoint.
    if crate::job_history::is_ray_job_submit(&method, &path) && status.is_success() {
        let bytes = axum::body::to_bytes(
            Body::from_stream(upstream.bytes_stream()),
            crate::job_history::MAX_SUBMIT_BODY_BYTES,
        )
        .await
        .map_err(|_| GatewayError::BodyTooLarge)?;
        crate::job_history::record_submission(
            gw.store.as_ref(),
            &cluster.id,
            subject.as_deref(),
            &bytes,
        )
        .await;
        let mut response = Response::builder()
            .status(status)
            .body(Body::from(bytes))
            .expect("valid response");
        *response.headers_mut() = response_headers;
        return Ok(response);
    }

    let mut response = Response::builder()
        .status(status)
        .body(Body::from_stream(upstream.bytes_stream()))
        .expect("valid response");
    *response.headers_mut() = response_headers;
    Ok(response)
}

/// Headers nominated by the `Connection` header are hop-by-hop per
/// RFC 9110 §7.6.1 and must not be forwarded — a static denylist alone
/// leaves a smuggling channel (`Connection: x-secret`) (issue #5).
fn connection_nominated(headers: &HeaderMap) -> std::collections::HashSet<String> {
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
/// set plus Connection-nominated names), the northbound Host, and any
/// inbound Authorization — the caller's identity must never reach the
/// cluster; only the injected Ray token does.
fn southbound_headers(inbound: &HeaderMap) -> HeaderMap {
    let nominated = connection_nominated(inbound);
    let mut headers = HeaderMap::new();
    for (name, value) in inbound {
        // Also drop, beyond the obvious credential/host headers (#32):
        //  - Cookie: the caller's control-plane session cookie must not be
        //    shipped to every cluster head they route to;
        //  - X-Forwarded-*/Forwarded: client-supplied values would spoof
        //    source identity in cluster-side logs/ACLs. Mobula does not
        //    currently append a trusted XFF; it strips inbound ones.
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

fn is_forwarded(name: &header::HeaderName) -> bool {
    let n = name.as_str();
    n == "x-forwarded-for" || n == "x-forwarded-host" || n == "x-forwarded-proto"
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

/// Websocket passthrough — Ray's job log tail (`…/logs/tail`) is a
/// websocket endpoint proxied by the dashboard head; the gateway bridges
/// it with the same credential swap as plain HTTP.
mod ws {
    use axum::extract::ws::{self as axws, WebSocketUpgrade};
    use axum::extract::{FromRequestParts, Request};
    use axum::http::{header, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use futures::{SinkExt, StreamExt};
    use mobula_controller::{now_unix, Store};
    use mobula_core::{AuditDecision, AuditEvent, ClusterEndpoint};
    use std::sync::Arc;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::protocol::Message as TsMessage;

    pub async fn proxy_upgrade(
        store: Option<&Arc<dyn Store>>,
        cluster: &ClusterEndpoint,
        limits: &super::GatewayLimits,
        permit: tokio::sync::OwnedSemaphorePermit,
        req: Request,
    ) -> Response {
        // `None` only in dev-unauthenticated mode (see proxy()).
        let subject = req
            .extensions()
            .get::<mobula_auth::Identity>()
            .map(|i| i.subject.clone());
        let (mut parts, _body) = req.into_parts();

        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_string();
        let base = cluster.api_base_url.trim_end_matches('/');
        let ws_base = if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            base.to_string()
        };
        let url = format!("{ws_base}{path_and_query}");

        let mut southbound = match url.into_client_request() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(cluster = %cluster.id, error = %e, "bad upstream ws url");
                return (StatusCode::BAD_GATEWAY, "bad upstream url").into_response();
            }
        };
        if let Some(token) = &cluster.auth_token {
            match HeaderValue::from_str(&format!("Bearer {token}")) {
                Ok(v) => {
                    southbound.headers_mut().insert(header::AUTHORIZATION, v);
                }
                Err(_) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "bad cluster token").into_response()
                }
            }
        }

        // Connect southbound BEFORE accepting the client upgrade so an
        // unreachable cluster surfaces as 502, not a dead socket — and
        // bound the connect so a black-holing head can't pin the client's
        // half-open upgrade indefinitely (#31). Frame/message caps apply
        // on the southbound hop too, so a hostile cluster can't OOM the
        // gateway any more than a hostile client can.
        let mut ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
        ws_config.max_frame_size = Some(limits.ws_max_frame_bytes);
        ws_config.max_message_size = Some(limits.ws_max_message_bytes);
        let connect =
            tokio_tungstenite::connect_async_with_config(southbound, Some(ws_config), false);
        let upstream = match tokio::time::timeout(limits.ws_connect_timeout, connect).await {
            Ok(Ok((stream, _resp))) => stream,
            Ok(Err(e)) => {
                tracing::warn!(cluster = %cluster.id, error = %e, "upstream ws connect failed");
                return (StatusCode::BAD_GATEWAY, "cluster unreachable").into_response();
            }
            Err(_) => {
                tracing::warn!(cluster = %cluster.id, "upstream ws connect timed out");
                return (StatusCode::GATEWAY_TIMEOUT, "cluster connect timed out").into_response();
            }
        };

        let upgrade = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
            Ok(u) => u,
            Err(e) => return e.into_response(),
        };
        // The bridge opening is an allowed gateway request (same policy as
        // HTTP proxy rows); there is no status/latency until it closes.
        crate::audit::emit(
            store,
            AuditEvent {
                ts: now_unix(),
                subject,
                decision: AuditDecision::Allow,
                cluster: Some(cluster.id.to_string()),
                method: Some("WS".into()),
                path: Some(parts.uri.path().to_string()),
                ..Default::default()
            },
        )
        .await;
        let idle_timeout = limits.ws_idle_timeout;
        upgrade
            .max_frame_size(limits.ws_max_frame_bytes)
            .max_message_size(limits.ws_max_message_bytes)
            .on_upgrade(move |client| bridge(client, upstream, idle_timeout, permit))
            .into_response()
    }

    /// Relay frames both ways until either side closes/errors (including
    /// the configured frame/message caps) or the bridge goes idle for
    /// `idle_timeout` (#31). The semaphore `permit` is held for the whole
    /// bridge lifetime so open bridges count against `max_inflight`.
    async fn bridge<S>(
        client: axws::WebSocket,
        upstream: tokio_tungstenite::WebSocketStream<S>,
        idle_timeout: std::time::Duration,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (mut client_tx, mut client_rx) = client.split();
        let (mut upstream_tx, mut upstream_rx) = upstream.split();

        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                msg = upstream_rx.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            if let Some(msg) = ts_to_axum(msg) {
                                if client_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                        // Protocol error (e.g. oversize frame) or EOF.
                        Some(Err(_)) | None => break,
                    }
                }
                msg = client_rx.next() => {
                    match msg {
                        Some(Ok(msg)) => {
                            if let Some(msg) = axum_to_ts(msg) {
                                if upstream_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Err(_)) | None => break,
                    }
                }
                _ = &mut idle => {
                    tracing::debug!("ws bridge closed: idle timeout");
                    break;
                }
            }
            // Any frame in either direction resets the idle clock.
            idle.as_mut()
                .reset(tokio::time::Instant::now() + idle_timeout);
        }
        let _ = client_tx.close().await;
        let _ = upstream_tx.close().await;
    }

    fn ts_to_axum(msg: TsMessage) -> Option<axws::Message> {
        Some(match msg {
            TsMessage::Text(t) => axws::Message::Text(t.as_str().into()),
            TsMessage::Binary(b) => axws::Message::Binary(b),
            TsMessage::Ping(p) => axws::Message::Ping(p),
            TsMessage::Pong(p) => axws::Message::Pong(p),
            TsMessage::Close(frame) => axws::Message::Close(frame.map(|f| axws::CloseFrame {
                code: f.code.into(),
                reason: f.reason.as_str().into(),
            })),
            TsMessage::Frame(_) => return None,
        })
    }

    fn axum_to_ts(msg: axws::Message) -> Option<TsMessage> {
        Some(match msg {
            axws::Message::Text(t) => TsMessage::Text(t.as_str().into()),
            axws::Message::Binary(b) => TsMessage::Binary(b),
            axws::Message::Ping(p) => TsMessage::Ping(p),
            axws::Message::Pong(p) => TsMessage::Pong(p),
            axws::Message::Close(frame) => TsMessage::Close(frame.map(|f| {
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: f.code.into(),
                    reason: f.reason.as_str().to_string().into(),
                }
            })),
        })
    }
}

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderName;

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
    fn southbound_strips_host_auth_and_hop_by_hop() {
        let inbound = headers(&[
            ("host", "demo.ray.test"),
            ("authorization", "Bearer user-jwt"),
            ("connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("content-length", "42"),
            ("content-type", "application/json"),
            ("x-request-id", "abc123"),
        ]);
        let out = southbound_headers(&inbound);
        assert!(out.get(header::HOST).is_none());
        assert!(out.get(header::AUTHORIZATION).is_none());
        assert!(out.get(header::CONNECTION).is_none());
        assert!(out.get(header::TRANSFER_ENCODING).is_none());
        assert!(out.get(header::CONTENT_LENGTH).is_none());
        assert_eq!(out.get(header::CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(out.get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn southbound_strips_cookie_and_forwarded() {
        let inbound = headers(&[
            ("cookie", "session=abc"),
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-host", "evil.example"),
            ("x-forwarded-proto", "http"),
            ("forwarded", "for=1.2.3.4"),
            ("content-type", "application/json"),
        ]);
        let out = southbound_headers(&inbound);
        assert!(out.get(header::COOKIE).is_none());
        assert!(out.get("x-forwarded-for").is_none());
        assert!(out.get("x-forwarded-host").is_none());
        assert!(out.get("x-forwarded-proto").is_none());
        assert!(out.get(header::FORWARDED).is_none());
        assert_eq!(out.get(header::CONTENT_TYPE).unwrap(), "application/json");
    }

    #[test]
    fn southbound_preserves_repeated_headers() {
        let inbound = headers(&[("accept-encoding", "gzip"), ("accept-encoding", "br")]);
        let out = southbound_headers(&inbound);
        assert_eq!(out.get_all("accept-encoding").iter().count(), 2);
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

    #[test]
    fn websocket_upgrade_detection_is_case_insensitive() {
        assert!(is_websocket_upgrade(&headers(&[("upgrade", "WebSocket")])));
        assert!(is_websocket_upgrade(&headers(&[("upgrade", "websocket")])));
        assert!(!is_websocket_upgrade(&headers(&[("upgrade", "h2c")])));
        assert!(!is_websocket_upgrade(&headers(&[])));
    }

    #[test]
    fn gateway_error_status_codes() {
        assert_eq!(
            GatewayError::BodyTooLarge.into_response().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            GatewayError::BadToken.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            GatewayError::Upstream("c".into(), "e".into())
                .into_response()
                .status(),
            StatusCode::BAD_GATEWAY
        );
    }
}
