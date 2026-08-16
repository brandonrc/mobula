//! Northbound authentication/authorization (Phase 2, ADR-0003).
//!
//! Deny by default: when a validator is configured, every request needs a
//! valid Bearer JWT except a small public allowlist on the control-plane
//! host. Requests addressed to a registered cluster hostname are NEVER
//! public — the stock Ray client sends `Authorization` on every call
//! (including `/api/version` negotiation), so the full surface is gated.
//!
//! Every refusal (authn failure, authz denial) is an audit event via
//! [`crate::audit::emit`] — traced on the `mobula::audit` target and
//! persisted when a store is configured (api-v1.md §5.9).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use mobula_auth::{Identity, PermissionType, Target, Validator};
use mobula_controller::{now_unix, Store};
use mobula_core::{AuditDecision, AuditEvent, AuditRequired, ClusterRegistry};

use crate::audit::{emit, permission_str, role_str, target_str};

#[derive(Clone)]
pub struct AuthState {
    pub validator: Option<Arc<Validator>>,
    pub registry: Arc<ClusterRegistry>,
    /// Audit persistence (api-v1.md §5.9); `None` in gateway-only mode.
    pub store: Option<Arc<dyn Store>>,
}

/// Paths that stay public on the control-plane host (never on cluster
/// hosts): probes and API documentation.
fn is_public(path: &str) -> bool {
    path == "/healthz"
        || path == "/api/v1/version"
        || path == "/api/v1/openapi.json"
        || path == "/docs"
        || path.starts_with("/docs/")
}

/// The permission a proxied gateway request requires. Reads (and the
/// websocket log tail, a GET upgrade) need `Read`; mutations need `Write`.
/// DELETE on the proxied Ray surface is job deletion — a Developer action,
/// not cluster lifecycle — so it maps to `Write`, not `Delete`. Mobula's
/// own lifecycle/admin routes (Phase 3) will require permissions per route
/// against a cluster/project target, not by HTTP method. This picks the
/// verb only; the target is derived separately (see [`target_for_path`],
/// whose prefixes must stay in sync with clusters.rs/services.rs).
fn required_permission(method: &Method) -> PermissionType {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        PermissionType::Read
    } else {
        PermissionType::Write
    }
}

/// Which permission target a forwarded control-plane path maps to. Roles are
/// permission-sets over (verb, target), not an ordinal rank, so the target
/// must be derived from the path — a Developer has Write on `Job`/`Service`
/// but only Read on `Cluster`, and an Operator is the reverse. These prefixes
/// MUST stay in sync with the router prefixes in `clusters.rs`
/// (`/api/v1/clusters`), `services.rs` (`/api/v1/services`), `pools.rs`
/// (`/api/v1/pools`), `registry.rs` (`/api/v1/registry`), and `audit.rs`
/// (`/api/v1/audit`).
///
/// Matching is on segment boundaries — an exact match or a `<prefix>/…`
/// child — so `/api/v1/clusters-evil` is NOT a cluster path and falls through
/// to `Job` (the safe default for the proxied Ray surface).
fn target_for_path(path: &str) -> Target {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let is_under = |prefix: &str| path == prefix || path.starts_with(&format!("{prefix}/"));
    if is_under("/api/v1/clusters") {
        Target::Cluster
    } else if is_under("/api/v1/services") {
        Target::Service
    } else if is_under("/api/v1/pools") {
        Target::Pool
    } else if is_under("/api/v1/registry") || is_under("/api/v1/audit") {
        // Registry entries describe cluster routing and the audit trail is
        // dominated by cluster decisions; both route handlers enforce Admin
        // themselves — this mapping is for the ext_authz verb check.
        Target::Cluster
    } else {
        Target::Job
    }
}

fn bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub async fn require_auth(State(st): State<AuthState>, req: Request, next: Next) -> Response {
    let Some(validator) = &st.validator else {
        // Auth disabled: dev mode, guarded by --dev-allow-unauthenticated.
        return next.run(req).await;
    };

    let host_is_cluster = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| st.registry.by_hostname(h).is_some());

    if !host_is_cluster && is_public(req.uri().path()) {
        return next.run(req).await;
    }

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let Some(token) = bearer(&req) else {
        // Audit 401s at INFO so credential-stuffing / token-guessing is
        // visible in the audit stream, not just debug logs (#23). Authn
        // failures have no identity, so the row's subject is null.
        emit(
            st.store.as_ref(),
            AuditEvent {
                ts: now_unix(),
                decision: AuditDecision::Deny,
                reason: Some("missing_token".into()),
                method: Some(method.to_string()),
                path: Some(path),
                status: Some(StatusCode::UNAUTHORIZED.as_u16()),
                ..Default::default()
            },
        )
        .await;
        return unauthorized("missing bearer token");
    };
    let identity = match validator.validate(token).await {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!(error = %e, "token validation failed");
            emit(
                st.store.as_ref(),
                AuditEvent {
                    ts: now_unix(),
                    decision: AuditDecision::Deny,
                    reason: Some("invalid_token".into()),
                    method: Some(method.to_string()),
                    path: Some(path),
                    status: Some(StatusCode::UNAUTHORIZED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            return unauthorized("invalid token");
        }
    };

    // Cluster-host traffic is the proxied Ray surface: it goes straight to
    // the gateway with no per-route handler, so enforce its Job permission
    // here. Control-plane API routes attach the identity and let each route
    // check its own target (e.g. cluster lifecycle needs Cluster, not Job).
    if host_is_cluster {
        let required = required_permission(req.method());
        // Target::Job is correct here: cluster-host traffic is the proxied
        // Ray job surface, guarded by host_is_cluster above.
        if !identity.permits(required, Target::Job) {
            emit(
                st.store.as_ref(),
                AuditEvent {
                    ts: now_unix(),
                    subject: Some(identity.subject.clone()),
                    decision: AuditDecision::Deny,
                    reason: Some("insufficient_permission".into()),
                    method: Some(method.to_string()),
                    path: Some(path),
                    status: Some(StatusCode::FORBIDDEN.as_u16()),
                    required: Some(AuditRequired {
                        action: permission_str(required),
                        target: "job".into(),
                    }),
                    granted_roles: identity.roles.iter().map(role_str).collect(),
                    ..Default::default()
                },
            )
            .await;
            return (StatusCode::FORBIDDEN, "insufficient permission").into_response();
        }
    }
    let mut req = req;
    req.extensions_mut().insert(identity);
    next.run(req).await
}

/// Route-handler authorization helper. Returns `Some(denial_response)` when
/// access is refused, `None` when permitted. `identity` is `None` only in
/// dev/no-auth mode (guarded by `--dev-allow-unauthenticated`), where all
/// access is permitted; otherwise deny-by-default against (action, target).
///
/// A denial is also an audit event (api-v1.md §5.9) carrying the
/// required/granted permission detail, persisted when `store` is `Some` —
/// handlers pass their store state; store-less routers (registry, services)
/// pass `None` and the denial is trace-only.
pub async fn authorize(
    store: Option<&Arc<dyn Store>>,
    identity: Option<&Identity>,
    action: PermissionType,
    target: Target,
) -> Option<Response> {
    match identity {
        None => None,
        Some(id) if id.permits(action, target) => None,
        Some(id) => {
            emit(
                store,
                AuditEvent {
                    ts: now_unix(),
                    subject: Some(id.subject.clone()),
                    decision: AuditDecision::Deny,
                    reason: Some("insufficient_permission".into()),
                    status: Some(StatusCode::FORBIDDEN.as_u16()),
                    required: Some(AuditRequired {
                        action: permission_str(action),
                        target: target_str(target),
                    }),
                    granted_roles: id.roles.iter().map(role_str).collect(),
                    ..Default::default()
                },
            )
            .await;
            Some((StatusCode::FORBIDDEN, "insufficient permission").into_response())
        }
    }
}

/// Envoy `ext_authz` HTTP check endpoint (ADR-0003): Envoy forwards the
/// original request's method and headers; 2xx allows, anything else
/// denies. Returns the resolved identity in response headers so Envoy
/// can propagate it upstream if configured.
///
/// The authorization target is derived from the forwarded path via
/// [`target_for_path`], not hardcoded — so pointing ext_authz at a cluster
/// or service path enforces the right (verb, target) permission. Its path
/// prefixes MUST stay in sync with the router prefixes in `clusters.rs` and
/// `services.rs`.
pub async fn authz_check(State(st): State<AuthState>, req: Request) -> Response {
    let Some(validator) = &st.validator else {
        return (StatusCode::NOT_IMPLEMENTED, "authn not configured").into_response();
    };
    // Envoy forwards the original method/path via x-forwarded-*; fall back
    // to the check request's own for direct callers.
    let method = req
        .headers()
        .get("x-forwarded-method")
        .and_then(|v| v.to_str().ok())
        .and_then(|m| Method::from_bytes(m.as_bytes()).ok())
        .unwrap_or_else(|| req.method().clone());
    let path = req
        .headers()
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| req.uri().path().to_string());

    let Some(token) = bearer(&req) else {
        emit(
            st.store.as_ref(),
            AuditEvent {
                ts: now_unix(),
                decision: AuditDecision::Deny,
                reason: Some("missing_token".into()),
                method: Some(method.to_string()),
                path: Some(path),
                status: Some(StatusCode::UNAUTHORIZED.as_u16()),
                ..Default::default()
            },
        )
        .await;
        return unauthorized("missing bearer token");
    };
    let identity: Identity = match validator.validate(token).await {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!(error = %e, "token validation failed");
            emit(
                st.store.as_ref(),
                AuditEvent {
                    ts: now_unix(),
                    decision: AuditDecision::Deny,
                    reason: Some("invalid_token".into()),
                    method: Some(method.to_string()),
                    path: Some(path),
                    status: Some(StatusCode::UNAUTHORIZED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            return unauthorized("invalid token");
        }
    };
    let required = required_permission(&method);
    let target = target_for_path(&path);
    if identity.permits(required, target) {
        emit(
            st.store.as_ref(),
            AuditEvent {
                ts: now_unix(),
                subject: Some(identity.subject.clone()),
                decision: AuditDecision::Allow,
                method: Some(method.to_string()),
                path: Some(path),
                status: Some(StatusCode::OK.as_u16()),
                ..Default::default()
            },
        )
        .await;
        (
            StatusCode::OK,
            [("x-mobula-subject", identity.subject.clone())],
            "allowed",
        )
            .into_response()
    } else {
        emit(
            st.store.as_ref(),
            AuditEvent {
                ts: now_unix(),
                subject: Some(identity.subject.clone()),
                decision: AuditDecision::Deny,
                reason: Some("insufficient_permission".into()),
                method: Some(method.to_string()),
                path: Some(path),
                status: Some(StatusCode::FORBIDDEN.as_u16()),
                required: Some(AuditRequired {
                    action: permission_str(required),
                    target: target_str(target),
                }),
                granted_roles: identity.roles.iter().map(role_str).collect(),
                ..Default::default()
            },
        )
        .await;
        (StatusCode::FORBIDDEN, "insufficient permission").into_response()
    }
}

fn unauthorized(msg: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        msg,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_allowlist_is_narrow() {
        for p in [
            "/healthz",
            "/api/v1/version",
            "/api/v1/openapi.json",
            "/docs",
            "/docs/x",
        ] {
            assert!(is_public(p), "{p}");
        }
        for p in ["/api/jobs/", "/api/v1/authz/check", "/docsx", "/"] {
            assert!(!is_public(p), "{p}");
        }
    }

    #[test]
    fn permission_matrix_maps_reads_to_read_and_writes_to_write() {
        assert_eq!(required_permission(&Method::GET), PermissionType::Read);
        assert_eq!(required_permission(&Method::HEAD), PermissionType::Read);
        assert_eq!(required_permission(&Method::POST), PermissionType::Write);
        assert_eq!(required_permission(&Method::PUT), PermissionType::Write);
        assert_eq!(required_permission(&Method::DELETE), PermissionType::Write);
    }

    #[test]
    fn target_for_path_maps_prefixes() {
        assert_eq!(target_for_path("/api/v1/clusters"), Target::Cluster);
        assert_eq!(target_for_path("/api/v1/clusters/abc"), Target::Cluster);
        assert_eq!(target_for_path("/api/v1/services/x"), Target::Service);
        assert_eq!(target_for_path("/api/v1/pools"), Target::Pool);
        assert_eq!(
            target_for_path("/api/v1/pools/gpu/allocations/p"),
            Target::Pool
        );
        assert_eq!(target_for_path("/api/v1/audit"), Target::Cluster);
        assert_eq!(target_for_path("/api/jobs/"), Target::Job);
        // Segment boundary, not naive prefix: `clusters-evil` is not clusters.
        assert_eq!(target_for_path("/api/v1/clusters-evil"), Target::Job);
        // Query strings are stripped before matching.
        assert_eq!(target_for_path("/api/v1/clusters?x=1"), Target::Cluster);
    }
}
