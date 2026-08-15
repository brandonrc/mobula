//! Northbound authentication/authorization (Phase 2, ADR-0003).
//!
//! Deny by default: when a validator is configured, every request needs a
//! valid Bearer JWT except a small public allowlist on the control-plane
//! host. Requests addressed to a registered cluster hostname are NEVER
//! public — the stock Ray client sends `Authorization` on every call
//! (including `/api/version` negotiation), so the full surface is gated.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use mobula_auth::{Identity, PermissionType, Validator};
use mobula_core::ClusterRegistry;

#[derive(Clone)]
pub struct AuthState {
    pub validator: Option<Arc<Validator>>,
    pub registry: Arc<ClusterRegistry>,
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
/// against a cluster/project target, not by HTTP method.
fn required_permission(method: &Method) -> PermissionType {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        PermissionType::Read
    } else {
        PermissionType::Write
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

    let path = req.uri().path().to_string();
    let Some(token) = bearer(&req) else {
        // Audit 401s at INFO so credential-stuffing / token-guessing is
        // visible in the audit stream, not just debug logs (#23).
        tracing::info!(
            target: "mobula::audit",
            decision = "deny", reason = "missing_token",
            path = %path, "authentication failed"
        );
        return unauthorized("missing bearer token");
    };
    let identity = match validator.validate(token).await {
        Ok(i) => i,
        Err(e) => {
            tracing::info!(
                target: "mobula::audit",
                decision = "deny", reason = "invalid_token",
                error = %e, path = %path, "authentication failed"
            );
            return unauthorized("invalid token");
        }
    };

    let required = required_permission(req.method());
    if identity.permits(required) {
        let mut req = req;
        req.extensions_mut().insert(identity);
        next.run(req).await
    } else {
        tracing::info!(
            target: "mobula::audit",
            decision = "deny", reason = "insufficient_permission",
            subject = %identity.subject,
            required = ?required,
            granted = ?identity.roles,
            "authorization denied"
        );
        (StatusCode::FORBIDDEN, "insufficient permission").into_response()
    }
}

/// Envoy `ext_authz` HTTP check endpoint (ADR-0003): Envoy forwards the
/// original request's method and headers; 2xx allows, anything else
/// denies. Returns the resolved identity in response headers so Envoy
/// can propagate it upstream if configured.
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
        tracing::info!(
            target: "mobula::audit",
            decision = "deny", reason = "missing_token",
            path = %path, "ext_authz"
        );
        return unauthorized("missing bearer token");
    };
    let identity: Identity = match validator.validate(token).await {
        Ok(i) => i,
        Err(e) => {
            tracing::info!(
                target: "mobula::audit",
                decision = "deny", reason = "invalid_token",
                error = %e, path = %path, "ext_authz"
            );
            return unauthorized("invalid token");
        }
    };
    let required = required_permission(&method);
    if identity.permits(required) {
        tracing::info!(
            target: "mobula::audit",
            decision = "allow", subject = %identity.subject,
            %method, path = %path, "ext_authz"
        );
        (
            StatusCode::OK,
            [("x-mobula-subject", identity.subject.clone())],
            "allowed",
        )
            .into_response()
    } else {
        tracing::info!(
            target: "mobula::audit",
            decision = "deny", reason = "insufficient_permission",
            subject = %identity.subject, required = ?required,
            granted = ?identity.roles, %method, path = %path, "ext_authz"
        );
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
}
