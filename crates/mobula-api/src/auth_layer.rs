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
use mobula_auth::{Identity, Role, Validator};
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

fn required_role(method: &Method) -> Role {
    // v0 matrix: reads (and the websocket log tail, which arrives as a
    // GET upgrade) need Viewer; anything mutating needs Developer.
    // Admin-only surfaces arrive with the lifecycle API in Phase 3.
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        Role::Viewer
    } else {
        Role::Developer
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

    let Some(token) = bearer(&req) else {
        return unauthorized("missing bearer token");
    };
    let identity = match validator.validate(token).await {
        Ok(i) => i,
        Err(e) => {
            tracing::debug!(error = %e, "token rejected");
            return unauthorized("invalid token");
        }
    };

    let required = required_role(req.method());
    match identity.role {
        Some(role) if role.permits(required) => {
            let mut req = req;
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        _ => {
            tracing::info!(
                target: "mobula::audit",
                subject = %identity.subject,
                required = ?required,
                granted = ?identity.role,
                "authorization denied"
            );
            (StatusCode::FORBIDDEN, "insufficient role").into_response()
        }
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
    let Some(token) = bearer(&req) else {
        return unauthorized("missing bearer token");
    };
    let identity: Identity = match validator.validate(token).await {
        Ok(i) => i,
        Err(_) => return unauthorized("invalid token"),
    };
    let required = required_role(req.method());
    match identity.role {
        Some(role) if role.permits(required) => (
            StatusCode::OK,
            [("x-mobula-subject", identity.subject.clone())],
            "allowed",
        )
            .into_response(),
        _ => (StatusCode::FORBIDDEN, "insufficient role").into_response(),
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
    fn role_matrix_maps_reads_to_viewer_and_writes_to_developer() {
        assert_eq!(required_role(&Method::GET), Role::Viewer);
        assert_eq!(required_role(&Method::HEAD), Role::Viewer);
        assert_eq!(required_role(&Method::POST), Role::Developer);
        assert_eq!(required_role(&Method::PUT), Role::Developer);
        assert_eq!(required_role(&Method::DELETE), Role::Developer);
    }
}
