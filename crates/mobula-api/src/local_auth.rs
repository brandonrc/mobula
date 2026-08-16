//! Local-auth routes (ADR-0011): login, provider metadata, personal access
//! tokens, logout.
//!
//! Mounted only when local auth is enabled (`serve --local-auth`), except
//! `GET /api/v1/auth/providers`, which is always mounted and public (it's
//! in the unauthenticated allowlist) so the login page can render the
//! right form. PAT management requires an authenticated identity and is
//! owner-scoped: a caller only ever sees/revokes their own tokens.
//!
//! Wire-contract notes:
//! - every login failure — unknown user, wrong password, locked, disabled
//!   — returns the SAME `401 {"error":"invalid_credentials"}` body (no
//!   user enumeration); the distinction lives only in the audit trail;
//! - token plaintext is returned exactly once (`POST .../tokens`, 201);
//!   list views never contain hashes ([`ApiTokenView`]);
//! - revoking someone else's token and revoking a nonexistent one are both
//!   404 (no ownership probing).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use mobula_auth::local::{token_prefix, LocalAuthError, LocalAuthenticator};
use mobula_auth::Identity;
use mobula_controller::{now_unix, Store};
use mobula_core::{ApiTokenView, AuditDecision, AuditEvent};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::audit::{emit, role_str};

#[derive(Clone)]
pub struct LocalAuthApiState {
    pub auth: Arc<LocalAuthenticator>,
}

impl LocalAuthApiState {
    fn store(&self) -> &Arc<dyn Store> {
        self.auth.store()
    }
}

#[derive(Clone)]
pub struct ProvidersState {
    pub local: bool,
    pub oidc_issuer: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// The identity half of a login response.
#[derive(Serialize, ToSchema)]
pub struct LoginIdentity {
    pub subject: String,
    pub roles: Vec<String>,
}

/// `POST /api/v1/auth/login` success body. `token` is an opaque
/// `mob_…` bearer credential (ADR-0011: stored, never signed).
#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    /// Always "bearer".
    #[schema(example = "bearer")]
    pub token_type: &'static str,
    /// Unix seconds after which the token no longer authenticates.
    pub expires_at: u64,
    pub identity: LoginIdentity,
}

/// Which auth providers this deployment offers (login-page metadata; not
/// sensitive — the endpoint is public by design).
#[derive(Serialize, ToSchema)]
pub struct ProvidersResponse {
    /// Local username/password auth is enabled (ADR-0011).
    pub local: bool,
    /// OIDC configuration, when a validator is configured.
    pub oidc: Option<OidcProviderInfo>,
}

#[derive(Serialize, ToSchema)]
pub struct OidcProviderInfo {
    pub issuer: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    /// Human label ("ci", "laptop") — shown in listings.
    pub label: String,
    /// Lifetime in days; capped at the server maximum (90).
    pub expires_in_days: u64,
}

/// `POST /api/v1/auth/tokens` success body. The plaintext `token` is
/// returned ONLY here — store it now; it cannot be recovered.
#[derive(Serialize, ToSchema)]
pub struct CreateTokenResponse {
    pub prefix: String,
    pub token: String,
    /// Unix seconds.
    pub expires_at: u64,
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

/// The one and only login-failure wire shape. Lockout/disablement is
/// visible only in the audit trail (ADR-0011).
fn invalid_credentials() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "invalid_credentials"})),
    )
        .into_response()
}

async fn audit_login(
    store: Option<&Arc<dyn Store>>,
    username: &str,
    decision: AuditDecision,
    reason: Option<&str>,
    status: u16,
) {
    emit(
        store,
        AuditEvent {
            ts: now_unix(),
            subject: Some(username.to_string()),
            decision,
            reason: reason.map(String::from),
            action: Some("login".into()),
            method: Some("POST".into()),
            path: Some("/api/v1/auth/login".into()),
            status: Some(status),
            ..Default::default()
        },
    )
    .await;
}

/// Username/password login (ADR-0011). Public (allowlisted); rate-limited
/// by bcrypt cost and the 5-strikes/5-minute account lockout.
#[utoipa::path(
    post, path = "/api/v1/auth/login", tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Logged in; opaque bearer token returned", body = LoginResponse),
        (status = 401, description = "Invalid credentials (identical body for unknown user, wrong password, locked, or disabled)"),
    )
)]
async fn login(State(st): State<LocalAuthApiState>, Json(body): Json<LoginRequest>) -> Response {
    match st.auth.login(&body.username, &body.password).await {
        Ok(outcome) => {
            audit_login(
                Some(st.store()),
                &body.username,
                AuditDecision::Allow,
                None,
                200,
            )
            .await;
            Json(LoginResponse {
                token: outcome.token.token,
                token_type: "bearer",
                expires_at: outcome.expires_at,
                identity: LoginIdentity {
                    subject: outcome.identity.subject,
                    roles: outcome.identity.roles.iter().map(role_str).collect(),
                },
            })
            .into_response()
        }
        Err(e) => {
            let reason = match e {
                LocalAuthError::InvalidCredentials | LocalAuthError::UnknownUser => {
                    "invalid_credentials"
                }
                LocalAuthError::Locked => "locked",
                LocalAuthError::Disabled => "disabled",
                LocalAuthError::Backend(_) | LocalAuthError::TtlTooLong => "backend_error",
            };
            audit_login(
                Some(st.store()),
                &body.username,
                AuditDecision::Deny,
                Some(reason),
                401,
            )
            .await;
            invalid_credentials()
        }
    }
}

/// Login-page metadata: which providers are configured. Public by design.
#[utoipa::path(
    get, path = "/api/v1/auth/providers", tag = "auth",
    responses((status = 200, description = "Configured auth providers", body = ProvidersResponse))
)]
async fn providers(State(st): State<ProvidersState>) -> Json<ProvidersResponse> {
    Json(ProvidersResponse {
        local: st.local,
        oidc: st.oidc_issuer.map(|issuer| OidcProviderInfo { issuer }),
    })
}

/// Mint a personal access token for the caller (ADR-0011). Any
/// authenticated identity; the plaintext is shown once.
#[utoipa::path(
    post, path = "/api/v1/auth/tokens", tag = "auth",
    request_body = CreateTokenRequest,
    responses(
        (status = 201, description = "Token created; plaintext returned once", body = CreateTokenResponse),
        (status = 400, description = "expires_in_days out of range"),
        (status = 401, description = "No/invalid token"),
    ),
    security(("bearer" = []))
)]
async fn create_token(
    State(st): State<LocalAuthApiState>,
    identity: Option<Extension<Identity>>,
    Json(body): Json<CreateTokenRequest>,
) -> Response {
    let Some(identity) = ident(&identity) else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    match st
        .auth
        .issue_token(&identity.subject, &body.label, body.expires_in_days)
        .await
    {
        Ok((minted, record)) => {
            emit(
                Some(st.store()),
                AuditEvent {
                    ts: now_unix(),
                    subject: Some(identity.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("issue_token".into()),
                    method: Some("POST".into()),
                    path: Some("/api/v1/auth/tokens".into()),
                    status: Some(StatusCode::CREATED.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            (
                StatusCode::CREATED,
                Json(CreateTokenResponse {
                    prefix: minted.prefix,
                    token: minted.token,
                    expires_at: record.expires_at,
                }),
            )
                .into_response()
        }
        Err(LocalAuthError::TtlTooLong) => (
            StatusCode::BAD_REQUEST,
            "expires_in_days must be between 1 and the server maximum (90)",
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "token issuance failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// List the caller's own tokens. Hashes are never serialized.
#[utoipa::path(
    get, path = "/api/v1/auth/tokens", tag = "auth",
    responses(
        (status = 200, description = "The caller's tokens, newest first", body = Vec<ApiTokenView>),
        (status = 401, description = "No/invalid token"),
    ),
    security(("bearer" = []))
)]
async fn list_tokens(
    State(st): State<LocalAuthApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    let Some(identity) = ident(&identity) else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    match st.store().list_api_tokens(&identity.subject).await {
        Ok(tokens) => Json(tokens.iter().map(|t| t.view()).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "token list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// Revoke one of the caller's own tokens. Someone else's token (or a
/// nonexistent prefix) is a 404 — ownership can't be probed.
#[utoipa::path(
    delete, path = "/api/v1/auth/tokens/{prefix}", tag = "auth",
    params(("prefix" = String, Path, description = "The token's 8-char lookup prefix")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "No/invalid token"),
        (status = 404, description = "No such token for this caller"),
    ),
    security(("bearer" = []))
)]
async fn revoke_token(
    State(st): State<LocalAuthApiState>,
    identity: Option<Extension<Identity>>,
    Path(prefix): Path<String>,
) -> Response {
    let Some(identity) = ident(&identity) else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    match st
        .store()
        .revoke_api_token(&prefix, &identity.subject)
        .await
    {
        Ok(()) => {
            emit(
                Some(st.store()),
                AuditEvent {
                    ts: now_unix(),
                    subject: Some(identity.subject.clone()),
                    decision: AuditDecision::Allow,
                    action: Some("revoke_token".into()),
                    method: Some("DELETE".into()),
                    path: Some(format!("/api/v1/auth/tokens/{prefix}")),
                    status: Some(StatusCode::NO_CONTENT.as_u16()),
                    ..Default::default()
                },
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => (StatusCode::NOT_FOUND, "no such token").into_response(),
    }
}

/// Log out: if the caller authenticated with a PAT, revoke it; otherwise a
/// 204 no-op (JWTs are stateless — there is nothing server-side to kill).
#[utoipa::path(
    post, path = "/api/v1/auth/logout", tag = "auth",
    responses(
        (status = 204, description = "Logged out (PAT revoked when one was used)"),
        (status = 401, description = "No/invalid token"),
    ),
    security(("bearer" = []))
)]
async fn logout(
    State(st): State<LocalAuthApiState>,
    identity: Option<Extension<Identity>>,
    headers: HeaderMap,
) -> Response {
    let Some(identity) = ident(&identity) else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    if let Some(prefix) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(token_prefix)
    {
        // Owner-scoped revoke; a nonexistent/already-revoked token is fine.
        let _ = st.store().revoke_api_token(prefix, &identity.subject).await;
    }
    emit(
        Some(st.store()),
        AuditEvent {
            ts: now_unix(),
            subject: Some(identity.subject.clone()),
            decision: AuditDecision::Allow,
            action: Some("logout".into()),
            method: Some("POST".into()),
            path: Some("/api/v1/auth/logout".into()),
            status: Some(StatusCode::NO_CONTENT.as_u16()),
            ..Default::default()
        },
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

/// The local-auth route bundle, mounted only when local auth is enabled.
pub fn router(auth: Arc<LocalAuthenticator>) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/tokens", post(create_token).get(list_tokens))
        .route("/api/v1/auth/tokens/{prefix}", delete(revoke_token))
        .route("/api/v1/auth/logout", post(logout))
        .with_state(LocalAuthApiState { auth })
}

/// The providers metadata route: always mounted, always public.
pub fn providers_router(local: bool, oidc_issuer: Option<String>) -> Router {
    Router::new()
        .route("/api/v1/auth/providers", get(providers))
        .with_state(ProvidersState { local, oidc_issuer })
}
