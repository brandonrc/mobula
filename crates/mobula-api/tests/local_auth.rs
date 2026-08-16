//! Local-auth integration tests (ADR-0011): login, lockout, PAT
//! create/list/revoke, RBAC via PAT-authenticated identity, providers
//! metadata, logout, and expired-token rejection — through the full app
//! with the shared harness.

mod common;
use common::{local_auth_app, spawn_idp};

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use mobula_auth::local::{hash_password, hash_token, mint_token_parts};
use mobula_controller::{InMemoryStore, Store};
use mobula_core::LocalRole;
use tower::ServiceExt;

async fn store_with_admin() -> Arc<dyn Store> {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let hash = hash_password("admin-pw").await.unwrap();
    store
        .create_local_user("admin", None, &hash, LocalRole::Admin)
        .await
        .unwrap();
    store
}

fn post_json_anon(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::post(path)
        .header(header::HOST, "mobula.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_json_auth(path: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::post(path)
        .header(header::HOST, "mobula.test")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_auth(path: &str, token: Option<&str>) -> Request<Body> {
    let mut req = Request::get(path).header(header::HOST, "mobula.test");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req.body(Body::empty()).unwrap()
}

fn delete_auth(path: &str, token: &str) -> Request<Body> {
    Request::delete(path)
        .header(header::HOST, "mobula.test")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn login(app: &axum::Router, username: &str, password: &str) -> axum::response::Response {
    app.clone()
        .oneshot(post_json_anon(
            "/api/v1/auth/login",
            serde_json::json!({"username": username, "password": password}),
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn login_issues_an_opaque_token_that_authenticates() {
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store).await;

    // Login is public (allowlisted).
    let res = login(&app, "admin", "admin-pw").await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let token = body["token"].as_str().unwrap();
    assert!(token.starts_with("mob_"), "{token}");
    assert_eq!(body["token_type"], "bearer");
    assert!(body["expires_at"].as_u64().unwrap() > 0);
    assert_eq!(body["identity"]["subject"], "admin");
    assert_eq!(body["identity"]["roles"], serde_json::json!(["admin"]));

    // The token authenticates against a protected route.
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/clusters", Some(token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_failures_are_indistinguishable_and_lock_out() {
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store).await;

    // Unknown user vs wrong password: identical 401 bodies (no enumeration).
    let unknown = login(&app, "ghost", "admin-pw").await;
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    let unknown_body = body_json(unknown).await;
    let wrong = login(&app, "admin", "nope").await;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let wrong_body = body_json(wrong).await;
    assert_eq!(unknown_body, wrong_body);
    assert_eq!(unknown_body["error"], "invalid_credentials");

    // Four more wrong attempts cross the 5-strike threshold...
    for _ in 0..4 {
        let res = login(&app, "admin", "nope").await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    // ...and the 6th is refused EVEN WITH the correct password — with the
    // same wire body (lockout is visible only in the audit trail).
    let res = login(&app, "admin", "admin-pw").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "locked out");
    assert_eq!(body_json(res).await, unknown_body);
}

#[tokio::test]
async fn pat_create_list_revoke_flow_is_owner_scoped() {
    let store = store_with_admin().await;
    // A second user to prove owner-scoping.
    let hash = hash_password("viewer-pw").await.unwrap();
    store
        .create_local_user("bob", None, &hash, LocalRole::Viewer)
        .await
        .unwrap();
    let (app, _auth) = local_auth_app(store).await;

    let res = login(&app, "admin", "admin-pw").await;
    let admin_token = body_json(res).await["token"].as_str().unwrap().to_string();
    let res = login(&app, "bob", "viewer-pw").await;
    let bob_token = body_json(res).await["token"].as_str().unwrap().to_string();

    // Tokens route requires authentication (not in the public allowlist).
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/tokens", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Create a PAT: 201, plaintext shown once.
    let res = app
        .clone()
        .oneshot(post_json_auth(
            "/api/v1/auth/tokens",
            &admin_token,
            serde_json::json!({"label": "ci", "expires_in_days": 30}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = body_json(res).await;
    let prefix = body["prefix"].as_str().unwrap().to_string();
    let pat = body["token"].as_str().unwrap().to_string();
    assert!(pat.starts_with(&format!("mob_{prefix}_")), "{pat}");

    // ttl cap: 91 days is a 400.
    let res = app
        .clone()
        .oneshot(post_json_auth(
            "/api/v1/auth/tokens",
            &admin_token,
            serde_json::json!({"label": "too-long", "expires_in_days": 91}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // List: the caller sees their own tokens (login token + PAT), no hashes.
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/tokens", Some(&admin_token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let tokens = body.as_array().unwrap();
    assert_eq!(tokens.len(), 2);
    let raw = serde_json::to_string(tokens).unwrap();
    assert!(!raw.contains("$2b$") && !raw.contains("hash"), "{raw}");
    assert!(tokens.iter().any(|t| t["prefix"] == prefix));
    // bob sees only his own (login) token — not admin's.
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/tokens", Some(&bob_token)))
        .await
        .unwrap();
    let body = body_json(res).await;
    assert_eq!(body.as_array().unwrap().len(), 1);

    // bob cannot revoke admin's PAT: same 404 as a nonexistent prefix.
    let res = app
        .clone()
        .oneshot(delete_auth(
            &format!("/api/v1/auth/tokens/{prefix}"),
            &bob_token,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = app
        .clone()
        .oneshot(delete_auth("/api/v1/auth/tokens/zzzz9999", &bob_token))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // The PAT works, then admin revokes it and it dies.
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/clusters", Some(&pat)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app
        .clone()
        .oneshot(delete_auth(
            &format!("/api/v1/auth/tokens/{prefix}"),
            &admin_token,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/clusters", Some(&pat)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "revoked PAT");
}

#[tokio::test]
async fn pat_identity_enforces_rbac_by_role() {
    let store = store_with_admin().await;
    let hash = hash_password("viewer-pw").await.unwrap();
    store
        .create_local_user("bob", None, &hash, LocalRole::Viewer)
        .await
        .unwrap();
    let (app, _auth) = local_auth_app(store).await;
    let res = login(&app, "bob", "viewer-pw").await;
    let bob_token = body_json(res).await["token"].as_str().unwrap().to_string();

    // Viewer: read OK, cluster create denied (Write on Cluster is
    // Operator/Admin).
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/clusters", Some(&bob_token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app
        .clone()
        .oneshot(post_json_auth(
            "/api/v1/clusters",
            &bob_token,
            serde_json::json!({
                "id": "c1",
                "spec": {
                    "name": "c1", "project": "demo", "ray_version": "2.57.0",
                    "image": "img", "head_cpu": "1", "head_memory": "2Gi",
                    "worker_groups": [], "ttl_seconds": null
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer cannot create");
}

#[tokio::test]
async fn providers_reports_local_and_oidc_configuration() {
    // Local-only app.
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store).await;
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/providers", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "providers is public");
    let body = body_json(res).await;
    assert_eq!(body["local"], true);
    assert!(body["oidc"].is_null());

    // OIDC-only app: local is false, issuer surfaces.
    let idp = spawn_idp().await;
    let app = common::authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/providers", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["local"], false);
    assert_eq!(body["oidc"]["issuer"], idp.issuer.as_str());
}

#[tokio::test]
async fn logout_revokes_the_callers_pat() {
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store).await;
    let res = login(&app, "admin", "admin-pw").await;
    let token = body_json(res).await["token"].as_str().unwrap().to_string();

    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/clusters", Some(&token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(post_json_auth(
            "/api/v1/auth/logout",
            &token,
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/clusters", Some(&token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "logged-out token");
}

#[tokio::test]
async fn expired_tokens_are_rejected() {
    let store = store_with_admin().await;
    // Insert a token whose expiry is in the past.
    let (prefix, plaintext) = mint_token_parts();
    let hash = hash_token(&plaintext).await.unwrap();
    store
        .create_api_token(mobula_core::ApiTokenRecord {
            prefix,
            token_hash: hash,
            username: "admin".into(),
            label: "old".into(),
            created_at: 1,
            expires_at: 2,
            revoked: false,
            last_used_at: None,
        })
        .await
        .unwrap();
    let (app, _auth) = local_auth_app(store).await;
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/clusters", Some(&plaintext)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "expired token");
}

#[tokio::test]
async fn login_and_audit_events_are_persisted() {
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store.clone()).await;
    login(&app, "admin", "wrong").await;
    login(&app, "admin", "admin-pw").await;

    let (events, _) = store
        .list_audit(&mobula_core::AuditFilter::default())
        .await
        .unwrap();
    let login_events: Vec<_> = events
        .iter()
        .filter(|(_, e)| e.action.as_deref() == Some("login"))
        .collect();
    assert_eq!(login_events.len(), 2);
    // Deny first (newest-first ordering puts the allow first).
    assert_eq!(
        login_events[0].1.decision,
        mobula_core::AuditDecision::Allow
    );
    assert_eq!(login_events[1].1.decision, mobula_core::AuditDecision::Deny);
    assert_eq!(
        login_events[1].1.reason.as_deref(),
        Some("invalid_credentials")
    );
    assert_eq!(login_events[1].1.subject.as_deref(), Some("admin"));
}
