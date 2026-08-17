//! Identity & access integration tests (api-v1.md §5.8): `/api/v1/identity`
//! in OIDC/local/dev modes, the Admin-only `/api/v1/access/roles` mappings
//! (file vs local source), and the Admin-only local user-management CRUD
//! (`/api/v1/auth/users`) with its audit trail.

mod common;
use common::{authed_app_with_store, idp_token, local_auth_app, spawn_idp};

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use mobula_auth::local::hash_password;
use mobula_controller::{InMemoryStore, Store};
use mobula_core::LocalRole;
use tower::ServiceExt;

fn get_auth(path: &str, token: Option<&str>) -> Request<Body> {
    let mut req = Request::get(path).header(header::HOST, "mobula.test");
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req.body(Body::empty()).unwrap()
}

fn json_req(method: &str, path: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "mobula.test")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn store_with_admin() -> Arc<dyn Store> {
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let hash = hash_password("admin-pw").await.unwrap();
    store
        .create_local_user("admin", None, &hash, LocalRole::Admin)
        .await
        .unwrap();
    store
}

/// Log in through the full app and return the bearer token.
async fn login_token(app: &axum::Router, username: &str, password: &str) -> String {
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::HOST, "mobula.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"username": username, "password": password}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "login failed for {username}");
    body_json(res).await["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn identity_with_oidc_token_maps_roles_from_groups() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;

    let token = idp_token(&idp, &["/platform-admins", "/ml-eng"]);
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/identity", Some(&token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["subject"], "user-123");
    assert_eq!(body["email"], "user@example.com");
    assert_eq!(
        body["groups"],
        serde_json::json!(["/platform-admins", "/ml-eng"])
    );
    let roles = body["roles"].as_array().unwrap();
    assert!(roles.contains(&serde_json::json!("admin")), "{roles:?}");
    assert!(roles.contains(&serde_json::json!("developer")), "{roles:?}");
}

#[tokio::test]
async fn identity_requires_a_token_when_auth_is_configured() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/identity", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/identity", Some("garbage.token.here")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn identity_in_dev_mode_returns_the_specced_dev_identity() {
    // No validator AND no local auth: the specced dev identity (§5.8).
    let app = mobula_api::build_router();
    let res = app
        .oneshot(get_auth("/api/v1/identity", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(
        body,
        serde_json::json!({
            "subject": "dev", "email": null, "groups": [], "roles": ["admin"]
        })
    );
}

#[tokio::test]
async fn identity_in_pure_local_mode_reads_the_role_from_the_user_row() {
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store).await;
    let token = login_token(&app, "admin", "admin-pw").await;

    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/identity", Some(&token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["subject"], "admin");
    assert_eq!(body["email"], serde_json::Value::Null);
    assert_eq!(body["groups"], serde_json::json!([]));
    assert_eq!(body["roles"], serde_json::json!(["admin"]));

    // Auth configured (local) + no token → 401 via the middleware.
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/identity", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn roles_endpoint_returns_the_validators_mappings_to_admins_only() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;

    // Viewer: 403 (access-control surfaces are Admin-only, §2.2).
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/access/roles", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Admin: the configured mappings, source "file", not editable.
    let admin = idp_token(&idp, &["/platform-admins"]);
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/access/roles", Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(
        body,
        serde_json::json!({
            "mappings": {
                "admin": ["/platform-admins"],
                "operator": ["/sre"],
                "developer": ["/ml-eng"],
                "viewer": ["/observers"],
                "auditor": ["/compliance"],
            },
            "source": "file",
            "editable": false,
        })
    );
}

#[tokio::test]
async fn roles_endpoint_in_local_mode_returns_null_mappings() {
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store).await;
    let token = login_token(&app, "admin", "admin-pw").await;

    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/access/roles", Some(&token)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    // Group→role mappings are meaningless without an OIDC validator: local
    // users carry their role as a column (§5.8 deviation).
    assert_eq!(
        body,
        serde_json::json!({"mappings": null, "source": "local", "editable": false})
    );
}

#[tokio::test]
async fn users_crud_flow_with_live_role_and_disablement() {
    let store = store_with_admin().await;
    let (app, _auth) = local_auth_app(store.clone()).await;
    let admin = login_token(&app, "admin", "admin-pw").await;

    // Only the bootstrap admin exists; no hash material in the list.
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/users", Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let users = body.as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["username"], "admin");
    let raw = serde_json::to_string(&body).unwrap();
    assert!(!raw.contains("$2b$") && !raw.contains("hash"), "{raw}");

    // Create alice (viewer).
    let res = app
        .clone()
        .oneshot(json_req(
            "POST",
            "/api/v1/auth/users",
            &admin,
            serde_json::json!({
                "username": "alice", "email": "alice@example.com",
                "password": "password123", "role": "viewer"
            }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = body_json(res).await;
    assert_eq!(body["username"], "alice");
    assert_eq!(body["role"], "viewer");
    assert_eq!(body["disabled"], false);
    assert_eq!(body["email"], "alice@example.com");
    assert!(body["created_at"].as_u64().unwrap() > 0);
    assert!(body.get("password_hash").is_none(), "{body}");

    // Duplicate username → 409.
    let res = app
        .clone()
        .oneshot(json_req(
            "POST",
            "/api/v1/auth/users",
            &admin,
            serde_json::json!({"username": "alice", "password": "password123", "role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // Bad username / short password → 400; unknown role → 4xx.
    let res = app
        .clone()
        .oneshot(json_req(
            "POST",
            "/api/v1/auth/users",
            &admin,
            serde_json::json!({"username": "Not_A_Name!", "password": "password123", "role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = app
        .clone()
        .oneshot(json_req(
            "POST",
            "/api/v1/auth/users",
            &admin,
            serde_json::json!({"username": "bob", "password": "short", "role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = app
        .clone()
        .oneshot(json_req(
            "POST",
            "/api/v1/auth/users",
            &admin,
            serde_json::json!({"username": "bob", "password": "password123", "role": "superuser"}),
        ))
        .await
        .unwrap();
    assert!(
        res.status().is_client_error(),
        "unknown role rejected: {}",
        res.status()
    );

    // Role change applies live: alice's token picks up operator without
    // re-login (ADR-0011: roles are a column, resolved per request).
    let alice_token = login_token(&app, "alice", "password123").await;
    let res = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/v1/auth/users/alice",
            &admin,
            serde_json::json!({"role": "operator"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["role"], "operator");
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/identity", Some(&alice_token)))
        .await
        .unwrap();
    assert_eq!(
        body_json(res).await["roles"],
        serde_json::json!(["operator"])
    );

    // Disable: login and the existing token both die.
    let res = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/v1/auth/users/alice",
            &admin,
            serde_json::json!({"disabled": true}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["disabled"], true);
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/identity", Some(&alice_token)))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "disabled user's PAT"
    );
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::HOST, "mobula.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({"username": "alice", "password": "password123"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "disabled user login"
    );

    // Unknown user → 404.
    let res = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/v1/auth/users/ghost",
            &admin,
            serde_json::json!({"role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Mutations are audited.
    let (events, _) = store
        .list_audit(&mobula_core::AuditFilter::default())
        .await
        .unwrap();
    let creates = events
        .iter()
        .filter(|(_, e)| e.action.as_deref() == Some("create_user"))
        .count();
    let updates = events
        .iter()
        .filter(|(_, e)| e.action.as_deref() == Some("update_user"))
        .count();
    assert_eq!(creates, 1, "create_user audit rows: {events:?}");
    assert_eq!(updates, 2, "update_user audit rows: {events:?}");
}

#[tokio::test]
async fn user_management_is_admin_only() {
    let store = store_with_admin().await;
    let hash = hash_password("viewer-pw").await.unwrap();
    store
        .create_local_user("bob", None, &hash, LocalRole::Viewer)
        .await
        .unwrap();
    let (app, _auth) = local_auth_app(store).await;
    let viewer = login_token(&app, "bob", "viewer-pw").await;

    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/users", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer list");
    let res = app
        .clone()
        .oneshot(json_req(
            "POST",
            "/api/v1/auth/users",
            &viewer,
            serde_json::json!({"username": "mallory", "password": "password123", "role": "admin"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer create");
    let res = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/v1/auth/users/bob",
            &viewer,
            serde_json::json!({"role": "admin"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer self-promote");

    // And the routes need a token at all (middleware).
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/auth/users", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// --- Scoped role bindings (ADR-0009 addendum, #49) ---

fn delete_req(path: &str, token: &str) -> Request<Body> {
    Request::delete(path)
        .header(header::HOST, "mobula.test")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn assignments_crud_is_admin_only_validated_and_audited() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store.clone()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Empty initially.
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/access/assignments", Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await, serde_json::json!([]));

    // Validation: unknown role, bad scope grammar, bad role type.
    for body in [
        serde_json::json!({"role": "superuser", "scope": "*"}),
        serde_json::json!({"role": "operator", "scope": "cluster:c1"}),
        serde_json::json!({"role": "operator", "scope": "project:"}),
        serde_json::json!({"role": "operator"}),
    ] {
        let res = app
            .clone()
            .oneshot(json_req(
                "PUT",
                "/api/v1/access/assignments/dev-1",
                &admin,
                body,
            ))
            .await
            .unwrap();
        assert!(res.status().is_client_error(), "rejected {res:?}");
    }

    // Upsert two bindings for dev-1 and one for bob.
    let res = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/v1/access/assignments/dev-1",
            &admin,
            serde_json::json!({"role": "operator", "scope": "project:ml-team"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["principal"], "dev-1");
    assert_eq!(body["role"], "operator");
    assert_eq!(body["scope"], "project:ml-team");
    assert!(body["created_at"].as_u64().unwrap() > 0);
    let first_created = body["created_at"].as_u64().unwrap();

    for (principal, role, scope) in [
        ("dev-1", "viewer", "*"),
        ("bob", "developer", "project:data"),
    ] {
        let res = app
            .clone()
            .oneshot(json_req(
                "PUT",
                &format!("/api/v1/access/assignments/{principal}"),
                &admin,
                serde_json::json!({"role": role, "scope": scope}),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{principal}");
    }

    // Re-upsert of the same triple is idempotent (created_at preserved).
    let res = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/v1/access/assignments/dev-1",
            &admin,
            serde_json::json!({"role": "operator", "scope": "project:ml-team"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["created_at"], first_created);

    // List shows all three, ordered by (principal, scope, role).
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/access/assignments", Some(&admin)))
        .await
        .unwrap();
    let rows = body_json(res).await;
    let triples: Vec<(&str, &str, &str)> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["principal"].as_str().unwrap(),
                r["role"].as_str().unwrap(),
                r["scope"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        triples,
        [
            ("bob", "developer", "project:data"),
            ("dev-1", "viewer", "*"),
            ("dev-1", "operator", "project:ml-team"),
        ]
    );

    // Delete one; deleting it again (or an unknown triple) 404s.
    let res = app
        .clone()
        .oneshot(delete_req(
            "/api/v1/access/assignments/dev-1?role=viewer&scope=*",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let res = app
        .clone()
        .oneshot(delete_req(
            "/api/v1/access/assignments/dev-1?role=viewer&scope=*",
            &admin,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "re-delete 404");

    // Non-admins are locked out of all three routes; no token → 401.
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/access/assignments", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer list");
    let res = app
        .clone()
        .oneshot(json_req(
            "PUT",
            "/api/v1/access/assignments/mallory",
            &viewer,
            serde_json::json!({"role": "admin", "scope": "*"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer grant");
    let res = app
        .clone()
        .oneshot(delete_req(
            "/api/v1/access/assignments/dev-1?role=operator&scope=project:ml-team",
            &viewer,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer delete");
    let res = app
        .clone()
        .oneshot(get_auth("/api/v1/access/assignments", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Mutations are audited: two distinct principals' upserts + one delete
    // (the idempotent re-upsert also writes a row).
    let (events, _) = store
        .list_audit(&mobula_core::AuditFilter::default())
        .await
        .unwrap();
    let upserts = events
        .iter()
        .filter(|(_, e)| e.action.as_deref() == Some("upsert_assignment"))
        .count();
    let deletes = events
        .iter()
        .filter(|(_, e)| e.action.as_deref() == Some("delete_assignment"))
        .count();
    assert_eq!(upserts, 4, "upsert audit rows: {events:?}");
    assert_eq!(deletes, 1, "delete audit rows: {events:?}");
    // The admin's denials of the viewer are audited too.
    let denies = events
        .iter()
        .filter(|(_, e)| {
            e.decision == mobula_core::AuditDecision::Deny
                && e.subject.as_deref() == Some("user-123")
        })
        .count();
    assert_eq!(denies, 3, "viewer denial rows: {events:?}");
}
