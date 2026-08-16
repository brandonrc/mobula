//! Registry read API: the gateway's routing table is exposed Admin-only,
//! with static Ray tokens reduced to a `token_set` boolean — the raw
//! credential must never appear in a response body (security issue #4).

mod common;

use axum::http::StatusCode;
use mobula_core::{ClusterEndpoint, ClusterId, ClusterRegistry};
use tower::ServiceExt;

fn registry() -> ClusterRegistry {
    ClusterRegistry {
        clusters: vec![
            ClusterEndpoint {
                id: ClusterId("demo".into()),
                hostname: "demo.ray.example.com".into(),
                api_base_url: "https://demo-head:8265".into(),
                auth_token: Some("super-secret-ray-token".into()),
            },
            ClusterEndpoint {
                id: ClusterId("open".into()),
                hostname: "open.ray.example.com".into(),
                api_base_url: "https://open-head:8265".into(),
                auth_token: None,
            },
        ],
    }
}

async fn app(idp: &common::Idp) -> axum::Router {
    let config = mobula_auth::AuthConfig {
        issuer: idp.issuer.clone(),
        audience: "mobula".into(),
        groups_claim: "groups".into(),
        roles: mobula_auth::RoleMappings {
            admin: vec!["/platform-admins".into()],
            operator: vec!["/sre".into()],
            developer: vec!["/ml-eng".into()],
            viewer: vec!["/observers".into()],
        },
    };
    let validator = mobula_auth::Validator::discover(config, reqwest::Client::new(), true)
        .await
        .unwrap();
    mobula_api::build_app(registry(), Some(std::sync::Arc::new(validator)))
}

#[tokio::test]
async fn admin_sees_the_routing_table_without_tokens() {
    let idp = common::spawn_idp().await;
    let token = common::idp_token(&idp, &["/platform-admins"]);
    let resp = app(&idp)
        .await
        .oneshot(common::get(
            "/api/v1/registry/clusters",
            "mobula.example.com",
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    // The credential itself must never leak (issue #4) — only its presence.
    assert!(!text.contains("super-secret-ray-token"), "{text}");
    let entries: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], "demo");
    assert_eq!(arr[0]["hostname"], "demo.ray.example.com");
    assert_eq!(arr[0]["token_set"], true);
    assert_eq!(arr[1]["token_set"], false);
    // Forward-compat field, always null today.
    assert!(arr[0]["validation"].is_null());
}

#[tokio::test]
async fn non_admin_roles_are_denied() {
    let idp = common::spawn_idp().await;
    for groups in [&["/sre"][..], &["/ml-eng"][..], &["/observers"][..]] {
        let token = common::idp_token(&idp, groups);
        let resp = app(&idp)
            .await
            .oneshot(common::get(
                "/api/v1/registry/clusters",
                "mobula.example.com",
                Some(&token),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "groups {groups:?} must not read the registry"
        );
    }
}

#[tokio::test]
async fn no_token_is_unauthorized() {
    let idp = common::spawn_idp().await;
    let resp = app(&idp)
        .await
        .oneshot(common::get(
            "/api/v1/registry/clusters",
            "mobula.example.com",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn empty_registry_returns_an_empty_list() {
    let idp = common::spawn_idp().await;
    let token = common::idp_token(&idp, &["/platform-admins"]);
    let config = mobula_auth::AuthConfig {
        issuer: idp.issuer.clone(),
        audience: "mobula".into(),
        groups_claim: "groups".into(),
        roles: mobula_auth::RoleMappings {
            admin: vec!["/platform-admins".into()],
            operator: vec![],
            developer: vec![],
            viewer: vec![],
        },
    };
    let validator = mobula_auth::Validator::discover(config, reqwest::Client::new(), true)
        .await
        .unwrap();
    let app = mobula_api::build_app(
        ClusterRegistry::default(),
        Some(std::sync::Arc::new(validator)),
    );
    let resp = app
        .oneshot(common::get(
            "/api/v1/registry/clusters",
            "mobula.example.com",
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!([])
    );
}
