//! Device-code and client-credentials flows against a mock IdP.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::{Form, Json, Router};
use mobula_auth::flows::{self, DevicePoll, TokenExchange, GRANT_TYPE_TOKEN_EXCHANGE};

#[derive(serde::Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    device_code: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    subject_token: Option<String>,
    #[serde(default)]
    subject_token_type: Option<String>,
    #[serde(default)]
    requested_token_type: Option<String>,
    #[serde(default)]
    audience: Option<String>,
}

/// Token endpoint: device grant is pending twice (second says slow_down),
/// then succeeds; client_credentials checks the secret; token-exchange
/// (RFC 8693) checks the secret and swaps the subject_token for a
/// user-scoped token addressed to the requested audience.
async fn token(
    State(polls): State<Arc<AtomicUsize>>,
    Form(form): Form<TokenForm>,
) -> axum::response::Response {
    if form.grant_type == GRANT_TYPE_TOKEN_EXCHANGE {
        // A confidential client authenticates the exchange.
        if form.client_secret.as_deref() != Some("s3cret") {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_client",
                    "error_description": "bad secret"
                })),
            )
                .into_response();
        }
        // The exchanged token's identity comes from the subject_token; a
        // real IdP re-mints a JWT with the subject's `sub`. The mock echoes
        // the subject token and the requested audience so the test can prove
        // the swap happened and was addressed to Mobula.
        assert_eq!(
            form.requested_token_type.as_deref(),
            Some("urn:ietf:params:oauth:token-type:access_token")
        );
        // new() defaults the subject token type to an access token.
        assert_eq!(
            form.subject_token_type.as_deref(),
            Some("urn:ietf:params:oauth:token-type:access_token")
        );
        let subject_token = form.subject_token.clone().expect("subject_token required");
        let audience = form.audience.clone().unwrap_or_default();
        return Json(serde_json::json!({
            "access_token": format!("exchanged:{subject_token}:aud={audience}"),
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 300,
        }))
        .into_response();
    }
    match form.grant_type.as_str() {
        "urn:ietf:params:oauth:grant-type:device_code" => {
            assert_eq!(form.device_code.as_deref(), Some("dev-code-42"));
            let n = polls.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "authorization_pending"})),
                )
                    .into_response(),
                1 => (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "slow_down"})),
                )
                    .into_response(),
                _ => Json(serde_json::json!({
                    "access_token": "device-token-ok",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "refresh-1",
                }))
                .into_response(),
            }
        }
        "client_credentials" => {
            if form.client_secret.as_deref() == Some("s3cret") {
                Json(serde_json::json!({
                    "access_token": format!("svc-token-for-{}", form.client_id.unwrap()),
                    "token_type": "Bearer",
                    "expires_in": 300,
                }))
                .into_response()
            } else {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({
                        "error": "invalid_client",
                        "error_description": "bad secret"
                    })),
                )
                    .into_response()
            }
        }
        other => panic!("unexpected grant_type {other}"),
    }
}

async fn device_auth() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "device_code": "dev-code-42",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://idp.example/device",
        "verification_uri_complete": "https://idp.example/device?user_code=WDJB-MJHT",
        "expires_in": 600,
        "interval": 1,
    }))
}

async fn spawn_idp() -> String {
    let polls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/token", axum::routing::post(token))
        .route("/device", axum::routing::post(device_auth))
        .with_state(polls);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn device_flow_polls_until_token() {
    let base = spawn_idp().await;
    let client = reqwest::Client::new();

    let auth = flows::device_authorize(&client, &format!("{base}/device"), "mobula-cli", "openid")
        .await
        .unwrap();
    assert_eq!(auth.user_code, "WDJB-MJHT");
    assert_eq!(auth.interval, 1);

    let mut slow_downs = 0;
    let token = loop {
        match flows::poll_device_token(
            &client,
            &format!("{base}/token"),
            "mobula-cli",
            &auth.device_code,
        )
        .await
        .unwrap()
        {
            DevicePoll::Pending { slow_down } => {
                if slow_down {
                    slow_downs += 1;
                }
            }
            DevicePoll::Ready(t) => break t,
        }
    };
    assert_eq!(token.access_token, "device-token-ok");
    assert_eq!(token.refresh_token.as_deref(), Some("refresh-1"));
    assert_eq!(slow_downs, 1, "second poll must signal slow_down");
}

#[tokio::test]
async fn client_credentials_success_and_bad_secret() {
    let base = spawn_idp().await;
    let client = reqwest::Client::new();

    let token =
        flows::client_credentials(&client, &format!("{base}/token"), "ci-bot", "s3cret", None)
            .await
            .unwrap();
    assert_eq!(token.access_token, "svc-token-for-ci-bot");

    let err = flows::client_credentials(&client, &format!("{base}/token"), "ci-bot", "wrong", None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid_client"), "{err}");
}

#[tokio::test]
async fn token_exchange_swaps_subject_and_targets_audience() {
    let base = spawn_idp().await;
    let client = reqwest::Client::new();

    // The service holds the user's gateway-verified token and exchanges it
    // for a mobula-audience token that carries the USER as subject (#102).
    let mut params = TokenExchange::new("checkmaite-svc", "s3cret", "users-live-token");
    params.audience = Some("mobula");
    let token = flows::exchange_token(&client, &format!("{base}/token"), &params)
        .await
        .unwrap();
    // The exchanged token is derived from the user's subject token and was
    // addressed to the Mobula audience — not a fresh service-account token.
    assert_eq!(token.access_token, "exchanged:users-live-token:aud=mobula");
    assert_eq!(token.expires_in, Some(300));

    // A wrong client secret is rejected like any confidential grant.
    let bad = TokenExchange::new("checkmaite-svc", "wrong", "users-live-token");
    let err = flows::exchange_token(&client, &format!("{base}/token"), &bad)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid_client"), "{err}");
}

/// A token endpoint that returns a non-RFC 502 (like an ingress blip) on
/// the first poll, then succeeds — the flow must treat the 502 as
/// transient and keep polling (#22).
mod transient {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn flaky_token(State(polls): State<Arc<AtomicUsize>>) -> axum::response::Response {
        if polls.fetch_add(1, Ordering::SeqCst) == 0 {
            (
                axum::http::StatusCode::BAD_GATEWAY,
                "<html>502 Bad Gateway</html>",
            )
                .into_response()
        } else {
            Json(serde_json::json!({
                "access_token": "ok-after-blip", "token_type": "Bearer"
            }))
            .into_response()
        }
    }

    #[tokio::test]
    async fn device_poll_retries_through_a_502() {
        let polls = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/token", axum::routing::post(flaky_token))
            .with_state(polls);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::new();
        let ep = format!("http://{addr}/token");

        // First poll: 502 → Pending (not an error).
        match flows::poll_device_token(&client, &ep, "cli", "dc")
            .await
            .unwrap()
        {
            DevicePoll::Pending { .. } => {}
            DevicePoll::Ready(_) => panic!("should have been pending on 502"),
        }
        // Second poll: success.
        match flows::poll_device_token(&client, &ep, "cli", "dc")
            .await
            .unwrap()
        {
            DevicePoll::Ready(t) => assert_eq!(t.access_token, "ok-after-blip"),
            DevicePoll::Pending { .. } => panic!("should have succeeded"),
        }
    }
}
