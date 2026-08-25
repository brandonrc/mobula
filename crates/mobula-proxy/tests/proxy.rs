//! End-to-end tests: a mock OIDC issuer (discovery + JWKS backed by a real
//! RSA key — the same pattern as mobula-api's tests/common, replicated here
//! because those helpers are test-gated inside that crate) and a mock
//! upstream on 127.0.0.1 that echoes what it received.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mobula_auth::{AuthConfig, PermissionType, RoleMappings, Target};
use mobula_proxy::{router, ProxyConfig};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use tower::ServiceExt;

const KID: &str = "test-key-1";
const MAX_BODY: usize = 1024;

struct Idp {
    issuer: String,
    encoding_key: EncodingKey,
}

fn b64url(bytes: &[u8]) -> String {
    use std::fmt::Write;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        let chars = [
            ALPHABET[(n >> 18) as usize & 63],
            ALPHABET[(n >> 12) as usize & 63],
            ALPHABET[(n >> 6) as usize & 63],
            ALPHABET[n as usize & 63],
        ];
        let keep = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for c in &chars[..keep] {
            out.write_char(*c as char).unwrap();
        }
    }
    out
}

async fn spawn_idp() -> Idp {
    let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let public = private.to_public_key();
    let jwk = serde_json::json!({
        "kty": "RSA", "kid": KID, "alg": "RS256", "use": "sig",
        "n": b64url(&public.n().to_bytes_be()),
        "e": b64url(&public.e().to_bytes_be()),
    });
    let pem = private.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap();
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");
    let issuer_for_doc = issuer.clone();

    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let doc = serde_json::json!({
                    "issuer": issuer_for_doc,
                    "jwks_uri": format!("{issuer_for_doc}/jwks"),
                });
                async move { Json(doc).into_response() }
            }),
        )
        .route(
            "/jwks",
            axum::routing::get(move || {
                let keys = serde_json::json!({ "keys": [jwk] });
                async move { Json(keys).into_response() }
            }),
        );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    Idp {
        issuer,
        encoding_key,
    }
}

fn idp_token(idp: &Idp, groups: &[&str]) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "sub": "user-123", "email": "user@example.com",
        "iss": idp.issuer, "aud": "mobula",
        "exp": now + 300, "iat": now, "groups": groups,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    encode(&header, &claims, &idp.encoding_key).unwrap()
}

/// Mock upstream: `/echo` reports back exactly what it received (method,
/// path, query, headers, body); `/redirect` answers 302 with a Location.
async fn spawn_upstream() -> String {
    async fn echo(req: Request) -> Response {
        let (parts, body) = req.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
            .collect();
        (
            StatusCode::OK,
            [("x-upstream-marker", "yes")],
            Json(serde_json::json!({
                "method": parts.method.to_string(),
                "path": parts.uri.path(),
                "query": parts.uri.query(),
                "headers": headers,
                "body": String::from_utf8_lossy(&bytes),
            })),
        )
            .into_response()
    }
    async fn redirect() -> Response {
        (
            StatusCode::FOUND,
            [
                (
                    header::LOCATION,
                    HeaderValue::from_static("http://169.254.1.1/internal"),
                ),
                (
                    header::SERVER,
                    HeaderValue::from_static("ray-dashboard/2.57"),
                ),
            ],
        )
            .into_response()
    }
    let app = Router::new()
        .route("/redirect", axum::routing::any(redirect))
        .fallback(echo);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn config(idp: &Idp, upstream: &str) -> ProxyConfig {
    ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: upstream.to_string(),
        auth: AuthConfig {
            issuer: idp.issuer.clone(),
            audience: "mobula".into(),
            groups_claim: "groups".into(),
            project_roles: Default::default(),
            roles: RoleMappings {
                developer: vec!["/ml-eng".into()],
                viewer: vec!["/observers".into()],
                ..RoleMappings::default()
            },
        },
        required: (PermissionType::Write, Target::Job),
        inject_header: Some(("authorization".into(), "Bearer ray-static-token".into())),
        allow_insecure: true, // mock IdP is plain http on loopback
        max_body_bytes: MAX_BODY,
    }
}

fn req(method: &str, path: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "dash.example.test");
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

async fn body_json(resp: Response) -> serde_json::Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn healthz_is_public() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    let resp = app.oneshot(req("GET", "/healthz", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_token_is_401() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    let resp = app.oneshot(req("GET", "/echo", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );
}

#[tokio::test]
async fn invalid_token_is_401() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    let resp = app
        .oneshot(req("GET", "/echo", Some("not-a-jwt")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn insufficient_role_is_403() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    // The proxy requires (Write, Job); a Viewer holds Read only.
    let viewer = idp_token(&idp, &["/observers"]);
    let resp = app
        .oneshot(req("GET", "/echo", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn passthrough_strips_caller_credential_and_injects() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    let developer = idp_token(&idp, &["/ml-eng"]);

    let resp = app
        .oneshot(
            Request::post("/echo/deep/path?a=1&b=2")
                .header(header::HOST, "dash.example.test")
                .header(header::AUTHORIZATION, format!("Bearer {developer}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::CONNECTION, "keep-alive, x-smuggle")
                .header("x-smuggle", "must-not-cross")
                .header("x-request-id", "r-1")
                .body(Body::from("{\"hello\":\"world\"}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers().get("x-upstream-marker").unwrap(), "yes");

    let echoed = body_json(resp).await;
    assert_eq!(echoed["method"], "POST");
    assert_eq!(echoed["path"], "/echo/deep/path");
    assert_eq!(echoed["query"], "a=1&b=2");
    assert_eq!(echoed["body"], "{\"hello\":\"world\"}");

    let headers: Vec<(String, String)> = serde_json::from_value(echoed["headers"].clone()).unwrap();
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    // The exchange: caller's JWT never crosses; only the injected static
    // Ray token does.
    assert_eq!(get("authorization"), Some("Bearer ray-static-token"));
    assert!(get("x-smuggle").is_none(), "Connection-nominated smuggling");
    assert!(get("cookie").is_none() || get("cookie") != Some("session=abc"));
    assert_eq!(get("x-request-id"), Some("r-1"));
    // reqwest sets its own Host for the upstream, not the caller's.
    assert_ne!(get("host"), Some("dash.example.test"));
}

#[tokio::test]
async fn redirect_is_not_followed_and_topology_headers_stripped() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    let developer = idp_token(&idp, &["/ml-eng"]);
    let resp = app
        .oneshot(req("GET", "/redirect", Some(&developer)))
        .await
        .unwrap();
    // 3xx passes through raw — never followed southbound.
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(resp.headers().get(header::LOCATION).is_none());
    assert!(resp.headers().get(header::SERVER).is_none());
}

#[tokio::test]
async fn unreachable_upstream_is_502() {
    let idp = spawn_idp().await;
    // Bind then drop to get a closed port on 127.0.0.1.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let app = router(&config(&idp, &format!("http://{closed}")))
        .await
        .unwrap();
    let developer = idp_token(&idp, &["/ml-eng"]);
    let resp = app
        .oneshot(req("GET", "/echo", Some(&developer)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn oversized_body_is_413() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    let developer = idp_token(&idp, &["/ml-eng"]);
    let resp = app
        .oneshot(
            Request::post("/echo")
                .header(header::AUTHORIZATION, format!("Bearer {developer}"))
                .body(Body::from(vec![b'x'; MAX_BODY + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn websocket_upgrade_is_501() {
    let idp = spawn_idp().await;
    let upstream = spawn_upstream().await;
    let app = router(&config(&idp, &upstream)).await.unwrap();
    let developer = idp_token(&idp, &["/ml-eng"]);
    let resp = app
        .oneshot(
            Request::get("/api/jobs/abc/logs/tail")
                .header(header::AUTHORIZATION, format!("Bearer {developer}"))
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "websocket")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}
