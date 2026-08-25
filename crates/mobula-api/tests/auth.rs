//! End-to-end authn/authz tests: a mock OIDC provider (discovery + JWKS
//! backed by a real RSA key), locally signed JWTs, and the deny-by-default
//! matrix through the full app — the negative tests security issue #1
//! requires.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum::Router;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mobula_auth::{AuthConfig, RoleMappings, Validator};
use mobula_core::{ClusterEndpoint, ClusterId, ClusterRegistry};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use tower::ServiceExt;

const KID: &str = "test-key-1";

struct Idp {
    issuer: String,
    encoding_key: EncodingKey,
}

fn b64url(bytes: &[u8]) -> String {
    use std::fmt::Write;
    // Minimal base64url (no padding) to avoid a base64 dev-dependency.
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

/// Spawn a mock OIDC issuer serving discovery + JWKS for a fresh RSA key.
async fn spawn_idp() -> Idp {
    let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let public = private.to_public_key();
    let jwk = serde_json::json!({
        "kty": "RSA",
        "kid": KID,
        "alg": "RS256",
        "use": "sig",
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

impl Idp {
    fn token(&self, groups: &[&str], aud: &str, exp_offset_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = serde_json::json!({
            "sub": "user-123",
            "email": "user@example.com",
            "iss": self.issuer,
            "aud": aud,
            "exp": now + exp_offset_secs,
            "iat": now,
            "groups": groups,
        });
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.into());
        encode(&header, &claims, &self.encoding_key).unwrap()
    }
}

async fn validator_for(idp: &Idp) -> Arc<Validator> {
    let config = AuthConfig {
        issuer: idp.issuer.clone(),
        audience: "mobula".into(),
        groups_claim: "groups".into(),
        project_roles: Default::default(),
        roles: RoleMappings {
            admin: vec!["/platform-admins".into()],
            operator: vec!["/sre".into()],
            developer: vec!["/ml-eng".into()],
            viewer: vec!["/observers".into()],
            auditor: vec![],
        },
    };
    Arc::new(
        // Mock issuer is http://127.0.0.1 — allow insecure transport in tests.
        Validator::discover(config, reqwest::Client::new(), true)
            .await
            .unwrap(),
    )
}

/// Mock Ray head that records nothing and answers everything.
async fn spawn_head() -> SocketAddr {
    let app = Router::new().fallback(|| async { "head-ok" });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn authed_app(idp: &Idp) -> (Router, SocketAddr) {
    let head = spawn_head().await;
    let app = mobula_api::build_app(
        ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("demo".into()),
                hostname: "demo.ray.test".into(),
                api_base_url: format!("http://{head}"),
                auth_token: None,
                auth_token_env: None,
            }],
        },
        Some(validator_for(idp).await),
    );
    (app, head)
}

fn get(path: &str, host: &str, token: Option<&str>) -> Request<Body> {
    let mut req = Request::get(path).header(header::HOST, host);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req.body(Body::empty()).unwrap()
}

fn post(path: &str, host: &str, token: Option<&str>) -> Request<Body> {
    let mut req = Request::post(path).header(header::HOST, host);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req.body(Body::from("{}")).unwrap()
}

#[tokio::test]
async fn http_issuer_is_refused_without_override() {
    let idp = spawn_idp().await; // http://127.0.0.1
    let config = AuthConfig {
        issuer: idp.issuer.clone(),
        audience: "mobula".into(),
        groups_claim: "groups".into(),
        project_roles: Default::default(),
        roles: RoleMappings::default(),
    };
    let err = match Validator::discover(config.clone(), reqwest::Client::new(), false).await {
        Err(e) => e,
        Ok(_) => panic!("http issuer should be refused without override"),
    };
    assert!(err.to_string().contains("not https"), "{err}");
    // With the override it proceeds to real discovery.
    assert!(Validator::discover(config, reqwest::Client::new(), true)
        .await
        .is_ok());
}

#[tokio::test]
async fn token_without_subject_is_rejected() {
    let idp = spawn_idp().await;
    let validator = validator_for(&idp).await;
    // Sign a token whose `sub` is empty.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = serde_json::json!({
        "sub": "",
        "iss": idp.issuer,
        "aud": "mobula",
        "exp": now + 300,
        "groups": ["/ml-eng"],
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    let token = encode(&header, &claims, &idp.encoding_key).unwrap();
    let err = validator.validate(&token).await.unwrap_err();
    assert!(err.to_string().contains("no subject"), "{err}");
}

#[tokio::test]
async fn tokens_missing_iss_aud_or_with_future_nbf_are_rejected() {
    let idp = spawn_idp().await;
    let validator = validator_for(&idp).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let sign = |claims: serde_json::Value| {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.into());
        encode(&header, &claims, &idp.encoding_key).unwrap()
    };

    // Missing aud.
    let no_aud = sign(serde_json::json!({
        "sub": "u", "iss": idp.issuer, "exp": now + 300, "groups": ["/ml-eng"]
    }));
    assert!(validator.validate(&no_aud).await.is_err(), "missing aud");

    // Missing iss.
    let no_iss = sign(serde_json::json!({
        "sub": "u", "aud": "mobula", "exp": now + 300, "groups": ["/ml-eng"]
    }));
    assert!(validator.validate(&no_iss).await.is_err(), "missing iss");

    // Future nbf (not yet valid).
    let future_nbf = sign(serde_json::json!({
        "sub": "u", "iss": idp.issuer, "aud": "mobula",
        "exp": now + 600, "nbf": now + 300, "groups": ["/ml-eng"]
    }));
    assert!(validator.validate(&future_nbf).await.is_err(), "future nbf");
}

#[tokio::test]
async fn cluster_traffic_requires_a_token() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;
    let res = app
        .oneshot(get("/api/jobs/", "demo.ray.test", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    // WWW-Authenticate tells the client what's expected.
    assert_eq!(
        res.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );
}

#[tokio::test]
async fn garbage_and_expired_tokens_are_401() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;

    let res = app
        .clone()
        .oneshot(get("/api/jobs/", "demo.ray.test", Some("not-a-jwt")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let expired = idp.token(&["/ml-eng"], "mobula", -300);
    let res = app
        .clone()
        .oneshot(get("/api/jobs/", "demo.ray.test", Some(&expired)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "expired");

    let wrong_aud = idp.token(&["/ml-eng"], "not-mobula", 300);
    let res = app
        .oneshot(get("/api/jobs/", "demo.ray.test", Some(&wrong_aud)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "wrong audience");
}

#[tokio::test]
async fn viewer_reads_but_cannot_submit() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;
    let viewer = idp.token(&["/observers"], "mobula", 300);

    let res = app
        .clone()
        .oneshot(get("/api/jobs/", "demo.ray.test", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "viewer GET proxied");

    let res = app
        .oneshot(post("/api/jobs/", "demo.ray.test", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer POST denied");
}

#[tokio::test]
async fn operator_reads_but_cannot_submit_jobs() {
    // The capability the ordinal-role model couldn't express (#25):
    // operator = lifecycle but not code. On the proxied Ray surface,
    // submitting a job is a Write, which Operator lacks.
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;
    let operator = idp.token(&["/sre"], "mobula", 300);

    let res = app
        .clone()
        .oneshot(get("/api/jobs/", "demo.ray.test", Some(&operator)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "operator can read");

    let res = app
        .oneshot(post("/api/jobs/", "demo.ray.test", Some(&operator)))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "operator must not submit jobs"
    );
}

#[tokio::test]
async fn developer_submits_and_unmapped_groups_are_denied() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;

    let dev = idp.token(&["/ml-eng"], "mobula", 300);
    let res = app
        .clone()
        .oneshot(post("/api/jobs/", "demo.ray.test", Some(&dev)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "developer POST proxied");

    // Valid token, but no mapped role: deny by default.
    let stranger = idp.token(&["/unrelated-team"], "mobula", 300);
    let res = app
        .oneshot(get("/api/jobs/", "demo.ray.test", Some(&stranger)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn control_plane_public_paths_stay_public_but_cluster_hosts_do_not() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;

    let res = app
        .clone()
        .oneshot(get("/healthz", "mobula.example.com", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "probe stays public");

    // The same path on a cluster host is proxied traffic → 401.
    let res = app
        .oneshot(get("/healthz", "demo.ray.test", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ext_authz_check_endpoint_matrix() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;

    let res = app
        .clone()
        .oneshot(get("/api/v1/authz/check", "mobula.example.com", None))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "check requires token"
    );

    let dev = idp.token(&["/ml-eng"], "mobula", 300);
    let res = app
        .clone()
        .oneshot(get("/api/v1/authz/check", "mobula.example.com", Some(&dev)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("x-mobula-subject").unwrap(),
        "user-123",
        "identity propagated for Envoy to forward"
    );

    let stranger = idp.token(&["/nobody"], "mobula", 300);
    let res = app
        .oneshot(get(
            "/api/v1/authz/check",
            "mobula.example.com",
            Some(&stranger),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// ext_authz derives its target from the forwarded path, not a hardcoded
/// `Target::Job` (#46). Build a check request whose x-forwarded-* headers
/// describe the proxied request.
fn authz_check_req(fwd_method: &str, fwd_uri: &str, token: &str) -> Request<Body> {
    Request::post("/api/v1/authz/check")
        .header(header::HOST, "mobula.example.com")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-forwarded-method", fwd_method)
        .header("x-forwarded-uri", fwd_uri)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn ext_authz_forwarded_cluster_path_denies_developer() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;
    // Developer has Write on Job but only Read on Cluster → POST cluster = 403.
    let dev = idp.token(&["/ml-eng"], "mobula", 300);
    let res = app
        .oneshot(authz_check_req("POST", "/api/v1/clusters", &dev))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ext_authz_forwarded_cluster_path_allows_operator() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;
    // Operator has Write on Cluster → POST cluster = 200 with subject header.
    let operator = idp.token(&["/sre"], "mobula", 300);
    let res = app
        .oneshot(authz_check_req("POST", "/api/v1/clusters", &operator))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get("x-mobula-subject").unwrap(), "user-123");
}

#[tokio::test]
async fn ext_authz_forwarded_service_path_respects_service_target() {
    let idp = spawn_idp().await;
    let (app, _) = authed_app(&idp).await;
    // Service is a "code" surface: Developer has Write, Operator only Read.
    let operator = idp.token(&["/sre"], "mobula", 300);
    let res = app
        .clone()
        .oneshot(authz_check_req("POST", "/api/v1/services", &operator))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "operator cannot deploy"
    );

    let dev = idp.token(&["/ml-eng"], "mobula", 300);
    let res = app
        .oneshot(authz_check_req("POST", "/api/v1/services", &dev))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "developer can deploy");
}
