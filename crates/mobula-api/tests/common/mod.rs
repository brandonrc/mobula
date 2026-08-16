//! Shared test helpers: a mock OIDC issuer (discovery + JWKS backed by a
//! real RSA key) and app builders. Used by the cluster-route tests.

#![allow(dead_code)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request};
use axum::response::IntoResponse;
use axum::{Json, Router};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mobula_auth::{AuthConfig, RoleMappings, Validator};
use mobula_controller::Store;
use mobula_core::ClusterRegistry;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;

const KID: &str = "test-key-1";

pub struct Idp {
    pub issuer: String,
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

pub async fn spawn_idp() -> Idp {
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

pub fn idp_token(idp: &Idp, groups: &[&str]) -> String {
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

async fn validator_for(idp: &Idp) -> Arc<Validator> {
    let config = AuthConfig {
        issuer: idp.issuer.clone(),
        audience: "mobula".into(),
        groups_claim: "groups".into(),
        roles: RoleMappings {
            admin: vec!["/platform-admins".into()],
            operator: vec!["/sre".into()],
            developer: vec!["/ml-eng".into()],
            viewer: vec!["/observers".into()],
        },
    };
    Arc::new(
        Validator::discover(config, reqwest::Client::new(), true)
            .await
            .unwrap(),
    )
}

/// Full app with auth enabled and the cluster routes mounted on `store`.
pub async fn authed_app_with_store(idp: &Idp, store: Arc<dyn Store>) -> Router {
    mobula_api::build_app_full(
        ClusterRegistry::default(),
        Some(validator_for(idp).await),
        Some(store),
        Default::default(),
    )
}

/// Full app with auth enabled and the Serve-service routes mounted.
pub async fn authed_app_with_services(
    idp: &Idp,
    provisioner: Arc<dyn mobula_provision::ServiceProvisioner>,
) -> Router {
    mobula_api::build_app_full_svc(
        ClusterRegistry::default(),
        Some(validator_for(idp).await),
        None,
        Default::default(),
        Some(provisioner),
    )
}

/// Same, but with a governance policy (quotas/prices) for Phase 4 tests.
pub async fn authed_app_with_policy(
    idp: &Idp,
    store: Arc<dyn Store>,
    policy: mobula_api::clusters::PolicyConfig,
) -> Router {
    mobula_api::build_app_full(
        ClusterRegistry::default(),
        Some(validator_for(idp).await),
        Some(store),
        policy,
    )
}

pub fn get(path: &str, host: &str, token: Option<&str>) -> Request<Body> {
    let mut req = Request::get(path).header(header::HOST, host);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    req.body(Body::empty()).unwrap()
}

pub fn post_json(path: &str, host: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::post(path)
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A `Store` that delegates to `InMemoryStore` but fails the named methods
/// with an injected backend error — drives the handlers' 500 paths.
pub struct FailingStore {
    inner: mobula_controller::InMemoryStore,
    fail: std::sync::Mutex<std::collections::BTreeSet<&'static str>>,
}

impl FailingStore {
    pub fn new() -> Self {
        Self {
            inner: mobula_controller::InMemoryStore::new(),
            fail: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    /// Make `method` (a `Store` method name) fail from now on.
    pub fn fail(&self, method: &'static str) {
        self.fail.lock().unwrap().insert(method);
    }

    fn check(&self, method: &'static str) -> Result<(), mobula_controller::StoreError> {
        if self.fail.lock().unwrap().contains(method) {
            Err(mobula_controller::StoreError::Backend(format!(
                "injected {method} failure"
            )))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl mobula_controller::Store for FailingStore {
    async fn upsert_desired(
        &self,
        id: &mobula_core::ClusterId,
        spec: mobula_core::ClusterSpec,
    ) -> Result<u64, mobula_controller::StoreError> {
        self.check("upsert_desired")?;
        self.inner.upsert_desired(id, spec).await
    }
    async fn get(
        &self,
        id: &mobula_core::ClusterId,
    ) -> Result<Option<mobula_controller::StoredCluster>, mobula_controller::StoreError> {
        self.check("get")?;
        self.inner.get(id).await
    }
    async fn list(
        &self,
    ) -> Result<Vec<mobula_controller::StoredCluster>, mobula_controller::StoreError> {
        self.check("list")?;
        self.inner.list().await
    }
    async fn set_desired(
        &self,
        id: &mobula_core::ClusterId,
        desired: mobula_controller::DesiredState,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("set_desired")?;
        self.inner.set_desired(id, desired).await
    }
    async fn record_observation(
        &self,
        id: &mobula_core::ClusterId,
        observed: Option<mobula_core::ClusterState>,
        observed_generation: u64,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("record_observation")?;
        self.inner
            .record_observation(id, observed, observed_generation)
            .await
    }
    async fn set_condition(
        &self,
        id: &mobula_core::ClusterId,
        condition: Option<mobula_core::DriftCondition>,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("set_condition")?;
        self.inner.set_condition(id, condition).await
    }
    async fn is_quarantined(&self) -> Result<bool, mobula_controller::StoreError> {
        self.check("is_quarantined")?;
        self.inner.is_quarantined().await
    }
    async fn set_quarantine(&self, q: bool) -> Result<(), mobula_controller::StoreError> {
        self.check("set_quarantine")?;
        self.inner.set_quarantine(q).await
    }
    async fn record_attempt(
        &self,
        id: &mobula_core::ClusterId,
        failure_count: u32,
        next_attempt_at: u64,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("record_attempt")?;
        self.inner
            .record_attempt(id, failure_count, next_attempt_at)
            .await
    }
    async fn begin_intent(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Result<mobula_controller::IntentOutcome, mobula_controller::StoreError> {
        self.check("begin_intent")?;
        self.inner.begin_intent(key, fingerprint).await
    }
    async fn complete_intent(
        &self,
        key: &str,
        response_json: &str,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("complete_intent")?;
        self.inner.complete_intent(key, response_json).await
    }
    async fn get_intent(
        &self,
        key: &str,
    ) -> Result<Option<mobula_controller::IntentRecord>, mobula_controller::StoreError> {
        self.check("get_intent")?;
        self.inner.get_intent(key).await
    }
    async fn reap_intents(
        &self,
        applied_before: u64,
    ) -> Result<u64, mobula_controller::StoreError> {
        self.check("reap_intents")?;
        self.inner.reap_intents(applied_before).await
    }
    async fn record_job(
        &self,
        job: mobula_core::JobRecord,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("record_job")?;
        self.inner.record_job(job).await
    }
    async fn list_jobs(
        &self,
    ) -> Result<Vec<mobula_core::JobRecord>, mobula_controller::StoreError> {
        self.check("list_jobs")?;
        self.inner.list_jobs().await
    }
    async fn upsert_pool(
        &self,
        name: &str,
        spec: mobula_core::PoolSpec,
    ) -> Result<u64, mobula_controller::StoreError> {
        self.check("upsert_pool")?;
        self.inner.upsert_pool(name, spec).await
    }
    async fn get_pool(
        &self,
        name: &str,
    ) -> Result<Option<mobula_controller::StoredPool>, mobula_controller::StoreError> {
        self.check("get_pool")?;
        self.inner.get_pool(name).await
    }
    async fn list_pools(
        &self,
    ) -> Result<Vec<mobula_controller::StoredPool>, mobula_controller::StoreError> {
        self.check("list_pools")?;
        self.inner.list_pools().await
    }
    async fn delete_pool(&self, name: &str) -> Result<(), mobula_controller::StoreError> {
        self.check("delete_pool")?;
        self.inner.delete_pool(name).await
    }
    async fn record_pool_observation(
        &self,
        name: &str,
        observed_json: &str,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("record_pool_observation")?;
        self.inner
            .record_pool_observation(name, observed_json)
            .await
    }
    async fn upsert_allocation(
        &self,
        alloc: mobula_core::AllocationSpec,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("upsert_allocation")?;
        self.inner.upsert_allocation(alloc).await
    }
    async fn list_allocations(
        &self,
        pool: &str,
    ) -> Result<Vec<mobula_core::AllocationSpec>, mobula_controller::StoreError> {
        self.check("list_allocations")?;
        self.inner.list_allocations(pool).await
    }
    async fn delete_allocation(
        &self,
        pool: &str,
        project: &str,
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("delete_allocation")?;
        self.inner.delete_allocation(pool, project).await
    }
    async fn record_usage_samples(
        &self,
        samples: &[mobula_controller::UsageSample],
    ) -> Result<(), mobula_controller::StoreError> {
        self.check("record_usage_samples")?;
        self.inner.record_usage_samples(samples).await
    }
    async fn usage_samples(
        &self,
        project: Option<&str>,
        pool: Option<&str>,
        from: u64,
        to: u64,
    ) -> Result<Vec<mobula_controller::UsageSample>, mobula_controller::StoreError> {
        self.check("usage_samples")?;
        self.inner.usage_samples(project, pool, from, to).await
    }
}
