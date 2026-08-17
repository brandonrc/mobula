//! Metrics API tests (#52, first slice): the per-cluster Ray metrics
//! passthrough (`/api/v1/clusters/{id}/metrics`) and the control-plane
//! gauges on `/api/v1/metrics` — including the credential discipline
//! (the cluster's static registry token goes southbound, the caller's JWT
//! never does) and RBAC tripwires.

mod common;
use common::{get, idp_token, spawn_idp, Idp};

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use mobula_auth::{AuthConfig, RoleMappings, Validator};
use mobula_controller::{InMemoryStore, Store};
use mobula_core::{ClusterEndpoint, ClusterId, ClusterRegistry, ClusterSpec, ClusterState};
use mobula_provision::{DemoProvisioner, Provisioner};
use tower::ServiceExt;

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
            auditor: vec![],
        },
    };
    Arc::new(
        Validator::discover(config, reqwest::Client::new(), true)
            .await
            .unwrap(),
    )
}

async fn body_text(res: Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 22)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// A provisioner with a real metrics endpoint (the mock head's URL) and a
/// demo-provisioner lifecycle, so the passthrough has something to proxy.
struct StaticMetricsProvisioner {
    inner: DemoProvisioner,
    endpoint: String,
}

#[async_trait::async_trait]
impl Provisioner for StaticMetricsProvisioner {
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        generation: u64,
        idempotency_key: &str,
        queue: Option<&mobula_provision::QueueAssignment>,
    ) -> Result<mobula_provision::ApplyResponse, mobula_provision::ProvisionError> {
        self.inner
            .apply(id, spec, generation, idempotency_key, queue)
            .await
    }
    async fn terminate(&self, id: &ClusterId) -> Result<(), mobula_provision::ProvisionError> {
        self.inner.terminate(id).await
    }
    async fn suspend(&self, id: &ClusterId) -> Result<(), mobula_provision::ProvisionError> {
        self.inner.suspend(id).await
    }
    async fn resume(&self, id: &ClusterId) -> Result<(), mobula_provision::ProvisionError> {
        self.inner.resume(id).await
    }
    async fn observe(
        &self,
        id: &ClusterId,
    ) -> Result<mobula_provision::ObservedCluster, mobula_provision::ProvisionError> {
        self.inner.observe(id).await
    }
    async fn list(
        &self,
    ) -> Result<Vec<mobula_provision::ObservedCluster>, mobula_provision::ProvisionError> {
        self.inner.list().await
    }
    fn metrics_endpoint(&self, _id: &ClusterId) -> Option<String> {
        Some(self.endpoint.clone())
    }
}

/// A mock Ray head on 127.0.0.1 serving a fixed exposition and recording
/// the Authorization header of every request it receives.
async fn spawn_mock_head() -> (String, Arc<Mutex<Vec<Option<String>>>>) {
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_handler = seen.clone();
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move |headers: HeaderMap| {
            let seen = seen_handler.clone();
            async move {
                seen.lock().unwrap().push(
                    headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok().map(String::from)),
                );
                "# HELP ray_task_total Ray tasks\n# TYPE ray_task_total gauge\nray_task_total 7\n"
                    .to_string()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), seen)
}

fn registry_for(id: &str, base_url: &str, token: Option<&str>) -> ClusterRegistry {
    ClusterRegistry {
        clusters: vec![ClusterEndpoint {
            id: ClusterId(id.into()),
            hostname: format!("{id}.ray.example.com"),
            api_base_url: base_url.into(),
            auth_token: token.map(String::from),
            auth_token_env: None,
        }],
    }
}

/// App with auth, a store, the given registry, and the given cluster
/// provisioner backing `/api/v1/clusters/{id}/metrics`.
async fn metrics_app(
    idp: &Idp,
    store: Arc<dyn Store>,
    registry: ClusterRegistry,
    provisioner: Option<Arc<dyn Provisioner>>,
) -> axum::Router {
    mobula_api::build_app_full_prov(
        registry,
        Some(validator_for(idp).await),
        Some(store),
        Default::default(),
        provisioner,
    )
}

#[tokio::test]
async fn demo_mode_cluster_metrics_is_clean_404() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    // The demo provisioner names no metrics endpoint — the route must say so.
    let app = metrics_app(
        &idp,
        store,
        ClusterRegistry::default(),
        Some(Arc::new(DemoProvisioner::new())),
    )
    .await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/metrics",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(body_text(res).await.contains("metrics unavailable"));
}

#[tokio::test]
async fn gateway_only_deployment_has_no_provisioner_and_404s() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = metrics_app(&idp, store, ClusterRegistry::default(), None).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/metrics",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(body_text(res).await.contains("metrics unavailable"));
}

#[tokio::test]
async fn cluster_metrics_proxies_head_and_injects_registry_token_not_jwt() {
    let idp = spawn_idp().await;
    let (base_url, seen) = spawn_mock_head().await;
    let store = Arc::new(InMemoryStore::new());
    let registry = registry_for("c1", &base_url, Some("ray-static-token"));
    let provisioner = Arc::new(StaticMetricsProvisioner {
        inner: DemoProvisioner::new(),
        endpoint: format!("{base_url}/metrics"),
    });
    let app = metrics_app(&idp, store, registry, Some(provisioner)).await;

    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/metrics",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let ct = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(ct.starts_with("text/plain"), "content-type: {ct}");
    let body = body_text(res).await;
    assert!(body.contains("ray_task_total 7"), "{body}");

    // Credential discipline (ADR-0003): exactly one southbound request, with
    // the registry's static token — and the caller's JWT nowhere near it.
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].as_deref(), Some("Bearer ray-static-token"));
    assert!(!requests[0].as_ref().unwrap().contains(&viewer));
}

#[tokio::test]
async fn cluster_metrics_without_registry_token_sends_no_credential() {
    let idp = spawn_idp().await;
    let (base_url, seen) = spawn_mock_head().await;
    let store = Arc::new(InMemoryStore::new());
    // Registry entry WITHOUT a static token.
    let registry = registry_for("c1", &base_url, None);
    let provisioner = Arc::new(StaticMetricsProvisioner {
        inner: DemoProvisioner::new(),
        endpoint: format!("{base_url}/metrics"),
    });
    let app = metrics_app(&idp, store, registry, Some(provisioner)).await;

    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/metrics",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // The caller's JWT is stripped, and nothing replaces it.
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0], None, "no Authorization may go southbound");
}

#[tokio::test]
async fn cluster_metrics_rbac_viewer_reads_unauthenticated_401_roleless_403() {
    let idp = spawn_idp().await;
    let (base_url, _seen) = spawn_mock_head().await;
    let store = Arc::new(InMemoryStore::new());
    let registry = registry_for("c1", &base_url, Some("ray-static-token"));
    let provisioner = Arc::new(StaticMetricsProvisioner {
        inner: DemoProvisioner::new(),
        endpoint: format!("{base_url}/metrics"),
    });
    let app = metrics_app(&idp, store, registry, Some(provisioner)).await;

    // Viewer (lowest role) can read cluster metrics.
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters/c1/metrics",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // No token → 401.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters/c1/metrics",
            "mobula.example.com",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // A valid token whose groups map to no role → 403 at the handler.
    let nobody = idp_token(&idp, &["/no-such-group"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/metrics",
            "mobula.example.com",
            Some(&nobody),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

fn cluster_spec(project: &str) -> ClusterSpec {
    ClusterSpec {
        name: "c".into(),
        project: project.into(),
        ray_version: "2.57.0".into(),
        image: "img".into(),
        head_cpu: "1".into(),
        head_memory: "2Gi".into(),
        worker_groups: vec![],
        ttl_seconds: None,
    }
}

#[tokio::test]
async fn control_plane_gauges_reflect_seeded_store_state() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());

    // Fleet: two proj-a clusters (one Running, one Suspended) and a proj-b
    // cluster with no reconcile observation yet (→ state="unknown").
    let c1 = ClusterId("c1".into());
    let c2 = ClusterId("c2".into());
    let c3 = ClusterId("c3".into());
    store
        .upsert_desired(&c1, cluster_spec("proj-a"))
        .await
        .unwrap();
    store
        .upsert_desired(&c2, cluster_spec("proj-a"))
        .await
        .unwrap();
    store
        .upsert_desired(&c3, cluster_spec("proj-b"))
        .await
        .unwrap();
    store
        .record_observation(&c1, Some(ClusterState::Running), 1)
        .await
        .unwrap();
    store
        .record_observation(&c2, Some(ClusterState::Suspended), 1)
        .await
        .unwrap();

    // Pool capacity: cpu 64, memory 256Gi nominal across flavors.
    store
        .upsert_pool(
            "gpu",
            mobula_core::PoolSpec {
                name: "gpu".into(),
                flavors: vec![mobula_core::FlavorSpec {
                    name: "a100".into(),
                    resources: BTreeMap::from([
                        ("cpu".to_string(), "64".to_string()),
                        ("memory".to_string(), "256Gi".to_string()),
                    ]),
                    node_labels: BTreeMap::new(),
                    taints: vec![],
                }],
                cohort: "research".into(),
                fair_sharing_weight: 1.0,
                elastic: true,
            },
        )
        .await
        .unwrap();

    let app = metrics_app(&idp, store, ClusterRegistry::default(), None).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get("/api/v1/metrics", "mobula.example.com", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = body_text(res).await;

    // The pre-existing usage gauge is untouched.
    assert!(text.contains("# TYPE mobula_pool_resource_usage gauge"));

    assert!(text.contains("# TYPE mobula_clusters_total gauge"));
    assert!(
        text.contains("mobula_clusters_total{state=\"running\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("mobula_clusters_total{state=\"suspended\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("mobula_clusters_total{state=\"unknown\"} 1"),
        "unobserved cluster counts as unknown: {text}"
    );
    assert!(text.contains("# TYPE mobula_clusters_by_project gauge"));
    assert!(
        text.contains("mobula_clusters_by_project{project=\"proj-a\"} 2"),
        "{text}"
    );
    assert!(
        text.contains("mobula_clusters_by_project{project=\"proj-b\"} 1"),
        "{text}"
    );

    assert!(text.contains("# TYPE mobula_pool_nominal gauge"));
    assert!(
        text.contains("mobula_pool_nominal{pool=\"gpu\",resource=\"cpu\"} 64"),
        "{text}"
    );
    let gib = 256.0 * 1024.0 * 1024.0 * 1024.0;
    assert!(
        text.contains(&format!(
            "mobula_pool_nominal{{pool=\"gpu\",resource=\"memory\"}} {gib}"
        )),
        "{text}"
    );
}
