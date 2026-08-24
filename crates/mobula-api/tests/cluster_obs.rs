//! Per-cluster observability endpoints (Milestone C):
//! `GET /api/v1/clusters/{id}/nodes` (§5.3) and
//! `GET /api/v1/clusters/{id}/jobs` (§5.6).
//!
//! Covers the happy path, the credential discipline (registry token goes
//! southbound, caller JWT never does), read-scoped visibility (#49: a
//! project-scoped developer 404s on a foreign cluster), RBAC tripwires, and
//! — the key robustness guarantee — that an unreachable cluster yields a
//! clean 503, never a panic.

mod common;
use common::{get, idp_token, idp_token_sub, spawn_idp, Idp};

use std::sync::{Arc, Mutex};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use mobula_auth::{AuthConfig, RoleMappings, Validator};
use mobula_controller::{InMemoryStore, Store};
use mobula_core::{
    ClusterEndpoint, ClusterId, ClusterNodes, ClusterRegistry, ClusterSpec, NodeView,
    WorkerGroupNodes,
};
use mobula_provision::{DemoProvisioner, ProvisionError, Provisioner};
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

async fn body_json(res: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 22)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A provisioner wrapping the demo lifecycle, with a configurable node
/// breakdown and dashboard base so the obs routes have something to reach.
struct ObsProvisioner {
    inner: DemoProvisioner,
    /// The node breakdown to return; `None` → the trait-default `Ok(None)`
    /// (route answers 404 `nodes unavailable`).
    nodes: Option<ClusterNodes>,
    /// The dashboard base URL for the jobs proxy; `None` → default `None`.
    dashboard_base: Option<String>,
}

#[async_trait::async_trait]
impl Provisioner for ObsProvisioner {
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        generation: u64,
        idempotency_key: &str,
        queue: Option<&mobula_provision::QueueAssignment>,
    ) -> Result<mobula_provision::ApplyResponse, ProvisionError> {
        self.inner
            .apply(id, spec, generation, idempotency_key, queue)
            .await
    }
    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        self.inner.terminate(id).await
    }
    async fn suspend(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        self.inner.suspend(id).await
    }
    async fn resume(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        self.inner.resume(id).await
    }
    async fn observe(
        &self,
        id: &ClusterId,
    ) -> Result<mobula_provision::ObservedCluster, ProvisionError> {
        self.inner.observe(id).await
    }
    async fn list(&self) -> Result<Vec<mobula_provision::ObservedCluster>, ProvisionError> {
        self.inner.list().await
    }
    fn dashboard_api_base(&self, _id: &ClusterId) -> Option<String> {
        self.dashboard_base.clone()
    }
    async fn cluster_nodes(&self, _id: &ClusterId) -> Result<Option<ClusterNodes>, ProvisionError> {
        Ok(self.nodes.clone())
    }
}

fn sample_nodes(cluster_id: &str) -> ClusterNodes {
    ClusterNodes {
        cluster_id: cluster_id.into(),
        head: Some(NodeView {
            pod_name: format!("{cluster_id}-head-abc"),
            group: None,
            is_head: true,
            phase: "Running".into(),
            ready: true,
            node_ip: Some("10.1.0.1".into()),
            host: Some("node-a".into()),
            cpu: Some(1.0),
            memory_bytes: Some(2 * 1024 * 1024 * 1024),
            gpu: None,
        }),
        worker_groups: vec![WorkerGroupNodes {
            name: "cpu".into(),
            desired: 2,
            ready: 1,
            nodes: vec![NodeView {
                pod_name: format!("{cluster_id}-cpu-1"),
                group: Some("cpu".into()),
                is_head: false,
                phase: "Running".into(),
                ready: true,
                node_ip: Some("10.1.0.2".into()),
                host: Some("node-b".into()),
                cpu: Some(4.0),
                memory_bytes: Some(8 * 1024 * 1024 * 1024),
                gpu: None,
            }],
        }],
    }
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

async fn obs_app(
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

/// A mock Ray head serving `GET /api/jobs/`, recording each request's
/// Authorization header.
async fn spawn_mock_jobs_head() -> (String, Arc<Mutex<Vec<Option<String>>>>) {
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_handler = seen.clone();
    let app = axum::Router::new().route(
        "/api/jobs/",
        axum::routing::get(move |headers: HeaderMap| {
            let seen = seen_handler.clone();
            async move {
                seen.lock().unwrap().push(
                    headers
                        .get(header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok().map(String::from)),
                );
                axum::Json(serde_json::json!([
                    {
                        "job_id": "01000000",
                        "submission_id": "raysubmit_abc",
                        "status": "SUCCEEDED",
                        "entrypoint": "python train.py",
                        "start_time": 1_755_280_010_000u64,
                        "end_time": 1_755_281_900_000u64,
                        "message": "Job finished successfully."
                    },
                    {
                        "submission_id": "raysubmit_def",
                        "status": "RUNNING",
                        "entrypoint": "serve run app:main",
                        "start_time": 1_755_282_000_000u64
                    }
                ]))
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

// ---------------------------------------------------------------------------
// Nodes (§5.3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nodes_returns_head_and_worker_groups() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_desired(&ClusterId("c1".into()), cluster_spec("proj-a"))
        .await
        .unwrap();
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: Some(sample_nodes("c1")),
        dashboard_base: None,
    });
    let app = obs_app(
        &idp,
        store,
        registry_for("c1", "http://unused", None),
        Some(provisioner),
    )
    .await;

    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/nodes",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    assert_eq!(v["cluster_id"], "c1");
    assert_eq!(v["head"]["is_head"], true);
    assert_eq!(v["head"]["pod_name"], "c1-head-abc");
    assert_eq!(v["worker_groups"][0]["name"], "cpu");
    assert_eq!(v["worker_groups"][0]["desired"], 2);
    assert_eq!(v["worker_groups"][0]["ready"], 1);
    assert_eq!(v["worker_groups"][0]["nodes"][0]["group"], "cpu");
}

#[tokio::test]
async fn nodes_gateway_only_deployment_is_404() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_desired(&ClusterId("c1".into()), cluster_spec("proj-a"))
        .await
        .unwrap();
    // No provisioner → nodes unavailable.
    let app = obs_app(&idp, store, ClusterRegistry::default(), None).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/nodes",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(body_text(res).await.contains("nodes unavailable"));
}

#[tokio::test]
async fn nodes_unknown_cluster_is_404() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: Some(sample_nodes("c1")),
        dashboard_base: None,
    });
    let app = obs_app(&idp, store, ClusterRegistry::default(), Some(provisioner)).await;
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/ghost/nodes",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(body_text(res).await.contains("no such cluster"));
}

#[tokio::test]
async fn nodes_rbac_unauthenticated_401_roleless_403() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_desired(&ClusterId("c1".into()), cluster_spec("proj-a"))
        .await
        .unwrap();
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: Some(sample_nodes("c1")),
        dashboard_base: None,
    });
    let app = obs_app(&idp, store, ClusterRegistry::default(), Some(provisioner)).await;

    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters/c1/nodes", "mobula.example.com", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let nobody = idp_token(&idp, &["/no-such-group"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/nodes",
            "mobula.example.com",
            Some(&nobody),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// #49 read-scoping: a project-scoped developer sees her project's cluster
/// nodes (200) but 404s on a foreign cluster — existence must not leak.
#[tokio::test]
async fn nodes_read_scoping_hides_foreign_cluster() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    // alice: global viewer (via /observers) + operator scoped to ml-team.
    store
        .upsert_role_assignment("alice", "operator", "project:ml-team")
        .await
        .unwrap();
    store
        .upsert_desired(&ClusterId("vision".into()), cluster_spec("ml-team"))
        .await
        .unwrap();
    store
        .upsert_desired(&ClusterId("genai".into()), cluster_spec("genai"))
        .await
        .unwrap();
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: Some(sample_nodes("vision")),
        dashboard_base: None,
    });
    let app = obs_app(&idp, store, ClusterRegistry::default(), Some(provisioner)).await;

    let alice = idp_token_sub(&idp, "alice", &["/observers"]);
    // In-scope: 200.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters/vision/nodes",
            "mobula.example.com",
            Some(&alice),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "in-scope nodes");
    // Out-of-scope: 404, not 403.
    let res = app
        .oneshot(get(
            "/api/v1/clusters/genai/nodes",
            "mobula.example.com",
            Some(&alice),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "foreign cluster hidden"
    );
}

// ---------------------------------------------------------------------------
// Jobs (§5.6)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn jobs_proxies_normalizes_and_injects_registry_token_not_jwt() {
    let idp = spawn_idp().await;
    let (base_url, seen) = spawn_mock_jobs_head().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_desired(&ClusterId("c1".into()), cluster_spec("proj-a"))
        .await
        .unwrap();
    // Registry entry supplies the southbound base + static token.
    let registry = registry_for("c1", &base_url, Some("ray-static-token"));
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: None,
        dashboard_base: None,
    });
    let app = obs_app(&idp, store, registry, Some(provisioner)).await;

    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/jobs",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let v = body_json(res).await;
    let arr = v.as_array().expect("job list array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["submission_id"], "raysubmit_abc");
    assert_eq!(arr[0]["status"], "SUCCEEDED");
    assert_eq!(arr[0]["end_time"], 1_755_281_900_000u64);
    // Running job: no end_time serialized.
    assert_eq!(arr[1]["status"], "RUNNING");
    assert!(arr[1].get("end_time").is_none());

    // Credential discipline: registry token southbound, JWT nowhere.
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].as_deref(), Some("Bearer ray-static-token"));
    assert!(!requests[0].as_ref().unwrap().contains(&viewer));
}

#[tokio::test]
async fn jobs_lifecycle_managed_uses_provisioner_base_and_no_credential() {
    let idp = spawn_idp().await;
    let (base_url, seen) = spawn_mock_jobs_head().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_desired(&ClusterId("c1".into()), cluster_spec("proj-a"))
        .await
        .unwrap();
    // No registry entry: the base comes from the provisioner (lifecycle path),
    // and no static token is injected.
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: None,
        dashboard_base: Some(base_url),
    });
    let app = obs_app(&idp, store, ClusterRegistry::default(), Some(provisioner)).await;

    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/jobs",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0], None, "no Authorization may go southbound");
}

/// The key robustness guarantee: an unreachable cluster is a clean 503, not
/// a panic and not a 500.
#[tokio::test]
async fn jobs_unreachable_cluster_is_503() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_desired(&ClusterId("c1".into()), cluster_spec("proj-a"))
        .await
        .unwrap();
    // Port 1 refuses connections deterministically.
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: None,
        dashboard_base: Some("http://127.0.0.1:1".into()),
    });
    let app = obs_app(&idp, store, ClusterRegistry::default(), Some(provisioner)).await;

    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/c1/jobs",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(body_text(res).await.contains("cluster unreachable"));
}

#[tokio::test]
async fn jobs_read_scoping_hides_foreign_cluster() {
    let idp = spawn_idp().await;
    let (base_url, _seen) = spawn_mock_jobs_head().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_role_assignment("alice", "operator", "project:ml-team")
        .await
        .unwrap();
    store
        .upsert_desired(&ClusterId("genai".into()), cluster_spec("genai"))
        .await
        .unwrap();
    let provisioner = Arc::new(ObsProvisioner {
        inner: DemoProvisioner::new(),
        nodes: None,
        dashboard_base: Some(base_url),
    });
    let app = obs_app(&idp, store, ClusterRegistry::default(), Some(provisioner)).await;

    let alice = idp_token_sub(&idp, "alice", &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters/genai/jobs",
            "mobula.example.com",
            Some(&alice),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "foreign cluster hidden"
    );
}
