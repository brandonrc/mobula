//! Cluster lifecycle API tests, including the per-target RBAC tripwire
//! (#26): Operator can manage cluster lifecycle but Developer cannot, and
//! vice-versa on the job surface.

mod common;
use common::{authed_app_with_policy, authed_app_with_store, get, idp_token, post_json, spawn_idp};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use mobula_controller::{
    DesiredState, InMemoryStore, IntentOutcome, IntentRecord, Store, StoreError, StoredCluster,
};
use mobula_core::{ClusterId, ClusterSpec, ClusterState};

/// Store decorator that widens the quota check->write window: `list()` reads
/// the real snapshot, then sleeps before returning it. That makes the TOCTOU
/// bug in quota admission (#44) deterministic under cooperative scheduling —
/// without the per-project lock both concurrent creates capture the same
/// pre-insert snapshot and both admit; with the lock the second create blocks
/// until the first commits, then reads the fresh row and is 409'd.
struct SlowListStore {
    inner: Arc<InMemoryStore>,
}

#[async_trait::async_trait]
impl Store for SlowListStore {
    async fn upsert_desired(&self, id: &ClusterId, spec: ClusterSpec) -> Result<u64, StoreError> {
        self.inner.upsert_desired(id, spec).await
    }
    async fn get(&self, id: &ClusterId) -> Result<Option<StoredCluster>, StoreError> {
        self.inner.get(id).await
    }
    async fn list(&self) -> Result<Vec<StoredCluster>, StoreError> {
        // Read the snapshot first, then sleep before returning it: both
        // concurrent creates thus observe the same pre-insert view unless
        // serialized by the admission lock.
        let snapshot = self.inner.list().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        snapshot
    }
    async fn set_desired(&self, id: &ClusterId, desired: DesiredState) -> Result<(), StoreError> {
        self.inner.set_desired(id, desired).await
    }
    async fn record_observation(
        &self,
        id: &ClusterId,
        observed: Option<ClusterState>,
        observed_generation: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .record_observation(id, observed, observed_generation)
            .await
    }
    async fn begin_intent(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Result<IntentOutcome, StoreError> {
        self.inner.begin_intent(key, fingerprint).await
    }
    async fn complete_intent(&self, key: &str, response_json: &str) -> Result<(), StoreError> {
        self.inner.complete_intent(key, response_json).await
    }
    async fn get_intent(&self, key: &str) -> Result<Option<IntentRecord>, StoreError> {
        self.inner.get_intent(key).await
    }
    async fn reap_intents(&self, applied_before: u64) -> Result<u64, StoreError> {
        self.inner.reap_intents(applied_before).await
    }
    async fn set_condition(
        &self,
        id: &ClusterId,
        condition: Option<mobula_core::DriftCondition>,
    ) -> Result<(), StoreError> {
        self.inner.set_condition(id, condition).await
    }
    async fn is_quarantined(&self) -> Result<bool, StoreError> {
        self.inner.is_quarantined().await
    }
    async fn set_quarantine(&self, quarantined: bool) -> Result<(), StoreError> {
        self.inner.set_quarantine(quarantined).await
    }
    async fn record_attempt(
        &self,
        id: &ClusterId,
        failure_count: u32,
        next_attempt_at: u64,
    ) -> Result<(), StoreError> {
        self.inner
            .record_attempt(id, failure_count, next_attempt_at)
            .await
    }
    async fn record_job(&self, job: mobula_core::JobRecord) -> Result<(), StoreError> {
        self.inner.record_job(job).await
    }
    async fn list_jobs(&self) -> Result<Vec<mobula_core::JobRecord>, StoreError> {
        self.inner.list_jobs().await
    }
    async fn upsert_pool(
        &self,
        name: &str,
        spec: mobula_core::PoolSpec,
    ) -> Result<u64, StoreError> {
        self.inner.upsert_pool(name, spec).await
    }
    async fn get_pool(
        &self,
        name: &str,
    ) -> Result<Option<mobula_controller::StoredPool>, StoreError> {
        self.inner.get_pool(name).await
    }
    async fn list_pools(&self) -> Result<Vec<mobula_controller::StoredPool>, StoreError> {
        self.inner.list_pools().await
    }
    async fn delete_pool(&self, name: &str) -> Result<(), StoreError> {
        self.inner.delete_pool(name).await
    }
    async fn record_pool_observation(
        &self,
        name: &str,
        observed_json: &str,
    ) -> Result<(), StoreError> {
        self.inner
            .record_pool_observation(name, observed_json)
            .await
    }
    async fn upsert_allocation(
        &self,
        alloc: mobula_core::AllocationSpec,
    ) -> Result<(), StoreError> {
        self.inner.upsert_allocation(alloc).await
    }
    async fn list_allocations(
        &self,
        pool: &str,
    ) -> Result<Vec<mobula_core::AllocationSpec>, StoreError> {
        self.inner.list_allocations(pool).await
    }
    async fn delete_allocation(&self, pool: &str, project: &str) -> Result<(), StoreError> {
        self.inner.delete_allocation(pool, project).await
    }
    async fn record_usage_samples(
        &self,
        samples: &[mobula_controller::UsageSample],
    ) -> Result<(), StoreError> {
        self.inner.record_usage_samples(samples).await
    }
    async fn usage_samples(
        &self,
        project: Option<&str>,
        pool: Option<&str>,
        from: u64,
        to: u64,
    ) -> Result<Vec<mobula_controller::UsageSample>, StoreError> {
        self.inner.usage_samples(project, pool, from, to).await
    }
    async fn record_audit(&self, event: &mobula_core::AuditEvent) -> Result<u64, StoreError> {
        self.inner.record_audit(event).await
    }
    async fn list_audit(
        &self,
        filter: &mobula_core::AuditFilter,
    ) -> Result<(Vec<(u64, mobula_core::AuditEvent)>, Option<u64>), StoreError> {
        self.inner.list_audit(filter).await
    }
    async fn create_local_user(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        role: mobula_core::LocalRole,
    ) -> Result<(), StoreError> {
        self.inner
            .create_local_user(username, email, password_hash, role)
            .await
    }
    async fn get_local_user(
        &self,
        username: &str,
    ) -> Result<Option<mobula_core::LocalUserRecord>, StoreError> {
        self.inner.get_local_user(username).await
    }
    async fn list_local_users(&self) -> Result<Vec<mobula_core::LocalUserRecord>, StoreError> {
        self.inner.list_local_users().await
    }
    async fn set_local_user_password(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), StoreError> {
        self.inner
            .set_local_user_password(username, password_hash)
            .await
    }
    async fn set_local_user_role(
        &self,
        username: &str,
        role: mobula_core::LocalRole,
    ) -> Result<(), StoreError> {
        self.inner.set_local_user_role(username, role).await
    }
    async fn set_local_user_disabled(
        &self,
        username: &str,
        disabled: bool,
    ) -> Result<(), StoreError> {
        self.inner.set_local_user_disabled(username, disabled).await
    }
    async fn set_login_lockout(
        &self,
        username: &str,
        failed_logins: u32,
        locked_until: Option<u64>,
    ) -> Result<(), StoreError> {
        self.inner
            .set_login_lockout(username, failed_logins, locked_until)
            .await
    }
    async fn create_api_token(
        &self,
        record: mobula_core::ApiTokenRecord,
    ) -> Result<(), StoreError> {
        self.inner.create_api_token(record).await
    }
    async fn get_api_token_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<mobula_core::ApiTokenRecord>, StoreError> {
        self.inner.get_api_token_by_prefix(prefix).await
    }
    async fn list_api_tokens(
        &self,
        username: &str,
    ) -> Result<Vec<mobula_core::ApiTokenRecord>, StoreError> {
        self.inner.list_api_tokens(username).await
    }
    async fn revoke_api_token(&self, prefix: &str, username: &str) -> Result<(), StoreError> {
        self.inner.revoke_api_token(prefix, username).await
    }
    async fn touch_api_token(&self, prefix: &str, now: u64) -> Result<(), StoreError> {
        self.inner.touch_api_token(prefix, now).await
    }
}

fn create_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "spec": {
            "name": id,
            "project": "demo",
            "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0",
            "head_cpu": "1",
            "head_memory": "2Gi",
            "worker_groups": [],
            "ttl_seconds": null
        }
    })
}

fn create_body_sized(id: &str, cpu: &str, replicas: u32) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "spec": {
            "name": id, "project": "demo", "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0", "head_cpu": "1", "head_memory": "2Gi",
            "worker_groups": [{
                "name": "w", "cpu": cpu, "memory": "1Gi", "gpu": null,
                "min_replicas": replicas, "max_replicas": replicas, "replicas": replicas
            }],
            "ttl_seconds": null
        }
    })
}

#[tokio::test]
async fn quota_admission_rejects_over_limit_with_409() {
    use mobula_api::clusters::PolicyConfig;
    use mobula_policy::ResourceMap;

    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let mut quotas = std::collections::HashMap::new();
    // demo project capped at 5 CPU.
    quotas.insert(
        "demo".to_string(),
        ResourceMap::from_iter([("cpu".to_string(), 5.0), ("memory".to_string(), 100.0)]),
    );
    let policy = PolicyConfig {
        prices: None,
        quotas,
    };
    let app = authed_app_with_policy(&idp, store, policy).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // First cluster: head 1 + 3×1cpu workers = 4 CPU → fits under 5.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body_sized("a", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Second cluster would add head 1 + 3 = 4 → 4+4=8 > 5 → 409.
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body_sized("b", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "over-quota create must 409"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_creates_cannot_over_admit_quota() {
    use mobula_api::clusters::PolicyConfig;
    use mobula_policy::ResourceMap;

    let idp = spawn_idp().await;
    let inner = Arc::new(InMemoryStore::new());
    let store: Arc<dyn Store> = Arc::new(SlowListStore {
        inner: inner.clone(),
    });

    let mut quotas = std::collections::HashMap::new();
    // demo project capped at 5 CPU; two 4-CPU creates together need 8 > 5.
    quotas.insert(
        "demo".to_string(),
        ResourceMap::from_iter([("cpu".to_string(), 5.0), ("memory".to_string(), 100.0)]),
    );
    let policy = PolicyConfig {
        prices: None,
        quotas,
    };
    let app = authed_app_with_policy(&idp, store, policy).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Each create = head 1 + 3×1cpu workers = 4 CPU.
    let req_a = post_json(
        "/api/v1/clusters",
        "mobula.example.com",
        &admin,
        create_body_sized("a", "1", 3),
    );
    let req_b = post_json(
        "/api/v1/clusters",
        "mobula.example.com",
        &admin,
        create_body_sized("b", "1", 3),
    );

    let (ra, rb) = tokio::join!(app.clone().oneshot(req_a), app.clone().oneshot(req_b),);
    let (sa, sb) = (ra.unwrap().status(), rb.unwrap().status());

    // Exactly one admitted (201), one rejected (409) — never both admitted.
    let mut statuses = [sa, sb];
    statuses.sort_by_key(|s| s.as_u16());
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::CONFLICT],
        "expected exactly one 201 and one 409, got {sa} and {sb}"
    );

    // Only one Running cluster committed in project demo.
    let running = inner
        .list()
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.spec.project == "demo" && c.desired == DesiredState::Running)
        .count();
    assert_eq!(
        running, 1,
        "quota over-admission left extra clusters running"
    );
}

#[tokio::test]
async fn operator_manages_lifecycle_developer_cannot() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store.clone()).await;

    let operator = idp_token(&idp, &["/sre"]);
    let developer = idp_token(&idp, &["/ml-eng"]);

    // Developer (job code, not cluster lifecycle) is denied create.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &developer,
            create_body("dev-attempt"),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "developer cannot create clusters"
    );

    // Operator creates it.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &operator,
            create_body("c1"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(store.get(&ClusterId("c1".into())).await.unwrap().is_some());

    // Developer CAN read (Read on cluster target).
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters",
            "mobula.example.com",
            Some(&developer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Operator deletes (marks terminated).
    let res = app
        .oneshot(
            Request::delete("/api/v1/clusters/c1")
                .header(header::HOST, "mobula.example.com")
                .header(header::AUTHORIZATION, format!("Bearer {operator}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let stored = store.get(&ClusterId("c1".into())).await.unwrap().unwrap();
    assert_eq!(stored.desired, mobula_controller::DesiredState::Terminated);
}

#[tokio::test]
async fn get_single_cluster_and_not_found() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Create via API, then read it back.
    app.clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body("c9"),
        ))
        .await
        .unwrap();

    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters/c9",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["id"], "c9");
    assert_eq!(v["desired"], "running");
    assert_eq!(v["generation"], 1);

    // Missing cluster → 404.
    let res = app
        .oneshot(get(
            "/api/v1/clusters/ghost",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_with_pool_allocation_assigns_queue() {
    // ADR-0010 (Slice 3): with a pool + allocation seeded for the cluster's
    // project, create succeeds and the queue assignment the reconciler will
    // stamp onto the RayCluster is derivable from the store. (The label
    // itself is covered by mobula-provision's to_raycluster tests and the
    // controller's queue_assignment_flows_from_allocation_to_apply test —
    // no provisioner is reachable from the API tests.)
    use mobula_core::{AllocationSpec, FlavorSpec, PoolSpec};
    use std::collections::BTreeMap;

    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_pool(
            "gpu",
            PoolSpec {
                name: "gpu".into(),
                flavors: vec![FlavorSpec {
                    name: "cpu".into(),
                    resources: BTreeMap::from([("cpu".to_string(), "4".to_string())]),
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
    store
        .upsert_allocation(AllocationSpec {
            pool: "gpu".into(),
            project: "demo".into(),
            namespace: "demo".into(),
            nominal: BTreeMap::new(),
            borrowing_limit: BTreeMap::new(),
            lending_limit: BTreeMap::new(),
        })
        .await
        .unwrap();
    let app = authed_app_with_store(&idp, store.clone()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body("c1"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert!(store.get(&ClusterId("c1".into())).await.unwrap().is_some());

    // The store carries what the reconciler needs: the allocation-derived
    // assignment (queue = the allocation's LocalQueue name, elastic = the
    // pool's flag).
    let q = mobula_controller::queue_assignment_for_project(store.as_ref(), "demo")
        .await
        .unwrap();
    assert_eq!(
        q,
        Some(mobula_provision::QueueAssignment {
            queue_name: "demo".into(),
            elastic: true,
        })
    );
}

#[tokio::test]
async fn unauthenticated_and_unmapped_are_denied_on_cluster_routes() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;

    // No token → 401.
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters", "mobula.example.com", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Valid token, unmapped groups → 403 (deny by default).
    let stranger = idp_token(&idp, &["/nobody"]);
    let res = app
        .oneshot(get(
            "/api/v1/clusters",
            "mobula.example.com",
            Some(&stranger),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
