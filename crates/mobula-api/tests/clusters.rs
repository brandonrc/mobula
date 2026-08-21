//! Cluster lifecycle API tests, including the per-target RBAC tripwire
//! (#26): Operator can manage cluster lifecycle but Developer cannot, and
//! vice-versa on the job surface.

mod common;
use common::{authed_app_with_policy, authed_app_with_store, get, idp_token, post_json, spawn_idp};

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

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
    async fn get_policy(&self) -> Result<Option<mobula_controller::StoredPolicy>, StoreError> {
        self.inner.get_policy().await
    }
    async fn set_policy(&self, policy: &mobula_controller::StoredPolicy) -> Result<(), StoreError> {
        self.inner.set_policy(policy).await
    }
    async fn seed_policy(
        &self,
        policy: &mobula_controller::StoredPolicy,
    ) -> Result<bool, StoreError> {
        self.inner.seed_policy(policy).await
    }
    async fn list_audit(
        &self,
        filter: &mobula_core::AuditFilter,
    ) -> Result<(Vec<(u64, mobula_core::AuditEvent)>, Option<u64>), StoreError> {
        self.inner.list_audit(filter).await
    }
    async fn audit_chain(
        &self,
        from_seq: Option<u64>,
        limit: u32,
    ) -> Result<mobula_controller::AuditChainWindow, StoreError> {
        self.inner.audit_chain(from_seq, limit).await
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
    async fn upsert_role_assignment(
        &self,
        principal: &str,
        role: &str,
        scope: &str,
    ) -> Result<(), StoreError> {
        self.inner
            .upsert_role_assignment(principal, role, scope)
            .await
    }
    async fn list_role_assignments(
        &self,
        principal: Option<&str>,
    ) -> Result<Vec<mobula_controller::RoleAssignment>, StoreError> {
        self.inner.list_role_assignments(principal).await
    }
    async fn delete_role_assignment(
        &self,
        principal: &str,
        role: &str,
        scope: &str,
    ) -> Result<(), StoreError> {
        self.inner
            .delete_role_assignment(principal, role, scope)
            .await
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
        gpu_default_sharing: Default::default(),
        pod_shaping: Default::default(),
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
        gpu_default_sharing: Default::default(),
        pod_shaping: Default::default(),
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
                gpu_sharing: None,
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

/// POST with an empty body (lifecycle actions take no payload).
fn post_empty(path: &str, host: &str, token: &str) -> Request<Body> {
    Request::post(path)
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn suspend_resume_lifecycle_202_and_409s() {
    // #51: suspend/resume flip desired state (202) along legal
    // can_transition edges of the OBSERVED state; meaningless commands 409.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store.clone()).await;
    let operator = idp_token(&idp, &["/sre"]);
    let id = ClusterId("c1".into());

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

    // Not yet observed (never reconciled) → suspending is meaningless.
    let res = app
        .clone()
        .oneshot(post_empty(
            "/api/v1/clusters/c1/suspend",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "unprovisioned → 409");

    // Observed Running → suspend accepted; desired flips, response carries
    // the transitional state (api-v1.md §5.1).
    store
        .record_observation(&id, Some(ClusterState::Running), 1)
        .await
        .unwrap();
    let res = app
        .clone()
        .oneshot(post_empty(
            "/api/v1/clusters/c1/suspend",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["state"], "suspending");
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().desired,
        DesiredState::Suspended
    );

    // Already suspended → 409 illegal_state_transition.
    store
        .record_observation(&id, Some(ClusterState::Suspended), 1)
        .await
        .unwrap();
    let res = app
        .clone()
        .oneshot(post_empty(
            "/api/v1/clusters/c1/suspend",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "already suspended → 409"
    );

    // Resume from Suspended → 202, desired back to Running.
    let res = app
        .clone()
        .oneshot(post_empty(
            "/api/v1/clusters/c1/resume",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["state"], "provisioning", "resume re-provisions");
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().desired,
        DesiredState::Running
    );

    // Resuming a Running cluster is meaningless → 409.
    store
        .record_observation(&id, Some(ClusterState::Running), 1)
        .await
        .unwrap();
    let res = app
        .clone()
        .oneshot(post_empty(
            "/api/v1/clusters/c1/resume",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "running → resume 409");

    // Terminated is terminal for both commands.
    store
        .record_observation(&id, Some(ClusterState::Terminated), 1)
        .await
        .unwrap();
    for verb in ["suspend", "resume"] {
        let res = app
            .clone()
            .oneshot(post_empty(
                &format!("/api/v1/clusters/c1/{verb}"),
                "mobula.example.com",
                &operator,
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "terminated → {verb} 409"
        );
    }

    // Unknown cluster → 404.
    let res = app
        .oneshot(post_empty(
            "/api/v1/clusters/ghost/suspend",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn suspend_resume_require_cluster_write_permission() {
    // #51 + #26: Write on Target::Cluster is Operator/Admin only — a
    // Developer (job surface) gets 403 on both lifecycle actions.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store.clone()).await;
    let operator = idp_token(&idp, &["/sre"]);
    let developer = idp_token(&idp, &["/ml-eng"]);

    app.clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &operator,
            create_body("c1"),
        ))
        .await
        .unwrap();
    store
        .record_observation(&ClusterId("c1".into()), Some(ClusterState::Running), 1)
        .await
        .unwrap();

    for verb in ["suspend", "resume"] {
        let res = app
            .clone()
            .oneshot(post_empty(
                &format!("/api/v1/clusters/c1/{verb}"),
                "mobula.example.com",
                &developer,
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "developer → {verb} 403"
        );
    }
}

#[tokio::test]
async fn queue_assigned_cluster_rejects_suspend_and_resume() {
    // #51 + ADR-0010: Kueue owns spec.suspend for a cluster whose project is
    // admitted through a pool queue — both lifecycle commands are 409.
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
                elastic: false,
                gpu_sharing: None,
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
    let operator = idp_token(&idp, &["/sre"]);

    app.clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &operator,
            create_body("c1"),
        ))
        .await
        .unwrap();
    store
        .record_observation(&ClusterId("c1".into()), Some(ClusterState::Running), 1)
        .await
        .unwrap();

    let res = app
        .clone()
        .oneshot(post_empty(
            "/api/v1/clusters/c1/suspend",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "queued → suspend 409");
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"], "queue_owned_suspend");

    let res = app
        .oneshot(post_empty(
            "/api/v1/clusters/c1/resume",
            "mobula.example.com",
            &operator,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "queued → resume 409");

    // Neither command touched desired state.
    assert_eq!(
        store
            .get(&ClusterId("c1".into()))
            .await
            .unwrap()
            .unwrap()
            .desired,
        DesiredState::Running
    );
}

fn create_body_in(id: &str, project: &str) -> serde_json::Value {
    let mut b = create_body(id);
    b["spec"]["project"] = serde_json::json!(project);
    b
}

/// Scoped RBAC (ADR-0009 addendum, #49): a developer holding an `operator`
/// assignment at `project:ml-team` can manage ml-team clusters but gets 403
/// elsewhere; admins and assignment-less viewers are unchanged; a caller
/// with no global roles sees only their scoped projects in the list.
#[tokio::test]
async fn scoped_assignments_gate_cluster_lifecycle_per_project() {
    use common::idp_token_sub;

    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    store
        .upsert_role_assignment("dev-1", "operator", "project:ml-team")
        .await
        .unwrap();
    // "solo" holds NO group-derived role (viewer maps to /observers, no "*"
    // wildcard) — only the ml-team assignment.
    store
        .upsert_role_assignment("solo", "operator", "project:ml-team")
        .await
        .unwrap();
    let app = authed_app_with_store(&idp, store.clone()).await;

    let dev = idp_token_sub(&idp, "dev-1", &["/ml-eng"]);

    // Create in the assigned project succeeds (scoped Write on Cluster).
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.test",
            &dev,
            create_body_in("c-ml", "ml-team"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "scoped create");

    // Create in any other project is denied — the assignment doesn't cover it
    // and the flat Developer role has only Read on Cluster.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.test",
            &dev,
            create_body_in("c-nope", "other"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "out-of-scope create");

    // Get/delete follow the same scoping.
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters/c-ml", "mobula.test", Some(&dev)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "scoped get");
    let res = app
        .clone()
        .oneshot(
            Request::delete("/api/v1/clusters/c-ml")
                .header(header::HOST, "mobula.test")
                .header(header::AUTHORIZATION, format!("Bearer {dev}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED, "scoped delete");

    // Admin is unaffected: full lifecycle in any project, no assignments.
    let admin = idp_token(&idp, &["/platform-admins"]);
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.test",
            &admin,
            create_body_in("c-admin", "other"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "admin create");

    // Viewer with no assignments is unchanged: reads pass globally, writes 403.
    let viewer = idp_token_sub(&idp, "view-1", &["/observers"]);
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters", "mobula.test", Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "viewer list");
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.test",
            &viewer,
            create_body_in("c-v", "ml-team"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "viewer create");

    // List filtering: "solo" has no global roles, only the ml-team
    // assignment → sees exactly the ml-team clusters.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters",
            "mobula.test",
            Some(&idp_token_sub(&idp, "solo", &[])),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "scoped list");
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let ids: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["c-ml"], "scoped caller sees only ml-team clusters");

    // A caller with no roles AND no assignments is still denied, as before.
    let nobody = idp_token_sub(&idp, "nobody", &[]);
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters", "mobula.test", Some(&nobody)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "role-less list");
    let res = app
        .oneshot(get("/api/v1/clusters/c-ml", "mobula.test", Some(&nobody)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "role-less get");
}

/// Read-scoping (ADR-0009 addendum): a caller whose access derives from
/// project-scoped assignments only SEES those projects' clusters — the
/// list is filtered and an out-of-scope get-by-name is 404 — even while
/// also holding a global role (the both-global-and-scoped edge case:
/// scoped presence narrows visibility). Global admin and assignment-less
/// viewers are unaffected.
#[tokio::test]
async fn scoped_assignments_narrow_cluster_read_visibility() {
    use common::idp_token_sub;

    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    // alice: global viewer via group mapping + operator scoped to ml-team.
    store
        .upsert_role_assignment("alice", "operator", "project:ml-team")
        .await
        .unwrap();
    let app = authed_app_with_store(&idp, store.clone()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    for (id, project) in [
        ("vision-train", "ml-team"),
        ("alice-ml", "ml-team"),
        ("genai", "genai"),
    ] {
        let res = app
            .clone()
            .oneshot(post_json(
                "/api/v1/clusters",
                "mobula.test",
                &admin,
                create_body_in(id, project),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "seed {id}");
    }

    async fn list_ids(app: &axum::Router, token: &str) -> Vec<String> {
        let res = app
            .clone()
            .oneshot(get("/api/v1/clusters", "mobula.test", Some(token)))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut ids: Vec<String> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    }

    // alice is narrowed to her scoped project despite the global viewer role.
    let alice = idp_token_sub(&idp, "alice", &["/observers"]);
    assert_eq!(
        list_ids(&app, &alice).await,
        ["alice-ml", "vision-train"],
        "scoped list hides foreign projects"
    );

    // Get-by-name: in-scope reads fine; out-of-scope is 404, not 403 —
    // existence must not leak.
    let res = app
        .clone()
        .oneshot(get(
            "/api/v1/clusters/vision-train",
            "mobula.test",
            Some(&alice),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "in-scope get");
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters/genai", "mobula.test", Some(&alice)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "out-of-scope get 404");

    // Global admin still sees everything, list and by-name.
    assert_eq!(
        list_ids(&app, &admin).await,
        ["alice-ml", "genai", "vision-train"],
        "admin list unfiltered"
    );
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters/genai", "mobula.test", Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "admin get");

    // A global viewer with NO assignments is unaffected too.
    let viewer = idp_token_sub(&idp, "view-1", &["/observers"]);
    assert_eq!(
        list_ids(&app, &viewer).await,
        ["alice-ml", "genai", "vision-train"],
        "assignment-less viewer list unfiltered"
    );
}

/// #58 helpers: a GPU pool with the given sharing mode plus one allocation
/// per project, seeded straight into the store (the pools API is covered
/// separately in tests/pools.rs).
async fn seed_gpu_pool(
    store: &InMemoryStore,
    mode: Option<mobula_core::GpuSharing>,
    projects: &[&str],
) {
    use mobula_core::{AllocationSpec, FlavorSpec, PoolSpec};
    use std::collections::BTreeMap;
    store
        .upsert_pool(
            "gpu",
            PoolSpec {
                name: "gpu".into(),
                flavors: vec![FlavorSpec {
                    name: "a100".into(),
                    resources: BTreeMap::from([("nvidia.com/gpu".to_string(), "8".to_string())]),
                    node_labels: BTreeMap::new(),
                    taints: vec![],
                }],
                cohort: "research".into(),
                fair_sharing_weight: 1.0,
                elastic: false,
                gpu_sharing: mode,
            },
        )
        .await
        .unwrap();
    for project in projects {
        store
            .upsert_allocation(AllocationSpec {
                pool: "gpu".into(),
                project: project.to_string(),
                namespace: project.to_string(),
                nominal: BTreeMap::new(),
                borrowing_limit: BTreeMap::new(),
                lending_limit: BTreeMap::new(),
            })
            .await
            .unwrap();
    }
}

/// A create body whose single worker group requests `gpu` GPUs.
fn create_body_gpu(id: &str, project: &str, gpu: &str) -> serde_json::Value {
    let mut b = create_body_in(id, project);
    b["spec"]["worker_groups"] = serde_json::json!([{
        "name": "w", "cpu": "2", "memory": "4Gi", "gpu": gpu,
        "min_replicas": 1, "max_replicas": 1, "replicas": 1
    }]);
    b
}

/// #58: a fractional GPU request is device-plugin time-slicing — rejected
/// with the tenant-isolation reason when the project's pool is shared by
/// more than one project; whole-GPU requests admit.
#[tokio::test]
async fn fractional_gpu_rejected_in_multi_tenant_pool() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_gpu_pool(&store, None, &["proj-a", "proj-b"]).await;
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body_gpu("frac", "proj-a", "0.5"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        text.contains("tenant isolation"),
        "error names the tenant-isolation reason: {text}"
    );

    // Whole GPUs are fine cross-tenant.
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body_gpu("whole", "proj-a", "2"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// #58: single-tenant pools may time-slice — fractional requests admit,
/// whether the pool opts in explicitly or not.
#[tokio::test]
async fn fractional_gpu_allowed_in_single_tenant_pool() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_gpu_pool(
        &store,
        Some(mobula_core::GpuSharing::TimeSlice),
        &["proj-a"],
    )
    .await;
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body_gpu("frac", "proj-a", "0.5"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// #58: a project with no pool allocation is queue-free and unaffected.
#[tokio::test]
async fn fractional_gpu_allowed_without_pool_allocation() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_gpu_pool(&store, None, &["proj-a", "proj-b"]).await;
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body_gpu("frac", "unallocated", "0.5"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// #58: a multi-tenant time-slice pool is unreachable through the
/// validated API, but a pre-existing stored pool must fail closed — no
/// cluster admits into it at all.
#[tokio::test]
async fn noncompliant_multi_tenant_pool_admits_nothing() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    seed_gpu_pool(
        &store,
        Some(mobula_core::GpuSharing::TimeSlice),
        &["proj-a", "proj-b"],
    )
    .await;
    let app = authed_app_with_store(&idp, store).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body_gpu("whole", "proj-a", "1"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("tenant isolation"), "{text}");
}

// ---------------------------------------------------------------------------
// Pod shaping (#66): the platform declares what exists, the caller picks by
// name. These tests pin the privilege boundary, not the happy path.
// ---------------------------------------------------------------------------

fn shaping_policy() -> mobula_api::clusters::PolicyConfig {
    use mobula_policy::podshape::{MountEntry, PodShapeCatalog};
    mobula_api::clusters::PolicyConfig {
        prices: None,
        quotas: Default::default(),
        gpu_default_sharing: Default::default(),
        pod_shaping: PodShapeCatalog {
            mounts: vec![MountEntry {
                name: "home".into(),
                claim_name: "nebari-home".into(),
                mount_path: "/home/ray".into(),
                read_only: false,
                sub_path: Some("home/{project}".into()),
            }],
            service_accounts: vec!["ray-workload".into()],
            default_mounts: vec!["home".into()],
            ..Default::default()
        },
    }
}

async fn stored_spec(store: &Arc<InMemoryStore>, id: &str) -> ClusterSpec {
    store
        .get(&ClusterId(id.to_string()))
        .await
        .unwrap()
        .expect("cluster stored")
        .spec
}

#[tokio::test]
async fn default_mount_is_applied_and_scoped_to_the_project() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), shaping_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body("a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let shape = stored_spec(&store, "a")
        .await
        .pod_resolved
        .expect("resolved");
    assert_eq!(shape.volumes.len(), 1);
    assert_eq!(shape.volumes[0].claim_name, "nebari-home");
    // The project sub-path is what stops one project reading another's
    // directory out of a shared home volume.
    assert_eq!(shape.volumes[0].sub_path.as_deref(), Some("home/demo"));
}

#[tokio::test]
async fn selecting_an_unlisted_mount_is_refused_with_403() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), shaping_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let mut body = create_body("a");
    body["spec"]["pod"] = serde_json::json!({ "mounts": ["secrets"] });
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            body,
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a mount the deployment does not offer must be refused"
    );
    assert!(
        store.get(&ClusterId("a".into())).await.unwrap().is_none(),
        "a refused create must not be stored"
    );
}

#[tokio::test]
async fn an_unlisted_service_account_is_refused_with_403() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store, shaping_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let mut body = create_body("a");
    body["spec"]["pod"] = serde_json::json!({ "service_account": "default" });
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            body,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_client_supplied_resolution_is_discarded() {
    // The escalation this closes: `pod_resolved` is the field that actually
    // reaches the pod spec, so a caller who can set it directly can mount any
    // claim in the namespace. The server must overwrite it from the catalog,
    // never trust it.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), shaping_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let mut body = create_body("a");
    body["spec"]["pod_resolved"] = serde_json::json!({
        "volumes": [{
            "name": "steal",
            "claim_name": "someone-elses-data",
            "mount_path": "/mnt/steal",
            "read_only": false
        }],
        "service_account": "cluster-admin"
    });
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            body,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let shape = stored_spec(&store, "a")
        .await
        .pod_resolved
        .expect("resolved");
    let names: Vec<_> = shape.volumes.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(names, vec!["home"], "smuggled volume must not survive");
    assert_eq!(shape.service_account, None, "smuggled SA must not survive");
}

#[tokio::test]
async fn no_catalog_means_no_shaping_and_no_refusals() {
    // Deployments that configure nothing behave exactly as they did before.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), Default::default()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body("a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(stored_spec(&store, "a").await.pod_resolved, None);
}

#[tokio::test]
async fn no_catalog_means_env_is_refused_too() {
    // "Pod shaping switched off" must mean off for every field. Env is the
    // one with no catalog names to trip on, so without an explicit refusal
    // any Writer could inject LD_PRELOAD onto every container while the
    // deployment believes shaping is disabled.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), Default::default()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let mut body = create_body("a");
    body["spec"]["pod"] = serde_json::json!({
        "env": [{ "name": "LD_PRELOAD", "value": "/tmp/x.so" }]
    });
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            body,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(store.get(&ClusterId("a".into())).await.unwrap().is_none());
}

#[tokio::test]
async fn the_grant_is_readable_through_the_api() {
    // "What is this cluster actually mounting" must be answerable from GET,
    // not from direct store access (docs/api-v1.md §3.1.1, dev-stack.md).
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), shaping_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body("a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let res = app
        .oneshot(get(
            "/api/v1/clusters/a",
            "mobula.example.com",
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let view = body_json(res).await;
    assert_eq!(
        view["pod_resolved"]["volumes"][0]["claim_name"],
        "nebari-home"
    );
    assert_eq!(view["pod_resolved"]["volumes"][0]["sub_path"], "home/demo");
}

#[tokio::test]
async fn a_noop_pod_resubmit_does_not_roll_the_cluster() {
    // A re-submit whose resolution is byte-identical must not bump the
    // generation: a bump changes the pod-template annotation and KubeRay
    // rolls head and every worker, killing in-flight jobs for nothing.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), shaping_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            create_body("a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let g1 = store
        .get(&ClusterId("a".into()))
        .await
        .unwrap()
        .unwrap()
        .generation;

    // Explicitly-empty pod object: same resolution as absent.
    let mut body = create_body("a");
    body["spec"]["pod"] = serde_json::json!({});
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            body,
        ))
        .await
        .unwrap();
    assert!(res.status().is_success());

    // Redundantly requesting the default mount, twice: same resolution.
    let mut body = create_body("a");
    body["spec"]["pod"] = serde_json::json!({ "mounts": ["home", "home"] });
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            "mobula.example.com",
            &admin,
            body,
        ))
        .await
        .unwrap();
    assert!(res.status().is_success());

    let g2 = store
        .get(&ClusterId("a".into()))
        .await
        .unwrap()
        .unwrap()
        .generation;
    assert_eq!(g1, g2, "no-op re-submits must not bump the generation");
}
