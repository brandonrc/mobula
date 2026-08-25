//! End-to-end reconcile scenarios against a mock provisioner that records
//! every actuation, so tests assert the engine's decisions and its
//! idempotency/fencing behavior (ADR-0006/0007).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mobula_controller::{
    Action, DesiredState, InMemoryStore, RateLimits, ReconcileError, Reconciler, SqliteStore, Store,
};
use mobula_core::{ClusterId, ClusterSpec, ClusterState, WorkerGroup};
use mobula_provision::{ApplyResponse, ObservedCluster, ProvisionError, Provisioner};

#[derive(Default)]
struct MockProvisioner {
    /// Observed state per cluster (None entry = provisioned-but-unknown;
    /// absent = NotFound).
    state: Mutex<HashMap<String, ClusterState>>,
    /// Generation each cluster currently carries — the value `observe`
    /// reads back (#40). Set by `apply`, unchanged by `set_state` so a
    /// drift (state flip) keeps the applied generation.
    gen: Mutex<HashMap<String, u64>>,
    /// Fingerprint each cluster reports from `observe` (#41 drift). `apply`
    /// sets it to the applied spec's fingerprint (so a converged cluster
    /// never looks drifted); `set_fingerprint` overrides it to simulate an
    /// out-of-band edit.
    fp: Mutex<HashMap<String, Option<String>>>,
    /// The state `apply` leaves a cluster in. `None` = Running (healthy
    /// default); `Some(s)` simulates an apply that never brings the cluster up
    /// (e.g. Terminated) so #43 backoff can be exercised.
    apply_result: Mutex<Option<ClusterState>>,
    apply_keys: Mutex<Vec<String>>,
    /// Queue assignment each apply call received (ADR-0010 wiring check).
    apply_queues: Mutex<Vec<Option<mobula_provision::QueueAssignment>>>,
    terminate_calls: Mutex<Vec<String>>,
    /// Ids the engine asked to suspend (#51), in call order.
    suspend_calls: Mutex<Vec<String>>,
}

impl MockProvisioner {
    fn set_state(&self, id: &str, s: ClusterState) {
        self.state.lock().unwrap().insert(id.into(), s);
    }
    fn set_apply_result(&self, s: Option<ClusterState>) {
        *self.apply_result.lock().unwrap() = s;
    }
    fn set_fingerprint(&self, id: &str, fp: Option<String>) {
        self.fp.lock().unwrap().insert(id.into(), fp);
    }
    fn set_observed_generation(&self, id: &str, g: u64) {
        self.gen.lock().unwrap().insert(id.into(), g);
    }
    fn apply_count(&self) -> usize {
        self.apply_keys.lock().unwrap().len()
    }
    fn distinct_apply_keys(&self) -> usize {
        let v = self.apply_keys.lock().unwrap();
        let set: std::collections::HashSet<_> = v.iter().collect();
        set.len()
    }
}

#[async_trait]
impl Provisioner for MockProvisioner {
    async fn apply(
        &self,
        id: &ClusterId,
        _spec: &ClusterSpec,
        generation: u64,
        idempotency_key: &str,
        queue: Option<&mobula_provision::QueueAssignment>,
    ) -> Result<ApplyResponse, ProvisionError> {
        self.apply_keys.lock().unwrap().push(idempotency_key.into());
        self.apply_queues.lock().unwrap().push(queue.cloned());
        // Applying leaves the cluster in the configured result state
        // (Running by default; a failing provisioner leaves it Terminated).
        let result = self
            .apply_result
            .lock()
            .unwrap()
            .unwrap_or(ClusterState::Running);
        self.state.lock().unwrap().insert(id.0.clone(), result);
        self.gen.lock().unwrap().insert(id.0.clone(), generation);
        // A freshly-applied cluster reports the fingerprint of what we
        // applied, so it never looks drifted until something edits it.
        self.fp.lock().unwrap().insert(
            id.0.clone(),
            Some(mobula_provision::kuberay::owned_spec_fingerprint(_spec)),
        );
        Ok(ApplyResponse {
            generation,
            api_base_url: Some(format!("http://{}-head:8265", id.0)),
        })
    }

    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        self.terminate_calls.lock().unwrap().push(id.0.clone());
        self.state
            .lock()
            .unwrap()
            .insert(id.0.clone(), ClusterState::Terminated);
        Ok(())
    }

    async fn suspend(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        self.suspend_calls.lock().unwrap().push(id.0.clone());
        self.state
            .lock()
            .unwrap()
            .insert(id.0.clone(), ClusterState::Suspended);
        Ok(())
    }

    async fn resume(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        self.state
            .lock()
            .unwrap()
            .insert(id.0.clone(), ClusterState::Running);
        Ok(())
    }

    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        match self.state.lock().unwrap().get(&id.0) {
            Some(state) => Ok(ObservedCluster {
                id: id.clone(),
                state: *state,
                observed_generation: self.gen.lock().unwrap().get(&id.0).copied(),
                spec_fingerprint: self.fp.lock().unwrap().get(&id.0).cloned().flatten(),
                api_base_url: Some(format!("http://{}-head:8265", id.0)),
            }),
            None => Err(ProvisionError::NotFound(id.clone())),
        }
    }

    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        let gens = self.gen.lock().unwrap();
        let fps = self.fp.lock().unwrap();
        Ok(self
            .state
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| ObservedCluster {
                id: ClusterId(k.clone()),
                state: *v,
                observed_generation: gens.get(k).copied(),
                spec_fingerprint: fps.get(k).cloned().flatten(),
                api_base_url: None,
            })
            .collect())
    }
}

fn spec(name: &str, replicas: u32) -> ClusterSpec {
    ClusterSpec {
        engine: Default::default(),
        name: name.into(),
        project: "demo".into(),
        ray_version: "2.57.0".into(),
        image: "rayproject/ray:2.57.0".into(),
        head_cpu: "1".into(),
        head_memory: "2Gi".into(),
        worker_groups: vec![WorkerGroup {
            name: "cpu".into(),
            cpu: "1".into(),
            memory: "2Gi".into(),
            gpu: None,
            min_replicas: 0,
            max_replicas: 4,
            replicas,
        }],
        ttl_seconds: None,
        owner: None,
    }
}

fn setup() -> (
    Arc<InMemoryStore>,
    Arc<MockProvisioner>,
    Reconciler<InMemoryStore, MockProvisioner>,
) {
    let store = Arc::new(InMemoryStore::new());
    let prov = Arc::new(MockProvisioner::default());
    let rec = Reconciler::new(store.clone(), prov.clone());
    (store, prov, rec)
}

#[tokio::test]
async fn creates_then_converges_to_noop() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 2)).await.unwrap();

    // First pass provisions.
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Applied);
    assert_eq!(prov.apply_count(), 1);
    // Status was reconstructed from observation.
    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(stored.observed_state, Some(ClusterState::Running));
    assert_eq!(stored.observed_generation, 1);

    // Second pass: desired == observed, no re-actuation.
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert_eq!(prov.apply_count(), 1, "steady state must not re-apply");
}

#[tokio::test]
async fn repairs_drift_when_cluster_disappears() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    assert_eq!(prov.apply_count(), 1);

    // Cluster vanishes out-of-band.
    prov.set_state("demo", ClusterState::Terminated);

    // Reconcile repairs it.
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Applied);
    assert_eq!(prov.apply_count(), 2, "drift must trigger re-apply");
}

#[tokio::test]
async fn spec_change_bumps_generation_and_reapplies_with_new_key() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;

    // Change the spec — generation bumps to 2.
    let gen = store.upsert_desired(&id, spec("demo", 3)).await.unwrap();
    assert_eq!(gen, 2);

    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Applied);
    assert_eq!(prov.apply_count(), 2);
    // Two distinct idempotency keys: demo/1 and demo/2.
    assert_eq!(prov.distinct_apply_keys(), 2);
}

#[tokio::test]
async fn queue_assignment_flows_from_allocation_to_apply() {
    // ADR-0010: a project with a pool allocation gets its cluster admitted
    // through the allocation's LocalQueue; the reconciler derives the
    // assignment from the store (never from ClusterSpec) and hands it to
    // the provisioner. A queued cluster observed Suspended is Kueue
    // admission queueing — NOT re-applied (#47's suspend repair is
    // suspended for queued clusters, research doc §2).
    let (store, prov, rec) = setup();
    use mobula_core::{AllocationSpec, FlavorSpec, PoolSpec};
    use std::collections::BTreeMap;
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

    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    let queues = prov.apply_queues.lock().unwrap().clone();
    assert_eq!(
        queues.as_slice(),
        [Some(mobula_provision::QueueAssignment {
            queue_name: "demo".into(),
            elastic: true,
        })],
        "apply must receive the allocation-derived queue assignment"
    );

    // A queued cluster held Suspended by Kueue is left alone (no re-apply).
    prov.set_state("demo", ClusterState::Suspended);
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert_eq!(
        prov.apply_count(),
        1,
        "Kueue-owned suspension is not repaired"
    );
}

#[tokio::test]
async fn queue_free_cluster_behaves_as_before() {
    // No allocation for the project → apply gets no assignment, and
    // Suspended stays repairable drift (#47).
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    assert_eq!(prov.apply_queues.lock().unwrap().as_slice(), [None]);

    prov.set_state("demo", ClusterState::Suspended);
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Applied);
    assert_eq!(prov.apply_count(), 2, "queue-free suspension is repaired");
}

#[tokio::test]
async fn idempotent_apply_uses_stable_key_across_passes() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();

    // Force re-apply twice by clearing observed state between passes
    // (simulating a flapping cluster) — same generation, so same key.
    rec.reconcile_all().await;
    prov.set_state("demo", ClusterState::Terminated);
    rec.reconcile_all().await;
    prov.set_state("demo", ClusterState::Terminated);
    rec.reconcile_all().await;

    assert_eq!(prov.apply_count(), 3, "re-applied on each drift");
    assert_eq!(
        prov.distinct_apply_keys(),
        1,
        "same desired generation → one stable idempotency key (ADR-0007)"
    );
}

#[tokio::test]
async fn reconciles_over_a_real_sqlite_store() {
    // The full engine driving the sqlx-backed store end to end.
    let store = Arc::new(SqliteStore::in_memory().await.unwrap());
    let prov = Arc::new(MockProvisioner::default());
    let rec = Reconciler::new(store.clone(), prov.clone());
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 2)).await.unwrap();

    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Applied);
    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(stored.observed_state, Some(ClusterState::Running));
    assert_eq!(stored.observed_generation, 1);

    // Idempotent second pass.
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert_eq!(prov.apply_count(), 1);
}

#[tokio::test]
async fn reaper_terminates_expired_cluster() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    // ttl_seconds = 0 → expires as soon as it is observed Running.
    let mut s = spec("demo", 1);
    s.ttl_seconds = Some(0);
    store.upsert_desired(&id, s).await.unwrap();

    // First reconcile brings it to Running.
    rec.reconcile_all().await;
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().observed_state,
        Some(ClusterState::Running)
    );

    // Reap flips desired → Terminated; next reconcile tears it down.
    let reaped = rec.reap_expired(1).await.unwrap();
    assert_eq!(reaped, vec!["demo".to_string()]);
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Terminated);
    let _ = prov;
}

#[tokio::test]
async fn run_loop_converges_then_stops_on_shutdown() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();

    // Run the loop with a short interval; shut it down after a beat.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        rec.run(std::time::Duration::from_millis(10), async {
            let _ = rx.await;
        })
        .await;
    });

    // Give it a few ticks to converge without any manual reconcile call.
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().observed_state,
        Some(ClusterState::Running),
        "the background loop should have provisioned the cluster"
    );
    assert_eq!(
        prov.apply_count(),
        1,
        "steady state: applied once, no churn"
    );

    tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("loop should stop promptly on shutdown")
        .unwrap();
}

/// A provisioner that always *observes* generation 1 no matter what
/// generation was applied — modelling a cluster whose pods have not yet
/// rolled to a newer spec. Used to prove the engine records the observed
/// (read-back) generation, never the desired one (#40).
#[derive(Default)]
struct LaggingProvisioner {
    applies: Mutex<usize>,
}

#[async_trait]
impl Provisioner for LaggingProvisioner {
    async fn apply(
        &self,
        _id: &ClusterId,
        _spec: &ClusterSpec,
        generation: u64,
        _key: &str,
        _queue: Option<&mobula_provision::QueueAssignment>,
    ) -> Result<mobula_provision::ApplyResponse, ProvisionError> {
        *self.applies.lock().unwrap() += 1;
        Ok(mobula_provision::ApplyResponse {
            generation,
            api_base_url: None,
        })
    }
    async fn terminate(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
        Ok(())
    }
    async fn suspend(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
        Ok(())
    }
    async fn resume(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
        Ok(())
    }
    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        // Running, but forever stuck reporting generation 1.
        Ok(ObservedCluster {
            id: id.clone(),
            state: ClusterState::Running,
            observed_generation: Some(1),
            spec_fingerprint: None,
            api_base_url: None,
        })
    }
    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn observed_generation_is_read_back_not_self_certified() {
    // #40: after a spec bump to generation 2, the cluster still reports
    // generation 1 (pods not rolled). The engine must record the OBSERVED
    // generation (1), not self-certify the desired one (2), and therefore
    // must keep applying until the cluster actually catches up.
    let store = Arc::new(InMemoryStore::new());
    let prov = Arc::new(LaggingProvisioner::default());
    let rec = Reconciler::new(store.clone(), prov.clone());
    let id = ClusterId("demo".into());

    store.upsert_desired(&id, spec("demo", 1)).await.unwrap(); // gen 1
    rec.reconcile_all().await;
    // Bump the spec → desired generation 2.
    assert_eq!(store.upsert_desired(&id, spec("demo", 3)).await.unwrap(), 2);
    rec.reconcile_all().await;

    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(stored.generation, 2, "desired advanced");
    assert_eq!(
        stored.observed_generation, 1,
        "observed generation is read back from the cluster, not the desired gen"
    );

    // Because observed (1) < desired (2), convergence is NOT declared and the
    // next pass applies again — the opposite of self-certifying a no-op.
    let before = *prov.applies.lock().unwrap();
    rec.reconcile_all().await;
    assert_eq!(
        *prov.applies.lock().unwrap(),
        before + 1,
        "must keep applying until the observed generation catches up"
    );
}

#[tokio::test]
async fn conflicting_intent_fingerprint_is_rejected() {
    // #39: an outbox key reused with a different spec fingerprint (e.g. a DB
    // restore that reused generation 1 for a different spec) must be refused,
    // and the provider must not be actuated.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap(); // gen 1 → key demo/1

    // Pre-seed the outbox for demo/1 with a conflicting fingerprint.
    let outcome = store
        .begin_intent("demo/1", "a-different-fingerprint")
        .await
        .unwrap();
    assert_eq!(
        outcome,
        mobula_controller::IntentOutcome::Proceed { replay: false }
    );

    let r = rec.reconcile_all().await;
    assert!(
        matches!(r[0].1, Err(ReconcileError::StaleIntent(_))),
        "a conflicting-fingerprint intent must be rejected, got {:?}",
        r[0].1
    );
    assert_eq!(
        prov.apply_count(),
        0,
        "must not actuate under a conflicting intent"
    );
}

#[tokio::test]
async fn repairs_drift_when_suspended_out_of_band() {
    // #47: a Running-desired cluster observed Suspended must be re-applied
    // (resume-as-reprovision), not left NoOp forever.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    assert_eq!(prov.apply_count(), 1);

    prov.set_state("demo", ClusterState::Suspended);
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Applied);
    assert_eq!(
        prov.apply_count(),
        2,
        "Suspended must trigger a resume re-apply"
    );
}

#[tokio::test]
async fn degraded_desired_running_raises_drift_alarm() {
    // #47/#41: Degraded is a runtime failure, not spec drift — raise an alarm
    // (Action::Drift + persisted condition) and do NOT hot-loop re-applying.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    assert_eq!(prov.apply_count(), 1);

    prov.set_state("demo", ClusterState::Degraded);
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Drift);
    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(
        stored.condition,
        Some(mobula_core::DriftCondition::Degraded)
    );

    // Repeated passes must not churn the provider.
    rec.reconcile_all().await;
    rec.reconcile_all().await;
    assert_eq!(
        prov.apply_count(),
        1,
        "Degraded must not re-apply in a loop"
    );
}

#[tokio::test]
async fn out_of_band_spec_edit_raises_drift_and_does_not_silently_noop() {
    // #41: a live cluster at the desired generation whose observed spec
    // fingerprint diverges from desired is drift → alarm, never a silent NoOp.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    let applies = prov.apply_count();

    // Simulate an out-of-band edit: the cluster now reports a different
    // owned-field fingerprint than desired.
    prov.set_fingerprint("demo", Some("tampered-fingerprint".into()));
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Drift);
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().condition,
        Some(mobula_core::DriftCondition::SpecDrift)
    );
    assert_eq!(
        prov.apply_count(),
        applies,
        "drift alarms, it does not re-apply"
    );
}

#[tokio::test]
async fn autoscaler_owned_replicas_do_not_count_as_drift() {
    // #41 + ADR-0007: replica counts are excluded from the drift fingerprint,
    // so an autoscaler changing replicas must NOT raise a drift alarm.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 2)).await.unwrap();
    rec.reconcile_all().await;

    // The cluster reports the fingerprint of a spec that differs ONLY in
    // replica count — which fingerprints identically (replicas excluded).
    let fp_diff_replicas = mobula_provision::kuberay::owned_spec_fingerprint(&spec("demo", 99));
    prov.set_fingerprint("demo", Some(fp_diff_replicas));
    let r = rec.reconcile_all().await;
    assert_eq!(
        r[0].1.as_ref().unwrap(),
        &Action::NoOp,
        "replica delta is not drift"
    );
    assert_eq!(store.get(&id).await.unwrap().unwrap().condition, None);
}

#[tokio::test]
async fn stale_restore_quarantines_and_blocks_actuation() {
    // #41: if a backing cluster reports a generation NEWER than the store
    // (a rolled-back DB restore), detect_stale_restore quarantines, and the
    // reconciler then observes without actuating.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    let applies = prov.apply_count();

    // The live cluster is at a newer generation than the store believes.
    prov.set_observed_generation("demo", 5);
    assert!(
        rec.detect_stale_restore().await.unwrap(),
        "should quarantine"
    );
    assert!(store.is_quarantined().await.unwrap());

    // Force a reason to actuate (drift), but quarantine must block it.
    prov.set_state("demo", ClusterState::Terminated);
    rec.reconcile_all().await;
    assert_eq!(
        prov.apply_count(),
        applies,
        "quarantine must block actuation"
    );
}

#[tokio::test]
async fn quarantined_store_observes_but_does_not_actuate() {
    // #41: with quarantine set, a fresh cluster that would otherwise be
    // applied is only observed.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    store.set_quarantine(true).await.unwrap();

    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert_eq!(prov.apply_count(), 0, "quarantined: must not actuate");
}

#[tokio::test]
async fn permanently_failing_cluster_backs_off() {
    // #43: a cluster whose apply never brings it up must not re-apply every
    // tick — exponential backoff throttles it.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    prov.set_apply_result(Some(ClusterState::Terminated)); // never comes up
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();

    for now in 0..10 {
        rec.reconcile_all_at(now).await;
    }
    // Without backoff this would be 10; with base=5s backoff it applies at
    // t=0 and t=5 only.
    assert!(
        prov.apply_count() <= 3,
        "backoff must throttle a permanently-failing cluster, got {}",
        prov.apply_count()
    );
}

#[tokio::test]
async fn backoff_skips_within_window() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    prov.set_apply_result(Some(ClusterState::Terminated));
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();

    rec.reconcile_all_at(0).await; // applies, sets next_attempt_at = 5
    let after_first = prov.apply_count();
    let r = rec.reconcile_all_at(0).await; // still inside the backoff window
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Backoff);
    assert_eq!(
        prov.apply_count(),
        after_first,
        "must not re-apply within the window"
    );
}

#[tokio::test]
async fn backoff_resets_after_recovery() {
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    prov.set_apply_result(Some(ClusterState::Terminated));
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();

    rec.reconcile_all_at(0).await; // fail → failure_count 1, next 5
    rec.reconcile_all_at(5).await; // fail → failure_count 2, next 15
                                   // Cluster recovers: apply now brings it up.
    prov.set_apply_result(None);
    rec.reconcile_all_at(15).await; // success → reset
    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(stored.failure_count, 0, "success resets failure count");
    assert_eq!(stored.next_attempt_at, 0, "success clears backoff");

    // A subsequent out-of-band drift is repaired immediately (no stale gate).
    prov.set_state("demo", ClusterState::Terminated);
    let applies = prov.apply_count();
    let r = rec.reconcile_all_at(16).await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Applied);
    assert_eq!(
        prov.apply_count(),
        applies + 1,
        "reset means immediate repair"
    );
}

#[tokio::test]
async fn token_bucket_caps_actuations_per_pass() {
    // #43: a burst of failing clusters cannot exceed the global actuation
    // budget in a single pass.
    let store = Arc::new(InMemoryStore::new());
    let prov = Arc::new(MockProvisioner::default());
    prov.set_apply_result(Some(ClusterState::Terminated));
    let rec = Reconciler::with_limits(
        store.clone(),
        prov.clone(),
        RateLimits {
            capacity: 5.0,
            refill_per_sec: 0.0,
        },
    );
    for i in 0..50 {
        let id = ClusterId(format!("c{i}"));
        store
            .upsert_desired(&id, spec(&format!("c{i}"), 1))
            .await
            .unwrap();
    }
    rec.reconcile_all_at(0).await;
    assert!(
        prov.apply_count() <= 5,
        "token bucket (capacity 5) must cap actuations, got {}",
        prov.apply_count()
    );
}

#[tokio::test]
async fn terminate_desired_tears_down_then_noop() {
    let (store, _prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;

    store
        .set_desired(&id, DesiredState::Terminated)
        .await
        .unwrap();
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Terminated);

    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(stored.observed_state, Some(ClusterState::Terminated));

    // Already terminated → no repeated teardown.
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
}

#[tokio::test]
async fn suspend_desired_suspends_running_cluster_then_noop() {
    // #51: desired Suspended + observed Running → the provisioner's suspend
    // call (NOT a generation-keyed apply) drives the cluster to Suspended;
    // a converged cluster is a NoOp and never re-suspends.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    assert_eq!(prov.apply_count(), 1);

    store
        .set_desired(&id, DesiredState::Suspended)
        .await
        .unwrap();
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::Suspended);
    assert_eq!(
        prov.suspend_calls.lock().unwrap().as_slice(),
        ["demo".to_string()],
        "suspend actuates through Provisioner::suspend"
    );
    // Suspension changes no spec field → no new apply, no new intent key.
    assert_eq!(prov.apply_count(), 1, "suspend must not re-apply the spec");
    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(stored.observed_state, Some(ClusterState::Suspended));

    // Converged: desired Suspended + observed Suspended → NoOp.
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert_eq!(prov.suspend_calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn resume_flips_desired_back_and_apply_converges() {
    // #51: resume is not a separate actuation — the API flips desired back to
    // Running and the existing Running arm re-applies (to_raycluster owns
    // spec.suspend=false), so the cluster leaves Suspended.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;

    store
        .set_desired(&id, DesiredState::Suspended)
        .await
        .unwrap();
    rec.reconcile_all().await;
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().observed_state,
        Some(ClusterState::Suspended)
    );

    store.set_desired(&id, DesiredState::Running).await.unwrap();
    let r = rec.reconcile_all().await;
    assert_eq!(
        r[0].1.as_ref().unwrap(),
        &Action::Applied,
        "resume rides the generation-keyed apply path"
    );
    assert_eq!(prov.apply_count(), 2);
    let stored = store.get(&id).await.unwrap().unwrap();
    assert_eq!(stored.observed_state, Some(ClusterState::Running));

    // Steady state restored: no further actuation.
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert_eq!(prov.apply_count(), 2);
}

#[tokio::test]
async fn suspended_desired_on_gone_or_absent_cluster_is_noop() {
    // #51: nothing provisioned (or already terminated) means nothing to
    // suspend — the engine must not resurrect the cluster just to suspend it.
    let (store, prov, rec) = setup();
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    store
        .set_desired(&id, DesiredState::Suspended)
        .await
        .unwrap();

    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert_eq!(prov.apply_count(), 0, "suspend must not provision");
    assert!(prov.suspend_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn queued_cluster_is_never_suspended_by_the_engine() {
    // #51 + ADR-0010: Kueue owns spec.suspend for queue-assigned clusters.
    // The API rejects user suspend there, so desired=Suspended should never
    // co-occur with a queue assignment — but if it somehow does, the engine
    // must not fight the queue.
    let (store, prov, rec) = setup();
    use mobula_core::{AllocationSpec, FlavorSpec, PoolSpec};
    use std::collections::BTreeMap;
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

    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap();
    rec.reconcile_all().await;
    assert_eq!(prov.apply_count(), 1);

    store
        .set_desired(&id, DesiredState::Suspended)
        .await
        .unwrap();
    let r = rec.reconcile_all().await;
    assert_eq!(r[0].1.as_ref().unwrap(), &Action::NoOp);
    assert!(
        prov.suspend_calls.lock().unwrap().is_empty(),
        "Kueue owns suspend for queued clusters — the engine stays out"
    );
}
