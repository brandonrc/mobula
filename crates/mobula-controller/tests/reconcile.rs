//! End-to-end reconcile scenarios against a mock provisioner that records
//! every actuation, so tests assert the engine's decisions and its
//! idempotency/fencing behavior (ADR-0006/0007).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mobula_controller::{
    Action, DesiredState, InMemoryStore, ReconcileError, Reconciler, SqliteStore, Store,
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
    apply_keys: Mutex<Vec<String>>,
    terminate_calls: Mutex<Vec<String>>,
}

impl MockProvisioner {
    fn set_state(&self, id: &str, s: ClusterState) {
        self.state.lock().unwrap().insert(id.into(), s);
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
    ) -> Result<ApplyResponse, ProvisionError> {
        self.apply_keys.lock().unwrap().push(idempotency_key.into());
        // Applying makes it Running at the applied generation.
        self.state
            .lock()
            .unwrap()
            .insert(id.0.clone(), ClusterState::Running);
        self.gen.lock().unwrap().insert(id.0.clone(), generation);
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

    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        match self.state.lock().unwrap().get(&id.0) {
            Some(state) => Ok(ObservedCluster {
                id: id.clone(),
                state: *state,
                observed_generation: self.gen.lock().unwrap().get(&id.0).copied(),
                api_base_url: Some(format!("http://{}-head:8265", id.0)),
            }),
            None => Err(ProvisionError::NotFound(id.clone())),
        }
    }

    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        let gens = self.gen.lock().unwrap();
        Ok(self
            .state
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| ObservedCluster {
                id: ClusterId(k.clone()),
                state: *v,
                observed_generation: gens.get(k).copied(),
                api_base_url: None,
            })
            .collect())
    }
}

fn spec(name: &str, replicas: u32) -> ClusterSpec {
    ClusterSpec {
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
    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        // Running, but forever stuck reporting generation 1.
        Ok(ObservedCluster {
            id: id.clone(),
            state: ClusterState::Running,
            observed_generation: Some(1),
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
