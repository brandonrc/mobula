//! Pool reconcile loop (ADR-0010): the level-triggered counterpart of the
//! cluster reconciler for Kueue pool objects, and simpler — pools have no
//! state machine. Every pass lists desired pools + allocations from the
//! store and converges the Kueue objects (Cohort / ResourceFlavors /
//! ClusterQueue / LocalQueues) through a [`PoolProvisioner`], then records
//! the ClusterQueue status observation back onto the pool row (Slice 4's
//! metering loop reads those observations).
//!
//! Differences from the cluster engine, by design:
//! - **No-op when unchanged**: the outbox intent row for
//!   `pool:{name}/{generation}:{digest}` is the record of "this desired
//!   state is applied" — a matching Applied intent skips the provider call
//!   (the digest covers the allocations, which don't bump the pool
//!   generation, so allocation-only changes still re-apply under a fresh
//!   key).
//! - **Deletion is disappearance**: the store hard-deletes pools, so the
//!   loop tears down Kueue objects for pools it applied earlier that are no
//!   longer listed. The applied-set is in-memory; a control-plane restart
//!   between apply and delete leaves orphaned objects until the loop runs
//!   again in the same process — bounded, and the objects are
//!   `mobula.dev/pool`-labeled for manual/audit cleanup.
//! - **Absent Kueue = inert**: when the CRDs aren't served, the loop skips
//!   everything (no actuation, no observation) and pools remain in-process
//!   quota only (ADR-0010 fallback).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mobula_core::{AllocationSpec, PoolSpec};
use mobula_provision::PoolProvisioner;

use crate::reconcile::ReconcileError;
use crate::store::{IntentOutcome, IntentStatus, Store, StoredPool};

/// Per-pool outcome of a reconcile pass, for logging/metrics/tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolAction {
    /// Desired state already applied (matching Applied intent) or only
    /// observed (quarantined).
    NoOp,
    /// Applied the pool's Kueue objects (create or update).
    Applied,
    /// The pool vanished from the store; its Kueue objects were deleted.
    Deleted,
}

pub struct PoolReconciler<S, P> {
    store: Arc<S>,
    provisioner: Arc<P>,
    /// Names of pools this process has converged (applied or found already
    /// applied). Drives teardown when a pool disappears from the store.
    converged: Mutex<BTreeSet<String>>,
}

impl<S: Store, P: PoolProvisioner> PoolReconciler<S, P> {
    pub fn new(store: Arc<S>, provisioner: Arc<P>) -> Self {
        Self {
            store,
            provisioner,
            converged: Mutex::new(BTreeSet::new()),
        }
    }

    /// Reconcile every pool once. Empty when the Kueue CRDs are absent
    /// (nothing to actuate or observe). Errors on individual pools are
    /// collected, not fatal — one bad pool must not stall the loop.
    pub async fn reconcile_all(&self) -> Vec<(String, Result<PoolAction, ReconcileError>)> {
        if !self.provisioner.kueue_present().await {
            return Vec::new();
        }
        let pools = match self.store.list_pools().await {
            Ok(p) => p,
            Err(e) => return vec![("<list>".into(), Err(e.into()))],
        };
        let current: BTreeSet<String> = pools.iter().map(|p| p.name.clone()).collect();
        let mut out = Vec::with_capacity(pools.len());
        for p in &pools {
            out.push((p.name.clone(), self.reconcile_one(p).await));
        }
        // Teardown for pools that disappeared. Quarantine (ADR-0007, #41)
        // blocks ALL actuation, deletes included.
        match self.store.is_quarantined().await {
            Ok(false) => {
                let vanished: Vec<String> = self
                    .converged
                    .lock()
                    .unwrap()
                    .difference(&current)
                    .cloned()
                    .collect();
                for name in vanished {
                    match self.provisioner.delete_pool(&name).await {
                        Ok(()) => {
                            self.converged.lock().unwrap().remove(&name);
                            out.push((name, Ok(PoolAction::Deleted)));
                        }
                        Err(e) => out.push((name, Err(e.into()))),
                    }
                }
            }
            Ok(true) => {
                tracing::warn!(
                    target: "mobula::audit",
                    "control plane quarantined: pool teardowns deferred"
                );
            }
            Err(e) => out.push(("<quarantine>".into(), Err(e.into()))),
        }
        out
    }

    async fn reconcile_one(&self, pool: &StoredPool) -> Result<PoolAction, ReconcileError> {
        // 1. Observe and record (ADR-0006): the ClusterQueue status is the
        //    quota ledger; persist it for the API/metering regardless of
        //    what we actuate below. A missing ClusterQueue records nothing —
        //    the last known observation stays until one exists.
        if let Some(obs) = self.provisioner.observe_pool(&pool.name).await? {
            let json = serde_json::to_string(&obs).unwrap_or_default();
            self.store
                .record_pool_observation(&pool.name, &json)
                .await?;
        }

        // 2. Quarantine: observe but never actuate (ADR-0007, #41).
        if self.store.is_quarantined().await? {
            tracing::warn!(
                target: "mobula::audit",
                pool = %pool.name, "control plane quarantined: observing pool only, not actuating"
            );
            return Ok(PoolAction::NoOp);
        }

        // 3. Actuate on change. The intent key embeds the pool generation
        //    (spec changes) plus a digest of the full desired state
        //    (allocation changes don't bump the generation), so any desired
        //    change produces a fresh key and a same-state pass finds the
        //    Applied row and no-ops. The `pool:` prefix namespaces these
        //    intents from cluster intents (`{id}/{generation}`).
        let allocs = self.store.list_allocations(&pool.name).await?;
        let fp = desired_fingerprint(&pool.spec, &allocs);
        let key = pool_intent_key(pool, &fp);
        if self
            .store
            .get_intent(&key)
            .await?
            .is_some_and(|r| r.status == IntentStatus::Applied && r.params_fingerprint == fp)
        {
            self.converged.lock().unwrap().insert(pool.name.clone());
            return Ok(PoolAction::NoOp);
        }
        match self.store.begin_intent(&key, &fp).await? {
            // A fresh key must never collide with a different fingerprint;
            // if it does, the store is corrupt or replayed — refuse.
            IntentOutcome::ParamMismatch => Err(ReconcileError::StaleIntent(key)),
            IntentOutcome::Proceed { .. } => {
                self.provisioner.apply_pool(&pool.spec, &allocs).await?;
                self.store.complete_intent(&key, "{}").await?;
                self.converged.lock().unwrap().insert(pool.name.clone());
                Ok(PoolAction::Applied)
            }
        }
    }

    /// Run the pool control loop until `shutdown` resolves. Level-triggered
    /// on a fixed resync interval, like the cluster reconciler. Errors are
    /// logged per pass, never fatal.
    pub async fn run(&self, interval: Duration, shutdown: impl std::future::Future<Output = ()>) {
        // Log the Kueue posture once at startup; the per-client cache in
        // kueue_present makes later checks free and keeps this accurate for
        // the process lifetime.
        if self.provisioner.kueue_present().await {
            tracing::info!(
                interval_secs = interval.as_secs(),
                "pool reconcile loop started (Kueue present)"
            );
        } else {
            tracing::info!("Kueue CRDs absent — pools are in-process quota only");
        }
        let mut ticker = tokio::time::interval(interval);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    for (name, res) in self.reconcile_all().await {
                        if let Err(e) = res {
                            tracing::warn!(pool = %name, error = %e, "pool reconcile failed");
                        }
                    }
                }
                _ = &mut shutdown => {
                    tracing::info!("pool reconcile loop shutting down");
                    return;
                }
            }
        }
    }
}

/// Canonical JSON of a pool's full desired state: the spec plus its
/// allocations sorted by project (store iteration order is not stable).
/// Doubles as the outbox fingerprint and the input to the key digest.
fn desired_fingerprint(spec: &PoolSpec, allocs: &[AllocationSpec]) -> String {
    let mut allocs = allocs.to_vec();
    allocs.sort_by(|a, b| a.project.cmp(&b.project));
    serde_json::to_string(&serde_json::json!({
        "spec": spec,
        "allocations": allocs,
    }))
    .unwrap_or_default()
}

/// FNV-1a over the fingerprint: a short, stable-across-builds digest so the
/// intent key stays compact (no hashing dependency needed).
fn digest(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

/// Outbox key for a pool's desired state: `pool:{name}/{generation}:{digest}`
/// — derived from `{pool}/{generation}`, with the digest covering allocation
/// changes that don't bump the generation.
fn pool_intent_key(pool: &StoredPool, fingerprint: &str) -> String {
    format!(
        "pool:{}/{}:{}",
        pool.name,
        pool.generation,
        digest(fingerprint)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryStore;
    use async_trait::async_trait;
    use mobula_core::FlavorSpec;
    use mobula_provision::{PoolObservation, ProvisionError};
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockPools {
        present: bool,
        /// (pool name, allocation count) per apply call.
        applies: Mutex<Vec<(String, usize)>>,
        deletes: Mutex<Vec<String>>,
        observes: Mutex<usize>,
        delete_err: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl PoolProvisioner for MockPools {
        async fn apply_pool(
            &self,
            spec: &PoolSpec,
            allocs: &[AllocationSpec],
        ) -> Result<(), ProvisionError> {
            self.applies
                .lock()
                .unwrap()
                .push((spec.name.clone(), allocs.len()));
            Ok(())
        }
        async fn delete_pool(&self, name: &str) -> Result<(), ProvisionError> {
            if self.delete_err.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ProvisionError::Backend("injected delete failure".into()));
            }
            self.deletes.lock().unwrap().push(name.to_string());
            Ok(())
        }
        async fn observe_pool(
            &self,
            _name: &str,
        ) -> Result<Option<PoolObservation>, ProvisionError> {
            *self.observes.lock().unwrap() += 1;
            Ok(Some(PoolObservation {
                admitted_workloads: 1,
                ..Default::default()
            }))
        }
        async fn kueue_present(&self) -> bool {
            self.present
        }
    }

    fn pool(name: &str) -> PoolSpec {
        PoolSpec {
            name: name.into(),
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
        }
    }

    fn alloc(pool: &str, project: &str) -> AllocationSpec {
        AllocationSpec {
            pool: pool.into(),
            project: project.into(),
            namespace: project.into(),
            nominal: BTreeMap::new(),
            borrowing_limit: BTreeMap::new(),
            lending_limit: BTreeMap::new(),
        }
    }

    /// Unwrap a reconcile report into (name, action) pairs for comparison
    /// (ReconcileError isn't PartialEq).
    fn actions(
        out: Vec<(String, Result<PoolAction, ReconcileError>)>,
    ) -> Vec<(String, PoolAction)> {
        out.into_iter().map(|(n, r)| (n, r.unwrap())).collect()
    }

    fn rig(
        present: bool,
    ) -> (
        Arc<InMemoryStore>,
        Arc<MockPools>,
        PoolReconciler<InMemoryStore, MockPools>,
    ) {
        let store = Arc::new(InMemoryStore::new());
        let prov = Arc::new(MockPools {
            present,
            ..Default::default()
        });
        let rec = PoolReconciler::new(store.clone(), prov.clone());
        (store, prov, rec)
    }

    #[tokio::test]
    async fn apply_on_create_then_no_op_when_unchanged() {
        let (store, prov, rec) = rig(true);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        store
            .upsert_allocation(alloc("gpu", "proj-a"))
            .await
            .unwrap();
        store
            .upsert_allocation(alloc("gpu", "proj-b"))
            .await
            .unwrap();

        let out = rec.reconcile_all().await;
        assert_eq!(actions(out), [("gpu".to_string(), PoolAction::Applied)]);
        assert_eq!(
            prov.applies.lock().unwrap().as_slice(),
            [("gpu".to_string(), 2)]
        );
        // The observation is recorded onto the pool row every pass.
        assert!(store
            .get_pool("gpu")
            .await
            .unwrap()
            .unwrap()
            .observed_json
            .is_some());

        // Unchanged desired state → no second provider call.
        let out = rec.reconcile_all().await;
        assert_eq!(actions(out), [("gpu".to_string(), PoolAction::NoOp)]);
        assert_eq!(prov.applies.lock().unwrap().len(), 1);

        // An allocation change (no generation bump) still re-applies.
        store
            .upsert_allocation(alloc("gpu", "proj-c"))
            .await
            .unwrap();
        let out = rec.reconcile_all().await;
        assert_eq!(actions(out), [("gpu".to_string(), PoolAction::Applied)]);
        assert_eq!(prov.applies.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn delete_propagates_to_the_provisioner() {
        let (store, prov, rec) = rig(true);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        rec.reconcile_all().await;
        store.delete_pool("gpu").await.unwrap();

        let out = rec.reconcile_all().await;
        assert_eq!(actions(out), [("gpu".to_string(), PoolAction::Deleted)]);
        assert_eq!(prov.deletes.lock().unwrap().as_slice(), ["gpu"]);
        // Once deleted, the pool is forgotten — no repeat teardown.
        assert!(rec.reconcile_all().await.is_empty());
        assert_eq!(prov.deletes.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn quarantine_blocks_actuation_but_still_observes() {
        let (store, prov, rec) = rig(true);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        store.set_quarantine(true).await.unwrap();

        let out = rec.reconcile_all().await;
        assert_eq!(actions(out), [("gpu".to_string(), PoolAction::NoOp)]);
        assert!(
            prov.applies.lock().unwrap().is_empty(),
            "no actuation while quarantined"
        );
        assert_eq!(
            *prov.observes.lock().unwrap(),
            1,
            "observation still happens"
        );
        assert!(store
            .get_pool("gpu")
            .await
            .unwrap()
            .unwrap()
            .observed_json
            .is_some());

        // Teardown is actuation too: quarantined, a vanished pool's objects
        // are left alone (the converged set keeps the name for after the
        // quarantine lifts).
        rec.converged.lock().unwrap().insert("gpu".to_string());
        store.delete_pool("gpu").await.unwrap();
        let out = rec.reconcile_all().await;
        assert!(out.is_empty(), "no pools listed; teardown deferred");
        assert!(prov.deletes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn absent_kueue_skips_everything() {
        let (store, prov, rec) = rig(false);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();

        assert!(rec.reconcile_all().await.is_empty());
        assert!(prov.applies.lock().unwrap().is_empty());
        assert_eq!(*prov.observes.lock().unwrap(), 0);
        assert!(store
            .get_pool("gpu")
            .await
            .unwrap()
            .unwrap()
            .observed_json
            .is_none());
    }

    #[tokio::test]
    async fn store_list_error_is_reported_not_fatal() {
        // One bad pass must not stall the loop: the error is collected per
        // pool (here: the whole list fails).
        use crate::store::testkit::FailingStore;
        let store = Arc::new(FailingStore::new());
        store.fail("list_pools");
        let prov = Arc::new(MockPools {
            present: true,
            ..Default::default()
        });
        let rec = PoolReconciler::new(store, prov);
        let out = rec.reconcile_all().await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "<list>");
        assert!(out[0].1.is_err());
    }

    #[tokio::test]
    async fn delete_failure_keeps_the_pool_in_the_converged_set() {
        // A failed teardown is reported and the pool stays in `converged`,
        // so the next pass retries it.
        let (store, prov, rec) = rig(true);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        rec.reconcile_all().await;
        store.delete_pool("gpu").await.unwrap();

        prov.delete_err
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let out = rec.reconcile_all().await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "gpu");
        assert!(out[0].1.is_err(), "the failed delete is reported");
        assert!(
            rec.converged.lock().unwrap().contains("gpu"),
            "a failed delete must not forget the pool"
        );

        // Retry succeeds once the backend recovers.
        prov.delete_err
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let out = rec.reconcile_all().await;
        assert_eq!(actions(out), [("gpu".to_string(), PoolAction::Deleted)]);
    }

    #[tokio::test]
    async fn quarantine_check_error_is_reported() {
        use crate::store::testkit::FailingStore;
        let store = Arc::new(FailingStore::new());
        store.fail("is_quarantined");
        let prov = Arc::new(MockPools {
            present: true,
            ..Default::default()
        });
        let rec = PoolReconciler::new(store, prov);
        let out = rec.reconcile_all().await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "<quarantine>");
        assert!(out[0].1.is_err());
    }

    #[tokio::test]
    async fn observation_record_error_fails_the_pool_pass() {
        // Observing succeeds but persisting the observation fails → the
        // pool's pass errors before any actuation.
        use crate::store::testkit::FailingStore;
        let store = Arc::new(FailingStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        store.fail("record_pool_observation");
        let prov = Arc::new(MockPools {
            present: true,
            ..Default::default()
        });
        let rec = PoolReconciler::new(store, prov.clone());
        let out = rec.reconcile_all().await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "gpu");
        assert!(out[0].1.is_err());
        assert!(
            prov.applies.lock().unwrap().is_empty(),
            "no actuation when the observation couldn't be recorded"
        );
    }

    #[tokio::test]
    async fn stale_intent_fingerprint_is_rejected() {
        // An outbox row for this pool's key with a DIFFERENT fingerprint
        // (store corrupt or replayed) must refuse actuation, mirroring the
        // cluster reconciler's #39 fence.
        let (store, prov, rec) = rig(true);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        let stored = store.get_pool("gpu").await.unwrap().unwrap();
        let fp = desired_fingerprint(&stored.spec, &[]);
        let key = pool_intent_key(&stored, &fp);
        store
            .begin_intent(&key, "a-different-fingerprint")
            .await
            .unwrap();

        let out = rec.reconcile_all().await;
        assert!(
            matches!(out[0].1, Err(ReconcileError::StaleIntent(_))),
            "got {:?}",
            out[0].1
        );
        assert!(prov.applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_loop_converges_then_stops_on_shutdown() {
        let (store, prov, rec) = rig(true);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            rec.run(Duration::from_millis(10), async {
                let _ = rx.await;
            })
            .await;
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            prov.applies.lock().unwrap().as_slice(),
            [("gpu".to_string(), 0)],
            "the background loop should have applied the pool exactly once"
        );
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop should stop promptly on shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn run_loop_logs_absent_kueue_posture() {
        // The Kueue-absent startup branch: the loop runs inert and stops.
        let (store, prov, rec) = rig(false);
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            rec.run(Duration::from_millis(10), async {
                let _ = rx.await;
            })
            .await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(prov.applies.lock().unwrap().is_empty());
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop should stop promptly on shutdown")
            .unwrap();
    }
}
