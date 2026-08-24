//! Usage metering loop (Slice 4, ADR-0010). Appends `UsageSample` rows to
//! the store on a fixed interval; the `/api/v1/usage` report and the
//! Prometheus gauge read them back.
//!
//! ADR-0010's documented divergence: Kueue's `flavorsUsage` is a
//! *reservation* ledger (the amounts Kueue admits against quota), not
//! measured consumption — so Mobula meters attribution itself, and labels
//! each sample's provenance (`UsageSource`):
//!
//! - **Kueue present**: samples come from the pool's ClusterQueue
//!   `status.flavorsUsage` (pool-level aggregate, `project = ""` — the CQ is
//!   pool-scoped) and from each LocalQueue's own `status.flavorsUsage`
//!   (`project = <LocalQueue name>`; LQ status exists since Kueue v0.9).
//! - **Kueue absent** (no provisioner, or CRDs not served): samples are
//!   Mobula's own estimate from desired cluster specs — each Running
//!   cluster's `cluster_demand` **min** (the allocated baseline). Min, not
//!   max: max is a ceiling, and without autoscaling visibility the min is
//!   the honest floor. The choice is deliberate and documented here.
//!
//! Per-tick errors are logged, never fatal — the same discipline as the
//! reconcile loops. An unparseable quantity is skipped with a warning; it
//! never fails the tick.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use mobula_provision::PoolProvisioner;

use crate::store::{now_unix, DesiredState, Store, UsageSample, UsageSource};

pub struct Metering<S> {
    store: Arc<S>,
    /// `None` when the control plane runs without Kubernetes (e.g. `--demo`)
    /// — metering falls back to the observed-spec path.
    pool_provisioner: Option<Arc<dyn PoolProvisioner>>,
    interval: Duration,
}

impl<S: Store> Metering<S> {
    pub fn new(
        store: Arc<S>,
        pool_provisioner: Option<Arc<dyn PoolProvisioner>>,
        interval: Duration,
    ) -> Self {
        Self {
            store,
            pool_provisioner,
            interval,
        }
    }

    /// Collect and record one tick's samples. Returns how many were
    /// recorded (for tests/logging). All errors are logged and swallowed.
    pub async fn tick(&self) -> usize {
        let samples = self.collect(now_unix()).await;
        if samples.is_empty() {
            return 0;
        }
        match self.store.record_usage_samples(&samples).await {
            Ok(()) => samples.len(),
            Err(e) => {
                tracing::warn!(error = %e, "metering: failed to record usage samples");
                0
            }
        }
    }

    /// Run the metering loop until `shutdown` resolves. Level-triggered on
    /// a fixed interval, like the reconcilers.
    pub async fn run(&self, shutdown: impl std::future::Future<Output = ()>) {
        tracing::info!(
            interval_secs = self.interval.as_secs(),
            kueue = self.pool_provisioner.is_some(),
            "usage metering loop started"
        );
        let mut ticker = tokio::time::interval(self.interval);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.tick().await;
                }
                _ = &mut shutdown => {
                    tracing::info!("usage metering loop shutting down");
                    return;
                }
            }
        }
    }

    async fn collect(&self, now: u64) -> Vec<UsageSample> {
        let kueue = match &self.pool_provisioner {
            Some(p) => p.kueue_present().await,
            None => false,
        };
        if kueue {
            // The provisioner is Some when we get here.
            self.collect_kueue(now, self.pool_provisioner.as_ref().unwrap())
                .await
        } else {
            self.collect_observed_spec(now).await
        }
    }

    /// Kueue path: pool-level ledger rows (project = "") plus per-project
    /// rows from LocalQueue status. `project = ""` is the pool aggregate and
    /// OVERLAPS the per-project rows (the CQ total includes every LQ's
    /// reservations) — consumers must not sum across project boundaries.
    async fn collect_kueue(
        &self,
        now: u64,
        provisioner: &Arc<dyn PoolProvisioner>,
    ) -> Vec<UsageSample> {
        let pools = match self.store.list_pools().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "metering: failed to list pools");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for pool in &pools {
            let obs = match provisioner.observe_pool(&pool.name).await {
                Ok(Some(obs)) => obs,
                // No ClusterQueue yet — nothing to meter for this pool.
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(pool = %pool.name, error = %e, "metering: pool observation failed");
                    continue;
                }
            };
            for (flavor, resources) in &obs.flavors_usage {
                for (resource, qty) in resources {
                    if let Some(quantity) = parse_or_skip(&pool.name, resource, qty, flavor) {
                        out.push(UsageSample {
                            ts: now,
                            project: String::new(), // pool-level aggregate row
                            pool: pool.name.clone(),
                            resource: resource.clone(),
                            quantity,
                            source: UsageSource::KueueLedger,
                        });
                    }
                }
            }
            for (lq, resources) in &obs.queues_usage {
                for (resource, qty) in resources {
                    if let Some(quantity) = parse_or_skip(&pool.name, resource, qty, lq) {
                        out.push(UsageSample {
                            ts: now,
                            project: lq.clone(), // LocalQueue name = project
                            pool: pool.name.clone(),
                            resource: resource.clone(),
                            quantity,
                            source: UsageSource::KueueLedger,
                        });
                    }
                }
            }
        }
        out
    }

    /// Kueue-absent path: per Running cluster, emit the min-demand baseline
    /// per resource (see module docs for why min). `pool = ""` when the
    /// cluster's project has no allocation.
    async fn collect_observed_spec(&self, now: u64) -> Vec<UsageSample> {
        let clusters = match self.store.list().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "metering: failed to list clusters");
                return Vec::new();
            }
        };
        // project → pool, resolved once per tick from the allocations.
        let project_pools = self.project_pools().await;
        let mut out = Vec::new();
        for c in &clusters {
            if c.desired != DesiredState::Running {
                continue;
            }
            let (min, _max) = match mobula_policy::cluster_demand(&c.spec) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(cluster = %c.id, error = %e, "metering: cluster demand uncomputable, skipped");
                    continue;
                }
            };
            let pool = project_pools
                .get(&c.spec.project)
                .cloned()
                .unwrap_or_default();
            for (resource, quantity) in &min.0 {
                out.push(UsageSample {
                    ts: now,
                    project: c.spec.project.clone(),
                    pool: pool.clone(),
                    resource: resource.clone(),
                    quantity: *quantity,
                    source: UsageSource::ObservedSpec,
                });
            }
        }
        out
    }

    /// project → pool map from all allocations (a project appears in at most
    /// one allocation in practice; first match wins).
    async fn project_pools(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let pools = match self.store.list_pools().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "metering: failed to list pools for allocation lookup");
                return map;
            }
        };
        for pool in pools {
            match self.store.list_allocations(&pool.name).await {
                Ok(allocs) => {
                    for a in allocs {
                        map.entry(a.project).or_insert(pool.name.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(pool = %pool.name, error = %e, "metering: failed to list allocations");
                }
            }
        }
        map
    }
}

/// Parse a Kueue quantity string; unparseable values are skipped with a
/// warning (a bad quantity never fails the tick).
fn parse_or_skip(pool: &str, resource: &str, qty: &str, origin: &str) -> Option<f64> {
    match mobula_policy::quantity::parse_quantity(qty) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(pool = %pool, resource = %resource, quantity = %qty, origin = %origin, error = %e, "metering: unparseable quantity skipped");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::InMemoryStore;
    use async_trait::async_trait;
    use mobula_core::{AllocationSpec, ClusterId, ClusterSpec, FlavorSpec, PoolSpec, WorkerGroup};
    use mobula_provision::{PoolObservation, ProvisionError};

    #[derive(Default)]
    struct MockPools {
        present: bool,
        observation: Option<PoolObservation>,
        observe_err: bool,
    }

    #[async_trait]
    impl PoolProvisioner for MockPools {
        async fn apply_pool(
            &self,
            _spec: &PoolSpec,
            _allocs: &[AllocationSpec],
        ) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn delete_pool(&self, _name: &str) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn observe_pool(
            &self,
            _name: &str,
        ) -> Result<Option<PoolObservation>, ProvisionError> {
            if self.observe_err {
                return Err(ProvisionError::Backend("injected observe failure".into()));
            }
            Ok(self.observation.clone())
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
                resources: BTreeMap::from([("cpu".to_string(), "64".to_string())]),
                node_labels: BTreeMap::new(),
                taints: vec![],
            }],
            cohort: "research".into(),
            fair_sharing_weight: 1.0,
            elastic: false,
            gpu_sharing: None,
        }
    }

    fn cluster(id: &str, project: &str) -> ClusterSpec {
        ClusterSpec {
            engine: Default::default(),
            name: id.into(),
            project: project.into(),
            ray_version: "2.57.0".into(),
            image: "img".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: vec![WorkerGroup {
                name: "w".into(),
                cpu: "2".into(),
                memory: "4Gi".into(),
                gpu: None,
                min_replicas: 1,
                max_replicas: 4,
                replicas: 1,
            }],
            ttl_seconds: None,
            owner: None,
        }
    }

    #[tokio::test]
    async fn kueue_path_emits_lq_attributed_and_pool_aggregate_samples() {
        let store = Arc::new(InMemoryStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        let obs = PoolObservation {
            admitted_workloads: 2,
            flavors_usage: BTreeMap::from([(
                "a100".to_string(),
                BTreeMap::from([
                    ("cpu".to_string(), "16".to_string()),
                    ("memory".to_string(), "64Gi".to_string()),
                ]),
            )]),
            queues_usage: BTreeMap::from([(
                "proj-a".to_string(),
                BTreeMap::from([("cpu".to_string(), "10".to_string())]),
            )]),
            ..Default::default()
        };
        let prov: Arc<dyn PoolProvisioner> = Arc::new(MockPools {
            present: true,
            observation: Some(obs),
            ..Default::default()
        });
        let m = Metering::new(store.clone(), Some(prov), Duration::from_secs(60));
        let n = m.tick().await;
        assert_eq!(n, 3);

        let samples = store.usage_samples(None, None, 0, u64::MAX).await.unwrap();
        assert_eq!(samples.len(), 3);
        assert!(samples.iter().all(|s| s.source == UsageSource::KueueLedger));
        // Pool aggregate rows carry project = "".
        let agg: Vec<_> = samples.iter().filter(|s| s.project.is_empty()).collect();
        assert_eq!(agg.len(), 2);
        assert!(agg
            .iter()
            .any(|s| s.resource == "cpu" && s.quantity == 16.0));
        // memory: "64Gi" parses to bytes (parse_quantity is unit-agnostic).
        assert!(agg
            .iter()
            .any(|s| s.resource == "memory" && s.quantity == 64.0 * 1024.0 * 1024.0 * 1024.0));
        // LQ-attributed row.
        let lq: Vec<_> = samples.iter().filter(|s| s.project == "proj-a").collect();
        assert_eq!(lq.len(), 1);
        assert_eq!(lq[0].pool, "gpu");
        assert_eq!(lq[0].quantity, 10.0);
    }

    #[tokio::test]
    async fn unparseable_quantity_is_skipped_never_fails_the_tick() {
        let store = Arc::new(InMemoryStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        let obs = PoolObservation {
            flavors_usage: BTreeMap::from([(
                "a100".to_string(),
                BTreeMap::from([
                    ("cpu".to_string(), "banana".to_string()),
                    ("memory".to_string(), "64Gi".to_string()),
                ]),
            )]),
            ..Default::default()
        };
        let prov: Arc<dyn PoolProvisioner> = Arc::new(MockPools {
            present: true,
            observation: Some(obs),
            ..Default::default()
        });
        let m = Metering::new(store.clone(), Some(prov), Duration::from_secs(60));
        assert_eq!(
            m.tick().await,
            1,
            "the bad row is skipped, the good one kept"
        );
        let samples = store.usage_samples(None, None, 0, u64::MAX).await.unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].resource, "memory");
    }

    #[tokio::test]
    async fn kueue_absent_emits_observed_spec_min_demand() {
        let store = Arc::new(InMemoryStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        store
            .upsert_allocation(AllocationSpec {
                pool: "gpu".into(),
                project: "proj-a".into(),
                namespace: "proj-a".into(),
                nominal: BTreeMap::new(),
                borrowing_limit: BTreeMap::new(),
                lending_limit: BTreeMap::new(),
            })
            .await
            .unwrap();
        store
            .upsert_desired(&ClusterId("c1".into()), cluster("c1", "proj-a"))
            .await
            .unwrap();
        store
            .upsert_desired(&ClusterId("c2".into()), cluster("c2", "no-alloc"))
            .await
            .unwrap();
        // A terminated cluster is not metered.
        store
            .upsert_desired(&ClusterId("c3".into()), cluster("c3", "proj-a"))
            .await
            .unwrap();
        store
            .set_desired(&ClusterId("c3".into()), DesiredState::Terminated)
            .await
            .unwrap();

        // Kueue absent (present = false).
        let prov: Arc<dyn PoolProvisioner> = Arc::new(MockPools {
            present: false,
            observation: None,
            ..Default::default()
        });
        let m = Metering::new(store.clone(), Some(prov), Duration::from_secs(60));
        // 2 Running clusters × (cpu, memory); the terminated cluster is
        // not metered.
        assert_eq!(m.tick().await, 4);
        let samples = store.usage_samples(None, None, 0, u64::MAX).await.unwrap();
        assert!(samples
            .iter()
            .all(|s| s.project != "proj-a" || s.pool == "gpu"));
        assert!(!samples.iter().any(|s| s.project == "proj-a" && s.ts == 0));
        // The terminated cluster c3 (also proj-a) contributed nothing beyond
        // c1's rows: exactly 2 cpu rows total (c1 + c2).
        assert_eq!(samples.iter().filter(|s| s.resource == "cpu").count(), 2);
    }

    #[tokio::test]
    async fn kueue_absent_samples_attribute_pool_and_source() {
        let store = Arc::new(InMemoryStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        store
            .upsert_allocation(AllocationSpec {
                pool: "gpu".into(),
                project: "proj-a".into(),
                namespace: "proj-a".into(),
                nominal: BTreeMap::new(),
                borrowing_limit: BTreeMap::new(),
                lending_limit: BTreeMap::new(),
            })
            .await
            .unwrap();
        store
            .upsert_desired(&ClusterId("c1".into()), cluster("c1", "proj-a"))
            .await
            .unwrap();
        store
            .upsert_desired(&ClusterId("c2".into()), cluster("c2", "no-alloc"))
            .await
            .unwrap();

        // No provisioner at all (e.g. --demo) also takes the fallback path.
        let m: Metering<InMemoryStore> =
            Metering::new(store.clone(), None, Duration::from_secs(60));
        assert_eq!(m.tick().await, 4);

        let samples = store.usage_samples(None, None, 0, u64::MAX).await.unwrap();
        assert!(samples
            .iter()
            .all(|s| s.source == UsageSource::ObservedSpec));
        // proj-a is attributed to pool gpu at min demand (3 cpu / 6 GiB).
        let a_cpu = samples
            .iter()
            .find(|s| s.project == "proj-a" && s.resource == "cpu")
            .unwrap();
        assert_eq!(a_cpu.pool, "gpu");
        assert_eq!(a_cpu.quantity, 3.0);
        let a_mem = samples
            .iter()
            .find(|s| s.project == "proj-a" && s.resource == "memory")
            .unwrap();
        assert_eq!(a_mem.quantity, 6.0);
        // A project with no allocation gets pool = "".
        let orphan = samples
            .iter()
            .find(|s| s.project == "no-alloc" && s.resource == "cpu")
            .unwrap();
        assert_eq!(orphan.pool, "");
    }

    #[tokio::test]
    async fn empty_pools_and_clusters_emit_no_samples() {
        let store = Arc::new(InMemoryStore::new());
        let prov: Arc<dyn PoolProvisioner> = Arc::new(MockPools {
            present: true,
            observation: None,
            observe_err: false,
        });
        let m = Metering::new(store.clone(), Some(prov), Duration::from_secs(60));
        assert_eq!(m.tick().await, 0);
        let m2: Metering<InMemoryStore> = Metering::new(store, None, Duration::from_secs(60));
        assert_eq!(m2.tick().await, 0);
    }

    #[tokio::test]
    async fn record_failure_is_swallowed_and_reported_as_zero() {
        // Per-tick errors are logged, never fatal: a store that rejects the
        // batch makes tick() report 0 and must not panic the loop.
        use crate::store::testkit::FailingStore;
        let store = Arc::new(FailingStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        let obs = PoolObservation {
            flavors_usage: BTreeMap::from([(
                "a100".to_string(),
                BTreeMap::from([("cpu".to_string(), "16".to_string())]),
            )]),
            ..Default::default()
        };
        let prov: Arc<dyn PoolProvisioner> = Arc::new(MockPools {
            present: true,
            observation: Some(obs),
            observe_err: false,
        });
        store.fail("record_usage_samples");
        let m = Metering::new(store.clone(), Some(prov), Duration::from_secs(60));
        assert_eq!(m.tick().await, 0, "a failed record reports no samples");
    }

    #[tokio::test]
    async fn kueue_path_store_and_observe_errors_emit_nothing() {
        use crate::store::testkit::FailingStore;
        // list_pools failing → no samples, no panic.
        let store = Arc::new(FailingStore::new());
        store.fail("list_pools");
        let prov: Arc<dyn PoolProvisioner> = Arc::new(MockPools {
            present: true,
            ..Default::default()
        });
        let m = Metering::new(store.clone(), Some(prov), Duration::from_secs(60));
        assert_eq!(m.tick().await, 0);

        // A pool whose ClusterQueue observation fails is skipped; the tick
        // still succeeds for nothing (single pool).
        let store = Arc::new(InMemoryStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        let prov: Arc<dyn PoolProvisioner> = Arc::new(MockPools {
            present: true,
            observe_err: true,
            ..Default::default()
        });
        let m = Metering::new(store.clone(), Some(prov), Duration::from_secs(60));
        assert_eq!(m.tick().await, 0, "the failing pool is skipped");
        assert!(store
            .usage_samples(None, None, 0, u64::MAX)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn observed_spec_path_store_errors_emit_nothing() {
        use crate::store::testkit::FailingStore;
        // list() failing → no samples.
        let store = Arc::new(FailingStore::new());
        store.fail("list");
        let m: Metering<FailingStore> = Metering::new(store, None, Duration::from_secs(60));
        assert_eq!(m.tick().await, 0);

        // The allocation lookup failing still emits samples, just with no
        // pool attribution (fail-soft; a project→pool lookup error must not
        // drop the tick's data).
        let store = Arc::new(FailingStore::new());
        store
            .upsert_desired(&ClusterId("c1".into()), cluster("c1", "proj-a"))
            .await
            .unwrap();
        store.fail("list_pools");
        let m: Metering<FailingStore> = Metering::new(store.clone(), None, Duration::from_secs(60));
        assert_eq!(m.tick().await, 2);
        assert!(
            store
                .usage_samples(None, None, 0, u64::MAX)
                .await
                .unwrap()
                .iter()
                .all(|s| s.pool.is_empty()),
            "no pool attribution when the lookup fails"
        );

        // list_allocations failing per pool: same fail-soft behavior.
        let store = Arc::new(FailingStore::new());
        store.upsert_pool("gpu", pool("gpu")).await.unwrap();
        store
            .upsert_desired(&ClusterId("c1".into()), cluster("c1", "proj-a"))
            .await
            .unwrap();
        store.fail("list_allocations");
        let m: Metering<FailingStore> = Metering::new(store.clone(), None, Duration::from_secs(60));
        assert_eq!(m.tick().await, 2);
    }

    #[tokio::test]
    async fn uncomputable_demand_is_skipped_never_fails_the_tick() {
        // A Running cluster whose spec doesn't parse (e.g. bad cpu quantity)
        // is skipped with a warning; the healthy cluster is still metered.
        let store = Arc::new(InMemoryStore::new());
        let mut bad = cluster("bad", "proj-a");
        bad.head_cpu = "banana".into();
        store
            .upsert_desired(&ClusterId("bad".into()), bad)
            .await
            .unwrap();
        store
            .upsert_desired(&ClusterId("c1".into()), cluster("c1", "proj-a"))
            .await
            .unwrap();

        let m: Metering<InMemoryStore> =
            Metering::new(store.clone(), None, Duration::from_secs(60));
        // Only the healthy cluster's (cpu, memory) samples land.
        assert_eq!(m.tick().await, 2);
        let samples = store.usage_samples(None, None, 0, u64::MAX).await.unwrap();
        assert_eq!(samples.len(), 2);
        assert!(samples.iter().all(|s| s.project == "proj-a"));
    }

    #[tokio::test]
    async fn run_loop_ticks_until_shutdown() {
        // The loop meters on each tick and exits promptly on shutdown.
        let store = Arc::new(InMemoryStore::new());
        store
            .upsert_desired(&ClusterId("c1".into()), cluster("c1", "proj-a"))
            .await
            .unwrap();
        let m = Metering::new(store.clone(), None, Duration::from_millis(10));

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            m.run(async {
                let _ = rx.await;
            })
            .await
        });
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            !store
                .usage_samples(None, None, 0, u64::MAX)
                .await
                .unwrap()
                .is_empty(),
            "the background loop should have recorded samples"
        );
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop should stop promptly on shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn mock_pool_provisioner_apply_and_delete_are_noops() {
        // Keep the test double honest: apply/delete succeed and record nothing.
        let prov = MockPools::default();
        prov.apply_pool(&pool("gpu"), &[]).await.unwrap();
        prov.delete_pool("gpu").await.unwrap();
    }
}
