//! Engine router (multi-engine spike): a [`Provisioner`] that fronts one
//! [`KubeRayProvisioner`] and one [`DaskProvisioner`] and dispatches each call
//! to the right backend by the cluster's [`Engine`].
//!
//! `apply` carries the [`ClusterSpec`] (and therefore `spec.engine`), so its
//! dispatch is exact and it records the id→engine mapping. The level-triggered
//! calls (`observe`/`terminate`/`suspend`/`resume`/`cluster_*`) carry only a
//! [`ClusterId`]; the router resolves the engine from that cache, and on a cold
//! miss (e.g. after a control-plane restart, before the first apply) probes the
//! DaskCluster CRD — a hit means Dask, otherwise Ray. `list` fans out to both
//! backends and warms the cache. This keeps the reconciler generic over a
//! single `Provisioner` (its tests are untouched) while the production binary
//! wires the router as that `P`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use mobula_core::{ClusterId, ClusterSpec, Engine};
use tokio::sync::RwLock;

use crate::{
    ApplyResponse, DaskProvisioner, KubeRayProvisioner, ObservedCluster, ProvisionError,
    Provisioner, QueueAssignment,
};

pub struct EngineRouter {
    ray: Arc<KubeRayProvisioner>,
    dask: Arc<DaskProvisioner>,
    /// Cluster-id → engine, warmed by `apply`/`list` and by cold-miss probes.
    cache: RwLock<HashMap<String, Engine>>,
}

impl EngineRouter {
    /// Connect both backends against `namespace`. `autoscaling` selects the
    /// Ray field-ownership regime (unused by Dask).
    pub async fn connect(
        namespace: impl Into<String> + Clone,
        autoscaling: bool,
    ) -> Result<Self, ProvisionError> {
        let ray = Arc::new(KubeRayProvisioner::connect(namespace.clone(), autoscaling).await?);
        let dask = Arc::new(DaskProvisioner::connect(namespace).await?);
        Ok(Self::from_parts(ray, dask))
    }

    pub fn from_parts(ray: Arc<KubeRayProvisioner>, dask: Arc<DaskProvisioner>) -> Self {
        Self {
            ray,
            dask,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// The Ray backend, for the Ray-only surfaces the router does not front
    /// (Serve services, Kueue pool status): those stay engine-specific.
    pub fn ray(&self) -> Arc<KubeRayProvisioner> {
        self.ray.clone()
    }

    async fn remember(&self, id: &str, engine: Engine) {
        self.cache.write().await.insert(id.to_string(), engine);
    }

    /// Resolve the engine backing `id`: cache, else probe the DaskCluster CRD
    /// (present → Dask, absent/unserved → Ray) and cache the result.
    async fn engine_of(&self, id: &ClusterId) -> Engine {
        if let Some(e) = self.cache.read().await.get(&id.0).copied() {
            return e;
        }
        let engine = match self.dask.observe(id).await {
            Ok(_) => Engine::Dask,
            _ => Engine::Ray,
        };
        self.remember(&id.0, engine).await;
        engine
    }

    fn backend(&self, engine: Engine) -> &dyn Provisioner {
        match engine {
            Engine::Ray => self.ray.as_ref(),
            Engine::Dask => self.dask.as_ref(),
        }
    }
}

#[async_trait]
impl Provisioner for EngineRouter {
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        generation: u64,
        idempotency_key: &str,
        queue: Option<&QueueAssignment>,
    ) -> Result<ApplyResponse, ProvisionError> {
        self.remember(&id.0, spec.engine).await;
        self.backend(spec.engine)
            .apply(id, spec, generation, idempotency_key, queue)
            .await
    }

    async fn ensure_namespace_posture(&self) -> Result<(), ProvisionError> {
        // The default-deny / tenant-allow / PSS posture is per-namespace and
        // engine-agnostic (Dask pods carry the same tenant cluster-id label the
        // policies select on), so the shared Ray implementation covers both.
        // Disambiguate from KubeRayProvisioner's inherent same-named method
        // (which takes an explicit namespace) by calling through the trait.
        Provisioner::ensure_namespace_posture(self.ray.as_ref()).await
    }

    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        let engine = self.engine_of(id).await;
        self.backend(engine).terminate(id).await
    }

    async fn suspend(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        let engine = self.engine_of(id).await;
        self.backend(engine).suspend(id).await
    }

    async fn resume(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        let engine = self.engine_of(id).await;
        self.backend(engine).resume(id).await
    }

    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        // Fast path: if we know the engine, ask exactly that backend.
        if let Some(e) = self.cache.read().await.get(&id.0).copied() {
            return self.backend(e).observe(id).await;
        }
        // Cold miss: probe Dask; a hit is Dask, otherwise Ray.
        match self.dask.observe(id).await {
            Ok(o) => {
                self.remember(&id.0, Engine::Dask).await;
                Ok(o)
            }
            Err(ProvisionError::NotFound(_)) => {
                self.remember(&id.0, Engine::Ray).await;
                self.ray.observe(id).await
            }
            Err(e) => Err(e),
        }
    }

    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        let mut out = self.ray.list().await?;
        for o in &out {
            self.remember(&o.id.0, Engine::Ray).await;
        }
        let dask = self.dask.list().await?;
        for o in &dask {
            self.remember(&o.id.0, Engine::Dask).await;
        }
        out.extend(dask);
        Ok(out)
    }

    fn metrics_endpoint(&self, id: &ClusterId) -> Option<String> {
        // Dask has no Ray-style Prometheus surface; Ray names one. Sync call:
        // consult the cache non-blockingly, default to Ray on an unknown id.
        match self
            .cache
            .try_read()
            .ok()
            .and_then(|c| c.get(&id.0).copied())
        {
            Some(Engine::Dask) => None,
            _ => self.ray.metrics_endpoint(id),
        }
    }

    fn dashboard_api_base(&self, id: &ClusterId) -> Option<String> {
        // Dask has no Ray-Jobs dashboard proxy surface (batch is out of scope),
        // so it names none; the jobs route additionally rejects engine=dask
        // with a clear 400 before ever reaching here.
        match self
            .cache
            .try_read()
            .ok()
            .and_then(|c| c.get(&id.0).copied())
        {
            Some(Engine::Dask) => None,
            _ => self.ray.dashboard_api_base(id),
        }
    }

    async fn cluster_nodes(
        &self,
        id: &ClusterId,
    ) -> Result<Option<mobula_core::ClusterNodes>, ProvisionError> {
        let engine = self.engine_of(id).await;
        self.backend(engine).cluster_nodes(id).await
    }

    async fn cluster_events(
        &self,
        id: &ClusterId,
    ) -> Result<Option<mobula_core::ClusterEvents>, ProvisionError> {
        let engine = self.engine_of(id).await;
        self.backend(engine).cluster_events(id).await
    }

    async fn cluster_logs(
        &self,
        id: &ClusterId,
        pod: Option<&str>,
        tail: usize,
    ) -> Result<Option<mobula_core::ClusterLogs>, ProvisionError> {
        let engine = self.engine_of(id).await;
        self.backend(engine).cluster_logs(id, pod, tail).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dask_pod, daskcluster_cr, mock_client, Fixture, Recorder};
    use mobula_core::{ClusterState, WorkerGroup};
    use serde_json::json;

    fn dask_spec() -> ClusterSpec {
        ClusterSpec {
            name: "d1".into(),
            project: "p".into(),
            engine: Engine::Dask,
            ray_version: String::new(),
            image: "ghcr.io/dask/dask:latest".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: vec![WorkerGroup {
                name: "default".into(),
                cpu: "2".into(),
                memory: "4Gi".into(),
                gpu: None,
                min_replicas: 1,
                max_replicas: 1,
                replicas: 1,
            }],
            ttl_seconds: None,
            idle_timeout_secs: None,
            owner: None,
        }
    }

    fn ray_spec() -> ClusterSpec {
        ClusterSpec {
            engine: Engine::Ray,
            ray_version: "2.57.0".into(),
            image: "rayproject/ray:2.57.0".into(),
            ..dask_spec()
        }
    }

    fn raycluster_cr(name: &str) -> serde_json::Value {
        json!({
            "apiVersion": "ray.io/v1",
            "kind": "RayCluster",
            "metadata": {
                "name": name, "namespace": "test-ns",
                "annotations": { "mobula.dev/generation": "1" },
            },
            "spec": {},
            "status": { "state": "ready" },
        })
    }

    /// Build a router whose Ray and Dask backends each speak to their own mock
    /// client, returning both recorders so a test can prove which backend a
    /// call was dispatched to.
    fn router(ray_fx: Fixture, dask_fx: Fixture) -> (EngineRouter, Recorder, Recorder) {
        let (ray_client, ray_rec) = mock_client(ray_fx);
        let (dask_client, dask_rec) = mock_client(dask_fx);
        let ray = Arc::new(KubeRayProvisioner::with_client(
            ray_client, "test-ns", false,
        ));
        let dask = Arc::new(DaskProvisioner::with_client(dask_client, "test-ns"));
        (EngineRouter::from_parts(ray, dask), ray_rec, dask_rec)
    }

    fn touched(rec: &Recorder, needle: &str) -> bool {
        rec.lock().unwrap().iter().any(|(_, p)| p.contains(needle))
    }

    #[tokio::test]
    async fn apply_routes_dask_spec_to_dask_backend() {
        let (r, ray_rec, dask_rec) = router(Fixture::default(), Fixture::default());
        r.apply(&ClusterId("d1".into()), &dask_spec(), 1, "k", None)
            .await
            .unwrap();
        assert!(touched(&dask_rec, "/daskclusters/d1"));
        assert!(!touched(&ray_rec, "/rayclusters"), "ray must be untouched");
    }

    #[tokio::test]
    async fn apply_routes_ray_spec_to_ray_backend() {
        let (r, ray_rec, dask_rec) = router(Fixture::default(), Fixture::default());
        r.apply(&ClusterId("r1".into()), &ray_spec(), 1, "k", None)
            .await
            .unwrap();
        assert!(touched(&ray_rec, "/rayclusters/r1"));
        assert!(
            !touched(&dask_rec, "/daskclusters"),
            "dask must be untouched"
        );
    }

    #[tokio::test]
    async fn observe_resolves_from_cache_after_apply() {
        let dask_fx = Fixture {
            daskcluster: Some(daskcluster_cr("d1", 1, Some("Pending"))),
            pods: vec![
                dask_pod("d1", "scheduler", "Running", true),
                dask_pod("d1", "worker", "Running", true),
            ],
            ..Default::default()
        };
        let (r, ray_rec, _dask_rec) = router(Fixture::default(), dask_fx);
        // apply warms the cache (d1 → Dask).
        r.apply(&ClusterId("d1".into()), &dask_spec(), 1, "k", None)
            .await
            .unwrap();
        let obs = r.observe(&ClusterId("d1".into())).await.unwrap();
        // #121 pod-based readiness flows through the router unchanged.
        assert_eq!(obs.state, ClusterState::Running);
        assert!(
            !touched(&ray_rec, "/rayclusters"),
            "cached Dask id must never probe Ray"
        );
    }

    #[tokio::test]
    async fn observe_cold_miss_probes_dask_then_hits_it() {
        // No prior apply: the router must probe Dask, find the CR, and serve it.
        let dask_fx = Fixture {
            daskcluster: Some(daskcluster_cr("d1", 2, Some("Pending"))),
            pods: vec![
                dask_pod("d1", "scheduler", "Running", true),
                dask_pod("d1", "worker", "Running", true),
            ],
            ..Default::default()
        };
        let (r, ray_rec, dask_rec) = router(Fixture::default(), dask_fx);
        let obs = r.observe(&ClusterId("d1".into())).await.unwrap();
        assert_eq!(obs.state, ClusterState::Running);
        assert!(touched(&dask_rec, "/daskclusters/d1"));
        assert!(!touched(&ray_rec, "/rayclusters"));
    }

    #[tokio::test]
    async fn observe_cold_miss_falls_back_to_ray_when_not_dask() {
        // Dask probe 404s (no such DaskCluster) → the router serves Ray.
        let ray_fx = Fixture {
            raycluster: Some(raycluster_cr("r1")),
            ..Default::default()
        };
        let (r, ray_rec, dask_rec) = router(ray_fx, Fixture::default());
        let obs = r.observe(&ClusterId("r1".into())).await.unwrap();
        assert_eq!(obs.state, ClusterState::Running);
        assert!(touched(&dask_rec, "/daskclusters/r1"), "probed Dask first");
        assert!(touched(&ray_rec, "/rayclusters/r1"), "then served from Ray");
    }

    #[tokio::test]
    async fn terminate_resolves_engine_via_cold_probe() {
        let dask_fx = Fixture {
            daskcluster: Some(daskcluster_cr("d1", 1, Some("Pending"))),
            pods: vec![dask_pod("d1", "scheduler", "Running", true)],
            ..Default::default()
        };
        let (r, ray_rec, dask_rec) = router(Fixture::default(), dask_fx);
        r.terminate(&ClusterId("d1".into())).await.unwrap();
        assert!(touched(&dask_rec, "/daskclusters/d1"));
        assert!(!touched(&ray_rec, "/rayclusters"));
    }

    #[tokio::test]
    async fn nodes_resolve_via_engine_of() {
        let dask_fx = Fixture {
            daskcluster: Some(daskcluster_cr("d1", 1, None)),
            pods: vec![
                dask_pod("d1", "scheduler", "Running", true),
                dask_pod("d1", "worker", "Running", true),
            ],
            ..Default::default()
        };
        let (r, _ray_rec, dask_rec) = router(Fixture::default(), dask_fx);
        let nodes = r
            .cluster_nodes(&ClusterId("d1".into()))
            .await
            .unwrap()
            .unwrap();
        assert!(nodes.head.is_some());
        assert!(touched(&dask_rec, "/pods"));
    }

    #[tokio::test]
    async fn list_fans_out_to_both_backends_and_warms_cache() {
        let ray_fx = Fixture {
            ray_list: vec![raycluster_cr("r1")],
            ..Default::default()
        };
        let dask_fx = Fixture {
            dask_list: vec![daskcluster_cr("d1", 1, Some("Running"))],
            ..Default::default()
        };
        let (r, _ray_rec, _dask_rec) = router(ray_fx, dask_fx);
        let all = r.list().await.unwrap();
        let ids: Vec<&str> = all.iter().map(|o| o.id.0.as_str()).collect();
        assert!(ids.contains(&"r1"), "ray cluster listed");
        assert!(ids.contains(&"d1"), "dask cluster listed");
        // Cache warmed by list ⇒ metrics_endpoint routes by engine without I/O.
        assert!(r.metrics_endpoint(&ClusterId("d1".into())).is_none());
        assert!(r.metrics_endpoint(&ClusterId("r1".into())).is_some());
        assert!(r.dashboard_api_base(&ClusterId("d1".into())).is_none());
        assert!(r.dashboard_api_base(&ClusterId("r1".into())).is_some());
    }

    #[tokio::test]
    async fn suspend_resume_route_to_engine() {
        // Dask suspend/resume are no-ops but must dispatch without error.
        let dask_fx = Fixture {
            daskcluster: Some(daskcluster_cr("d1", 1, Some("Pending"))),
            ..Default::default()
        };
        let (r, _ray_rec, _dask_rec) = router(Fixture::default(), dask_fx);
        r.suspend(&ClusterId("d1".into())).await.unwrap();
        r.resume(&ClusterId("d1".into())).await.unwrap();
    }
}
