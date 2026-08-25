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

    async fn reap_network_policies(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        // #122: the per-cluster netpol name (`mobula-cluster-<id>`) is
        // identical for both engines and lives in the one namespace, and by
        // reap time the CR is typically gone so `engine_of` cannot resolve the
        // owner. Reap on BOTH backends (idempotent — the second is a 404
        // no-op) so the policy is gone regardless of which engine created it.
        self.ray.reap_network_policies(id).await?;
        self.dask.reap_network_policies(id).await
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
