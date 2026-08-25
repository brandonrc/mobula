//! Provisioner abstraction: the only place cloud/Kubernetes specifics live.
//!
//! `mobula-core` stays provider-agnostic; each backend (KubeRay first, VM
//! providers later) implements [`Provisioner`]. All mutating calls carry an
//! idempotency key so an HA failover mid-provision cannot double-provision
//! (PLAN.md, review finding A4).

pub mod dask;
#[cfg(feature = "kuberay")]
pub mod dask_client;
pub mod demo;
pub mod kuberay;
#[cfg(feature = "kuberay")]
pub mod kuberay_client;
pub mod kueue;
#[cfg(feature = "kuberay")]
pub mod kueue_client;
#[cfg(feature = "kuberay")]
pub mod router;
#[cfg(all(test, feature = "kuberay"))]
mod test_support;
#[cfg(feature = "kuberay")]
pub use dask_client::DaskProvisioner;
pub use demo::DemoProvisioner;
pub use kuberay::QueueAssignment;
#[cfg(feature = "kuberay")]
pub use kuberay_client::KubeRayProvisioner;
#[cfg(feature = "kuberay")]
pub use kueue_client::KueueClient;
#[cfg(feature = "kuberay")]
pub use router::EngineRouter;

use mobula_core::{AllocationSpec, ClusterId, ClusterSpec, ClusterState, PoolSpec, ServiceSpec};

#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    #[error("cluster not found: {0}")]
    NotFound(ClusterId),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Observed state of a cluster as reported by a backend.
#[derive(Debug, Clone)]
pub struct ObservedCluster {
    pub id: ClusterId,
    pub state: ClusterState,
    /// The spec generation the backing cluster actually reflects, read back
    /// from the resource Mobula stamps (ADR-0006, #40) — *not* the desired
    /// generation the engine intended. `None` when the backend exposes no
    /// generation marker (e.g. an out-of-band resource). The reconcile
    /// engine records this, so convergence is observed rather than
    /// self-certified.
    pub observed_generation: Option<u64>,
    /// Fingerprint of the Mobula-owned, drift-relevant fields as they exist
    /// on the *live* resource (ADR-0004 drift detection, #41). Recomputed
    /// from the observed manifest, so an out-of-band edit of an owned field
    /// makes it diverge from the desired fingerprint. `None` when the backend
    /// can't project one.
    pub spec_fingerprint: Option<String>,
    /// Base URL of the cluster's native Ray dashboard/job API, reachable
    /// from the control plane. The job gateway proxies to this; it is never
    /// exposed to users directly.
    pub api_base_url: Option<String>,
}

/// The outcome of an [`Provisioner::apply`], stored in the transactional
/// outbox (ADR-0007, #39) so a replay can return it without re-actuating a
/// non-idempotent backend. Serializable because the store persists it as
/// opaque JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApplyResponse {
    /// The generation this apply actuated.
    pub generation: u64,
    /// The cluster's native Ray API base URL, if the backend can name it.
    pub api_base_url: Option<String>,
}

#[async_trait::async_trait]
pub trait Provisioner: Send + Sync {
    /// Create or update the backing resources for `spec` at `generation`.
    /// Idempotent per `idempotency_key`: repeating a call must not create
    /// duplicates. `generation` is stamped onto the backing resource so
    /// [`Provisioner::observe`] can read it back (ADR-0006, #40). Returns
    /// the [`ApplyResponse`] recorded in the outbox (ADR-0007, #39).
    /// `queue` nominates the Kueue LocalQueue the workload is admitted
    /// through (ADR-0010); `None` leaves the manifest queue-free.
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        generation: u64,
        idempotency_key: &str,
        queue: Option<&QueueAssignment>,
    ) -> Result<ApplyResponse, ProvisionError>;

    /// Ensure the namespace-level security posture for the namespace this
    /// backend provisions into (#56 tenant network isolation, #62 STIG
    /// pod-security defaults): a default-deny NetworkPolicy plus explicit
    /// allows — both scoped to the backend's own tenant pods, never
    /// namespace-wide (#86: the namespace can be the control plane's own,
    /// and a namespace-wide deny locks it out) — and Pod Security Standards
    /// labels on the namespace. This is
    /// a per-namespace concern, not per-cluster — the reconcile engine calls
    /// it before/with each actuating `apply`. Idempotent (server-side
    /// apply), and must NOT overwrite a stricter existing posture
    /// (check-then-apply). Default no-op: backends without a namespace
    /// concept (demo) have nothing to ensure.
    async fn ensure_namespace_posture(&self) -> Result<(), ProvisionError> {
        Ok(())
    }

    /// Begin teardown. Idempotent; succeeds if already gone. This also
    /// removes the cluster's per-cluster NetworkPolicy (see
    /// [`Provisioner::reap_network_policies`]) so the happy path leaves no
    /// orphan behind.
    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError>;

    /// Delete the per-cluster NetworkPolicy(ies) for `id` (#122): the
    /// per-owner intra-cluster allow policy the backend created on `apply`
    /// (`mobula-cluster-<id>`, see
    /// [`kuberay::cluster_allow_network_policy`] and its Dask twin — one
    /// policy per cluster that carries both the intra-cluster allow and the
    /// tier-2 per-owner client pin). Idempotent: already-gone is success, so
    /// a teardown that races the CR's disappearance — or retries after a
    /// transient failure — still converges to no orphaned netpol.
    /// Engine-agnostic: the policy name is identical for every engine.
    ///
    /// [`Provisioner::terminate`] already calls this on the happy path; the
    /// reconciler also calls it when it purges a terminated tombstone
    /// (`reap_terminated`), so a netpol that outlived its CR — the CR vanished
    /// before `terminate` fired, leaving the reconciler nothing to tear down —
    /// is still reaped instead of accumulating (#122). Default no-op:
    /// backends without a per-cluster netpol (demo) have nothing to reap.
    async fn reap_network_policies(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        let _ = id;
        Ok(())
    }

    /// Suspend the cluster: release its compute while keeping spec and
    /// state (#51). Idempotent; succeeds if already suspended. Like
    /// [`Provisioner::terminate`] this is a level-triggered call, NOT
    /// generation-keyed through the outbox — suspension changes no spec
    /// field, so it must not ride the `{id}/{generation}` intent key (ADR-0007:
    /// same key = same actuation parameters). Mobula owns `spec.suspend`
    /// (SSA field manager), so this is a single-field actuation on an owned
    /// field.
    async fn suspend(&self, id: &ClusterId) -> Result<(), ProvisionError>;

    /// Resume a suspended cluster (`spec.suspend: false`). Idempotent.
    /// The reconcile engine normally resumes through the generation-keyed
    /// `apply` path (the full manifest already writes `suspend: false`, which
    /// also repairs drift); this method exists for callers that must resume
    /// *without* re-asserting the rest of the spec.
    async fn resume(&self, id: &ClusterId) -> Result<(), ProvisionError>;

    /// Observe current state without mutating anything.
    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError>;

    /// List every cluster this backend manages (field-manager scoped).
    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError>;

    /// The Ray head's Prometheus metrics endpoint for `id`, reachable from
    /// the control plane (`GET /api/v1/clusters/{id}/metrics` proxies it,
    /// #52). Synchronous and pure — it derives a name, it never I/Os.
    /// `None` (the default) when the backend can't name one; the route then
    /// answers a clean 404 `metrics unavailable`.
    fn metrics_endpoint(&self, id: &ClusterId) -> Option<String> {
        let _ = id;
        None
    }

    /// Base URL of the cluster's native Ray dashboard / Job Submission API
    /// (`http://<head-svc>:8265`), reachable from the control plane — the
    /// southbound target for the path-based jobs proxy
    /// (`GET /api/v1/clusters/{id}/jobs`, api-v1.md §5.6). Synchronous and
    /// pure: it derives a service DNS name, it never I/Os, so it inherits the
    /// registry's SSRF posture rather than adding a new attack surface.
    /// `None` (the default) when the backend can't name one.
    fn dashboard_api_base(&self, id: &ClusterId) -> Option<String> {
        let _ = id;
        None
    }

    /// Kubernetes-sourced head + worker-group node breakdown for `id`
    /// (`GET /api/v1/clusters/{id}/nodes`, api-v1.md §5.3). Reads the
    /// RayCluster and the pods the backend owns (`ray.io/cluster=<id>`) —
    /// never the Ray dashboard — so it works even when the dashboard is
    /// unreachable. `Ok(None)` (the default) when the backend cannot produce
    /// one (the route then answers a clean 404 `nodes unavailable`);
    /// `Err(NotFound)` when the cluster is unknown to the backend.
    async fn cluster_nodes(
        &self,
        id: &ClusterId,
    ) -> Result<Option<mobula_core::ClusterNodes>, ProvisionError> {
        let _ = id;
        Ok(None)
    }

    /// Kubernetes Events for `id`'s objects (the RayCluster + the pods/services
    /// KubeRay owns), normalized newest-first (`GET /api/v1/clusters/{id}/events`,
    /// api-v1.md §5.8). Sourced from the K8s API — NOT the Ray dashboard — so it
    /// answers even when Ray is down; the highest-value signal for scheduling /
    /// image-pull / probe failures. `Ok(None)` (the default) when the backend
    /// cannot produce one (the route then answers 404 `events unavailable`).
    async fn cluster_events(
        &self,
        id: &ClusterId,
    ) -> Result<Option<mobula_core::ClusterEvents>, ProvisionError> {
        let _ = id;
        Ok(None)
    }

    /// Tail-capped pod logs for `id` (`GET /api/v1/clusters/{id}/logs`,
    /// api-v1.md §5.6, non-streaming first cut). Reads pod logs through the K8s
    /// API (the kubectl-logs equivalent). `pod` selects one of the cluster's
    /// pods; `None` tails the head pod. `tail` bounds the returned lines.
    /// `Ok(None)` (the default, or when the requested pod is not part of the
    /// cluster) → the route answers 404; a K8s failure → `Err`, which the route
    /// maps to 503. WS streaming is the eventual design (Milestone C).
    async fn cluster_logs(
        &self,
        id: &ClusterId,
        pod: Option<&str>,
        tail: usize,
    ) -> Result<Option<mobula_core::ClusterLogs>, ProvisionError> {
        let _ = (id, pod, tail);
        Ok(None)
    }
}

/// Observed state of a Serve service.
#[derive(Debug, Clone)]
pub struct ObservedService {
    pub name: String,
    pub state: ClusterState,
    /// The service's external Serve endpoint base URL, if ready.
    pub url: Option<String>,
}

/// A pool's quota ledger as read back from Kueue's ClusterQueue `.status`
/// (ADR-0010 §5 of the research doc: the status *is* the ledger). All counts
/// default to 0 when the CQ exists but Kueue hasn't populated status yet.
/// Serializable: the controller persists it as opaque JSON on the pool row
/// (`record_pool_observation`), and Slice 4's metering loop reads it back.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PoolObservation {
    pub admitted_workloads: u32,
    pub reserving_workloads: u32,
    pub pending_workloads: u32,
    /// flavor → resource → quantity string (from `status.flavorsUsage`
    /// `total` — the amounts Kueue admits against, not measured consumption).
    pub flavors_usage:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    /// LocalQueue name → resource → quantity string, from each LocalQueue's
    /// own `status.flavorsUsage` (summed across flavors; LQ status exists
    /// since Kueue v0.9). This is the *per-project* attribution the CQ-level
    /// `flavors_usage` lacks (a CQ is pool-scoped). Added in Slice 4:
    /// `#[serde(default)]` so observations persisted by an older build
    /// still deserialize (they parse with an empty map — a version note,
    /// not a format break).
    #[serde(default)]
    pub queues_usage:
        std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
}

/// Manages a pool's Kueue objects (Cohort / ResourceFlavors / ClusterQueue /
/// LocalQueues). Defined here — next to [`Provisioner`] — rather than in
/// mobula-controller so the live client can implement it without a crate
/// cycle (the controller already depends on this crate); the controller's
/// pool reconcile loop is generic over this trait and stays k8s-free.
#[async_trait::async_trait]
pub trait PoolProvisioner: Send + Sync {
    /// Create or update all of a pool's Kueue objects (server-side apply:
    /// idempotent for identical desired state).
    async fn apply_pool(
        &self,
        spec: &PoolSpec,
        allocs: &[AllocationSpec],
    ) -> Result<(), ProvisionError>;

    /// Delete every Kueue object of the named pool. Idempotent; succeeds
    /// when already gone.
    async fn delete_pool(&self, name: &str) -> Result<(), ProvisionError>;

    /// Read the pool's quota ledger from its ClusterQueue status. `None`
    /// when the ClusterQueue does not exist.
    async fn observe_pool(&self, name: &str) -> Result<Option<PoolObservation>, ProvisionError>;

    /// Whether the API server serves the Kueue CRDs. When false the pool
    /// reconcile loop skips actuation entirely and pools remain in-process
    /// quota only (ADR-0010 fallback). Cached per client.
    async fn kueue_present(&self) -> bool;
}

/// Manages Ray Serve services (RayService CRs). Distinct from
/// [`Provisioner`] because KubeRay's RayService controller owns
/// convergence and zero-downtime upgrades — Mobula is a thin
/// authenticated CRUD proxy here, with no desired-state store or reconcile
/// loop of its own.
#[async_trait::async_trait]
pub trait ServiceProvisioner: Send + Sync {
    /// Deploy or update a service (server-side apply of a RayService).
    /// Idempotent; the upgrade strategy in the spec drives canary vs
    /// in-place rollout.
    async fn deploy(&self, name: &str, spec: &ServiceSpec) -> Result<(), ProvisionError>;
    async fn get(&self, name: &str) -> Result<Option<ObservedService>, ProvisionError>;
    /// Idempotent teardown; succeeds if already gone.
    async fn delete(&self, name: &str) -> Result<(), ProvisionError>;
    async fn list(&self) -> Result<Vec<ObservedService>, ProvisionError>;
}
