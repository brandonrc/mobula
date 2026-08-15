//! Provisioner abstraction: the only place cloud/Kubernetes specifics live.
//!
//! `mobula-core` stays provider-agnostic; each backend (KubeRay first, VM
//! providers later) implements [`Provisioner`]. All mutating calls carry an
//! idempotency key so an HA failover mid-provision cannot double-provision
//! (PLAN.md, review finding A4).

pub mod kuberay;
#[cfg(feature = "kuberay")]
pub mod kuberay_client;
#[cfg(feature = "kuberay")]
pub use kuberay_client::KubeRayProvisioner;

use mobula_core::{ClusterId, ClusterSpec, ClusterState, ServiceSpec};

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
    /// Base URL of the cluster's native Ray dashboard/job API, reachable
    /// from the control plane. The job gateway proxies to this; it is never
    /// exposed to users directly.
    pub api_base_url: Option<String>,
}

#[async_trait::async_trait]
pub trait Provisioner: Send + Sync {
    /// Create or update the backing resources for `spec`. Idempotent per
    /// `idempotency_key`: repeating a call must not create duplicates.
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        idempotency_key: &str,
    ) -> Result<(), ProvisionError>;

    /// Begin teardown. Idempotent; succeeds if already gone.
    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError>;

    /// Observe current state without mutating anything.
    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError>;

    /// List every cluster this backend manages (field-manager scoped).
    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError>;
}

/// Observed state of a Serve service.
#[derive(Debug, Clone)]
pub struct ObservedService {
    pub name: String,
    pub state: ClusterState,
    /// The service's external Serve endpoint base URL, if ready.
    pub url: Option<String>,
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
