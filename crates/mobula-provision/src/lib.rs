//! Provisioner abstraction: the only place cloud/Kubernetes specifics live.
//!
//! `mobula-core` stays provider-agnostic; each backend (KubeRay first, VM
//! providers later) implements [`Provisioner`]. All mutating calls carry an
//! idempotency key so an HA failover mid-provision cannot double-provision
//! (PLAN.md, review finding A4).

use mobula_core::{ClusterId, ClusterSpec, ClusterState};

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
