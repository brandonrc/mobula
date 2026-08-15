//! Desired-state store (ADR-0004: Postgres is truth; SQLite in dev).
//!
//! This slice defines the `Store` trait and an in-memory implementation so
//! the reconcile engine is testable without a database. The sqlx-backed
//! store lands in the next slice behind the same trait.

use async_trait::async_trait;
use mobula_core::{ClusterId, ClusterSpec, ClusterState};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),
}

/// What the operator wants a cluster to be. The *observed* state is
/// reconstructed from the provisioner every reconcile (ADR-0006) — it is
/// never stored as authoritative truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredState {
    Running,
    Terminated,
}

/// A persisted cluster: desired spec + a monotonic `generation` that bumps
/// whenever the spec changes, plus the last observation. `generation` vs
/// `observed_generation` is the drift signal (K8s convention, ADR-0006).
#[derive(Debug, Clone)]
pub struct StoredCluster {
    pub id: ClusterId,
    pub spec: ClusterSpec,
    pub generation: u64,
    pub desired: DesiredState,
    pub observed_state: Option<ClusterState>,
    pub observed_generation: u64,
    /// Unix seconds when the cluster was first created (for TTL reaping).
    pub created_at: u64,
}

/// Current unix time in whole seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl StoredCluster {
    /// The idempotency/fencing key for actuating this desired state
    /// (ADR-0007): derived from id + generation, so a level-triggered loop
    /// produces the *same* key for the *same* desired state — never a
    /// per-call UUID.
    pub fn intent_key(&self) -> String {
        format!("{}/{}", self.id, self.generation)
    }
}

/// Whether two specs differ in a way that should bump `generation`.
/// `ClusterSpec` isn't `PartialEq`, so compare the fields that drive
/// actuation. Shared by every `Store` implementation.
pub(crate) fn spec_changed(a: &ClusterSpec, b: &ClusterSpec) -> bool {
    a.name != b.name
        || a.project != b.project
        || a.ray_version != b.ray_version
        || a.image != b.image
        || a.head_cpu != b.head_cpu
        || a.head_memory != b.head_memory
        || a.ttl_seconds != b.ttl_seconds
        || a.worker_groups.len() != b.worker_groups.len()
        || a.worker_groups.iter().zip(&b.worker_groups).any(|(x, y)| {
            x.name != y.name
                || x.cpu != y.cpu
                || x.memory != y.memory
                || x.gpu != y.gpu
                || x.min_replicas != y.min_replicas
                || x.max_replicas != y.max_replicas
                || x.replicas != y.replicas
        })
}

#[async_trait]
pub trait Store: Send + Sync {
    /// Create or update desired spec. Returns the (possibly bumped)
    /// generation. Generation only advances when the spec actually changes.
    async fn upsert_desired(&self, id: &ClusterId, spec: ClusterSpec) -> Result<u64, StoreError>;

    async fn get(&self, id: &ClusterId) -> Result<Option<StoredCluster>, StoreError>;
    async fn list(&self) -> Result<Vec<StoredCluster>, StoreError>;

    /// Flip desired state (e.g. request termination).
    async fn set_desired(&self, id: &ClusterId, desired: DesiredState) -> Result<(), StoreError>;

    /// Record the reconstructed observation and the generation it reflects.
    async fn record_observation(
        &self,
        id: &ClusterId,
        observed: Option<ClusterState>,
        observed_generation: u64,
    ) -> Result<(), StoreError>;

    /// Transactional outbox / fence (ADR-0007): record that we are about to
    /// actuate `key`. Returns true if newly recorded, false if it was
    /// already present — the provisioner call is still idempotent either
    /// way, but this gives crash-recovery a record of in-flight intents.
    async fn record_intent(&self, key: &str) -> Result<bool, StoreError>;
}

pub mod memory {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    /// In-memory `Store` for tests and single-node dev.
    #[derive(Default)]
    pub struct InMemoryStore {
        clusters: Mutex<HashMap<String, StoredCluster>>,
        intents: Mutex<HashSet<String>>,
    }

    impl InMemoryStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    use super::spec_changed;

    #[async_trait]
    impl Store for InMemoryStore {
        async fn upsert_desired(
            &self,
            id: &ClusterId,
            spec: ClusterSpec,
        ) -> Result<u64, StoreError> {
            let mut map = self.clusters.lock().unwrap();
            let generation = match map.get(&id.0) {
                Some(existing) if !spec_changed(&existing.spec, &spec) => existing.generation,
                Some(existing) => existing.generation + 1,
                None => 1,
            };
            let observed = map.get(&id.0);
            let record = StoredCluster {
                id: id.clone(),
                spec,
                generation,
                desired: observed.map(|c| c.desired).unwrap_or(DesiredState::Running),
                observed_state: observed.and_then(|c| c.observed_state),
                observed_generation: observed.map(|c| c.observed_generation).unwrap_or(0),
                created_at: observed.map(|c| c.created_at).unwrap_or_else(now_unix),
            };
            map.insert(id.0.clone(), record);
            Ok(generation)
        }

        async fn get(&self, id: &ClusterId) -> Result<Option<StoredCluster>, StoreError> {
            Ok(self.clusters.lock().unwrap().get(&id.0).cloned())
        }

        async fn list(&self) -> Result<Vec<StoredCluster>, StoreError> {
            Ok(self.clusters.lock().unwrap().values().cloned().collect())
        }

        async fn set_desired(
            &self,
            id: &ClusterId,
            desired: DesiredState,
        ) -> Result<(), StoreError> {
            let mut map = self.clusters.lock().unwrap();
            let c = map
                .get_mut(&id.0)
                .ok_or_else(|| StoreError::Backend(format!("no such cluster {id}")))?;
            c.desired = desired;
            Ok(())
        }

        async fn record_observation(
            &self,
            id: &ClusterId,
            observed: Option<ClusterState>,
            observed_generation: u64,
        ) -> Result<(), StoreError> {
            let mut map = self.clusters.lock().unwrap();
            if let Some(c) = map.get_mut(&id.0) {
                c.observed_state = observed;
                c.observed_generation = observed_generation;
            }
            Ok(())
        }

        async fn record_intent(&self, key: &str) -> Result<bool, StoreError> {
            Ok(self.intents.lock().unwrap().insert(key.to_string()))
        }
    }
}
