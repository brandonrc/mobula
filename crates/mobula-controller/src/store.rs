//! Desired-state store (ADR-0004: Postgres is truth; SQLite in dev).
//!
//! This slice defines the `Store` trait and an in-memory implementation so
//! the reconcile engine is testable without a database. The sqlx-backed
//! store lands in the next slice behind the same trait.

use async_trait::async_trait;
use mobula_core::{ClusterId, ClusterSpec, ClusterState, DriftCondition};

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
    /// Drift/health alarm raised by the reconcile engine (ADR-0004, #41/#47),
    /// distinct from `observed_state`. `None` when the cluster is converging
    /// normally.
    pub condition: Option<DriftCondition>,
    /// Consecutive no-progress reconcile attempts (#43). Resets to 0 on
    /// progress; drives the exponential backoff delay.
    pub failure_count: u32,
    /// Unix seconds before which the reconciler must not re-actuate this
    /// cluster (#43 backoff gate). 0 means "no backoff pending".
    pub next_attempt_at: u64,
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

/// A canonical fingerprint of the actuation-relevant spec, used by the
/// outbox to detect a *conflicting* re-use of an intent key (ADR-0007:
/// stale-generation writes must be rejected). Two specs that produce the
/// same generation must produce the same fingerprint; a `{id}/{generation}`
/// key that reappears with a different fingerprint is a restore/rollback
/// anomaly. `ClusterSpec`'s fields are all actuation-relevant, so its JSON
/// serialization is a stable fingerprint.
pub(crate) fn params_fingerprint(spec: &ClusterSpec) -> String {
    serde_json::to_string(spec).unwrap_or_default()
}

/// Lifecycle of an outbox intent (ADR-0007). A `Pending` row left behind by
/// a crash between `begin_intent` and `complete_intent` tells recovery the
/// previous apply may not have finished; `Applied` means it committed and a
/// response was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentStatus {
    Pending,
    Applied,
}

/// A persisted outbox row: what we were about to actuate (`key`), the spec
/// fingerprint we actuated, the completion status, and the stored provider
/// response (opaque JSON so the store stays decoupled from provider types).
#[derive(Debug, Clone)]
pub struct IntentRecord {
    pub key: String,
    pub params_fingerprint: String,
    pub status: IntentStatus,
    pub response_json: Option<String>,
    pub created_at: u64,
    pub completed_at: Option<u64>,
}

/// Result of opening an intent before actuating (ADR-0007 fence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentOutcome {
    /// Safe to actuate. `replay` is true when a matching-params row already
    /// existed (a crash-recovery or drift re-apply of the *same* desired
    /// state) — the caller still applies, because the provider call is
    /// idempotent per key and drift repair depends on re-applying.
    Proceed { replay: bool },
    /// The key already exists with a *different* fingerprint: a stale or
    /// conflicting generation write (e.g. a DB restore reusing a generation
    /// number for a different spec). The caller must refuse to actuate.
    ParamMismatch,
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
    /// The stored `observed_generation` is monotonic non-decreasing (ADR-0007
    /// stale-generation fence, #41): an observation reporting an *older*
    /// generation than what's stored does not roll it back.
    async fn record_observation(
        &self,
        id: &ClusterId,
        observed: Option<ClusterState>,
        observed_generation: u64,
    ) -> Result<(), StoreError>;

    /// Set (or clear) the drift/health condition on a cluster (#41/#47).
    async fn set_condition(
        &self,
        id: &ClusterId,
        condition: Option<DriftCondition>,
    ) -> Result<(), StoreError>;

    /// Whether the control plane is quarantined (ADR-0007 restore quarantine,
    /// #41): a stale-restore boot check trips this, and while set the
    /// reconcile engine observes but never actuates until an operator clears
    /// it.
    async fn is_quarantined(&self) -> Result<bool, StoreError>;

    /// Enter or leave quarantine.
    async fn set_quarantine(&self, quarantined: bool) -> Result<(), StoreError>;

    /// Persist a cluster's backoff state after a reconcile attempt (#43):
    /// `failure_count` consecutive no-progress attempts and the unix time
    /// before which not to re-actuate. Both 0 clears the backoff.
    async fn record_attempt(
        &self,
        id: &ClusterId,
        failure_count: u32,
        next_attempt_at: u64,
    ) -> Result<(), StoreError>;

    /// Transactional outbox (ADR-0007): open an intent to actuate `key` with
    /// the given spec `fingerprint`, committing a `Pending` row *before* the
    /// provider call. Returns [`IntentOutcome::Proceed`] when the caller
    /// should actuate (fresh, or a same-params re-apply), or
    /// [`IntentOutcome::ParamMismatch`] when the key already exists with a
    /// different fingerprint (reject — stale/conflicting generation).
    async fn begin_intent(&self, key: &str, fingerprint: &str)
        -> Result<IntentOutcome, StoreError>;

    /// Mark an opened intent `Applied` and store the provider `response_json`
    /// (opaque). Called after a successful provider actuation.
    async fn complete_intent(&self, key: &str, response_json: &str) -> Result<(), StoreError>;

    /// Read an outbox row (crash-recovery / audit / tests).
    async fn get_intent(&self, key: &str) -> Result<Option<IntentRecord>, StoreError>;

    /// Bound outbox growth: delete `Applied` rows whose `completed_at` is
    /// older than `applied_before`. Returns how many were removed.
    async fn reap_intents(&self, applied_before: u64) -> Result<u64, StoreError>;
}

pub mod memory {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// In-memory `Store` for tests and single-node dev.
    #[derive(Default)]
    pub struct InMemoryStore {
        clusters: Mutex<HashMap<String, StoredCluster>>,
        intents: Mutex<HashMap<String, IntentRecord>>,
        quarantined: AtomicBool,
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
                condition: observed.and_then(|c| c.condition),
                failure_count: observed.map(|c| c.failure_count).unwrap_or(0),
                next_attempt_at: observed.map(|c| c.next_attempt_at).unwrap_or(0),
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
                // Monotonic fence (#41): never roll the observed generation
                // backwards (a stale-restore observation must not overwrite a
                // newer one).
                c.observed_generation = c.observed_generation.max(observed_generation);
            }
            Ok(())
        }

        async fn set_condition(
            &self,
            id: &ClusterId,
            condition: Option<DriftCondition>,
        ) -> Result<(), StoreError> {
            if let Some(c) = self.clusters.lock().unwrap().get_mut(&id.0) {
                c.condition = condition;
            }
            Ok(())
        }

        async fn is_quarantined(&self) -> Result<bool, StoreError> {
            Ok(self.quarantined.load(Ordering::SeqCst))
        }

        async fn set_quarantine(&self, quarantined: bool) -> Result<(), StoreError> {
            self.quarantined.store(quarantined, Ordering::SeqCst);
            Ok(())
        }

        async fn record_attempt(
            &self,
            id: &ClusterId,
            failure_count: u32,
            next_attempt_at: u64,
        ) -> Result<(), StoreError> {
            if let Some(c) = self.clusters.lock().unwrap().get_mut(&id.0) {
                c.failure_count = failure_count;
                c.next_attempt_at = next_attempt_at;
            }
            Ok(())
        }

        async fn begin_intent(
            &self,
            key: &str,
            fingerprint: &str,
        ) -> Result<IntentOutcome, StoreError> {
            let mut map = self.intents.lock().unwrap();
            match map.get(key) {
                Some(existing) if existing.params_fingerprint != fingerprint => {
                    Ok(IntentOutcome::ParamMismatch)
                }
                Some(_) => Ok(IntentOutcome::Proceed { replay: true }),
                None => {
                    map.insert(
                        key.to_string(),
                        IntentRecord {
                            key: key.to_string(),
                            params_fingerprint: fingerprint.to_string(),
                            status: IntentStatus::Pending,
                            response_json: None,
                            created_at: now_unix(),
                            completed_at: None,
                        },
                    );
                    Ok(IntentOutcome::Proceed { replay: false })
                }
            }
        }

        async fn complete_intent(&self, key: &str, response_json: &str) -> Result<(), StoreError> {
            if let Some(rec) = self.intents.lock().unwrap().get_mut(key) {
                rec.status = IntentStatus::Applied;
                rec.response_json = Some(response_json.to_string());
                rec.completed_at = Some(now_unix());
            }
            Ok(())
        }

        async fn get_intent(&self, key: &str) -> Result<Option<IntentRecord>, StoreError> {
            Ok(self.intents.lock().unwrap().get(key).cloned())
        }

        async fn reap_intents(&self, applied_before: u64) -> Result<u64, StoreError> {
            let mut map = self.intents.lock().unwrap();
            let before = map.len();
            map.retain(|_, r| {
                !(r.status == IntentStatus::Applied
                    && r.completed_at.is_some_and(|c| c < applied_before))
            });
            Ok((before - map.len()) as u64)
        }
    }
}
