//! Mobula cluster controller: desired-state store + observation-first
//! reconcile engine (Phase 3, ADR-0004/0006/0007).
//!
//! The reconcile engine is provider-agnostic — it drives any
//! [`mobula_provision::Provisioner`] (KubeRay first) against a [`Store`]
//! (in-memory now, sqlx-backed next).

pub mod metering;
pub mod pool_reconcile;
pub mod reconcile;
pub mod store;
pub mod store_sqlite;

pub use metering::Metering;
pub use pool_reconcile::{PoolAction, PoolReconciler};
pub use reconcile::{Action, RateLimits, ReconcileError, Reconciler};
pub use store::{
    memory::InMemoryStore, now_unix, queue_assignment_for_project, DesiredState, IntentOutcome,
    IntentRecord, IntentStatus, Store, StoreError, StoredCluster, StoredPolicy, StoredPool,
    UsageSample, UsageSource, LOCKOUT_SECS, LOGIN_LOCKOUT_THRESHOLD,
};
pub use store_sqlite::SqliteStore;
