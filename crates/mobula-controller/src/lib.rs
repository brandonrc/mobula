//! Mobula cluster controller: desired-state store + observation-first
//! reconcile engine (Phase 3, ADR-0004/0006/0007).
//!
//! The reconcile engine is provider-agnostic — it drives any
//! [`mobula_provision::Provisioner`] (KubeRay first) against a [`Store`]
//! (in-memory now, sqlx-backed next).

pub mod reconcile;
pub mod store;

pub use reconcile::{Action, ReconcileError, Reconciler};
pub use store::{memory::InMemoryStore, DesiredState, Store, StoreError, StoredCluster};
