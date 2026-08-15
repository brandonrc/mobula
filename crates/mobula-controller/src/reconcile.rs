//! Observation-first reconcile engine (ADR-0006, ADR-0007).
//!
//! Level-triggered: every pass reconstructs each cluster's state from the
//! provisioner (never trusts a stored phase), compares it to desired, and
//! actuates the difference through an idempotency-keyed provisioner call.
//! It is safe to run on a fixed resync interval and safe to re-run after a
//! crash — repeating an actuation with the same desired generation is a
//! no-op at the provider.

use std::sync::Arc;

use mobula_core::ClusterState;
use mobula_provision::{ProvisionError, Provisioner};

use crate::store::{DesiredState, Store, StoreError, StoredCluster};

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Provision(#[from] ProvisionError),
}

/// Per-cluster outcome of a reconcile pass, for logging/metrics/tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Desired and observed already agree.
    NoOp,
    /// Applied desired spec (create or update).
    Applied,
    /// Requested teardown.
    Terminated,
}

pub struct Reconciler<S, P> {
    store: Arc<S>,
    provisioner: Arc<P>,
}

impl<S: Store, P: Provisioner> Reconciler<S, P> {
    pub fn new(store: Arc<S>, provisioner: Arc<P>) -> Self {
        Self { store, provisioner }
    }

    /// Reconcile every known cluster once. Errors on individual clusters
    /// are collected, not fatal — one bad cluster must not stall the loop.
    pub async fn reconcile_all(&self) -> Vec<(String, Result<Action, ReconcileError>)> {
        let clusters = match self.store.list().await {
            Ok(c) => c,
            Err(e) => return vec![("<list>".into(), Err(e.into()))],
        };
        let mut out = Vec::with_capacity(clusters.len());
        for c in clusters {
            let id = c.id.to_string();
            out.push((id, self.reconcile_one(&c).await));
        }
        out
    }

    async fn reconcile_one(&self, c: &StoredCluster) -> Result<Action, ReconcileError> {
        // 1. Observe: reconstruct actual state (ADR-0006). A NotFound means
        //    nothing is provisioned yet — model that as no observed state.
        let observed = match self.provisioner.observe(&c.id).await {
            Ok(o) => Some(o.state),
            Err(ProvisionError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };

        // 2. Decide and actuate against *observed* reality.
        let action = match c.desired {
            DesiredState::Running => {
                if needs_apply(observed, c.generation, c.observed_generation) {
                    // Fence + outbox: record the intent before the call
                    // (ADR-0007). The provisioner call is idempotent per key
                    // regardless, so a duplicate intent is harmless.
                    let key = c.intent_key();
                    self.store.record_intent(&key).await?;
                    self.provisioner.apply(&c.id, &c.spec, &key).await?;
                    Action::Applied
                } else {
                    Action::NoOp
                }
            }
            DesiredState::Terminated => {
                if observed.is_some_and(|s| s != ClusterState::Terminated) {
                    self.provisioner.terminate(&c.id).await?;
                    Action::Terminated
                } else {
                    Action::NoOp
                }
            }
        };

        // 3. Re-observe and persist status reconstructed from reality, not
        //    from what we intended (ADR-0006).
        let final_state = match self.provisioner.observe(&c.id).await {
            Ok(o) => Some(o.state),
            Err(ProvisionError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };
        self.store
            .record_observation(&c.id, final_state, c.generation)
            .await?;

        Ok(action)
    }
}

/// Apply is needed when nothing is provisioned, when the backing cluster is
/// gone/terminated but we still want it, or when the desired generation is
/// ahead of what we last reconciled (spec changed).
fn needs_apply(observed: Option<ClusterState>, generation: u64, observed_generation: u64) -> bool {
    match observed {
        None => true,
        Some(ClusterState::Terminated) | Some(ClusterState::Terminating) => true,
        Some(_) => generation > observed_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_apply_matrix() {
        // Nothing provisioned yet.
        assert!(needs_apply(None, 1, 0));
        // Gone but wanted.
        assert!(needs_apply(Some(ClusterState::Terminated), 1, 1));
        // Spec changed (generation ahead).
        assert!(needs_apply(Some(ClusterState::Running), 2, 1));
        // Steady state, up to date.
        assert!(!needs_apply(Some(ClusterState::Running), 1, 1));
    }
}
