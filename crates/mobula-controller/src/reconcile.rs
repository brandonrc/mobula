//! Observation-first reconcile engine (ADR-0006, ADR-0007).
//!
//! Level-triggered: every pass reconstructs each cluster's state from the
//! provisioner (never trusts a stored phase), compares it to desired, and
//! actuates the difference through an idempotency-keyed provisioner call.
//! It is safe to run on a fixed resync interval and safe to re-run after a
//! crash — repeating an actuation with the same desired generation is a
//! no-op at the provider.

use std::sync::Arc;
use std::time::Duration;

use mobula_core::{ClusterState, DriftCondition};
use mobula_provision::{ProvisionError, Provisioner};

use crate::store::{
    now_unix, params_fingerprint, DesiredState, IntentOutcome, Store, StoreError, StoredCluster,
};

/// How long an `Applied` outbox row is retained before the run loop reaps it
/// (ADR-0007, #39). Kept well beyond a few resync intervals so crash
/// recovery can still inspect recent intents, but bounded so the table can't
/// grow one row per (cluster, generation) forever.
const INTENT_RETENTION_SECS: u64 = 3600;

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Provision(#[from] ProvisionError),
    /// The outbox already holds this idempotency key with a *different* spec
    /// fingerprint — a stale or conflicting generation write (ADR-0007). We
    /// refuse to actuate rather than apply the wrong spec under an old key.
    #[error("stale/conflicting intent for key {0}: spec fingerprint mismatch")]
    StaleIntent(String),
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
    /// Observed divergence that re-applying can't fix (Degraded, or an
    /// out-of-band spec edit) — raised as an alarm, not silently converged
    /// (ADR-0004, #41/#47). A drift condition is persisted.
    Drift,
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
        //    `observed_generation` is the generation the cluster actually
        //    carries (read back), never the desired one (#40).
        let observed = match self.provisioner.observe(&c.id).await {
            Ok(o) => Some(o),
            Err(ProvisionError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };
        let observed_state = observed.as_ref().map(|o| o.state);
        let observed_gen = observed
            .as_ref()
            .and_then(|o| o.observed_generation)
            .unwrap_or(0);
        let observed_fp = observed.as_ref().and_then(|o| o.spec_fingerprint.clone());

        // Quarantine (ADR-0007 restore fence, #41): while set, observe and
        // record but never actuate — an operator clears it after reviewing a
        // suspected stale DB restore.
        if self.store.is_quarantined().await? {
            tracing::warn!(
                target: "mobula::audit",
                cluster = %c.id, "control plane quarantined: observing only, not actuating"
            );
            self.store
                .record_observation(&c.id, observed_state, observed_gen)
                .await?;
            return Ok(Action::NoOp);
        }

        // 2. Decide and actuate against *observed* reality. Track the
        //    drift/health condition to persist (#41/#47); every branch sets it.
        let new_condition: Option<DriftCondition>;
        let action = match c.desired {
            DesiredState::Running => {
                if matches!(observed_state, Some(ClusterState::Degraded)) {
                    // #47: Degraded is a runtime failure, not spec drift —
                    // re-applying the unchanged spec can't heal it and would
                    // hot-loop. Alarm instead (ADR-0004), leave it Degraded.
                    new_condition = Some(DriftCondition::Degraded);
                    tracing::warn!(
                        target: "mobula::audit",
                        cluster = %c.id, "observed Degraded while desired Running — raising alarm, not re-applying"
                    );
                    Action::Drift
                } else if needs_apply(observed_state, observed_gen, c.generation) {
                    // None/Terminated/Terminating/Suspended(#47)/generation-
                    // behind → (re)apply. Transactional outbox (ADR-0007, #39):
                    // open the intent before the call; a same-params re-open
                    // (`replay`) still actuates (idempotent SSA; drift repair
                    // needs it), a different-params re-use is rejected.
                    new_condition = None;
                    let key = c.intent_key();
                    let fp = params_fingerprint(&c.spec);
                    match self.store.begin_intent(&key, &fp).await? {
                        IntentOutcome::ParamMismatch => {
                            return Err(ReconcileError::StaleIntent(key));
                        }
                        IntentOutcome::Proceed { replay } => {
                            let resp = self
                                .provisioner
                                .apply(&c.id, &c.spec, c.generation, &key)
                                .await?;
                            let resp_json = serde_json::to_string(&resp).unwrap_or_default();
                            self.store.complete_intent(&key, &resp_json).await?;
                            if replay {
                                tracing::debug!(cluster = %c.id, key, "re-applied existing intent (drift/replay)");
                            }
                            Action::Applied
                        }
                    }
                } else {
                    // Live at the desired generation: check for an out-of-band
                    // edit of a Mobula-owned field (#41). The observed
                    // fingerprint is recomputed from the live resource, so a
                    // divergence is real drift — alarm, don't silently NoOp.
                    let desired_fp = mobula_provision::kuberay::owned_spec_fingerprint(&c.spec);
                    if observed_fp.as_deref().is_some_and(|fp| fp != desired_fp) {
                        new_condition = Some(DriftCondition::SpecDrift);
                        tracing::warn!(
                            target: "mobula::audit",
                            cluster = %c.id, "observed spec drift from desired — raising alarm"
                        );
                        Action::Drift
                    } else {
                        new_condition = None;
                        Action::NoOp
                    }
                }
            }
            DesiredState::Terminated => {
                new_condition = None;
                if observed_state.is_some_and(|s| s != ClusterState::Terminated) {
                    self.provisioner.terminate(&c.id).await?;
                    Action::Terminated
                } else {
                    Action::NoOp
                }
            }
        };

        // 3. Re-observe and persist status reconstructed from reality, not
        //    from what we intended (ADR-0006). Record the generation the
        //    cluster reports, so convergence is observed, not self-certified.
        let (final_state, final_gen) = match self.provisioner.observe(&c.id).await {
            Ok(o) => (Some(o.state), o.observed_generation.unwrap_or(0)),
            Err(ProvisionError::NotFound(_)) => (None, 0),
            Err(e) => return Err(e.into()),
        };
        self.store
            .record_observation(&c.id, final_state, final_gen)
            .await?;
        if new_condition != c.condition {
            self.store.set_condition(&c.id, new_condition).await?;
        }

        Ok(action)
    }
}

impl<S: Store, P: Provisioner> Reconciler<S, P> {
    /// TTL reaping: a running cluster with `ttl_seconds` set whose age
    /// exceeds it is flipped to desired=Terminated; the next reconcile
    /// pass tears it down. This is a **max-age** reaper, not idle-based —
    /// idle detection needs job-activity tracking (deferred; documented in
    /// REQUIREMENTS §3.1). Returns the ids reaped.
    pub async fn reap_expired(&self, now: u64) -> Result<Vec<String>, ReconcileError> {
        let clusters = self.store.list().await?;
        let mut reaped = Vec::new();
        for c in clusters {
            if is_expired(&c, now) {
                self.store
                    .set_desired(&c.id, DesiredState::Terminated)
                    .await?;
                tracing::info!(
                    target: "mobula::audit",
                    cluster = %c.id, ttl = c.spec.ttl_seconds, age = now.saturating_sub(c.created_at),
                    "cluster reaped (max-age TTL)"
                );
                reaped.push(c.id.0);
            }
        }
        Ok(reaped)
    }

    /// Boot check for a stale DB restore (ADR-0007 restore quarantine, #41):
    /// if any backing cluster reports a generation *newer* than what the store
    /// holds, the store was restored behind reality — actuating would stomp a
    /// newer cluster with older desired state. Quarantine and alarm instead;
    /// an operator clears it after review. Returns whether it quarantined.
    /// Call this once before spawning [`Reconciler::run`].
    pub async fn detect_stale_restore(&self) -> Result<bool, ReconcileError> {
        let clusters = self.store.list().await?;
        for c in clusters {
            match self.provisioner.observe(&c.id).await {
                Ok(o) => {
                    if o.observed_generation.is_some_and(|g| g > c.generation) {
                        tracing::error!(
                            target: "mobula::audit",
                            cluster = %c.id, stored_generation = c.generation,
                            observed_generation = ?o.observed_generation,
                            "stale DB restore detected (backing cluster is newer than the store) — quarantining"
                        );
                        self.store.set_quarantine(true).await?;
                        return Ok(true);
                    }
                }
                Err(ProvisionError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(false)
    }

    /// Run the control loop until `shutdown` resolves: each tick reaps
    /// expired clusters then reconciles all. Level-triggered with a fixed
    /// resync interval (ADR-0006) — an edge-trigger/watch is only an
    /// optimization we can add later. Errors are logged per pass, never
    /// fatal, so one bad tick doesn't stop the loop.
    pub async fn run(&self, interval: Duration, shutdown: impl std::future::Future<Output = ()>) {
        tracing::info!(interval_secs = interval.as_secs(), "reconcile loop started");
        let mut ticker = tokio::time::interval(interval);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.reap_expired(now_unix()).await {
                        tracing::warn!(error = %e, "reap pass failed");
                    }
                    // Bound outbox growth (ADR-0007, #39): drop Applied
                    // intents older than the retention window.
                    let cutoff = now_unix().saturating_sub(INTENT_RETENTION_SECS);
                    match self.store.reap_intents(cutoff).await {
                        Ok(n) if n > 0 => tracing::debug!(reaped = n, "outbox intents reaped"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "intent reap pass failed"),
                    }
                    for (id, res) in self.reconcile_all().await {
                        if let Err(e) = res {
                            tracing::warn!(cluster = %id, error = %e, "reconcile failed");
                        }
                    }
                }
                _ = &mut shutdown => {
                    tracing::info!("reconcile loop shutting down");
                    return;
                }
            }
        }
    }
}

/// A running cluster is expired when it has a TTL and its age exceeds it.
fn is_expired(c: &StoredCluster, now: u64) -> bool {
    matches!(c.desired, DesiredState::Running)
        && c.observed_state == Some(ClusterState::Running)
        && c.spec
            .ttl_seconds
            .is_some_and(|ttl| now.saturating_sub(c.created_at) >= ttl)
}

/// Apply is needed when nothing is provisioned, when the backing cluster is
/// gone/terminated but we still want it, or when the generation the cluster
/// actually carries (`observed_generation`, read back — #40) is behind the
/// desired one (spec changed and the cluster hasn't picked it up yet).
/// Re-applying an in-flight roll (same generation, still Provisioning) is
/// *not* needed: the cluster already carries the desired generation, so we
/// wait and re-observe rather than churn the provider.
fn needs_apply(
    observed: Option<ClusterState>,
    observed_generation: u64,
    desired_generation: u64,
) -> bool {
    match observed {
        None => true,
        Some(ClusterState::Terminated) | Some(ClusterState::Terminating) => true,
        // #47: a Suspended cluster whose desired state is Running is
        // repairable drift — re-apply resumes it (to_raycluster owns
        // spec.suspend=false, so the force-SSA re-apply clears it).
        Some(ClusterState::Suspended) => true,
        Some(_) => observed_generation < desired_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::DesiredState;
    use mobula_core::{ClusterId, ClusterSpec};

    fn stored(ttl: Option<u64>, created_at: u64, observed: Option<ClusterState>) -> StoredCluster {
        StoredCluster {
            id: ClusterId("c".into()),
            spec: ClusterSpec {
                name: "c".into(),
                project: "p".into(),
                ray_version: "2.57.0".into(),
                image: "img".into(),
                head_cpu: "1".into(),
                head_memory: "2Gi".into(),
                worker_groups: vec![],
                ttl_seconds: ttl,
            },
            generation: 1,
            desired: DesiredState::Running,
            observed_state: observed,
            observed_generation: 1,
            condition: None,
            created_at,
        }
    }

    #[test]
    fn is_expired_matrix() {
        // Running past TTL → expired.
        assert!(is_expired(
            &stored(Some(60), 100, Some(ClusterState::Running)),
            200
        ));
        // Within TTL → not.
        assert!(!is_expired(
            &stored(Some(60), 100, Some(ClusterState::Running)),
            130
        ));
        // No TTL → never.
        assert!(!is_expired(
            &stored(None, 0, Some(ClusterState::Running)),
            999_999
        ));
        // Not observed Running yet → don't reap mid-provision.
        assert!(!is_expired(
            &stored(Some(1), 0, Some(ClusterState::Provisioning)),
            999
        ));
    }

    #[test]
    fn needs_apply_matrix() {
        // Args are (observed_state, observed_generation, desired_generation).
        // Nothing provisioned yet.
        assert!(needs_apply(None, 0, 1));
        // Gone but wanted.
        assert!(needs_apply(Some(ClusterState::Terminated), 1, 1));
        // Cluster carries an older generation than desired (spec changed,
        // not yet picked up).
        assert!(needs_apply(Some(ClusterState::Running), 1, 2));
        // Steady state, cluster carries the desired generation.
        assert!(!needs_apply(Some(ClusterState::Running), 1, 1));
        // Mid-roll at the desired generation → wait, don't re-apply/churn.
        assert!(!needs_apply(Some(ClusterState::Provisioning), 2, 2));
        // #47: Suspended with desired Running is repairable → re-apply.
        assert!(needs_apply(Some(ClusterState::Suspended), 1, 1));
    }
}
