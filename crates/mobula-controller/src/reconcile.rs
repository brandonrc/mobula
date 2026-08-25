//! Observation-first reconcile engine (ADR-0006, ADR-0007).
//!
//! Level-triggered: every pass reconstructs each cluster's state from the
//! provisioner (never trusts a stored phase), compares it to desired, and
//! actuates the difference through an idempotency-keyed provisioner call.
//! It is safe to run on a fixed resync interval and safe to re-run after a
//! crash — repeating an actuation with the same desired generation is a
//! no-op at the provider.
//!
//! ## Lifecycle reaping (#100)
//!
//! [`Reconciler::reap_expired`] enforces two independent lifecycle bounds on a
//! running cluster:
//!
//! * **max-age** (`ttl_seconds`) — reaped this long after creation regardless
//!   of activity (the absolute cap); and
//! * **activity-idle** (`idle_timeout_secs`) — reaped once it has been idle for
//!   the window, so a *busy* cluster survives past it while an unused one is
//!   released. This exists because a pure max-age TTL kills a cluster mid-use.
//!
//! **Activity signal.** Idleness is derived from the persisted job history
//! (`Store::list_jobs`): a cluster with a running/pending job is busy now, and
//! a finished job counts as activity through its end time; creation is the
//! floor. This is the cheapest robust signal already in the store — the
//! reconcile `observe` path carries no live resource usage, and polling each
//! cluster's Ray dashboard/metrics every sweep would add provider load and
//! break when the dashboard is down, so it was deliberately not used here.
//!
//! **Limitation — interactive sessions.** Interactive Ray Client / Dask
//! sessions submit no *gateway* jobs, so job history is empty for them and
//! their derived activity never advances past creation. An interactive-only
//! cluster therefore looks idle from birth: `idle_timeout_secs` would reap it
//! even while actively used. For such sessions leave `idle_timeout_secs` unset
//! (max-age-only, the prior behavior) or rely on `ttl_seconds`. A robust
//! interactive-idle signal (live utilization / active client connections from
//! the engine) is future work.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mobula_core::{ClusterState, DriftCondition, Engine, JobRecord};
use mobula_provision::{ProvisionError, Provisioner};

use crate::store::{
    now_unix, params_fingerprint, queue_assignment_for_project, DesiredState, IntentOutcome, Store,
    StoreError, StoredCluster,
};

/// How long an `Applied` outbox row is retained before the run loop reaps it
/// (ADR-0007, #39). Kept well beyond a few resync intervals so crash
/// recovery can still inspect recent intents, but bounded so the table can't
/// grow one row per (cluster, generation) forever.
const INTENT_RETENTION_SECS: u64 = 3600;

/// Default window a terminated cluster's tombstone row is retained before the
/// run loop hard-deletes it (Truthful Console). Generous by design: an
/// operator and the dashboard have a full day to see that a cluster died
/// before its row disappears from `GET /api/v1/clusters`.
pub const TERMINATED_RETENTION_SECS: u64 = 24 * 3600;

/// Exponential-backoff base and ceiling for a no-progress cluster (#43).
const BACKOFF_BASE_SECS: u64 = 5;
const BACKOFF_CEIL_SECS: u64 = 300;

/// Delay before re-actuating a cluster that has made no progress for
/// `failure_count` consecutive attempts (#43): `base * 2^(n-1)`, capped.
fn backoff_secs(failure_count: u32) -> u64 {
    let shift = failure_count.saturating_sub(1).min(20);
    BACKOFF_BASE_SECS
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_CEIL_SECS)
}

/// Global actuation rate limit across all clusters (ADR-0006 token bucket,
/// #43): a burst of failing clusters can't exceed the provider-call budget.
#[derive(Debug, Clone, Copy)]
pub struct RateLimits {
    /// Maximum actuations available in a burst.
    pub capacity: f64,
    /// Tokens replenished per second.
    pub refill_per_sec: f64,
}

/// Time-based token bucket keyed on the reconcile `now` (unix secs), so it is
/// deterministic in tests. Only *actuating* passes (apply) take a token.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: u64,
}

impl TokenBucket {
    fn new(limits: RateLimits, now: u64) -> Self {
        Self {
            tokens: limits.capacity,
            capacity: limits.capacity,
            refill_per_sec: limits.refill_per_sec,
            last: now,
        }
    }

    fn try_take(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last) as f64;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

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
    /// Suspended the cluster (#51): compute released, spec and store state
    /// kept. Actuated through the provisioner's `suspend` call, not the
    /// generation-keyed apply path.
    Suspended,
    /// Observed divergence that re-applying can't fix (Degraded, or an
    /// out-of-band spec edit) — raised as an alarm, not silently converged
    /// (ADR-0004, #41/#47). A drift condition is persisted.
    Drift,
    /// Skipped actuation this pass: the cluster is inside its backoff window
    /// or the global rate-limit budget is exhausted (#43). Retried next tick.
    Backoff,
}

pub struct Reconciler<S, P> {
    store: Arc<S>,
    provisioner: Arc<P>,
    /// Global actuation token bucket (#43); `None` = unlimited.
    limits: Option<Mutex<TokenBucket>>,
    /// How long a terminated cluster's tombstone row is retained before the
    /// run loop hard-deletes it (Truthful Console).
    terminated_retention_secs: u64,
}

impl<S: Store, P: Provisioner> Reconciler<S, P> {
    /// Unlimited (no global rate cap). Per-cluster backoff still applies.
    pub fn new(store: Arc<S>, provisioner: Arc<P>) -> Self {
        Self {
            store,
            provisioner,
            limits: None,
            terminated_retention_secs: TERMINATED_RETENTION_SECS,
        }
    }

    /// With a global actuation rate limit (#43).
    pub fn with_limits(store: Arc<S>, provisioner: Arc<P>, limits: RateLimits) -> Self {
        Self {
            store,
            provisioner,
            limits: Some(Mutex::new(TokenBucket::new(limits, 0))),
            terminated_retention_secs: TERMINATED_RETENTION_SECS,
        }
    }

    /// Override the terminated-tombstone retention window (Truthful Console).
    /// Default is [`TERMINATED_RETENTION_SECS`].
    pub fn with_terminated_retention(mut self, secs: u64) -> Self {
        self.terminated_retention_secs = secs;
        self
    }

    /// Take one actuation token, or `true` when unlimited. `false` means the
    /// budget is exhausted this pass — skip actuating (retry next tick).
    fn take_token(&self, now: u64) -> bool {
        match &self.limits {
            None => true,
            Some(b) => b.lock().unwrap().try_take(now),
        }
    }

    /// Reconcile every known cluster once at the current wall-clock time.
    pub async fn reconcile_all(&self) -> Vec<(String, Result<Action, ReconcileError>)> {
        self.reconcile_all_at(now_unix()).await
    }

    /// Reconcile every known cluster once at time `now` (unix secs). `now` is
    /// injected so backoff/rate-limit decisions (#43) are deterministic in
    /// tests. Errors on individual clusters are collected, not fatal — one
    /// bad cluster must not stall the loop.
    pub async fn reconcile_all_at(
        &self,
        now: u64,
    ) -> Vec<(String, Result<Action, ReconcileError>)> {
        let clusters = match self.store.list().await {
            Ok(c) => c,
            Err(e) => return vec![("<list>".into(), Err(e.into()))],
        };
        let mut out = Vec::with_capacity(clusters.len());
        for c in clusters {
            let id = c.id.to_string();
            out.push((id, self.reconcile_one(&c, now).await));
        }
        out
    }

    async fn reconcile_one(&self, c: &StoredCluster, now: u64) -> Result<Action, ReconcileError> {
        // Backoff gate (#43): a Running-desired cluster that has made no
        // progress is left untouched — not even observed — until its
        // next-attempt time, so a permanently-failing cluster can't hammer
        // the provider every tick.
        if matches!(c.desired, DesiredState::Running) && now < c.next_attempt_at {
            return Ok(Action::Backoff);
        }

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
        //
        // Resolve the Kueue queue assignment for the cluster's project
        // (ADR-0010) from the store — the store is the transport between
        // create_cluster's allocation lookup and actuation, so ClusterSpec's
        // serialized form stays free of it. A queued cluster's `suspend` is
        // owned by Kueue, so for queued clusters Suspended is admission
        // queueing, not repairable drift (see needs_apply).
        let queue = queue_assignment_for_project(self.store.as_ref(), &c.spec.project).await?;
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
                } else if needs_apply(observed_state, observed_gen, c.generation, queue.is_some()) {
                    // Global actuation budget (#43): if the token bucket is
                    // empty, defer this cluster to a later tick rather than
                    // exceed the provider-call rate. NoOp/observe passes don't
                    // take a token, so only real actuation is capped.
                    if !self.take_token(now) {
                        return Ok(Action::Backoff);
                    }
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
                            // #56/#62: namespace security posture (default-
                            // deny NetworkPolicy + PSS labels) is per-
                            // namespace, not per-cluster — ensure it with
                            // each actuating apply. Fail-closed: a posture
                            // error blocks the cluster apply.
                            self.provisioner.ensure_namespace_posture().await?;
                            let resp = self
                                .provisioner
                                .apply(&c.id, &c.spec, c.generation, &key, queue.as_ref())
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
                    // Engine-neutral drift check: each engine projects its own
                    // owned-field fingerprint, symmetric with what its
                    // provisioner reads back in `observe`.
                    let desired_fp = match c.spec.engine {
                        Engine::Ray => mobula_provision::kuberay::owned_spec_fingerprint(&c.spec),
                        Engine::Dask => mobula_provision::dask::owned_spec_fingerprint(&c.spec),
                    };
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
            DesiredState::Suspended => {
                // #51: drive the backing cluster to spec.suspend=true. The
                // actuation is a level-triggered, idempotent provisioner call
                // like terminate above — deliberately NOT the generation-keyed
                // apply path: suspension changes no spec field, and the outbox
                // key `{id}/{generation}` must always map to the same
                // actuation parameters (ADR-0007). Resume is the reverse: the
                // API flips desired back to Running and the Running arm's
                // apply (which writes suspend:false) converges it.
                new_condition = None;
                if queue.is_some() {
                    // Kueue owns spec.suspend for queue-assigned clusters
                    // (ADR-0010); the API rejects user suspend/resume there,
                    // so this combination should never occur — if it does,
                    // never fight the queue.
                    Action::NoOp
                } else if observed_state.is_some_and(|s| {
                    !matches!(
                        s,
                        ClusterState::Suspended
                            | ClusterState::Terminated
                            | ClusterState::Terminating
                    )
                }) {
                    self.provisioner.suspend(&c.id).await?;
                    Action::Suspended
                } else {
                    // Already suspended, or nothing/gone — nothing to suspend.
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

        // 4. Backoff accounting (#43): after actuating a Running cluster, did
        //    it make progress? A cluster observed back at None/Terminated/
        //    Terminating after an apply is not coming up → bump the failure
        //    count and push out next_attempt_at. Progress (or a converged
        //    NoOp) clears the backoff.
        let progressed: Option<bool> = match action {
            Action::Applied => Some(!matches!(
                final_state,
                None | Some(ClusterState::Terminated) | Some(ClusterState::Terminating)
            )),
            Action::NoOp if matches!(c.desired, DesiredState::Running) => Some(true),
            _ => None,
        };
        match progressed {
            Some(false) => {
                let failure_count = c.failure_count.saturating_add(1);
                let next_attempt_at = now.saturating_add(backoff_secs(failure_count));
                self.store
                    .record_attempt(&c.id, failure_count, next_attempt_at)
                    .await?;
                tracing::warn!(
                    target: "mobula::audit",
                    cluster = %c.id, failure_count, retry_in_secs = backoff_secs(failure_count),
                    "cluster made no progress — backing off"
                );
            }
            // Progress after a prior failure: clear the backoff.
            Some(true) if c.failure_count != 0 || c.next_attempt_at != 0 => {
                self.store.record_attempt(&c.id, 0, 0).await?;
            }
            _ => {}
        }

        Ok(action)
    }
}

impl<S: Store, P: Provisioner> Reconciler<S, P> {
    /// Lifecycle reaping (#100): a running cluster is flipped to
    /// desired=Terminated — and torn down by the next reconcile pass — when
    /// either lifecycle bound fires:
    ///
    /// * **max-age** — its age exceeds `ttl_seconds` (the absolute cap, reaped
    ///   regardless of activity); or
    /// * **activity-idle** — it has been idle (no job activity) for longer than
    ///   `idle_timeout_secs`, so a busy cluster survives past the window while a
    ///   genuinely unused one is released.
    ///
    /// Max-age is checked first, so a cluster that is *both* over its age cap
    /// and idle is attributed to max-age. Each reap logs a `mobula::audit`
    /// event whose `reason` field (`max_age` / `idle`) distinguishes the two.
    /// Returns the ids reaped.
    ///
    /// The activity signal is the persisted job history (see the [module
    /// docs](self)): the reap fetches it once per pass and buckets it by
    /// cluster rather than querying per cluster.
    pub async fn reap_expired(&self, now: u64) -> Result<Vec<String>, ReconcileError> {
        let clusters = self.store.list().await?;
        // Activity signal: bucket the job history by cluster id once per pass.
        let jobs = self.store.list_jobs().await?;
        let mut jobs_by_cluster: std::collections::HashMap<&str, Vec<&JobRecord>> =
            std::collections::HashMap::new();
        for j in &jobs {
            jobs_by_cluster
                .entry(j.cluster.as_str())
                .or_default()
                .push(j);
        }
        let no_jobs: Vec<&JobRecord> = Vec::new();
        let mut reaped = Vec::new();
        for c in &clusters {
            let cjobs = jobs_by_cluster.get(c.id.0.as_str()).unwrap_or(&no_jobs);
            let last_activity = last_activity_at(c.created_at, cjobs, now);
            // Max-age is the absolute cap and takes precedence in attribution.
            let reason = if is_expired(c, now) {
                Some(ReapReason::MaxAge)
            } else if is_idle_expired(c, last_activity, now) {
                Some(ReapReason::Idle)
            } else {
                None
            };
            let Some(reason) = reason else { continue };
            self.store
                .set_desired(&c.id, DesiredState::Terminated)
                .await?;
            match reason {
                ReapReason::MaxAge => tracing::info!(
                    target: "mobula::audit",
                    cluster = %c.id, reason = "max_age",
                    ttl = c.spec.ttl_seconds, age = now.saturating_sub(c.created_at),
                    "cluster reaped (max-age TTL)"
                ),
                ReapReason::Idle => tracing::info!(
                    target: "mobula::audit",
                    cluster = %c.id, reason = "idle",
                    idle_timeout = c.spec.idle_timeout_secs,
                    idle_for = now.saturating_sub(last_activity),
                    "cluster reaped (activity-idle)"
                ),
            }
            reaped.push(c.id.0.clone());
        }
        Ok(reaped)
    }

    /// Tombstone retention sweep (Truthful Console): hard-delete cluster rows
    /// that have been desired=Terminated and observed gone for longer than the
    /// retention window, so a reaped cluster stops lingering forever in
    /// `GET /api/v1/clusters`. A row still tearing down (observed_state still a
    /// live state) is left alone — only a genuinely dead tombstone is removed.
    /// Returns the ids removed.
    pub async fn reap_terminated(&self, now: u64) -> Result<Vec<String>, ReconcileError> {
        let clusters = self.store.list().await?;
        let mut removed = Vec::new();
        for c in clusters {
            if !is_purgeable_tombstone(&c, now, self.terminated_retention_secs) {
                continue;
            }
            // #122: reap any per-cluster NetworkPolicy that outlived the CR
            // before dropping the row. `terminate` deletes it on the happy
            // path (cluster still observed up when we tore it down); this is
            // the backstop for a netpol whose CR vanished before `terminate`
            // fired — the reconciler's Terminated arm then never actuated, so
            // the policy would otherwise accumulate. Idempotent (already-gone
            // = ok). If it errors, leave the row so the next pass retries
            // rather than purging the last record that this netpol is owed a
            // reap.
            if let Err(e) = self.provisioner.reap_network_policies(&c.id).await {
                tracing::warn!(
                    target: "mobula::audit",
                    cluster = %c.id, error = %e,
                    "failed to reap per-cluster NetworkPolicy on tombstone purge; deferring row removal"
                );
                continue;
            }
            if self.store.remove_cluster(&c.id).await? {
                tracing::info!(
                    target: "mobula::audit",
                    cluster = %c.id,
                    age = c.terminated_at.map(|t| now.saturating_sub(t)),
                    "terminated cluster row reaped (retention window elapsed)"
                );
                removed.push(c.id.0);
            }
        }
        Ok(removed)
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
                    // Truthful Console: drop terminated tombstone rows older
                    // than the retention window.
                    match self.reap_terminated(now_unix()).await {
                        Ok(ids) if !ids.is_empty() => {
                            tracing::info!(reaped = ids.len(), "terminated cluster rows reaped")
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "terminated-row reap pass failed"),
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

/// Whether a cluster's backing resource is gone (or was never observed), so
/// the row is safe to treat as a dead tombstone rather than a live cluster
/// (Truthful Console). Shared by the retention sweep and the API purge guard.
pub fn observed_gone(observed: Option<ClusterState>) -> bool {
    matches!(observed, None | Some(ClusterState::Terminated))
}

/// A terminated cluster row is a purgeable tombstone once it is
/// desired=Terminated, observed gone, and its `terminated_at` stamp is older
/// than the retention window.
fn is_purgeable_tombstone(c: &StoredCluster, now: u64, retention_secs: u64) -> bool {
    matches!(c.desired, DesiredState::Terminated)
        && observed_gone(c.observed_state)
        && c.terminated_at
            .is_some_and(|t| now.saturating_sub(t) >= retention_secs)
}

/// Why a cluster was reaped (#100), so the audit log distinguishes the two
/// lifecycle bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapReason {
    /// Absolute age exceeded `ttl_seconds`.
    MaxAge,
    /// Idle (no job activity) for longer than `idle_timeout_secs`.
    Idle,
}

/// A running cluster is expired when it has a max-age TTL and its age exceeds
/// it (the absolute cap — reaped regardless of activity).
fn is_expired(c: &StoredCluster, now: u64) -> bool {
    matches!(c.desired, DesiredState::Running)
        && c.observed_state == Some(ClusterState::Running)
        && c.spec
            .ttl_seconds
            .is_some_and(|ttl| now.saturating_sub(c.created_at) >= ttl)
}

/// Ray job statuses that mean the job is finished. Compared case-insensitively
/// and kept as a set here rather than in the wire type so a Ray status rename
/// degrades to "treat as still-active" (fail-safe: an unknown status keeps the
/// cluster alive) rather than mis-reaping.
fn job_is_terminal(status: &str) -> bool {
    matches!(
        status.to_ascii_uppercase().as_str(),
        "SUCCEEDED" | "FAILED" | "STOPPED"
    )
}

/// The cluster's last-activity unix time, derived from its job history.
///
/// `created_at` is the floor: a freshly created cluster that has run no jobs is
/// "active as of creation", so its idle window starts at birth (never epoch).
/// A **non-terminal** (PENDING/RUNNING) job means the cluster is busy *right
/// now*, so this returns `now` — such a cluster is never idle. Otherwise each
/// finished job counts as activity through its end (`submitted_at +
/// duration_secs`, falling back to `submitted_at` when the duration is
/// unknown), and the latest such end wins.
///
/// `jobs` must already be filtered to this cluster's records.
fn last_activity_at(created_at: u64, jobs: &[&JobRecord], now: u64) -> u64 {
    let mut last = created_at;
    for j in jobs {
        if !job_is_terminal(&j.status) {
            // Busy now — cannot be idle regardless of the other jobs' ages.
            return now;
        }
        let end = j.submitted_at.saturating_add(j.duration_secs.unwrap_or(0));
        last = last.max(end);
    }
    last
}

/// A running cluster is idle-expired when it has an `idle_timeout_secs` window
/// and its time since last activity exceeds it (#100). Independent of the
/// max-age cap; whichever bound fires first reaps the cluster.
fn is_idle_expired(c: &StoredCluster, last_activity: u64, now: u64) -> bool {
    matches!(c.desired, DesiredState::Running)
        && c.observed_state == Some(ClusterState::Running)
        && c.spec
            .idle_timeout_secs
            .is_some_and(|idle| now.saturating_sub(last_activity) >= idle)
}

/// Apply is needed when nothing is provisioned, when the backing cluster is
/// gone/terminated but we still want it, or when the generation the cluster
/// actually carries (`observed_generation`, read back — #40) is behind the
/// desired one (spec changed and the cluster hasn't picked it up yet).
/// Re-applying an in-flight roll (same generation, still Provisioning) is
/// *not* needed: the cluster already carries the desired generation, so we
/// wait and re-observe rather than churn the provider.
///
/// `queued` (the cluster has a Kueue queue assignment, ADR-0010) changes one
/// case: Suspended is then Kueue holding an unadmitted workload pod-less
/// (research doc §2 — Kueue owns `spec.suspend` for queued clusters), so
/// re-applying would fight the queue. Leave it; admission unsuspends it.
/// For queue-free clusters Suspended stays repairable drift (#47).
fn needs_apply(
    observed: Option<ClusterState>,
    observed_generation: u64,
    desired_generation: u64,
    queued: bool,
) -> bool {
    match observed {
        None => true,
        Some(ClusterState::Terminated) | Some(ClusterState::Terminating) => true,
        // #47: a Suspended cluster whose desired state is Running is
        // repairable drift — re-apply resumes it (to_raycluster owns
        // spec.suspend=false, so the force-SSA re-apply clears it). Not so
        // for queued clusters: Kueue legitimately holds them Suspended.
        Some(ClusterState::Suspended) => !queued,
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
                engine: Default::default(),
                name: "c".into(),
                project: "p".into(),
                ray_version: "2.57.0".into(),
                image: "img".into(),
                head_cpu: "1".into(),
                head_memory: "2Gi".into(),
                worker_groups: vec![],
                ttl_seconds: ttl,
                idle_timeout_secs: None,
                owner: None,
            },
            generation: 1,
            desired: DesiredState::Running,
            observed_state: observed,
            observed_generation: 1,
            condition: None,
            failure_count: 0,
            next_attempt_at: 0,
            created_at,
            terminated_at: None,
        }
    }

    /// [`stored`] with an idle-reap window set (#100).
    fn stored_idle(
        idle: Option<u64>,
        created_at: u64,
        observed: Option<ClusterState>,
    ) -> StoredCluster {
        let mut c = stored(None, created_at, observed);
        c.spec.idle_timeout_secs = idle;
        c
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

    fn job(cluster: &str, status: &str, submitted_at: u64, duration: Option<u64>) -> JobRecord {
        JobRecord {
            id: format!("{cluster}-{submitted_at}"),
            cluster: cluster.into(),
            submitter: "-".into(),
            status: status.into(),
            duration_secs: duration,
            submitted_at,
        }
    }

    #[test]
    fn last_activity_derives_from_job_history() {
        // No jobs → creation is the floor.
        assert_eq!(last_activity_at(100, &[], 999), 100);
        // A finished job's end (submitted + duration) beats creation.
        let done = job("c", "SUCCEEDED", 200, Some(50));
        assert_eq!(last_activity_at(100, &[&done], 999), 250);
        // Terminal without a duration counts at submission time.
        let done_nodur = job("c", "FAILED", 300, None);
        assert_eq!(last_activity_at(100, &[&done_nodur], 999), 300);
        // The latest finished job wins.
        let older = job("c", "STOPPED", 150, Some(10));
        assert_eq!(last_activity_at(100, &[&older, &done], 999), 250);
        // A still-running job → busy *now*, regardless of other jobs' ages.
        let running = job("c", "RUNNING", 120, None);
        assert_eq!(last_activity_at(100, &[&older, &running], 999), 999);
        // An unknown status is treated as still-active (fail-safe: keep alive).
        let weird = job("c", "SOME_NEW_STATE", 120, None);
        assert_eq!(last_activity_at(100, &[&weird], 999), 999);
        // Status matching is case-insensitive.
        assert!(job_is_terminal("succeeded") && job_is_terminal("Failed"));
        assert!(!job_is_terminal("running"));
    }

    #[test]
    fn is_idle_expired_matrix() {
        // Idle window elapsed since last activity → idle-expired.
        assert!(is_idle_expired(
            &stored_idle(Some(60), 0, Some(ClusterState::Running)),
            100, // last activity
            200, // now: 100s idle >= 60
        ));
        // Within the idle window → not.
        assert!(!is_idle_expired(
            &stored_idle(Some(60), 0, Some(ClusterState::Running)),
            100,
            130, // 30s idle < 60
        ));
        // No idle window set → never (keeps old max-age-only behavior).
        assert!(!is_idle_expired(
            &stored_idle(None, 0, Some(ClusterState::Running)),
            0,
            999_999,
        ));
        // Not observed Running yet → don't idle-reap mid-provision.
        assert!(!is_idle_expired(
            &stored_idle(Some(1), 0, Some(ClusterState::Provisioning)),
            0,
            999,
        ));
    }

    #[tokio::test]
    async fn reap_idles_unused_but_spares_busy_clusters() {
        use crate::store::memory::InMemoryStore;
        let store = Arc::new(InMemoryStore::new());

        // The store stamps `created_at` to wall-clock `now_unix()` on insert,
        // so anchor the test's `now` far ahead of it (like reap_terminated's
        // test) and set job times relative to that.
        let base = now_unix();
        let now = base + 10_000;

        // Helper: insert a cluster observed Running with an idle window.
        async fn insert_idle(store: &InMemoryStore, id: &str, idle: u64) {
            let mut spec = stored(None, 0, None).spec;
            spec.idle_timeout_secs = Some(idle);
            let cid = ClusterId(id.into());
            store.upsert_desired(&cid, spec).await.unwrap();
            store
                .record_observation(&cid, Some(ClusterState::Running), 1)
                .await
                .unwrap();
        }

        // `idle`: no jobs at all → idle since creation (~10_000s ago) → reaped.
        insert_idle(&store, "idle", 60).await;
        // `busy`: a currently-running job → active now → spared.
        insert_idle(&store, "busy", 60).await;
        store
            .record_job(job("busy", "RUNNING", base, None))
            .await
            .unwrap();
        // `recent`: a job that finished 10s ago → within the window → spared.
        insert_idle(&store, "recent", 60).await;
        store
            .record_job(job("recent", "SUCCEEDED", now - 10, Some(0)))
            .await
            .unwrap();
        // `stale`: a job that finished ~10_000s ago → past the window → reaped.
        insert_idle(&store, "stale", 60).await;
        store
            .record_job(job("stale", "SUCCEEDED", base, Some(5)))
            .await
            .unwrap();

        let rec = Reconciler::new(store.clone(), Arc::new(ErrProv));
        let mut reaped = rec.reap_expired(now).await.unwrap();
        reaped.sort();
        assert_eq!(reaped, vec!["idle".to_string(), "stale".to_string()]);

        // Reaped clusters were flipped to Terminated; spared ones stay Running.
        for (id, want) in [
            ("idle", DesiredState::Terminated),
            ("stale", DesiredState::Terminated),
            ("busy", DesiredState::Running),
            ("recent", DesiredState::Running),
        ] {
            let c = store.get(&ClusterId(id.into())).await.unwrap().unwrap();
            assert_eq!(c.desired, want, "cluster {id}");
        }
    }

    #[tokio::test]
    async fn max_age_caps_a_busy_cluster_and_idle_unset_keeps_old_behavior() {
        use crate::store::memory::InMemoryStore;
        let store = Arc::new(InMemoryStore::new());
        let base = now_unix();
        let now = base + 10_000;

        // `capped`: over its max-age ttl AND actively running a job — max-age is
        // the absolute cap, so it is reaped anyway. Its idle window (large) has
        // NOT elapsed, proving the reap is attributed to max-age, not idle.
        let mut capped_spec = stored(Some(60), 0, None).spec;
        capped_spec.idle_timeout_secs = Some(1_000_000); // idle window not hit
        let capped = ClusterId("capped".into());
        store.upsert_desired(&capped, capped_spec).await.unwrap();
        store
            .record_observation(&capped, Some(ClusterState::Running), 1)
            .await
            .unwrap();
        store
            .record_job(job("capped", "RUNNING", base, None))
            .await
            .unwrap();

        // `plain`: neither ttl nor idle set → never reaped (old behavior for a
        // cluster with no lifecycle bounds).
        let plain = ClusterId("plain".into());
        store
            .upsert_desired(&plain, stored(None, 0, None).spec)
            .await
            .unwrap();
        store
            .record_observation(&plain, Some(ClusterState::Running), 1)
            .await
            .unwrap();

        let rec = Reconciler::new(store.clone(), Arc::new(ErrProv));
        let reaped = rec.reap_expired(now).await.unwrap();
        assert_eq!(reaped, vec!["capped".to_string()]);
        assert_eq!(
            store.get(&plain).await.unwrap().unwrap().desired,
            DesiredState::Running,
        );
    }

    #[test]
    fn needs_apply_matrix() {
        // Args are (observed_state, observed_generation, desired_generation,
        // queued).
        // Nothing provisioned yet.
        assert!(needs_apply(None, 0, 1, false));
        // Gone but wanted.
        assert!(needs_apply(Some(ClusterState::Terminated), 1, 1, false));
        // Cluster carries an older generation than desired (spec changed,
        // not yet picked up).
        assert!(needs_apply(Some(ClusterState::Running), 1, 2, false));
        // Steady state, cluster carries the desired generation.
        assert!(!needs_apply(Some(ClusterState::Running), 1, 1, false));
        // Mid-roll at the desired generation → wait, don't re-apply/churn.
        assert!(!needs_apply(Some(ClusterState::Provisioning), 2, 2, false));
        // #47: Suspended with desired Running is repairable → re-apply.
        assert!(needs_apply(Some(ClusterState::Suspended), 1, 1, false));
        // ADR-0010: a QUEUED cluster's Suspended is Kueue admission
        // queueing, not drift — re-applying would fight Kueue's suspend.
        assert!(!needs_apply(Some(ClusterState::Suspended), 1, 1, true));
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        assert_eq!(backoff_secs(1), 5);
        assert_eq!(backoff_secs(2), 10);
        assert_eq!(backoff_secs(3), 20);
        // Capped at the ceiling…
        assert_eq!(backoff_secs(10), 300);
        // …and a saturated failure_count can't overflow the shift.
        assert_eq!(backoff_secs(u32::MAX), 300);
    }

    fn spec() -> ClusterSpec {
        ClusterSpec {
            name: "c".into(),
            project: "p".into(),
            engine: Default::default(),
            ray_version: "2.57.0".into(),
            image: "img".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: vec![],
            ttl_seconds: None,
            idle_timeout_secs: None,
            owner: None,
        }
    }

    fn tombstone(observed: Option<ClusterState>, terminated_at: Option<u64>) -> StoredCluster {
        let mut c = stored(None, 0, observed);
        c.desired = DesiredState::Terminated;
        c.terminated_at = terminated_at;
        c
    }

    #[test]
    fn purgeable_tombstone_matrix() {
        let retention = 3600;
        // Terminated, never observed, old enough → purgeable.
        assert!(is_purgeable_tombstone(
            &tombstone(None, Some(0)),
            4000,
            retention
        ));
        // Terminated, observed Terminated, old enough → purgeable.
        assert!(is_purgeable_tombstone(
            &tombstone(Some(ClusterState::Terminated), Some(0)),
            4000,
            retention
        ));
        // Too recent → not yet.
        assert!(!is_purgeable_tombstone(
            &tombstone(None, Some(1000)),
            2000,
            retention
        ));
        // Still observed live (teardown in flight) → never, even if old.
        assert!(!is_purgeable_tombstone(
            &tombstone(Some(ClusterState::Running), Some(0)),
            999_999,
            retention
        ));
        // No terminated_at stamp → never.
        assert!(!is_purgeable_tombstone(
            &tombstone(None, None),
            999_999,
            retention
        ));
        // Not terminated (desired Running) → never.
        assert!(!is_purgeable_tombstone(
            &stored(None, 0, None),
            999_999,
            retention
        ));
    }

    #[tokio::test]
    async fn reap_terminated_removes_only_dead_tombstones() {
        use crate::store::memory::InMemoryStore;
        let store = Arc::new(InMemoryStore::new());

        // A dead tombstone: terminated and never observed (gone).
        let dead = ClusterId("dead".into());
        store.upsert_desired(&dead, spec()).await.unwrap();
        store
            .set_desired(&dead, DesiredState::Terminated)
            .await
            .unwrap();

        // Terminated but still observed Running (teardown in flight): keep.
        let live = ClusterId("live".into());
        store.upsert_desired(&live, spec()).await.unwrap();
        store
            .set_desired(&live, DesiredState::Terminated)
            .await
            .unwrap();
        store
            .record_observation(&live, Some(ClusterState::Running), 1)
            .await
            .unwrap();

        // A running cluster (not a tombstone): keep.
        let run = ClusterId("run".into());
        store.upsert_desired(&run, spec()).await.unwrap();

        let recon = Reconciler::new(store.clone(), Arc::new(ErrProv)).with_terminated_retention(0);
        // `now` in the future so age (now - terminated_at) clears the (zero)
        // retention window.
        let mut reaped = recon.reap_terminated(now_unix() + 10).await.unwrap();
        reaped.sort();
        assert_eq!(reaped, vec!["dead".to_string()]);
        assert!(store.get(&dead).await.unwrap().is_none());
        assert!(store.get(&live).await.unwrap().is_some());
        assert!(store.get(&run).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn set_desired_stamps_and_clears_terminated_at() {
        use crate::store::memory::InMemoryStore;
        let store = InMemoryStore::new();
        let id = ClusterId("c".into());
        store.upsert_desired(&id, spec()).await.unwrap();
        assert_eq!(store.get(&id).await.unwrap().unwrap().terminated_at, None);
        // Terminate → stamped.
        store
            .set_desired(&id, DesiredState::Terminated)
            .await
            .unwrap();
        assert!(store
            .get(&id)
            .await
            .unwrap()
            .unwrap()
            .terminated_at
            .is_some());
        // Resume → cleared (a resumed cluster is never a tombstone).
        store.set_desired(&id, DesiredState::Running).await.unwrap();
        assert_eq!(store.get(&id).await.unwrap().unwrap().terminated_at, None);
    }

    /// A provisioner whose `observe` always fails with a backend error.
    struct ErrProv;

    #[async_trait::async_trait]
    impl Provisioner for ErrProv {
        async fn apply(
            &self,
            _id: &ClusterId,
            _spec: &ClusterSpec,
            generation: u64,
            _key: &str,
            _queue: Option<&mobula_provision::QueueAssignment>,
        ) -> Result<mobula_provision::ApplyResponse, ProvisionError> {
            Ok(mobula_provision::ApplyResponse {
                generation,
                api_base_url: None,
            })
        }
        async fn terminate(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn suspend(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn resume(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn observe(
            &self,
            _id: &ClusterId,
        ) -> Result<mobula_provision::ObservedCluster, ProvisionError> {
            Err(ProvisionError::Backend("injected observe failure".into()))
        }
        async fn list(&self) -> Result<Vec<mobula_provision::ObservedCluster>, ProvisionError> {
            Ok(vec![])
        }
    }

    /// A provisioner that reports a converged cluster on the first observe of
    /// each reconcile pass, then NotFound on the re-observe (the cluster
    /// vanished mid-pass).
    struct VanishingProv {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Provisioner for VanishingProv {
        async fn apply(
            &self,
            _id: &ClusterId,
            _spec: &ClusterSpec,
            generation: u64,
            _key: &str,
            _queue: Option<&mobula_provision::QueueAssignment>,
        ) -> Result<mobula_provision::ApplyResponse, ProvisionError> {
            Ok(mobula_provision::ApplyResponse {
                generation,
                api_base_url: None,
            })
        }
        async fn terminate(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn suspend(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn resume(&self, _id: &ClusterId) -> Result<(), ProvisionError> {
            Ok(())
        }
        async fn observe(
            &self,
            id: &ClusterId,
        ) -> Result<mobula_provision::ObservedCluster, ProvisionError> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n % 2 == 0 {
                Ok(mobula_provision::ObservedCluster {
                    id: id.clone(),
                    state: ClusterState::Running,
                    observed_generation: Some(1),
                    spec_fingerprint: None,
                    api_base_url: None,
                })
            } else {
                Err(ProvisionError::NotFound(id.clone()))
            }
        }
        async fn list(&self) -> Result<Vec<mobula_provision::ObservedCluster>, ProvisionError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn store_list_error_is_collected_not_fatal() {
        use crate::store::testkit::FailingStore;
        let store = Arc::new(FailingStore::new());
        store.fail("list");
        let rec = Reconciler::new(store, Arc::new(ErrProv));
        let out = rec.reconcile_all_at(0).await;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "<list>");
        assert!(out[0].1.is_err());
    }

    #[tokio::test]
    async fn observe_backend_error_fails_the_cluster_pass() {
        use crate::store::memory::InMemoryStore;
        let store = Arc::new(InMemoryStore::new());
        store
            .upsert_desired(&ClusterId("c".into()), stored(None, 0, None).spec)
            .await
            .unwrap();
        let rec = Reconciler::new(store, Arc::new(ErrProv));
        let out = rec.reconcile_all_at(0).await;
        assert!(matches!(out[0].1, Err(ReconcileError::Provision(_))));
    }

    #[tokio::test]
    async fn cluster_vanishing_mid_pass_records_no_observation() {
        // The re-observe after a NoOp decision returns NotFound: the stored
        // observation is cleared (recorded as absent), not left stale.
        use crate::store::memory::InMemoryStore;
        let store = Arc::new(InMemoryStore::new());
        let id = ClusterId("c".into());
        store
            .upsert_desired(&id, stored(None, 0, None).spec)
            .await
            .unwrap();
        let rec = Reconciler::new(
            store.clone(),
            Arc::new(VanishingProv {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }),
        );
        let out = rec.reconcile_all_at(0).await;
        assert_eq!(out[0].1.as_ref().unwrap(), &Action::NoOp);
        let stored = store.get(&id).await.unwrap().unwrap();
        assert_eq!(stored.observed_state, None, "vanish mid-pass is recorded");
        assert_eq!(stored.observed_generation, 0);
    }

    #[tokio::test]
    async fn stale_restore_check_handles_absent_and_failing_clusters() {
        use crate::store::memory::InMemoryStore;

        // No clusters → no quarantine.
        let store = Arc::new(InMemoryStore::new());
        let rec = Reconciler::new(store.clone(), Arc::new(ErrProv));
        assert!(!rec.detect_stale_restore().await.unwrap());

        // A stored cluster whose backing resource is gone (NotFound) is
        // skipped, not fatal.
        store
            .upsert_desired(&ClusterId("c".into()), stored(None, 0, None).spec)
            .await
            .unwrap();
        let rec = Reconciler::new(
            store.clone(),
            Arc::new(VanishingProv {
                calls: std::sync::atomic::AtomicUsize::new(1), // odd → NotFound first
            }),
        );
        assert!(!rec.detect_stale_restore().await.unwrap());
        assert!(!store.is_quarantined().await.unwrap());

        // A backend error on observe propagates.
        let rec = Reconciler::new(store, Arc::new(ErrProv));
        assert!(matches!(
            rec.detect_stale_restore().await,
            Err(ReconcileError::Provision(_))
        ));
    }

    #[tokio::test]
    async fn run_loop_logs_pass_errors_and_stops_on_shutdown() {
        // With a failing store, every tick logs reap/reconcile errors and
        // keeps going; shutdown still stops the loop promptly.
        use crate::store::testkit::FailingStore;
        let store = Arc::new(FailingStore::new());
        store.fail("list");
        store.fail("reap_intents");
        let rec = Reconciler::new(store, Arc::new(ErrProv));

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            rec.run(Duration::from_millis(10), async {
                let _ = rx.await;
            })
            .await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("loop should stop promptly on shutdown")
            .unwrap();
    }
}
