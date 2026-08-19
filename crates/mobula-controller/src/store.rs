//! Desired-state store (ADR-0004: Postgres is truth; SQLite in dev).
//!
//! This slice defines the `Store` trait and an in-memory implementation so
//! the reconcile engine is testable without a database. The sqlx-backed
//! store lands in the next slice behind the same trait.

use async_trait::async_trait;
use mobula_core::{
    AllocationSpec, ApiTokenRecord, AuditEvent, AuditFilter, ClusterId, ClusterSpec, ClusterState,
    DriftCondition, JobRecord, LocalUserRecord, PoolSpec,
};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store backend error: {0}")]
    Backend(String),
}

// Shared by the sqlx-backed stores (SQLite, Postgres).
impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

/// Shared by the sqlx-backed stores (SQLite, Postgres): spec/enum columns are
/// JSON text, so a serialization failure surfaces as a store error.
pub(crate) fn json_err(e: serde_json::Error) -> StoreError {
    StoreError::Backend(format!("serialization: {e}"))
}

/// What the operator wants a cluster to be. The *observed* state is
/// reconstructed from the provisioner every reconcile (ADR-0006) — it is
/// never stored as authoritative truth.
///
/// Persisted as a string column (`desired`) by the sqlx stores, so adding a
/// variant is back-compatible with old rows; an *old binary* reading a row
/// written by a newer one errors rather than guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredState {
    Running,
    /// #51: compute released, spec kept. The reconciler drives the backing
    /// cluster to `spec.suspend: true` (Mobula owns that field, ADR-0007) —
    /// except for queue-assigned clusters, where Kueue owns suspend and the
    /// API rejects user suspend/resume with 409.
    Suspended,
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
        // Pod shaping (#66) drives actuation: a changed mount, env var,
        // service account or placement must roll the pods, so it has to
        // bump the generation like any other owned field. Both sides are
        // compared — the selections because they are what the caller
        // asked for, the resolution because a catalog change that alters
        // an existing cluster's grant must be re-applied, not ignored.
        || a.pod != b.pod
        || a.pod_resolved != b.pod_resolved
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

/// A persisted pool (ADR-0004/ADR-0010): the pool spec plus a monotonic
/// `generation` that bumps whenever the spec changes, plus the last
/// Kueue observation (`observed_json`, opaque serialized
/// [`mobula_provision::PoolObservation`]) recorded by the pool reconcile
/// loop — the Slice 4 metering loop reads it from here.
#[derive(Debug, Clone)]
pub struct StoredPool {
    pub name: String,
    pub spec: PoolSpec,
    pub generation: u64,
    /// Last observed ClusterQueue status (opaque JSON), if the pool
    /// reconcile loop has observed this pool. Never authoritative — pools
    /// are level-triggered from the spec like clusters are.
    pub observed_json: Option<String>,
    /// When `observed_json` was recorded (unix seconds). `None` until the
    /// first observation; surfaces as `sampled_at` on the pool-usage API.
    pub observed_at: Option<u64>,
    /// Unix seconds when the pool was first created.
    pub created_at: u64,
}

/// Whether two pool specs differ in a way that should bump `generation`.
/// `PoolSpec` is `PartialEq`, so this is a direct comparison; the helper
/// exists to mirror the `spec_changed` convention and give every `Store`
/// implementation one shared definition.
pub(crate) fn pool_spec_changed(a: &PoolSpec, b: &PoolSpec) -> bool {
    a != b
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

/// Resolve the Kueue queue a project's clusters are admitted through
/// (ADR-0010): the first allocation matching `project` across all pools,
/// carrying the pool's `elastic` flag. `None` = the project has no
/// allocation and its clusters stay queue-free. Derived from the store at
/// apply time (the store is truth, ADR-0004), so the assignment never
/// travels inside `ClusterSpec`'s serialized form — both the cluster
/// reconciler and the create API resolve it through this helper.
pub async fn queue_assignment_for_project<S: Store + ?Sized>(
    store: &S,
    project: &str,
) -> Result<Option<mobula_provision::QueueAssignment>, StoreError> {
    for pool in store.list_pools().await? {
        for alloc in store.list_allocations(&pool.name).await? {
            if alloc.project == project {
                return Ok(Some(mobula_provision::QueueAssignment {
                    queue_name: alloc.project,
                    elastic: pool.spec.elastic,
                }));
            }
        }
    }
    Ok(None)
}

/// Where a usage sample came from (ADR-0010's documented divergence: Kueue's
/// `flavorsUsage` is a *reservation* ledger, not measured consumption, so
/// Mobula meters attribution itself and labels each sample's provenance).
/// Serialized snake_case (`kueue_ledger` / `observed_spec`) in both JSON and
/// the `usage_samples.source` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// Kueue's ClusterQueue/LocalQueue `status.flavorsUsage` — reservation
    /// ledger amounts (what Kueue admits against quota).
    KueueLedger,
    /// Mobula's own estimate from desired cluster specs (the min-demand
    /// baseline), used when Kueue is absent.
    ObservedSpec,
}

impl UsageSource {
    pub fn as_str(self) -> &'static str {
        match self {
            UsageSource::KueueLedger => "kueue_ledger",
            UsageSource::ObservedSpec => "observed_spec",
        }
    }

    pub fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "kueue_ledger" => Ok(UsageSource::KueueLedger),
            "observed_spec" => Ok(UsageSource::ObservedSpec),
            other => Err(StoreError::Backend(format!("bad usage source {other:?}"))),
        }
    }
}

/// One point-in-time usage reading (Slice 4 metering): `quantity` units of
/// `resource` attributed to (`project`, `pool`) at `ts`. Append-only
/// timeseries — no primary key, no updates; aggregation
/// (`mobula_policy::resource_hours`) interprets the series as a step
/// function. An empty `project` is the pool-level aggregate row (not
/// attributable to a single project); an empty `pool` means the project has
/// no allocation. Plain columns, no JSON — this table is query-facing.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UsageSample {
    /// Unix seconds.
    pub ts: u64,
    pub project: String,
    pub pool: String,
    pub resource: String,
    /// Amount in the resource key's natural unit (cores / GiB / devices).
    pub quantity: f64,
    pub source: UsageSource,
}

/// The persisted governance policy (api-v1.md §5.16): the optional price
/// sheet (resource → $/unit-hour) and per-project quota limits (project →
/// resource → amount), stored as one JSON-text row (the `control` KV table
/// in SQLite — policy is a singleton like the quarantine flag, so a
/// dedicated single-row table would add schema for nothing; the JSON-text
/// convention keeps the SQL Postgres-portable).
///
/// `from_file_seed` records provenance: the row written from the `--policy`
/// boot seed carries `true`; the first `PUT /api/v1/settings/policy` edit
/// rewrites the row with `false`. The settings API derives its `source`
/// field ("file" | "store") from it; "none" is simply the absence of a row.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredPolicy {
    /// resource → $/unit-hour; `None` = no price sheet (no cost estimates).
    pub prices: Option<std::collections::BTreeMap<String, f64>>,
    /// project → resource → limit. Empty = no quotas enforced.
    #[serde(default)]
    pub quotas: std::collections::BTreeMap<String, std::collections::BTreeMap<String, f64>>,
    /// Pod-shaping catalog (#66): the mounts, placements and service
    /// accounts callers may select. Store-backed and Admin-editable for the
    /// same reason pools are (ADR-0010): adding a mount must not require a
    /// restart.
    ///
    /// Editing the catalog does NOT re-shape running clusters — a cluster's
    /// grant is frozen onto its spec as `pod_resolved` at admission, and the
    /// KubeRay translation reads only the spec. A cluster moves onto a new
    /// catalog when, and only when, someone re-submits it: the re-resolution
    /// changes `pod_resolved`, `spec_changed` bumps the generation, and
    /// KubeRay rolls the pods. Migration is deliberate, never ambient.
    ///
    /// `#[serde(default)]` keeps rows written before #66 readable.
    #[serde(default)]
    pub pod_shaping: mobula_policy::podshape::PodShapeCatalog,
    /// True while the row is the untouched `--policy` boot seed.
    pub from_file_seed: bool,
}

/// A scoped role assignment (ADR-0009 addendum, #49): `principal` (the
/// Identity `subject`) holds `role` at `scope`, where scope is `"*"`
/// (global — today's flat behavior) or `"project:<name>"`. Assignments are
/// additive grants on top of the group-derived roles; there are no deny
/// rules. Group-principal bindings are deliberately out of scope — they
/// belong to the OIDC-mapping layer.
///
/// Stored as plain TEXT columns (role/scope are not JSON — this table is
/// query-facing, keyed by (principal, role, scope) so an upsert of the same
/// triple replaces it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleAssignment {
    pub principal: String,
    /// Role name ("viewer" | "developer" | "operator" | "admin" |
    /// "auditor") — the `mobula_auth::Role` wire form; the store stays free
    /// of the auth crate.
    pub role: String,
    /// `"*"` or `"project:<name>"`.
    pub scope: String,
    /// Unix seconds when the assignment was first written.
    pub created_at: u64,
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

/// Local-auth lockout policy (ADR-0011): after this many consecutive failed
/// logins the account locks for [`LOCKOUT_SECS`].
pub const LOGIN_LOCKOUT_THRESHOLD: u32 = 5;
/// Lockout duration in seconds (5 minutes, mirroring artifact-keeper).
pub const LOCKOUT_SECS: u64 = 300;

/// Pure lockout state machine, shared by every `Store` implementation via
/// the default [`Store::record_login_failure`]: one more failure increments
/// the counter; crossing [`LOGIN_LOCKOUT_THRESHOLD`] resets the counter and
/// locks the account until `now + LOCKOUT_SECS`.
pub fn next_login_failure_state(failed_logins: u32, now: u64) -> (u32, Option<u64>) {
    let failed = failed_logins + 1;
    if failed >= LOGIN_LOCKOUT_THRESHOLD {
        (0, Some(now + LOCKOUT_SECS))
    } else {
        (failed, None)
    }
}

// --- Audit tamper-evidence (#59, api-v1.md §5.9) ---
//
// The audit trail is hash-chained: every appended row carries a
// `chain_hash` = sha256 over (previous row's chain_hash ‖ this row's
// canonical serialization). A single `chain_hash` column suffices — the
// previous row's hash is an *input* to this row's hash, so a separate
// `prev_hash` column would be redundant (the previous row's `chain_hash`
// IS the prev_hash). The genesis row chains from [`AUDIT_GENESIS_HASH`].
// This is tamper-EVIDENCE, not tamper-proofing: there is no secret key, so
// an attacker with write access to the table can recompute the chain — but
// any edit, insert, or delete of a middle row breaks every later hash, and
// `GET /api/v1/audit/verify` detects that. (Deleting the *newest* rows
// leaves no gap to detect — a documented limitation; ship the JSONL export
// off-box for non-repudiation.)

/// The chain head the very first audit row (seq 1) chains from: 64 zero
/// hex chars. Fixed-length like every other hash in the chain, so the
/// hash input's concatenation is unambiguous without a separator.
pub const AUDIT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One audit row as the chain sees it: (seq, event, stored chain_hash).
pub type ChainedAuditRow = (u64, AuditEvent, String);

/// A window of the audit chain, ascending by seq, for verification.
#[derive(Debug, Clone)]
pub struct AuditChainWindow {
    /// The hash the first row in `rows` must chain from:
    /// [`AUDIT_GENESIS_HASH`] when the window starts at the beginning of
    /// the trail, else the newest row before the window's `chain_hash`.
    pub head: String,
    /// (seq, event, chain_hash), ascending by seq.
    pub rows: Vec<ChainedAuditRow>,
}

/// The chain hash of a row: sha256 hex over (prev_hash ‖ canonical event
/// serialization). The canonical serialization is `serde_json` over
/// [`AuditEvent`]: struct field order is fixed by declaration and `Option`
/// fields always serialize (nulls present), so every store implementation
/// — and the verifier — produces byte-identical input. `prev_hash` is
/// always 64 lowercase hex chars (genesis included), making the
/// concatenation unambiguous.
pub fn audit_chain_hash(prev_hash: &str, event: &AuditEvent) -> String {
    use sha2::Digest;
    let canonical =
        serde_json::to_vec(event).expect("AuditEvent is plain data; serialization cannot fail");
    let mut hasher = sha2::Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(&canonical);
    let digest = hasher.finalize();
    use std::fmt::Write;
    let mut out = String::with_capacity(64);
    for b in digest {
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// The result of replaying a chain window ([`verify_audit_chain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditChainVerification {
    /// Rows that verified before the replay stopped (all rows on success;
    /// the rows *before* the broken one on failure).
    pub events_checked: u64,
    /// Seq of the first row whose stored `chain_hash` doesn't match the
    /// replay; `None` when the whole window verifies.
    pub first_broken_seq: Option<u64>,
}

impl AuditChainVerification {
    pub fn ok(&self) -> bool {
        self.first_broken_seq.is_none()
    }
}

/// Replay a chain window: recompute each row's hash from its predecessor
/// (starting at `head`) and compare against the stored `chain_hash`. Stops
/// at the first mismatch — everything after a broken link is untrustworthy
/// by construction. Pure and shared by every store backend and the
/// `/api/v1/audit/verify` endpoint.
pub fn verify_audit_chain(head: &str, rows: &[ChainedAuditRow]) -> AuditChainVerification {
    let mut prev = head;
    let mut checked = 0u64;
    for (seq, event, stored) in rows {
        if audit_chain_hash(prev, event) != *stored {
            return AuditChainVerification {
                events_checked: checked,
                first_broken_seq: Some(*seq),
            };
        }
        prev = stored;
        checked += 1;
    }
    AuditChainVerification {
        events_checked: checked,
        first_broken_seq: None,
    }
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

    /// Record or update a job in the persistent history (Phase 3, #20),
    /// keyed by job id. Job records live independently of clusters, so they
    /// survive the deletion of the cluster that ran them.
    async fn record_job(&self, job: JobRecord) -> Result<(), StoreError>;

    /// List job history, most recently submitted first.
    async fn list_jobs(&self) -> Result<Vec<JobRecord>, StoreError>;

    /// Create or update a pool's spec (ADR-0004: the store is truth; Kueue
    /// objects are actuation). Returns the (possibly bumped) generation —
    /// like clusters, generation only advances when the spec actually
    /// changes.
    async fn upsert_pool(&self, name: &str, spec: PoolSpec) -> Result<u64, StoreError>;

    async fn get_pool(&self, name: &str) -> Result<Option<StoredPool>, StoreError>;
    async fn list_pools(&self) -> Result<Vec<StoredPool>, StoreError>;

    /// Hard-delete a pool (the Kueue teardown is driven by the pool
    /// reconcile loop observing the pool's disappearance). Errors naming
    /// the missing pool when it does not exist, mirroring
    /// `delete_cluster`'s convention.
    async fn delete_pool(&self, name: &str) -> Result<(), StoreError>;

    /// Record the pool reconcile loop's last observation of a pool's Kueue
    /// ClusterQueue status (opaque JSON — the store stays decoupled from
    /// the observation type). Overwrites on every pass; `None`-able in
    /// storage, recorded only when the observe succeeded.
    async fn record_pool_observation(
        &self,
        name: &str,
        observed_json: &str,
    ) -> Result<(), StoreError>;

    /// Create or update a project's allocation within a pool (keyed by
    /// (pool, project)). Allocations are part of the pool's desired state.
    async fn upsert_allocation(&self, alloc: AllocationSpec) -> Result<(), StoreError>;

    /// List the allocations of one pool.
    async fn list_allocations(&self, pool: &str) -> Result<Vec<AllocationSpec>, StoreError>;

    /// Delete one allocation. Errors naming the missing (pool, project)
    /// when it does not exist.
    async fn delete_allocation(&self, pool: &str, project: &str) -> Result<(), StoreError>;

    /// Append usage samples (Slice 4 metering). Append-only timeseries —
    /// the metering loop writes, nothing updates or deletes individual rows.
    async fn record_usage_samples(&self, samples: &[UsageSample]) -> Result<(), StoreError>;

    /// Read usage samples in `[from, to]` (unix seconds, inclusive),
    /// ordered by `ts` ascending. `project`/`pool` filter when `Some`.
    /// Callers wanting carry-in for aggregation should query from `0` and
    /// let `mobula_policy::resource_hours` clamp — a sample before `from`
    /// sets the level entering the window.
    async fn usage_samples(
        &self,
        project: Option<&str>,
        pool: Option<&str>,
        from: u64,
        to: u64,
    ) -> Result<Vec<UsageSample>, StoreError>;

    /// Read the persisted governance policy (api-v1.md §5.16); `None` when
    /// no policy row exists (never seeded, never edited).
    async fn get_policy(&self) -> Result<Option<StoredPolicy>, StoreError>;

    /// Overwrite the governance policy row (the settings PUT path).
    async fn set_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError>;

    /// Insert the `--policy` boot seed ONLY when no policy row exists
    /// (insert-if-absent, so a concurrent edit or seeder is never
    /// clobbered). Returns true when this call inserted the row. Backends
    /// must implement this atomically (a single conditional INSERT), not as
    /// get+set.
    async fn seed_policy(&self, policy: &StoredPolicy) -> Result<bool, StoreError>;

    /// Append an audit event (api-v1.md §5.9). Append-only: returns the
    /// row's `seq`, a 1-based monotonic sequence number that doubles as the
    /// pagination cursor for [`Store::list_audit`]. Callers must treat a
    /// failure as non-fatal (log and continue) — audit persistence never
    /// fails the request being audited.
    async fn record_audit(&self, event: &AuditEvent) -> Result<u64, StoreError>;

    /// List audit events matching `filter`, newest-first by `seq`
    /// (descending). `filter.cursor` selects only rows with
    /// `seq < cursor`; the page holds at most `filter.effective_limit()`
    /// rows. The returned `next_cursor` is `Some(seq)` of the oldest row in
    /// the page when more matching rows exist beyond it, `None` at the end —
    /// pass it back as `cursor` for the next page.
    async fn list_audit(
        &self,
        filter: &AuditFilter,
    ) -> Result<(Vec<(u64, AuditEvent)>, Option<u64>), StoreError>;

    /// Read the audit chain (#59) in ASCENDING seq order for verification:
    /// rows with `seq >= from_seq` (the whole trail when `None`), at most
    /// `limit`. The window's `head` is the hash the first row must chain
    /// from — [`AUDIT_GENESIS_HASH`] at the start of the trail, else the
    /// newest preceding row's `chain_hash` — so a mid-trail window verifies
    /// against the same head the rows were written with.
    async fn audit_chain(
        &self,
        from_seq: Option<u64>,
        limit: u32,
    ) -> Result<AuditChainWindow, StoreError>;

    // --- Local auth (ADR-0011) ---

    /// Create a local user. The store receives the bcrypt password hash,
    /// never plaintext. `created_at` is stamped by the store; lockout
    /// counters start cleared. Errors when the username already exists.
    async fn create_local_user(
        &self,
        username: &str,
        email: Option<&str>,
        password_hash: &str,
        role: mobula_core::LocalRole,
    ) -> Result<(), StoreError>;

    /// Read a local user row (including the password hash — the caller is
    /// the auth layer, which must never serialize it).
    async fn get_local_user(&self, username: &str) -> Result<Option<LocalUserRecord>, StoreError>;

    /// List all local users, ordered by username.
    async fn list_local_users(&self) -> Result<Vec<LocalUserRecord>, StoreError>;

    /// Replace a user's bcrypt password hash. Errors naming the missing
    /// user when it does not exist.
    async fn set_local_user_password(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), StoreError>;

    /// Change a user's role (ADR-0011: resolved per request, so this
    /// applies to the very next authenticated call). Errors naming the
    /// missing user.
    async fn set_local_user_role(
        &self,
        username: &str,
        role: mobula_core::LocalRole,
    ) -> Result<(), StoreError>;

    /// Disable or re-enable a user. Disabled users cannot log in and their
    /// existing tokens stop authenticating. Errors naming the missing user.
    async fn set_local_user_disabled(
        &self,
        username: &str,
        disabled: bool,
    ) -> Result<(), StoreError>;

    /// Persist the lockout counters. Backend hook for the default
    /// [`Store::record_login_failure`] / [`Store::record_login_success`]
    /// implementations; errors naming the missing user.
    async fn set_login_lockout(
        &self,
        username: &str,
        failed_logins: u32,
        locked_until: Option<u64>,
    ) -> Result<(), StoreError>;

    /// Record a failed login: increments the counter, and when it crosses
    /// [`LOGIN_LOCKOUT_THRESHOLD`] locks the account for [`LOCKOUT_SECS`]
    /// and resets the counter. The decision lives in
    /// [`next_login_failure_state`] so every backend shares semantics.
    async fn record_login_failure(&self, username: &str) -> Result<(), StoreError> {
        let user = self
            .get_local_user(username)
            .await?
            .ok_or_else(|| StoreError::Backend(format!("no such local user {username}")))?;
        let (failed, locked) = next_login_failure_state(user.failed_logins, now_unix());
        self.set_login_lockout(username, failed, locked).await
    }

    /// Record a successful login: clears the failure counter and any lock.
    async fn record_login_success(&self, username: &str) -> Result<(), StoreError> {
        self.set_login_lockout(username, 0, None).await
    }

    /// Store an opaque API token (ADR-0011). `record` carries the bcrypt
    /// token hash; the plaintext is shown once at issuance and never
    /// stored. Errors when the prefix collides.
    async fn create_api_token(&self, record: ApiTokenRecord) -> Result<(), StoreError>;

    /// Look a token up by its 8-char prefix (including the hash — the
    /// caller is the auth layer, which must never serialize it).
    async fn get_api_token_by_prefix(
        &self,
        prefix: &str,
    ) -> Result<Option<ApiTokenRecord>, StoreError>;

    /// List one user's tokens, newest first. Never returns hashes to the
    /// wire — callers project to `ApiTokenView`.
    async fn list_api_tokens(&self, username: &str) -> Result<Vec<ApiTokenRecord>, StoreError>;

    /// Revoke a token, owner-scoped: revoking someone else's token (or a
    /// nonexistent one) errors as "no such token" so ownership can't be
    /// probed. Idempotent for an already-revoked own token.
    async fn revoke_api_token(&self, prefix: &str, username: &str) -> Result<(), StoreError>;

    /// Best-effort `last_used_at` stamp on a successful token
    /// authentication. Never fails the request being authenticated.
    async fn touch_api_token(&self, prefix: &str, now: u64) -> Result<(), StoreError>;

    // --- Scoped role assignments (ADR-0009 addendum, #49) ---

    /// Create or replace a scoped role assignment, keyed by
    /// (principal, role, scope). `created_at` is stamped by the store on
    /// insert and preserved on re-upsert. Validation of the role name and
    /// scope grammar is the API layer's job (access.rs) — the store is dumb
    /// persistence.
    async fn upsert_role_assignment(
        &self,
        principal: &str,
        role: &str,
        scope: &str,
    ) -> Result<(), StoreError>;

    /// List assignments, ordered by (principal, scope, role). `principal`
    /// filters to one subject — the per-request authz lookup path (one
    /// indexed row read per request).
    async fn list_role_assignments(
        &self,
        principal: Option<&str>,
    ) -> Result<Vec<RoleAssignment>, StoreError>;

    /// Remove one assignment. Errors naming the missing
    /// (principal, role, scope) when it does not exist, mirroring
    /// `delete_allocation`'s convention.
    async fn delete_role_assignment(
        &self,
        principal: &str,
        role: &str,
        scope: &str,
    ) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_source_round_trips_and_rejects_unknown() {
        for s in [UsageSource::KueueLedger, UsageSource::ObservedSpec] {
            assert_eq!(UsageSource::parse(s.as_str()).unwrap(), s);
        }
        let err = UsageSource::parse("bogus").unwrap_err().to_string();
        assert!(err.contains("bad usage source"), "{err}");
    }

    // --- #59 audit chain ---

    fn chain_event(ts: u64, subject: Option<&str>) -> AuditEvent {
        AuditEvent {
            ts,
            subject: subject.map(String::from),
            decision: mobula_core::AuditDecision::Allow,
            action: Some("create_cluster".into()),
            ..Default::default()
        }
    }

    /// Chain n events from genesis, returning rows as `(seq, event, hash)`.
    fn chain_rows(events: Vec<AuditEvent>) -> Vec<ChainedAuditRow> {
        let mut prev = AUDIT_GENESIS_HASH.to_string();
        events
            .into_iter()
            .enumerate()
            .map(|(i, e)| {
                let hash = audit_chain_hash(&prev, &e);
                prev = hash.clone();
                (i as u64 + 1, e, hash)
            })
            .collect()
    }

    #[test]
    fn chain_hash_is_deterministic_and_prev_sensitive() {
        let e = chain_event(100, Some("alice"));
        let h1 = audit_chain_hash(AUDIT_GENESIS_HASH, &e);
        assert_eq!(h1, audit_chain_hash(AUDIT_GENESIS_HASH, &e));
        assert_eq!(h1.len(), 64, "lowercase hex sha256");
        assert!(h1.chars().all(|c| c.is_ascii_hexdigit()));
        // A different predecessor yields a different hash for the same row.
        assert_ne!(h1, audit_chain_hash(&h1, &e));
        // A different row under the same predecessor differs too.
        assert_ne!(
            h1,
            audit_chain_hash(AUDIT_GENESIS_HASH, &chain_event(101, Some("alice")))
        );
    }

    #[test]
    fn verify_accepts_an_intact_chain_from_genesis() {
        let rows = chain_rows(vec![
            chain_event(100, Some("alice")),
            chain_event(200, None),
            chain_event(300, Some("bob")),
        ]);
        let v = verify_audit_chain(AUDIT_GENESIS_HASH, &rows);
        assert!(v.ok());
        assert_eq!(v.events_checked, 3);
        assert_eq!(v.first_broken_seq, None);
        // An empty window trivially verifies (nothing to check).
        let v = verify_audit_chain(AUDIT_GENESIS_HASH, &[]);
        assert!(v.ok() && v.events_checked == 0);
    }

    #[test]
    fn verify_flags_a_tampered_row_at_its_seq() {
        let mut rows = chain_rows(vec![
            chain_event(100, Some("alice")),
            chain_event(200, None),
            chain_event(300, Some("bob")),
        ]);
        // Tamper with the middle row's payload without fixing the chain.
        rows[1].1.subject = Some("mallory".into());
        let v = verify_audit_chain(AUDIT_GENESIS_HASH, &rows);
        assert!(!v.ok());
        assert_eq!(v.events_checked, 1, "row 1 verified, row 2 broke");
        assert_eq!(v.first_broken_seq, Some(2));

        // A forged hash on the last row is caught at that row.
        let mut rows = chain_rows(vec![chain_event(100, None), chain_event(200, None)]);
        rows[1].2 = "f".repeat(64);
        let v = verify_audit_chain(AUDIT_GENESIS_HASH, &rows);
        assert_eq!(v.first_broken_seq, Some(2));
        assert_eq!(v.events_checked, 1);
    }

    #[test]
    fn verify_flags_a_deleted_middle_row() {
        let rows = chain_rows(vec![
            chain_event(100, None),
            chain_event(200, None),
            chain_event(300, None),
        ]);
        // Drop the middle row: row 3's stored hash chains from row 2's, so
        // replay from row 1 mismatches at seq 3.
        let truncated = vec![rows[0].clone(), rows[2].clone()];
        let v = verify_audit_chain(AUDIT_GENESIS_HASH, &truncated);
        assert_eq!(v.first_broken_seq, Some(3));
    }

    #[test]
    fn verify_a_mid_trail_window_against_its_head() {
        let rows = chain_rows(vec![
            chain_event(100, None),
            chain_event(200, None),
            chain_event(300, None),
        ]);
        // The window [2, 3] verifies against row 1's hash as head.
        let v = verify_audit_chain(&rows[0].2, &rows[1..]);
        assert!(v.ok() && v.events_checked == 2);
        // The same window from genesis (the wrong head) breaks at seq 2.
        let v = verify_audit_chain(AUDIT_GENESIS_HASH, &rows[1..]);
        assert_eq!(v.first_broken_seq, Some(2));
    }

    #[tokio::test]
    async fn queue_assignment_resolves_first_matching_allocation() {
        use mobula_core::FlavorSpec;
        use std::collections::BTreeMap;

        let store = memory::InMemoryStore::new();
        // No pools at all → no assignment.
        assert!(queue_assignment_for_project(&store, "p")
            .await
            .unwrap()
            .is_none());

        let pool_spec = |name: &str, elastic: bool| PoolSpec {
            name: name.into(),
            flavors: vec![FlavorSpec {
                name: "cpu".into(),
                resources: BTreeMap::from([("cpu".to_string(), "4".to_string())]),
                node_labels: BTreeMap::new(),
                taints: vec![],
            }],
            cohort: "research".into(),
            fair_sharing_weight: 1.0,
            elastic,
            gpu_sharing: None,
        };
        let alloc = |pool: &str, project: &str| AllocationSpec {
            pool: pool.into(),
            project: project.into(),
            namespace: project.into(),
            nominal: BTreeMap::new(),
            borrowing_limit: BTreeMap::new(),
            lending_limit: BTreeMap::new(),
        };
        store
            .upsert_pool("gpu", pool_spec("gpu", true))
            .await
            .unwrap();
        store.upsert_allocation(alloc("gpu", "p")).await.unwrap();

        // The assignment carries the queue name (= project) and the pool's
        // elastic flag.
        let q = queue_assignment_for_project(&store, "p")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(q.queue_name, "p");
        assert!(q.elastic);
        // A project with no allocation stays queue-free.
        assert!(queue_assignment_for_project(&store, "other")
            .await
            .unwrap()
            .is_none());
    }
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
        jobs: Mutex<HashMap<String, JobRecord>>,
        pools: Mutex<HashMap<String, StoredPool>>,
        allocations: Mutex<HashMap<(String, String), AllocationSpec>>,
        usage: Mutex<Vec<UsageSample>>,
        /// Governance policy row (api-v1.md §5.16); `None` = never seeded
        /// nor edited.
        policy: Mutex<Option<StoredPolicy>>,
        /// (seq, event, chain_hash) in insertion order; seq is 1-based from
        /// `audit_seq`. The chain hash (#59) is computed at append time.
        audit: Mutex<Vec<ChainedAuditRow>>,
        audit_seq: std::sync::atomic::AtomicU64,
        local_users: Mutex<HashMap<String, LocalUserRecord>>,
        api_tokens: Mutex<HashMap<String, ApiTokenRecord>>,
        /// Scoped role assignments (#49), keyed by (principal, role, scope).
        assignments: Mutex<HashMap<(String, String, String), RoleAssignment>>,
    }

    impl InMemoryStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    use super::pool_spec_changed;
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

        async fn record_job(&self, job: JobRecord) -> Result<(), StoreError> {
            self.jobs.lock().unwrap().insert(job.id.clone(), job);
            Ok(())
        }

        async fn list_jobs(&self) -> Result<Vec<JobRecord>, StoreError> {
            let mut jobs: Vec<JobRecord> = self.jobs.lock().unwrap().values().cloned().collect();
            jobs.sort_by_key(|r| std::cmp::Reverse(r.submitted_at));
            Ok(jobs)
        }

        async fn upsert_pool(&self, name: &str, spec: PoolSpec) -> Result<u64, StoreError> {
            let mut map = self.pools.lock().unwrap();
            let existing = map.get(name);
            let generation = match existing {
                Some(p) if !pool_spec_changed(&p.spec, &spec) => p.generation,
                Some(p) => p.generation + 1,
                None => 1,
            };
            let record = StoredPool {
                name: name.to_string(),
                spec,
                generation,
                // Observations survive spec updates, like cluster observed state.
                observed_json: existing.and_then(|p| p.observed_json.clone()),
                observed_at: existing.and_then(|p| p.observed_at),
                created_at: existing.map(|p| p.created_at).unwrap_or_else(now_unix),
            };
            map.insert(name.to_string(), record);
            Ok(generation)
        }

        async fn get_pool(&self, name: &str) -> Result<Option<StoredPool>, StoreError> {
            Ok(self.pools.lock().unwrap().get(name).cloned())
        }

        async fn list_pools(&self) -> Result<Vec<StoredPool>, StoreError> {
            Ok(self.pools.lock().unwrap().values().cloned().collect())
        }

        async fn delete_pool(&self, name: &str) -> Result<(), StoreError> {
            let mut map = self.pools.lock().unwrap();
            if map.remove(name).is_none() {
                return Err(StoreError::Backend(format!("no such pool {name}")));
            }
            Ok(())
        }

        async fn record_pool_observation(
            &self,
            name: &str,
            observed_json: &str,
        ) -> Result<(), StoreError> {
            let mut map = self.pools.lock().unwrap();
            if let Some(p) = map.get_mut(name) {
                p.observed_json = Some(observed_json.to_string());
                p.observed_at = Some(now_unix());
            }
            Ok(())
        }

        async fn upsert_allocation(&self, alloc: AllocationSpec) -> Result<(), StoreError> {
            self.allocations
                .lock()
                .unwrap()
                .insert((alloc.pool.clone(), alloc.project.clone()), alloc);
            Ok(())
        }

        async fn list_allocations(&self, pool: &str) -> Result<Vec<AllocationSpec>, StoreError> {
            Ok(self
                .allocations
                .lock()
                .unwrap()
                .values()
                .filter(|a| a.pool == pool)
                .cloned()
                .collect())
        }

        async fn delete_allocation(&self, pool: &str, project: &str) -> Result<(), StoreError> {
            let mut map = self.allocations.lock().unwrap();
            if map
                .remove(&(pool.to_string(), project.to_string()))
                .is_none()
            {
                return Err(StoreError::Backend(format!(
                    "no such allocation {pool}/{project}"
                )));
            }
            Ok(())
        }

        async fn record_usage_samples(&self, samples: &[UsageSample]) -> Result<(), StoreError> {
            self.usage.lock().unwrap().extend_from_slice(samples);
            Ok(())
        }

        async fn usage_samples(
            &self,
            project: Option<&str>,
            pool: Option<&str>,
            from: u64,
            to: u64,
        ) -> Result<Vec<UsageSample>, StoreError> {
            let mut out: Vec<UsageSample> = self
                .usage
                .lock()
                .unwrap()
                .iter()
                .filter(|s| {
                    s.ts >= from
                        && s.ts <= to
                        && project.is_none_or(|p| s.project == p)
                        && pool.is_none_or(|p| s.pool == p)
                })
                .cloned()
                .collect();
            out.sort_by_key(|s| s.ts);
            Ok(out)
        }

        async fn record_audit(&self, event: &AuditEvent) -> Result<u64, StoreError> {
            let mut rows = self.audit.lock().unwrap();
            let seq = self.audit_seq.fetch_add(1, Ordering::SeqCst) + 1;
            let prev = rows
                .last()
                .map(|(_, _, h)| h.as_str())
                .unwrap_or(AUDIT_GENESIS_HASH);
            let chain_hash = audit_chain_hash(prev, event);
            rows.push((seq, event.clone(), chain_hash));
            Ok(seq)
        }

        async fn audit_chain(
            &self,
            from_seq: Option<u64>,
            limit: u32,
        ) -> Result<AuditChainWindow, StoreError> {
            let rows = self.audit.lock().unwrap();
            let from = from_seq.unwrap_or(1);
            let head = rows
                .iter()
                .rev()
                .find(|(seq, _, _)| *seq < from)
                .map(|(_, _, h)| h.clone())
                .unwrap_or_else(|| AUDIT_GENESIS_HASH.to_string());
            let window = rows
                .iter()
                .filter(|(seq, _, _)| *seq >= from)
                .take(limit as usize)
                .cloned()
                .collect();
            Ok(AuditChainWindow { head, rows: window })
        }

        async fn get_policy(&self) -> Result<Option<StoredPolicy>, StoreError> {
            Ok(self.policy.lock().unwrap().clone())
        }

        async fn set_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
            *self.policy.lock().unwrap() = Some(policy.clone());
            Ok(())
        }

        async fn seed_policy(&self, policy: &StoredPolicy) -> Result<bool, StoreError> {
            let mut slot = self.policy.lock().unwrap();
            if slot.is_some() {
                return Ok(false);
            }
            *slot = Some(policy.clone());
            Ok(true)
        }

        async fn list_audit(
            &self,
            filter: &AuditFilter,
        ) -> Result<(Vec<(u64, AuditEvent)>, Option<u64>), StoreError> {
            let limit = filter.effective_limit() as usize;
            let mut rows: Vec<(u64, AuditEvent)> = self
                .audit
                .lock()
                .unwrap()
                .iter()
                .filter(|(seq, e, _)| filter.cursor.is_none_or(|c| *seq < c) && filter.matches(e))
                .map(|(seq, e, _)| (*seq, e.clone()))
                .collect();
            // Newest first; insertion order is ascending seq.
            rows.reverse();
            // Fetch one row beyond the page to know whether more exist.
            let next_cursor = if rows.len() > limit {
                rows.truncate(limit);
                rows.last().map(|(seq, _)| *seq)
            } else {
                None
            };
            Ok((rows, next_cursor))
        }

        async fn create_local_user(
            &self,
            username: &str,
            email: Option<&str>,
            password_hash: &str,
            role: mobula_core::LocalRole,
        ) -> Result<(), StoreError> {
            let mut map = self.local_users.lock().unwrap();
            if map.contains_key(username) {
                return Err(StoreError::Backend(format!(
                    "local user {username} already exists"
                )));
            }
            map.insert(
                username.to_string(),
                LocalUserRecord {
                    username: username.to_string(),
                    email: email.map(String::from),
                    password_hash: password_hash.to_string(),
                    role,
                    disabled: false,
                    created_at: now_unix(),
                    failed_logins: 0,
                    locked_until: None,
                },
            );
            Ok(())
        }

        async fn get_local_user(
            &self,
            username: &str,
        ) -> Result<Option<LocalUserRecord>, StoreError> {
            Ok(self.local_users.lock().unwrap().get(username).cloned())
        }

        async fn list_local_users(&self) -> Result<Vec<LocalUserRecord>, StoreError> {
            let mut users: Vec<LocalUserRecord> =
                self.local_users.lock().unwrap().values().cloned().collect();
            users.sort_by(|a, b| a.username.cmp(&b.username));
            Ok(users)
        }

        async fn set_local_user_password(
            &self,
            username: &str,
            password_hash: &str,
        ) -> Result<(), StoreError> {
            let mut map = self.local_users.lock().unwrap();
            let user = map
                .get_mut(username)
                .ok_or_else(|| StoreError::Backend(format!("no such local user {username}")))?;
            user.password_hash = password_hash.to_string();
            Ok(())
        }

        async fn set_local_user_role(
            &self,
            username: &str,
            role: mobula_core::LocalRole,
        ) -> Result<(), StoreError> {
            let mut map = self.local_users.lock().unwrap();
            let user = map
                .get_mut(username)
                .ok_or_else(|| StoreError::Backend(format!("no such local user {username}")))?;
            user.role = role;
            Ok(())
        }

        async fn set_local_user_disabled(
            &self,
            username: &str,
            disabled: bool,
        ) -> Result<(), StoreError> {
            let mut map = self.local_users.lock().unwrap();
            let user = map
                .get_mut(username)
                .ok_or_else(|| StoreError::Backend(format!("no such local user {username}")))?;
            user.disabled = disabled;
            Ok(())
        }

        async fn set_login_lockout(
            &self,
            username: &str,
            failed_logins: u32,
            locked_until: Option<u64>,
        ) -> Result<(), StoreError> {
            let mut map = self.local_users.lock().unwrap();
            let user = map
                .get_mut(username)
                .ok_or_else(|| StoreError::Backend(format!("no such local user {username}")))?;
            user.failed_logins = failed_logins;
            user.locked_until = locked_until;
            Ok(())
        }

        async fn create_api_token(&self, record: ApiTokenRecord) -> Result<(), StoreError> {
            let mut map = self.api_tokens.lock().unwrap();
            if map.contains_key(&record.prefix) {
                return Err(StoreError::Backend(format!(
                    "api token prefix {} already exists",
                    record.prefix
                )));
            }
            map.insert(record.prefix.clone(), record);
            Ok(())
        }

        async fn get_api_token_by_prefix(
            &self,
            prefix: &str,
        ) -> Result<Option<ApiTokenRecord>, StoreError> {
            Ok(self.api_tokens.lock().unwrap().get(prefix).cloned())
        }

        async fn list_api_tokens(&self, username: &str) -> Result<Vec<ApiTokenRecord>, StoreError> {
            let mut tokens: Vec<ApiTokenRecord> = self
                .api_tokens
                .lock()
                .unwrap()
                .values()
                .filter(|t| t.username == username)
                .cloned()
                .collect();
            tokens.sort_by_key(|t| std::cmp::Reverse(t.created_at));
            Ok(tokens)
        }

        async fn revoke_api_token(&self, prefix: &str, username: &str) -> Result<(), StoreError> {
            let mut map = self.api_tokens.lock().unwrap();
            match map.get_mut(prefix) {
                Some(token) if token.username == username => {
                    token.revoked = true;
                    Ok(())
                }
                _ => Err(StoreError::Backend(format!("no such api token {prefix}"))),
            }
        }

        async fn touch_api_token(&self, prefix: &str, now: u64) -> Result<(), StoreError> {
            if let Some(token) = self.api_tokens.lock().unwrap().get_mut(prefix) {
                token.last_used_at = Some(now);
            }
            Ok(())
        }

        async fn upsert_role_assignment(
            &self,
            principal: &str,
            role: &str,
            scope: &str,
        ) -> Result<(), StoreError> {
            let mut map = self.assignments.lock().unwrap();
            let key = (principal.to_string(), role.to_string(), scope.to_string());
            // Re-upsert preserves the original created_at.
            let created_at = map.get(&key).map(|a| a.created_at).unwrap_or_else(now_unix);
            map.insert(
                key,
                RoleAssignment {
                    principal: principal.to_string(),
                    role: role.to_string(),
                    scope: scope.to_string(),
                    created_at,
                },
            );
            Ok(())
        }

        async fn list_role_assignments(
            &self,
            principal: Option<&str>,
        ) -> Result<Vec<RoleAssignment>, StoreError> {
            let mut out: Vec<RoleAssignment> = self
                .assignments
                .lock()
                .unwrap()
                .values()
                .filter(|a| principal.is_none_or(|p| a.principal == p))
                .cloned()
                .collect();
            out.sort_by(|a, b| {
                a.principal
                    .cmp(&b.principal)
                    .then(a.scope.cmp(&b.scope))
                    .then(a.role.cmp(&b.role))
            });
            Ok(out)
        }

        async fn delete_role_assignment(
            &self,
            principal: &str,
            role: &str,
            scope: &str,
        ) -> Result<(), StoreError> {
            let key = (principal.to_string(), role.to_string(), scope.to_string());
            if self.assignments.lock().unwrap().remove(&key).is_none() {
                return Err(StoreError::Backend(format!(
                    "no such assignment {principal}/{role}/{scope}"
                )));
            }
            Ok(())
        }
    }
}

/// Test-only [`Store`] that delegates to [`memory::InMemoryStore`] but fails
/// the named methods with an injected backend error — for exercising the
/// reconcile/metering loops' per-tick error discipline (log, skip, never
/// fatal).
#[cfg(test)]
pub(crate) mod testkit {
    use super::memory::InMemoryStore;
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    pub(crate) struct FailingStore {
        inner: InMemoryStore,
        fail: Mutex<BTreeSet<&'static str>>,
    }

    impl FailingStore {
        pub(crate) fn new() -> Self {
            Self {
                inner: InMemoryStore::new(),
                fail: Mutex::new(BTreeSet::new()),
            }
        }

        /// Make `method` (a `Store` method name) fail from now on.
        pub(crate) fn fail(&self, method: &'static str) {
            self.fail.lock().unwrap().insert(method);
        }

        fn check(&self, method: &'static str) -> Result<(), StoreError> {
            if self.fail.lock().unwrap().contains(method) {
                Err(StoreError::Backend(format!("injected {method} failure")))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl Store for FailingStore {
        async fn upsert_desired(
            &self,
            id: &ClusterId,
            spec: ClusterSpec,
        ) -> Result<u64, StoreError> {
            self.check("upsert_desired")?;
            self.inner.upsert_desired(id, spec).await
        }
        async fn get(&self, id: &ClusterId) -> Result<Option<StoredCluster>, StoreError> {
            self.check("get")?;
            self.inner.get(id).await
        }
        async fn list(&self) -> Result<Vec<StoredCluster>, StoreError> {
            self.check("list")?;
            self.inner.list().await
        }
        async fn set_desired(
            &self,
            id: &ClusterId,
            desired: DesiredState,
        ) -> Result<(), StoreError> {
            self.check("set_desired")?;
            self.inner.set_desired(id, desired).await
        }
        async fn record_observation(
            &self,
            id: &ClusterId,
            observed: Option<ClusterState>,
            observed_generation: u64,
        ) -> Result<(), StoreError> {
            self.check("record_observation")?;
            self.inner
                .record_observation(id, observed, observed_generation)
                .await
        }
        async fn set_condition(
            &self,
            id: &ClusterId,
            condition: Option<DriftCondition>,
        ) -> Result<(), StoreError> {
            self.check("set_condition")?;
            self.inner.set_condition(id, condition).await
        }
        async fn is_quarantined(&self) -> Result<bool, StoreError> {
            self.check("is_quarantined")?;
            self.inner.is_quarantined().await
        }
        async fn set_quarantine(&self, quarantined: bool) -> Result<(), StoreError> {
            self.check("set_quarantine")?;
            self.inner.set_quarantine(quarantined).await
        }
        async fn record_attempt(
            &self,
            id: &ClusterId,
            failure_count: u32,
            next_attempt_at: u64,
        ) -> Result<(), StoreError> {
            self.check("record_attempt")?;
            self.inner
                .record_attempt(id, failure_count, next_attempt_at)
                .await
        }
        async fn begin_intent(
            &self,
            key: &str,
            fingerprint: &str,
        ) -> Result<IntentOutcome, StoreError> {
            self.check("begin_intent")?;
            self.inner.begin_intent(key, fingerprint).await
        }
        async fn complete_intent(&self, key: &str, response_json: &str) -> Result<(), StoreError> {
            self.check("complete_intent")?;
            self.inner.complete_intent(key, response_json).await
        }
        async fn get_intent(&self, key: &str) -> Result<Option<IntentRecord>, StoreError> {
            self.check("get_intent")?;
            self.inner.get_intent(key).await
        }
        async fn reap_intents(&self, applied_before: u64) -> Result<u64, StoreError> {
            self.check("reap_intents")?;
            self.inner.reap_intents(applied_before).await
        }
        async fn record_job(&self, job: JobRecord) -> Result<(), StoreError> {
            self.check("record_job")?;
            self.inner.record_job(job).await
        }
        async fn list_jobs(&self) -> Result<Vec<JobRecord>, StoreError> {
            self.check("list_jobs")?;
            self.inner.list_jobs().await
        }
        async fn upsert_pool(&self, name: &str, spec: PoolSpec) -> Result<u64, StoreError> {
            self.check("upsert_pool")?;
            self.inner.upsert_pool(name, spec).await
        }
        async fn get_pool(&self, name: &str) -> Result<Option<StoredPool>, StoreError> {
            self.check("get_pool")?;
            self.inner.get_pool(name).await
        }
        async fn list_pools(&self) -> Result<Vec<StoredPool>, StoreError> {
            self.check("list_pools")?;
            self.inner.list_pools().await
        }
        async fn delete_pool(&self, name: &str) -> Result<(), StoreError> {
            self.check("delete_pool")?;
            self.inner.delete_pool(name).await
        }
        async fn record_pool_observation(
            &self,
            name: &str,
            observed_json: &str,
        ) -> Result<(), StoreError> {
            self.check("record_pool_observation")?;
            self.inner
                .record_pool_observation(name, observed_json)
                .await
        }
        async fn upsert_allocation(&self, alloc: AllocationSpec) -> Result<(), StoreError> {
            self.check("upsert_allocation")?;
            self.inner.upsert_allocation(alloc).await
        }
        async fn list_allocations(&self, pool: &str) -> Result<Vec<AllocationSpec>, StoreError> {
            self.check("list_allocations")?;
            self.inner.list_allocations(pool).await
        }
        async fn delete_allocation(&self, pool: &str, project: &str) -> Result<(), StoreError> {
            self.check("delete_allocation")?;
            self.inner.delete_allocation(pool, project).await
        }
        async fn record_usage_samples(&self, samples: &[UsageSample]) -> Result<(), StoreError> {
            self.check("record_usage_samples")?;
            self.inner.record_usage_samples(samples).await
        }
        async fn usage_samples(
            &self,
            project: Option<&str>,
            pool: Option<&str>,
            from: u64,
            to: u64,
        ) -> Result<Vec<UsageSample>, StoreError> {
            self.check("usage_samples")?;
            self.inner.usage_samples(project, pool, from, to).await
        }
        async fn record_audit(&self, event: &AuditEvent) -> Result<u64, StoreError> {
            self.check("record_audit")?;
            self.inner.record_audit(event).await
        }
        async fn audit_chain(
            &self,
            from_seq: Option<u64>,
            limit: u32,
        ) -> Result<AuditChainWindow, StoreError> {
            self.check("audit_chain")?;
            self.inner.audit_chain(from_seq, limit).await
        }
        async fn get_policy(&self) -> Result<Option<StoredPolicy>, StoreError> {
            self.check("get_policy")?;
            self.inner.get_policy().await
        }
        async fn set_policy(&self, policy: &StoredPolicy) -> Result<(), StoreError> {
            self.check("set_policy")?;
            self.inner.set_policy(policy).await
        }
        async fn seed_policy(&self, policy: &StoredPolicy) -> Result<bool, StoreError> {
            self.check("seed_policy")?;
            self.inner.seed_policy(policy).await
        }
        async fn list_audit(
            &self,
            filter: &AuditFilter,
        ) -> Result<(Vec<(u64, AuditEvent)>, Option<u64>), StoreError> {
            self.check("list_audit")?;
            self.inner.list_audit(filter).await
        }
        async fn create_local_user(
            &self,
            username: &str,
            email: Option<&str>,
            password_hash: &str,
            role: mobula_core::LocalRole,
        ) -> Result<(), StoreError> {
            self.check("create_local_user")?;
            self.inner
                .create_local_user(username, email, password_hash, role)
                .await
        }
        async fn get_local_user(
            &self,
            username: &str,
        ) -> Result<Option<LocalUserRecord>, StoreError> {
            self.check("get_local_user")?;
            self.inner.get_local_user(username).await
        }
        async fn list_local_users(&self) -> Result<Vec<LocalUserRecord>, StoreError> {
            self.check("list_local_users")?;
            self.inner.list_local_users().await
        }
        async fn set_local_user_password(
            &self,
            username: &str,
            password_hash: &str,
        ) -> Result<(), StoreError> {
            self.check("set_local_user_password")?;
            self.inner
                .set_local_user_password(username, password_hash)
                .await
        }
        async fn set_local_user_role(
            &self,
            username: &str,
            role: mobula_core::LocalRole,
        ) -> Result<(), StoreError> {
            self.check("set_local_user_role")?;
            self.inner.set_local_user_role(username, role).await
        }
        async fn set_local_user_disabled(
            &self,
            username: &str,
            disabled: bool,
        ) -> Result<(), StoreError> {
            self.check("set_local_user_disabled")?;
            self.inner.set_local_user_disabled(username, disabled).await
        }
        async fn set_login_lockout(
            &self,
            username: &str,
            failed_logins: u32,
            locked_until: Option<u64>,
        ) -> Result<(), StoreError> {
            self.check("set_login_lockout")?;
            self.inner
                .set_login_lockout(username, failed_logins, locked_until)
                .await
        }
        async fn record_login_failure(&self, username: &str) -> Result<(), StoreError> {
            self.check("record_login_failure")?;
            self.inner.record_login_failure(username).await
        }
        async fn record_login_success(&self, username: &str) -> Result<(), StoreError> {
            self.check("record_login_success")?;
            self.inner.record_login_success(username).await
        }
        async fn create_api_token(&self, record: ApiTokenRecord) -> Result<(), StoreError> {
            self.check("create_api_token")?;
            self.inner.create_api_token(record).await
        }
        async fn get_api_token_by_prefix(
            &self,
            prefix: &str,
        ) -> Result<Option<ApiTokenRecord>, StoreError> {
            self.check("get_api_token_by_prefix")?;
            self.inner.get_api_token_by_prefix(prefix).await
        }
        async fn list_api_tokens(&self, username: &str) -> Result<Vec<ApiTokenRecord>, StoreError> {
            self.check("list_api_tokens")?;
            self.inner.list_api_tokens(username).await
        }
        async fn revoke_api_token(&self, prefix: &str, username: &str) -> Result<(), StoreError> {
            self.check("revoke_api_token")?;
            self.inner.revoke_api_token(prefix, username).await
        }
        async fn touch_api_token(&self, prefix: &str, now: u64) -> Result<(), StoreError> {
            self.check("touch_api_token")?;
            self.inner.touch_api_token(prefix, now).await
        }
        async fn upsert_role_assignment(
            &self,
            principal: &str,
            role: &str,
            scope: &str,
        ) -> Result<(), StoreError> {
            self.check("upsert_role_assignment")?;
            self.inner
                .upsert_role_assignment(principal, role, scope)
                .await
        }
        async fn list_role_assignments(
            &self,
            principal: Option<&str>,
        ) -> Result<Vec<RoleAssignment>, StoreError> {
            self.check("list_role_assignments")?;
            self.inner.list_role_assignments(principal).await
        }
        async fn delete_role_assignment(
            &self,
            principal: &str,
            role: &str,
            scope: &str,
        ) -> Result<(), StoreError> {
            self.check("delete_role_assignment")?;
            self.inner
                .delete_role_assignment(principal, role, scope)
                .await
        }
    }
}
