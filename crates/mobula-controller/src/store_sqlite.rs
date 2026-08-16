//! SQLite-backed `Store` (ADR-0004: Postgres is truth in prod; SQLite for
//! single-node dev). Uses runtime queries — no compile-time `DATABASE_URL`.
//!
//! Spec and enums are stored as JSON text so the schema stays portable to
//! Postgres (the SQL is standard); a Postgres impl reuses this shape.

use async_trait::async_trait;
use mobula_core::{
    AllocationSpec, AuditDecision, AuditEvent, AuditFilter, AuditRequired, ClusterId, ClusterSpec,
    ClusterState, DriftCondition, PoolSpec,
};
use sqlx::sqlite::{SqlitePoolOptions, SqliteRow};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

use mobula_core::JobRecord;

use crate::store::{
    now_unix, pool_spec_changed, spec_changed, DesiredState, IntentOutcome, IntentRecord,
    IntentStatus, Store, StoreError, StoredCluster, StoredPool, UsageSample, UsageSource,
};

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        StoreError::Backend(e.to_string())
    }
}

fn json_err(e: serde_json::Error) -> StoreError {
    StoreError::Backend(format!("serialization: {e}"))
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS clusters (
    id                    TEXT PRIMARY KEY,
    spec_json             TEXT NOT NULL,
    generation            INTEGER NOT NULL,
    desired               TEXT NOT NULL,
    observed_state        TEXT,
    observed_generation   INTEGER NOT NULL DEFAULT 0,
    condition             TEXT,
    failure_count         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at       INTEGER NOT NULL DEFAULT 0,
    created_at            INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS intents (
    intent_key         TEXT PRIMARY KEY,
    params_fingerprint TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'applied',
    response_json      TEXT,
    created_at         INTEGER NOT NULL DEFAULT 0,
    completed_at       INTEGER
);
-- Singleton control flags (e.g. restore quarantine, #41).
CREATE TABLE IF NOT EXISTS control (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Persistent job history (Phase 3, #20). Deliberately has NO foreign key to
-- clusters: records outlive the clusters that ran them.
CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    cluster       TEXT NOT NULL,
    submitter     TEXT NOT NULL,
    status        TEXT NOT NULL,
    duration_secs INTEGER,
    submitted_at  INTEGER NOT NULL
);
-- Capacity pools (ADR-0010): the store is truth; Kueue objects are
-- actuation. Spec as JSON text so the SQL ports to Postgres unchanged.
-- observed_json holds the pool reconcile loop's last ClusterQueue status
-- observation (opaque JSON).
CREATE TABLE IF NOT EXISTS pools (
    name          TEXT PRIMARY KEY,
    spec_json     TEXT NOT NULL,
    generation    INTEGER NOT NULL,
    observed_json TEXT,
    created_at    INTEGER NOT NULL DEFAULT 0
);
-- Per-project allocations within a pool (ADR-0010), keyed by (pool, project).
CREATE TABLE IF NOT EXISTS allocations (
    pool      TEXT NOT NULL,
    project   TEXT NOT NULL,
    spec_json TEXT NOT NULL,
    PRIMARY KEY (pool, project)
);
-- Usage metering timeseries (Slice 4): append-only, no primary key. Plain
-- columns (query-facing, unlike the spec tables) with standard SQL that
-- ports to Postgres unchanged. `project = ''` is the pool-level aggregate
-- row; `pool = ''` means the project has no allocation. `source` is
-- 'kueue_ledger' or 'observed_spec' (UsageSource).
CREATE TABLE IF NOT EXISTS usage_samples (
    ts       INTEGER NOT NULL,
    project  TEXT NOT NULL,
    pool     TEXT NOT NULL,
    resource TEXT NOT NULL,
    quantity REAL NOT NULL,
    source   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_samples_project_ts ON usage_samples (project, ts);
-- Persisted audit trail (api-v1.md §5.9): append-only. `seq` is the
-- pagination cursor (rows are read newest-first). Filter-facing fields are
-- plain columns; `required_json` keeps the spec's JSON-text convention.
-- Postgres port: `INTEGER PRIMARY KEY AUTOINCREMENT` becomes an identity
-- column; the SELECT/INSERT statements below are standard SQL.
CREATE TABLE IF NOT EXISTS audit_events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    subject       TEXT,
    decision      TEXT NOT NULL,
    reason        TEXT,
    action        TEXT,
    cluster       TEXT,
    method        TEXT,
    path          TEXT,
    status        INTEGER,
    latency_ms    INTEGER,
    required_json TEXT,
    granted_roles TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events (ts);
"#;

/// Additive column migrations for databases created by an older schema (#39
/// outbox columns, #41 cluster condition). Each is idempotent: on a fresh DB
/// the column already exists and SQLite errors with "duplicate column name",
/// which we ignore. Ordering doesn't matter (all independent).
const COLUMN_MIGRATIONS: &[&str] = &[
    "ALTER TABLE intents ADD COLUMN params_fingerprint TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE intents ADD COLUMN status TEXT NOT NULL DEFAULT 'applied'",
    "ALTER TABLE intents ADD COLUMN response_json TEXT",
    "ALTER TABLE intents ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE intents ADD COLUMN completed_at INTEGER",
    "ALTER TABLE clusters ADD COLUMN condition TEXT",
    "ALTER TABLE clusters ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE clusters ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE pools ADD COLUMN observed_json TEXT",
    "ALTER TABLE pools ADD COLUMN observed_at INTEGER",
];

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    async fn init(pool: &SqlitePool) -> Result<(), StoreError> {
        // Wait for the write lock rather than failing SQLITE_BUSY under
        // concurrent writers (#42) — matters for the file/multi-connection
        // deployment; harmless for the single-connection in-memory store.
        sqlx::query("PRAGMA busy_timeout = 5000")
            .execute(pool)
            .await?;
        sqlx::query(SCHEMA).execute(pool).await?;
        for m in COLUMN_MIGRATIONS {
            // Ignore "duplicate column name" on fresh DBs; surface anything else.
            if let Err(e) = sqlx::query(m).execute(pool).await {
                let msg = e.to_string();
                if !msg.contains("duplicate column name") {
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    /// Connect (creating the file if needed) and apply the schema.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new().connect(url).await?;
        Self::init(&pool).await?;
        Ok(Self { pool })
    }

    /// A private in-memory database for tests. `max_connections(1)` keeps
    /// the single in-memory DB alive and consistent across calls.
    pub async fn in_memory() -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        Self::init(&pool).await?;
        Ok(Self { pool })
    }
}

fn intent_status_from_str(s: &str) -> IntentStatus {
    match s {
        "pending" => IntentStatus::Pending,
        _ => IntentStatus::Applied,
    }
}

fn desired_to_str(d: DesiredState) -> &'static str {
    match d {
        DesiredState::Running => "running",
        DesiredState::Terminated => "terminated",
    }
}

fn desired_from_str(s: &str) -> Result<DesiredState, StoreError> {
    match s {
        "running" => Ok(DesiredState::Running),
        "terminated" => Ok(DesiredState::Terminated),
        other => Err(StoreError::Backend(format!("bad desired state {other:?}"))),
    }
}

fn row_to_cluster(row: SqliteRow) -> Result<StoredCluster, StoreError> {
    let spec_json: String = row.try_get("spec_json")?;
    let spec: ClusterSpec = serde_json::from_str(&spec_json).map_err(json_err)?;
    let observed_json: Option<String> = row.try_get("observed_state")?;
    let observed_state = match observed_json {
        Some(s) => Some(serde_json::from_str::<ClusterState>(&s).map_err(json_err)?),
        None => None,
    };
    let condition = match row.try_get::<Option<String>, _>("condition")? {
        Some(s) => Some(serde_json::from_str::<DriftCondition>(&s).map_err(json_err)?),
        None => None,
    };
    Ok(StoredCluster {
        id: ClusterId(row.try_get::<String, _>("id")?),
        spec,
        generation: row.try_get::<i64, _>("generation")? as u64,
        desired: desired_from_str(&row.try_get::<String, _>("desired")?)?,
        observed_state,
        observed_generation: row.try_get::<i64, _>("observed_generation")? as u64,
        condition,
        failure_count: row.try_get::<i64, _>("failure_count")? as u32,
        next_attempt_at: row.try_get::<i64, _>("next_attempt_at")? as u64,
        created_at: row.try_get::<i64, _>("created_at")? as u64,
    })
}

fn row_to_pool(row: SqliteRow) -> Result<StoredPool, StoreError> {
    let spec_json: String = row.try_get("spec_json")?;
    let spec: PoolSpec = serde_json::from_str(&spec_json).map_err(json_err)?;
    Ok(StoredPool {
        name: row.try_get::<String, _>("name")?,
        spec,
        generation: row.try_get::<i64, _>("generation")? as u64,
        observed_json: row.try_get::<Option<String>, _>("observed_json")?,
        observed_at: row
            .try_get::<Option<i64>, _>("observed_at")?
            .map(|v| v as u64),
        created_at: row.try_get::<i64, _>("created_at")? as u64,
    })
}

#[async_trait]
impl Store for SqliteStore {
    async fn upsert_desired(&self, id: &ClusterId, spec: ClusterSpec) -> Result<u64, StoreError> {
        // BEGIN IMMEDIATE takes the write lock at transaction start (#42), so
        // two concurrent upserts on the same id are serialized: the second
        // blocks until the first commits and then reads the already-bumped
        // generation, instead of both reading gen=N under a DEFERRED tx and
        // collapsing two spec changes into one bump. `pool.begin()` is
        // DEFERRED (read lock, upgraded lazily) and cannot give this.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let result: Result<u64, StoreError> = async {
            let existing = sqlx::query("SELECT spec_json, generation FROM clusters WHERE id = ?")
                .bind(&id.0)
                .fetch_optional(&mut *conn)
                .await?;

            let generation: u64 = match existing {
                Some(row) => {
                    let cur_json: String = row.try_get("spec_json")?;
                    let cur: ClusterSpec = serde_json::from_str(&cur_json).map_err(json_err)?;
                    let gen: i64 = row.try_get("generation")?;
                    if spec_changed(&cur, &spec) {
                        gen as u64 + 1
                    } else {
                        gen as u64
                    }
                }
                None => 1,
            };

            let spec_json = serde_json::to_string(&spec).map_err(json_err)?;
            // Keep desired/observed on update; default desired=running on insert.
            sqlx::query(
                r#"
                INSERT INTO clusters (id, spec_json, generation, desired, observed_generation, created_at)
                VALUES (?, ?, ?, 'running', 0, ?)
                ON CONFLICT(id) DO UPDATE SET
                    spec_json = excluded.spec_json,
                    generation = excluded.generation
                "#,
            )
            .bind(&id.0)
            .bind(&spec_json)
            .bind(generation as i64)
            .bind(now_unix() as i64)
            .execute(&mut *conn)
            .await?;
            Ok(generation)
        }
        .await;

        match result {
            Ok(generation) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(generation)
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    async fn get(&self, id: &ClusterId) -> Result<Option<StoredCluster>, StoreError> {
        let row = sqlx::query("SELECT * FROM clusters WHERE id = ?")
            .bind(&id.0)
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_cluster).transpose()
    }

    async fn list(&self) -> Result<Vec<StoredCluster>, StoreError> {
        let rows = sqlx::query("SELECT * FROM clusters")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_cluster).collect()
    }

    async fn set_desired(&self, id: &ClusterId, desired: DesiredState) -> Result<(), StoreError> {
        let affected = sqlx::query("UPDATE clusters SET desired = ? WHERE id = ?")
            .bind(desired_to_str(desired))
            .bind(&id.0)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(StoreError::Backend(format!("no such cluster {id}")));
        }
        Ok(())
    }

    async fn record_observation(
        &self,
        id: &ClusterId,
        observed: Option<ClusterState>,
        observed_generation: u64,
    ) -> Result<(), StoreError> {
        let observed_json = match observed {
            Some(s) => Some(serde_json::to_string(&s).map_err(json_err)?),
            None => None,
        };
        // MAX() keeps observed_generation monotonic (#41 stale-generation
        // fence): a restore reporting an older generation can't roll it back.
        sqlx::query(
            "UPDATE clusters \
             SET observed_state = ?, observed_generation = MAX(observed_generation, ?) \
             WHERE id = ?",
        )
        .bind(observed_json)
        .bind(observed_generation as i64)
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_condition(
        &self,
        id: &ClusterId,
        condition: Option<DriftCondition>,
    ) -> Result<(), StoreError> {
        let condition_json = match condition {
            Some(c) => Some(serde_json::to_string(&c).map_err(json_err)?),
            None => None,
        };
        sqlx::query("UPDATE clusters SET condition = ? WHERE id = ?")
            .bind(condition_json)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn is_quarantined(&self) -> Result<bool, StoreError> {
        let v: Option<String> = sqlx::query("SELECT value FROM control WHERE key = 'quarantine'")
            .fetch_optional(&self.pool)
            .await?
            .map(|row| row.try_get::<String, _>("value"))
            .transpose()?;
        Ok(v.as_deref() == Some("true"))
    }

    async fn set_quarantine(&self, quarantined: bool) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO control (key, value) VALUES ('quarantine', ?) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(if quarantined { "true" } else { "false" })
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_attempt(
        &self,
        id: &ClusterId,
        failure_count: u32,
        next_attempt_at: u64,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE clusters SET failure_count = ?, next_attempt_at = ? WHERE id = ?")
            .bind(failure_count as i64)
            .bind(next_attempt_at as i64)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn begin_intent(
        &self,
        key: &str,
        fingerprint: &str,
    ) -> Result<IntentOutcome, StoreError> {
        // Atomic open under BEGIN IMMEDIATE so two reconcilers can't both
        // treat the same key as fresh. Insert a pending row if absent;
        // otherwise classify against the stored fingerprint.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let result: Result<IntentOutcome, StoreError> = async {
            let existing: Option<String> =
                sqlx::query("SELECT params_fingerprint FROM intents WHERE intent_key = ?")
                    .bind(key)
                    .fetch_optional(&mut *conn)
                    .await?
                    .map(|row| row.try_get::<String, _>("params_fingerprint"))
                    .transpose()?;
            match existing {
                Some(fp) if fp != fingerprint => Ok(IntentOutcome::ParamMismatch),
                Some(_) => Ok(IntentOutcome::Proceed { replay: true }),
                None => {
                    sqlx::query(
                        "INSERT INTO intents (intent_key, params_fingerprint, status, created_at) \
                         VALUES (?, ?, 'pending', ?)",
                    )
                    .bind(key)
                    .bind(fingerprint)
                    .bind(now_unix() as i64)
                    .execute(&mut *conn)
                    .await?;
                    Ok(IntentOutcome::Proceed { replay: false })
                }
            }
        }
        .await;

        match result {
            Ok(outcome) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(outcome)
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    async fn complete_intent(&self, key: &str, response_json: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE intents SET status = 'applied', response_json = ?, completed_at = ? \
             WHERE intent_key = ?",
        )
        .bind(response_json)
        .bind(now_unix() as i64)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_intent(&self, key: &str) -> Result<Option<IntentRecord>, StoreError> {
        let row = sqlx::query("SELECT * FROM intents WHERE intent_key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok::<_, StoreError>(IntentRecord {
                key: row.try_get::<String, _>("intent_key")?,
                params_fingerprint: row.try_get::<String, _>("params_fingerprint")?,
                status: intent_status_from_str(&row.try_get::<String, _>("status")?),
                response_json: row.try_get::<Option<String>, _>("response_json")?,
                created_at: row.try_get::<i64, _>("created_at")? as u64,
                completed_at: row
                    .try_get::<Option<i64>, _>("completed_at")?
                    .map(|v| v as u64),
            })
        })
        .transpose()
    }

    async fn reap_intents(&self, applied_before: u64) -> Result<u64, StoreError> {
        let affected = sqlx::query(
            "DELETE FROM intents WHERE status = 'applied' \
             AND completed_at IS NOT NULL AND completed_at < ?",
        )
        .bind(applied_before as i64)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected)
    }

    async fn record_job(&self, job: JobRecord) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO jobs (id, cluster, submitter, status, duration_secs, submitted_at) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET status = excluded.status, \
                 duration_secs = excluded.duration_secs",
        )
        .bind(&job.id)
        .bind(&job.cluster)
        .bind(&job.submitter)
        .bind(&job.status)
        .bind(job.duration_secs.map(|d| d as i64))
        .bind(job.submitted_at as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_jobs(&self) -> Result<Vec<JobRecord>, StoreError> {
        let rows = sqlx::query("SELECT * FROM jobs ORDER BY submitted_at DESC")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok::<_, StoreError>(JobRecord {
                    id: row.try_get::<String, _>("id")?,
                    cluster: row.try_get::<String, _>("cluster")?,
                    submitter: row.try_get::<String, _>("submitter")?,
                    status: row.try_get::<String, _>("status")?,
                    duration_secs: row
                        .try_get::<Option<i64>, _>("duration_secs")?
                        .map(|d| d as u64),
                    submitted_at: row.try_get::<i64, _>("submitted_at")? as u64,
                })
            })
            .collect()
    }

    async fn upsert_pool(&self, name: &str, spec: PoolSpec) -> Result<u64, StoreError> {
        // Same BEGIN IMMEDIATE discipline as upsert_desired (#42): two
        // concurrent pool updates serialize, each seeing the other's bump.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let result: Result<u64, StoreError> = async {
            let existing = sqlx::query("SELECT spec_json, generation FROM pools WHERE name = ?")
                .bind(name)
                .fetch_optional(&mut *conn)
                .await?;

            let generation: u64 = match existing {
                Some(row) => {
                    let cur_json: String = row.try_get("spec_json")?;
                    let cur: PoolSpec = serde_json::from_str(&cur_json).map_err(json_err)?;
                    let gen: i64 = row.try_get("generation")?;
                    if pool_spec_changed(&cur, &spec) {
                        gen as u64 + 1
                    } else {
                        gen as u64
                    }
                }
                None => 1,
            };

            let spec_json = serde_json::to_string(&spec).map_err(json_err)?;
            // Keep created_at on update; set it on insert.
            sqlx::query(
                r#"
                INSERT INTO pools (name, spec_json, generation, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    spec_json = excluded.spec_json,
                    generation = excluded.generation
                "#,
            )
            .bind(name)
            .bind(&spec_json)
            .bind(generation as i64)
            .bind(now_unix() as i64)
            .execute(&mut *conn)
            .await?;
            Ok(generation)
        }
        .await;

        match result {
            Ok(generation) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(generation)
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    async fn get_pool(&self, name: &str) -> Result<Option<StoredPool>, StoreError> {
        let row = sqlx::query("SELECT * FROM pools WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_pool).transpose()
    }

    async fn list_pools(&self) -> Result<Vec<StoredPool>, StoreError> {
        let rows = sqlx::query("SELECT * FROM pools")
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_pool).collect()
    }

    async fn delete_pool(&self, name: &str) -> Result<(), StoreError> {
        let affected = sqlx::query("DELETE FROM pools WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(StoreError::Backend(format!("no such pool {name}")));
        }
        Ok(())
    }

    async fn record_pool_observation(
        &self,
        name: &str,
        observed_json: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE pools SET observed_json = ?, observed_at = ? WHERE name = ?")
            .bind(observed_json)
            .bind(now_unix() as i64)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn upsert_allocation(&self, alloc: AllocationSpec) -> Result<(), StoreError> {
        let spec_json = serde_json::to_string(&alloc).map_err(json_err)?;
        sqlx::query(
            r#"
            INSERT INTO allocations (pool, project, spec_json)
            VALUES (?, ?, ?)
            ON CONFLICT(pool, project) DO UPDATE SET spec_json = excluded.spec_json
            "#,
        )
        .bind(&alloc.pool)
        .bind(&alloc.project)
        .bind(&spec_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_allocations(&self, pool: &str) -> Result<Vec<AllocationSpec>, StoreError> {
        let rows = sqlx::query("SELECT spec_json FROM allocations WHERE pool = ?")
            .bind(pool)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter()
            .map(|row| {
                let spec_json: String = row.try_get("spec_json")?;
                serde_json::from_str::<AllocationSpec>(&spec_json).map_err(json_err)
            })
            .collect()
    }

    async fn delete_allocation(&self, pool: &str, project: &str) -> Result<(), StoreError> {
        let affected = sqlx::query("DELETE FROM allocations WHERE pool = ? AND project = ?")
            .bind(pool)
            .bind(project)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(StoreError::Backend(format!(
                "no such allocation {pool}/{project}"
            )));
        }
        Ok(())
    }

    async fn record_usage_samples(&self, samples: &[UsageSample]) -> Result<(), StoreError> {
        // One transaction per batch so a tick's samples land atomically.
        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result: Result<(), StoreError> = async {
            for s in samples {
                sqlx::query(
                    "INSERT INTO usage_samples (ts, project, pool, resource, quantity, source) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                )
                .bind(s.ts as i64)
                .bind(&s.project)
                .bind(&s.pool)
                .bind(&s.resource)
                .bind(s.quantity)
                .bind(s.source.as_str())
                .execute(&mut *conn)
                .await?;
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                sqlx::query("COMMIT").execute(&mut *conn).await?;
                Ok(())
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                Err(e)
            }
        }
    }

    async fn usage_samples(
        &self,
        project: Option<&str>,
        pool: Option<&str>,
        from: u64,
        to: u64,
    ) -> Result<Vec<UsageSample>, StoreError> {
        let rows = sqlx::query(
            "SELECT ts, project, pool, resource, quantity, source FROM usage_samples \
             WHERE ts >= ? AND ts <= ? \
             AND (? IS NULL OR project = ?) \
             AND (? IS NULL OR pool = ?) \
             ORDER BY ts ASC",
        )
        // Clamp into i64 range: u64::MAX ("unbounded") must not wrap negative.
        .bind(from.min(i64::MAX as u64) as i64)
        .bind(to.min(i64::MAX as u64) as i64)
        .bind(project)
        .bind(project)
        .bind(pool)
        .bind(pool)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok::<_, StoreError>(UsageSample {
                    ts: row.try_get::<i64, _>("ts")? as u64,
                    project: row.try_get::<String, _>("project")?,
                    pool: row.try_get::<String, _>("pool")?,
                    resource: row.try_get::<String, _>("resource")?,
                    quantity: row.try_get::<f64, _>("quantity")?,
                    source: UsageSource::parse(&row.try_get::<String, _>("source")?)?,
                })
            })
            .collect()
    }

    async fn record_audit(&self, event: &AuditEvent) -> Result<u64, StoreError> {
        let required_json = match &event.required {
            Some(r) => Some(serde_json::to_string(r).map_err(json_err)?),
            None => None,
        };
        let granted_roles = serde_json::to_string(&event.granted_roles).map_err(json_err)?;
        // RETURNING is standard SQL (SQLite 3.35+, Postgres) — one round
        // trip, no last_insert_rowid() coupling to the connection.
        let row = sqlx::query(
            "INSERT INTO audit_events \
             (ts, subject, decision, reason, action, cluster, method, path, \
              status, latency_ms, required_json, granted_roles) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq",
        )
        .bind(event.ts.min(i64::MAX as u64) as i64)
        .bind(&event.subject)
        .bind(event.decision.as_str())
        .bind(&event.reason)
        .bind(&event.action)
        .bind(&event.cluster)
        .bind(&event.method)
        .bind(&event.path)
        .bind(event.status.map(|s| s as i64))
        .bind(event.latency_ms.map(|l| l.min(i64::MAX as u64) as i64))
        .bind(required_json)
        .bind(granted_roles)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>("seq")? as u64)
    }

    async fn list_audit(
        &self,
        filter: &AuditFilter,
    ) -> Result<(Vec<(u64, AuditEvent)>, Option<u64>), StoreError> {
        // One condition per filter field, ANDed — must stay behaviourally
        // identical to `AuditFilter::matches` (the conformance suite runs
        // the same scenarios against both). `WHERE 1=1` keeps the
        // conditional appends uniform; `substr(path, 1, length(?)) = ?`
        // instead of LIKE so a prefix containing `%`/`_` can't go wildcard.
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(
            "SELECT seq, ts, subject, decision, reason, action, cluster, method, path, \
             status, latency_ms, required_json, granted_roles FROM audit_events WHERE 1=1",
        );
        if let Some(cursor) = filter.cursor {
            qb.push(" AND seq < ")
                .push_bind(cursor.min(i64::MAX as u64) as i64);
        }
        if let Some(from) = filter.from {
            qb.push(" AND ts >= ")
                .push_bind(from.min(i64::MAX as u64) as i64);
        }
        if let Some(to) = filter.to {
            qb.push(" AND ts <= ")
                .push_bind(to.min(i64::MAX as u64) as i64);
        }
        if let Some(subject) = &filter.subject {
            qb.push(" AND subject = ").push_bind(subject);
        }
        if let Some(cluster) = &filter.cluster {
            qb.push(" AND cluster = ").push_bind(cluster);
        }
        if let Some(method) = &filter.method {
            qb.push(" AND method = ").push_bind(method);
        }
        if let Some(prefix) = &filter.path_prefix {
            // `push_bind` appends the placeholder itself; never write `?`.
            qb.push(" AND substr(path, 1, length(")
                .push_bind(prefix)
                .push(")) = ")
                .push_bind(prefix);
        }
        if let Some(min) = filter.min_status {
            // NULL status rows are excluded: NULL >= n is never true.
            qb.push(" AND status >= ").push_bind(min as i64);
        }
        if let Some(decision) = filter.decision {
            qb.push(" AND decision = ").push_bind(decision.as_str());
        }
        if let Some(reason) = &filter.reason {
            qb.push(" AND reason = ").push_bind(reason);
        }
        // One row beyond the page tells us whether a next page exists.
        qb.push(" ORDER BY seq DESC LIMIT ")
            .push_bind(filter.effective_limit() as i64 + 1);
        let rows = qb.build().fetch_all(&self.pool).await?;

        let limit = filter.effective_limit() as usize;
        let mut out: Vec<(u64, AuditEvent)> = rows
            .into_iter()
            .map(|row| {
                let required = match row.try_get::<Option<String>, _>("required_json")? {
                    Some(s) => Some(serde_json::from_str::<AuditRequired>(&s).map_err(json_err)?),
                    None => None,
                };
                let granted_roles = serde_json::from_str::<Vec<String>>(
                    &row.try_get::<String, _>("granted_roles")?,
                )
                .map_err(json_err)?;
                let decision = AuditDecision::parse(&row.try_get::<String, _>("decision")?)
                    .ok_or_else(|| StoreError::Backend("bad audit decision".to_string()))?;
                let event = AuditEvent {
                    ts: row.try_get::<i64, _>("ts")? as u64,
                    subject: row.try_get::<Option<String>, _>("subject")?,
                    decision,
                    reason: row.try_get::<Option<String>, _>("reason")?,
                    action: row.try_get::<Option<String>, _>("action")?,
                    cluster: row.try_get::<Option<String>, _>("cluster")?,
                    method: row.try_get::<Option<String>, _>("method")?,
                    path: row.try_get::<Option<String>, _>("path")?,
                    status: row.try_get::<Option<i64>, _>("status")?.map(|s| s as u16),
                    latency_ms: row
                        .try_get::<Option<i64>, _>("latency_ms")?
                        .map(|l| l as u64),
                    required,
                    granted_roles,
                };
                Ok::<_, StoreError>((row.try_get::<i64, _>("seq")? as u64, event))
            })
            .collect::<Result<_, _>>()?;
        let next_cursor = if out.len() > limit {
            out.truncate(limit);
            out.last().map(|(seq, _)| *seq)
        } else {
            None
        };
        Ok((out, next_cursor))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::WorkerGroup;

    fn spec(name: &str) -> ClusterSpec {
        ClusterSpec {
            name: name.into(),
            project: "demo".into(),
            ray_version: "2.57.0".into(),
            image: "img".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: vec![WorkerGroup {
                name: "w".into(),
                cpu: "1".into(),
                memory: "2Gi".into(),
                gpu: None,
                min_replicas: 0,
                max_replicas: 4,
                replicas: 1,
            }],
            ttl_seconds: None,
        }
    }

    #[tokio::test]
    async fn corrupt_spec_json_is_a_store_error_not_a_panic() {
        let store = SqliteStore::in_memory().await.unwrap();
        let id = ClusterId("demo".into());
        store.upsert_desired(&id, spec("demo")).await.unwrap();
        sqlx::query("UPDATE clusters SET spec_json = 'not json' WHERE id = ?")
            .bind(&id.0)
            .execute(&store.pool)
            .await
            .unwrap();
        let err = store.get(&id).await.unwrap_err().to_string();
        assert!(err.contains("serialization"), "{err}");
    }

    #[tokio::test]
    async fn unknown_desired_value_is_a_store_error() {
        let store = SqliteStore::in_memory().await.unwrap();
        let id = ClusterId("demo".into());
        store.upsert_desired(&id, spec("demo")).await.unwrap();
        sqlx::query("UPDATE clusters SET desired = 'bogus' WHERE id = ?")
            .bind(&id.0)
            .execute(&store.pool)
            .await
            .unwrap();
        let err = store.get(&id).await.unwrap_err().to_string();
        assert!(err.contains("bad desired state"), "{err}");
        // list() hits the same row-mapping error.
        assert!(store.list().await.is_err());
    }

    #[tokio::test]
    async fn backend_errors_are_wrapped_not_panicked() {
        let store = SqliteStore::in_memory().await.unwrap();
        sqlx::query("DROP TABLE jobs")
            .execute(&store.pool)
            .await
            .unwrap();
        let err = store.list_jobs().await.unwrap_err().to_string();
        assert!(err.contains("store backend error"), "{err}");
    }

    #[tokio::test]
    async fn unexpected_migration_failure_surfaces() {
        // A "duplicate column name" migration error is ignored (fresh DBs
        // already have the column); anything else must fail init — e.g. a
        // pre-existing VIEW squatting on the pools table name makes the
        // ALTER fail with a different message.
        let dir = std::env::temp_dir().join(format!("mobula-migration-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::query("CREATE VIEW pools AS SELECT 'x' AS name")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let err = match SqliteStore::connect(&url).await {
            Ok(_) => panic!("init must fail when a migration errors unexpectedly"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("store backend error"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
