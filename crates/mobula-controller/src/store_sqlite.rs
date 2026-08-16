//! SQLite-backed `Store` (ADR-0004: Postgres is truth in prod; SQLite for
//! single-node dev). Uses runtime queries — no compile-time `DATABASE_URL`.
//!
//! Spec and enums are stored as JSON text so the schema stays portable to
//! Postgres (the SQL is standard); a Postgres impl reuses this shape.

use async_trait::async_trait;
use mobula_core::{ClusterId, ClusterSpec, ClusterState, DriftCondition};
use sqlx::sqlite::{SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};

use crate::store::{
    now_unix, spec_changed, DesiredState, IntentOutcome, IntentRecord, IntentStatus, Store,
    StoreError, StoredCluster,
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
}
