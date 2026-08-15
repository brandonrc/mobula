//! SQLite-backed `Store` (ADR-0004: Postgres is truth in prod; SQLite for
//! single-node dev). Uses runtime queries — no compile-time `DATABASE_URL`.
//!
//! Spec and enums are stored as JSON text so the schema stays portable to
//! Postgres (the SQL is standard); a Postgres impl reuses this shape.

use async_trait::async_trait;
use mobula_core::{ClusterId, ClusterSpec, ClusterState};
use sqlx::sqlite::{SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};

use crate::store::{now_unix, spec_changed, DesiredState, Store, StoreError, StoredCluster};

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
    created_at            INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS intents (
    intent_key TEXT PRIMARY KEY
);
"#;

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Connect (creating the file if needed) and apply the schema.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new().connect(url).await?;
        sqlx::query(SCHEMA).execute(&pool).await?;
        Ok(Self { pool })
    }

    /// A private in-memory database for tests. `max_connections(1)` keeps
    /// the single in-memory DB alive and consistent across calls.
    pub async fn in_memory() -> Result<Self, StoreError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        sqlx::query(SCHEMA).execute(&pool).await?;
        Ok(Self { pool })
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
    Ok(StoredCluster {
        id: ClusterId(row.try_get::<String, _>("id")?),
        spec,
        generation: row.try_get::<i64, _>("generation")? as u64,
        desired: desired_from_str(&row.try_get::<String, _>("desired")?)?,
        observed_state,
        observed_generation: row.try_get::<i64, _>("observed_generation")? as u64,
        created_at: row.try_get::<i64, _>("created_at")? as u64,
    })
}

#[async_trait]
impl Store for SqliteStore {
    async fn upsert_desired(&self, id: &ClusterId, spec: ClusterSpec) -> Result<u64, StoreError> {
        let mut tx = self.pool.begin().await?;

        let existing = sqlx::query("SELECT spec_json, generation FROM clusters WHERE id = ?")
            .bind(&id.0)
            .fetch_optional(&mut *tx)
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
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(generation)
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
        sqlx::query("UPDATE clusters SET observed_state = ?, observed_generation = ? WHERE id = ?")
            .bind(observed_json)
            .bind(observed_generation as i64)
            .bind(&id.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn record_intent(&self, key: &str) -> Result<bool, StoreError> {
        let affected =
            sqlx::query("INSERT INTO intents (intent_key) VALUES (?) ON CONFLICT DO NOTHING")
                .bind(key)
                .execute(&self.pool)
                .await?
                .rows_affected();
        Ok(affected > 0)
    }
}
