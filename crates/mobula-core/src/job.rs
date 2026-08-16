//! Persistent job history (PLAN §Phase 3, spec §5.5).
//!
//! Ray dashboards forget a job the moment its cluster goes away. Mobula
//! records each job it sees submitted through the gateway into its own store,
//! so the history outlives the clusters that ran it. This is the record
//! shape; the store persists it (SQLite dev, Postgres prod) and the API
//! lists it at `GET /api/v1/jobs`.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A single job Mobula has observed, independent of its cluster's lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JobRecord {
    /// Ray submission id (stable across the job's life).
    pub id: String,
    /// Id of the cluster the job ran on (may since be terminated/gone).
    pub cluster: String,
    /// Authenticated subject that submitted it ("-" in dev-unauthenticated).
    pub submitter: String,
    /// Ray job status, verbatim: PENDING | RUNNING | SUCCEEDED | FAILED |
    /// STOPPED. Kept as a string so a Ray status rename doesn't break the
    /// store.
    pub status: String,
    /// Wall-clock duration in seconds once the job reaches a terminal state;
    /// `None` while it is still running.
    pub duration_secs: Option<u64>,
    /// Unix seconds when the job was submitted.
    pub submitted_at: u64,
}
