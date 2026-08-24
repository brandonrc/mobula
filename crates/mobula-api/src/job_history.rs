//! Persistent job history recording (Truthful Console, spec §5.5 / #89).
//!
//! Ray forgets a job once its cluster is gone. When a job is submitted
//! through the federating gateway (`POST /api/jobs/`, Host-routed to a
//! registered cluster), Mobula records a [`JobRecord`] into its own store so
//! the job shows up in `GET /api/v1/jobs` attributed to the real caller and
//! outlives the cluster that ran it. A light background refresher then walks
//! non-terminal records and advances their status from each cluster's Ray Job
//! API, so history converges to a terminal state even when nobody polls.
//!
//! Engine awareness: this is Ray-only. The gateway registry holds Ray
//! clusters, and only the Ray job-submit path is recorded — Dask has no jobs,
//! so nothing here ever touches a Dask cluster.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mobula_controller::{now_unix, Store};
use mobula_core::{ClusterId, ClusterRegistry, JobRecord};

use crate::cluster_obs::{normalize_jobs, RayJobSummary};

/// Cap on the buffered Ray job-submit response body. A submit reply is a tiny
/// `{"submission_id": "..."}`; anything larger is not a submit reply and is
/// not worth buffering.
pub(crate) const MAX_SUBMIT_BODY_BYTES: usize = 64 * 1024;

/// Terminal Ray job statuses (verbatim Ray vocabulary). A record in any of
/// these is never refreshed again.
pub(crate) fn is_terminal(status: &str) -> bool {
    matches!(status, "SUCCEEDED" | "FAILED" | "STOPPED")
}

/// Whether a proxied request is a Ray job submission worth recording:
/// `POST /api/jobs/` (the fixed root path the stock `ray job submit` client
/// hits, with or without the trailing slash).
pub(crate) fn is_ray_job_submit(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::POST && matches!(path, "/api/jobs" | "/api/jobs/")
}

/// Pull the Ray submission id out of a `POST /api/jobs/` response body. Ray
/// returns `{"submission_id": "raysubmit_..."}`; older/adjacent shapes use
/// `job_id`, accepted as a fallback.
fn parse_submission_id(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get("submission_id")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("job_id").and_then(|x| x.as_str()))
        .map(String::from)
}

/// Record a successful gateway job submission (#89). Best-effort: a parse or
/// store failure is logged, never surfaced to the caller — the job itself
/// already ran on the cluster. `subject` is the authenticated caller, or
/// `None` in dev-unauthenticated mode (recorded as `-`).
pub(crate) async fn record_submission(
    store: Option<&Arc<dyn Store>>,
    cluster: &ClusterId,
    subject: Option<&str>,
    body: &[u8],
) {
    let Some(store) = store else { return };
    let Some(id) = parse_submission_id(body) else {
        tracing::warn!(
            cluster = %cluster,
            "gateway job submit response carried no submission_id; not recording"
        );
        return;
    };
    let record = JobRecord {
        id,
        cluster: cluster.to_string(),
        submitter: subject.unwrap_or("-").to_string(),
        // Ray reports a fresh submission as PENDING; the refresher advances it.
        status: "PENDING".into(),
        duration_secs: None,
        submitted_at: now_unix(),
    };
    if let Err(e) = store.record_job(record).await {
        tracing::warn!(cluster = %cluster, error = %e, "failed to record gateway job submission");
    }
}

/// Background loop that advances non-terminal [`JobRecord`]s toward their
/// terminal state by re-reading each cluster's Ray Job API. Runs alongside
/// the reconcile loop; a cluster that is unreachable or has been removed from
/// the registry simply leaves its jobs untouched this pass.
pub struct JobRefresher {
    store: Arc<dyn Store>,
    registry: Arc<ClusterRegistry>,
    client: reqwest::Client,
    interval: Duration,
}

impl JobRefresher {
    pub fn new(
        store: Arc<dyn Store>,
        registry: Arc<ClusterRegistry>,
        client: reqwest::Client,
        interval: Duration,
    ) -> Self {
        Self {
            store,
            registry,
            client,
            interval,
        }
    }

    /// Run until `shutdown` resolves. Errors are logged per pass, never fatal.
    pub async fn run(&self, shutdown: impl std::future::Future<Output = ()>) {
        tracing::info!(
            interval_secs = self.interval.as_secs(),
            "job-history refresher started"
        );
        let mut ticker = tokio::time::interval(self.interval);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.refresh_once().await {
                        Ok(n) if n > 0 => tracing::debug!(updated = n, "job statuses refreshed"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!(error = %e, "job-history refresh pass failed"),
                    }
                }
                _ = &mut shutdown => {
                    tracing::info!("job-history refresher shutting down");
                    return;
                }
            }
        }
    }

    /// One refresh pass. Returns how many records were updated. Non-terminal
    /// records are grouped by cluster so each reachable cluster is queried at
    /// most once.
    pub async fn refresh_once(&self) -> Result<usize, mobula_controller::StoreError> {
        let jobs = self.store.list_jobs().await?;
        let mut by_cluster: HashMap<String, Vec<JobRecord>> = HashMap::new();
        for j in jobs {
            if !is_terminal(&j.status) {
                by_cluster.entry(j.cluster.clone()).or_default().push(j);
            }
        }
        let mut updated = 0usize;
        for (cluster_id, records) in by_cluster {
            let cid = ClusterId(cluster_id.clone());
            let Some(ep) = self.registry.by_id(&cid) else {
                // Cluster no longer routable (e.g. purged tombstone): leave its
                // records as last seen — we can't refresh what we can't reach.
                continue;
            };
            let summaries = match self
                .fetch_jobs(&ep.api_base_url, ep.auth_token.as_deref())
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(cluster = %cluster_id, error = %e, "job refresh: cluster unreachable");
                    continue;
                }
            };
            let index: HashMap<&str, &RayJobSummary> = summaries
                .iter()
                .filter_map(|s| s.submission_id.as_deref().map(|id| (id, s)))
                .collect();
            for job in records {
                if let Some(summary) = index.get(job.id.as_str()) {
                    if let Some(next) = merge_status(&job, summary) {
                        self.store.record_job(next).await?;
                        updated += 1;
                    }
                }
            }
        }
        Ok(updated)
    }

    /// Fetch and normalize a cluster's Ray job list (`GET /api/jobs/`), the
    /// same southbound discipline as the gateway and cluster-obs proxy.
    async fn fetch_jobs(
        &self,
        api_base_url: &str,
        token: Option<&str>,
    ) -> Result<Vec<RayJobSummary>, reqwest::Error> {
        let url = format!("{}/api/jobs/", api_base_url.trim_end_matches('/'));
        let mut req = self.client.get(&url);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?.error_for_status()?;
        let raw: serde_json::Value = resp.json().await?;
        Ok(normalize_jobs(&raw))
    }
}

/// Produce an updated record if the Ray summary advances the stored status or
/// newly yields a duration; `None` when nothing changed. Duration is derived
/// from Ray's unix-millis `start_time`/`end_time` once both are present.
fn merge_status(job: &JobRecord, summary: &RayJobSummary) -> Option<JobRecord> {
    let new_status = summary.status.clone()?;
    let duration_secs = match (summary.start_time, summary.end_time) {
        (Some(start), Some(end)) if end >= start => Some((end - start) / 1000),
        _ => job.duration_secs,
    };
    if new_status == job.status && duration_secs == job.duration_secs {
        return None;
    }
    Some(JobRecord {
        id: job.id.clone(),
        cluster: job.cluster.clone(),
        submitter: job.submitter.clone(),
        status: new_status,
        duration_secs,
        submitted_at: job.submitted_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(status: &str, dur: Option<u64>) -> JobRecord {
        JobRecord {
            id: "raysubmit_1".into(),
            cluster: "c1".into(),
            submitter: "alice".into(),
            status: status.into(),
            duration_secs: dur,
            submitted_at: 100,
        }
    }

    fn summary(status: Option<&str>, start: Option<u64>, end: Option<u64>) -> RayJobSummary {
        RayJobSummary {
            job_id: None,
            submission_id: Some("raysubmit_1".into()),
            status: status.map(String::from),
            entrypoint: None,
            start_time: start,
            end_time: end,
            message: None,
        }
    }

    #[test]
    fn terminal_classification() {
        for s in ["SUCCEEDED", "FAILED", "STOPPED"] {
            assert!(is_terminal(s), "{s}");
        }
        for s in ["PENDING", "RUNNING", ""] {
            assert!(!is_terminal(s), "{s}");
        }
    }

    #[test]
    fn job_submit_detection() {
        use axum::http::Method;
        assert!(is_ray_job_submit(&Method::POST, "/api/jobs/"));
        assert!(is_ray_job_submit(&Method::POST, "/api/jobs"));
        assert!(!is_ray_job_submit(&Method::GET, "/api/jobs/"));
        assert!(!is_ray_job_submit(&Method::POST, "/api/jobs/raysubmit_1"));
        assert!(!is_ray_job_submit(&Method::POST, "/api/packages/x"));
    }

    #[test]
    fn parse_submission_id_shapes() {
        assert_eq!(
            parse_submission_id(br#"{"submission_id":"raysubmit_abc"}"#).as_deref(),
            Some("raysubmit_abc")
        );
        // job_id fallback.
        assert_eq!(
            parse_submission_id(br#"{"job_id":"0100"}"#).as_deref(),
            Some("0100")
        );
        assert_eq!(parse_submission_id(b"not json"), None);
        assert_eq!(parse_submission_id(br#"{"other":1}"#), None);
    }

    #[test]
    fn merge_advances_status_and_computes_duration() {
        // PENDING -> RUNNING, no end yet: status changes, duration stays None.
        let next = merge_status(
            &rec("PENDING", None),
            &summary(Some("RUNNING"), Some(1_000), None),
        )
        .expect("status changed");
        assert_eq!(next.status, "RUNNING");
        assert_eq!(next.duration_secs, None);

        // RUNNING -> SUCCEEDED with start/end: duration is (end-start)/1000.
        let next = merge_status(
            &rec("RUNNING", None),
            &summary(Some("SUCCEEDED"), Some(1_000), Some(6_000)),
        )
        .expect("terminal with duration");
        assert_eq!(next.status, "SUCCEEDED");
        assert_eq!(next.duration_secs, Some(5));
        assert_eq!(next.submitter, "alice");
        assert_eq!(next.submitted_at, 100);
    }

    #[test]
    fn merge_is_none_when_unchanged() {
        assert!(
            merge_status(&rec("RUNNING", None), &summary(Some("RUNNING"), None, None)).is_none()
        );
        assert!(merge_status(
            &rec("SUCCEEDED", Some(5)),
            &summary(Some("SUCCEEDED"), Some(1_000), Some(6_000))
        )
        .is_none());
    }

    #[test]
    fn merge_without_status_is_none() {
        assert!(merge_status(&rec("RUNNING", None), &summary(None, None, None)).is_none());
    }
}
