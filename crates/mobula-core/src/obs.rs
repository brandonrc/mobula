//! Provider-agnostic wire types for the cluster drill-down observability tabs
//! (api-v1.md §5.3/§5.6/§5.8, Milestone C) that are NOT the node breakdown
//! (that lives in [`crate::node`]):
//!
//! - [`ClusterEvents`] — Kubernetes Events for the cluster's objects, the body
//!   of `GET /api/v1/clusters/{id}/events`. Sourced from the K8s API (never
//!   the Ray dashboard), so it answers even when Ray is down — the highest-
//!   value signal for "why won't this cluster come up" (image pulls, probe
//!   failures, scheduling).
//! - [`ClusterMetrics`] — a normalized cluster resource-usage summary (used vs
//!   total CPU/GPU/memory + node counts), the body of
//!   `GET /api/v1/clusters/{id}/metrics`. Distilled from the Ray dashboard's
//!   autoscaler status so the UI can render stat tiles against one schema.
//! - [`ClusterLogs`] — a non-streaming, tail-capped pod log view, the body of
//!   `GET /api/v1/clusters/{id}/logs`. The WS streaming upgrade is future work
//!   (api-v1.md §5.6); this is the pragmatic first cut.
//!
//! These are pure domain types: this crate never depends on a Kubernetes
//! client (ADR-0002). The backends in `mobula-provision` produce them.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// ---------------------------------------------------------------------------
// Events (§5.8)
// ---------------------------------------------------------------------------

/// One normalized Kubernetes Event about a cluster object (api-v1.md §5.8).
/// Fields are `Option` because the two Event schemas (core/v1 and
/// events.k8s.io/v1) name them differently and any of them may be absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ClusterEvent {
    /// Event severity: `Normal` or `Warning` (verbatim from `type`).
    #[serde(rename = "type")]
    pub event_type: String,
    /// Short machine reason (`FailedScheduling`, `Pulled`, `BackOff`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// How many times this event has fired (K8s collapses repeats). Defaults
    /// to 1 when the source records no count.
    pub count: u32,
    /// First occurrence (RFC3339); `None` when the source omits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    /// Most recent occurrence (RFC3339); the field the list is sorted by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// The object the event is about, as `Kind/name` (e.g. `Pod/foo-head-abc`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
}

/// Kubernetes Events for one cluster's objects (api-v1.md §5.8), newest first
/// and capped — the body of `GET /api/v1/clusters/{id}/events`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ClusterEvents {
    /// The cluster id (RayCluster name).
    pub cluster_id: String,
    /// Normalized events, most-recent-first, capped (see the endpoint's cap).
    pub events: Vec<ClusterEvent>,
}

// ---------------------------------------------------------------------------
// Metrics (§5.x resource summary)
// ---------------------------------------------------------------------------

/// A single resource's capacity, and its used amount when known. `used`/
/// `total` are in the resource's natural unit: CPU in cores, GPU in device
/// count, memory in bytes. `used` is `None` when the cluster does not report
/// live utilization (e.g. a non-autoscaling cluster whose Ray dashboard has
/// no load-metrics report) — the tile then shows capacity only.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ResourceStat {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<f64>,
    pub total: f64,
}

/// Normalized cluster resource-usage summary (the body of
/// `GET /api/v1/clusters/{id}/metrics`), distilled from the Ray dashboard's
/// autoscaler / load-metrics report. Every stat is `Option` because a cluster
/// may not report GPUs, and an older/mismatched Ray may omit a field — the UI
/// renders a tile only for the stats present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ClusterMetrics {
    /// The cluster id (RayCluster name).
    pub cluster_id: String,
    /// CPU cores used vs total across the Ray cluster.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<ResourceStat>,
    /// GPU devices used vs total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<ResourceStat>,
    /// Memory bytes used vs total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<ResourceStat>,
    /// Object-store memory bytes used vs total.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_store_memory: Option<ResourceStat>,
    /// Active Ray nodes the autoscaler reports; `None` when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_nodes: Option<u64>,
    /// Nodes pending launch; `None` when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_nodes: Option<u64>,
    /// Nodes the autoscaler marked failed; `None` when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_nodes: Option<u64>,
}

// ---------------------------------------------------------------------------
// Logs (§5.6, non-streaming first cut)
// ---------------------------------------------------------------------------

/// A tail-capped pod log view for one cluster (api-v1.md §5.6, non-streaming
/// first cut) — the body of `GET /api/v1/clusters/{id}/logs`. WS streaming is
/// the eventual design (Milestone C); this GET-tail form removes the
/// pending-backend stub now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ClusterLogs {
    /// The cluster id (RayCluster name).
    pub cluster_id: String,
    /// Names of the cluster's pods the caller may tail (head first), so the UI
    /// can offer a pod selector.
    pub pods: Vec<String>,
    /// The pod these `lines` are from (the requested pod, or the head pod when
    /// none was requested). Empty only when the cluster has no pods yet.
    pub pod: String,
    /// The tail line count that was requested.
    pub tail: u32,
    /// The most recent log lines (up to `tail`), oldest first.
    pub lines: Vec<String>,
    /// `true` when the tail was filled (there may be older lines beyond it).
    pub truncated: bool,
}
