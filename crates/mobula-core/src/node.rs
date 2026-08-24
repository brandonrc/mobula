//! Kubernetes-sourced node view for the cluster nodes tab (api-v1.md §5.3).
//!
//! Observability only (decision D2): there is no per-node mutation anywhere
//! in the API — scale is group-level. The breakdown is read from the
//! RayCluster and the pods KubeRay owns (label `ray.io/cluster=<name>`), NOT
//! from the Ray dashboard, so it is available even when the dashboard is
//! unreachable. That is a deliberate refinement of the original §5.3 draft
//! (which named the Ray node summary as the source): Kubernetes is the
//! authority for "what pods exist and where", and it answers when Ray does
//! not.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A single Ray node (head or one worker) as Kubernetes sees it: the pod
/// KubeRay created for it, its scheduling/readiness, and the compute it
/// requests. Fields are `Option` because a pod may not yet be scheduled
/// (no IP/host) and a quantity may be unparseable or unset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct NodeView {
    /// The pod's name (`metadata.name`).
    pub pod_name: String,
    /// Worker-group name (`ray.io/group`); `None` for the head node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Whether this is the cluster's head node.
    pub is_head: bool,
    /// Kubernetes pod phase: `Pending` | `Running` | `Succeeded` | `Failed` |
    /// `Unknown` (verbatim from `status.phase`).
    pub phase: String,
    /// Whether the pod's `Ready` condition is true. Distinct from `phase`: a
    /// pod can be `Running` but not yet `Ready`.
    pub ready: bool,
    /// Pod IP once scheduled (`status.podIP`); `None` before scheduling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_ip: Option<String>,
    /// Kubernetes node the pod landed on (`spec.nodeName`); `None` before
    /// scheduling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// CPU cores requested, summed across the pod's containers and parsed
    /// from the K8s quantity (`500m` → 0.5). `None` when unset/unparseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<f64>,
    /// Memory bytes requested, summed across the pod's containers (`2Gi` →
    /// 2147483648). `None` when unset/unparseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// GPUs requested (`nvidia.com/gpu`), summed across containers. `None`
    /// when the pod requests no GPU.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<f64>,
}

/// One worker group and its nodes (api-v1.md §5.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct WorkerGroupNodes {
    /// The worker-group name (`groupName` in the RayCluster spec).
    pub name: String,
    /// Desired replicas: the group's `replicas` field, or `minReplicas` when
    /// autoscaling leaves `replicas` unmanaged (ADR-0007). Per-group desired
    /// counts are not in the RayCluster status, so this is the spec's answer.
    pub desired: u32,
    /// Ready replicas: pods in this group that are `Running` and `Ready`.
    pub ready: u32,
    /// The group's nodes.
    pub nodes: Vec<NodeView>,
}

/// Head + per-worker-group node breakdown for one cluster (api-v1.md §5.3),
/// the body of `GET /api/v1/clusters/{id}/nodes`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ClusterNodes {
    /// The cluster id (RayCluster name).
    pub cluster_id: String,
    /// The head node; `None` if KubeRay has not created the head pod yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<NodeView>,
    /// One entry per worker group, in the RayCluster spec's order.
    pub worker_groups: Vec<WorkerGroupNodes>,
}
