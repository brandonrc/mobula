//! Dask backend (multi-engine spike): translate a Mobula [`ClusterSpec`]
//! into a `DaskCluster` custom resource for the dask-kubernetes operator, and
//! map DaskCluster status back to a [`ClusterState`].
//!
//! Mirrors [`super::kuberay`] deliberately: this module is pure (no Kubernetes
//! client) so the translation and the per-owner NetworkPolicy are exhaustively
//! unit-testable, and the live client (`dask_client`) does the I/O on top.
//!
//! Scope (per the multi-engine spike): Dask gets the CONTROL path (provision /
//! quota / RBAC / pod-shaping caps / idle-TTL / audit — all engine-agnostic,
//! reused from the control plane) and the INTERACTIVE path (a notebook connects
//! a `distributed.Client` to the scheduler). It does NOT get the batch job
//! gateway (no Ray-Jobs-REST equivalent) or serving (no Ray Serve equivalent).
//!
//! The CRD shape targeted (dask-kubernetes-operator, apiVersion
//! `kubernetes.dask.org/v1`, kind `DaskCluster`):
//! ```yaml
//! spec:
//!   scheduler:
//!     spec: { containers: [ { name: scheduler, image, args: [dask-scheduler], ports: [8786 tcp-comm, 8787 http-dashboard], resources } ] }
//!     service: { type: ClusterIP, selector: {dask.org/cluster-name, dask.org/component: scheduler}, ports: [8786, 8787] }
//!   worker:
//!     replicas: N
//!     spec: { containers: [ { name: worker, image, args: [dask-worker ...], resources } ] }
//! ```
//! The operator injects `DASK_SCHEDULER_ADDRESS` into worker pods and names the
//! scheduler Service `<name>-scheduler`, so a notebook reaches the cluster at
//! `tcp://<id>-scheduler.<ns>.svc:8786`.

use mobula_core::{ClusterId, ClusterSpec, ClusterState, WorkerGroup};
use serde_json::{json, Value};

// Reuse the engine-neutral control-plane labels/consts from the kuberay module
// — owner attribution, the notebook namespace, the managed-by/cluster-id
// labels, the generation annotation and the per-cluster NetworkPolicy naming
// are all shared across engines (that is the whole point of the seam).
use crate::kuberay::{
    cluster_allow_policy_name, CLUSTER_ID_LABEL, FIELD_MANAGER, GENERATION_ANNOTATION,
    MANAGED_BY_LABEL, NETWORK_POLICY_API_VERSION, NETWORK_POLICY_KIND, NOTEBOOK_NAMESPACE,
    OWNER_LABEL,
};
use mobula_core::{ClusterNodes, NodeView, WorkerGroupNodes};

pub const API_VERSION: &str = "kubernetes.dask.org/v1";
pub const KIND: &str = "DaskCluster";

/// The scheduler's client (comm) port — the Dask analog of Ray's client
/// `:10001`. A notebook's `distributed.Client` connects here.
pub const SCHEDULER_COMM_PORT: u16 = 8786;
/// The scheduler's Bokeh dashboard port — the Dask analog of Ray's `:8265`.
pub const SCHEDULER_DASHBOARD_PORT: u16 = 8787;
/// The worker's dashboard port (per-worker Bokeh).
pub const WORKER_DASHBOARD_PORT: u16 = 8788;

/// Labels the dask-kubernetes operator stamps on the pods/services it owns.
/// `dask.org/cluster-name=<id>` is the selector the live client lists by; the
/// component label distinguishes scheduler from worker.
pub const DASK_CLUSTER_NAME_LABEL: &str = "dask.org/cluster-name";
pub const DASK_COMPONENT_LABEL: &str = "dask.org/component";

/// Build the DaskCluster manifest for `spec` at `generation`.
///
/// The head/scheduler comes from `head_cpu`/`head_memory`; the worker group
/// comes from `worker_groups[0]` (the dask-kubernetes-operator's embedded
/// `spec.worker` is a single default group — heterogeneous groups are separate
/// `DaskWorkerGroup` CRs, out of scope for the spike). `spec.image` carries the
/// Dask image (`ray_version` is unused for Dask). The owner (tier-2) is stamped
/// on every pod so it self-describes who owns it and the per-owner ingress
/// policy has a label to key on.
pub fn to_daskcluster(id: &ClusterId, spec: &ClusterSpec, generation: u64) -> Value {
    let owner = spec.owner.as_deref();
    let worker = spec.worker_groups.first();
    let replicas = worker.map(|w| w.replicas).unwrap_or(0);

    let mut labels = json!({
        MANAGED_BY_LABEL: FIELD_MANAGER,
        CLUSTER_ID_LABEL: id.0,
    });
    if let Some(owner) = owner {
        labels[OWNER_LABEL] = json!(owner);
    }

    json!({
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {
            "name": id.0,
            "labels": labels,
            "annotations": { GENERATION_ANNOTATION: generation.to_string() },
        },
        "spec": {
            "scheduler": scheduler_spec(&id.0, spec, Some(generation), owner),
            "worker": worker_spec(&id.0, spec, worker, replicas, Some(generation), owner),
        },
    })
}

/// Container resource block: requests AND limits both set to the same values
/// (mirrors [`super::kuberay`] — the requested caps must be honored on the pod,
/// so a `resources.limits` is always emitted, never dropped).
fn resources(cpu: &str, memory: &str, gpu: Option<&str>) -> Value {
    let mut limits = json!({ "cpu": cpu, "memory": memory });
    let mut requests = json!({ "cpu": cpu, "memory": memory });
    if let Some(gpu) = gpu {
        limits["nvidia.com/gpu"] = json!(gpu);
        requests["nvidia.com/gpu"] = json!(gpu);
    }
    json!({ "limits": limits, "requests": requests })
}

/// The pod-template `metadata` (labels + generation annotation) every Dask pod
/// carries. `CLUSTER_ID_LABEL` is what the scoped NetworkPolicies select on
/// (same contract as the Ray pods); the owner label is tier-2 attribution.
fn pod_metadata(cluster_id: &str, generation: Option<u64>, owner: Option<&str>) -> Value {
    let mut pod_labels = json!({ CLUSTER_ID_LABEL: cluster_id });
    if let Some(owner) = owner {
        pod_labels[OWNER_LABEL] = json!(owner);
    }
    let mut meta = json!({ "labels": pod_labels });
    if let Some(gen) = generation {
        meta["annotations"] = json!({ GENERATION_ANNOTATION: gen.to_string() });
    }
    meta
}

fn scheduler_spec(
    cluster_id: &str,
    spec: &ClusterSpec,
    generation: Option<u64>,
    owner: Option<&str>,
) -> Value {
    let container = json!({
        "name": "scheduler",
        "image": spec.image,
        "imagePullPolicy": "IfNotPresent",
        "args": ["dask-scheduler"],
        "ports": [
            { "name": "tcp-comm", "containerPort": SCHEDULER_COMM_PORT, "protocol": "TCP" },
            { "name": "http-dashboard", "containerPort": SCHEDULER_DASHBOARD_PORT, "protocol": "TCP" },
        ],
        "resources": resources(&spec.head_cpu, &spec.head_memory, None),
        // The operator's documented default health probes on the dashboard.
        "readinessProbe": { "httpGet": { "port": "http-dashboard", "path": "/health" }, "initialDelaySeconds": 5, "periodSeconds": 10 },
        "livenessProbe": { "httpGet": { "port": "http-dashboard", "path": "/health" }, "initialDelaySeconds": 15, "periodSeconds": 20 },
    });
    json!({
        "metadata": pod_metadata(cluster_id, generation, owner),
        "spec": { "containers": [container] },
        // ClusterIP: reachable in-cluster at `<id>-scheduler.<ns>.svc:8786`,
        // which is what the notebook `distributed.Client` connects to. Not
        // NodePort (the operator's example default) — we want no node-level
        // exposure of a tenant scheduler.
        "service": {
            "type": "ClusterIP",
            "selector": {
                DASK_CLUSTER_NAME_LABEL: cluster_id,
                DASK_COMPONENT_LABEL: "scheduler",
            },
            "ports": [
                { "name": "tcp-comm", "protocol": "TCP", "port": SCHEDULER_COMM_PORT, "targetPort": "tcp-comm" },
                { "name": "http-dashboard", "protocol": "TCP", "port": SCHEDULER_DASHBOARD_PORT, "targetPort": "http-dashboard" },
            ],
        },
    })
}

fn worker_spec(
    cluster_id: &str,
    spec: &ClusterSpec,
    group: Option<&WorkerGroup>,
    replicas: u32,
    generation: Option<u64>,
    owner: Option<&str>,
) -> Value {
    // Fall back to the scheduler's caps if the spec somehow carries no worker
    // group (defensive; the API always sends at least one).
    let (cpu, memory, gpu) = match group {
        Some(g) => (g.cpu.as_str(), g.memory.as_str(), g.gpu.as_deref()),
        None => (spec.head_cpu.as_str(), spec.head_memory.as_str(), None),
    };
    let container = json!({
        "name": "worker",
        "image": spec.image,
        "imagePullPolicy": "IfNotPresent",
        // The operator injects DASK_SCHEDULER_ADDRESS into every worker
        // container, so the address is not spelled out here; $(DASK_WORKER_NAME)
        // is likewise operator-injected.
        "args": [
            "dask-worker",
            "--name", "$(DASK_WORKER_NAME)",
            "--dashboard",
            "--dashboard-address", WORKER_DASHBOARD_PORT.to_string(),
        ],
        "resources": resources(cpu, memory, gpu),
    });
    json!({
        "replicas": replicas,
        "metadata": pod_metadata(cluster_id, generation, owner),
        "spec": { "containers": [container] },
    })
}

/// Fingerprint of the Mobula-owned, drift-relevant fields for a Dask cluster
/// (ADR-0004 drift detection). Deliberately EXCLUDES worker `replicas` (a
/// scale count is never treated as drift — mirrors the Ray side). Projects the
/// same shape [`fingerprint_from_cr`] reads back off a live DaskCluster.
pub fn owned_spec_fingerprint(spec: &ClusterSpec) -> String {
    let (wcpu, wmem, wgpu) = spec
        .worker_groups
        .first()
        .map(|g| (g.cpu.clone(), g.memory.clone(), g.gpu.clone()))
        .unwrap_or_default();
    json!({
        "image": spec.image,
        "head_cpu": spec.head_cpu,
        "head_memory": spec.head_memory,
        "worker_cpu": wcpu,
        "worker_memory": wmem,
        "worker_gpu": wgpu,
    })
    .to_string()
}

/// Recompute the owned-field fingerprint from a live DaskCluster `.spec` object
/// (the inverse projection of [`to_daskcluster`]). Returns `None` if the fields
/// we own are absent (nothing to compare).
pub fn fingerprint_from_cr(cr_spec: &Value) -> Option<String> {
    let sched_c = first_container(cr_spec.get("scheduler")?)?;
    let (head_cpu, head_memory) = container_requests(sched_c)?;
    let image = sched_c.get("image").and_then(|v| v.as_str()).unwrap_or("");
    let (wcpu, wmem, wgpu) = match cr_spec
        .get("worker")
        .and_then(first_container)
        .and_then(|c| container_requests(c).map(|(cpu, mem)| (cpu, mem, container_gpu(c))))
    {
        Some((cpu, mem, gpu)) => (cpu, mem, gpu),
        None => (String::new(), String::new(), None),
    };
    Some(
        json!({
            "image": image,
            "head_cpu": head_cpu,
            "head_memory": head_memory,
            "worker_cpu": wcpu,
            "worker_memory": wmem,
            "worker_gpu": wgpu,
        })
        .to_string(),
    )
}

/// The first container of a scheduler/worker group spec (`spec.containers[0]`).
fn first_container(group: &Value) -> Option<&Value> {
    group.get("spec")?.get("containers")?.as_array()?.first()
}

fn container_requests(c: &Value) -> Option<(String, String)> {
    let req = c.get("resources")?.get("requests")?;
    Some((
        req.get("cpu")?.as_str()?.to_string(),
        req.get("memory")?.as_str()?.to_string(),
    ))
}

fn container_gpu(c: &Value) -> Option<String> {
    c.get("resources")?
        .get("requests")?
        .get("nvidia.com/gpu")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// The per-cluster intra-tenant allow for a Dask cluster (the Dask analog of
/// [`super::kuberay::cluster_allow_network_policy`]). Pods of cluster `id`
/// (matched by [`CLUSTER_ID_LABEL`]) may talk to each other on every port
/// (scheduler↔workers) and to nothing else — tenant clusters stay isolated.
///
/// Tier-2 per-owner pin: when `owner` is `Some`, a second ingress rule admits
/// the owner's notebook — pods in [`NOTEBOOK_NAMESPACE`] carrying
/// `mobula.dev/owner=<owner>` — to the scheduler comm (`:8786`) and dashboard
/// (`:8787`) ports only. A different user's notebook carries a different owner
/// value, matches neither peer selector, and is left to the default-deny — so
/// alice cannot reach bob's Dask scheduler.
pub fn cluster_allow_network_policy(id: &str, owner: Option<&str>) -> Value {
    let same_cluster = json!({ "matchLabels": { CLUSTER_ID_LABEL: id } });
    let mut ingress = vec![json!({ "from": [ { "podSelector": &same_cluster } ] })];
    if let Some(owner) = owner {
        ingress.push(json!({
            "from": [
                {
                    "namespaceSelector": {
                        "matchLabels": { "kubernetes.io/metadata.name": NOTEBOOK_NAMESPACE },
                    },
                    "podSelector": {
                        "matchLabels": { OWNER_LABEL: owner },
                    },
                },
            ],
            "ports": [
                { "protocol": "TCP", "port": SCHEDULER_COMM_PORT },
                { "protocol": "TCP", "port": SCHEDULER_DASHBOARD_PORT },
            ],
        }));
    }
    json!({
        "apiVersion": NETWORK_POLICY_API_VERSION,
        "kind": NETWORK_POLICY_KIND,
        "metadata": {
            "name": cluster_allow_policy_name(id),
            "labels": { MANAGED_BY_LABEL: FIELD_MANAGER, CLUSTER_ID_LABEL: id },
        },
        "spec": {
            "podSelector": &same_cluster,
            "policyTypes": ["Ingress", "Egress"],
            "ingress": ingress,
            "egress": [ { "to": [ { "podSelector": &same_cluster } ] } ],
        },
    })
}

/// Map a DaskCluster `.status.phase` to a Mobula [`ClusterState`]
/// (observation-first). The operator reports "Created"/"Pending"/"Running".
///
/// NOTE (#121): the dask-operator only *writes* `.status.phase` when the
/// installed `daskclusters` CRD serves a `status` subresource. On a CRD
/// without one, the phase patch silently fails and the CR is stuck at
/// `Pending` forever — so this mapping alone never reports `Running`. The live
/// client therefore prefers [`observed_state_from_pods`] and falls back to
/// this only when no pods are visible.
pub fn status_to_state(status: &Value) -> ClusterState {
    match status.get("phase").and_then(|s| s.as_str()) {
        Some("Running") => ClusterState::Running,
        Some("Failed") => ClusterState::Degraded,
        // Created / Pending / none → still coming up.
        _ => ClusterState::Provisioning,
    }
}

/// Derive a Dask cluster's observed [`ClusterState`] from the operator-owned
/// **pods** (scheduler + workers), independent of the DaskCluster's
/// `.status.phase` (#121). This is the robust readiness signal: it works
/// regardless of whether the installed CRD serves a `status` subresource,
/// exactly as the nodes endpoint already derives per-pod readiness for both
/// engines.
///
/// Rules (mirroring the KubeRay "ready" semantics):
/// - scheduler pod `Running`+`Ready` **and** ≥1 worker `Running`+`Ready`
///   ⇒ [`ClusterState::Running`];
/// - scheduler pod present but `Failed` (or any pod `Failed` while not yet
///   Running) ⇒ [`ClusterState::Degraded`];
/// - otherwise (pods still scheduling / pulling / starting)
///   ⇒ [`ClusterState::Provisioning`].
///
/// Returns `None` when there are no pods to judge from (the operator has not
/// created any yet, or the pod list was unavailable), so the caller can fall
/// back to the CR phase via [`status_to_state`].
pub fn observed_state_from_pods(pods: &[Value]) -> Option<ClusterState> {
    if pods.is_empty() {
        return None;
    }
    let scheduler = pods
        .iter()
        .find(|p| pod_label(p, DASK_COMPONENT_LABEL) == Some("scheduler"));
    let scheduler_ready = scheduler.is_some_and(pod_running_ready);
    let workers_ready = pods
        .iter()
        .filter(|p| pod_label(p, DASK_COMPONENT_LABEL) == Some("worker"))
        .filter(|p| pod_running_ready(p))
        .count();
    let any_failed = pods.iter().any(|p| pod_phase(p) == "Failed");

    // A failed scheduler is unambiguously Degraded (nothing can come up
    // without it). A ready scheduler + at least one ready worker is Running,
    // even amid worker churn. Any other failure with no full readiness is
    // Degraded; everything else is still coming up.
    if scheduler.is_some_and(|p| pod_phase(p) == "Failed") {
        Some(ClusterState::Degraded)
    } else if scheduler_ready && workers_ready >= 1 {
        Some(ClusterState::Running)
    } else if any_failed {
        Some(ClusterState::Degraded)
    } else {
        Some(ClusterState::Provisioning)
    }
}

// ---------------------------------------------------------------------------
// Node breakdown (§5.3) — pure mapping from the pods the operator owns.
// ---------------------------------------------------------------------------

fn pod_label<'a>(pod: &'a Value, key: &str) -> Option<&'a str> {
    pod.get("metadata")?
        .get("labels")?
        .get(key)
        .and_then(|v| v.as_str())
}

/// A pod's `.status.phase` (`"Unknown"` when absent).
fn pod_phase(pod: &Value) -> &str {
    pod.get("status")
        .and_then(|s| s.get("phase"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown")
}

/// Whether the pod carries a `Ready=True` condition (the kubelet's readiness
/// gate — the same signal the nodes endpoint reports per pod).
fn pod_ready(pod: &Value) -> bool {
    pod.get("status")
        .and_then(|s| s.get("conditions"))
        .and_then(|c| c.as_array())
        .is_some_and(|conds| {
            conds.iter().any(|c| {
                c.get("type").and_then(|v| v.as_str()) == Some("Ready")
                    && c.get("status").and_then(|v| v.as_str()) == Some("True")
            })
        })
}

/// A pod is "up" when it is both `Running` and `Ready` — the readiness signal
/// the pod-based observe ([`observed_state_from_pods`]) counts on.
fn pod_running_ready(pod: &Value) -> bool {
    pod_phase(pod) == "Running" && pod_ready(pod)
}

fn pod_to_node_view(pod: &Value, is_head: bool) -> NodeView {
    let status = pod.get("status");
    let phase = pod_phase(pod).to_string();
    let ready = pod_ready(pod);
    NodeView {
        pod_name: pod
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        group: if is_head {
            None
        } else {
            Some("default".into())
        },
        is_head,
        phase,
        ready,
        node_ip: status
            .and_then(|s| s.get("podIP"))
            .and_then(|v| v.as_str())
            .map(String::from),
        host: pod
            .get("spec")
            .and_then(|s| s.get("nodeName"))
            .and_then(|v| v.as_str())
            .map(String::from),
        // Compute-request parsing is Ray-side polish; the Dask nodes endpoint
        // reports scheduling/readiness only in the spike (kubectl is the
        // resource-cap proof).
        cpu: None,
        memory_bytes: None,
        gpu: None,
    }
}

/// Head (scheduler) + worker-group node breakdown for a Dask cluster from the
/// pods the operator owns (already filtered by `dask.org/cluster-name=<id>`).
/// A single "default" worker group is reported (the DaskCluster embeds one).
pub fn node_breakdown(cluster_id: &str, pods: &[Value]) -> ClusterNodes {
    let is_sched = |p: &&Value| pod_label(p, DASK_COMPONENT_LABEL) == Some("scheduler");
    let head = pods
        .iter()
        .find(is_sched)
        .map(|p| pod_to_node_view(p, true));
    let workers: Vec<NodeView> = pods
        .iter()
        .filter(|p| pod_label(p, DASK_COMPONENT_LABEL) == Some("worker"))
        .map(|p| pod_to_node_view(p, false))
        .collect();
    let ready = workers
        .iter()
        .filter(|n| n.phase == "Running" && n.ready)
        .count() as u32;
    let worker_groups = if workers.is_empty() {
        Vec::new()
    } else {
        vec![WorkerGroupNodes {
            name: "default".into(),
            desired: workers.len() as u32,
            ready,
            nodes: workers,
        }]
    };
    ClusterNodes {
        cluster_id: cluster_id.to_string(),
        head,
        worker_groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::{Engine, WorkerGroup};

    fn spec(replicas: u32) -> ClusterSpec {
        ClusterSpec {
            name: "demo".into(),
            project: "p".into(),
            engine: Engine::Dask,
            ray_version: String::new(),
            image: "ghcr.io/dask/dask:latest".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: vec![WorkerGroup {
                name: "default".into(),
                cpu: "2".into(),
                memory: "4Gi".into(),
                gpu: None,
                min_replicas: replicas,
                max_replicas: replicas,
                replicas,
            }],
            ttl_seconds: None,
            idle_timeout_secs: None,
            owner: None,
        }
    }

    #[test]
    fn manifest_shape_kind_and_ports() {
        let m = to_daskcluster(&ClusterId("demo".into()), &spec(2), 1);
        assert_eq!(m["apiVersion"], "kubernetes.dask.org/v1");
        assert_eq!(m["kind"], "DaskCluster");
        assert_eq!(m["metadata"]["name"], "demo");
        assert_eq!(m["metadata"]["labels"][MANAGED_BY_LABEL], "mobula");
        assert_eq!(m["metadata"]["labels"][CLUSTER_ID_LABEL], "demo");
        // Scheduler container: dask-scheduler + the two ports.
        let sc = &m["spec"]["scheduler"]["spec"]["containers"][0];
        assert_eq!(sc["args"][0], "dask-scheduler");
        assert_eq!(sc["image"], "ghcr.io/dask/dask:latest");
        assert_eq!(sc["ports"][0]["containerPort"], 8786);
        assert_eq!(sc["ports"][1]["containerPort"], 8787);
        // Scheduler service is ClusterIP on 8786/8787.
        let svc = &m["spec"]["scheduler"]["service"];
        assert_eq!(svc["type"], "ClusterIP");
        assert_eq!(svc["ports"][0]["port"], 8786);
        assert_eq!(svc["ports"][1]["port"], 8787);
        // Worker group: replicas + dask-worker args.
        assert_eq!(m["spec"]["worker"]["replicas"], 2);
        assert_eq!(
            m["spec"]["worker"]["spec"]["containers"][0]["args"][0],
            "dask-worker"
        );
    }

    #[test]
    fn caps_are_honored_on_scheduler_and_worker() {
        // Resource-control contract: the requested caps must reach BOTH the
        // scheduler and the worker container as requests AND limits — never
        // dropped (the coordinator's resource-control proof depends on it).
        let m = to_daskcluster(&ClusterId("demo".into()), &spec(1), 1);
        let sc = &m["spec"]["scheduler"]["spec"]["containers"][0]["resources"];
        assert_eq!(sc["requests"]["cpu"], "1");
        assert_eq!(sc["requests"]["memory"], "2Gi");
        assert_eq!(sc["limits"]["cpu"], "1");
        assert_eq!(sc["limits"]["memory"], "2Gi");
        let wk = &m["spec"]["worker"]["spec"]["containers"][0]["resources"];
        assert_eq!(wk["requests"]["cpu"], "2");
        assert_eq!(wk["requests"]["memory"], "4Gi");
        assert_eq!(wk["limits"]["cpu"], "2");
        assert_eq!(wk["limits"]["memory"], "4Gi");
    }

    #[test]
    fn gpu_worker_gets_resource_limits() {
        let mut s = spec(1);
        s.worker_groups[0].gpu = Some("1".into());
        let m = to_daskcluster(&ClusterId("demo".into()), &s, 1);
        let res = &m["spec"]["worker"]["spec"]["containers"][0]["resources"];
        assert_eq!(res["limits"]["nvidia.com/gpu"], "1");
        assert_eq!(res["requests"]["nvidia.com/gpu"], "1");
    }

    #[test]
    fn owner_stamped_on_cr_and_every_pod() {
        let mut s = spec(2);
        s.owner = Some("bob".into());
        let m = to_daskcluster(&ClusterId("sess-bob".into()), &s, 1);
        assert_eq!(m["metadata"]["labels"][OWNER_LABEL], "bob");
        assert_eq!(
            m["spec"]["scheduler"]["metadata"]["labels"][OWNER_LABEL],
            "bob"
        );
        assert_eq!(
            m["spec"]["worker"]["metadata"]["labels"][OWNER_LABEL],
            "bob"
        );
        // Cluster-id label rides every pod (the NetworkPolicy selector).
        assert_eq!(
            m["spec"]["scheduler"]["metadata"]["labels"][CLUSTER_ID_LABEL],
            "sess-bob"
        );
        assert_eq!(
            m["spec"]["worker"]["metadata"]["labels"][CLUSTER_ID_LABEL],
            "sess-bob"
        );
    }

    #[test]
    fn ownerless_cluster_carries_no_owner_label() {
        let m = to_daskcluster(&ClusterId("demo".into()), &spec(1), 1);
        assert!(m["metadata"]["labels"].get(OWNER_LABEL).is_none());
        assert!(m["spec"]["scheduler"]["metadata"]["labels"]
            .get(OWNER_LABEL)
            .is_none());
    }

    #[test]
    fn fingerprint_round_trips_through_the_manifest() {
        // The fingerprint recomputed from a freshly-built manifest must equal
        // the desired fingerprint, or every Dask cluster would report drift.
        let s = spec(2);
        let m = to_daskcluster(&ClusterId("demo".into()), &s, 1);
        assert_eq!(
            owned_spec_fingerprint(&s),
            fingerprint_from_cr(&m["spec"]).unwrap()
        );
    }

    #[test]
    fn fingerprint_ignores_replicas_but_catches_image() {
        let a = spec(2);
        let mut b = spec(9); // only replicas differ
        assert_eq!(
            owned_spec_fingerprint(&a),
            owned_spec_fingerprint(&b),
            "replica delta must not change the fingerprint"
        );
        b.image = "ghcr.io/dask/dask:2024".into();
        assert_ne!(
            owned_spec_fingerprint(&a),
            owned_spec_fingerprint(&b),
            "an image edit must change the fingerprint"
        );
    }

    #[test]
    fn status_mapping() {
        assert_eq!(
            status_to_state(&json!({"phase": "Running"})),
            ClusterState::Running
        );
        assert_eq!(
            status_to_state(&json!({"phase": "Created"})),
            ClusterState::Provisioning
        );
        assert_eq!(
            status_to_state(&json!({"phase": "Pending"})),
            ClusterState::Provisioning
        );
        assert_eq!(status_to_state(&json!({})), ClusterState::Provisioning);
    }

    #[test]
    fn per_owner_policy_admits_only_owner_notebook_to_scheduler_ports() {
        // The tier-2 isolation contract, for Dask: bob's notebook (ns=jupyter
        // AND owner=bob) → :8786/:8787; nothing else.
        let p = cluster_allow_network_policy("sess-bob", Some("bob"));
        assert_eq!(p["metadata"]["name"], "mobula-cluster-sess-bob");
        assert_eq!(
            p["spec"]["podSelector"]["matchLabels"][CLUSTER_ID_LABEL],
            "sess-bob"
        );
        let ingress = p["spec"]["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 2);
        // [0] intra-cluster (scheduler↔workers), all ports.
        assert_eq!(
            ingress[0]["from"][0]["podSelector"]["matchLabels"][CLUSTER_ID_LABEL],
            "sess-bob"
        );
        assert!(ingress[0].get("ports").is_none());
        // [1] owner notebook → 8786 + 8787 only.
        let peer = &ingress[1]["from"][0];
        assert_eq!(
            peer["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
            NOTEBOOK_NAMESPACE
        );
        assert_eq!(peer["podSelector"]["matchLabels"][OWNER_LABEL], "bob");
        assert_eq!(
            ingress[1]["ports"],
            json!([
                { "protocol": "TCP", "port": 8786 },
                { "protocol": "TCP", "port": 8787 },
            ])
        );
    }

    #[test]
    fn ownerless_policy_is_intra_cluster_only() {
        let p = cluster_allow_network_policy("sess-x", None);
        let ingress = p["spec"]["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 1, "no owner → only the intra-cluster allow");
    }

    #[test]
    fn different_owner_does_not_match_the_pin() {
        // alice's notebook carries owner=alice, so bob's policy (owner=bob)
        // never admits it — the per-owner isolation that blocks cross-user
        // access.
        let p = cluster_allow_network_policy("sess-bob", Some("bob"));
        let peer = &p["spec"]["ingress"][1]["from"][0];
        assert_eq!(peer["podSelector"]["matchLabels"][OWNER_LABEL], "bob");
        assert_ne!(peer["podSelector"]["matchLabels"][OWNER_LABEL], "alice");
    }

    // --- #121: pod-based readiness (independent of CR .status.phase) ---

    fn dpod(comp: &str, phase: &str, ready: bool) -> Value {
        json!({
            "metadata": { "name": format!("demo-{comp}"), "labels": {
                DASK_CLUSTER_NAME_LABEL: "demo", DASK_COMPONENT_LABEL: comp,
            } },
            "status": { "phase": phase, "conditions": [
                { "type": "Ready", "status": if ready { "True" } else { "False" } },
            ] },
        })
    }

    #[test]
    fn pods_none_when_empty_so_caller_falls_back_to_cr_phase() {
        assert_eq!(observed_state_from_pods(&[]), None);
    }

    #[test]
    fn pods_running_when_scheduler_and_one_worker_ready() {
        let pods = vec![
            dpod("scheduler", "Running", true),
            dpod("worker", "Running", true),
            dpod("worker", "Pending", false),
        ];
        assert_eq!(
            observed_state_from_pods(&pods),
            Some(ClusterState::Running),
            "scheduler + ≥1 worker ready ⇒ Running even while another worker starts"
        );
    }

    #[test]
    fn pods_provisioning_when_scheduler_ready_but_no_worker_ready() {
        let pods = vec![
            dpod("scheduler", "Running", true),
            dpod("worker", "Pending", false),
        ];
        assert_eq!(
            observed_state_from_pods(&pods),
            Some(ClusterState::Provisioning)
        );
    }

    #[test]
    fn pods_provisioning_when_scheduler_not_yet_ready() {
        // Scheduler Running but not Ready (probe not passing yet), worker up.
        let pods = vec![
            dpod("scheduler", "Running", false),
            dpod("worker", "Running", true),
        ];
        assert_eq!(
            observed_state_from_pods(&pods),
            Some(ClusterState::Provisioning)
        );
    }

    #[test]
    fn pods_running_does_not_require_cr_status_phase() {
        // The whole point of #121: no `.status` at all on the pods' owner, yet
        // pod truth alone yields Running. (This function never sees the CR.)
        let pods = vec![
            dpod("scheduler", "Running", true),
            dpod("worker", "Running", true),
        ];
        assert_eq!(observed_state_from_pods(&pods), Some(ClusterState::Running));
    }

    #[test]
    fn pods_degraded_when_scheduler_failed() {
        let pods = vec![
            dpod("scheduler", "Failed", false),
            dpod("worker", "Running", true),
        ];
        assert_eq!(
            observed_state_from_pods(&pods),
            Some(ClusterState::Degraded),
            "a failed scheduler is Degraded regardless of workers"
        );
    }

    #[test]
    fn pods_degraded_when_a_worker_failed_and_not_ready_overall() {
        let pods = vec![
            dpod("scheduler", "Running", true),
            dpod("worker", "Failed", false),
        ];
        assert_eq!(
            observed_state_from_pods(&pods),
            Some(ClusterState::Degraded)
        );
    }

    #[test]
    fn node_breakdown_splits_scheduler_and_workers() {
        let pod = |name: &str, comp: &str, phase: &str, ready: bool| {
            json!({
                "metadata": { "name": name, "labels": {
                    DASK_CLUSTER_NAME_LABEL: "demo", DASK_COMPONENT_LABEL: comp,
                } },
                "status": { "phase": phase, "conditions": [
                    { "type": "Ready", "status": if ready { "True" } else { "False" } },
                ] },
            })
        };
        let pods = vec![
            pod("demo-scheduler", "scheduler", "Running", true),
            pod("demo-worker-1", "worker", "Running", true),
            pod("demo-worker-2", "worker", "Pending", false),
        ];
        let nb = node_breakdown("demo", &pods);
        assert!(nb.head.as_ref().unwrap().is_head);
        assert_eq!(nb.worker_groups.len(), 1);
        assert_eq!(nb.worker_groups[0].nodes.len(), 2);
        assert_eq!(nb.worker_groups[0].ready, 1);
    }
}
