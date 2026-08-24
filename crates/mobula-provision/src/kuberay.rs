//! KubeRay backend: translate a Mobula [`ClusterSpec`] into a RayCluster
//! custom resource, and map RayCluster status back to a [`ClusterState`].
//!
//! This module is pure (no Kubernetes client) so the ADR-0007 field-
//! ownership rule is exhaustively testable: when Ray's in-tree autoscaler
//! is enabled, Mobula owns `minReplicas`/`maxReplicas` only and must NEVER
//! write `replicas` or `scaleStrategy` — the autoscaler sidecar owns those,
//! and writing them causes the stuck-instance conflicts documented upstream.
//! The live client wiring (server-side apply, observe, delete) is added on
//! top of these functions.

use mobula_core::{
    ClusterId, ClusterSpec, ClusterState, ServiceSpec, UpgradeStrategy, WorkerGroup,
};
use serde_json::{json, Value};

use crate::kueue::{ELASTIC_JOB_ANNOTATION, QUEUE_LABEL};

/// The Kueue queue a RayCluster is admitted through (ADR-0010): the
/// allocation's LocalQueue name, plus whether the pool allows elastic
/// resizing. Derived at apply time from the project→allocation lookup (not
/// user input), so it is a parameter of [`to_raycluster`], never part of
/// `ClusterSpec`'s serialized form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueAssignment {
    /// LocalQueue name (= the allocation's project name).
    pub queue_name: String,
    /// Elastic pools stamp `kueue.x-k8s.io/elastic-job` and force the
    /// in-tree autoscaler on — elastic mode (KEP-77 Workload Slices)
    /// requires it (research doc §2).
    pub elastic: bool,
}

pub const API_VERSION: &str = "ray.io/v1";
pub const KIND: &str = "RayCluster";
/// Server-side-apply field manager (ADR-0007): identifies Mobula's owned
/// fields so drift is attributable and `replicas` can be left unmanaged.
pub const FIELD_MANAGER: &str = "mobula";
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const CLUSTER_ID_LABEL: &str = "mobula.dev/cluster-id";
/// Annotation carrying the Mobula spec generation this resource reflects
/// (ADR-0006, #40). Stamped on the RayCluster metadata (so `observe` can
/// read back the generation the cluster actually carries) *and* on the pod
/// templates (so a generation bump changes the pod-template hash and KubeRay
/// rolls the pods — the roll drives `.status.state` away from ready until it
/// completes, making convergence observed rather than self-certified).
pub const GENERATION_ANNOTATION: &str = "mobula.dev/generation";

/// Build the RayCluster manifest for `spec` at `generation`. `autoscaling`
/// selects the field-ownership regime (ADR-0007). `queue` nominates the
/// Kueue LocalQueue (ADR-0010): `None` (the default) produces a manifest
/// byte-identical to the queue-free form; `Some` stamps the
/// `kueue.x-k8s.io/queue-name` label, and an elastic assignment also stamps
/// the `kueue.x-k8s.io/elastic-job` annotation and forces the in-tree
/// autoscaler on regardless of `autoscaling` (KEP-77 requires it).
pub fn to_raycluster(
    id: &ClusterId,
    spec: &ClusterSpec,
    autoscaling: bool,
    generation: u64,
    queue: Option<&QueueAssignment>,
) -> Value {
    // Elastic pools are always in-tree-autoscaled (research doc §2: elastic
    // mode requires the autoscaler; a non-elastic queue leaves the flag as
    // the operator set it). ADR-0007 still holds: with autoscaling on we
    // never write `replicas`.
    let autoscaling = autoscaling || queue.is_some_and(|q| q.elastic);
    let worker_specs: Vec<Value> = spec
        .worker_groups
        .iter()
        .map(|g| worker_group_spec(&id.0, g, &spec.image, autoscaling, Some(generation)))
        .collect();

    let mut labels = json!({
        MANAGED_BY_LABEL: FIELD_MANAGER,
        CLUSTER_ID_LABEL: id.0,
    });
    let mut annotations = json!({
        GENERATION_ANNOTATION: generation.to_string(),
    });
    if let Some(q) = queue {
        labels[QUEUE_LABEL] = json!(q.queue_name);
        if q.elastic {
            annotations[ELASTIC_JOB_ANNOTATION] = json!("true");
        }
    }

    json!({
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {
            "name": id.0,
            "labels": labels,
            "annotations": annotations,
        },
        "spec": {
            "rayVersion": spec.ray_version,
            "enableInTreeAutoscaling": autoscaling,
            // Mobula owns `suspend` (SSA field manager) so a force re-apply
            // clears an out-of-band `suspend: true` and resumes the cluster
            // (#47). Without this, our field manager never owns the field and
            // a Suspended cluster could never be repaired by re-applying.
            // Note Kueue also drives `suspend` for admission (gang
            // scheduling): it sets suspend=true on unadmitted workloads and
            // false once admitted, so Mobula's desired false never fights
            // Kueue — an admitted cluster converges to running pods.
            "suspend": false,
            "headGroupSpec": head_group_spec(&id.0, spec, Some(generation)),
            "workerGroupSpecs": worker_specs,
        },
    })
}

/// Fingerprint of the Mobula-owned, drift-relevant fields (ADR-0004 drift
/// detection, #41). Deliberately EXCLUDES `replicas`/`scaleStrategy`: those
/// are the autoscaler's when in-tree autoscaling is on (ADR-0007), and even
/// off they converge on their own — so a replica count is never treated as
/// drift. `name`/`project`/`ttl` are control-plane metadata, not on the CR.
/// Both [`to_raycluster`] (implicitly) and [`fingerprint_from_cr`] project the
/// same shape, so an out-of-band edit of an owned field changes the result.
pub fn owned_spec_fingerprint(spec: &ClusterSpec) -> String {
    let workers: Vec<Value> = spec
        .worker_groups
        .iter()
        .map(|g| {
            json!({
                "name": g.name, "cpu": g.cpu, "memory": g.memory, "gpu": g.gpu,
                "min": g.min_replicas, "max": g.max_replicas,
            })
        })
        .collect();
    json!({
        "ray_version": spec.ray_version,
        "image": spec.image,
        "head_cpu": spec.head_cpu,
        "head_memory": spec.head_memory,
        "workers": workers,
    })
    .to_string()
}

/// Recompute the owned-field fingerprint from a *live* RayCluster `.spec`
/// object (the inverse projection of [`to_raycluster`]), so `observe` can
/// detect out-of-band edits. Returns `None` if the manifest is missing the
/// fields we own (nothing to compare). Container resources are read from the
/// first container of each group's pod template, matching [`pod_template`].
pub fn fingerprint_from_cr(cr_spec: &Value) -> Option<String> {
    let head = cr_spec.get("headGroupSpec")?;
    let (head_cpu, head_memory) = container_resources(head)?;
    let workers: Vec<Value> = cr_spec
        .get("workerGroupSpecs")
        .and_then(|w| w.as_array())
        .map(|groups| {
            groups
                .iter()
                .filter_map(|g| {
                    let (cpu, memory) = container_resources(g)?;
                    Some(json!({
                        "name": g.get("groupName").and_then(|v| v.as_str()).unwrap_or(""),
                        "cpu": cpu,
                        "memory": memory,
                        "gpu": container_gpu(g),
                        "min": g.get("minReplicas").and_then(|v| v.as_u64()).unwrap_or(0),
                        "max": g.get("maxReplicas").and_then(|v| v.as_u64()).unwrap_or(0),
                    }))
                })
                .collect()
        })
        .unwrap_or_default();
    Some(
        json!({
            "ray_version": cr_spec.get("rayVersion").and_then(|v| v.as_str()).unwrap_or(""),
            "image": container_image(head).unwrap_or_default(),
            "head_cpu": head_cpu,
            "head_memory": head_memory,
            "workers": workers,
        })
        .to_string(),
    )
}

/// The first container of a group's pod template (`template.spec.containers[0]`).
fn first_container(group: &Value) -> Option<&Value> {
    group
        .get("template")?
        .get("spec")?
        .get("containers")?
        .as_array()?
        .first()
}

fn container_resources(group: &Value) -> Option<(String, String)> {
    let c = first_container(group)?;
    let req = c.get("resources")?.get("requests")?;
    let cpu = req.get("cpu")?.as_str()?.to_string();
    let mem = req.get("memory")?.as_str()?.to_string();
    Some((cpu, mem))
}

fn container_gpu(group: &Value) -> Option<String> {
    first_container(group)?
        .get("resources")?
        .get("requests")?
        .get("nvidia.com/gpu")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn container_image(group: &Value) -> Option<String> {
    first_container(group)?
        .get("image")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn head_group_spec(id: &str, spec: &ClusterSpec, generation: Option<u64>) -> Value {
    json!({
        "rayStartParams": { "dashboard-host": "0.0.0.0" },
        "template": pod_template(
            id,
            "ray-head",
            &spec.image,
            &spec.head_cpu,
            &spec.head_memory,
            None,
            generation,
        ),
    })
}

fn worker_group_spec(
    id: &str,
    g: &WorkerGroup,
    image: &str,
    autoscaling: bool,
    generation: Option<u64>,
) -> Value {
    // Workers run the cluster image (Kubernetes requires an image on every
    // container; KubeRay does NOT copy the head image onto worker groups,
    // so an empty image would be rejected — review R2#1).
    let mut ws = json!({
        "groupName": g.name,
        "minReplicas": g.min_replicas,
        "maxReplicas": g.max_replicas,
        "rayStartParams": {},
        "template": pod_template(id, "ray-worker", image, &g.cpu, &g.memory, g.gpu.as_deref(), generation),
    });
    // ADR-0007: only set `replicas` when we own it (autoscaling off). With
    // the in-tree autoscaler on, the sidecar owns replicas + scaleStrategy;
    // writing them here would fight it.
    if !autoscaling {
        ws["replicas"] = json!(g.replicas);
    }
    ws
}

fn pod_template(
    cluster_id: &str,
    container_name: &str,
    image: &str,
    cpu: &str,
    memory: &str,
    gpu: Option<&str>,
    generation: Option<u64>,
) -> Value {
    let mut limits = json!({ "cpu": cpu, "memory": memory });
    let mut requests = json!({ "cpu": cpu, "memory": memory });
    if let Some(gpu) = gpu {
        limits["nvidia.com/gpu"] = json!(gpu);
        requests["nvidia.com/gpu"] = json!(gpu);
    }
    let mut container = json!({
        "name": container_name,
        "resources": { "limits": limits, "requests": requests },
    });
    // Both head and workers carry the cluster image; only omitted if a
    // caller passes empty (KubeRay then applies its default).
    if !image.is_empty() {
        container["image"] = json!(image);
    }
    // Every tenant pod carries the cluster-id label (#86): it is what the
    // scoped NetworkPolicies select on — the default-deny/tenant-allow pair
    // matches pods with the label at all, and the per-cluster allow matches
    // this exact value, keeping tenant clusters isolated from each other.
    // KubeRay merges its own ray.io/* labels alongside it.
    let mut template = json!({
        "metadata": {
            "labels": { CLUSTER_ID_LABEL: cluster_id },
        },
        "spec": { "containers": [container] },
    });
    // Stamp the generation into the pod template so a spec bump changes the
    // template hash and KubeRay rolls the pods (#40). Services pass None —
    // KubeRay's RayService controller owns their rollout, not Mobula.
    if let Some(gen) = generation {
        template["metadata"]["annotations"] = json!({ GENERATION_ANNOTATION: gen.to_string() });
    }
    template
}

pub const SERVICE_KIND: &str = "RayService";

// ---------------------------------------------------------------------------
// Namespace security posture (#56 tenant network isolation, #62 STIG
// pod-security defaults). These are per-namespace objects — one set covers
// every RayCluster Mobula applies into the namespace — translated here
// (pure) and applied by the live client's `ensure_namespace_posture`.
// ---------------------------------------------------------------------------

pub const NETWORK_POLICY_API_VERSION: &str = "networking.k8s.io/v1";
pub const NETWORK_POLICY_KIND: &str = "NetworkPolicy";
/// The default-deny policy Mobula ensures. Distinct name so an admin's own
/// default-deny is detectable (check-then-apply never overwrites it).
pub const DEFAULT_DENY_POLICY_NAME: &str = "mobula-default-deny";
/// The explicit-allow policy paired with the default-deny.
pub const TENANT_ALLOW_POLICY_NAME: &str = "mobula-tenant-allow";
/// Name prefix of the per-cluster intra-tenant allow policy
/// ([`cluster_allow_network_policy`]); the suffix is the cluster id.
pub const CLUSTER_ALLOW_POLICY_PREFIX: &str = "mobula-cluster-";
/// Namespace label marking the namespace(s) the Mobula control plane
/// (API / reconciler / job gateway) runs in. The tenant allow policy opens
/// ingress from control-plane pods in those namespaces so the control plane
/// can reach the Ray head (dashboard/jobs/metrics 8265, Ray client 10001).
/// Operators label the control-plane namespace once:
/// `kubectl label namespace <ns> mobula.dev/control-plane=true`.
pub const CONTROL_PLANE_NAMESPACE_LABEL: &str = "mobula.dev/control-plane";
/// Pod label marking the Mobula control-plane pods themselves (#86): the
/// tenant allow policy admits ingress from pods carrying this label, never
/// from a whole namespace — a namespace-wide peer would let colocated
/// tenant pods reach each other's head ports. Deployments set it on the
/// Mobula pod template: `mobula.dev/control-plane: "true"`.
pub const CONTROL_PLANE_POD_LABEL: &str = "mobula.dev/control-plane";

/// The pod selector every Mobula tenant policy scopes to (#86): only pods
/// Mobula itself provisioned, recognized by the [`CLUSTER_ID_LABEL`] that
/// [`to_raycluster`] / [`to_rayservice`] stamp onto every head and worker
/// pod template. NEVER an empty (namespace-wide) selector: the kuberay
/// namespace can be — and in the pack deployment is — Mobula's own
/// namespace, and a namespace-wide default-deny locks the control plane,
/// the UI, and the gateway's upstreams out of it (#86). Admin- or
/// pack-managed Ray clusters colocated in the namespace are equally out of
/// scope: their network posture belongs to whoever provisioned them.
fn tenant_pod_selector() -> Value {
    json!({
        "matchExpressions": [
            { "key": CLUSTER_ID_LABEL, "operator": "Exists" },
        ],
    })
}

/// The name of the per-cluster allow policy for cluster `id`.
pub fn cluster_allow_policy_name(id: &str) -> String {
    format!("{CLUSTER_ALLOW_POLICY_PREFIX}{id}")
}

/// The default-deny NetworkPolicy (#56, research: compliance gap §4.3 —
/// the single highest-impact isolation fix): select every *Mobula-
/// provisioned tenant* pod ([`tenant_pod_selector`], #86 — never every pod
/// in the namespace), deny all ingress and egress. NetworkPolicies are
/// additive (union of allows), so pairing this with
/// [`tenant_allow_network_policy`] + the per-cluster
/// [`cluster_allow_network_policy`] yields exactly the allow rules and
/// nothing else — and non-tenant pods in the namespace are untouched.
pub fn default_deny_network_policy() -> Value {
    json!({
        "apiVersion": NETWORK_POLICY_API_VERSION,
        "kind": NETWORK_POLICY_KIND,
        "metadata": {
            "name": DEFAULT_DENY_POLICY_NAME,
            "labels": { MANAGED_BY_LABEL: FIELD_MANAGER },
        },
        "spec": {
            "podSelector": tenant_pod_selector(),
            "policyTypes": ["Ingress", "Egress"],
        },
    })
}

/// The allows every Mobula tenant pod needs under the default-deny (#56),
/// scoped to [`tenant_pod_selector`] (#86). Intra-cluster traffic is NOT
/// here — it is per-cluster ([`cluster_allow_network_policy`]) so tenant
/// clusters stay isolated from each other. This policy carries only the
/// cross-cutting allows:
///
/// - ingress from Mobula control-plane pods ([`CONTROL_PLANE_POD_LABEL`],
///   same namespace or a [`CONTROL_PLANE_NAMESPACE_LABEL`]-labeled one) to
///   the head's dashboard (8265) and Ray client (10001) ports only — GCS
///   is not a control-plane surface;
/// - ingress from the KubeRay operator (any namespace, pods labeled
///   `app.kubernetes.io/name: kuberay-operator`) to the dashboard (8265),
///   dashboard agent (52365) and serve (8000) ports — RayService health
///   checking and serve-config submission need it;
/// - egress to kube-dns (namespace `kube-system`, `k8s-app: kube-dns`,
///   port 53 UDP+TCP) — default-deny otherwise breaks DNS
///   (research §4.3). The `kubernetes.io/metadata.name` namespace label is
///   API-server-managed since 1.22, so this needs no admin labeling.
///
/// TODO(#86): dashboards of provisioned clusters are not reachable from
/// the ingress gateway's namespace (e.g. a NebariApp-exposed dashboard).
/// If that exposure is wanted, it needs an explicit, configurable
/// gateway-namespace ingress knob here — deliberately not built as part of
/// the #86 lockout fix.
pub fn tenant_allow_network_policy() -> Value {
    json!({
        "apiVersion": NETWORK_POLICY_API_VERSION,
        "kind": NETWORK_POLICY_KIND,
        "metadata": {
            "name": TENANT_ALLOW_POLICY_NAME,
            "labels": { MANAGED_BY_LABEL: FIELD_MANAGER },
        },
        "spec": {
            "podSelector": tenant_pod_selector(),
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                // The Mobula control plane → Ray head dashboard/client.
                // Pod-labeled peers only (#86): same-namespace control-plane
                // pods, and control-plane pods in a labeled namespace.
                {
                    "from": [
                        { "podSelector": {
                            "matchLabels": { CONTROL_PLANE_POD_LABEL: "true" },
                        } },
                        {
                            "namespaceSelector": {
                                "matchLabels": { CONTROL_PLANE_NAMESPACE_LABEL: "true" },
                            },
                            "podSelector": {
                                "matchLabels": { CONTROL_PLANE_POD_LABEL: "true" },
                            },
                        },
                    ],
                    "ports": [
                        { "protocol": "TCP", "port": 8265 },
                        { "protocol": "TCP", "port": 10001 },
                    ],
                },
                // The KubeRay operator (wherever it runs) → dashboard,
                // dashboard agent, serve.
                {
                    "from": [
                        {
                            "namespaceSelector": {},
                            "podSelector": {
                                "matchLabels": { "app.kubernetes.io/name": "kuberay-operator" },
                            },
                        },
                    ],
                    "ports": [
                        { "protocol": "TCP", "port": 8265 },
                        { "protocol": "TCP", "port": 52365 },
                        { "protocol": "TCP", "port": 8000 },
                    ],
                },
            ],
            "egress": [
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": { "kubernetes.io/metadata.name": "kube-system" },
                            },
                            "podSelector": {
                                "matchLabels": { "k8s-app": "kube-dns" },
                            },
                        },
                    ],
                    "ports": [
                        { "protocol": "UDP", "port": 53 },
                        { "protocol": "TCP", "port": 53 },
                    ],
                },
            ],
        },
    })
}

/// The per-cluster intra-tenant allow (#86, preserving #56's tenant-vs-
/// tenant isolation): pods of cluster `id` (matched by the exact
/// [`CLUSTER_ID_LABEL`] value) may talk to each other on every port — Ray
/// head↔workers use GCS 6379, dashboard 8265, client 10001 plus the
/// raylet's dynamic ports, too many to enumerate — and to nothing else.
/// Pods of a different cluster carry a different label value, match
/// neither the subject nor the peer selector, and stay unreachable.
/// Applied with the cluster's RayCluster/RayService and deleted with it.
pub fn cluster_allow_network_policy(id: &str) -> Value {
    let same_cluster = json!({
        "matchLabels": { CLUSTER_ID_LABEL: id },
    });
    json!({
        "apiVersion": NETWORK_POLICY_API_VERSION,
        "kind": NETWORK_POLICY_KIND,
        "metadata": {
            "name": cluster_allow_policy_name(id),
            "labels": {
                MANAGED_BY_LABEL: FIELD_MANAGER,
                CLUSTER_ID_LABEL: id,
            },
        },
        "spec": {
            "podSelector": &same_cluster,
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                { "from": [ { "podSelector": &same_cluster } ] },
            ],
            "egress": [
                { "to": [ { "podSelector": &same_cluster } ] },
            ],
        },
    })
}

pub const PSS_ENFORCE_LABEL: &str = "pod-security.kubernetes.io/enforce";
pub const PSS_WARN_LABEL: &str = "pod-security.kubernetes.io/warn";
pub const PSS_AUDIT_LABEL: &str = "pod-security.kubernetes.io/audit";

/// Pod Security Standards namespace labels (#62, K8s STIG V-242437).
/// `enforce` is **baseline**, not restricted: KubeRay-generated Ray pods do
/// not carry the full restricted securityContext (`runAsNonRoot`, seccomp,
/// drop-all capabilities), so enforcing restricted would reject every Ray
/// pod Mobula provisions. `warn`/`audit` at restricted still surface the
/// gap (and the evidence trail) without breaking workloads; an admin can
/// tighten `enforce` to `restricted` once tenant images comply — the live
/// client never downgrades a stricter existing level.
pub fn namespace_pss_labels() -> Value {
    json!({
        PSS_ENFORCE_LABEL: "baseline",
        PSS_WARN_LABEL: "restricted",
        PSS_AUDIT_LABEL: "restricted",
    })
}

/// Structural check for check-then-apply (#56): does this NetworkPolicy
/// object deny all ingress+egress for every pod in the namespace? Used to
/// detect an admin-managed default-deny Mobula must not touch. `policy` is
/// the full object (or its `data` for a dynamic object); the spec must have
/// an empty `podSelector` (all pods), both policyTypes, and no allow rules.
pub fn is_default_deny(policy: &Value) -> bool {
    let Some(spec) = policy.get("spec") else {
        return false;
    };
    let selects_all = spec
        .get("podSelector")
        .and_then(|s| s.as_object())
        .is_some_and(|m| m.is_empty());
    let types: Vec<&str> = spec
        .get("policyTypes")
        .and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let denies_both = types.contains(&"Ingress") && types.contains(&"Egress");
    let no_rules = |key: &str| match spec.get(key) {
        None => true,
        Some(v) => v.as_array().is_some_and(|a| a.is_empty()),
    };
    selects_all && denies_both && no_rules("ingress") && no_rules("egress")
}

/// The partial manifest a suspend/resume call actuates (#51): a JSON merge
/// patch flipping only `spec.suspend`. Deliberately NOT a server-side apply:
/// a partial SSA apply with Mobula's field manager is fully-specified intent
/// and would drop every other Mobula-owned field from the applied set. Mobula
/// already owns `spec.suspend` via the full apply ([`to_raycluster`] always
/// writes it), so a merge patch flips the value while single-writer ownership
/// (ADR-0007) stays with the `mobula` field manager.
pub fn suspend_patch(suspend: bool) -> Value {
    json!({ "spec": { "suspend": suspend } })
}

/// Build the RayService manifest for a Serve service. The `serveConfigV2`
/// is passed through verbatim; `upgradeStrategy` selects canary
/// (NewCluster — zero-downtime with safe rollback) vs in-place (None).
pub fn to_rayservice(name: &str, spec: &ServiceSpec) -> Value {
    let upgrade = match spec.upgrade {
        UpgradeStrategy::Canary => "NewCluster",
        UpgradeStrategy::InPlace => "None",
    };
    let worker = WorkerGroup {
        name: "worker".into(),
        cpu: spec.worker_cpu.clone(),
        memory: spec.worker_memory.clone(),
        gpu: None,
        min_replicas: spec.worker_replicas,
        max_replicas: spec.worker_replicas,
        replicas: spec.worker_replicas,
    };
    json!({
        "apiVersion": API_VERSION,
        "kind": SERVICE_KIND,
        "metadata": {
            "name": name,
            "labels": {
                MANAGED_BY_LABEL: FIELD_MANAGER,
                CLUSTER_ID_LABEL: name,
            },
        },
        "spec": {
            "serveConfigV2": spec.serve_config_v2,
            "upgradeStrategy": { "type": upgrade },
            "rayClusterConfig": {
                "rayVersion": spec.ray_version,
                "headGroupSpec": {
                    "rayStartParams": { "dashboard-host": "0.0.0.0" },
                    "template": pod_template(name, "ray-head", &spec.image, &spec.head_cpu, &spec.head_memory, None, None),
                },
                // Serve worker replicas are fixed here; Serve autoscaling is
                // Ray Serve's own concern (deployment num_replicas).
                "workerGroupSpecs": [worker_group_spec(name, &worker, &spec.image, false, None)],
            },
        },
    })
}

/// Map a RayService `.status.serviceStatus` to a Mobula [`ClusterState`].
/// KubeRay reports "Running" once the Serve app is healthy and serving.
pub fn service_status_to_state(status: &Value) -> ClusterState {
    match status.get("serviceStatus").and_then(|s| s.as_str()) {
        Some("Running") => ClusterState::Running,
        // A new version is being rolled out / health-checked.
        Some("Restarting") | Some("UpgradingCluster") => ClusterState::Updating,
        Some("") | None => ClusterState::Provisioning,
        _ => ClusterState::Provisioning,
    }
}

/// Map a RayCluster `.status` object to a Mobula [`ClusterState`]
/// (observation-first, ADR-0006 — derived from observed reality, never a
/// stored phase). KubeRay reports `.status.state` as "ready"/"unhealthy"/
/// "suspended" and carries `.status.conditions`.
pub fn status_to_state(status: &Value) -> ClusterState {
    match status.get("state").and_then(|s| s.as_str()) {
        Some("ready") => ClusterState::Running,
        Some("suspended") => ClusterState::Suspended,
        Some("unhealthy") => ClusterState::Degraded,
        // No state yet → still coming up.
        _ => ClusterState::Provisioning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::{ServiceSpec, UpgradeStrategy, WorkerGroup};

    fn service_spec(upgrade: UpgradeStrategy) -> ServiceSpec {
        ServiceSpec {
            name: "svc".into(),
            project: "p".into(),
            ray_version: "2.57.0".into(),
            image: "rayproject/ray:2.57.0".into(),
            serve_config_v2: "applications:\n  - name: app\n".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_replicas: 2,
            worker_cpu: "1".into(),
            worker_memory: "2Gi".into(),
            upgrade,
        }
    }

    #[test]
    fn rayservice_canary_vs_inplace_upgrade_strategy() {
        let canary = to_rayservice("svc", &service_spec(UpgradeStrategy::Canary));
        assert_eq!(canary["kind"], "RayService");
        assert_eq!(canary["spec"]["upgradeStrategy"]["type"], "NewCluster");
        assert!(canary["spec"]["serveConfigV2"]
            .as_str()
            .unwrap()
            .contains("applications"));
        assert_eq!(
            canary["spec"]["rayClusterConfig"]["workerGroupSpecs"][0]["replicas"],
            2
        );

        let inplace = to_rayservice("svc", &service_spec(UpgradeStrategy::InPlace));
        assert_eq!(inplace["spec"]["upgradeStrategy"]["type"], "None");
    }

    #[test]
    fn rayservice_status_mapping() {
        assert_eq!(
            service_status_to_state(&json!({"serviceStatus": "Running"})),
            ClusterState::Running
        );
        assert_eq!(
            service_status_to_state(&json!({"serviceStatus": "Restarting"})),
            ClusterState::Updating
        );
        assert_eq!(
            service_status_to_state(&json!({})),
            ClusterState::Provisioning
        );
        // An unrecognized status string is not Running: still coming up.
        assert_eq!(
            service_status_to_state(&json!({"serviceStatus": "Preparing"})),
            ClusterState::Provisioning
        );
    }

    fn spec(autoscale_groups: &[(&str, u32, u32, u32)]) -> ClusterSpec {
        ClusterSpec {
            name: "demo".into(),
            project: "p".into(),
            ray_version: "2.57.0".into(),
            image: "rayproject/ray:2.57.0".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: autoscale_groups
                .iter()
                .map(|(n, mn, mx, r)| WorkerGroup {
                    name: (*n).into(),
                    cpu: "1".into(),
                    memory: "2Gi".into(),
                    gpu: None,
                    min_replicas: *mn,
                    max_replicas: *mx,
                    replicas: *r,
                })
                .collect(),
            ttl_seconds: None,
        }
    }

    #[test]
    fn manifest_shape_and_labels() {
        let m = to_raycluster(
            &ClusterId("demo".into()),
            &spec(&[("cpu", 0, 4, 2)]),
            false,
            1,
            None,
        );
        assert_eq!(m["apiVersion"], "ray.io/v1");
        assert_eq!(m["kind"], "RayCluster");
        assert_eq!(m["metadata"]["name"], "demo");
        assert_eq!(m["metadata"]["labels"][MANAGED_BY_LABEL], "mobula");
        assert_eq!(m["metadata"]["labels"][CLUSTER_ID_LABEL], "demo");
        assert_eq!(m["spec"]["rayVersion"], "2.57.0");
        assert_eq!(
            m["spec"]["headGroupSpec"]["template"]["spec"]["containers"][0]["image"],
            "rayproject/ray:2.57.0"
        );
    }

    #[test]
    fn autoscaling_off_sets_replicas() {
        let m = to_raycluster(
            &ClusterId("demo".into()),
            &spec(&[("cpu", 0, 4, 2)]),
            false,
            1,
            None,
        );
        let wg = &m["spec"]["workerGroupSpecs"][0];
        assert_eq!(m["spec"]["enableInTreeAutoscaling"], false);
        assert_eq!(wg["replicas"], 2);
        assert_eq!(wg["minReplicas"], 0);
        assert_eq!(wg["maxReplicas"], 4);
        // Workers must carry the cluster image or the API server rejects
        // the pod (review R2#1).
        assert_eq!(
            wg["template"]["spec"]["containers"][0]["image"],
            "rayproject/ray:2.57.0"
        );
    }

    #[test]
    fn autoscaling_on_omits_replicas_adr_0007() {
        let m = to_raycluster(
            &ClusterId("demo".into()),
            &spec(&[("cpu", 1, 8, 3)]),
            true,
            1,
            None,
        );
        let wg = &m["spec"]["workerGroupSpecs"][0];
        assert_eq!(m["spec"]["enableInTreeAutoscaling"], true);
        // The autoscaler sidecar owns replicas — Mobula must not write it.
        assert!(
            wg.get("replicas").is_none(),
            "replicas must be unset when autoscaling"
        );
        assert!(
            wg.get("scaleStrategy").is_none(),
            "scaleStrategy is the sidecar's"
        );
        // We still own the bounds.
        assert_eq!(wg["minReplicas"], 1);
        assert_eq!(wg["maxReplicas"], 8);
    }

    #[test]
    fn gpu_workers_get_resource_limits() {
        let mut s = spec(&[("gpu", 0, 2, 1)]);
        s.worker_groups[0].gpu = Some("1".into());
        let m = to_raycluster(&ClusterId("demo".into()), &s, false, 1, None);
        let res =
            &m["spec"]["workerGroupSpecs"][0]["template"]["spec"]["containers"][0]["resources"];
        assert_eq!(res["limits"]["nvidia.com/gpu"], "1");
        assert_eq!(res["requests"]["nvidia.com/gpu"], "1");
    }

    #[test]
    fn to_raycluster_sets_suspend_false() {
        // #47: Mobula must own spec.suspend so a force re-apply resumes an
        // out-of-band-suspended cluster.
        let m = to_raycluster(
            &ClusterId("demo".into()),
            &spec(&[("cpu", 0, 4, 2)]),
            false,
            1,
            None,
        );
        assert_eq!(m["spec"]["suspend"], serde_json::json!(false));
    }

    #[test]
    fn suspend_patch_flips_only_the_suspend_field() {
        // #51: the suspend/resume actuation is a merge patch touching only
        // spec.suspend — Mobula owns the field (to_raycluster always writes
        // it), so ownership stays with the `mobula` field manager.
        assert_eq!(suspend_patch(true), json!({ "spec": { "suspend": true } }));
        assert_eq!(
            suspend_patch(false),
            json!({ "spec": { "suspend": false } })
        );
        // The patch must carry nothing else — a partial SSA apply would be
        // fully-specified intent and drop Mobula's other owned fields.
        assert_eq!(suspend_patch(true)["spec"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn owned_fingerprint_round_trips_through_the_manifest() {
        // #41: the fingerprint recomputed from a freshly-built manifest must
        // equal the desired fingerprint, so an unedited cluster never looks
        // drifted.
        let s = spec(&[("cpu", 0, 4, 2)]);
        let m = to_raycluster(&ClusterId("demo".into()), &s, false, 1, None);
        let from_cr = fingerprint_from_cr(&m["spec"]).expect("fingerprint from CR");
        assert_eq!(owned_spec_fingerprint(&s), from_cr);
    }

    #[test]
    fn owned_fingerprint_ignores_replicas_but_catches_image() {
        // #41 + ADR-0007: replica count is excluded (autoscaler-owned); an
        // image change is real drift.
        let a = spec(&[("cpu", 0, 4, 2)]);
        let mut b = spec(&[("cpu", 0, 4, 9)]); // only replicas differ
        assert_eq!(
            owned_spec_fingerprint(&a),
            owned_spec_fingerprint(&b),
            "replica delta must not change the fingerprint"
        );
        b.image = "rayproject/ray:9.9.9".into();
        assert_ne!(
            owned_spec_fingerprint(&a),
            owned_spec_fingerprint(&b),
            "an image edit must change the fingerprint"
        );
    }

    #[test]
    fn status_mapping() {
        assert_eq!(
            status_to_state(&json!({"state": "ready"})),
            ClusterState::Running
        );
        assert_eq!(
            status_to_state(&json!({"state": "suspended"})),
            ClusterState::Suspended
        );
        assert_eq!(
            status_to_state(&json!({"state": "unhealthy"})),
            ClusterState::Degraded
        );
        assert_eq!(status_to_state(&json!({})), ClusterState::Provisioning);
        assert_eq!(status_to_state(&Value::Null), ClusterState::Provisioning);
    }

    #[test]
    fn no_queue_assignment_is_byte_identical_to_before() {
        // The queue-free form must not change: no queue label, no elastic
        // annotation, autoscaling flag exactly as passed.
        let s = spec(&[("cpu", 0, 4, 2)]);
        let m = to_raycluster(&ClusterId("demo".into()), &s, false, 1, None);
        assert!(m["metadata"]["labels"].get(QUEUE_LABEL).is_none());
        assert!(m["metadata"]["annotations"]
            .get(ELASTIC_JOB_ANNOTATION)
            .is_none());
        assert_eq!(m["spec"]["enableInTreeAutoscaling"], false);
    }

    #[test]
    fn queue_assignment_stamps_queue_label() {
        let s = spec(&[("cpu", 0, 4, 2)]);
        let q = QueueAssignment {
            queue_name: "proj-a".into(),
            elastic: false,
        };
        let m = to_raycluster(&ClusterId("demo".into()), &s, false, 1, Some(&q));
        assert_eq!(m["metadata"]["labels"][QUEUE_LABEL], "proj-a");
        // Non-elastic: no annotation, autoscaling flag untouched.
        assert!(m["metadata"]["annotations"]
            .get(ELASTIC_JOB_ANNOTATION)
            .is_none());
        assert_eq!(m["spec"]["enableInTreeAutoscaling"], false);
        // replicas still owned by Mobula (ADR-0007 unchanged).
        assert_eq!(m["spec"]["workerGroupSpecs"][0]["replicas"], 2);
    }

    #[test]
    fn elastic_assignment_forces_autoscaling_and_annotation() {
        let s = spec(&[("cpu", 0, 4, 2)]);
        let q = QueueAssignment {
            queue_name: "proj-a".into(),
            elastic: true,
        };
        // autoscaling=false passed, but elastic mode requires the in-tree
        // autoscaler — it must win (research doc §2).
        let m = to_raycluster(&ClusterId("demo".into()), &s, false, 1, Some(&q));
        assert_eq!(m["metadata"]["labels"][QUEUE_LABEL], "proj-a");
        assert_eq!(m["metadata"]["annotations"][ELASTIC_JOB_ANNOTATION], "true");
        assert_eq!(m["spec"]["enableInTreeAutoscaling"], true);
        // ADR-0007 unaffected: with autoscaling on, Mobula never writes
        // replicas (the autoscaler sidecar owns it).
        assert!(m["spec"]["workerGroupSpecs"][0].get("replicas").is_none());
        assert_eq!(m["spec"]["workerGroupSpecs"][0]["maxReplicas"], 4);
    }

    /// The tenant selector every namespace-level policy must scope to:
    /// pods carrying the Mobula cluster-id label at all.
    fn tenant_selector() -> Value {
        json!({
            "matchExpressions": [
                { "key": CLUSTER_ID_LABEL, "operator": "Exists" },
            ],
        })
    }

    #[test]
    fn default_deny_policy_shape() {
        // #56: deny all ingress+egress, carry no allow rules — the allow
        // rules live only in the tenant-allow / per-cluster policies.
        // #86: select ONLY Mobula-provisioned tenant pods, never every pod
        // in the namespace — a namespace-wide deny locks the control plane
        // (and the gateway's upstreams) out of its own namespace.
        let p = default_deny_network_policy();
        assert_eq!(p["apiVersion"], "networking.k8s.io/v1");
        assert_eq!(p["kind"], "NetworkPolicy");
        assert_eq!(p["metadata"]["name"], DEFAULT_DENY_POLICY_NAME);
        assert_eq!(p["metadata"]["labels"][MANAGED_BY_LABEL], "mobula");
        let spec = &p["spec"];
        assert_eq!(spec["podSelector"], tenant_selector());
        assert_ne!(
            spec["podSelector"],
            json!({}),
            "the deny must never be namespace-wide (#86)"
        );
        assert_eq!(spec["policyTypes"], json!(["Ingress", "Egress"]));
        assert!(spec.get("ingress").is_none());
        assert!(spec.get("egress").is_none());
        // The scoped deny is NOT a namespace-wide default-deny: the
        // check-then-apply probe only skips posture setup for an
        // admin-managed deny-all, which this deliberately is not.
        assert!(!is_default_deny(&p));
    }

    #[test]
    fn tenant_allow_policy_shape() {
        // #56/#86: exactly the cross-cutting allows every tenant pod needs —
        // control-plane-pod ingress to the head's dashboard/client ports,
        // KubeRay-operator ingress, kube-dns egress — and nothing else.
        // Intra-cluster traffic is per-cluster (cluster_allow_network_policy),
        // NOT here: a namespace-wide pod-to-pod allow would let tenant A
        // reach tenant B.
        let p = tenant_allow_network_policy();
        assert_eq!(p["metadata"]["name"], TENANT_ALLOW_POLICY_NAME);
        assert_eq!(p["metadata"]["labels"][MANAGED_BY_LABEL], "mobula");
        let spec = &p["spec"];
        assert_eq!(spec["podSelector"], tenant_selector());
        assert_eq!(spec["policyTypes"], json!(["Ingress", "Egress"]));
        // An allow policy is not a default-deny (the probe must not skip
        // posture setup because of it).
        assert!(!is_default_deny(&p));

        let ingress = spec["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 2);
        // Mobula control plane → head: dashboard (8265) + Ray client
        // (10001) only, and only from pods carrying the control-plane pod
        // label (#86) — same namespace or a labeled one. Never a bare
        // namespaceSelector: that would admit colocated tenant pods.
        assert_eq!(
            ingress[0]["from"],
            json!([
                { "podSelector": {
                    "matchLabels": { CONTROL_PLANE_POD_LABEL: "true" },
                } },
                {
                    "namespaceSelector": {
                        "matchLabels": { CONTROL_PLANE_NAMESPACE_LABEL: "true" },
                    },
                    "podSelector": {
                        "matchLabels": { CONTROL_PLANE_POD_LABEL: "true" },
                    },
                },
            ])
        );
        assert_eq!(
            ingress[0]["ports"],
            json!([
                { "protocol": "TCP", "port": 8265 },
                { "protocol": "TCP", "port": 10001 },
            ])
        );
        // KubeRay operator (any namespace, operator pods only) → dashboard,
        // dashboard agent, serve.
        assert_eq!(
            ingress[1]["from"],
            json!([{
                "namespaceSelector": {},
                "podSelector": {
                    "matchLabels": { "app.kubernetes.io/name": "kuberay-operator" },
                },
            }])
        );
        assert_eq!(
            ingress[1]["ports"],
            json!([
                { "protocol": "TCP", "port": 8265 },
                { "protocol": "TCP", "port": 52365 },
                { "protocol": "TCP", "port": 8000 },
            ])
        );

        let egress = spec["egress"].as_array().unwrap();
        assert_eq!(egress.len(), 1);
        // kube-dns only: kube-system namespace + kube-dns pods, 53 UDP+TCP.
        assert_eq!(
            egress[0]["to"],
            json!([{
                "namespaceSelector": {
                    "matchLabels": { "kubernetes.io/metadata.name": "kube-system" },
                },
                "podSelector": { "matchLabels": { "k8s-app": "kube-dns" } },
            }])
        );
        assert_eq!(
            egress[0]["ports"],
            json!([
                { "protocol": "UDP", "port": 53 },
                { "protocol": "TCP", "port": 53 },
            ])
        );
    }

    #[test]
    fn cluster_allow_policy_is_scoped_to_one_cluster() {
        // #86: intra-cluster traffic is allowed per cluster — the subject
        // and every peer match the exact cluster-id label value, all ports
        // (GCS 6379, dashboard 8265, client 10001, raylet dynamic ports).
        let p = cluster_allow_network_policy("tenant-a");
        assert_eq!(p["apiVersion"], "networking.k8s.io/v1");
        assert_eq!(p["kind"], "NetworkPolicy");
        assert_eq!(p["metadata"]["name"], "mobula-cluster-tenant-a");
        assert_eq!(p["metadata"]["labels"][MANAGED_BY_LABEL], "mobula");
        assert_eq!(p["metadata"]["labels"][CLUSTER_ID_LABEL], "tenant-a");
        let spec = &p["spec"];
        let own = json!({ "matchLabels": { CLUSTER_ID_LABEL: "tenant-a" } });
        assert_eq!(spec["podSelector"], own);
        assert_eq!(spec["policyTypes"], json!(["Ingress", "Egress"]));
        let ingress = spec["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 1);
        assert_eq!(ingress[0]["from"], json!([{ "podSelector": own }]));
        assert!(ingress[0].get("ports").is_none());
        let egress = spec["egress"].as_array().unwrap();
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0]["to"], json!([{ "podSelector": own }]));
        assert!(egress[0].get("ports").is_none());
        assert!(!is_default_deny(&p));
    }

    #[test]
    fn tenant_clusters_stay_isolated_from_each_other() {
        // #56 intent under the #86 rescope: a pod of tenant-b (labels
        // cluster-id=tenant-b) matches neither the subject nor any allow
        // peer of tenant-a's policy — and the namespace-level tenant-allow
        // has no pod-to-pod rule at all — so B cannot reach A.
        let a = cluster_allow_network_policy("tenant-a");
        let b_labels = json!({ CLUSTER_ID_LABEL: "tenant-b" });
        for rule in a["spec"]["ingress"].as_array().unwrap() {
            for peer in rule["from"].as_array().unwrap() {
                let sel = &peer["podSelector"]["matchLabels"];
                assert_ne!(sel, &b_labels, "tenant-b must not be an allowed peer");
                assert_eq!(sel, &json!({ CLUSTER_ID_LABEL: "tenant-a" }));
            }
        }
        let shared = tenant_allow_network_policy();
        for rule in shared["spec"]["ingress"].as_array().unwrap() {
            for peer in rule["from"].as_array().unwrap() {
                assert_ne!(
                    peer["podSelector"],
                    json!({}),
                    "no allow rule may admit arbitrary same-namespace pods"
                );
                assert!(
                    peer["podSelector"].get("matchLabels").is_some(),
                    "every peer must be pod-label-scoped: {peer}"
                );
            }
        }
    }

    #[test]
    fn no_mobula_policy_selects_namespace_wide() {
        // #86 regression pin: no Mobula NetworkPolicy may carry an empty
        // (namespace-wide) podSelector — that is exactly the shape that
        // locked the control plane out of its own namespace. Non-tenant
        // pods (the Mobula API/UI, gateway upstreams, colocated services)
        // must be unaffected by every policy Mobula ensures.
        for p in [
            default_deny_network_policy(),
            tenant_allow_network_policy(),
            cluster_allow_network_policy("demo"),
        ] {
            let sel = &p["spec"]["podSelector"];
            assert_ne!(
                sel,
                &json!({}),
                "{} must not select the whole namespace",
                p["metadata"]["name"]
            );
            let non_empty = sel
                .get("matchLabels")
                .and_then(|m| m.as_object())
                .is_some_and(|m| !m.is_empty())
                || sel
                    .get("matchExpressions")
                    .and_then(|m| m.as_array())
                    .is_some_and(|a| !a.is_empty());
            assert!(
                non_empty,
                "{} podSelector must positively select tenant pods",
                p["metadata"]["name"]
            );
        }
    }

    #[test]
    fn pod_templates_carry_the_cluster_id_label() {
        // #86: the scoped policies select on the cluster-id pod label, so
        // every head and worker template Mobula renders must carry it —
        // RayCluster and RayService alike (a RayService's generated
        // RayClusters inherit the template labels across upgrades).
        let m = to_raycluster(
            &ClusterId("demo".into()),
            &spec(&[("cpu", 0, 4, 2)]),
            false,
            1,
            None,
        );
        assert_eq!(
            m["spec"]["headGroupSpec"]["template"]["metadata"]["labels"][CLUSTER_ID_LABEL],
            "demo"
        );
        assert_eq!(
            m["spec"]["workerGroupSpecs"][0]["template"]["metadata"]["labels"][CLUSTER_ID_LABEL],
            "demo"
        );
        // The generation annotation still rides the same metadata (#40).
        assert_eq!(
            m["spec"]["headGroupSpec"]["template"]["metadata"]["annotations"]
                [GENERATION_ANNOTATION],
            "1"
        );

        let s = to_rayservice("svc", &service_spec(UpgradeStrategy::Canary));
        let cfg = &s["spec"]["rayClusterConfig"];
        assert_eq!(
            cfg["headGroupSpec"]["template"]["metadata"]["labels"][CLUSTER_ID_LABEL],
            "svc"
        );
        assert_eq!(
            cfg["workerGroupSpecs"][0]["template"]["metadata"]["labels"][CLUSTER_ID_LABEL],
            "svc"
        );
    }

    #[test]
    fn control_plane_reaches_the_head_dashboard() {
        // #86: the job gateway / lifecycle path (mobula pod → head:8265)
        // must stay explicitly allowed — as a pod-label-scoped peer, not
        // namespace-wide openness.
        let p = tenant_allow_network_policy();
        let rule = &p["spec"]["ingress"][0];
        let same_ns_peer = &rule["from"][0];
        assert_eq!(
            same_ns_peer["podSelector"]["matchLabels"][CONTROL_PLANE_POD_LABEL],
            "true"
        );
        let ports = rule["ports"].as_array().unwrap();
        assert!(
            ports.iter().any(|p| p["port"] == 8265),
            "dashboard/job port 8265 must be allowed from the control plane"
        );
    }

    #[test]
    fn pss_labels_enforce_baseline_warn_audit_restricted() {
        // #62 (K8s STIG V-242437): enforce=baseline (restricted would reject
        // KubeRay-generated Ray pods), warn+audit=restricted to surface the
        // gap without breaking workloads.
        let labels = namespace_pss_labels();
        assert_eq!(labels[PSS_ENFORCE_LABEL], "baseline");
        assert_eq!(labels[PSS_WARN_LABEL], "restricted");
        assert_eq!(labels[PSS_AUDIT_LABEL], "restricted");
    }

    #[test]
    fn is_default_deny_recognizes_foreign_deny_all() {
        // #56 check-then-apply: an admin-managed deny-all (any name, no
        // Mobula labels) must be detected so Mobula leaves the stricter
        // posture untouched.
        let foreign = json!({
            "metadata": { "name": "org-deny-all" },
            "spec": { "podSelector": {}, "policyTypes": ["Egress", "Ingress"] },
        });
        assert!(is_default_deny(&foreign));
        // Explicit empty rule arrays still count as deny-all.
        let explicit_empty = json!({
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        });
        assert!(is_default_deny(&explicit_empty));

        // Not default-deny: has allow rules, selects specific pods, covers
        // only one direction, or is malformed.
        let with_rules = json!({
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{ "from": [{ "podSelector": {} }] }],
            },
        });
        assert!(!is_default_deny(&with_rules));
        let selective = json!({
            "spec": {
                "podSelector": { "matchLabels": { "app": "x" } },
                "policyTypes": ["Ingress", "Egress"],
            },
        });
        assert!(!is_default_deny(&selective));
        let ingress_only = json!({
            "spec": { "podSelector": {}, "policyTypes": ["Ingress"] },
        });
        assert!(!is_default_deny(&ingress_only));
        assert!(!is_default_deny(&json!({})));
        assert!(!is_default_deny(&json!({ "spec": {} })));
    }
}
