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
    ClusterId, ClusterSpec, ClusterState, ResolvedPodShape, ServiceSpec, UpgradeStrategy,
    WorkerGroup,
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
        .map(|g| {
            worker_group_spec(
                g,
                &spec.image,
                autoscaling,
                Some(generation),
                spec.pod_resolved.as_ref(),
            )
        })
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
            "headGroupSpec": head_group_spec(spec, Some(generation)),
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
///
/// Pod shaping (#66) is included per group — head *and* every worker — and
/// both sides derive it through [`shape_from_pod_template`]: here by
/// projecting the templates this module would render, there by projecting
/// the live ones. Going through the same projection is what keeps the two
/// symmetric: an out-of-band edit that strips a mount or swaps the service
/// account reads as drift, and a round-trip of our own manifest never does.
pub fn owned_spec_fingerprint(spec: &ClusterSpec) -> String {
    let workers: Vec<Value> = spec
        .worker_groups
        .iter()
        .map(|g| {
            json!({
                "name": g.name, "cpu": g.cpu, "memory": g.memory, "gpu": g.gpu,
                "min": g.min_replicas, "max": g.max_replicas,
                // Per-group, not just head: the same shape is applied to
                // every group, so an edit that strips a mount from ONE
                // worker group would otherwise be invisible.
                // `autoscaling: true` only suppresses `replicas`, which
                // the projection never reads.
                "pod": shape_from_pod_template(&worker_group_spec(
                    g,
                    &spec.image,
                    true,
                    None,
                    spec.pod_resolved.as_ref(),
                )),
            })
        })
        .collect();
    json!({
        "ray_version": spec.ray_version,
        "image": spec.image,
        "head_cpu": spec.head_cpu,
        "head_memory": spec.head_memory,
        "workers": workers,
        "pod": shape_from_pod_template(&head_group_spec(spec, None)),
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
                        "pod": shape_from_pod_template(g),
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
            "pod": shape_from_pod_template(head),
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

fn head_group_spec(spec: &ClusterSpec, generation: Option<u64>) -> Value {
    json!({
        "rayStartParams": { "dashboard-host": "0.0.0.0" },
        "template": pod_template(
            "ray-head",
            &spec.image,
            &spec.head_cpu,
            &spec.head_memory,
            None,
            generation,
            spec.pod_resolved.as_ref(),
        ),
    })
}

fn worker_group_spec(
    g: &WorkerGroup,
    image: &str,
    autoscaling: bool,
    generation: Option<u64>,
    shape: Option<&ResolvedPodShape>,
) -> Value {
    // Workers run the cluster image (Kubernetes requires an image on every
    // container; KubeRay does NOT copy the head image onto worker groups,
    // so an empty image would be rejected — review R2#1).
    let mut ws = json!({
        "groupName": g.name,
        "minReplicas": g.min_replicas,
        "maxReplicas": g.max_replicas,
        "rayStartParams": {},
        "template": pod_template(
            "ray-worker",
            image,
            &g.cpu,
            &g.memory,
            g.gpu.as_deref(),
            generation,
            shape,
        ),
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
    container_name: &str,
    image: &str,
    cpu: &str,
    memory: &str,
    gpu: Option<&str>,
    generation: Option<u64>,
    shape: Option<&ResolvedPodShape>,
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
    let mut pod_spec = json!({ "containers": [container] });
    // Pod shaping (#66). Absent or empty leaves the manifest byte-identical
    // to the pre-#66 form, so an unconfigured deployment sees no change.
    if let Some(s) = shape.filter(|s| !s.is_empty()) {
        apply_pod_shape(&mut pod_spec, s);
    }
    let mut template = json!({ "spec": pod_spec });
    // Stamp the generation into the pod template so a spec bump changes the
    // template hash and KubeRay rolls the pods (#40). Services pass None —
    // KubeRay's RayService controller owns their rollout, not Mobula.
    if let Some(gen) = generation {
        template["metadata"] = json!({
            "annotations": { GENERATION_ANNOTATION: gen.to_string() },
        });
    }
    template
}

/// Render an already-authorized [`ResolvedPodShape`] into a pod spec: env
/// and volume mounts onto every container, volumes/serviceAccountName/
/// nodeSelector/tolerations onto the pod.
///
/// Nothing here validates: by the time a shape reaches this function the
/// policy layer has already decided the caller may have it
/// (`mobula_policy::podshape::resolve`). Keeping the check upstream is what
/// lets this stay a pure rendering step.
fn apply_pod_shape(pod_spec: &mut Value, shape: &ResolvedPodShape) {
    if !shape.env.is_empty() || !shape.volumes.is_empty() {
        let env: Vec<Value> = shape
            .env
            .iter()
            .map(|e| json!({ "name": e.name, "value": e.value }))
            .collect();
        let mounts: Vec<Value> = shape
            .volumes
            .iter()
            .map(|v| {
                let mut m = json!({
                    "name": v.name,
                    "mountPath": v.mount_path,
                    "readOnly": v.read_only,
                });
                if let Some(sp) = &v.sub_path {
                    m["subPath"] = json!(sp);
                }
                m
            })
            .collect();
        if let Some(containers) = pod_spec
            .get_mut("containers")
            .and_then(|c| c.as_array_mut())
        {
            for c in containers {
                if !env.is_empty() {
                    c["env"] = json!(env);
                }
                if !mounts.is_empty() {
                    c["volumeMounts"] = json!(mounts);
                }
            }
        }
    }
    if !shape.volumes.is_empty() {
        pod_spec["volumes"] = json!(shape
            .volumes
            .iter()
            .map(|v| json!({
                "name": v.name,
                "persistentVolumeClaim": {
                    "claimName": v.claim_name,
                    "readOnly": v.read_only,
                },
            }))
            .collect::<Vec<_>>());
    }
    if let Some(sa) = &shape.service_account {
        pod_spec["serviceAccountName"] = json!(sa);
    }
    if !shape.node_selector.is_empty() {
        pod_spec["nodeSelector"] = json!(shape.node_selector);
    }
    if !shape.tolerations.is_empty() {
        pod_spec["tolerations"] = json!(shape
            .tolerations
            .iter()
            .map(|t| {
                let mut v = json!({
                    "key": t.key,
                    "operator": t.operator,
                    "effect": t.effect,
                });
                if let Some(val) = &t.value {
                    v["value"] = json!(val);
                }
                v
            })
            .collect::<Vec<_>>());
    }
}

/// Project the pod shaping back out of a live pod template, so
/// [`fingerprint_from_cr`] compares the same shape [`owned_spec_fingerprint`]
/// projects. Reads the first container (matching [`pod_template`]) plus the
/// pod-level fields.
fn shape_from_pod_template(group: &Value) -> Value {
    let spec = group.get("template").and_then(|t| t.get("spec"));
    let container = first_container(group);
    let list = |v: Option<&Value>| v.and_then(|v| v.as_array()).cloned().unwrap_or_default();
    json!({
        "env": list(container.and_then(|c| c.get("env"))),
        "volumeMounts": list(container.and_then(|c| c.get("volumeMounts"))),
        "volumes": list(spec.and_then(|s| s.get("volumes"))),
        "serviceAccountName": spec
            .and_then(|s| s.get("serviceAccountName"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "nodeSelector": spec.and_then(|s| s.get("nodeSelector")).cloned().unwrap_or(json!({})),
        "tolerations": list(spec.and_then(|s| s.get("tolerations"))),
    })
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
/// Namespace label marking the namespace(s) the Mobula control plane
/// (API / reconciler / job gateway) runs in. The tenant allow policy opens
/// ingress from those namespaces so the control plane can reach the Ray
/// head (dashboard/jobs/metrics 8265, Ray client 10001). Operators label
/// the control-plane namespace once:
/// `kubectl label namespace <ns> mobula.dev/control-plane=true`.
pub const CONTROL_PLANE_NAMESPACE_LABEL: &str = "mobula.dev/control-plane";

/// The default-deny NetworkPolicy (#56, research: compliance gap §4.3 —
/// the single highest-impact isolation fix): select every pod in the
/// namespace, deny all ingress and egress. NetworkPolicies are additive
/// (union of allows), so pairing this with [`tenant_allow_network_policy`]
/// yields exactly the allow rules and nothing else.
pub fn default_deny_network_policy() -> Value {
    json!({
        "apiVersion": NETWORK_POLICY_API_VERSION,
        "kind": NETWORK_POLICY_KIND,
        "metadata": {
            "name": DEFAULT_DENY_POLICY_NAME,
            "labels": { MANAGED_BY_LABEL: FIELD_MANAGER },
        },
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        },
    })
}

/// The explicit allows a Ray cluster needs under the default-deny (#56):
///
/// - same-namespace pod-to-pod, all ports (Ray head↔workers: GCS 6379,
///   dashboard 8265, client 10001, plus the raylet's dynamic ports — too
///   many to enumerate, and they stay inside the tenant boundary);
/// - ingress from Mobula control-plane namespaces
///   ([`CONTROL_PLANE_NAMESPACE_LABEL`]) to the head's dashboard (8265) and
///   Ray client (10001) ports only — GCS is not a control-plane surface;
/// - egress to kube-dns (namespace `kube-system`, `k8s-app: kube-dns`,
///   port 53 UDP+TCP) — default-deny otherwise breaks DNS
///   (research §4.3). The `kubernetes.io/metadata.name` namespace label is
///   API-server-managed since 1.22, so this needs no admin labeling.
pub fn tenant_allow_network_policy() -> Value {
    json!({
        "apiVersion": NETWORK_POLICY_API_VERSION,
        "kind": NETWORK_POLICY_KIND,
        "metadata": {
            "name": TENANT_ALLOW_POLICY_NAME,
            "labels": { MANAGED_BY_LABEL: FIELD_MANAGER },
        },
        "spec": {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                // Ray head↔workers, unrestricted ports inside the tenant.
                { "from": [ { "podSelector": {} } ] },
                // The Mobula control plane → Ray head dashboard/client.
                {
                    "from": [
                        { "namespaceSelector": {
                            "matchLabels": { CONTROL_PLANE_NAMESPACE_LABEL: "true" },
                        } },
                    ],
                    "ports": [
                        { "protocol": "TCP", "port": 8265 },
                        { "protocol": "TCP", "port": 10001 },
                    ],
                },
            ],
            "egress": [
                { "to": [ { "podSelector": {} } ] },
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
                    "template": pod_template(
                        "ray-head",
                        &spec.image,
                        &spec.head_cpu,
                        &spec.head_memory,
                        None,
                        None,
                        None,
                    ),
                },
                // Serve worker replicas are fixed here; Serve autoscaling is
                // Ray Serve's own concern (deployment num_replicas).
                "workerGroupSpecs": [worker_group_spec(&worker, &spec.image, false, None, None)],
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

    // -----------------------------------------------------------------
    // Pod shaping (#66)
    // -----------------------------------------------------------------

    fn shape() -> ResolvedPodShape {
        use mobula_core::podspec::{EnvVar, Toleration, VolumeMount};
        ResolvedPodShape {
            env: vec![EnvVar {
                name: "AWS_ENDPOINT_URL".into(),
                value: "https://s3.example.com".into(),
            }],
            volumes: vec![VolumeMount {
                name: "home".into(),
                claim_name: "nebari-home".into(),
                mount_path: "/home/ray".into(),
                read_only: false,
                sub_path: Some("home/ml-team".into()),
            }],
            service_account: Some("ray-workload".into()),
            node_selector: std::collections::BTreeMap::from([(
                "accelerator".to_string(),
                "a100".to_string(),
            )]),
            tolerations: vec![Toleration {
                key: "nvidia.com/gpu".into(),
                operator: "Exists".into(),
                value: None,
                effect: "NoSchedule".into(),
            }],
        }
    }

    #[test]
    fn no_shape_leaves_the_manifest_untouched() {
        // A deployment that configures no pod shaping must produce exactly
        // the manifest it produced before #66.
        let mut s = spec(&[("w", 1, 1, 1)]);
        let without = to_raycluster(&ClusterId("c".into()), &s, false, 1, None);
        s.pod_resolved = Some(ResolvedPodShape::default());
        let empty_shape = to_raycluster(&ClusterId("c".into()), &s, false, 1, None);
        assert_eq!(without, empty_shape, "an empty shape must add nothing");
    }

    #[test]
    fn shape_reaches_head_and_every_worker() {
        // The whole point of the meeting's decision is that WORKERS see the
        // environment; a mount that only lands on the head is useless.
        let mut s = spec(&[("w1", 1, 1, 1), ("w2", 0, 2, 0)]);
        s.pod_resolved = Some(shape());
        let cr = to_raycluster(&ClusterId("c".into()), &s, false, 7, None);

        let head = &cr["spec"]["headGroupSpec"]["template"]["spec"];
        let workers = cr["spec"]["workerGroupSpecs"].as_array().unwrap();
        assert_eq!(workers.len(), 2);

        for pod in std::iter::once(head).chain(workers.iter().map(|w| &w["template"]["spec"])) {
            let c = &pod["containers"][0];
            assert_eq!(c["env"][0]["name"], "AWS_ENDPOINT_URL");
            assert_eq!(c["volumeMounts"][0]["mountPath"], "/home/ray");
            assert_eq!(c["volumeMounts"][0]["subPath"], "home/ml-team");
            assert_eq!(c["volumeMounts"][0]["readOnly"], false);
            assert_eq!(
                pod["volumes"][0]["persistentVolumeClaim"]["claimName"],
                "nebari-home"
            );
            assert_eq!(pod["serviceAccountName"], "ray-workload");
            assert_eq!(pod["nodeSelector"]["accelerator"], "a100");
            assert_eq!(pod["tolerations"][0]["key"], "nvidia.com/gpu");
            assert_eq!(pod["tolerations"][0]["operator"], "Exists");
            assert!(
                pod["tolerations"][0].get("value").is_none(),
                "an Exists toleration must not carry a value"
            );
        }
    }

    #[test]
    fn sub_path_omitted_when_unscoped() {
        let mut s = spec(&[("w", 1, 1, 1)]);
        let mut sh = shape();
        sh.volumes[0].sub_path = None;
        s.pod_resolved = Some(sh);
        let cr = to_raycluster(&ClusterId("c".into()), &s, false, 1, None);
        let mount =
            &cr["spec"]["headGroupSpec"]["template"]["spec"]["containers"][0]["volumeMounts"][0];
        assert!(mount.get("subPath").is_none());
    }

    #[test]
    fn shape_round_trips_through_the_fingerprint() {
        // owned_spec_fingerprint and fingerprint_from_cr must agree on a
        // manifest we produced ourselves, or every shaped cluster would
        // report permanent spec drift.
        let mut s = spec(&[("w", 1, 2, 1)]);
        s.pod_resolved = Some(shape());
        let cr = to_raycluster(&ClusterId("c".into()), &s, false, 3, None);
        assert_eq!(
            owned_spec_fingerprint(&s),
            fingerprint_from_cr(&cr["spec"]).unwrap()
        );
    }

    #[test]
    fn stripping_a_mount_out_of_band_reads_as_drift() {
        // The failure this guards against: someone edits the RayCluster to
        // drop the home mount and Mobula never notices the cluster no longer
        // matches what was admitted.
        let mut s = spec(&[("w", 1, 2, 1)]);
        s.pod_resolved = Some(shape());
        let mut cr = to_raycluster(&ClusterId("c".into()), &s, false, 3, None);
        let before = fingerprint_from_cr(&cr["spec"]).unwrap();

        cr["spec"]["headGroupSpec"]["template"]["spec"]["containers"][0]["volumeMounts"] =
            json!([]);
        assert_ne!(before, fingerprint_from_cr(&cr["spec"]).unwrap());

        // Same for the service account — swapping it is a privilege change.
        let mut cr2 = to_raycluster(&ClusterId("c".into()), &s, false, 3, None);
        cr2["spec"]["headGroupSpec"]["template"]["spec"]["serviceAccountName"] = json!("default");
        assert_ne!(before, fingerprint_from_cr(&cr2["spec"]).unwrap());
    }

    #[test]
    fn stripping_a_mount_from_one_worker_group_reads_as_drift() {
        // The shape lands on every group, so drift detection has to look at
        // every group: an edit to a single worker group's mounts leaves the
        // head untouched and would otherwise pass unnoticed.
        let mut s = spec(&[("w1", 1, 2, 1), ("w2", 1, 2, 1)]);
        s.pod_resolved = Some(shape());
        let mut cr = to_raycluster(&ClusterId("c".into()), &s, false, 3, None);
        let before = fingerprint_from_cr(&cr["spec"]).unwrap();

        cr["spec"]["workerGroupSpecs"][1]["template"]["spec"]["containers"][0]["volumeMounts"] =
            json!([]);
        assert_ne!(before, fingerprint_from_cr(&cr["spec"]).unwrap());
    }

    #[test]
    fn unshaped_fingerprint_is_unaffected_by_missing_pod_fields() {
        // A CR with no shaping at all still round-trips: the projection
        // reads absent fields as empty, not as a mismatch.
        let s = spec(&[("w", 1, 2, 1)]);
        let cr = to_raycluster(&ClusterId("c".into()), &s, false, 3, None);
        assert_eq!(
            owned_spec_fingerprint(&s),
            fingerprint_from_cr(&cr["spec"]).unwrap()
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
            pod: None,
            pod_resolved: None,
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

    #[test]
    fn default_deny_policy_shape() {
        // #56: select every pod, deny all ingress+egress, carry no allow
        // rules — the allow rules live only in the tenant-allow policy.
        let p = default_deny_network_policy();
        assert_eq!(p["apiVersion"], "networking.k8s.io/v1");
        assert_eq!(p["kind"], "NetworkPolicy");
        assert_eq!(p["metadata"]["name"], DEFAULT_DENY_POLICY_NAME);
        assert_eq!(p["metadata"]["labels"][MANAGED_BY_LABEL], "mobula");
        let spec = &p["spec"];
        assert_eq!(spec["podSelector"], json!({}));
        assert_eq!(spec["policyTypes"], json!(["Ingress", "Egress"]));
        assert!(spec.get("ingress").is_none());
        assert!(spec.get("egress").is_none());
        // Our own default-deny is recognized by the check-then-apply probe.
        assert!(is_default_deny(&p));
    }

    #[test]
    fn tenant_allow_policy_shape() {
        // #56: exactly the allows a Ray cluster needs — same-namespace
        // pod-to-pod, control-plane ingress to the head's dashboard/client
        // ports, kube-dns egress — and nothing else.
        let p = tenant_allow_network_policy();
        assert_eq!(p["metadata"]["name"], TENANT_ALLOW_POLICY_NAME);
        assert_eq!(p["metadata"]["labels"][MANAGED_BY_LABEL], "mobula");
        let spec = &p["spec"];
        assert_eq!(spec["podSelector"], json!({}));
        assert_eq!(spec["policyTypes"], json!(["Ingress", "Egress"]));
        // An allow policy is not a default-deny (the probe must not skip
        // posture setup because of it).
        assert!(!is_default_deny(&p));

        let ingress = spec["ingress"].as_array().unwrap();
        assert_eq!(ingress.len(), 2);
        // Ray head↔workers: same-namespace pods, all ports (GCS 6379,
        // dashboard 8265, client 10001, raylet dynamic ports).
        assert_eq!(ingress[0]["from"], json!([{ "podSelector": {} }]));
        assert!(ingress[0].get("ports").is_none());
        // Control plane → head: dashboard (8265) + Ray client (10001) only,
        // from namespaces carrying the documented control-plane label.
        assert_eq!(
            ingress[1]["from"],
            json!([{ "namespaceSelector": {
                "matchLabels": { CONTROL_PLANE_NAMESPACE_LABEL: "true" },
            } }])
        );
        assert_eq!(
            ingress[1]["ports"],
            json!([
                { "protocol": "TCP", "port": 8265 },
                { "protocol": "TCP", "port": 10001 },
            ])
        );

        let egress = spec["egress"].as_array().unwrap();
        assert_eq!(egress.len(), 2);
        // Same-namespace pod-to-pod (workers → head).
        assert_eq!(egress[0]["to"], json!([{ "podSelector": {} }]));
        assert!(egress[0].get("ports").is_none());
        // kube-dns only: kube-system namespace + kube-dns pods, 53 UDP+TCP.
        assert_eq!(
            egress[1]["to"],
            json!([{
                "namespaceSelector": {
                    "matchLabels": { "kubernetes.io/metadata.name": "kube-system" },
                },
                "podSelector": { "matchLabels": { "k8s-app": "kube-dns" } },
            }])
        );
        assert_eq!(
            egress[1]["ports"],
            json!([
                { "protocol": "UDP", "port": 53 },
                { "protocol": "TCP", "port": 53 },
            ])
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
