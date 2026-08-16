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
        .map(|g| worker_group_spec(g, &spec.image, autoscaling, Some(generation)))
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
        ),
    })
}

fn worker_group_spec(
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
        "template": pod_template("ray-worker", image, &g.cpu, &g.memory, g.gpu.as_deref(), generation),
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
    let mut template = json!({ "spec": { "containers": [container] } });
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

pub const SERVICE_KIND: &str = "RayService";

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
                    "template": pod_template("ray-head", &spec.image, &spec.head_cpu, &spec.head_memory, None, None),
                },
                // Serve worker replicas are fixed here; Serve autoscaling is
                // Ray Serve's own concern (deployment num_replicas).
                "workerGroupSpecs": [worker_group_spec(&worker, &spec.image, false, None)],
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
}
