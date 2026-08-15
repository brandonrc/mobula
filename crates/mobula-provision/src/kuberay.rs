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

pub const API_VERSION: &str = "ray.io/v1";
pub const KIND: &str = "RayCluster";
/// Server-side-apply field manager (ADR-0007): identifies Mobula's owned
/// fields so drift is attributable and `replicas` can be left unmanaged.
pub const FIELD_MANAGER: &str = "mobula";
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const CLUSTER_ID_LABEL: &str = "mobula.dev/cluster-id";

/// Build the RayCluster manifest for `spec`. `autoscaling` selects the
/// field-ownership regime (ADR-0007).
pub fn to_raycluster(id: &ClusterId, spec: &ClusterSpec, autoscaling: bool) -> Value {
    let worker_specs: Vec<Value> = spec
        .worker_groups
        .iter()
        .map(|g| worker_group_spec(g, &spec.image, autoscaling))
        .collect();

    json!({
        "apiVersion": API_VERSION,
        "kind": KIND,
        "metadata": {
            "name": id.0,
            "labels": {
                MANAGED_BY_LABEL: FIELD_MANAGER,
                CLUSTER_ID_LABEL: id.0,
            },
        },
        "spec": {
            "rayVersion": spec.ray_version,
            "enableInTreeAutoscaling": autoscaling,
            "headGroupSpec": head_group_spec(spec),
            "workerGroupSpecs": worker_specs,
        },
    })
}

fn head_group_spec(spec: &ClusterSpec) -> Value {
    json!({
        "rayStartParams": { "dashboard-host": "0.0.0.0" },
        "template": pod_template(
            "ray-head",
            &spec.image,
            &spec.head_cpu,
            &spec.head_memory,
            None,
        ),
    })
}

fn worker_group_spec(g: &WorkerGroup, image: &str, autoscaling: bool) -> Value {
    // Workers run the cluster image (Kubernetes requires an image on every
    // container; KubeRay does NOT copy the head image onto worker groups,
    // so an empty image would be rejected — review R2#1).
    let mut ws = json!({
        "groupName": g.name,
        "minReplicas": g.min_replicas,
        "maxReplicas": g.max_replicas,
        "rayStartParams": {},
        "template": pod_template("ray-worker", image, &g.cpu, &g.memory, g.gpu.as_deref()),
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
    json!({ "spec": { "containers": [container] } })
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
                    "template": pod_template("ray-head", &spec.image, &spec.head_cpu, &spec.head_memory, None),
                },
                // Serve worker replicas are fixed here; Serve autoscaling is
                // Ray Serve's own concern (deployment num_replicas).
                "workerGroupSpecs": [worker_group_spec(&worker, &spec.image, false)],
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
        let m = to_raycluster(&ClusterId("demo".into()), &spec(&[("cpu", 0, 4, 2)]), false);
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
        let m = to_raycluster(&ClusterId("demo".into()), &spec(&[("cpu", 0, 4, 2)]), false);
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
        let m = to_raycluster(&ClusterId("demo".into()), &spec(&[("cpu", 1, 8, 3)]), true);
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
        let m = to_raycluster(&ClusterId("demo".into()), &s, false);
        let res =
            &m["spec"]["workerGroupSpecs"][0]["template"]["spec"]["containers"][0]["resources"];
        assert_eq!(res["limits"]["nvidia.com/gpu"], "1");
        assert_eq!(res["requests"]["nvidia.com/gpu"], "1");
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
}
