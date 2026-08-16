//! Kueue backend for resource pools (ADR-0010): translate Mobula pool
//! domain types into Kueue custom resources.
//!
//! This module is pure (no Kubernetes client) so the pool→Kueue mapping is
//! exhaustively testable, mirroring the `kuberay` module's approach. The
//! object model (see docs/research/RESEARCH-2026-08-kueue-pool-substrate.md
//! §1): a `ResourceFlavor` per pool flavor, one `ClusterQueue` per pool
//! joined to a shared `Cohort` for elastic borrowing, and one `LocalQueue`
//! per project allocation.
//!
//! **v0 queue layout: one ClusterQueue per pool.** All project allocations
//! in a pool point their LocalQueue at the same ClusterQueue, so borrowing
//! between projects inside a pool is arbitrated by Kueue's admission fair
//! sharing rather than per-project quotas. The `AllocationSpec` nominal /
//! borrowing / lending limits are reserved for a future per-project
//! ClusterQueue layout; until then they are serialized into LocalQueue
//! metadata annotations (`mobula.dev/nominal` etc., as JSON) so the
//! declared intent is recorded on the object and a later layout migration
//! can read it back.

use mobula_core::{AllocationSpec, FlavorSpec, PoolSpec};
use serde_json::{json, Value};

/// API version for all Kueue objects Mobula manages. v1beta2 is the storage
/// version since Kueue v0.19 and the only one carrying `spec.cohortName`
/// (v1beta1 spells it `spec.cohort` and is deprecated) — applying a v1beta1
/// manifest with `cohortName` is rejected by the structural schema
/// ("field not declared in schema"), which the kueue-e2e workflow caught.
pub const API_VERSION: &str = "kueue.x-k8s.io/v1beta2";
/// Label a workload carries to nominate its LocalQueue
/// (kueue.x-k8s.io/queue-name).
pub const QUEUE_LABEL: &str = "kueue.x-k8s.io/queue-name";
/// Annotation marking a RayCluster/RayJob as elastic (Workload Slices,
/// KEP-77) — post-admission scaling is re-accounted against quota.
pub const ELASTIC_JOB_ANNOTATION: &str = "kueue.x-k8s.io/elastic-job";
/// Label tying every Kueue object Mobula creates back to its pool
/// (`mobula.dev/pool`). Stamped on the ResourceFlavors, Cohort,
/// ClusterQueue, and LocalQueues so `delete_pool` can find and remove a
/// pool's objects by selector after the spec is gone from the store.
pub const POOL_LABEL: &str = "mobula.dev/pool";

/// Annotation keys recording the reserved per-project limits on the
/// LocalQueue (see module docs).
pub const NOMINAL_ANNOTATION: &str = "mobula.dev/nominal";
pub const BORROWING_LIMIT_ANNOTATION: &str = "mobula.dev/borrowing-limit";
pub const LENDING_LIMIT_ANNOTATION: &str = "mobula.dev/lending-limit";

/// Build the ResourceFlavor manifest for one pool flavor: node labels and
/// taints select the hardware this flavor's quota applies to. `pool` is the
/// owning pool's name, stamped as the [`POOL_LABEL`] so the object is
/// findable by selector at teardown.
pub fn to_resource_flavor(pool: &str, flavor: &FlavorSpec) -> Value {
    let taints: Vec<Value> = flavor
        .taints
        .iter()
        .map(|t| {
            json!({
                "key": t.key,
                "value": t.value,
                "effect": t.effect,
            })
        })
        .collect();
    json!({
        "apiVersion": API_VERSION,
        "kind": "ResourceFlavor",
        "metadata": {
            "name": flavor.name,
            "labels": { POOL_LABEL: pool },
        },
        "spec": {
            "nodeLabels": flavor.node_labels,
            "nodeTaints": taints,
        },
    })
}

/// Build the Cohort manifest — the shared capacity envelope member
/// ClusterQueues borrow from (KEP-79; `v1beta2` since Kueue v0.19). Empty
/// spec: the v0 topology keeps quotas on the ClusterQueues, not on the
/// cohort itself.
pub fn to_cohort(pool: &PoolSpec) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "kind": "Cohort",
        "metadata": {
            "name": pool.cohort,
            "labels": { POOL_LABEL: pool.name },
        },
        "spec": {},
    })
}

/// Kueue's `fairSharing.weight` is an int-or-string; emit integral weights
/// as JSON integers (`1`, not `1.0`) so structural-schema appliers and
/// apimachinery's IntOrString decoding never see a float.
fn weight_json(w: f64) -> Value {
    if w.fract() == 0.0 && w.abs() < 9.0e15 {
        json!(w as i64)
    } else {
        json!(w)
    }
}

/// Build the pool's ClusterQueue: joined to the cohort, weighted for fair
/// sharing, with one resource group covering the union of all flavor
/// resource keys. Quotas land per flavor per resource as `nominalQuota`
/// quantity strings (passed through verbatim — parseability is validated
/// upstream in mobula-policy).
pub fn to_cluster_queue(pool: &PoolSpec) -> Value {
    // coveredResources is the sorted union of resource keys across flavors.
    let covered: Vec<&String> = pool
        .flavors
        .iter()
        .flat_map(|f| f.resources.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let flavors: Vec<Value> = pool
        .flavors
        .iter()
        .map(|f| {
            let resources: Vec<Value> = f
                .resources
                .iter()
                .map(|(name, quota)| {
                    json!({
                        "name": name,
                        "nominalQuota": quota,
                    })
                })
                .collect();
            json!({
                "name": f.name,
                "resources": resources,
            })
        })
        .collect();
    json!({
        "apiVersion": API_VERSION,
        "kind": "ClusterQueue",
        "metadata": {
            "name": pool.name,
            "labels": { POOL_LABEL: pool.name },
        },
        "spec": {
            "cohortName": pool.cohort,
            "fairSharing": {
                "weight": weight_json(pool.fair_sharing_weight),
            },
            "resourceGroups": [{
                "coveredResources": covered,
                "flavors": flavors,
            }],
        },
    })
}

/// Build a project allocation's LocalQueue: the namespaced tenant handle
/// pointing at the pool's ClusterQueue. The reserved nominal/borrowing/
/// lending limits are recorded as JSON annotations (see module docs).
pub fn to_local_queue(alloc: &AllocationSpec) -> Value {
    json!({
        "apiVersion": API_VERSION,
        "kind": "LocalQueue",
        "metadata": {
            "name": alloc.project,
            "namespace": alloc.namespace,
            "labels": { POOL_LABEL: alloc.pool },
            "annotations": {
                NOMINAL_ANNOTATION: json!(alloc.nominal).to_string(),
                BORROWING_LIMIT_ANNOTATION: json!(alloc.borrowing_limit).to_string(),
                LENDING_LIMIT_ANNOTATION: json!(alloc.lending_limit).to_string(),
            },
        },
        "spec": {
            "clusterQueue": alloc.pool,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::TaintSpec;
    use std::collections::BTreeMap;

    fn flavor(name: &str, resources: &[(&str, &str)]) -> FlavorSpec {
        FlavorSpec {
            name: name.into(),
            resources: resources
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            node_labels: BTreeMap::new(),
            taints: vec![],
        }
    }

    fn pool() -> PoolSpec {
        PoolSpec {
            name: "gpu-pool".into(),
            flavors: vec![
                flavor(
                    "a100",
                    &[("cpu", "64"), ("memory", "256Gi"), ("nvidia.com/gpu", "8")],
                ),
                flavor("spot-cpu", &[("cpu", "128"), ("memory", "512Gi")]),
            ],
            cohort: "research".into(),
            fair_sharing_weight: 2.0,
            elastic: true,
        }
    }

    fn alloc() -> AllocationSpec {
        AllocationSpec {
            pool: "gpu-pool".into(),
            project: "proj-a".into(),
            namespace: "proj-a".into(),
            nominal: BTreeMap::from([("cpu".to_string(), "16".to_string())]),
            borrowing_limit: BTreeMap::from([("cpu".to_string(), "64".to_string())]),
            lending_limit: BTreeMap::new(),
        }
    }

    #[test]
    fn resource_flavor_carries_labels_and_taints() {
        let mut f = flavor("a100", &[("nvidia.com/gpu", "8")]);
        f.node_labels.insert(
            "node.kubernetes.io/instance-type".into(),
            "p4d.24xlarge".into(),
        );
        f.taints.push(TaintSpec {
            key: "nvidia.com/gpu".into(),
            value: "present".into(),
            effect: "NoSchedule".into(),
        });
        let m = to_resource_flavor("gpu-pool", &f);
        assert_eq!(m["apiVersion"], "kueue.x-k8s.io/v1beta2");
        assert_eq!(m["kind"], "ResourceFlavor");
        assert_eq!(m["metadata"]["name"], "a100");
        assert_eq!(m["metadata"]["labels"][POOL_LABEL], "gpu-pool");
        assert_eq!(
            m["spec"]["nodeLabels"]["node.kubernetes.io/instance-type"],
            "p4d.24xlarge"
        );
        assert_eq!(
            m["spec"]["nodeTaints"][0],
            json!({"key": "nvidia.com/gpu", "value": "present", "effect": "NoSchedule"})
        );
    }

    #[test]
    fn cohort_is_named_and_empty() {
        let m = to_cohort(&pool());
        assert_eq!(m["apiVersion"], "kueue.x-k8s.io/v1beta2");
        assert_eq!(m["kind"], "Cohort");
        assert_eq!(m["metadata"]["name"], "research");
        assert_eq!(m["metadata"]["labels"][POOL_LABEL], "gpu-pool");
        assert_eq!(m["spec"], json!({}));
    }

    #[test]
    fn cluster_queue_propagates_cohort_and_weight() {
        let m = to_cluster_queue(&pool());
        assert_eq!(m["kind"], "ClusterQueue");
        assert_eq!(m["metadata"]["name"], "gpu-pool");
        assert_eq!(m["metadata"]["labels"][POOL_LABEL], "gpu-pool");
        assert_eq!(m["spec"]["cohortName"], "research");
        assert_eq!(m["spec"]["fairSharing"]["weight"], 2.0);
    }

    #[test]
    fn covered_resources_is_sorted_union_across_flavors() {
        let m = to_cluster_queue(&pool());
        assert_eq!(
            m["spec"]["resourceGroups"][0]["coveredResources"],
            json!(["cpu", "memory", "nvidia.com/gpu"])
        );
    }

    #[test]
    fn quota_lands_under_the_right_flavor_and_resource() {
        let m = to_cluster_queue(&pool());
        let flavors = m["spec"]["resourceGroups"][0]["flavors"]
            .as_array()
            .unwrap();
        assert_eq!(flavors.len(), 2);
        // a100 flavor: gpu quota under nvidia.com/gpu, cpu under cpu.
        let a100 = &flavors[0];
        assert_eq!(a100["name"], "a100");
        let resources = a100["resources"].as_array().unwrap();
        assert_eq!(resources[0], json!({"name": "cpu", "nominalQuota": "64"}));
        assert_eq!(
            resources[1],
            json!({"name": "memory", "nominalQuota": "256Gi"})
        );
        assert_eq!(
            resources[2],
            json!({"name": "nvidia.com/gpu", "nominalQuota": "8"})
        );
        // spot-cpu flavor declares no GPU quota.
        let spot = &flavors[1];
        assert_eq!(spot["name"], "spot-cpu");
        assert_eq!(spot["resources"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn local_queue_points_at_pool_in_project_namespace() {
        let m = to_local_queue(&alloc());
        assert_eq!(m["apiVersion"], "kueue.x-k8s.io/v1beta2");
        assert_eq!(m["kind"], "LocalQueue");
        assert_eq!(m["metadata"]["name"], "proj-a");
        assert_eq!(m["metadata"]["namespace"], "proj-a");
        assert_eq!(m["spec"]["clusterQueue"], "gpu-pool");
        // The pool label lets delete_pool find a pool's LocalQueues by
        // selector after the spec is gone from the store.
        assert_eq!(m["metadata"]["labels"][POOL_LABEL], "gpu-pool");
    }

    #[test]
    fn local_queue_annotations_record_allocation_limits() {
        let m = to_local_queue(&alloc());
        let anns = &m["metadata"]["annotations"];
        let nominal: Value =
            serde_json::from_str(anns["mobula.dev/nominal"].as_str().unwrap()).unwrap();
        assert_eq!(nominal, json!({"cpu": "16"}));
        let borrowing: Value =
            serde_json::from_str(anns["mobula.dev/borrowing-limit"].as_str().unwrap()).unwrap();
        assert_eq!(borrowing, json!({"cpu": "64"}));
        let lending: Value =
            serde_json::from_str(anns["mobula.dev/lending-limit"].as_str().unwrap()).unwrap();
        assert_eq!(lending, json!({}));
    }

    #[test]
    fn constants_match_kueue_conventions() {
        assert_eq!(QUEUE_LABEL, "kueue.x-k8s.io/queue-name");
        assert_eq!(ELASTIC_JOB_ANNOTATION, "kueue.x-k8s.io/elastic-job");
    }

    #[test]
    fn fractional_fair_sharing_weight_stays_a_json_float() {
        // Integral weights serialize as JSON integers for IntOrString;
        // fractional weights must remain floats, not be truncated.
        let mut p = pool();
        p.fair_sharing_weight = 0.5;
        let m = to_cluster_queue(&p);
        assert_eq!(m["spec"]["fairSharing"]["weight"], json!(0.5));
    }
}
