//! Live Kueue [`PoolProvisioner`] over kube-rs (feature `kuberay` — it
//! shares the kube-rs dependency with the KubeRay client).
//!
//! Mirrors `kuberay_client`'s pattern: the dynamic API against the Kueue
//! GVKs (no vendored CRD types), server-side apply with the `mobula` field
//! manager, and idempotent deletes (404 = success). Unlike the KubeRay
//! client, applies do NOT force conflicts: the Cohort may be shared with
//! pools/objects Mobula does not own, and a forced apply would steal those
//! fields rather than report the conflict.

use async_trait::async_trait;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::{GroupVersionKind, ObjectMeta};
use kube::discovery::ApiResource;
use kube::Client;
use mobula_core::{AllocationSpec, PoolSpec};
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::kuberay::FIELD_MANAGER;
use crate::kueue::{self, POOL_LABEL};
use crate::{PoolObservation, PoolProvisioner, ProvisionError};

/// The Kueue kinds Mobula manages; `clusterqueues.kueue.x-k8s.io/v1beta2`
/// doubles as the discovery probe for [`KueueClient::kueue_present`].
const KINDS: [&str; 4] = ["Cohort", "ResourceFlavor", "ClusterQueue", "LocalQueue"];

fn kueue_gvk(kind: &str) -> GroupVersionKind {
    GroupVersionKind {
        group: "kueue.x-k8s.io".into(),
        version: "v1beta2".into(),
        kind: kind.into(),
    }
}

fn kueue_resource(kind: &str) -> ApiResource {
    ApiResource::from_gvk(&kueue_gvk(kind))
}

/// Kueue-backed pool provisioner. Cluster-scoped objects (Cohort,
/// ResourceFlavor, ClusterQueue) are applied cluster-wide; LocalQueues are
/// applied into each allocation's namespace (which must already exist).
pub struct KueueClient {
    client: Client,
    /// Cached CRD-presence probe (None until first checked).
    present: OnceCell<bool>,
}

impl KueueClient {
    /// Connect using the ambient kubeconfig / in-cluster service account.
    pub async fn connect() -> Result<Self, ProvisionError> {
        // See KubeRayProvisioner::connect: more than one rustls crypto
        // provider in the tree makes rustls panic on first TLS use unless a
        // default is installed explicitly (idempotent). FIPS builds (#61)
        // install the aws-lc-rs FIPS provider instead of ring.
        #[cfg(not(feature = "fips"))]
        let _ = rustls::crypto::ring::default_provider().install_default();
        #[cfg(feature = "fips")]
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = Client::try_default()
            .await
            .map_err(|e| ProvisionError::Backend(e.to_string()))?;
        Ok(Self {
            client,
            present: OnceCell::new(),
        })
    }

    /// Wrap a pure-translator manifest as a `DynamicObject` for the dynamic
    /// API: name/namespace/labels/annotations onto metadata, `spec` into
    /// `data` (the same shape `kuberay_client` applies).
    fn to_dynamic(manifest: &Value, kind: &str) -> DynamicObject {
        let meta = &manifest["metadata"];
        let name = meta["name"].as_str().unwrap_or_default();
        let mut obj = DynamicObject::new(name, &kueue_resource(kind));
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            namespace: meta
                .get("namespace")
                .and_then(|v| v.as_str())
                .map(String::from),
            labels: meta
                .get("labels")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .ok()
                .flatten(),
            annotations: meta
                .get("annotations")
                .cloned()
                .map(serde_json::from_value)
                .transpose()
                .ok()
                .flatten(),
            ..Default::default()
        };
        obj.data = serde_json::json!({ "spec": manifest.get("spec").cloned().unwrap_or_default() });
        obj
    }

    fn cluster_scoped(&self, kind: &str) -> Api<DynamicObject> {
        Api::all_with(self.client.clone(), &kueue_resource(kind))
    }

    /// Delete one object; 404 (already gone) is success — idempotent
    /// teardown, same convention as `kuberay_client::terminate`.
    async fn delete_ok_gone(api: &Api<DynamicObject>, name: &str) -> Result<(), ProvisionError> {
        match api.delete(name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Read a `u32` counter out of a ClusterQueue status object, defaulting to 0
/// when Kueue hasn't populated it yet.
fn status_u32(status: &Value, key: &str) -> u32 {
    status
        .get(key)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32
}

/// Parse a Kueue `status.flavorsUsage` array into flavor → resource → total
/// quantity string. Shared by the ClusterQueue (pool ledger) and each
/// LocalQueue (per-project attribution) — same shape on both since v0.9.
fn flavors_usage_map(
    status: &Value,
) -> std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>> {
    let mut out = std::collections::BTreeMap::new();
    if let Some(flavors) = status.get("flavorsUsage").and_then(|v| v.as_array()) {
        for f in flavors {
            let Some(flavor) = f.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let entry: &mut std::collections::BTreeMap<String, String> =
                out.entry(flavor.to_string()).or_default();
            if let Some(resources) = f.get("resources").and_then(|v| v.as_array()) {
                for r in resources {
                    if let (Some(res), Some(total)) = (
                        r.get("name").and_then(|v| v.as_str()),
                        r.get("total").and_then(|v| v.as_str()),
                    ) {
                        entry.insert(res.to_string(), total.to_string());
                    }
                }
            }
        }
    }
    out
}

/// Render a summed quantity back to a string: integral values without a
/// decimal point ("128"), fractional values as-is ("0.5"). Same convention
/// as the API's `format_quantity`.
fn format_quantity(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// Flatten an LQ's flavor-scoped usage into resource → quantity string by
/// summing across flavors. Unparseable quantities are skipped with a warning
/// (never fail the observation — one bad quantity must not lose the rest).
fn sum_usage_by_resource(
    lq: &str,
    by_flavor: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
) -> std::collections::BTreeMap<String, String> {
    let mut sums: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for (flavor, resources) in by_flavor {
        for (res, qty) in resources {
            match mobula_policy::quantity::parse_quantity(&qty) {
                Ok(v) => *sums.entry(res).or_insert(0.0) += v,
                Err(e) => {
                    tracing::warn!(local_queue = %lq, flavor = %flavor, resource = %res, quantity = %qty, error = %e, "unparseable LocalQueue usage quantity skipped")
                }
            }
        }
    }
    sums.into_iter()
        .map(|(k, v)| (k, format_quantity(v)))
        .collect()
}

#[async_trait]
impl PoolProvisioner for KueueClient {
    async fn apply_pool(
        &self,
        spec: &PoolSpec,
        allocs: &[AllocationSpec],
    ) -> Result<(), ProvisionError> {
        // No `.force()` (see module docs): conflicts surface as errors
        // instead of Mobula stealing fields it doesn't own.
        let params = PatchParams::apply(FIELD_MANAGER);
        // Order: the shared Cohort and flavors first, then the ClusterQueue
        // that references them, then the namespaced LocalQueues (which need
        // their namespaces to exist) pointing at it. Kueue is eventually
        // consistent, so this ordering is for tidiness, not correctness.
        let cohort = kueue::to_cohort(spec);
        self.cluster_scoped("Cohort")
            .patch(
                &spec.cohort,
                &params,
                &Patch::Apply(Self::to_dynamic(&cohort, "Cohort")),
            )
            .await?;
        for flavor in &spec.flavors {
            let manifest = kueue::to_resource_flavor(&spec.name, flavor);
            self.cluster_scoped("ResourceFlavor")
                .patch(
                    &flavor.name,
                    &params,
                    &Patch::Apply(Self::to_dynamic(&manifest, "ResourceFlavor")),
                )
                .await?;
        }
        let cq = kueue::to_cluster_queue(spec);
        self.cluster_scoped("ClusterQueue")
            .patch(
                &spec.name,
                &params,
                &Patch::Apply(Self::to_dynamic(&cq, "ClusterQueue")),
            )
            .await?;
        for alloc in allocs {
            let manifest = kueue::to_local_queue(alloc);
            let api: Api<DynamicObject> = Api::namespaced_with(
                self.client.clone(),
                &alloc.namespace,
                &kueue_resource("LocalQueue"),
            );
            api.patch(
                &alloc.project,
                &params,
                &Patch::Apply(Self::to_dynamic(&manifest, "LocalQueue")),
            )
            .await?;
        }
        tracing::info!(
            target: "mobula::audit",
            pool = %spec.name, allocations = allocs.len(), "pool applied to Kueue"
        );
        Ok(())
    }

    async fn delete_pool(&self, name: &str) -> Result<(), ProvisionError> {
        // Every object Mobula creates for a pool carries the POOL_LABEL
        // (stamped by the pure translators), so teardown finds them by
        // selector even though the pool spec is already gone from the store.
        let sel = ListParams::default().labels(&format!("{POOL_LABEL}={name}"));
        // LocalQueues are namespaced — list across all namespaces, delete
        // each in its own namespace.
        let lqs: Api<DynamicObject> =
            Api::all_with(self.client.clone(), &kueue_resource("LocalQueue"));
        for obj in lqs.list(&sel).await? {
            if let (Some(n), Some(ns)) = (obj.metadata.name, obj.metadata.namespace) {
                let api: Api<DynamicObject> =
                    Api::namespaced_with(self.client.clone(), &ns, &kueue_resource("LocalQueue"));
                Self::delete_ok_gone(&api, &n).await?;
            }
        }
        // Cluster-scoped objects, also by selector.
        for kind in KINDS {
            if kind == "LocalQueue" {
                continue;
            }
            let api = self.cluster_scoped(kind);
            for obj in api.list(&sel).await? {
                if let Some(n) = obj.metadata.name {
                    Self::delete_ok_gone(&api, &n).await?;
                }
            }
        }
        tracing::info!(target: "mobula::audit", pool = %name, "pool deleted from Kueue");
        Ok(())
    }

    async fn observe_pool(&self, name: &str) -> Result<Option<PoolObservation>, ProvisionError> {
        let Some(obj) = self.cluster_scoped("ClusterQueue").get_opt(name).await? else {
            return Ok(None);
        };
        let status = obj.data.get("status").cloned().unwrap_or(Value::Null);
        let flavors_usage = flavors_usage_map(&status);

        // Per-project attribution: the CQ's flavorsUsage is pool-scoped, so
        // read each LocalQueue's own status.flavorsUsage (present since Kueue
        // v0.9) for the queues that belong to this pool. LQ objects are
        // namespaced — list across all namespaces by the pool label, keyed
        // by LQ name (= the project name in Mobula's v0 queue layout).
        let mut queues_usage = std::collections::BTreeMap::new();
        let sel = ListParams::default().labels(&format!("{POOL_LABEL}={name}"));
        let lqs: Api<DynamicObject> =
            Api::all_with(self.client.clone(), &kueue_resource("LocalQueue"));
        for lq in lqs.list(&sel).await? {
            let Some(lq_name) = lq.metadata.name.clone() else {
                continue;
            };
            let lq_status = lq.data.get("status").cloned().unwrap_or(Value::Null);
            let by_resource = sum_usage_by_resource(&lq_name, flavors_usage_map(&lq_status));
            if !by_resource.is_empty() {
                queues_usage.insert(lq_name, by_resource);
            }
        }

        Ok(Some(PoolObservation {
            admitted_workloads: status_u32(&status, "admittedWorkloads"),
            reserving_workloads: status_u32(&status, "reservingWorkloads"),
            pending_workloads: status_u32(&status, "pendingWorkloads"),
            flavors_usage,
            queues_usage,
        }))
    }

    async fn kueue_present(&self) -> bool {
        // Discovery: does the API server serve clusterqueues
        // kueue.x-k8s.io/v1beta2? Cached per client — installing Kueue into
        // a running control plane takes effect on restart.
        *self
            .present
            .get_or_init(|| async {
                match kube::discovery::pinned_kind(&self.client, &kueue_gvk("ClusterQueue")).await {
                    Ok(_) => true,
                    Err(e) => {
                        tracing::warn!(error = %e, "Kueue ClusterQueue CRD not served by the API server");
                        false
                    }
                }
            })
            .await
    }
}
