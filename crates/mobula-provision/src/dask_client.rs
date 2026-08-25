//! Live Dask [`Provisioner`] over kube-rs (feature `kuberay`), targeting the
//! dask-kubernetes operator's `DaskCluster` CRD (multi-engine spike).
//!
//! Mirrors [`super::kuberay_client`]: dynamic API against the DaskCluster GVK
//! (no vendored CRD types), server-side apply with the `mobula` field manager
//! (idempotent for identical desired state). The pure translation and the
//! per-owner NetworkPolicy live in [`super::dask`].
//!
//! Out of scope for Dask (documented, not forced): batch job submission (no
//! Ray-Jobs-REST equivalent) and serving (no Ray Serve equivalent), so
//! `dashboard_api_base`/`metrics_endpoint` return `None` and the job gateway
//! answers accordingly. Suspend/resume is a no-op: the DaskCluster CRD has no
//! suspend field, and the spike drives lifecycle through terminate + the
//! max-age reaper (Dask's own `spec.idleTimeout` activity-idle is noted as the
//! next step, deliberately not wired so it doesn't fight the reconciler).

use async_trait::async_trait;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::{GroupVersionKind, ObjectMeta};
use kube::discovery::ApiResource;
use kube::Client;
use mobula_core::{ClusterId, ClusterSpec};

use crate::dask;
use crate::kuberay::{
    cluster_allow_policy_name, is_default_deny, CLUSTER_ID_LABEL, FIELD_MANAGER,
    GENERATION_ANNOTATION, MANAGED_BY_LABEL, OWNER_LABEL,
};
use crate::{ApplyResponse, ObservedCluster, ProvisionError, Provisioner};

/// Dask-backed provisioner scoped to one namespace.
pub struct DaskProvisioner {
    client: Client,
    namespace: String,
}

fn daskcluster_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind {
        group: "kubernetes.dask.org".into(),
        version: "v1".into(),
        kind: "DaskCluster".into(),
    })
}

fn networkpolicy_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind {
        group: "networking.k8s.io".into(),
        version: "v1".into(),
        kind: "NetworkPolicy".into(),
    })
}

fn pod_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind {
        group: "".into(),
        version: "v1".into(),
        kind: "Pod".into(),
    })
}

impl DaskProvisioner {
    /// Connect using the ambient kubeconfig / in-cluster service account.
    /// Shares the process-wide rustls provider the KubeRay client installs
    /// (both run in the same binary), so it does not re-install one.
    pub async fn connect(namespace: impl Into<String>) -> Result<Self, ProvisionError> {
        let client = Client::try_default()
            .await
            .map_err(|e| ProvisionError::Backend(e.to_string()))?;
        Ok(Self {
            client,
            namespace: namespace.into(),
        })
    }

    /// Construct from an already-connected client (used by the router so both
    /// engines share one `kube::Client`).
    pub fn with_client(client: Client, namespace: impl Into<String>) -> Self {
        Self {
            client,
            namespace: namespace.into(),
        }
    }

    fn api(&self) -> Api<DynamicObject> {
        Api::namespaced_with(
            self.client.clone(),
            &self.namespace,
            &daskcluster_resource(),
        )
    }

    fn policies_api(&self) -> Api<DynamicObject> {
        Api::namespaced_with(
            self.client.clone(),
            &self.namespace,
            &networkpolicy_resource(),
        )
    }

    /// Does the namespace carry a default-deny NetworkPolicy Mobula does not
    /// manage? If so an admin runs their own posture and Mobula adds nothing
    /// (same check-then-apply as the Ray client, #56/#86).
    async fn admin_managed_deny(&self) -> Result<bool, ProvisionError> {
        let existing = self.policies_api().list(&ListParams::default()).await?;
        Ok(existing.items.iter().any(|p| {
            let ours = p
                .metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(MANAGED_BY_LABEL))
                .is_some_and(|v| v == FIELD_MANAGER);
            !ours && is_default_deny(&p.data)
        }))
    }

    /// Ensure the per-cluster allow policy (intra-cluster + the tier-2
    /// per-owner scheduler pin on `:8786`/`:8787`). Skipped under an
    /// admin-managed default-deny (never widen an admin posture).
    async fn ensure_cluster_allow(
        &self,
        id: &str,
        owner: Option<&str>,
    ) -> Result<(), ProvisionError> {
        if self.admin_managed_deny().await? {
            tracing::info!(
                target: "mobula::audit",
                namespace = %self.namespace, cluster = id,
                "admin-managed default-deny present; not adding per-cluster (dask) allow"
            );
            return Ok(());
        }
        let manifest = dask::cluster_allow_network_policy(id, owner);
        let name = cluster_allow_policy_name(id);
        let labels: std::collections::BTreeMap<String, String> =
            serde_json::from_value(manifest["metadata"]["labels"].clone())
                .map_err(|e| ProvisionError::Backend(e.to_string()))?;
        let mut obj = DynamicObject::new(&name, &networkpolicy_resource());
        obj.metadata = ObjectMeta {
            name: Some(name.clone()),
            labels: Some(labels),
            ..Default::default()
        };
        obj.data = serde_json::json!({ "spec": manifest["spec"] });
        let params = PatchParams::apply(FIELD_MANAGER).force();
        self.policies_api()
            .patch(&name, &params, &Patch::Apply(&obj))
            .await?;
        tracing::info!(
            target: "mobula::audit",
            namespace = %self.namespace, cluster = id, "per-cluster (dask) allow NetworkPolicy ensured"
        );
        Ok(())
    }

    async fn delete_cluster_allow(&self, id: &str) -> Result<(), ProvisionError> {
        let name = cluster_allow_policy_name(id);
        match self
            .policies_api()
            .delete(&name, &DeleteParams::default())
            .await
        {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// List the pods the dask-operator owns for cluster `id` (selector
    /// `dask.org/cluster-name=<id>`), as raw JSON values for the pure mappers
    /// in [`super::dask`]. Shared by `observe` (pod-based readiness, #121) and
    /// `cluster_nodes` (the node breakdown).
    async fn list_cluster_pods(&self, id: &str) -> Result<Vec<serde_json::Value>, ProvisionError> {
        let pods: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &pod_resource());
        let params =
            ListParams::default().labels(&format!("{}={}", dask::DASK_CLUSTER_NAME_LABEL, id));
        Ok(pods
            .list(&params)
            .await?
            .into_iter()
            .filter_map(|p| serde_json::to_value(&p).ok())
            .collect())
    }
}

fn observed_generation(obj: &DynamicObject) -> Option<u64> {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(GENERATION_ANNOTATION))
        .and_then(|v| v.parse().ok())
}

/// Map a kube error that means "the DaskCluster CRD is not served / the object
/// is absent" to `NotFound`, so the router can safely probe a namespace whose
/// dask-kubernetes operator may not be installed.
fn map_absent(id: &ClusterId, e: kube::Error) -> ProvisionError {
    match &e {
        kube::Error::Api(a) if a.code == 404 => ProvisionError::NotFound(id.clone()),
        _ => e.into(),
    }
}

#[async_trait]
impl Provisioner for DaskProvisioner {
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        generation: u64,
        idempotency_key: &str,
        _queue: Option<&crate::kuberay::QueueAssignment>,
    ) -> Result<ApplyResponse, ProvisionError> {
        // Per-cluster allow first, so scheduler↔worker traffic is never up
        // under the default-deny without its own allow. Tier-2: the same
        // policy carries the per-owner scheduler pin.
        self.ensure_cluster_allow(&id.0, spec.owner.as_deref())
            .await?;

        let manifest = dask::to_daskcluster(id, spec, generation);
        let mut labels = std::collections::BTreeMap::from([
            (MANAGED_BY_LABEL.to_string(), FIELD_MANAGER.to_string()),
            (CLUSTER_ID_LABEL.to_string(), id.0.clone()),
        ]);
        if let Some(owner) = spec.owner.as_deref() {
            labels.insert(OWNER_LABEL.to_string(), owner.to_string());
        }
        let mut obj = DynamicObject::new(&id.0, &daskcluster_resource());
        obj.metadata = ObjectMeta {
            name: Some(id.0.clone()),
            labels: Some(labels),
            annotations: Some(std::collections::BTreeMap::from([(
                GENERATION_ANNOTATION.to_string(),
                generation.to_string(),
            )])),
            ..Default::default()
        };
        obj.data = serde_json::json!({ "spec": manifest["spec"] });

        let params = PatchParams::apply(FIELD_MANAGER).force();
        self.api()
            .patch(&id.0, &params, &Patch::Apply(&obj))
            .await?;
        tracing::info!(
            target: "mobula::audit",
            cluster = %id, generation, key = idempotency_key, engine = "dask", "daskcluster applied"
        );
        // Dask has no Ray-jobs/dashboard proxy surface, so no api_base_url.
        Ok(ApplyResponse {
            generation,
            api_base_url: None,
        })
    }

    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        match self.api().delete(&id.0, &DeleteParams::default()).await {
            Ok(_) => {}
            Err(kube::Error::Api(e)) if e.code == 404 => {}
            Err(e) => return Err(e.into()),
        }
        self.delete_cluster_allow(&id.0).await
    }

    async fn suspend(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        // The DaskCluster CRD has no suspend field; the spike does not
        // suspend Dask clusters (documented gap). No-op so the reconciler
        // does not error if a suspend is ever requested.
        tracing::warn!(
            target: "mobula::audit",
            cluster = %id, "suspend not supported for engine=dask; no-op"
        );
        Ok(())
    }

    async fn resume(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        let _ = id;
        Ok(())
    }

    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        let obj = self
            .api()
            .get_opt(&id.0)
            .await
            .map_err(|e| map_absent(id, e))?
            .ok_or_else(|| ProvisionError::NotFound(id.clone()))?;
        let status = obj
            .data
            .get("status")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let spec_fingerprint = obj.data.get("spec").and_then(dask::fingerprint_from_cr);

        // #121: derive observed state from the POD state, not the DaskCluster
        // `.status.phase`. The operator can only write that phase when the
        // installed CRD serves a `status` subresource; without one it never
        // leaves `Pending`, so a pod-based signal is what actually reports
        // Running. Fall back to the CR phase only when no pods are visible
        // (none created yet, or the pod list failed) — never let a transient
        // pod-list error regress a cluster's observed state.
        let state = match self.list_cluster_pods(&id.0).await {
            Ok(pods) => dask::observed_state_from_pods(&pods)
                .unwrap_or_else(|| dask::status_to_state(&status)),
            Err(e) => {
                tracing::warn!(
                    target: "mobula::audit",
                    cluster = %id, error = %e,
                    "dask pod list failed during observe; falling back to CR phase"
                );
                dask::status_to_state(&status)
            }
        };

        Ok(ObservedCluster {
            id: id.clone(),
            state,
            observed_generation: observed_generation(&obj),
            spec_fingerprint,
            api_base_url: None,
        })
    }

    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        let params = ListParams::default().labels(&format!("{MANAGED_BY_LABEL}={FIELD_MANAGER}"));
        let list = match self.api().list(&params).await {
            Ok(l) => l,
            // CRD not installed → this backend manages nothing here.
            Err(kube::Error::Api(e)) if e.code == 404 => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        Ok(list
            .into_iter()
            .filter_map(|obj| {
                let name = obj.metadata.name.clone()?;
                let status = obj
                    .data
                    .get("status")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                Some(ObservedCluster {
                    id: ClusterId(name),
                    state: dask::status_to_state(&status),
                    observed_generation: observed_generation(&obj),
                    spec_fingerprint: obj.data.get("spec").and_then(dask::fingerprint_from_cr),
                    api_base_url: None,
                })
            })
            .collect())
    }

    async fn cluster_nodes(
        &self,
        id: &ClusterId,
    ) -> Result<Option<mobula_core::ClusterNodes>, ProvisionError> {
        // Confirm the cluster exists (NotFound propagates), then list the pods
        // the operator owns (label `dask.org/cluster-name=<id>`).
        self.api()
            .get_opt(&id.0)
            .await
            .map_err(|e| map_absent(id, e))?
            .ok_or_else(|| ProvisionError::NotFound(id.clone()))?;
        let pod_values = self.list_cluster_pods(&id.0).await?;
        Ok(Some(dask::node_breakdown(&id.0, &pod_values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{dask_pod, daskcluster_cr, mock_client, Fixture};
    use mobula_core::{ClusterState, Engine, WorkerGroup};

    fn spec() -> ClusterSpec {
        ClusterSpec {
            name: "c1".into(),
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
                min_replicas: 1,
                max_replicas: 1,
                replicas: 1,
            }],
            ttl_seconds: None,
            idle_timeout_secs: None,
            owner: Some("bob".into()),
        }
    }

    fn prov(fx: Fixture) -> (DaskProvisioner, crate::test_support::Recorder) {
        let (client, rec) = mock_client(fx);
        (DaskProvisioner::with_client(client, "test-ns"), rec)
    }

    #[tokio::test]
    async fn observe_reports_running_from_pods_even_when_cr_phase_pending() {
        // #121: the CR is stuck at phase=Pending (its CRD has no status
        // subresource) but the pods are up — pod truth must win.
        let (prov, _rec) = prov(Fixture {
            daskcluster: Some(daskcluster_cr("c1", 3, Some("Pending"))),
            pods: vec![
                dask_pod("c1", "scheduler", "Running", true),
                dask_pod("c1", "worker", "Running", true),
            ],
            ..Default::default()
        });
        let obs = prov.observe(&ClusterId("c1".into())).await.unwrap();
        assert_eq!(obs.state, ClusterState::Running);
        assert_eq!(obs.observed_generation, Some(3));
        assert!(obs.spec_fingerprint.is_some());
        assert!(obs.api_base_url.is_none());
    }

    #[tokio::test]
    async fn observe_falls_back_to_cr_phase_when_no_pods() {
        // No pods visible yet → fall back to the CR phase rather than
        // reporting a bogus Provisioning.
        let (prov, _rec) = prov(Fixture {
            daskcluster: Some(daskcluster_cr("c1", 1, Some("Running"))),
            pods: vec![],
            ..Default::default()
        });
        let obs = prov.observe(&ClusterId("c1".into())).await.unwrap();
        assert_eq!(obs.state, ClusterState::Running);
    }

    #[tokio::test]
    async fn observe_provisioning_from_pods_while_worker_pending() {
        let (prov, _rec) = prov(Fixture {
            daskcluster: Some(daskcluster_cr("c1", 1, Some("Pending"))),
            pods: vec![
                dask_pod("c1", "scheduler", "Running", true),
                dask_pod("c1", "worker", "Pending", false),
            ],
            ..Default::default()
        });
        let obs = prov.observe(&ClusterId("c1".into())).await.unwrap();
        assert_eq!(obs.state, ClusterState::Provisioning);
    }

    #[tokio::test]
    async fn observe_absent_cr_is_not_found() {
        let (prov, _rec) = prov(Fixture::default());
        let err = prov.observe(&ClusterId("nope".into())).await.unwrap_err();
        assert!(matches!(err, ProvisionError::NotFound(_)));
    }

    #[tokio::test]
    async fn apply_ensures_allow_then_patches_cluster() {
        let (prov, rec) = prov(Fixture::default());
        let resp = prov
            .apply(&ClusterId("c1".into()), &spec(), 5, "key", None)
            .await
            .unwrap();
        assert_eq!(resp.generation, 5);
        assert!(
            resp.api_base_url.is_none(),
            "dask has no job/dashboard base"
        );
        let calls = rec.lock().unwrap().clone();
        // Admin-deny probe + per-owner allow apply precede the CR patch.
        assert!(calls
            .iter()
            .any(|(m, p)| m == "GET" && p.contains("/networkpolicies")));
        assert!(calls
            .iter()
            .any(|(m, p)| m == "PATCH" && p.contains("/networkpolicies")));
        assert!(calls
            .iter()
            .any(|(m, p)| m == "PATCH" && p.contains("/daskclusters/c1")));
    }

    #[tokio::test]
    async fn terminate_deletes_cluster_and_allow_policy() {
        let (prov, rec) = prov(Fixture::default());
        prov.terminate(&ClusterId("c1".into())).await.unwrap();
        let calls = rec.lock().unwrap().clone();
        assert!(calls
            .iter()
            .any(|(m, p)| m == "DELETE" && p.contains("/daskclusters/c1")));
        assert!(calls
            .iter()
            .any(|(m, p)| m == "DELETE" && p.contains("/networkpolicies")));
    }

    #[tokio::test]
    async fn list_maps_items_and_generation() {
        let (prov, _rec) = prov(Fixture {
            dask_list: vec![daskcluster_cr("c1", 2, Some("Running"))],
            ..Default::default()
        });
        let list = prov.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id.0, "c1");
        assert_eq!(list[0].observed_generation, Some(2));
        assert!(list[0].spec_fingerprint.is_some());
    }

    #[tokio::test]
    async fn cluster_nodes_splits_scheduler_and_workers() {
        let (prov, _rec) = prov(Fixture {
            daskcluster: Some(daskcluster_cr("c1", 1, None)),
            pods: vec![
                dask_pod("c1", "scheduler", "Running", true),
                dask_pod("c1", "worker", "Running", true),
                dask_pod("c1", "worker", "Pending", false),
            ],
            ..Default::default()
        });
        let nodes = prov
            .cluster_nodes(&ClusterId("c1".into()))
            .await
            .unwrap()
            .unwrap();
        assert!(nodes.head.as_ref().unwrap().is_head);
        assert_eq!(nodes.worker_groups.len(), 1);
        assert_eq!(nodes.worker_groups[0].nodes.len(), 2);
        assert_eq!(nodes.worker_groups[0].ready, 1);
    }

    #[tokio::test]
    async fn cluster_nodes_absent_cr_is_not_found() {
        let (prov, _rec) = prov(Fixture::default());
        let err = prov
            .cluster_nodes(&ClusterId("gone".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisionError::NotFound(_)));
    }

    #[tokio::test]
    async fn suspend_and_resume_are_noops() {
        let (prov, _rec) = prov(Fixture::default());
        prov.suspend(&ClusterId("c1".into())).await.unwrap();
        prov.resume(&ClusterId("c1".into())).await.unwrap();
    }
}
