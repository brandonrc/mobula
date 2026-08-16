//! Live KubeRay [`Provisioner`] over kube-rs (feature `kuberay`).
//!
//! Uses the dynamic API against the RayCluster GVK — no vendored CRD types.
//! Mutations are server-side applies with the `mobula` field manager
//! (ADR-0007): SSA is idempotent for identical desired state, and the field
//! manager keeps `replicas` unmanaged when the autoscaler owns it (the
//! manifest simply omits it, see [`super::kuberay`]).

use async_trait::async_trait;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams};
use kube::core::{GroupVersionKind, ObjectMeta};
use kube::discovery::ApiResource;
use kube::Client;
use mobula_core::{ClusterId, ClusterSpec, ServiceSpec};

use crate::kuberay::{
    self, CLUSTER_ID_LABEL, FIELD_MANAGER, GENERATION_ANNOTATION, MANAGED_BY_LABEL,
};
use crate::kueue;
use crate::{
    ApplyResponse, ObservedCluster, ObservedService, ProvisionError, Provisioner,
    ServiceProvisioner,
};

impl From<kube::Error> for ProvisionError {
    fn from(e: kube::Error) -> Self {
        ProvisionError::Backend(e.to_string())
    }
}

/// KubeRay-backed provisioner scoped to one namespace.
pub struct KubeRayProvisioner {
    client: Client,
    namespace: String,
    /// Whether new clusters enable Ray's in-tree autoscaler (selects the
    /// field-ownership regime, ADR-0007).
    autoscaling: bool,
}

fn raycluster_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind {
        group: "ray.io".into(),
        version: "v1".into(),
        kind: "RayCluster".into(),
    })
}

fn rayservice_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind {
        group: "ray.io".into(),
        version: "v1".into(),
        kind: "RayService".into(),
    })
}

impl KubeRayProvisioner {
    /// Connect using the ambient kubeconfig / in-cluster service account.
    pub async fn connect(
        namespace: impl Into<String>,
        autoscaling: bool,
    ) -> Result<Self, ProvisionError> {
        // reqwest and kube each bring a rustls crypto provider; with more
        // than one in the tree rustls refuses to auto-pick a default and
        // panics on first TLS use. Install one explicitly (idempotent —
        // Err just means already installed).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::try_default()
            .await
            .map_err(|e| ProvisionError::Backend(e.to_string()))?;
        Ok(Self {
            client,
            namespace: namespace.into(),
            autoscaling,
        })
    }

    fn api(&self) -> Api<DynamicObject> {
        Api::namespaced_with(self.client.clone(), &self.namespace, &raycluster_resource())
    }

    /// The dashboard/job API URL KubeRay's head service exposes for `id`.
    fn api_base_url(&self, id: &str) -> String {
        format!("http://{id}-head-svc.{}.svc:8265", self.namespace)
    }
}

/// Read the Mobula generation an observed RayCluster carries (ADR-0006, #40)
/// from its metadata annotation, if present and parseable.
fn observed_generation(obj: &DynamicObject) -> Option<u64> {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(GENERATION_ANNOTATION))
        .and_then(|v| v.parse().ok())
}

#[async_trait]
impl Provisioner for KubeRayProvisioner {
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        generation: u64,
        idempotency_key: &str,
        queue: Option<&crate::kuberay::QueueAssignment>,
    ) -> Result<ApplyResponse, ProvisionError> {
        let manifest = kuberay::to_raycluster(id, spec, self.autoscaling, generation, queue);
        // Wrap the manifest as a DynamicObject the dynamic Api can apply.
        let mut labels = std::collections::BTreeMap::from([
            (MANAGED_BY_LABEL.to_string(), FIELD_MANAGER.to_string()),
            (CLUSTER_ID_LABEL.to_string(), id.0.clone()),
        ]);
        // The Kueue queue label must ride on the applied object's metadata
        // (to_raycluster already carries it inside the manifest).
        if let Some(q) = queue {
            labels.insert(kueue::QUEUE_LABEL.to_string(), q.queue_name.clone());
        }
        let mut obj = DynamicObject::new(&id.0, &raycluster_resource());
        obj.metadata = ObjectMeta {
            name: Some(id.0.clone()),
            labels: Some(labels),
            // Stamp the generation on the CR so observe() reads it back
            // (ADR-0006, #40). The pod-template stamp lives inside the spec
            // (manifest["spec"]) and rolls pods on a bump.
            annotations: Some(std::collections::BTreeMap::from([(
                GENERATION_ANNOTATION.to_string(),
                generation.to_string(),
            )])),
            ..Default::default()
        };
        obj.data = serde_json::json!({ "spec": manifest["spec"] });

        // Server-side apply: idempotent per (name, field-manager); `force`
        // takes ownership of Mobula's fields on conflict. `replicas` is
        // simply absent from the manifest when autoscaling, so the
        // sidecar's ownership of it is never contested.
        let params = PatchParams::apply(FIELD_MANAGER).force();
        self.api()
            .patch(&id.0, &params, &Patch::Apply(&obj))
            .await?;
        tracing::info!(
            target: "mobula::audit",
            cluster = %id, generation, key = idempotency_key, "raycluster applied"
        );
        Ok(ApplyResponse {
            generation,
            api_base_url: Some(self.api_base_url(&id.0)),
        })
    }

    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        match self.api().delete(&id.0, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            // Already gone is success (idempotent teardown).
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        let obj = self
            .api()
            .get_opt(&id.0)
            .await?
            .ok_or_else(|| ProvisionError::NotFound(id.clone()))?;
        let status = obj
            .data
            .get("status")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let state = kuberay::status_to_state(&status);
        let spec_fingerprint = obj.data.get("spec").and_then(kuberay::fingerprint_from_cr);
        // The head service KubeRay creates is `<name>-head-svc`; the job
        // gateway targets its dashboard port.
        Ok(ObservedCluster {
            id: id.clone(),
            state,
            observed_generation: observed_generation(&obj),
            spec_fingerprint,
            api_base_url: Some(self.api_base_url(&id.0)),
        })
    }

    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        let params = ListParams::default().labels(&format!("{MANAGED_BY_LABEL}={FIELD_MANAGER}"));
        let list = self.api().list(&params).await?;
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
                    id: ClusterId(name.clone()),
                    state: kuberay::status_to_state(&status),
                    observed_generation: observed_generation(&obj),
                    spec_fingerprint: obj.data.get("spec").and_then(kuberay::fingerprint_from_cr),
                    api_base_url: Some(self.api_base_url(&name)),
                })
            })
            .collect())
    }
}

#[async_trait]
impl ServiceProvisioner for KubeRayProvisioner {
    async fn deploy(&self, name: &str, spec: &ServiceSpec) -> Result<(), ProvisionError> {
        let manifest = kuberay::to_rayservice(name, spec);
        let mut obj = DynamicObject::new(name, &rayservice_resource());
        obj.metadata = ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(std::collections::BTreeMap::from([
                (MANAGED_BY_LABEL.to_string(), FIELD_MANAGER.to_string()),
                (CLUSTER_ID_LABEL.to_string(), name.to_string()),
            ])),
            ..Default::default()
        };
        obj.data = serde_json::json!({ "spec": manifest["spec"] });
        let params = PatchParams::apply(FIELD_MANAGER).force();
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &rayservice_resource());
        api.patch(name, &params, &Patch::Apply(&obj)).await?;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<ObservedService>, ProvisionError> {
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &rayservice_resource());
        Ok(api.get_opt(name).await?.map(|obj| {
            let status = obj
                .data
                .get("status")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            ObservedService {
                name: name.to_string(),
                state: kuberay::service_status_to_state(&status),
                url: Some(format!(
                    "http://{name}-serve-svc.{}.svc:8000",
                    self.namespace
                )),
            }
        }))
    }

    async fn delete(&self, name: &str) -> Result<(), ProvisionError> {
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &rayservice_resource());
        match api.delete(name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(&self) -> Result<Vec<ObservedService>, ProvisionError> {
        let api: Api<DynamicObject> =
            Api::namespaced_with(self.client.clone(), &self.namespace, &rayservice_resource());
        let params = ListParams::default().labels(&format!("{MANAGED_BY_LABEL}={FIELD_MANAGER}"));
        Ok(api
            .list(&params)
            .await?
            .into_iter()
            .filter_map(|obj| {
                let name = obj.metadata.name.clone()?;
                let status = obj
                    .data
                    .get("status")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                Some(ObservedService {
                    name: name.clone(),
                    state: kuberay::service_status_to_state(&status),
                    url: Some(format!(
                        "http://{name}-serve-svc.{}.svc:8000",
                        self.namespace
                    )),
                })
            })
            .collect())
    }
}
