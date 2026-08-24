//! In-memory demo backend: a [`Provisioner`] + [`ServiceProvisioner`] that
//! fakes cluster/service lifecycle with no Kubernetes at all.
//!
//! This is what `mobula serve --demo` uses so the whole control-plane API
//! (and the dashboard on top of it) can run in a plain container / docker
//! compose with zero cluster dependency: `apply` immediately reports the
//! resource Running, `terminate` reports it Terminated, and `observe` reads
//! back the generation + owned-field fingerprint Mobula stamped (so the
//! reconcile engine's #40/#41 logic behaves exactly as against KubeRay).
//! NOT for production — nothing is actually provisioned.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use mobula_core::{ClusterId, ClusterSpec, ClusterState, ServiceSpec};

use crate::kuberay::owned_spec_fingerprint;
use crate::{
    ApplyResponse, ObservedCluster, ObservedService, ProvisionError, Provisioner,
    ServiceProvisioner,
};

#[derive(Clone)]
struct DemoCluster {
    state: ClusterState,
    generation: u64,
    fingerprint: String,
}

#[derive(Default)]
pub struct DemoProvisioner {
    clusters: Mutex<HashMap<String, DemoCluster>>,
    services: Mutex<HashMap<String, ClusterState>>,
}

impl DemoProvisioner {
    pub fn new() -> Self {
        Self::default()
    }

    fn base_url(id: &str) -> String {
        format!("http://{id}.demo.local:8265")
    }
}

#[async_trait]
impl Provisioner for DemoProvisioner {
    async fn apply(
        &self,
        id: &ClusterId,
        spec: &ClusterSpec,
        generation: u64,
        _idempotency_key: &str,
        _queue: Option<&crate::kuberay::QueueAssignment>,
    ) -> Result<ApplyResponse, ProvisionError> {
        self.clusters.lock().unwrap().insert(
            id.0.clone(),
            DemoCluster {
                state: ClusterState::Running,
                generation,
                fingerprint: owned_spec_fingerprint(spec),
            },
        );
        Ok(ApplyResponse {
            generation,
            api_base_url: Some(Self::base_url(&id.0)),
        })
    }

    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        if let Some(c) = self.clusters.lock().unwrap().get_mut(&id.0) {
            c.state = ClusterState::Terminated;
        }
        Ok(())
    }

    async fn suspend(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        if let Some(c) = self.clusters.lock().unwrap().get_mut(&id.0) {
            // Suspending a terminated cluster is meaningless; everything
            // else drops to Suspended (idempotent).
            if c.state != ClusterState::Terminated {
                c.state = ClusterState::Suspended;
            }
        }
        Ok(())
    }

    async fn resume(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        if let Some(c) = self.clusters.lock().unwrap().get_mut(&id.0) {
            if c.state == ClusterState::Suspended {
                c.state = ClusterState::Running;
            }
        }
        Ok(())
    }

    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        match self.clusters.lock().unwrap().get(&id.0) {
            Some(c) => Ok(ObservedCluster {
                id: id.clone(),
                state: c.state,
                observed_generation: Some(c.generation),
                spec_fingerprint: Some(c.fingerprint.clone()),
                api_base_url: Some(Self::base_url(&id.0)),
            }),
            None => Err(ProvisionError::NotFound(id.clone())),
        }
    }

    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        Ok(self
            .clusters
            .lock()
            .unwrap()
            .iter()
            .map(|(id, c)| ObservedCluster {
                id: ClusterId(id.clone()),
                state: c.state,
                observed_generation: Some(c.generation),
                spec_fingerprint: Some(c.fingerprint.clone()),
                api_base_url: Some(Self::base_url(id)),
            })
            .collect())
    }

    fn metrics_endpoint(&self, _id: &ClusterId) -> Option<String> {
        // Nothing is actually provisioned — there is no head to scrape, so
        // the metrics passthrough answers 404 `metrics unavailable` (#52).
        None
    }
}

#[async_trait]
impl ServiceProvisioner for DemoProvisioner {
    async fn deploy(&self, name: &str, _spec: &ServiceSpec) -> Result<(), ProvisionError> {
        self.services
            .lock()
            .unwrap()
            .insert(name.to_string(), ClusterState::Running);
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Option<ObservedService>, ProvisionError> {
        Ok(self
            .services
            .lock()
            .unwrap()
            .get(name)
            .map(|state| ObservedService {
                name: name.to_string(),
                state: *state,
                url: Some(format!("http://{name}.demo.local:8000")),
            }))
    }

    async fn delete(&self, name: &str) -> Result<(), ProvisionError> {
        self.services.lock().unwrap().remove(name);
        Ok(())
    }

    async fn list(&self) -> Result<Vec<ObservedService>, ProvisionError> {
        Ok(self
            .services
            .lock()
            .unwrap()
            .iter()
            .map(|(name, state)| ObservedService {
                name: name.clone(),
                state: *state,
                url: Some(format!("http://{name}.demo.local:8000")),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::{UpgradeStrategy, WorkerGroup};

    fn cluster_spec(name: &str) -> ClusterSpec {
        ClusterSpec {
            engine: Default::default(),
            name: name.into(),
            project: "demo".into(),
            ray_version: "2.57.0".into(),
            image: "img".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: vec![WorkerGroup {
                name: "w".into(),
                cpu: "1".into(),
                memory: "2Gi".into(),
                gpu: None,
                min_replicas: 0,
                max_replicas: 4,
                replicas: 1,
            }],
            ttl_seconds: None,
            owner: None,
        }
    }

    fn service_spec(name: &str) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            project: "demo".into(),
            ray_version: "2.57.0".into(),
            image: "img".into(),
            serve_config_v2: "applications: []".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_replicas: 1,
            worker_cpu: "1".into(),
            worker_memory: "2Gi".into(),
            upgrade: UpgradeStrategy::Canary,
        }
    }

    #[tokio::test]
    async fn cluster_lifecycle_is_faked_without_kubernetes() {
        let p = DemoProvisioner::new();
        let id = ClusterId("c1".into());

        // Nothing applied yet → NotFound, like a real backend.
        assert!(matches!(
            p.observe(&id).await,
            Err(ProvisionError::NotFound(_))
        ));
        assert!(Provisioner::list(&p).await.unwrap().is_empty());

        // apply immediately reports Running with the generation and the
        // owned-field fingerprint stamped (so #40/#41 reconcile logic sees
        // the same shape as against KubeRay).
        let resp = p
            .apply(&id, &cluster_spec("c1"), 3, "c1/3", None)
            .await
            .unwrap();
        assert_eq!(resp.generation, 3);
        assert_eq!(
            resp.api_base_url.as_deref(),
            Some("http://c1.demo.local:8265")
        );

        let obs = p.observe(&id).await.unwrap();
        assert_eq!(obs.state, ClusterState::Running);
        assert_eq!(obs.observed_generation, Some(3));
        assert_eq!(
            obs.spec_fingerprint.as_deref(),
            Some(owned_spec_fingerprint(&cluster_spec("c1")).as_str())
        );

        // terminate flips the observed state; the record is kept.
        p.terminate(&id).await.unwrap();
        assert_eq!(
            p.observe(&id).await.unwrap().state,
            ClusterState::Terminated
        );
        // Terminating an unknown id is a no-op, not an error.
        p.terminate(&ClusterId("ghost".into())).await.unwrap();

        // suspend/resume drive the state (#51): suspended keeps the record,
        // resume returns to Running; both are idempotent no-ops for unknown
        // ids and resume never revives a terminated cluster.
        p.resume(&id).await.unwrap();
        assert_eq!(
            p.observe(&id).await.unwrap().state,
            ClusterState::Terminated,
            "resume must not revive a terminated cluster"
        );
        p.apply(&id, &cluster_spec("c1"), 3, "c1/3", None)
            .await
            .unwrap();
        p.suspend(&id).await.unwrap();
        assert_eq!(p.observe(&id).await.unwrap().state, ClusterState::Suspended);
        p.suspend(&id).await.unwrap(); // idempotent
        p.resume(&id).await.unwrap();
        assert_eq!(p.observe(&id).await.unwrap().state, ClusterState::Running);
        p.suspend(&ClusterId("ghost".into())).await.unwrap();
        p.resume(&ClusterId("ghost".into())).await.unwrap();

        // list reflects what was applied.
        let all = Provisioner::list(&p).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, id);
        assert_eq!(all[0].observed_generation, Some(3));
    }

    #[tokio::test]
    async fn service_lifecycle_is_faked_without_kubernetes() {
        let p = DemoProvisioner::new();
        assert!(p.get("svc").await.unwrap().is_none());

        p.deploy("svc", &service_spec("svc")).await.unwrap();
        let svc = p.get("svc").await.unwrap().unwrap();
        assert_eq!(svc.state, ClusterState::Running);
        assert_eq!(svc.url.as_deref(), Some("http://svc.demo.local:8000"));

        let all = ServiceProvisioner::list(&p).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "svc");

        p.delete("svc").await.unwrap();
        assert!(p.get("svc").await.unwrap().is_none());
        // Deleting an unknown service is a no-op.
        p.delete("svc").await.unwrap();
    }
}
