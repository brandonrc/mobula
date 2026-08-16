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
