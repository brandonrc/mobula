//! Ray Serve service domain model. A "service" is a long-lived Serve
//! application; on KubeRay it maps to a RayService CR (which wraps a Ray
//! cluster + the Serve config and handles zero-downtime upgrades).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// How to roll out a new version of a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeStrategy {
    /// Canary: KubeRay stands up a new cluster, health-checks it, then
    /// switches traffic (zero-downtime; safe rollback if the new version
    /// is unhealthy). Maps to RayService `upgradeStrategy: NewCluster`.
    Canary,
    /// In-place: update the existing cluster's Serve config. Maps to
    /// RayService `upgradeStrategy: None`.
    InPlace,
}

/// Declarative spec for a managed Serve service.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceSpec {
    pub name: String,
    pub project: String,
    pub ray_version: String,
    pub image: String,
    /// The Serve application config (KubeRay `serveConfigV2`), passed
    /// through verbatim as a YAML string — Mobula does not interpret it.
    pub serve_config_v2: String,
    pub head_cpu: String,
    pub head_memory: String,
    /// Fixed worker replicas backing the service (autoscaling of Serve
    /// deployments is Ray Serve's own concern).
    pub worker_replicas: u32,
    pub worker_cpu: String,
    pub worker_memory: String,
    #[serde(default = "default_upgrade")]
    pub upgrade: UpgradeStrategy,
}

fn default_upgrade() -> UpgradeStrategy {
    UpgradeStrategy::Canary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_defaults_to_canary_when_omitted() {
        // serve_config_v2 passes through verbatim; upgrade has a serde
        // default so older clients can omit it.
        let v = serde_json::json!({
            "name": "svc",
            "project": "p",
            "ray_version": "2.57.0",
            "image": "img",
            "serve_config_v2": "applications: []",
            "head_cpu": "1",
            "head_memory": "2Gi",
            "worker_replicas": 2,
            "worker_cpu": "1",
            "worker_memory": "2Gi"
        });
        let spec: ServiceSpec = serde_json::from_value(v).unwrap();
        assert_eq!(spec.upgrade, UpgradeStrategy::Canary);
    }

    #[test]
    fn upgrade_round_trips_snake_case() {
        assert_eq!(
            serde_json::to_value(UpgradeStrategy::InPlace).unwrap(),
            serde_json::json!("in_place")
        );
        assert_eq!(
            serde_json::from_value::<UpgradeStrategy>(serde_json::json!("canary")).unwrap(),
            UpgradeStrategy::Canary
        );
    }
}
