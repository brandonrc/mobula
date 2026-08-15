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
