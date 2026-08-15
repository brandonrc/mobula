//! Domain model for the Mobula control plane.
//!
//! Mobula orchestrates stock Ray clusters through their stable seams
//! (KubeRay CRDs, the Jobs REST API via a federating gateway, Serve
//! ingress). This crate holds the provider-agnostic domain types; it must
//! never depend on a cloud SDK or Kubernetes client (see ADR-0002).

pub mod cluster;
pub mod registry;
pub mod service;

pub use cluster::{ClusterId, ClusterSpec, ClusterState, TransitionError, WorkerGroup};
pub use registry::{ClusterEndpoint, ClusterRegistry, RegistryError};
pub use service::{ServiceSpec, UpgradeStrategy};
