//! Domain model for the Mobula control plane.
//!
//! Mobula orchestrates stock Ray clusters through their stable seams
//! (KubeRay CRDs, the Jobs REST API via a federating gateway, Serve
//! ingress). This crate holds the provider-agnostic domain types; it must
//! never depend on a cloud SDK or Kubernetes client (see ADR-0002).

pub mod audit;
pub mod auth;
pub mod cluster;
pub mod job;
pub mod pool;
pub mod registry;
pub mod service;

pub use audit::{AuditDecision, AuditEvent, AuditFilter, AuditRequired};
pub use auth::{ApiTokenRecord, ApiTokenView, LocalRole, LocalUserRecord, LocalUserView};
pub use cluster::{
    ClusterId, ClusterSpec, ClusterState, DriftCondition, TransitionError, WorkerGroup,
};
pub use job::JobRecord;
pub use pool::{
    AllocationSpec, AllocationSpecError, FlavorSpec, FlavorSpecError, PoolSpec, PoolSpecError,
    TaintSpec, TaintSpecError,
};
pub use registry::{ClusterEndpoint, ClusterRegistry, RegistryError};
pub use service::{ServiceSpec, UpgradeStrategy};
