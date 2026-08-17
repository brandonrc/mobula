//! Resource pool domain types (ADR-0010).
//!
//! A `ResourcePool` is Mobula's unit of shared capacity: a set of hardware
//! flavors drawing from a common cohort, with per-project allocations.
//! These types are provider-agnostic; the translation to Kueue objects
//! (ResourceFlavor / ClusterQueue / LocalQueue) lives in
//! `mobula-provision::kueue`, and quantity *parseability* validation lives
//! in `mobula-policy` — core validates shape (names, structure), never
//! quantity syntax.
//!
//! Resource keys are arbitrary Kubernetes resource names (`cpu`, `memory`,
//! `nvidia.com/gpu`, `nvidia.com/mig-1g.10gb`, `example.com/license`, …);
//! there is deliberately no hard-coded key list, matching Kueue's ability
//! to quota any resource name.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PoolSpecError {
    #[error("pool name {0:?} is not a valid Kubernetes name (RFC 1123 subdomain)")]
    InvalidName(String),
    #[error("cohort name {0:?} is not a valid Kubernetes name (RFC 1123 subdomain)")]
    InvalidCohort(String),
    #[error("pool must declare at least one flavor")]
    NoFlavors,
    #[error("duplicate flavor name {0:?}")]
    DuplicateFlavor(String),
    #[error("fair_sharing_weight must be a finite, non-negative number")]
    InvalidFairSharingWeight,
    #[error("flavor {flavor}: {source}")]
    Flavor {
        flavor: String,
        source: FlavorSpecError,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FlavorSpecError {
    #[error("flavor name {0:?} is not a valid Kubernetes name (RFC 1123 subdomain)")]
    InvalidName(String),
    #[error("resource key must be non-empty")]
    EmptyResourceKey,
    #[error("taint {key:?}: {source}")]
    Taint { key: String, source: TaintSpecError },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TaintSpecError {
    #[error("taint key must be non-empty")]
    EmptyKey,
    #[error("taint value must be non-empty")]
    EmptyValue,
    #[error("taint effect must be non-empty (e.g. \"NoSchedule\")")]
    EmptyEffect,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AllocationSpecError {
    #[error("{field} name {name:?} is not a valid Kubernetes name (RFC 1123 subdomain)")]
    InvalidName { field: &'static str, name: String },
}

/// RFC 1123 subdomain: lowercase alphanumerics, `-` and `.`, starting and
/// ending alphanumeric, ≤253 chars. Kueue object names (flavors, queues,
/// cohorts), namespaces, and local-auth usernames all follow this.
pub fn is_k8s_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes().last().is_some_and(|b| b.is_ascii_alphanumeric())
}

/// How a pool's GPUs may be shared between workloads (#58).
///
/// NVIDIA GPU time-slicing (and fractional `nvidia.com/gpu` requests via the
/// device plugin) shares one GPU's SMs across processes with no hardware
/// isolation — acceptable within one tenant, never across tenants. MIG is
/// hardware partitioning and whole-GPU allocation needs no sharing at all,
/// so both are isolation-safe. The tenant-isolation rule itself is enforced
/// by `mobula-policy::gpu` at admission time; this field is the per-pool
/// knob it evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum GpuSharing {
    /// One workload per GPU (the safe default).
    #[default]
    WholeGpu,
    /// MIG hardware partitioning — isolation-safe sharing.
    Mig,
    /// Device-plugin time-slicing — software sharing, single-tenant pools
    /// only.
    TimeSlice,
}

/// A shared capacity pool: flavors + a cohort to borrow from (ADR-0010).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct PoolSpec {
    pub name: String,
    pub flavors: Vec<FlavorSpec>,
    /// Name of the Kueue cohort this pool's ClusterQueue joins for elastic
    /// borrowing.
    pub cohort: String,
    /// Kueue `spec.fairSharing.weight` for the pool's ClusterQueue.
    pub fair_sharing_weight: f64,
    /// Whether workloads in this pool may be elastically resized (Kueue
    /// elastic jobs / Workload Slices).
    pub elastic: bool,
    /// GPU sharing mode for this pool (#58). `None` inherits the platform
    /// default (`[gpu] default_sharing` in the policy file, itself
    /// defaulting to `whole-gpu`). A pool shared by more than one project
    /// may not resolve to `time-slice` — enforced at admission by
    /// `mobula-policy::gpu`, not here (core validates shape; tenancy is
    /// known only at the API edge, where allocations live).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_sharing: Option<GpuSharing>,
}

impl PoolSpec {
    pub fn validate(&self) -> Result<(), PoolSpecError> {
        if !is_k8s_name(&self.name) {
            return Err(PoolSpecError::InvalidName(self.name.clone()));
        }
        if !is_k8s_name(&self.cohort) {
            return Err(PoolSpecError::InvalidCohort(self.cohort.clone()));
        }
        if self.flavors.is_empty() {
            return Err(PoolSpecError::NoFlavors);
        }
        if !self.fair_sharing_weight.is_finite() || self.fair_sharing_weight < 0.0 {
            return Err(PoolSpecError::InvalidFairSharingWeight);
        }
        for (i, f) in self.flavors.iter().enumerate() {
            f.validate().map_err(|source| PoolSpecError::Flavor {
                flavor: f.name.clone(),
                source,
            })?;
            if self.flavors[..i].iter().any(|o| o.name == f.name) {
                return Err(PoolSpecError::DuplicateFlavor(f.name.clone()));
            }
        }
        Ok(())
    }
}

/// A hardware flavor within a pool: node selection plus per-resource
/// nominal quota (K8s quantity strings, e.g. "4", "512Gi").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct FlavorSpec {
    pub name: String,
    /// Resource key → nominal quota quantity string.
    pub resources: BTreeMap<String, String>,
    pub node_labels: BTreeMap<String, String>,
    pub taints: Vec<TaintSpec>,
}

impl FlavorSpec {
    pub fn validate(&self) -> Result<(), FlavorSpecError> {
        if !is_k8s_name(&self.name) {
            return Err(FlavorSpecError::InvalidName(self.name.clone()));
        }
        if self.resources.keys().any(|k| k.is_empty()) {
            return Err(FlavorSpecError::EmptyResourceKey);
        }
        for t in &self.taints {
            t.validate().map_err(|source| FlavorSpecError::Taint {
                key: t.key.clone(),
                source,
            })?;
        }
        Ok(())
    }
}

/// A Kubernetes taint on a flavor's nodes. `effect` is e.g. "NoSchedule";
/// validated non-empty here (the set of legal effects is Kubernetes', not
/// ours).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TaintSpec {
    pub key: String,
    pub value: String,
    pub effect: String,
}

impl TaintSpec {
    pub fn validate(&self) -> Result<(), TaintSpecError> {
        if self.key.is_empty() {
            return Err(TaintSpecError::EmptyKey);
        }
        if self.value.is_empty() {
            return Err(TaintSpecError::EmptyValue);
        }
        if self.effect.is_empty() {
            return Err(TaintSpecError::EmptyEffect);
        }
        Ok(())
    }
}

/// A project's allocation within a pool (translates to a Kueue LocalQueue).
///
/// `nominal` / `borrowing_limit` / `lending_limit` are reserved for a future
/// per-project ClusterQueue layout (ADR-0010): in the v0 layout all
/// allocations in a pool share one ClusterQueue, so these are recorded as
/// LocalQueue annotations rather than enforced quotas.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AllocationSpec {
    pub pool: String,
    pub project: String,
    pub namespace: String,
    pub nominal: BTreeMap<String, String>,
    pub borrowing_limit: BTreeMap<String, String>,
    pub lending_limit: BTreeMap<String, String>,
}

impl AllocationSpec {
    pub fn validate(&self) -> Result<(), AllocationSpecError> {
        for (field, name) in [
            ("pool", &self.pool),
            ("project", &self.project),
            ("namespace", &self.namespace),
        ] {
            if !is_k8s_name(name) {
                return Err(AllocationSpecError::InvalidName {
                    field,
                    name: name.clone(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flavor(name: &str) -> FlavorSpec {
        FlavorSpec {
            name: name.into(),
            resources: BTreeMap::from([
                ("cpu".to_string(), "64".to_string()),
                ("memory".to_string(), "256Gi".to_string()),
            ]),
            node_labels: BTreeMap::new(),
            taints: vec![],
        }
    }

    fn pool() -> PoolSpec {
        PoolSpec {
            name: "gpu-pool".into(),
            flavors: vec![flavor("a100")],
            cohort: "research".into(),
            fair_sharing_weight: 1.0,
            elastic: true,
            gpu_sharing: None,
        }
    }

    #[test]
    fn valid_pool_passes() {
        pool().validate().unwrap();
    }

    #[test]
    fn pool_name_must_be_k8s_safe() {
        for bad in [
            "",
            "GPU_Pool",
            "-lead",
            "trail-",
            "has space",
            "under_score",
        ] {
            let mut p = pool();
            p.name = bad.into();
            assert!(matches!(p.validate(), Err(PoolSpecError::InvalidName(_))));
        }
        // Dots and dashes inside are fine.
        let mut p = pool();
        p.name = "gpu-pool.v2".into();
        p.validate().unwrap();
    }

    #[test]
    fn cohort_must_be_k8s_safe() {
        let mut p = pool();
        p.cohort = "".into();
        assert!(matches!(p.validate(), Err(PoolSpecError::InvalidCohort(_))));
    }

    #[test]
    fn pool_requires_a_flavor() {
        let mut p = pool();
        p.flavors.clear();
        assert_eq!(p.validate(), Err(PoolSpecError::NoFlavors));
    }

    #[test]
    fn duplicate_flavor_names_rejected() {
        let mut p = pool();
        p.flavors.push(flavor("a100"));
        assert_eq!(
            p.validate(),
            Err(PoolSpecError::DuplicateFlavor("a100".into()))
        );
    }

    #[test]
    fn flavor_errors_carry_flavor_context() {
        let mut p = pool();
        p.flavors[0].taints.push(TaintSpec {
            key: "nvidia.com/gpu".into(),
            value: "present".into(),
            effect: "".into(),
        });
        assert_eq!(
            p.validate(),
            Err(PoolSpecError::Flavor {
                flavor: "a100".into(),
                source: FlavorSpecError::Taint {
                    key: "nvidia.com/gpu".into(),
                    source: TaintSpecError::EmptyEffect,
                },
            })
        );
    }

    #[test]
    fn arbitrary_resource_keys_allowed() {
        // No hard-coded key list: extended and custom resources pass.
        let mut f = flavor("mixed");
        f.resources
            .insert("nvidia.com/mig-1g.10gb".into(), "7".into());
        f.resources.insert("example.com/license".into(), "2".into());
        f.validate().unwrap();
        // …but the empty key is never a resource name.
        f.resources.insert("".into(), "1".into());
        assert_eq!(f.validate(), Err(FlavorSpecError::EmptyResourceKey));
    }

    #[test]
    fn taint_fields_must_be_non_empty() {
        assert_eq!(
            TaintSpec {
                key: "".into(),
                value: "v".into(),
                effect: "NoSchedule".into(),
            }
            .validate(),
            Err(TaintSpecError::EmptyKey)
        );
        assert_eq!(
            TaintSpec {
                key: "k".into(),
                value: "".into(),
                effect: "NoSchedule".into(),
            }
            .validate(),
            Err(TaintSpecError::EmptyValue)
        );
    }

    #[test]
    fn allocation_names_must_be_k8s_safe() {
        let alloc = AllocationSpec {
            pool: "gpu-pool".into(),
            project: "proj-a".into(),
            namespace: "proj-a".into(),
            nominal: BTreeMap::new(),
            borrowing_limit: BTreeMap::new(),
            lending_limit: BTreeMap::new(),
        };
        alloc.validate().unwrap();
        let mut bad = alloc.clone();
        bad.namespace = "Not_A_Namespace".into();
        assert_eq!(
            bad.validate(),
            Err(AllocationSpecError::InvalidName {
                field: "namespace",
                name: "Not_A_Namespace".into(),
            })
        );
    }

    #[test]
    fn serde_round_trip_snake_case() {
        let mut p = pool();
        p.gpu_sharing = Some(GpuSharing::Mig);
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("fair_sharing_weight").is_some());
        assert_eq!(v["gpu_sharing"], "mig");
        assert!(v.get("node_labels").is_none()); // that's on flavors
        assert_eq!(serde_json::from_value::<PoolSpec>(v).unwrap(), p,);
    }

    #[test]
    fn gpu_sharing_defaults_to_platform_default_when_absent() {
        // A spec without the field (incl. rows stored before #58) carries
        // None — the platform default applies at enforcement time, and the
        // field is omitted from serialization rather than stored as null.
        let p = pool();
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("gpu_sharing").is_none());
        assert_eq!(serde_json::from_value::<PoolSpec>(v).unwrap(), p);
    }

    #[test]
    fn gpu_sharing_values_are_kebab_case() {
        for (json, mode) in [
            ("\"whole-gpu\"", GpuSharing::WholeGpu),
            ("\"mig\"", GpuSharing::Mig),
            ("\"time-slice\"", GpuSharing::TimeSlice),
        ] {
            assert_eq!(serde_json::from_str::<GpuSharing>(json).unwrap(), mode);
        }
        // The safe default is whole-GPU.
        assert_eq!(GpuSharing::default(), GpuSharing::WholeGpu);
        // Unknown modes are rejected at parse time, never silently coerced.
        assert!(serde_json::from_str::<GpuSharing>("\"timeslice\"").is_err());
        assert!(serde_json::from_str::<GpuSharing>("\"shared\"").is_err());
    }

    #[test]
    fn fair_sharing_weight_must_be_finite_and_non_negative() {
        for bad in [-1.0, f64::NAN, f64::INFINITY] {
            let mut p = pool();
            p.fair_sharing_weight = bad;
            assert_eq!(p.validate(), Err(PoolSpecError::InvalidFairSharingWeight));
        }
        // Zero is a legitimate weight (Kueue's default).
        let mut p = pool();
        p.fair_sharing_weight = 0.0;
        p.validate().unwrap();
    }

    #[test]
    fn flavor_name_must_be_k8s_safe() {
        let f = flavor("Bad_Name");
        assert_eq!(
            f.validate(),
            Err(FlavorSpecError::InvalidName("Bad_Name".into()))
        );
    }

    #[test]
    fn taint_effect_must_be_non_empty() {
        assert_eq!(
            TaintSpec {
                key: "k".into(),
                value: "v".into(),
                effect: "".into(),
            }
            .validate(),
            Err(TaintSpecError::EmptyEffect)
        );
    }
}
