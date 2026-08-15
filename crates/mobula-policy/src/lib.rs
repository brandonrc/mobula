//! Governance policy for Mobula (Phase 4): resource accounting, cost
//! estimation, and quota admission. Pure and provider-agnostic — the
//! reconciler and API call in; nothing here touches Kubernetes or a live
//! autoscaler (Ray owns scaling; we shape bounds and enforce quota,
//! per ADR-0007 and the literature audit's "quota is admission control").

pub mod quantity;

use mobula_core::ClusterSpec;
use serde::Deserialize;

/// A multi-resource demand/quota vector.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ResourceVector {
    pub cpu: f64,
    pub gpu: f64,
    pub mem_gib: f64,
}

impl std::ops::Add for ResourceVector {
    type Output = ResourceVector;
    fn add(self, o: ResourceVector) -> ResourceVector {
        ResourceVector {
            cpu: self.cpu + o.cpu,
            gpu: self.gpu + o.gpu,
            mem_gib: self.mem_gib + o.mem_gib,
        }
    }
}

impl ResourceVector {
    pub fn scale(self, n: f64) -> ResourceVector {
        ResourceVector {
            cpu: self.cpu * n,
            gpu: self.gpu * n,
            mem_gib: self.mem_gib * n,
        }
    }

    /// True when every component is <= `limit`'s.
    pub fn fits_within(self, limit: ResourceVector) -> bool {
        self.cpu <= limit.cpu && self.gpu <= limit.gpu && self.mem_gib <= limit.mem_gib
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PolicyError {
    #[error("invalid quantity: {0}")]
    Quantity(String),
}

fn worker_unit(g: &mobula_core::WorkerGroup) -> Result<ResourceVector, PolicyError> {
    Ok(ResourceVector {
        cpu: quantity::cpu_cores(&g.cpu).map_err(PolicyError::Quantity)?,
        gpu: quantity::gpu_count(g.gpu.as_deref()).map_err(PolicyError::Quantity)?,
        mem_gib: quantity::mem_gib(&g.memory).map_err(PolicyError::Quantity)?,
    })
}

fn head_unit(spec: &ClusterSpec) -> Result<ResourceVector, PolicyError> {
    Ok(ResourceVector {
        cpu: quantity::cpu_cores(&spec.head_cpu).map_err(PolicyError::Quantity)?,
        gpu: 0.0,
        mem_gib: quantity::mem_gib(&spec.head_memory).map_err(PolicyError::Quantity)?,
    })
}

/// The resource demand of a cluster at its minimum and maximum size. Min =
/// head + Σ(worker_unit × min_replicas); max = head + Σ(worker_unit ×
/// max_replicas). Quota admits against `max` (worst case, conservative —
/// Borg oversells at low priority; that refinement is future work).
pub fn cluster_demand(spec: &ClusterSpec) -> Result<(ResourceVector, ResourceVector), PolicyError> {
    let head = head_unit(spec)?;
    let mut min = head;
    let mut max = head;
    for g in &spec.worker_groups {
        let unit = worker_unit(g)?;
        min = min + unit.scale(g.min_replicas as f64);
        max = max + unit.scale(g.max_replicas as f64);
    }
    Ok((min, max))
}

/// Per-resource hourly prices (pluggable; a static sheet is fine at v0).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct PriceSheet {
    pub cpu_core_hour: f64,
    pub gpu_hour: f64,
    pub mem_gib_hour: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostEstimate {
    pub min_hourly: f64,
    pub max_hourly: f64,
}

impl PriceSheet {
    fn price(&self, v: ResourceVector) -> f64 {
        v.cpu * self.cpu_core_hour + v.gpu * self.gpu_hour + v.mem_gib * self.mem_gib_hour
    }

    /// Estimated $/hr at the cluster's min and max size.
    pub fn estimate(&self, spec: &ClusterSpec) -> Result<CostEstimate, PolicyError> {
        let (min, max) = cluster_demand(spec)?;
        Ok(CostEstimate {
            min_hourly: self.price(min),
            max_hourly: self.price(max),
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error(
    "project {project} quota exceeded: requested max {requested:?} + in-use {in_use:?} \
     exceeds limit {limit:?}"
)]
pub struct QuotaExceeded {
    pub project: String,
    pub requested: ResourceVector,
    pub in_use: ResourceVector,
    pub limit: ResourceVector,
}

/// Admission check (Borg: quota is admission control). `in_use` is the
/// summed max-demand of the project's *other* clusters; `requested` is the
/// max-demand of the cluster being created/updated. Admits iff the total
/// fits within `limit`.
pub fn admit(
    project: &str,
    limit: ResourceVector,
    in_use: ResourceVector,
    requested: ResourceVector,
) -> Result<(), QuotaExceeded> {
    if (in_use + requested).fits_within(limit) {
        Ok(())
    } else {
        Err(QuotaExceeded {
            project: project.to_string(),
            requested,
            in_use,
            limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::WorkerGroup;

    fn spec(min: u32, max: u32, gpu: Option<&str>) -> ClusterSpec {
        ClusterSpec {
            name: "c".into(),
            project: "p".into(),
            ray_version: "2.57.0".into(),
            image: "img".into(),
            head_cpu: "1".into(),
            head_memory: "2Gi".into(),
            worker_groups: vec![WorkerGroup {
                name: "w".into(),
                cpu: "2".into(),
                memory: "4Gi".into(),
                gpu: gpu.map(String::from),
                min_replicas: min,
                max_replicas: max,
                replicas: min,
            }],
            ttl_seconds: None,
        }
    }

    #[test]
    fn demand_min_and_max() {
        let (min, max) = cluster_demand(&spec(1, 3, None)).unwrap();
        // head(1cpu,2Gi) + 1 worker(2cpu,4Gi)
        assert_eq!(
            min,
            ResourceVector {
                cpu: 3.0,
                gpu: 0.0,
                mem_gib: 6.0
            }
        );
        // head + 3 workers
        assert_eq!(
            max,
            ResourceVector {
                cpu: 7.0,
                gpu: 0.0,
                mem_gib: 14.0
            }
        );
    }

    #[test]
    fn gpu_demand_counted() {
        let (_, max) = cluster_demand(&spec(0, 2, Some("1"))).unwrap();
        assert_eq!(max.gpu, 2.0);
    }

    #[test]
    fn cost_estimate_min_below_max() {
        let prices = PriceSheet {
            cpu_core_hour: 0.04,
            gpu_hour: 2.0,
            mem_gib_hour: 0.005,
        };
        let est = prices.estimate(&spec(1, 3, None)).unwrap();
        assert!(est.min_hourly < est.max_hourly);
        // max = 7cpu*0.04 + 0 + 14*0.005 = 0.28 + 0.07 = 0.35
        assert!((est.max_hourly - 0.35).abs() < 1e-9);
    }

    #[test]
    fn quota_admits_and_rejects() {
        let limit = ResourceVector {
            cpu: 10.0,
            gpu: 0.0,
            mem_gib: 20.0,
        };
        let in_use = ResourceVector {
            cpu: 4.0,
            gpu: 0.0,
            mem_gib: 8.0,
        };
        // requested max for spec(1,3): 7cpu/14Gi → 4+7=11 > 10 → reject.
        let (_, req) = cluster_demand(&spec(1, 3, None)).unwrap();
        assert!(admit("p", limit, in_use, req).is_err());
        // Smaller cluster fits.
        let (_, small) = cluster_demand(&spec(0, 1, None)).unwrap();
        assert!(admit("p", limit, in_use, small).is_ok());
    }

    #[test]
    fn gpu_quota_enforced_independently() {
        let limit = ResourceVector {
            cpu: 100.0,
            gpu: 1.0,
            mem_gib: 100.0,
        };
        let (_, req) = cluster_demand(&spec(0, 2, Some("1"))).unwrap(); // 2 GPUs
        assert!(admit("p", limit, ResourceVector::default(), req).is_err());
    }

    #[test]
    fn bad_quantity_surfaces_error() {
        let mut s = spec(1, 1, None);
        s.head_cpu = "banana".into();
        assert!(matches!(cluster_demand(&s), Err(PolicyError::Quantity(_))));
    }
}
