//! GPU-sharing tenant isolation (#58).
//!
//! Threat model: NVIDIA GPU time-slicing — and equivalently fractional
//! `nvidia.com/gpu` requests via the device plugin — multiplexes one GPU's
//! SMs across processes with no hardware isolation: co-resident tenants can
//! observe or starve each other (and share the same failure domain). That
//! is acceptable *within* one tenant, never *across* tenants. MIG partitions
//! the GPU in hardware (dedicated SMs, memory, and L2 per slice) and
//! whole-GPU allocation shares nothing, so both are isolation-safe.
//!
//! The rule, enforced at admission (pool allocation and cluster creation):
//!
//! - A pool shared by **more than one project** may not resolve to
//!   [`GpuSharing::TimeSlice`], and clusters admitted to it may not make
//!   fractional GPU requests. `whole-gpu` and `mig` are always allowed.
//! - A **single-project** pool may opt into `time-slice` explicitly
//!   (`gpu_sharing = "time-slice"` on the pool spec), and fractional
//!   requests into it are fine.
//!
//! Pure functions over plain inputs, mirroring the rest of this crate: the
//! caller (the API edge) supplies the pool spec, the platform default, and
//! the tenant count — tenancy lives in allocations, which core types never
//! see.

use mobula_core::{ClusterSpec, GpuSharing, PoolSpec};

use crate::quantity;

/// The sharing mode a pool effectively runs: its own `gpu_sharing` when
/// set, else the platform default (`[gpu] default_sharing` in the policy
/// file, itself defaulting to `whole-gpu`).
pub fn effective_gpu_sharing(pool: &PoolSpec, platform_default: GpuSharing) -> GpuSharing {
    pool.gpu_sharing.unwrap_or(platform_default)
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum GpuSharingViolation {
    #[error(
        "tenant isolation: pool {pool:?} is shared by {tenants} projects, so gpu_sharing = \
         \"time-slice\" is forbidden — time-slicing shares GPU SMs across processes with no \
         hardware isolation; use \"mig\" (hardware partitioning) or \"whole-gpu\""
    )]
    CrossTenantTimeSlice { pool: String, tenants: usize },
    #[error(
        "tenant isolation: pool {pool:?} is shared by {tenants} projects, so fractional GPU \
         requests are forbidden — worker group {group:?} requests {requested} nvidia.com/gpu, \
         and a fractional GPU is device-plugin time-slicing; request whole GPUs or a MIG slice \
         resource (e.g. nvidia.com/mig-1g.10gb)"
    )]
    CrossTenantFractionalGpu {
        pool: String,
        group: String,
        requested: String,
        tenants: usize,
    },
    #[error("invalid quantity: {0}")]
    Quantity(String),
}

/// Pool-side check: a pool shared by more than one project may not resolve
/// to `time-slice`. `tenants` is the number of distinct projects holding an
/// allocation in the pool *after* the pending change.
pub fn check_pool_gpu_isolation(
    pool: &PoolSpec,
    platform_default: GpuSharing,
    tenants: usize,
) -> Result<(), GpuSharingViolation> {
    if tenants > 1 && effective_gpu_sharing(pool, platform_default) == GpuSharing::TimeSlice {
        return Err(GpuSharingViolation::CrossTenantTimeSlice {
            pool: pool.name.clone(),
            tenants,
        });
    }
    Ok(())
}

/// Cluster-side check for admission of `spec` into `pool`: never admit into
/// a non-compliant pool at all (fail closed — a multi-tenant time-slice
/// pool should be unreachable through validated writes, but rows predate
/// rules), and reject fractional `nvidia.com/gpu` requests when the pool is
/// shared, since a fractional GPU *is* time-slicing.
pub fn check_cluster_gpu_isolation(
    pool: &PoolSpec,
    platform_default: GpuSharing,
    tenants: usize,
    spec: &ClusterSpec,
) -> Result<(), GpuSharingViolation> {
    check_pool_gpu_isolation(pool, platform_default, tenants)?;
    if tenants <= 1 {
        return Ok(());
    }
    for g in &spec.worker_groups {
        let Some(raw) = g.gpu.as_deref() else {
            continue;
        };
        let n = quantity::gpu_count(Some(raw)).map_err(GpuSharingViolation::Quantity)?;
        if n.fract() != 0.0 {
            return Err(GpuSharingViolation::CrossTenantFractionalGpu {
                pool: pool.name.clone(),
                group: g.name.clone(),
                requested: raw.to_string(),
                tenants,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::{FlavorSpec, WorkerGroup};
    use std::collections::BTreeMap;

    fn pool(mode: Option<GpuSharing>) -> PoolSpec {
        PoolSpec {
            name: "gpu-pool".into(),
            flavors: vec![FlavorSpec {
                name: "a100".into(),
                resources: BTreeMap::from([("nvidia.com/gpu".to_string(), "8".to_string())]),
                node_labels: BTreeMap::new(),
                taints: vec![],
            }],
            cohort: "main".into(),
            fair_sharing_weight: 1.0,
            elastic: false,
            gpu_sharing: mode,
        }
    }

    fn cluster(gpu: Option<&str>) -> ClusterSpec {
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
                min_replicas: 1,
                max_replicas: 1,
                replicas: 1,
            }],
            ttl_seconds: None,
        }
    }

    #[test]
    fn cross_tenant_time_slice_rejected() {
        let p = pool(Some(GpuSharing::TimeSlice));
        let err = check_pool_gpu_isolation(&p, GpuSharing::WholeGpu, 2).unwrap_err();
        assert!(
            matches!(
                &err,
                GpuSharingViolation::CrossTenantTimeSlice { pool, tenants: 2 } if pool == "gpu-pool"
            ),
            "{err}"
        );
        // The error names the tenant-isolation reason.
        assert!(err.to_string().contains("tenant isolation"), "{err}");
        // …regardless of how many tenants beyond one share the pool.
        assert!(check_pool_gpu_isolation(&p, GpuSharing::WholeGpu, 5).is_err());
    }

    #[test]
    fn cross_tenant_mig_and_whole_gpu_allowed() {
        for mode in [GpuSharing::Mig, GpuSharing::WholeGpu] {
            check_pool_gpu_isolation(&pool(Some(mode)), GpuSharing::WholeGpu, 3).unwrap();
        }
    }

    #[test]
    fn single_tenant_time_slice_opt_in_allowed() {
        let p = pool(Some(GpuSharing::TimeSlice));
        check_pool_gpu_isolation(&p, GpuSharing::WholeGpu, 1).unwrap();
        check_pool_gpu_isolation(&p, GpuSharing::WholeGpu, 0).unwrap();
        // …and fractional requests into it are fine.
        check_cluster_gpu_isolation(&p, GpuSharing::WholeGpu, 1, &cluster(Some("0.5"))).unwrap();
    }

    #[test]
    fn platform_default_applies_when_pool_unset() {
        let p = pool(None);
        assert_eq!(
            effective_gpu_sharing(&p, GpuSharing::WholeGpu),
            GpuSharing::WholeGpu
        );
        // A platform default of time-slice makes an unset pool time-slice —
        // and therefore rejects cross-tenant sharing all the same.
        assert_eq!(
            effective_gpu_sharing(&p, GpuSharing::TimeSlice),
            GpuSharing::TimeSlice
        );
        assert!(matches!(
            check_pool_gpu_isolation(&p, GpuSharing::TimeSlice, 2),
            Err(GpuSharingViolation::CrossTenantTimeSlice { .. })
        ));
        // The pool's own setting wins over the platform default.
        check_pool_gpu_isolation(&pool(Some(GpuSharing::Mig)), GpuSharing::TimeSlice, 2).unwrap();
    }

    #[test]
    fn fractional_gpu_rejected_cross_tenant() {
        let p = pool(Some(GpuSharing::Mig));
        let err = check_cluster_gpu_isolation(&p, GpuSharing::WholeGpu, 2, &cluster(Some("0.5")))
            .unwrap_err();
        assert!(
            matches!(
                &err,
                GpuSharingViolation::CrossTenantFractionalGpu { group, requested, tenants: 2, .. }
                    if group == "w" && requested == "0.5"
            ),
            "{err}"
        );
        assert!(err.to_string().contains("tenant isolation"), "{err}");
    }

    #[test]
    fn whole_gpu_requests_allowed_cross_tenant() {
        let p = pool(Some(GpuSharing::WholeGpu));
        check_cluster_gpu_isolation(&p, GpuSharing::WholeGpu, 4, &cluster(Some("2"))).unwrap();
        // No GPU request at all is trivially fine.
        check_cluster_gpu_isolation(&p, GpuSharing::WholeGpu, 4, &cluster(None)).unwrap();
        // Zero is not a share of anything.
        check_cluster_gpu_isolation(&p, GpuSharing::WholeGpu, 4, &cluster(Some("0"))).unwrap();
    }

    #[test]
    fn cluster_admission_into_noncompliant_pool_fails_closed() {
        // A multi-tenant time-slice pool is unreachable through validated
        // writes, but a stored pool could predate the rule — never admit.
        let p = pool(Some(GpuSharing::TimeSlice));
        assert!(matches!(
            check_cluster_gpu_isolation(&p, GpuSharing::WholeGpu, 2, &cluster(Some("1"))),
            Err(GpuSharingViolation::CrossTenantTimeSlice { .. })
        ));
    }

    #[test]
    fn unparseable_gpu_quantity_surfaces() {
        let p = pool(None);
        assert!(matches!(
            check_cluster_gpu_isolation(&p, GpuSharing::WholeGpu, 2, &cluster(Some("half"))),
            Err(GpuSharingViolation::Quantity(_))
        ));
    }
}
