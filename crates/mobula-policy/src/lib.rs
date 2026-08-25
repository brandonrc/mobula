//! Governance policy for Mobula (Phase 4): resource accounting, cost
//! estimation, and quota admission. Pure and provider-agnostic — the
//! reconciler and API call in; nothing here touches Kubernetes or a live
//! autoscaler (Ray owns scaling; we shape bounds and enforce quota,
//! per ADR-0007 and the literature audit's "quota is admission control").
//!
//! Resource accounting is keyed by arbitrary Kubernetes resource names
//! (ADR-0010): pools and Kueue quota any resource name, so the fixed
//! cpu/gpu/memory vector generalizes to [`ResourceMap`]. The well-known
//! keys are `cpu` (cores), `memory` (**GiB**, not bytes — the map keeps
//! the old `mem_gib` semantics under the K8s resource name), and
//! `nvidia.com/gpu` (devices).

pub mod gpu;
pub mod quantity;
pub mod usage;

use mobula_core::ClusterSpec;
use serde::Deserialize;
use std::collections::BTreeMap;

/// Well-known resource keys (any other K8s resource name is equally valid).
pub const CPU: &str = "cpu";
pub const MEMORY: &str = "memory";
pub const GPU: &str = "nvidia.com/gpu";

/// A multi-resource demand/quota map: resource name → amount.
///
/// Amounts are plain `f64` in the key's natural unit (cores for `cpu`,
/// GiB for `memory`, devices for `nvidia.com/gpu`). A missing key means
/// zero — maps are sparse, so demand for a resource a quota doesn't
/// mention is rejected by [`ResourceMap::fits_within`].
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct ResourceMap(pub BTreeMap<String, f64>);

impl std::ops::Add for ResourceMap {
    type Output = ResourceMap;
    /// Union of keys; shared keys sum.
    fn add(self, o: ResourceMap) -> ResourceMap {
        let mut m = self.0;
        for (k, v) in o.0 {
            *m.entry(k).or_insert(0.0) += v;
        }
        ResourceMap(m)
    }
}

impl FromIterator<(String, f64)> for ResourceMap {
    fn from_iter<I: IntoIterator<Item = (String, f64)>>(it: I) -> ResourceMap {
        ResourceMap(it.into_iter().collect())
    }
}

impl ResourceMap {
    pub fn scale(&self, n: f64) -> ResourceMap {
        ResourceMap(self.0.iter().map(|(k, v)| (k.clone(), v * n)).collect())
    }

    /// True when every key in `self` is <= `limit`'s value for that key.
    /// A key missing from `limit` counts as 0, so any demand for an
    /// unlisted resource does not fit.
    pub fn fits_within(&self, limit: &ResourceMap) -> bool {
        self.0
            .iter()
            .all(|(k, v)| *v <= *limit.0.get(k).unwrap_or(&0.0))
    }

    /// Cores under the well-known `cpu` key (0 when absent).
    pub fn cpu(&self) -> f64 {
        self.get(CPU)
    }

    /// Devices under the well-known `nvidia.com/gpu` key (0 when absent).
    pub fn gpu(&self) -> f64 {
        self.get(GPU)
    }

    /// GiB under the well-known `memory` key (0 when absent).
    pub fn mem_gib(&self) -> f64 {
        self.get(MEMORY)
    }

    fn get(&self, key: &str) -> f64 {
        *self.0.get(key).unwrap_or(&0.0)
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PolicyError {
    #[error("invalid quantity: {0}")]
    Quantity(String),
}

fn worker_unit(g: &mobula_core::WorkerGroup) -> Result<ResourceMap, PolicyError> {
    let mut m = BTreeMap::from([
        (
            CPU.to_string(),
            quantity::cpu_cores(&g.cpu).map_err(PolicyError::Quantity)?,
        ),
        (
            MEMORY.to_string(),
            quantity::mem_gib(&g.memory).map_err(PolicyError::Quantity)?,
        ),
    ]);
    let gpu = quantity::gpu_count(g.gpu.as_deref()).map_err(PolicyError::Quantity)?;
    if gpu > 0.0 {
        m.insert(GPU.to_string(), gpu);
    }
    Ok(ResourceMap(m))
}

fn head_unit(spec: &ClusterSpec) -> Result<ResourceMap, PolicyError> {
    Ok(ResourceMap(BTreeMap::from([
        (
            CPU.to_string(),
            quantity::cpu_cores(&spec.head_cpu).map_err(PolicyError::Quantity)?,
        ),
        (
            MEMORY.to_string(),
            quantity::mem_gib(&spec.head_memory).map_err(PolicyError::Quantity)?,
        ),
    ])))
}

/// The resource demand of a cluster at its minimum and maximum size. Min =
/// head + Σ(worker_unit × min_replicas); max = head + Σ(worker_unit ×
/// max_replicas). Quota admits against `max` (worst case, conservative —
/// Borg oversells at low priority; that refinement is future work).
///
/// Emits exactly the keys `cpu` and `memory` (GiB), plus `nvidia.com/gpu`
/// when a worker group requests GPUs.
pub fn cluster_demand(spec: &ClusterSpec) -> Result<(ResourceMap, ResourceMap), PolicyError> {
    let head = head_unit(spec)?;
    let mut min = head.clone();
    let mut max = head;
    for g in &spec.worker_groups {
        // A group with min > max is nonsensical and would make the
        // "max" demand smaller than the min — quota admits against max,
        // so this must be rejected, not silently mischarged (review R2#4).
        if g.min_replicas > g.max_replicas {
            return Err(PolicyError::Quantity(format!(
                "worker group {}: min_replicas ({}) > max_replicas ({})",
                g.name, g.min_replicas, g.max_replicas
            )));
        }
        let unit = worker_unit(g)?;
        min = min + unit.scale(g.min_replicas as f64);
        max = max + unit.scale(g.max_replicas as f64);
    }
    Ok((min, max))
}

/// Hourly price per unit of each resource key (pluggable; a static sheet
/// is fine at v0). Deserialized from config as a flat map of resource name
/// → price: `cpu` = $/core-hour, `memory` = $/GiB-hour, `nvidia.com/gpu`
/// = $/GPU-hour. Keys absent from the sheet price at 0 — an unpriced
/// resource is free for estimation purposes, never an error.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct PriceSheet(pub BTreeMap<String, f64>);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CostEstimate {
    pub min_hourly: f64,
    pub max_hourly: f64,
}

impl PriceSheet {
    fn price(&self, v: &ResourceMap) -> f64 {
        v.0.iter()
            .map(|(k, amount)| amount * self.0.get(k).copied().unwrap_or(0.0))
            .sum()
    }

    /// Estimated $/hr at the cluster's min and max size.
    pub fn estimate(&self, spec: &ClusterSpec) -> Result<CostEstimate, PolicyError> {
        let (min, max) = cluster_demand(spec)?;
        Ok(CostEstimate {
            min_hourly: self.price(&min),
            max_hourly: self.price(&max),
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
    pub requested: ResourceMap,
    pub in_use: ResourceMap,
    pub limit: ResourceMap,
}

/// Admission check (Borg: quota is admission control). `in_use` is the
/// summed max-demand of the project's *other* clusters; `requested` is the
/// max-demand of the cluster being created/updated. Admits iff the total
/// fits within `limit` on every resource key.
pub fn admit(
    project: &str,
    limit: ResourceMap,
    in_use: ResourceMap,
    requested: ResourceMap,
) -> Result<(), QuotaExceeded> {
    let fits = (in_use.clone() + requested.clone()).fits_within(&limit);
    if fits {
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

/// A time-windowed compute **budget** (#77): a cap on *cumulative*
/// consumption over a trailing window, distinct from the [`admit`] quota
/// which caps *concurrent* live demand. `limits` is resource name →
/// resource-hours allowed over the last `window_secs` seconds (`cpu` =
/// core-hours, `memory` = GiB-hours, `nvidia.com/gpu` = GPU-hours, and any
/// extended K8s resource name is equally valid — same key convention as
/// [`ResourceMap`]).
///
/// The flattened deserialization mirrors the `[quotas]` config shape with an
/// extra `window_secs` key:
///
/// ```toml
/// [budgets.team-a]
/// window_secs = 604800        # 7 days
/// "nvidia.com/gpu" = 100      # 100 GPU-hours / 7 days
/// cpu = 5000                  # 5000 core-hours / 7 days
/// ```
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Budget {
    /// Trailing window length in seconds (e.g. 604800 = 7 days).
    pub window_secs: u64,
    /// resource name → resource-hours allowed over the window. Every other
    /// key on the section flattens in here.
    #[serde(flatten)]
    pub limits: BTreeMap<String, f64>,
}

impl Budget {
    /// The cap map as a [`ResourceMap`].
    pub fn limit_map(&self) -> ResourceMap {
        ResourceMap(self.limits.clone())
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error(
    "project {project} budget exceeded: consumed {consumed:?} of {limit:?} \
     resource-hours over the last {window_secs}s"
)]
pub struct BudgetExceeded {
    pub project: String,
    pub consumed: ResourceMap,
    pub limit: ResourceMap,
    pub window_secs: u64,
}

/// Time-windowed budget admission (#77). `consumed` is the project's
/// cumulative resource-hours over the trailing `budget.window_secs`, derived
/// from the metering `usage_samples` (see
/// [`crate::usage::windowed_resource_hours`]).
///
/// **Enforcement model (v1, deliberately simple and documented):** admit iff
/// the *already-consumed* windowed usage is strictly below the cap on every
/// resource the budget lists. We do NOT project the new cluster's future
/// consumption onto the window — a cluster's lifetime is unknown at admission
/// (TTL is optional, autoscaling is Ray's), so any projection would be a
/// guess. Blocking on `consumed >= cap` is the honest floor: once a project
/// has burned its window allowance it can create nothing new until the window
/// rolls forward and older usage ages out. A resource the budget does not
/// list is unconstrained. A cap of 0 admits nothing for that resource.
pub fn admit_budget(
    project: &str,
    budget: &Budget,
    consumed: &ResourceMap,
) -> Result<(), BudgetExceeded> {
    let over = budget
        .limits
        .iter()
        .any(|(resource, cap)| consumed.get(resource) >= *cap);
    if over {
        Err(BudgetExceeded {
            project: project.to_string(),
            consumed: consumed.clone(),
            limit: budget.limit_map(),
            window_secs: budget.window_secs,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::WorkerGroup;

    fn spec(min: u32, max: u32, gpu: Option<&str>) -> ClusterSpec {
        ClusterSpec {
            engine: Default::default(),
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
            idle_timeout_secs: None,
            owner: None,
        }
    }

    fn map(pairs: &[(&str, f64)]) -> ResourceMap {
        pairs.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    #[test]
    fn demand_min_and_max() {
        let (min, max) = cluster_demand(&spec(1, 3, None)).unwrap();
        // head(1cpu,2Gi) + 1 worker(2cpu,4Gi)
        assert_eq!(min, map(&[("cpu", 3.0), ("memory", 6.0)]));
        // head + 3 workers
        assert_eq!(max, map(&[("cpu", 7.0), ("memory", 14.0)]));
    }

    #[test]
    fn gpu_demand_counted() {
        let (_, max) = cluster_demand(&spec(0, 2, Some("1"))).unwrap();
        assert_eq!(max.gpu(), 2.0);
        // The well-known helpers read the well-known keys.
        assert_eq!(max.cpu(), 5.0); // head 1 + 2×2
        assert_eq!(max.mem_gib(), 10.0); // head 2 + 2×4
    }

    #[test]
    fn no_gpu_key_without_gpu_workers() {
        // Sparse maps: no GPU request means no key at all, so a quota
        // sheet without a GPU entry still admits GPU-free clusters.
        let (_, max) = cluster_demand(&spec(0, 2, None)).unwrap();
        assert!(!max.0.contains_key(GPU));
    }

    #[test]
    fn add_is_key_union() {
        let a = map(&[("cpu", 1.0), ("nvidia.com/gpu", 2.0)]);
        let b = map(&[("cpu", 3.0), ("example.com/license", 1.0)]);
        assert_eq!(
            a + b,
            map(&[
                ("cpu", 4.0),
                ("nvidia.com/gpu", 2.0),
                ("example.com/license", 1.0)
            ])
        );
    }

    #[test]
    fn fits_within_treats_missing_limit_key_as_zero() {
        // Any demand for a resource the limit doesn't list must reject.
        let demand = map(&[("cpu", 1.0), ("example.com/license", 1.0)]);
        let limit = map(&[("cpu", 10.0)]);
        assert!(!demand.fits_within(&limit));
        // Zero demand for an unlisted resource fits.
        let demand = map(&[("cpu", 1.0)]);
        assert!(demand.fits_within(&limit));
    }

    #[test]
    fn extended_resource_keys_in_demand_maps() {
        // Demand maps are constructed directly with arbitrary K8s resource
        // names (MIG slices, custom licenses) — no hard-coded key list.
        let demand = map(&[("nvidia.com/mig-1g.10gb", 7.0), ("cpu", 4.0)]);
        let limit = map(&[("nvidia.com/mig-1g.10gb", 7.0), ("cpu", 8.0)]);
        assert!(demand.fits_within(&limit));
        let scaled = demand.scale(2.0);
        assert_eq!(scaled.0["nvidia.com/mig-1g.10gb"], 14.0);
        assert!(!scaled.fits_within(&limit));
    }

    #[test]
    fn cost_estimate_min_below_max() {
        let prices = PriceSheet(BTreeMap::from([
            ("cpu".to_string(), 0.04),
            ("nvidia.com/gpu".to_string(), 2.0),
            ("memory".to_string(), 0.005),
        ]));
        let est = prices.estimate(&spec(1, 3, None)).unwrap();
        assert!(est.min_hourly < est.max_hourly);
        // max = 7cpu*0.04 + 0 + 14*0.005 = 0.28 + 0.07 = 0.35
        assert!((est.max_hourly - 0.35).abs() < 1e-9);
    }

    #[test]
    fn price_sheet_ignores_unknown_keys() {
        // A resource with no price entry contributes 0, never an error.
        let prices = PriceSheet(BTreeMap::from([("cpu".to_string(), 0.04)]));
        let demand = map(&[("cpu", 2.0), ("example.com/license", 5.0)]);
        assert!((prices.price(&demand) - 0.08).abs() < 1e-9);
    }

    #[test]
    fn price_sheet_deserializes_from_flat_config_map() {
        let sheet: PriceSheet =
            serde_json::from_str(r#"{"cpu": 0.04, "nvidia.com/gpu": 2.0, "memory": 0.005}"#)
                .unwrap();
        assert!((sheet.0["nvidia.com/gpu"] - 2.0).abs() < 1e-9);
    }

    #[test]
    fn quota_admits_and_rejects() {
        let limit = map(&[("cpu", 10.0), ("memory", 20.0)]);
        let in_use = map(&[("cpu", 4.0), ("memory", 8.0)]);
        // requested max for spec(1,3): 7cpu/14Gi → 4+7=11 > 10 → reject.
        let (_, req) = cluster_demand(&spec(1, 3, None)).unwrap();
        assert!(admit("p", limit.clone(), in_use.clone(), req).is_err());
        // Smaller cluster fits.
        let (_, small) = cluster_demand(&spec(0, 1, None)).unwrap();
        assert!(admit("p", limit, in_use, small).is_ok());
    }

    #[test]
    fn gpu_quota_enforced_independently() {
        let limit = map(&[("cpu", 100.0), ("nvidia.com/gpu", 1.0), ("memory", 100.0)]);
        let (_, req) = cluster_demand(&spec(0, 2, Some("1"))).unwrap(); // 2 GPUs
        assert!(admit("p", limit, ResourceMap::default(), req).is_err());
    }

    #[test]
    fn bad_quantity_surfaces_error() {
        let mut s = spec(1, 1, None);
        s.head_cpu = "banana".into();
        assert!(matches!(cluster_demand(&s), Err(PolicyError::Quantity(_))));
    }

    #[test]
    fn budget_deserializes_window_and_flattened_resource_hours() {
        // window_secs is a named field; every other key flattens into limits.
        // (TOML deserializes through the same serde path — covered by the CLI
        // crate's parse_policy test; here we use serde_json, the store/PUT
        // wire shape, to avoid a toml dev-dependency.)
        let b: Budget =
            serde_json::from_str(r#"{"window_secs":604800,"nvidia.com/gpu":100.0,"cpu":5000.0}"#)
                .unwrap();
        assert_eq!(b.window_secs, 604800);
        assert_eq!(b.limits["nvidia.com/gpu"], 100.0);
        assert_eq!(b.limits["cpu"], 5000.0);
        assert_eq!(b.limit_map().gpu(), 100.0);
        // The window field is not swept into the resource limits.
        assert!(!b.limits.contains_key("window_secs"));
    }

    #[test]
    fn budget_admits_under_and_denies_at_or_over_cap() {
        let budget = Budget {
            window_secs: 604800,
            limits: BTreeMap::from([("nvidia.com/gpu".to_string(), 100.0)]),
        };
        // Under the cap admits.
        assert!(admit_budget("team-a", &budget, &map(&[("nvidia.com/gpu", 99.9)])).is_ok());
        // At the cap denies (consumed >= cap).
        assert!(admit_budget("team-a", &budget, &map(&[("nvidia.com/gpu", 100.0)])).is_err());
        // Over the cap denies, and the error carries the accounting.
        let err = admit_budget("team-a", &budget, &map(&[("nvidia.com/gpu", 150.0)])).unwrap_err();
        assert_eq!(err.project, "team-a");
        assert_eq!(err.consumed.gpu(), 150.0);
        assert_eq!(err.limit.gpu(), 100.0);
        assert_eq!(err.window_secs, 604800);
    }

    #[test]
    fn budget_only_constrains_listed_resources() {
        // A budget on GPU-hours does not constrain CPU-hours at all.
        let budget = Budget {
            window_secs: 604800,
            limits: BTreeMap::from([("nvidia.com/gpu".to_string(), 100.0)]),
        };
        // Huge CPU consumption, zero GPU consumption → admits.
        assert!(admit_budget("team-a", &budget, &map(&[("cpu", 1_000_000.0)])).is_ok());
        // Empty budget (no listed resources) never denies.
        let empty = Budget {
            window_secs: 604800,
            limits: BTreeMap::new(),
        };
        assert!(admit_budget(
            "team-a",
            &empty,
            &map(&[("cpu", 9e9), ("nvidia.com/gpu", 9e9)])
        )
        .is_ok());
    }

    #[test]
    fn min_replicas_above_max_is_rejected() {
        // A group with min > max would make "max" demand smaller than the
        // min — quota admits against max, so this is rejected, not
        // silently mischarged (review R2#4).
        let err = cluster_demand(&spec(3, 1, None)).unwrap_err();
        assert!(
            matches!(&err, PolicyError::Quantity(m) if m.contains("min_replicas (3) > max_replicas (1)")),
            "{err}"
        );
    }
}
