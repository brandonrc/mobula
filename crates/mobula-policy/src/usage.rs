//! Usage aggregation (Slice 4): turn the append-only usage-sample
//! timeseries into resource-hours and dollars. Pure functions over plain
//! input shapes, decoupled from the controller's `UsageSample` type so the
//! policy crate stays storage-agnostic.

use crate::{PriceSheet, ResourceMap};

/// One usage sample as the aggregator sees it: a quantity reading at `ts`
/// (unix seconds). Decoupled from `mobula_controller::UsageSample` on
/// purpose — the caller projects its rows down to this shape.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UsageSampleView {
    pub ts: u64,
    pub quantity: f64,
}

/// Integrate a usage timeseries over `[from, to]` (unix seconds) into
/// **resource-hours**: Σ qty_i × held_seconds / 3600.
///
/// The series is a **step function**: a sample's quantity holds until the
/// next sample changes it (samples are point readings of a level, not
/// deltas). Rules:
///
/// - **Carry-in**: the last sample at-or-before `from` establishes the
///   level entering the window. With no such sample the level is 0 until
///   the first in-window sample (unknown history reads as zero, never an
///   invented value).
/// - **Clamping**: the window edges `from`/`to` bound the integration; a
///   sample's level never extends past `to`, and levels entering at `from`
///   start accruing there.
/// - **Sampler gaps**: a gap longer than the sampling cadence (e.g. the
///   metering loop was down) is treated as "last known state persisted" —
///   the step still holds across it. This is simple and honest: the gap is
///   visible in the sample density, and no interpolation invents usage.
///
/// Input need not be sorted; it is sorted internally. `from >= to` yields 0.
pub fn resource_hours(samples: &[(u64, f64)], from: u64, to: u64) -> f64 {
    if from >= to {
        return 0.0;
    }
    let mut pts: Vec<(u64, f64)> = samples.to_vec();
    pts.sort_by_key(|&(t, _)| t);

    let mut level = 0.0;
    let mut cursor = from;
    let mut seconds = 0.0f64;
    for &(t, q) in &pts {
        if t <= from {
            // Carry-in: keep the latest level at-or-before the window start.
            level = q;
            continue;
        }
        if t >= to {
            break;
        }
        seconds += level * (t - cursor) as f64;
        cursor = t;
        level = q;
    }
    // The final level holds to the window end.
    seconds += level * (to - cursor) as f64;
    seconds / 3600.0
}

/// Windowed cumulative consumption per resource (#77), summed correctly
/// across pools. Input is keyed by `(pool, resource)` → the step-series of
/// `(ts, quantity)` readings; each series is integrated over `[from, to]`
/// with [`resource_hours`] (carry-in and clamping included) and the
/// per-pool hours are summed per resource.
///
/// Series from different pools must NOT be interleaved into one step series
/// (readings of different levels), so grouping by pool is load-bearing — it
/// matches how `/api/v1/usage` groups by `(project, pool)`. A project
/// normally lives in one pool, but a re-homed project can have samples in
/// two; this sums them honestly.
pub fn windowed_resource_hours(
    by_pool_resource: &std::collections::BTreeMap<(String, String), Vec<(u64, f64)>>,
    from: u64,
    to: u64,
) -> ResourceMap {
    let mut out: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
    for ((_pool, resource), series) in by_pool_resource {
        let hours = resource_hours(series, from, to);
        *out.entry(resource.clone()).or_insert(0.0) += hours;
    }
    ResourceMap(out)
}

/// Dollar cost of a per-resource hours roll-up under a price sheet:
/// Σ hours_r × price_r. Resources absent from the sheet price at 0 (an
/// unpriced resource is free for estimation, never an error — same rule as
/// `PriceSheet::estimate`).
pub fn cost(quantity_hours_per_resource: &ResourceMap, sheet: &PriceSheet) -> f64 {
    quantity_hours_per_resource
        .0
        .iter()
        .map(|(k, hours)| hours * sheet.0.get(k).copied().unwrap_or(0.0))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn hours(samples: &[(u64, f64)], from: u64, to: u64) -> f64 {
        resource_hours(samples, from, to)
    }

    #[test]
    fn constant_series() {
        // 4 cores held for the whole 3600s window = 4 core-hours.
        let s = [(0, 4.0)];
        assert!((hours(&s, 0, 3600) - 4.0).abs() < 1e-9);
    }

    #[test]
    fn step_change_mid_window() {
        // 4 cores for the first half, 8 for the second.
        let s = [(0, 4.0), (1800, 8.0)];
        assert!((hours(&s, 0, 3600) - (2.0 + 4.0)).abs() < 1e-9);
    }

    #[test]
    fn carry_in_from_before_from() {
        // A sample before the window sets the level entering it: 10 cores
        // held from t=50 carries into [100, 200] and holds to the end.
        let s = [(50, 10.0)];
        assert!((hours(&s, 100, 200) - 10.0 * 100.0 / 3600.0).abs() < 1e-9);
        // A later pre-window sample overrides an earlier one.
        let s = [(10, 1.0), (90, 5.0)];
        assert!((hours(&s, 100, 200) - 5.0 * 100.0 / 3600.0).abs() < 1e-9);
    }

    #[test]
    fn no_carry_in_means_zero_until_first_sample() {
        let s = [(150, 10.0)];
        // [100, 200]: 0 for [100,150), then 10 for [150,200).
        assert!((hours(&s, 100, 200) - 10.0 * 50.0 / 3600.0).abs() < 1e-9);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(hours(&[], 0, 3600), 0.0);
    }

    #[test]
    fn window_clamping() {
        // Samples outside the window on both sides: level at `from` is 2
        // (from t=0), the t=2000 sample is beyond `to` and never applies.
        let s = [(0, 2.0), (2000, 9.0)];
        assert!((hours(&s, 100, 1000) - 2.0 * 900.0 / 3600.0).abs() < 1e-9);
        // A sample exactly at `to` contributes nothing.
        let s = [(0, 2.0), (1000, 9.0)];
        assert!((hours(&s, 100, 1000) - 2.0 * 900.0 / 3600.0).abs() < 1e-9);
        // Degenerate window.
        assert_eq!(hours(&s, 500, 500), 0.0);
        assert_eq!(hours(&s, 900, 100), 0.0);
    }

    #[test]
    fn gap_step_holds_last_known_state() {
        // Sampler was down for hours: the last reading persists across the
        // gap instead of interpolating to zero.
        let s = [(0, 4.0), (7200, 4.0)];
        assert!((hours(&s, 0, 7200) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn unsorted_input_is_sorted() {
        let s = [(1800, 8.0), (0, 4.0)];
        assert!((hours(&s, 0, 3600) - 6.0).abs() < 1e-9);
    }

    #[test]
    fn cost_rolls_up_priced_and_unpriced_keys() {
        let hours = ResourceMap(BTreeMap::from([
            ("cpu".to_string(), 10.0),                // 10 × 0.04 = 0.40
            ("memory".to_string(), 100.0),            // 100 × 0.005 = 0.50
            ("example.com/license".to_string(), 7.0), // unpriced → 0
        ]));
        let sheet = PriceSheet(BTreeMap::from([
            ("cpu".to_string(), 0.04),
            ("memory".to_string(), 0.005),
        ]));
        assert!((cost(&hours, &sheet) - 0.90).abs() < 1e-9);
        // Empty sheet prices everything at 0.
        assert_eq!(cost(&hours, &PriceSheet::default()), 0.0);
    }

    #[test]
    fn windowed_hours_sums_across_pools_per_resource() {
        // proj-a ran in two pools during the window; GPU-hours sum across
        // both, CPU only appears in pool gpu.
        let mut by: BTreeMap<(String, String), Vec<(u64, f64)>> = BTreeMap::new();
        // pool "gpu": 2 GPUs held the whole 3600s window = 2 GPU-hours.
        by.insert(("gpu".into(), "nvidia.com/gpu".into()), vec![(0, 2.0)]);
        by.insert(("gpu".into(), "cpu".into()), vec![(0, 8.0)]);
        // pool "gpu2": 1 GPU held the whole window = 1 GPU-hour.
        by.insert(("gpu2".into(), "nvidia.com/gpu".into()), vec![(0, 1.0)]);
        let hrs = windowed_resource_hours(&by, 0, 3600);
        assert!((hrs.gpu() - 3.0).abs() < 1e-9, "2 + 1 GPU-hours");
        assert!((hrs.cpu() - 8.0).abs() < 1e-9);
    }

    #[test]
    fn windowed_hours_respects_window_carry_in() {
        // A reading before `from` carries into the window (older usage that
        // has not yet aged out still counts against the trailing window).
        let mut by: BTreeMap<(String, String), Vec<(u64, f64)>> = BTreeMap::new();
        by.insert(("p".into(), "cpu".into()), vec![(0, 4.0)]);
        // Window [1800, 5400): 4 cores held the whole hour = 4 core-hours.
        let hrs = windowed_resource_hours(&by, 1800, 5400);
        assert!((hrs.cpu() - 4.0).abs() < 1e-9);
        assert!(windowed_resource_hours(&BTreeMap::new(), 0, 3600)
            .0
            .is_empty());
    }

    #[test]
    fn sample_view_is_the_documented_input_shape() {
        // UsageSampleView exists so callers can project their own row type;
        // it carries exactly (ts, quantity).
        let v = UsageSampleView {
            ts: 0,
            quantity: 2.0,
        };
        let pairs: Vec<(u64, f64)> = [v].into_iter().map(|s| (s.ts, s.quantity)).collect();
        assert!((resource_hours(&pairs, 0, 3600) - 2.0).abs() < 1e-9);
    }
}
