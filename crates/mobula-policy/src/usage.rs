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
