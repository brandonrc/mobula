//! Minimal Kubernetes quantity parsing for CPU and memory strings.

/// Reject NaN, infinities, and negatives — a quantity must be a finite,
/// non-negative number (review R2#4: a negative demand would lower a
/// project's quota usage and let over-provisioning slip through).
fn finite_nonneg(v: f64, what: &str) -> Result<f64, String> {
    if v.is_finite() && v >= 0.0 {
        Ok(v)
    } else {
        Err(format!("invalid {what}: {v}"))
    }
}

/// Parse a CPU quantity to whole cores: `"1"` → 1.0, `"500m"` → 0.5.
pub fn cpu_cores(s: &str) -> Result<f64, String> {
    let s = s.trim();
    let v = if let Some(milli) = s.strip_suffix('m') {
        milli
            .parse::<f64>()
            .map(|m| m / 1000.0)
            .map_err(|_| format!("invalid cpu {s:?}"))?
    } else {
        s.parse::<f64>().map_err(|_| format!("invalid cpu {s:?}"))?
    };
    finite_nonneg(v, "cpu")
}

/// Parse a memory quantity to GiB. Supports Ki/Mi/Gi/Ti (binary) and
/// K/M/G/T (decimal); a bare number is bytes.
pub fn mem_gib(s: &str) -> Result<f64, String> {
    let s = s.trim();
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let (num, bytes_per) = if let Some(n) = s.strip_suffix("Ki") {
        (n, 1024.0)
    } else if let Some(n) = s.strip_suffix("Mi") {
        (n, 1024.0 * 1024.0)
    } else if let Some(n) = s.strip_suffix("Gi") {
        (n, GIB)
    } else if let Some(n) = s.strip_suffix("Ti") {
        (n, GIB * 1024.0)
    } else if let Some(n) = s.strip_suffix('K') {
        (n, 1_000.0)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1_000_000.0)
    } else if let Some(n) = s.strip_suffix('G') {
        (n, 1_000_000_000.0)
    } else if let Some(n) = s.strip_suffix('T') {
        (n, 1_000_000_000_000.0)
    } else {
        (s, 1.0)
    };
    let v = num
        .trim()
        .parse::<f64>()
        .map(|v| v * bytes_per / GIB)
        .map_err(|_| format!("invalid memory {s:?}"))?;
    finite_nonneg(v, "memory")
}

/// Parse a GPU count (optional field). `None`/empty → 0.
pub fn gpu_count(s: Option<&str>) -> Result<f64, String> {
    match s {
        None | Some("") => Ok(0.0),
        Some(v) => {
            let n = v
                .trim()
                .parse::<f64>()
                .map_err(|_| format!("invalid gpu {v:?}"))?;
            finite_nonneg(n, "gpu")
        }
    }
}

/// Parse an arbitrary Kubernetes quantity to a bare number (ADR-0010: pool
/// flavors quota any resource name, so no resource-specific unit
/// conversion). Binary suffixes (`Ki`…`Ei`) multiply by 1024ⁿ, decimal
/// suffixes (`n`, `u`, `m`, `k`, `M`…`E`) by 10ⁿ; a bare number (including
/// exponent notation, via f64 parsing) is its own value. Unlike
/// [`mem_gib`], a bare number is NOT treated as bytes — pool quantities
/// are counts of whatever the resource key measures.
pub fn parse_quantity(s: &str) -> Result<f64, String> {
    let s = s.trim();
    const KI: f64 = 1024.0;
    let (num, mult) = if let Some(n) = s.strip_suffix("Ki") {
        (n, KI)
    } else if let Some(n) = s.strip_suffix("Mi") {
        (n, KI.powi(2))
    } else if let Some(n) = s.strip_suffix("Gi") {
        (n, KI.powi(3))
    } else if let Some(n) = s.strip_suffix("Ti") {
        (n, KI.powi(4))
    } else if let Some(n) = s.strip_suffix("Pi") {
        (n, KI.powi(5))
    } else if let Some(n) = s.strip_suffix("Ei") {
        (n, KI.powi(6))
    } else if let Some(n) = s.strip_suffix('n') {
        (n, 1e-9)
    } else if let Some(n) = s.strip_suffix('u') {
        (n, 1e-6)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 1e-3)
    } else if let Some(n) = s.strip_suffix('k') {
        (n, 1e3)
    } else if let Some(n) = s.strip_suffix('M') {
        (n, 1e6)
    } else if let Some(n) = s.strip_suffix('G') {
        (n, 1e9)
    } else if let Some(n) = s.strip_suffix('T') {
        (n, 1e12)
    } else if let Some(n) = s.strip_suffix('P') {
        (n, 1e15)
    } else if let Some(n) = s.strip_suffix('E') {
        (n, 1e18)
    } else {
        (s, 1.0)
    };
    let v = num
        .trim()
        .parse::<f64>()
        .map(|v| v * mult)
        .map_err(|_| format!("invalid quantity {s:?}"))?;
    finite_nonneg(v, "quantity")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu() {
        assert_eq!(cpu_cores("1").unwrap(), 1.0);
        assert_eq!(cpu_cores("500m").unwrap(), 0.5);
        assert_eq!(cpu_cores("2").unwrap(), 2.0);
        assert!(cpu_cores("abc").is_err());
    }

    #[test]
    fn memory() {
        assert_eq!(mem_gib("2Gi").unwrap(), 2.0);
        assert_eq!(mem_gib("512Mi").unwrap(), 0.5);
        assert_eq!(mem_gib("1Ti").unwrap(), 1024.0);
        assert!((mem_gib("1G").unwrap() - 0.9313).abs() < 0.001); // decimal GB → GiB
        assert!(mem_gib("nope").is_err());
    }

    #[test]
    fn gpu() {
        assert_eq!(gpu_count(None).unwrap(), 0.0);
        assert_eq!(gpu_count(Some("2")).unwrap(), 2.0);
        assert!(gpu_count(Some("x")).is_err());
    }

    #[test]
    fn general_quantity() {
        assert_eq!(parse_quantity("64").unwrap(), 64.0);
        assert_eq!(parse_quantity("500m").unwrap(), 0.5);
        assert_eq!(parse_quantity("512Mi").unwrap(), 512.0 * 1024.0 * 1024.0);
        assert_eq!(parse_quantity("1Gi").unwrap(), 1073741824.0);
        assert_eq!(parse_quantity("2k").unwrap(), 2000.0);
        assert_eq!(parse_quantity("1.5").unwrap(), 1.5);
        assert!(parse_quantity("banana").is_err());
        assert!(parse_quantity("").is_err());
        assert!(parse_quantity("-3").is_err());
    }

    #[test]
    fn memory_suffixes_binary_and_decimal() {
        assert_eq!(mem_gib("1024Ki").unwrap(), 1024.0 * 1024.0 / GIB);
        assert_eq!(mem_gib("1000K").unwrap(), 1_000_000.0 / GIB);
        assert_eq!(mem_gib("1M").unwrap(), 1_000_000.0 / GIB);
        assert_eq!(mem_gib("1T").unwrap(), 1_000_000_000_000.0 / GIB);
        // A bare number is bytes.
        assert_eq!(mem_gib("1073741824").unwrap(), 1.0);
        // Surrounding whitespace is tolerated.
        assert_eq!(mem_gib(" 2Gi ").unwrap(), 2.0);
        // Negative and non-finite amounts are rejected.
        assert!(mem_gib("-1Gi").is_err());
        assert!(mem_gib("NaN").is_err());
    }

    #[test]
    fn cpu_rejects_negative_and_non_finite() {
        assert!(cpu_cores("-1").is_err());
        assert!(cpu_cores("-500m").is_err());
        assert!(cpu_cores("inf").is_err());
        assert!(cpu_cores("2xm").is_err());
    }

    #[test]
    fn gpu_rejects_negative() {
        assert_eq!(gpu_count(Some("")).unwrap(), 0.0);
        assert!(gpu_count(Some("-1")).is_err());
    }

    #[test]
    fn quantity_full_suffix_table() {
        // Binary suffixes multiply by 1024^n.
        assert_eq!(parse_quantity("1Ki").unwrap(), 1024.0);
        assert_eq!(parse_quantity("1Ti").unwrap(), 1024.0_f64.powi(4));
        assert_eq!(parse_quantity("1Pi").unwrap(), 1024.0_f64.powi(5));
        assert_eq!(parse_quantity("1Ei").unwrap(), 1024.0_f64.powi(6));
        // Decimal suffixes multiply by 10^n, sub-unit by 10^-n.
        assert_eq!(parse_quantity("1M").unwrap(), 1e6);
        assert_eq!(parse_quantity("1G").unwrap(), 1e9);
        assert_eq!(parse_quantity("1T").unwrap(), 1e12);
        assert_eq!(parse_quantity("1P").unwrap(), 1e15);
        assert_eq!(parse_quantity("1E").unwrap(), 1e18);
        assert_eq!(parse_quantity("5n").unwrap(), 5e-9);
        assert!((parse_quantity("5u").unwrap() - 5e-6).abs() < 1e-12);
        // Exponent notation on a bare number parses via f64.
        assert_eq!(parse_quantity("1e3").unwrap(), 1000.0);
        // Negative and non-finite quantities are rejected.
        assert!(parse_quantity("-1G").is_err());
        assert!(parse_quantity("inf").is_err());
    }

    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
}
