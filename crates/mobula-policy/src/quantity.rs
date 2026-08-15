//! Minimal Kubernetes quantity parsing for CPU and memory strings.

/// Parse a CPU quantity to whole cores: `"1"` → 1.0, `"500m"` → 0.5.
pub fn cpu_cores(s: &str) -> Result<f64, String> {
    let s = s.trim();
    if let Some(milli) = s.strip_suffix('m') {
        milli
            .parse::<f64>()
            .map(|m| m / 1000.0)
            .map_err(|_| format!("invalid cpu {s:?}"))
    } else {
        s.parse::<f64>().map_err(|_| format!("invalid cpu {s:?}"))
    }
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
    num.trim()
        .parse::<f64>()
        .map(|v| v * bytes_per / GIB)
        .map_err(|_| format!("invalid memory {s:?}"))
}

/// Parse a GPU count (optional field). `None`/empty → 0.
pub fn gpu_count(s: Option<&str>) -> Result<f64, String> {
    match s {
        None | Some("") => Ok(0.0),
        Some(v) => v
            .trim()
            .parse::<f64>()
            .map_err(|_| format!("invalid gpu {v:?}")),
    }
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
}
