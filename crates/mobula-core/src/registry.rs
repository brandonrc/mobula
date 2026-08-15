use serde::{Deserialize, Serialize};

use crate::ClusterId;

/// A cluster the job gateway can route to.
///
/// One hostname per cluster: the stock `ray job submit` client hits fixed
/// root paths (`/api/jobs/`, `/api/packages/…`) on its `--address`, so the
/// cluster identity must live in the host, not the path (ADR-0002).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterEndpoint {
    pub id: ClusterId,
    /// Hostname (without port) at which the gateway exposes this cluster.
    pub hostname: String,
    /// Base URL of the cluster's native Ray dashboard/job API, reachable
    /// from the control plane only.
    pub api_base_url: String,
    /// Static Ray auth token (Ray >= 2.52). The gateway injects it
    /// southbound; users never see it (ADR-0003). Excluded from
    /// serialization so it can't leak through API responses.
    #[serde(default, skip_serializing)]
    pub auth_token: Option<String>,
}

/// Static cluster registry — the Phase 1 stand-in for the Phase 3
/// lifecycle controller's dynamic view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterRegistry {
    #[serde(default)]
    pub clusters: Vec<ClusterEndpoint>,
}

impl ClusterRegistry {
    /// Look up a cluster by request Host header value. Ports are ignored
    /// and matching is case-insensitive, per RFC 9110 host semantics.
    pub fn by_hostname(&self, host: &str) -> Option<&ClusterEndpoint> {
        let host = strip_port(host);
        self.clusters
            .iter()
            .find(|c| c.hostname.eq_ignore_ascii_case(host))
    }

    pub fn by_id(&self, id: &ClusterId) -> Option<&ClusterEndpoint> {
        self.clusters.iter().find(|c| &c.id == id)
    }
}

/// Drop a `:port` suffix from a Host header value. Bracketed IPv6 hosts
/// (`[::1]:8080`) yield the literal inside the brackets; unbracketed
/// multi-colon strings are IPv6 literals with no port to strip.
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    if host.bytes().filter(|&b| b == b':').count() == 1 {
        if let Some((h, port)) = host.rsplit_once(':') {
            if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                return h;
            }
        }
    }
    host
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ClusterRegistry {
        ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("demo".into()),
                hostname: "demo.ray.example.com".into(),
                api_base_url: "http://demo-head-svc:8265".into(),
                auth_token: Some("secret".into()),
            }],
        }
    }

    #[test]
    fn hostname_lookup_ignores_port_and_case() {
        let r = registry();
        assert!(r.by_hostname("demo.ray.example.com").is_some());
        assert!(r.by_hostname("DEMO.ray.Example.com:8484").is_some());
        assert!(r.by_hostname("other.example.com").is_none());
    }

    #[test]
    fn lookup_by_id() {
        let r = registry();
        assert!(r.by_id(&ClusterId("demo".into())).is_some());
        assert!(r.by_id(&ClusterId("nope".into())).is_none());
    }

    #[test]
    fn ipv6_hosts_are_not_mangled_by_port_stripping() {
        // An unbracketed IPv6 literal's last segment is not a port.
        let r = ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("v6".into()),
                hostname: "fe80::1".into(),
                api_base_url: "http://[fe80::1]:8265".into(),
                auth_token: None,
            }],
        };
        assert!(r.by_hostname("fe80::1").is_some());
        assert!(r.by_hostname("[fe80::1]:8484").is_some());
        assert!(r.by_hostname("fe80::2").is_none());
    }

    #[test]
    fn strip_port_edge_cases() {
        assert_eq!(strip_port("example.com:8080"), "example.com");
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("example.com:"), "example.com:");
        assert_eq!(strip_port("example.com:8a"), "example.com:8a");
        assert_eq!(strip_port("[::1]:9000"), "::1");
        assert_eq!(strip_port("[::1]"), "::1");
        assert_eq!(strip_port("fe80::1"), "fe80::1");
        assert_eq!(strip_port("127.0.0.1:8484"), "127.0.0.1");
    }

    #[test]
    fn auth_token_never_serializes() {
        let json = serde_json::to_string(&registry()).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("auth_token"));
    }
}
