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
        let host = host.rsplit_once(':').map_or(host, |(h, port)| {
            // Only strip a real port suffix; an IPv6 literal's last colon
            // segment is not a port unless bracketed.
            if port.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                host
            }
        });
        self.clusters
            .iter()
            .find(|c| c.hostname.eq_ignore_ascii_case(host))
    }

    pub fn by_id(&self, id: &ClusterId) -> Option<&ClusterEndpoint> {
        self.clusters.iter().find(|c| &c.id == id)
    }
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
    fn auth_token_never_serializes() {
        let json = serde_json::to_string(&registry()).unwrap();
        assert!(!json.contains("secret"));
        assert!(!json.contains("auth_token"));
    }
}
