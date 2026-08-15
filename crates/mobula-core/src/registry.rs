use serde::{Deserialize, Serialize};

use crate::ClusterId;

/// A cluster the job gateway can route to.
///
/// One hostname per cluster: the stock `ray job submit` client hits fixed
/// root paths (`/api/jobs/`, `/api/packages/…`) on its `--address`, so the
/// cluster identity must live in the host, not the path (ADR-0002).
#[derive(Clone, Serialize, Deserialize)]
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

// Manual Debug: the auth token must never reach logs via `{:?}` — the
// serde skip protects API responses, this protects tracing/panic output
// (security issue #4).
impl std::fmt::Debug for ClusterEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterEndpoint")
            .field("id", &self.id)
            .field("hostname", &self.hostname)
            .field("api_base_url", &self.api_base_url)
            .field(
                "auth_token",
                &self.auth_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Static cluster registry — the Phase 1 stand-in for the Phase 3
/// lifecycle controller's dynamic view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterRegistry {
    #[serde(default)]
    pub clusters: Vec<ClusterEndpoint>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("duplicate hostname {0:?}: first match wins would silently misroute credentials")]
    DuplicateHostname(String),
    #[error("duplicate cluster id {0:?}")]
    DuplicateId(String),
    #[error("cluster {id}: invalid api_base_url {url:?}: {reason}")]
    InvalidUrl {
        id: String,
        url: String,
        reason: &'static str,
    },
    #[error(
        "cluster {0}: auth_token over cleartext http:// — refusing to ship a static \
         cluster credential unencrypted (use https, or pass an explicit insecure-transport \
         override for local dev)"
    )]
    CleartextToken(String),
    #[error("cluster {id}: invalid hostname {hostname:?}")]
    InvalidHostname { id: String, hostname: String },
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

    /// Validate the registry as security-sensitive input (issues #2/#8):
    /// duplicate hostnames/ids fail fast (first-match-wins misrouting),
    /// URLs are scheme-restricted with no userinfo/fragment, and a static
    /// token over cleartext http is rejected unless explicitly overridden.
    pub fn validate(&self, allow_insecure_transport: bool) -> Result<(), RegistryError> {
        let mut hostnames = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        for c in &self.clusters {
            if !ids.insert(c.id.0.to_ascii_lowercase()) {
                return Err(RegistryError::DuplicateId(c.id.0.clone()));
            }
            if !hostnames.insert(c.hostname.to_ascii_lowercase()) {
                return Err(RegistryError::DuplicateHostname(c.hostname.clone()));
            }
            if c.hostname.is_empty()
                || c.hostname
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch == '/' || ch == '@' || ch == '#')
            {
                return Err(RegistryError::InvalidHostname {
                    id: c.id.0.clone(),
                    hostname: c.hostname.clone(),
                });
            }

            let is_https = c.api_base_url.starts_with("https://");
            let is_http = c.api_base_url.starts_with("http://");
            let invalid = |reason| RegistryError::InvalidUrl {
                id: c.id.0.clone(),
                url: c.api_base_url.clone(),
                reason,
            };
            if !is_https && !is_http {
                return Err(invalid("scheme must be http or https"));
            }
            let rest = c
                .api_base_url
                .split_once("://")
                .map(|(_, r)| r)
                .unwrap_or("");
            let authority = rest.split('/').next().unwrap_or("");
            if authority.is_empty() {
                return Err(invalid("missing host"));
            }
            if authority.contains('@') {
                return Err(invalid("userinfo not allowed"));
            }
            if c.api_base_url.contains('#') {
                return Err(invalid("fragment not allowed"));
            }
            if c.auth_token.is_some() && is_http && !allow_insecure_transport {
                return Err(RegistryError::CleartextToken(c.id.0.clone()));
            }
        }
        Ok(())
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
    fn debug_redacts_auth_token() {
        let printed = format!("{:?}", registry());
        assert!(!printed.contains("secret"), "{printed}");
        assert!(printed.contains("[REDACTED]"));
    }

    #[test]
    fn validate_accepts_good_registry_and_rejects_cleartext_token() {
        let r = registry(); // http:// + token
        assert!(matches!(
            r.validate(false),
            Err(RegistryError::CleartextToken(_))
        ));
        assert!(r.validate(true).is_ok(), "dev override permits http+token");

        let mut https = registry();
        https.clusters[0].api_base_url = "https://demo-head-svc:8265".into();
        assert!(https.validate(false).is_ok());
    }

    #[test]
    fn validate_rejects_duplicates_and_bad_urls() {
        let mut dup = registry();
        dup.clusters.push(ClusterEndpoint {
            id: ClusterId("other".into()),
            hostname: "DEMO.ray.example.com".into(), // case-insensitive dup
            api_base_url: "https://x:1".into(),
            auth_token: None,
        });
        assert!(matches!(
            dup.validate(true),
            Err(RegistryError::DuplicateHostname(_))
        ));

        let mut dup_id = registry();
        dup_id.clusters.push(ClusterEndpoint {
            id: ClusterId("demo".into()),
            hostname: "other.example.com".into(),
            api_base_url: "https://x:1".into(),
            auth_token: None,
        });
        assert!(matches!(
            dup_id.validate(true),
            Err(RegistryError::DuplicateId(_))
        ));

        for (url, _why) in [
            ("ftp://host:1", "scheme"),
            ("https://user:pw@host:1", "userinfo"),
            ("https://host/x#frag", "fragment"),
            ("https://", "missing host"),
            ("not-a-url", "scheme"),
        ] {
            let mut bad = registry();
            bad.clusters[0].api_base_url = url.into();
            assert!(
                matches!(bad.validate(true), Err(RegistryError::InvalidUrl { .. })),
                "{url} should be rejected"
            );
        }

        let mut bad_host = registry();
        bad_host.clusters[0].hostname = "demo host".into();
        assert!(matches!(
            bad_host.validate(true),
            Err(RegistryError::InvalidHostname { .. })
        ));
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
