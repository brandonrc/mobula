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
    /// Name of the environment variable to read the auth token from at
    /// load time — secret indirection so the registry file holds no
    /// plaintext credential (compliance issue #57). Mutually exclusive
    /// with `auth_token`; unlike the token, the name is not a secret and
    /// may serialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token_env: Option<String>,
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
            .field("auth_token_env", &self.auth_token_env)
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
    #[error(
        "cluster {0}: both auth_token and auth_token_env are set — exactly one token \
         source is allowed (issue #57)"
    )]
    ConflictingTokenSource(String),
    #[error(
        "cluster {id}: auth_token_env {var:?} is unset or empty — refusing to start \
         with a missing cluster credential"
    )]
    MissingTokenEnv { id: String, var: String },
}

/// Where a registry entry's southbound token comes from — surfaced as
/// startup log lines (#57). Carries names (cluster id, env var) only,
/// never token values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSourceNote {
    /// Plaintext token sitting in the registry file — works, but should
    /// move to `auth_token_env`.
    Plaintext { id: String },
    /// Token is read from the named environment variable at load time.
    Env { id: String, var: String },
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

    /// Resolve `auth_token_env` indirections into `auth_token` at load
    /// time (issue #57): each entry naming an env var has the token read
    /// from the process environment, so downstream gateway code sees one
    /// in-memory shape. Fails fast on a missing/empty variable, naming
    /// the cluster and the variable — never a value. An entry setting
    /// both token sources is rejected. `auth_token_env` is kept set
    /// afterwards as provenance (it names the source; it is not a
    /// secret).
    pub fn resolve_auth_tokens(&mut self) -> Result<(), RegistryError> {
        for c in &mut self.clusters {
            if c.auth_token.is_some() && c.auth_token_env.is_some() {
                return Err(RegistryError::ConflictingTokenSource(c.id.0.clone()));
            }
            if let Some(var) = c.auth_token_env.clone() {
                match std::env::var(&var) {
                    Ok(token) if !token.is_empty() => c.auth_token = Some(token),
                    _ => {
                        return Err(RegistryError::MissingTokenEnv {
                            id: c.id.0.clone(),
                            var,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Per-entry token-source notes for startup logging (#57): plaintext
    /// entries get a nudge toward `auth_token_env`, env-sourced entries
    /// are acknowledged. Names only — never values.
    pub fn token_source_notes(&self) -> Vec<TokenSourceNote> {
        self.clusters
            .iter()
            .filter_map(|c| {
                if let Some(var) = &c.auth_token_env {
                    Some(TokenSourceNote::Env {
                        id: c.id.0.clone(),
                        var: var.clone(),
                    })
                } else if c.auth_token.is_some() {
                    Some(TokenSourceNote::Plaintext { id: c.id.0.clone() })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Validate the registry as security-sensitive input (issues #2/#8):
    /// duplicate hostnames/ids fail fast (first-match-wins misrouting),
    /// URLs are scheme-restricted with no userinfo/fragment, literal-IP
    /// hosts in link-local/CGNAT ranges are refused (SSRF: cloud metadata
    /// endpoints, overlay meshes), and a static token over cleartext http
    /// is rejected unless explicitly overridden.
    ///
    /// Residual risk: DNS-named `api_base_url`s pass unchecked — resolving
    /// them at validation can't defeat DNS rebinding, so name-based SSRF
    /// screening is accepted as out of scope. Only literal IPs are denied.
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
            // SSRF posture (#2): literal IPs in link-local/CGNAT ranges
            // never name a Ray head — they name cloud metadata endpoints
            // (169.254.169.254) or overlay meshes. DNS names pass through
            // (see validate's doc comment for the residual risk).
            if let Ok(ip) = authority_host(authority).parse::<std::net::IpAddr>() {
                if is_denied_southbound_ip(ip) {
                    return Err(invalid(
                        "literal IP in a link-local/CGNAT range (169.254.0.0/16, \
                         100.64.0.0/10, fe80::/10) is not a cluster endpoint",
                    ));
                }
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

/// Extract the host portion of a URL authority: `[fe80::1]:8265` yields
/// `fe80::1`, `host:8265` yields `host`, `host` yields `host`. Userinfo is
/// already rejected by validation before this runs.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    authority.split(':').next().unwrap_or(authority)
}

/// Literal-IP denylist for southbound `api_base_url`s (issue #2 remainder):
/// link-local and CGNAT ranges never name a Ray head — they name cloud
/// metadata endpoints (169.254.169.254) or overlay meshes (Tailscale etc.).
/// Computed from octets rather than the std `is_*` helpers so the ranges
/// are explicit and stable across toolchains.
fn is_denied_southbound_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // 169.254.0.0/16 link-local (includes cloud metadata 169.254.169.254)
            (o[0] == 169 && o[1] == 254)
                // 100.64.0.0/10 CGNAT / overlay meshes
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        // fe80::/10 link-local
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
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
                auth_token_env: None,
            }],
        }
    }

    fn endpoint(id: &str) -> ClusterEndpoint {
        ClusterEndpoint {
            id: ClusterId(id.into()),
            hostname: format!("{id}.ray.example.com"),
            api_base_url: "https://demo-head-svc:8265".into(),
            auth_token: None,
            auth_token_env: None,
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
                auth_token_env: None,
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
            auth_token_env: None,
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
            auth_token_env: None,
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
    fn validate_rejects_link_local_and_cgnat_literal_ips() {
        // #2: cloud metadata endpoints and overlay meshes must never be
        // registered as cluster heads.
        for url in [
            "http://169.254.169.254:8265",
            "https://169.254.0.1",
            "http://100.64.0.1:8265",
            "http://100.127.255.254",
            "http://[fe80::1]:8265",
            "http://[febf::ffff]:8265",
        ] {
            let mut bad = registry();
            bad.clusters[0].api_base_url = url.into();
            bad.clusters[0].auth_token = None;
            assert!(
                matches!(bad.validate(true), Err(RegistryError::InvalidUrl { .. })),
                "{url} should be rejected"
            );
        }
        // Ordinary private/loopback IPs (in-cluster heads, dev setups) and
        // DNS names (residual risk, documented on validate) still pass.
        for url in [
            "http://10.0.0.5:8265",
            "http://127.0.0.1:8265",
            "http://100.63.255.255:8265",
            "https://[fd00::1]:8265",
            "http://demo-head-svc:8265",
        ] {
            let mut ok = registry();
            ok.clusters[0].api_base_url = url.into();
            ok.clusters[0].auth_token = None;
            assert!(ok.validate(false).is_ok(), "{url} should pass");
        }
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

    #[test]
    fn auth_token_env_serializes_but_token_never_does() {
        // #57: the env var NAME is not a secret and may serialize; the
        // token itself must not, even when env-sourced.
        let mut r = ClusterRegistry {
            clusters: vec![{
                let mut e = endpoint("demo");
                e.auth_token_env = Some("DEMO_RAY_TOKEN".into());
                e
            }],
        };
        std::env::set_var("DEMO_RAY_TOKEN", "env-secret");
        r.resolve_auth_tokens().unwrap();
        std::env::remove_var("DEMO_RAY_TOKEN");

        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("auth_token_env"), "{json}");
        assert!(json.contains("DEMO_RAY_TOKEN"), "{json}");
        assert!(!json.contains("env-secret"), "{json}");
    }

    #[test]
    fn resolve_auth_tokens_reads_env_into_auth_token() {
        let mut r = ClusterRegistry {
            clusters: vec![{
                let mut e = endpoint("demo");
                e.auth_token_env = Some("MOBULA_CORE_TEST_TOKEN_OK".into());
                e
            }],
        };
        std::env::set_var("MOBULA_CORE_TEST_TOKEN_OK", "resolved-secret");
        r.resolve_auth_tokens().unwrap();
        std::env::remove_var("MOBULA_CORE_TEST_TOKEN_OK");
        // In-memory shape is unchanged: the gateway reads the resolved
        // token from `auth_token`; the env name stays as provenance.
        assert_eq!(r.clusters[0].auth_token.as_deref(), Some("resolved-secret"));
        assert_eq!(
            r.clusters[0].auth_token_env.as_deref(),
            Some("MOBULA_CORE_TEST_TOKEN_OK")
        );
    }

    #[test]
    fn resolve_auth_tokens_fails_fast_on_missing_or_empty_env() {
        for value in [None, Some("")] {
            let mut r = ClusterRegistry {
                clusters: vec![{
                    let mut e = endpoint("demo");
                    e.auth_token_env = Some("MOBULA_CORE_TEST_TOKEN_MISSING".into());
                    e
                }],
            };
            match value {
                Some(v) => std::env::set_var("MOBULA_CORE_TEST_TOKEN_MISSING", v),
                None => std::env::remove_var("MOBULA_CORE_TEST_TOKEN_MISSING"),
            }
            let err = r.resolve_auth_tokens().unwrap_err();
            std::env::remove_var("MOBULA_CORE_TEST_TOKEN_MISSING");
            assert_eq!(
                err,
                RegistryError::MissingTokenEnv {
                    id: "demo".into(),
                    var: "MOBULA_CORE_TEST_TOKEN_MISSING".into(),
                }
            );
            let msg = err.to_string();
            assert!(msg.contains("demo") && msg.contains("MOBULA_CORE_TEST_TOKEN_MISSING"));
        }
    }

    #[test]
    fn resolve_auth_tokens_rejects_both_token_sources() {
        let mut r = registry(); // plaintext token
        r.clusters[0].auth_token_env = Some("SOME_VAR".into());
        assert_eq!(
            r.resolve_auth_tokens().unwrap_err(),
            RegistryError::ConflictingTokenSource("demo".into())
        );
    }

    #[test]
    fn token_source_notes_flag_plaintext_and_acknowledge_env() {
        let r = registry(); // plaintext token
        assert_eq!(
            r.token_source_notes(),
            vec![TokenSourceNote::Plaintext { id: "demo".into() }]
        );

        let mut env_entry = endpoint("envdemo");
        env_entry.auth_token_env = Some("ENVDEMO_RAY_TOKEN".into());
        let r = ClusterRegistry {
            clusters: vec![env_entry],
        };
        assert_eq!(
            r.token_source_notes(),
            vec![TokenSourceNote::Env {
                id: "envdemo".into(),
                var: "ENVDEMO_RAY_TOKEN".into(),
            }]
        );

        // Tokenless entries produce no note.
        assert!(ClusterRegistry {
            clusters: vec![endpoint("bare")],
        }
        .token_source_notes()
        .is_empty());
    }
}
