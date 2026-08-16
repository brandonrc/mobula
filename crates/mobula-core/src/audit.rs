//! Audit event model (api-v1.md §5.9).
//!
//! Every security-relevant decision and mutation in the control plane emits
//! one `AuditEvent`. Events dual-write: the `mobula::audit` tracing target
//! (optionally exported to JSONL via `--audit-log`) and, when a store is
//! configured, the `audit_events` table behind `Store::record_audit`, read
//! back by `GET /api/v1/audit` through [`AuditFilter`].
//!
//! Wire conventions follow api-v1.md §2.1: snake_case serde defaults, unix
//! seconds for `ts`, and `Option` fields always present as `null` when the
//! emitting site has no value — missing context is never invented
//! (e.g. authn failures have no `subject`; pool mutations have no `cluster`).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Whether Mobula allowed or refused the thing the event describes.
/// Serialized snake_case (`allow` / `deny`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    #[default]
    Allow,
    Deny,
}

impl AuditDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditDecision::Allow => "allow",
            AuditDecision::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(AuditDecision::Allow),
            "deny" => Some(AuditDecision::Deny),
            _ => None,
        }
    }
}

/// The (verb, target) permission an authorization decision was checked
/// against — mirrors `mobula_auth::{PermissionType, Target}` as lowercase
/// strings (`"write"`, `"cluster"`) so core stays free of auth types.
/// Present only on authz denials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditRequired {
    /// e.g. "read" | "write" | "delete" | "admin".
    pub action: String,
    /// e.g. "job" | "cluster" | "service" | "pool".
    pub target: String,
}

/// One audit-trail row (api-v1.md §5.9). Fields not applicable to the
/// emitting site are `None` (serialized `null`); `granted_roles` is empty.
///
/// Decision policy (mobula-api `audit` module): `deny` rows are emitted at
/// the point of refusal (authn failures, authz denials, quota denials);
/// gateway per-request rows are always `allow` — a request Mobula refuses
/// never reaches the gateway, so its `deny` row comes from the refuser.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AuditEvent {
    /// Unix seconds.
    pub ts: u64,
    /// Authenticated subject; `null` for authn failures (no identity yet).
    pub subject: Option<String>,
    pub decision: AuditDecision,
    /// Machine-readable refusal reason (`missing_token`, `invalid_token`,
    /// `insufficient_permission`, `quota_exceeded`); `null` on allows.
    pub reason: Option<String>,
    /// Control-plane mutation (`create_cluster`, `delete_pool`, …);
    /// `null` on gateway rows.
    pub action: Option<String>,
    /// Cluster id the event concerns; `null` when not cluster-scoped.
    pub cluster: Option<String>,
    /// HTTP method, for gateway and authn/ext_authz rows.
    pub method: Option<String>,
    /// Request path (no query string).
    pub path: Option<String>,
    /// HTTP status of the outcome, when one is known.
    pub status: Option<u16>,
    /// Gateway upstream round-trip; `null` elsewhere.
    pub latency_ms: Option<u64>,
    /// The permission an authz denial was checked against.
    pub required: Option<AuditRequired>,
    /// Roles the caller held (snake_case); authz denials only, else `[]`.
    #[serde(default)]
    pub granted_roles: Vec<String>,
}

/// Filter for `Store::list_audit`, mirroring the `GET /api/v1/audit` query
/// params. All present conditions are ANDed; `from`/`to` are inclusive unix
/// seconds bounds on `ts`.
///
/// Pagination is deliberately dead simple: rows come back newest-first by
/// their autoincrement `seq`; `cursor` means "only rows with `seq` strictly
/// before this value"; the store returns `next_cursor = Some(seq)` of the
/// oldest returned row when more rows exist beyond the page.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Page size; [`AuditFilter::DEFAULT_LIMIT`] when absent, clamped to
    /// [`AuditFilter::MAX_LIMIT`].
    pub limit: Option<u32>,
    /// Only rows with `seq < cursor`.
    pub cursor: Option<u64>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub subject: Option<String>,
    pub cluster: Option<String>,
    pub method: Option<String>,
    pub path_prefix: Option<String>,
    pub min_status: Option<u16>,
    pub decision: Option<AuditDecision>,
    pub reason: Option<String>,
}

impl AuditFilter {
    pub const DEFAULT_LIMIT: u32 = 100;
    pub const MAX_LIMIT: u32 = 1000;

    /// The page size a store applies: the requested limit or the default,
    /// clamped into `[1, MAX_LIMIT]`.
    pub fn effective_limit(&self) -> u32 {
        self.limit
            .unwrap_or(Self::DEFAULT_LIMIT)
            .clamp(1, Self::MAX_LIMIT)
    }

    /// Whether an event matches the filter's non-pagination conditions
    /// (everything except `limit`/`cursor`). Shared by the in-memory store
    /// so it stays behaviourally identical to the SQL `WHERE` clause in the
    /// SQLite implementation (conformance suite).
    pub fn matches(&self, event: &AuditEvent) -> bool {
        self.from.is_none_or(|from| event.ts >= from)
            && self.to.is_none_or(|to| event.ts <= to)
            && self
                .subject
                .as_deref()
                .is_none_or(|s| event.subject.as_deref() == Some(s))
            && self
                .cluster
                .as_deref()
                .is_none_or(|c| event.cluster.as_deref() == Some(c))
            && self
                .method
                .as_deref()
                .is_none_or(|m| event.method.as_deref() == Some(m))
            && self.path_prefix.as_deref().is_none_or(|p| {
                event
                    .path
                    .as_deref()
                    .is_some_and(|path| path.starts_with(p))
            })
            && self
                .min_status
                .is_none_or(|min| event.status.is_some_and(|s| s >= min))
            && self.decision.is_none_or(|d| event.decision == d)
            && self
                .reason
                .as_deref()
                .is_none_or(|r| event.reason.as_deref() == Some(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_round_trips_snake_case() {
        for d in [AuditDecision::Allow, AuditDecision::Deny] {
            assert_eq!(AuditDecision::parse(d.as_str()), Some(d));
            assert_eq!(
                serde_json::to_string(&d).unwrap(),
                format!("\"{d:?}\"").to_lowercase()
            );
        }
        assert_eq!(AuditDecision::parse("bogus"), None);
    }

    #[test]
    fn option_fields_serialize_null_present() {
        let event = AuditEvent {
            ts: 1_755_280_000,
            decision: AuditDecision::Deny,
            ..Default::default()
        };
        let v = serde_json::to_value(&event).unwrap();
        for field in [
            "subject",
            "reason",
            "action",
            "cluster",
            "method",
            "path",
            "status",
            "latency_ms",
            "required",
        ] {
            assert!(v[field].is_null(), "{field} must be present as null");
        }
        assert_eq!(v["granted_roles"], serde_json::json!([]));
        assert_eq!(v["decision"], "deny");
    }

    #[test]
    fn effective_limit_defaults_and_clamps() {
        assert_eq!(AuditFilter::default().effective_limit(), 100);
        assert_eq!(
            AuditFilter {
                limit: Some(0),
                ..Default::default()
            }
            .effective_limit(),
            1
        );
        assert_eq!(
            AuditFilter {
                limit: Some(10_000),
                ..Default::default()
            }
            .effective_limit(),
            1000
        );
    }

    #[test]
    fn matches_applies_each_condition() {
        let event = AuditEvent {
            ts: 100,
            subject: Some("u1".into()),
            decision: AuditDecision::Deny,
            reason: Some("insufficient_permission".into()),
            cluster: Some("demo".into()),
            method: Some("GET".into()),
            path: Some("/api/jobs/abc".into()),
            status: Some(403),
            ..Default::default()
        };
        let yes = |f: AuditFilter| f.matches(&event);
        assert!(yes(AuditFilter::default()));
        assert!(yes(AuditFilter {
            from: Some(100),
            to: Some(100),
            ..Default::default()
        }));
        assert!(!yes(AuditFilter {
            from: Some(101),
            ..Default::default()
        }));
        assert!(!yes(AuditFilter {
            to: Some(99),
            ..Default::default()
        }));
        assert!(yes(AuditFilter {
            path_prefix: Some("/api/jobs".into()),
            ..Default::default()
        }));
        assert!(!yes(AuditFilter {
            path_prefix: Some("/api/v1".into()),
            ..Default::default()
        }));
        assert!(!yes(AuditFilter {
            min_status: Some(500),
            ..Default::default()
        }));
        assert!(!yes(AuditFilter {
            subject: Some("other".into()),
            ..Default::default()
        }));
        // A filter on a field the event lacks never matches.
        let no_subject = AuditEvent::default();
        assert!(!AuditFilter {
            subject: Some("u1".into()),
            ..Default::default()
        }
        .matches(&no_subject));
    }
}
