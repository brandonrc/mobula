//! Persisted audit trail (api-v1.md §5.9).
//!
//! Every audit-emitting site goes through [`emit`], which dual-writes: the
//! event is traced on the `mobula::audit` target (so the `--audit-log`
//! JSONL export keeps working) and, when a store is configured, appended to
//! the store. The store write is awaited (events are small) but a failure
//! logs a warning and NEVER fails the request being audited.
//!
//! Field policy — missing context is `None`/`[]`, never invented:
//! - authn failures (missing/invalid token) have no `subject`;
//! - gateway per-request rows carry `cluster`/`method`/`path`/`status`/
//!   `latency_ms` but no `action`/`reason`;
//! - `required`/`granted_roles` are set on authz denials only.
//!
//! Decision policy: `deny` rows are emitted at the point of refusal (authn
//! failures, authz denials from [`crate::auth_layer::authorize`] and
//! `require_auth`, quota denials). Gateway per-request rows are always
//! `allow`: a request Mobula refuses never reaches the gateway (its deny
//! row comes from the refuser), and an upstream 4xx/5xx is the cluster's
//! answer to an allowed request — the outcome lives in `status`.
//!
//! Tamper-evidence and access (#59, api-v1.md §5.9): the store hash-chains
//! every appended row (sha256 of prev-hash ‖ canonical row);
//! `GET /api/v1/audit/verify` replays it. Reads (list, CSV export, verify)
//! themselves append `audit_read` rows. Both endpoints need `Read` on
//! `Target::Audit` — Admin's catch-all or `Role::Auditor`, nothing else.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, Role, Target};
use mobula_controller::{now_unix, verify_audit_chain, Store};
use mobula_core::{AuditDecision, AuditEvent, AuditFilter};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth_layer::authorize;

/// Snake_case wire form of a permission verb (for `AuditRequired.action`).
pub(crate) fn permission_str(action: PermissionType) -> String {
    match action {
        PermissionType::Read => "read",
        PermissionType::Write => "write",
        PermissionType::Delete => "delete",
        PermissionType::Admin => "admin",
    }
    .to_string()
}

/// Snake_case wire form of a permission target (for `AuditRequired.target`).
pub(crate) fn target_str(target: Target) -> String {
    match target {
        Target::Job => "job",
        Target::Cluster => "cluster",
        Target::Service => "service",
        Target::Pool => "pool",
        Target::Audit => "audit",
    }
    .to_string()
}

/// Snake_case wire form of a role (for `AuditEvent.granted_roles`).
pub(crate) fn role_str(role: &Role) -> String {
    match role {
        Role::Viewer => "viewer",
        Role::Developer => "developer",
        Role::Operator => "operator",
        Role::Admin => "admin",
        Role::Auditor => "auditor",
    }
    .to_string()
}

/// Emit one audit event: trace it on the `mobula::audit` target (the JSONL
/// export consumes that), then append it to the store when one is
/// configured. Absent optional fields are omitted from the trace line
/// (tracing drops `None` values) and `null` in the store — never invented.
pub async fn emit(store: Option<&Arc<dyn Store>>, event: AuditEvent) {
    tracing::info!(
        target: "mobula::audit",
        ts = event.ts,
        subject = event.subject.as_deref(),
        decision = event.decision.as_str(),
        reason = event.reason.as_deref(),
        action = event.action.as_deref(),
        cluster = event.cluster.as_deref(),
        method = event.method.as_deref(),
        path = event.path.as_deref(),
        status = event.status,
        latency_ms = event.latency_ms,
        required = event.required.as_ref().map(|r| r.action.as_str()),
        required_target = event.required.as_ref().map(|r| r.target.as_str()),
        granted = ?event.granted_roles,
        "audit event"
    );
    if let Some(store) = store {
        if let Err(e) = store.record_audit(&event).await {
            // Audit persistence must never fail the audited request.
            tracing::warn!(error = %e, "failed to persist audit event");
        }
    }
}

#[derive(Clone)]
pub struct AuditApiState {
    pub store: Arc<dyn Store>,
}

/// Query for `GET /api/v1/audit` (api-v1.md §5.9).
#[derive(Deserialize, IntoParams)]
pub struct AuditQuery {
    /// Page size (default 100, max 1000).
    pub limit: Option<u32>,
    /// Only rows with `seq` strictly before this value (from a previous
    /// response's `next_cursor`).
    pub cursor: Option<u64>,
    /// Window start, unix seconds (inclusive).
    pub from: Option<u64>,
    /// Window end, unix seconds (inclusive).
    pub to: Option<u64>,
    /// Exact subject match.
    pub subject: Option<String>,
    /// Exact cluster id match.
    pub cluster: Option<String>,
    /// Exact HTTP method match (e.g. `POST`).
    pub method: Option<String>,
    /// Rows whose path starts with this prefix.
    pub path_prefix: Option<String>,
    /// Only rows with `status` >= this (status-less rows excluded).
    pub min_status: Option<u16>,
    /// `allow` or `deny`.
    pub decision: Option<AuditDecision>,
    /// Exact reason match (e.g. `insufficient_permission`).
    pub reason: Option<String>,
    /// `csv` exports the page as `text/csv`; anything else is a 400.
    pub format: Option<String>,
}

/// Response of `GET /api/v1/audit`. This endpoint is the ONE list route
/// that wraps its items in an envelope — the cursor has to live somewhere
/// (api-v1.md §5.9).
#[derive(Serialize, ToSchema)]
pub struct AuditListResponse {
    pub items: Vec<AuditEvent>,
    /// Pass as `cursor` for the next (older) page; `null` at the end.
    pub next_cursor: Option<u64>,
}

/// RFC 4180 quoting: a field containing `,`, `"`, CR or LF is wrapped in
/// double quotes, with inner quotes doubled.
fn csv_field(out: &mut String, value: &str) {
    if value.contains([',', '"', '\n', '\r']) {
        out.push('"');
        for c in value.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
    } else {
        out.push_str(value);
    }
}

/// Render one audit page as CSV. `granted_roles` joins with `;` (comma is
/// the delimiter); absent optional fields are empty cells.
fn render_csv(rows: &[(u64, AuditEvent)]) -> String {
    let mut out = String::from(
        "seq,ts,subject,decision,reason,action,cluster,method,path,status,\
         latency_ms,required_action,required_target,granted_roles\n",
    );
    for (seq, e) in rows {
        let cells = [
            seq.to_string(),
            e.ts.to_string(),
            e.subject.clone().unwrap_or_default(),
            e.decision.as_str().to_string(),
            e.reason.clone().unwrap_or_default(),
            e.action.clone().unwrap_or_default(),
            e.cluster.clone().unwrap_or_default(),
            e.method.clone().unwrap_or_default(),
            e.path.clone().unwrap_or_default(),
            e.status.map(|s| s.to_string()).unwrap_or_default(),
            e.latency_ms.map(|l| l.to_string()).unwrap_or_default(),
            e.required
                .as_ref()
                .map(|r| r.action.clone())
                .unwrap_or_default(),
            e.required
                .as_ref()
                .map(|r| r.target.clone())
                .unwrap_or_default(),
            e.granted_roles.join(";"),
        ];
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            csv_field(&mut out, cell);
        }
        out.push('\n');
    }
    out
}

/// Emit the `audit_read` event for a successful audit-surface read (#59,
/// SOC 2 CC7.2): reading the trail itself appends a row — deliberate
/// recursion, so audit access is itself auditable. Emitted for JSON reads,
/// CSV exports, and `/api/v1/audit/verify` alike. The row is
/// handler-styled (action, no method); its `path` carries the request's
/// query string — an exception to the usual no-query-string convention,
/// because the filter params ARE the payload worth auditing.
async fn emit_audit_read(store: &Arc<dyn Store>, identity: Option<&Identity>, uri: &Uri) {
    let path = match uri.query() {
        Some(query) if !query.is_empty() => format!("{}?{query}", uri.path()),
        _ => uri.path().to_string(),
    };
    emit(
        Some(store),
        AuditEvent {
            ts: now_unix(),
            subject: identity.map(|i| i.subject.clone()),
            decision: AuditDecision::Allow,
            action: Some("audit_read".into()),
            path: Some(path),
            status: Some(StatusCode::OK.as_u16()),
            ..Default::default()
        },
    )
    .await;
}

/// List the persisted audit trail, Admin/Auditor-only (api-v1.md §5.9).
#[utoipa::path(
    get, path = "/api/v1/audit", tag = "audit",
    params(AuditQuery),
    responses(
        (status = 200, description = "Audit events, newest first. \
             `?format=csv` returns text/csv instead.", body = AuditListResponse),
        (status = 400, description = "Bad query (e.g. from > to, unknown format)"),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin or Auditor only — audit subjects are Admin data"),
    ),
    security(("bearer" = []))
)]
async fn list_audit_events(
    State(st): State<AuditApiState>,
    identity: Option<Extension<Identity>>,
    uri: Uri,
    Query(q): Query<AuditQuery>,
) -> Response {
    // Admin or Auditor (#59): audit reads need Read on Target::Audit,
    // which Admin's catch-all and Auditor's only grant both cover. Audit
    // subjects are Admin data (api-v1.md §2.2), so Viewer is explicitly
    // excluded from this target.
    if let Some(deny) = authorize(
        Some(&st.store),
        identity.as_ref().map(|e| &e.0),
        PermissionType::Read,
        Target::Audit,
    )
    .await
    {
        return deny;
    }
    if q.from.is_some_and(|from| q.to.is_some_and(|to| from > to)) {
        return (StatusCode::BAD_REQUEST, "from must not be after to").into_response();
    }
    let csv = match q.format.as_deref() {
        None => false,
        Some("csv") => true,
        Some(other) => {
            return (StatusCode::BAD_REQUEST, format!("unknown format {other:?}")).into_response()
        }
    };

    let filter = AuditFilter {
        limit: q.limit,
        cursor: q.cursor,
        from: q.from,
        to: q.to,
        subject: q.subject,
        cluster: q.cluster,
        method: q.method,
        path_prefix: q.path_prefix,
        min_status: q.min_status,
        decision: q.decision,
        reason: q.reason,
    };
    match st.store.list_audit(&filter).await {
        Ok((rows, next_cursor)) => {
            // Successful reads are themselves audited (#59) — CSV exports
            // included; the export is distinguishable by `format=csv` in
            // the recorded path's query string.
            emit_audit_read(&st.store, identity.as_ref().map(|e| &e.0), &uri).await;
            if csv {
                (
                    [
                        (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                        (
                            axum::http::header::CONTENT_DISPOSITION,
                            "attachment; filename=\"audit.csv\"",
                        ),
                    ],
                    render_csv(&rows),
                )
                    .into_response()
            } else {
                Json(AuditListResponse {
                    items: rows.into_iter().map(|(_, e)| e).collect(),
                    next_cursor,
                })
                .into_response()
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit store error");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

/// Query for `GET /api/v1/audit/verify` (api-v1.md §5.9).
#[derive(Deserialize, IntoParams)]
pub struct AuditVerifyQuery {
    /// First `seq` to check (default 1 — the whole trail from genesis).
    /// The window chains from the newest preceding row's stored hash, so a
    /// mid-trail window verifies against the same head it was written with.
    pub from_seq: Option<u64>,
    /// Max rows to replay (default 100_000, clamped to 1_000_000). Trails
    /// larger than one window verify in successive `from_seq` windows.
    pub limit: Option<u32>,
}

/// Response of `GET /api/v1/audit/verify`.
#[derive(Serialize, ToSchema)]
pub struct AuditVerifyResponse {
    /// True when every row in the window matched the replayed chain.
    pub ok: bool,
    /// Rows that verified before the replay stopped (the whole window on
    /// success; the rows before the broken one on failure).
    pub events_checked: u64,
    /// Seq of the first row whose stored `chain_hash` doesn't match the
    /// replay; `null` when the window verifies clean.
    pub first_broken_seq: Option<u64>,
}

/// Default and hard cap for one verify window (#59): "all" in practice for
/// any realistic trail, bounded so a huge table can't OOM the process.
const VERIFY_DEFAULT_LIMIT: u32 = 100_000;
const VERIFY_MAX_LIMIT: u32 = 1_000_000;

/// Replay the audit hash chain over a window, Admin/Auditor-only (#59).
#[utoipa::path(
    get, path = "/api/v1/audit/verify", tag = "audit",
    params(AuditVerifyQuery),
    responses(
        (status = 200, description = "Chain replay result", body = AuditVerifyResponse),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin or Auditor only"),
    ),
    security(("bearer" = []))
)]
async fn verify_audit_trail(
    State(st): State<AuditApiState>,
    identity: Option<Extension<Identity>>,
    uri: Uri,
    Query(q): Query<AuditVerifyQuery>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st.store),
        identity.as_ref().map(|e| &e.0),
        PermissionType::Read,
        Target::Audit,
    )
    .await
    {
        return deny;
    }
    let limit = q
        .limit
        .unwrap_or(VERIFY_DEFAULT_LIMIT)
        .clamp(1, VERIFY_MAX_LIMIT);
    match st.store.audit_chain(q.from_seq, limit).await {
        Ok(window) => {
            let v = verify_audit_chain(&window.head, &window.rows);
            // Verify reads the trail, so it too leaves an audit_read row
            // (#59) — appended after the replay, so the event itself never
            // perturbs the window it just checked.
            emit_audit_read(&st.store, identity.as_ref().map(|e| &e.0), &uri).await;
            Json(AuditVerifyResponse {
                ok: v.ok(),
                events_checked: v.events_checked,
                first_broken_seq: v.first_broken_seq,
            })
            .into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "audit store error");
            (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
        }
    }
}

pub fn router(store: Arc<dyn Store>) -> Router {
    Router::new()
        .route("/api/v1/audit", get(list_audit_events))
        .route("/api/v1/audit/verify", get(verify_audit_trail))
        .with_state(AuditApiState { store })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mobula_core::AuditRequired;

    fn event(subject: Option<&str>, roles: &[&str]) -> AuditEvent {
        AuditEvent {
            ts: 1_755_280_000,
            subject: subject.map(String::from),
            decision: AuditDecision::Deny,
            reason: Some("insufficient_permission".into()),
            path: Some("/api/v1/audit".into()),
            status: Some(403),
            required: Some(AuditRequired {
                action: "admin".into(),
                target: "cluster".into(),
            }),
            granted_roles: roles.iter().map(|r| r.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn csv_has_header_and_one_row_per_event() {
        let csv = render_csv(&[
            (7, event(Some("alice"), &["viewer"])),
            (3, event(None, &[])),
        ]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "seq,ts,subject,decision,reason,action,cluster,method,path,status,latency_ms,required_action,required_target,granted_roles"
        );
        assert_eq!(
            lines[1],
            "7,1755280000,alice,deny,insufficient_permission,,,,/api/v1/audit,403,,admin,cluster,viewer"
        );
        // Absent fields are empty cells; roles list joins with ';'.
        assert_eq!(
            lines[2],
            "3,1755280000,,deny,insufficient_permission,,,,/api/v1/audit,403,,admin,cluster,"
        );
    }

    #[test]
    fn csv_quotes_commas_quotes_and_newlines() {
        let mut e = event(Some("a,b\"c\nd"), &[]);
        e.path = Some("/plain".into());
        let csv = render_csv(&[(1, e)]);
        // The subject contains a comma, a quote, and a newline: the field is
        // wrapped in quotes and the inner quote doubled (RFC 4180). The
        // embedded newline is legal inside a quoted field, so don't split
        // the output on lines for this check.
        assert!(csv.contains("\"a,b\"\"c\nd\""), "{csv}");
        assert!(csv.ends_with("/plain,403,,admin,cluster,\n"), "{csv}");
    }

    #[test]
    fn permission_target_role_strings_are_snake_case() {
        assert_eq!(permission_str(PermissionType::Write), "write");
        assert_eq!(target_str(Target::Cluster), "cluster");
        assert_eq!(target_str(Target::Audit), "audit");
        assert_eq!(role_str(&Role::Viewer), "viewer");
        assert_eq!(role_str(&Role::Admin), "admin");
        assert_eq!(role_str(&Role::Auditor), "auditor");
    }
}
