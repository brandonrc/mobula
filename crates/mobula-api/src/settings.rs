//! Settings API (api-v1.md §5.16): the store-backed, API-editable governance
//! policy — price sheet (cost estimates) and per-project quota limits.
//!
//! Precedence: the `--policy` TOML file is the boot-time DEFAULT; the store
//! wins once edited. The effective policy lives in the store (one JSON row
//! in the `control` table); handlers load it per request via
//! [`effective_policy`] so edits apply without a restart. A store with no
//! policy row yet is lazily seeded from the `--policy` seed (insert-if-absent
//! via [`Store::seed_policy`], so a concurrent edit is never clobbered) —
//! observable behavior is identical to seeding at startup, but the app
//! builders stay synchronous. The seeded row carries `from_file_seed: true`
//! until the first PUT, which is what `source: "file" | "store"` reports;
//! `"none"` means no row AND no seed (no policy configured at all).
//!
//! Both routes are Admin-only (governance is platform configuration, like
//! pools); the ext_authz target mapping is `Target::Cluster` (same
//! convention as registry/audit).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use mobula_auth::{Identity, PermissionType, Target};
use mobula_controller::{now_unix, Store, StoredPolicy};
use mobula_core::{AuditDecision, AuditEvent};
use mobula_policy::podshape::PodShapeCatalog;
use mobula_policy::{PriceSheet, ResourceMap};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::audit::emit;
use crate::auth_layer::authorize;
use crate::clusters::PolicyConfig;

#[derive(Clone)]
pub struct SettingsApiState {
    pub store: Arc<dyn Store>,
    /// The `--policy` boot-time default; consulted only until the store
    /// holds a policy row (see module docs).
    pub policy_seed: Arc<PolicyConfig>,
}

fn ident(ext: &Option<Extension<Identity>>) -> Option<&Identity> {
    ext.as_ref().map(|e| &e.0)
}

fn store_err(e: mobula_controller::StoreError) -> Response {
    tracing::warn!(error = %e, "settings store error");
    (StatusCode::INTERNAL_SERVER_ERROR, "store error").into_response()
}

/// Convert the in-flight [`PolicyConfig`] seed into a storable row, or
/// `None` when the seed is empty (no `--policy` given) — an empty seed
/// never materializes a row, so `source` stays `"none"`.
fn seed_from_config(cfg: &PolicyConfig) -> Option<StoredPolicy> {
    // A `[pod_shaping]`-only policy file is a real configuration: it must
    // materialize a row, or the catalog would never reach the store and
    // could not be edited.
    if cfg.prices.is_none() && cfg.quotas.is_empty() && cfg.pod_shaping.is_empty() {
        return None;
    }
    Some(StoredPolicy {
        prices: cfg.prices.as_ref().map(|p| p.0.clone()),
        quotas: cfg
            .quotas
            .iter()
            .map(|(k, v)| (k.clone(), v.0.clone()))
            .collect(),
        pod_shaping: cfg.pod_shaping.clone(),
        from_file_seed: true,
    })
}

/// Convert a stored row back into the in-flight [`PolicyConfig`] shape the
/// policy engine (`mobula_policy`) consumes. The GPU-sharing default (#58)
/// is boot-time-only config, not part of the stored row — callers that need
/// it read it from the `--policy` seed, not from here.
pub(crate) fn config_from_stored(p: &StoredPolicy) -> PolicyConfig {
    PolicyConfig {
        prices: p.prices.clone().map(PriceSheet),
        quotas: p
            .quotas
            .iter()
            .map(|(k, v)| (k.clone(), ResourceMap(v.clone())))
            .collect(),
        gpu_default_sharing: Default::default(),
        // The pod-shaping catalog (#66) IS part of the stored row, so
        // adding a mount is an API call rather than a restart — same
        // treatment as prices and quotas, and the same reasoning that made
        // pools API-managed (ADR-0010). `gpu_default_sharing` stays
        // boot-time-only: it is a safety default, not a catalog.
        pod_shaping: p.pod_shaping.clone(),
    }
}

/// The effective governance policy: the store row when one exists (seeded
/// or edited — the store is the one source of truth once it holds a row),
/// else the `--policy` boot seed, which is then persisted insert-if-absent
/// so it becomes the row. `None` = no policy configured at all (no row and
/// an empty seed) — callers behave as if governance were disabled.
///
/// Read once per request; it's a single indexed row read, cheap on both
/// SQLite and Postgres, and it keeps every handler race-free against edits.
pub(crate) async fn effective_policy(
    store: &Arc<dyn Store>,
    seed: &PolicyConfig,
) -> Result<Option<StoredPolicy>, mobula_controller::StoreError> {
    if let Some(p) = store.get_policy().await? {
        return Ok(Some(p));
    }
    match seed_from_config(seed) {
        Some(p) => {
            // Insert-if-absent: a concurrent PUT that landed first is not
            // clobbered; a concurrent seeder wrote the same values. When the
            // insert loses the race, read back the row that actually won so
            // this request never answers with a stale seed.
            if store.seed_policy(&p).await? {
                Ok(Some(p))
            } else {
                store.get_policy().await
            }
        }
        None => Ok(None),
    }
}

/// `GET /api/v1/settings/policy` response: the effective policy plus its
/// provenance.
#[derive(Serialize, ToSchema)]
pub struct PolicyView {
    /// resource → $/unit-hour; `null` when no price sheet is configured.
    pub prices: Option<BTreeMap<String, f64>>,
    /// project → (resource → limit). Empty when no quotas are configured.
    pub quotas: BTreeMap<String, BTreeMap<String, f64>>,
    /// The pod-shaping catalog (#66): what callers may select. Empty when
    /// pod shaping is not configured.
    pub pod_shaping: PodShapeCatalog,
    /// "file" (the untouched `--policy` boot seed) | "store" (edited via
    /// PUT) | "none" (no policy configured at all).
    #[schema(example = "file")]
    pub source: &'static str,
    /// Always true in v1 — the policy is editable via PUT.
    pub editable: bool,
}

impl PolicyView {
    fn of(p: StoredPolicy, source: &'static str) -> Self {
        PolicyView {
            prices: p.prices,
            quotas: p.quotas,
            pod_shaping: p.pod_shaping,
            source,
            editable: true,
        }
    }
}

/// Request body for `PUT /api/v1/settings/policy`. Section-replace
/// semantics: a present key replaces that whole section (`prices: null`
/// clears the price sheet; `quotas: {}` clears all quotas); an absent key
/// leaves that section untouched.
#[derive(Deserialize, ToSchema)]
pub struct UpdatePolicy {
    /// Present (incl. explicit `null`) replaces/clears the price sheet.
    #[serde(default, deserialize_with = "de_present_nullable")]
    pub prices: Option<Option<BTreeMap<String, f64>>>,
    /// Present replaces the whole quota map (`{}` clears all quotas).
    pub quotas: Option<BTreeMap<String, BTreeMap<String, f64>>>,
    /// Present replaces the whole pod-shaping catalog (`{}` switches pod
    /// shaping off). Validated as a unit before it is stored — a catalog
    /// whose defaults do not resolve would 403 every cluster create, so it
    /// is rejected here rather than discovered there.
    ///
    /// Editing this does NOT re-shape running clusters: each cluster's grant
    /// is frozen onto its spec at admission. A cluster moves onto the new
    /// catalog only when it is re-submitted.
    pub pod_shaping: Option<PodShapeCatalog>,
}

/// Distinguish an absent field from an explicit JSON `null`: serde's plain
/// `Option<Option<T>>` collapses both to `None`; wrapping the inner
/// deserialization keeps null as `Some(None)` (clear) vs absent as `None`
/// (untouched).
fn de_present_nullable<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(d)?))
}

/// Every incoming value must be a non-negative finite number (JSON can't
/// carry NaN/inf, but negative values can arrive; the check is the contract).
fn validate_amounts(map: &BTreeMap<String, f64>, what: &str) -> Result<(), String> {
    for (k, v) in map {
        if !v.is_finite() || *v < 0.0 {
            return Err(format!(
                "invalid {what} for {k:?}: must be a non-negative finite number"
            ));
        }
    }
    Ok(())
}

/// The effective governance policy. Admin-only: quotas and prices are
/// platform configuration (api-v1.md §2.2), classified with `Target::Cluster`
/// like the registry/audit surfaces.
#[utoipa::path(
    get, path = "/api/v1/settings/policy", tag = "settings",
    responses(
        (status = 200, description = "The effective policy and its provenance", body = PolicyView),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin only — governance is platform configuration"),
    ),
    security(("bearer" = []))
)]
async fn get_policy(
    State(st): State<SettingsApiState>,
    identity: Option<Extension<Identity>>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Admin,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    match effective_policy(&st.store, &st.policy_seed).await {
        Ok(Some(p)) => {
            let source = if p.from_file_seed { "file" } else { "store" };
            Json(PolicyView::of(p, source)).into_response()
        }
        Ok(None) => Json(PolicyView::of(StoredPolicy::default(), "none")).into_response(),
        Err(e) => store_err(e),
    }
}

/// Replace sections of the governance policy. Admin-only. Edits take effect
/// on the very next request — quota admission, cost estimates, and the usage
/// roll-up all read the store per request. Emits an `update_policy` audit
/// event on success.
#[utoipa::path(
    put, path = "/api/v1/settings/policy", tag = "settings",
    request_body = UpdatePolicy,
    responses(
        (status = 200, description = "The policy after the update (source is now \"store\")", body = PolicyView),
        (status = 400, description = "Negative or non-finite price/quota value"),
        (status = 401, description = "No/invalid token"),
        (status = 403, description = "Admin only — governance is platform configuration"),
    ),
    security(("bearer" = []))
)]
async fn update_policy(
    State(st): State<SettingsApiState>,
    identity: Option<Extension<Identity>>,
    Json(body): Json<UpdatePolicy>,
) -> Response {
    if let Some(deny) = authorize(
        Some(&st.store),
        ident(&identity),
        PermissionType::Admin,
        Target::Cluster,
    )
    .await
    {
        return deny;
    }
    // Validate the INCOMING sections only — existing stored/seeded values
    // were accepted by whatever wrote them and must not 400 an unrelated edit.
    if let Some(Some(prices)) = &body.prices {
        if let Err(msg) = validate_amounts(prices, "price") {
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
    }
    if let Some(quotas) = &body.quotas {
        for (project, map) in quotas {
            if let Err(msg) = validate_amounts(map, &format!("quota for project {project:?}")) {
                return (StatusCode::BAD_REQUEST, msg).into_response();
            }
        }
    }

    if let Some(catalog) = &body.pod_shaping {
        if let Err(e) = catalog.validate() {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid pod_shaping catalog: {e}"),
            )
                .into_response();
        }
    }

    let mut next = match effective_policy(&st.store, &st.policy_seed).await {
        Ok(p) => p.unwrap_or_default(),
        Err(e) => return store_err(e),
    };
    if let Some(prices) = body.prices {
        next.prices = prices;
    }
    if let Some(quotas) = body.quotas {
        next.quotas = quotas;
    }
    if let Some(catalog) = body.pod_shaping {
        next.pod_shaping = catalog;
    }
    next.from_file_seed = false;
    if let Err(e) = st.store.set_policy(&next).await {
        return store_err(e);
    }
    emit(
        Some(&st.store),
        AuditEvent {
            ts: now_unix(),
            subject: ident(&identity).map(|i| i.subject.clone()),
            decision: AuditDecision::Allow,
            action: Some("update_policy".into()),
            status: Some(StatusCode::OK.as_u16()),
            ..Default::default()
        },
    )
    .await;
    Json(PolicyView::of(next, "store")).into_response()
}

/// The settings route bundle; mounted only when a store is configured (same
/// condition as the clusters/pools routes).
pub fn router(store: Arc<dyn Store>, policy_seed: Arc<PolicyConfig>) -> Router {
    Router::new()
        .route(
            "/api/v1/settings/policy",
            get(get_policy).put(update_policy),
        )
        .with_state(SettingsApiState { store, policy_seed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_policy_distinguishes_absent_from_null() {
        // Absent keys → untouched.
        let body: UpdatePolicy = serde_json::from_str("{}").unwrap();
        assert!(body.prices.is_none());
        assert!(body.quotas.is_none());
        // Explicit null clears the price sheet; an empty map clears quotas.
        let body: UpdatePolicy = serde_json::from_str(r#"{"prices": null, "quotas": {}}"#).unwrap();
        assert_eq!(body.prices, Some(None));
        assert_eq!(body.quotas, Some(BTreeMap::new()));
        // A present sheet parses.
        let body: UpdatePolicy = serde_json::from_str(r#"{"prices": {"cpu": 0.048}}"#).unwrap();
        assert_eq!(
            body.prices.as_ref().unwrap().as_ref().unwrap()["cpu"],
            0.048
        );
    }

    #[test]
    fn validate_amounts_rejects_negative_and_non_finite() {
        assert!(validate_amounts(&BTreeMap::from([("cpu".into(), 0.04)]), "price").is_ok());
        for bad in [-1.0, f64::NAN, f64::INFINITY] {
            let err =
                validate_amounts(&BTreeMap::from([("cpu".into(), bad)]), "price").unwrap_err();
            assert!(err.contains("non-negative finite"), "{err}");
        }
    }

    #[test]
    fn empty_seed_produces_no_row() {
        assert!(seed_from_config(&PolicyConfig::default()).is_none());
        let seeded = seed_from_config(&PolicyConfig {
            prices: Some(PriceSheet(BTreeMap::from([("cpu".into(), 0.04)]))),
            quotas: Default::default(),
            gpu_default_sharing: Default::default(),
            pod_shaping: Default::default(),
        })
        .unwrap();
        assert!(seeded.from_file_seed);
        assert_eq!(seeded.prices.as_ref().unwrap()["cpu"], 0.04);
    }

    #[tokio::test]
    async fn effective_policy_seeds_once_then_store_wins() {
        use std::collections::HashMap;
        let store: Arc<dyn Store> = Arc::new(mobula_controller::InMemoryStore::new());
        let seed = PolicyConfig {
            prices: None,
            quotas: HashMap::from([(
                "demo".to_string(),
                ResourceMap(BTreeMap::from([("cpu".to_string(), 5.0)])),
            )]),
            gpu_default_sharing: Default::default(),
            pod_shaping: Default::default(),
        };
        // First read seeds from the file seed.
        let p = effective_policy(&store, &seed).await.unwrap().unwrap();
        assert!(p.from_file_seed);
        assert_eq!(p.quotas["demo"]["cpu"], 5.0);
        // An edit wins over the seed on subsequent reads.
        let edited = StoredPolicy {
            from_file_seed: false,
            ..p
        };
        store.set_policy(&edited).await.unwrap();
        let got = effective_policy(&store, &seed).await.unwrap().unwrap();
        assert!(!got.from_file_seed, "store row wins over the boot seed");
        // Empty seed + no row → None.
        let fresh: Arc<dyn Store> = Arc::new(mobula_controller::InMemoryStore::new());
        assert!(effective_policy(&fresh, &PolicyConfig::default())
            .await
            .unwrap()
            .is_none());
    }
}
