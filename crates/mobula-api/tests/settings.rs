//! Settings API tests (api-v1.md §5.16): the store-backed, API-editable
//! governance policy. Covers provenance (`source`: none/file/store), the
//! section-replace PUT semantics (incl. explicit-null clears), RBAC
//! (Admin-only), validation, and that consumers (quota admission, cost
//! estimates) read the EDITED policy without a restart.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::Response;
use mobula_api::clusters::PolicyConfig;
use mobula_controller::InMemoryStore;
use mobula_policy::{PriceSheet, ResourceMap};
use tower::ServiceExt;

use common::{
    authed_app_with_policy, authed_app_with_store, get, idp_token, post_json, put_json, spawn_idp,
};

const HOST: &str = "mobula.example.com";

async fn body_json(res: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// head 1 + `replicas` × `cpu` workers, in `project`.
fn create_body_sized(id: &str, project: &str, cpu: &str, replicas: u32) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "spec": {
            "name": id, "project": project, "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0", "head_cpu": "1", "head_memory": "2Gi",
            "worker_groups": [{
                "name": "w", "cpu": cpu, "memory": "1Gi", "gpu": null,
                "min_replicas": replicas, "max_replicas": replicas, "replicas": replicas
            }],
            "ttl_seconds": null
        }
    })
}

fn seeded_policy() -> PolicyConfig {
    PolicyConfig {
        prices: Some(PriceSheet(BTreeMap::from([("cpu".to_string(), 0.048)]))),
        quotas: HashMap::from([(
            "demo".to_string(),
            ResourceMap(BTreeMap::from([
                ("cpu".to_string(), 5.0),
                ("memory".to_string(), 100.0),
            ])),
        )]),
        gpu_default_sharing: Default::default(),
        pod_shaping: Default::default(),
    }
}

#[tokio::test]
async fn unset_policy_reports_none() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["source"], "none");
    assert!(body["prices"].is_null());
    assert_eq!(body["quotas"], serde_json::json!({}));
    assert_eq!(body["editable"], true);
}

#[tokio::test]
async fn seeded_policy_reports_file_and_drives_cost_estimates() {
    let idp = spawn_idp().await;
    let app = authed_app_with_policy(&idp, Arc::new(InMemoryStore::new()), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["source"], "file", "untouched boot seed reports file");
    assert_eq!(body["prices"]["cpu"], 0.048);
    assert_eq!(body["quotas"]["demo"]["cpu"], 5.0);

    // The seeded price sheet drives ClusterView cost estimates.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("a", "demo", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = app
        .oneshot(get("/api/v1/clusters", HOST, Some(&admin)))
        .await
        .unwrap();
    let clusters = body_json(res).await;
    // head 1 + 3×1cpu = 4 cores × $0.048 = $0.192/hr at min AND max.
    assert_eq!(clusters[0]["est_min_hourly"], 0.192);
    assert_eq!(clusters[0]["est_max_hourly"], 0.192);
}

#[tokio::test]
async fn put_prices_then_get_and_estimates_reflect_store() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": { "cpu": 0.1 } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["source"], "store");
    assert_eq!(body["prices"]["cpu"], 0.1);

    // GET reflects the edit.
    let res = app
        .clone()
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let body = body_json(res).await;
    assert_eq!(body["source"], "store");
    assert_eq!(body["prices"]["cpu"], 0.1);

    // A cluster created after the edit shows cost estimates.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("a", "demo", "2", 2),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters/a", HOST, Some(&admin)))
        .await
        .unwrap();
    let cluster = body_json(res).await;
    // head 1 + 2×2cpu = 5 cores × $0.1 = $0.5/hr.
    assert_eq!(cluster["est_min_hourly"], 0.5);

    // Absent keys are untouched: a quotas-only PUT keeps the price sheet.
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "quotas": { "demo": { "cpu": 50 } } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["prices"]["cpu"], 0.1, "absent prices key untouched");
    assert_eq!(body["quotas"]["demo"]["cpu"], 50.0);
}

#[tokio::test]
async fn put_quotas_replaces_file_quotas_for_admission() {
    let idp = spawn_idp().await;
    let app = authed_app_with_policy(&idp, Arc::new(InMemoryStore::new()), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    // Replace the whole quota section: demo's file quota (cpu 5) is gone,
    // project "q2" is now capped at 2 CPU.
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "quotas": { "q2": { "cpu": 2 } } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // The OLD file quota no longer applies: demo's create needs head 1 +
    // 3×2 = 7 CPU > the old 5-CPU cap, and must now be admitted.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("big", "demo", "2", 3),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "replaced file quota must no longer gate demo"
    );

    // The NEW quota gates q2: head 1 + 3×1 = 4 CPU > 2 → 409.
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("over", "q2", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "store-edited quota must gate admission"
    );
}

#[tokio::test]
async fn clear_prices_with_explicit_null() {
    let idp = spawn_idp().await;
    let app = authed_app_with_policy(&idp, Arc::new(InMemoryStore::new()), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": null }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(body["prices"].is_null(), "null clears the price sheet");
    assert_eq!(body["quotas"]["demo"]["cpu"], 5.0, "quotas untouched");
    assert_eq!(body["source"], "store");

    // Cost estimates disappear once the sheet is cleared.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body_sized("a", "demo", "1", 3),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let res = app
        .oneshot(get("/api/v1/clusters/a", HOST, Some(&admin)))
        .await
        .unwrap();
    let cluster = body_json(res).await;
    assert!(cluster["est_min_hourly"].is_null());
    assert!(cluster["est_max_hourly"].is_null());
}

#[tokio::test]
async fn viewer_is_forbidden_on_get_and_put() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let viewer = idp_token(&idp, &["/observers"]);

    let res = app
        .clone()
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&viewer)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = app
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &viewer,
            serde_json::json!({ "prices": { "cpu": 0.1 } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_values_are_400() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    for body in [
        serde_json::json!({ "prices": { "cpu": -0.5 } }),
        serde_json::json!({ "quotas": { "demo": { "cpu": -1 } } }),
    ] {
        let res = app
            .clone()
            .oneshot(put_json("/api/v1/settings/policy", HOST, &admin, body))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let text = String::from_utf8(
            axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("non-negative finite"), "{text}");
    }

    // A rejected PUT must not have written anything.
    let res = app
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let body = body_json(res).await;
    assert_eq!(body["source"], "none");
}

#[tokio::test]
async fn update_policy_is_audited() {
    let idp = spawn_idp().await;
    let app = authed_app_with_store(&idp, Arc::new(InMemoryStore::new())).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": { "cpu": 0.1 } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .oneshot(get("/api/v1/audit", HOST, Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    let actions: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert!(
        actions.contains(&"update_policy"),
        "expected an update_policy audit row, got {actions:?}"
    );
}

// ---------------------------------------------------------------------------
// Pod-shaping catalog (#66): live-editable, Admin-only, and never retroactive.
// ---------------------------------------------------------------------------

fn catalog_json(mount_path: &str) -> serde_json::Value {
    serde_json::json!({
        "mounts": [{
            "name": "home",
            "claim_name": "nebari-home",
            "mount_path": mount_path,
            "read_only": false,
            "sub_path": "home/{project}"
        }],
        "service_accounts": ["ray-workload"],
        "default_mounts": ["home"]
    })
}

fn plain_create(id: &str, project: &str) -> serde_json::Value {
    create_body_sized(id, project, "1", 0)
}

async fn stored_shape(
    store: &Arc<InMemoryStore>,
    id: &str,
) -> Option<mobula_core::ResolvedPodShape> {
    use mobula_controller::Store;
    store
        .get(&mobula_core::ClusterId(id.to_string()))
        .await
        .unwrap()
        .expect("cluster stored")
        .spec
        .pod_resolved
}

#[tokio::test]
async fn a_catalog_added_at_runtime_governs_the_next_create() {
    // The point of making this store-backed: adding a mount must not need a
    // restart. The server here boots with NO pod shaping at all.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), Default::default()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            plain_create("before", "demo"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    assert_eq!(
        stored_shape(&store, "before").await,
        None,
        "no catalog yet, so nothing is granted"
    );

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "pod_shaping": catalog_json("/home/ray") }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let view = body_json(res).await;
    assert_eq!(
        view["pod_shaping"]["mounts"][0]["claim_name"],
        "nebari-home"
    );
    assert_eq!(view["source"], "store");

    // No restart between these two lines.
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            plain_create("after", "demo"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let shape = stored_shape(&store, "after").await.expect("granted");
    assert_eq!(shape.volumes[0].claim_name, "nebari-home");
    assert_eq!(shape.volumes[0].mount_path, "/home/ray");
}

#[tokio::test]
async fn editing_the_catalog_does_not_re_shape_an_existing_cluster() {
    // The safety property that makes a live catalog acceptable: a cluster's
    // grant is frozen onto its spec at admission. An edit cannot silently
    // change what an already-admitted cluster mounts.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), Default::default()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    app.clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "pod_shaping": catalog_json("/home/ray") }),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            plain_create("c", "demo"),
        ))
        .await
        .unwrap();
    let before = stored_shape(&store, "c").await.expect("granted");
    assert_eq!(before.volumes[0].mount_path, "/home/ray");

    // Move the mount, then clear the catalog entirely.
    app.clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "pod_shaping": catalog_json("/mnt/elsewhere") }),
        ))
        .await
        .unwrap();
    assert_eq!(
        stored_shape(&store, "c").await.as_ref(),
        Some(&before),
        "a catalog edit must not touch an admitted cluster's grant"
    );

    app.clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "pod_shaping": {} }),
        ))
        .await
        .unwrap();
    assert_eq!(
        stored_shape(&store, "c").await.as_ref(),
        Some(&before),
        "clearing the catalog must not strip a running cluster's mounts"
    );

    // Re-submitting is the deliberate migration: now it picks up the new
    // catalog (here: emptied), which bumps the generation and rolls the pods.
    app.oneshot(post_json(
        "/api/v1/clusters",
        HOST,
        &admin,
        plain_create("c", "demo"),
    ))
    .await
    .unwrap();
    assert_eq!(
        stored_shape(&store, "c").await,
        None,
        "re-submitting migrates the cluster onto the current catalog"
    );
}

#[tokio::test]
async fn an_incoherent_catalog_is_rejected_at_the_edit() {
    // `default_mounts` naming a mount that does not exist would 403 EVERY
    // cluster create. Catch it where the mistake was made.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store.clone(), Default::default()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "pod_shaping": { "default_mounts": ["home"] } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // And the bad catalog was not stored, so creates still work.
    let res = app
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            plain_create("c", "demo"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn a_traversing_sub_path_is_rejected_at_the_edit() {
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store, Default::default()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let mut catalog = catalog_json("/home/ray");
    catalog["mounts"][0]["sub_path"] = serde_json::json!("home/{project}/../../root");
    let res = app
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "pod_shaping": catalog }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn editing_the_catalog_is_admin_only() {
    // A live catalog is a grant of data access, so a developer must not be
    // able to add themselves a mount.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let app = authed_app_with_policy(&idp, store, Default::default()).await;
    let dev = idp_token(&idp, &["/ml-eng"]);

    let res = app
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &dev,
            serde_json::json!({ "pod_shaping": catalog_json("/home/ray") }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_changed_file_seed_refreshes_an_unedited_row_on_restart() {
    // A `from_file_seed` row was never admin-edited, so the file stays
    // authoritative: restarting with `[pod_shaping]` added to the same file
    // must refresh the row. Without this, the operator's addition silently
    // never applies while the boot log and GET (source:"file") both claim
    // the file is in effect.
    use mobula_policy::podshape::{MountEntry, PodShapeCatalog};
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());

    // First boot: prices/quotas only. GET materializes the seed row.
    let app = authed_app_with_policy(&idp, store.clone(), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);
    let res = app
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let view = body_json(res).await;
    assert_eq!(view["source"], "file");
    assert!(view["pod_shaping"]["mounts"]
        .as_array()
        .is_none_or(|m| m.is_empty()));

    // "Restart" with [pod_shaping] added to the same policy file.
    let mut seed2 = seeded_policy();
    seed2.pod_shaping = PodShapeCatalog {
        mounts: vec![MountEntry {
            name: "home".into(),
            claim_name: "nebari-home".into(),
            mount_path: "/home/ray".into(),
            read_only: false,
            sub_path: None,
        }],
        default_mounts: vec!["home".into()],
        ..Default::default()
    };
    let app2 = authed_app_with_policy(&idp, store, seed2).await;
    let res = app2
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let view = body_json(res).await;
    assert_eq!(
        view["pod_shaping"]["mounts"][0]["name"], "home",
        "the changed file seed must refresh the unedited row"
    );
    assert_eq!(
        view["source"], "file",
        "an unedited row keeps file provenance"
    );
}

#[tokio::test]
async fn an_edited_row_is_never_clobbered_by_the_file_seed() {
    // Once an Admin has PUT the policy, the store is truth and the file is
    // history — a restart with any seed must not undo the edit.
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());

    let app = authed_app_with_policy(&idp, store.clone(), seeded_policy()).await;
    let admin = idp_token(&idp, &["/platform-admins"]);
    let res = app
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": { "cpu": 0.99 } }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // "Restart" with the original (different) file seed.
    let app2 = authed_app_with_policy(&idp, store, seeded_policy()).await;
    let res = app2
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let view = body_json(res).await;
    assert_eq!(view["source"], "store", "the edit survives the restart");
    assert_eq!(view["prices"]["cpu"], 0.99);
}

#[tokio::test]
async fn a_pod_shaping_only_policy_file_still_seeds_a_row() {
    // A deployment may configure ONLY pod shaping (no prices, no quotas).
    // That has to materialize a store row, or the catalog could never be
    // edited afterwards.
    use mobula_policy::podshape::{MountEntry, PodShapeCatalog};
    let idp = spawn_idp().await;
    let store = Arc::new(InMemoryStore::new());
    let seed = PolicyConfig {
        prices: None,
        quotas: Default::default(),
        gpu_default_sharing: Default::default(),
        pod_shaping: PodShapeCatalog {
            mounts: vec![MountEntry {
                name: "home".into(),
                claim_name: "nebari-home".into(),
                mount_path: "/home/ray".into(),
                read_only: false,
                sub_path: None,
            }],
            default_mounts: vec!["home".into()],
            ..Default::default()
        },
    };
    let app = authed_app_with_policy(&idp, store, seed).await;
    let admin = idp_token(&idp, &["/platform-admins"]);

    let res = app
        .clone()
        .oneshot(get("/api/v1/settings/policy", HOST, Some(&admin)))
        .await
        .unwrap();
    let view = body_json(res).await;
    assert_eq!(view["source"], "file", "the file seed materialized a row");
    assert_eq!(view["pod_shaping"]["mounts"][0]["name"], "home");

    // Editing another section must not drop the seeded catalog.
    let res = app
        .oneshot(put_json(
            "/api/v1/settings/policy",
            HOST,
            &admin,
            serde_json::json!({ "prices": { "cpu": 0.05 } }),
        ))
        .await
        .unwrap();
    let view = body_json(res).await;
    assert_eq!(view["pod_shaping"]["mounts"][0]["name"], "home");
    assert_eq!(view["source"], "store");
}
