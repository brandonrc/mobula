//! Self-service RBAC integration tests:
//!
//! * #103 — group→project-role automation: a caller's Keycloak group
//!   membership implies an `operator` role scoped to the matching project,
//!   with NO manual `PUT /access/assignments`. A member of `team-a` creates
//!   clusters in `project:team-a` (201) but is denied in `team-b` (403), and
//!   sees only their own project's clusters.
//!
//! * #88 — assignment principals keyed by username: an assignment granted to
//!   `alice` (the human `preferred_username`, not the opaque Keycloak `sub`
//!   UUID) actually authorizes her. Before the fix, evaluation looked up by
//!   `sub` only, so a username grant stored 200 and then never matched.

mod common;
use common::{
    authed_app_selfservice, authed_app_with_store, get, idp_token_named, post_json, put_json,
    spawn_idp,
};

use axum::http::StatusCode;
use std::sync::Arc;
use tower::ServiceExt;

use mobula_controller::{InMemoryStore, Store};

const HOST: &str = "mobula.example.com";

fn create_body(id: &str, project: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "spec": {
            "name": id,
            "project": project,
            "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0",
            "head_cpu": "1",
            "head_memory": "2Gi",
            "worker_groups": [],
            "ttl_seconds": null
        }
    })
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------- #103 ------

#[tokio::test]
async fn group_member_creates_in_matching_project_without_a_manual_grant() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_selfservice(&idp, store).await;

    // alice is ONLY in group team-a. No global role, no stored assignment.
    let alice = idp_token_named(&idp, "alice-sub-uuid", "alice", &["team-a"]);

    // #103: create in project team-a succeeds with no manual assignment.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &alice,
            create_body("a1", "team-a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "team-a create");

    // ...but she is denied in team-b (she is not a member).
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &alice,
            create_body("b1", "team-b"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "team-b create");
}

#[tokio::test]
async fn group_member_sees_only_their_projects_clusters() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_selfservice(&idp, store).await;

    // Global admin (group mobula-admins) seeds one cluster in each project.
    let admin = idp_token_named(&idp, "admin-sub", "admin", &["mobula-admins"]);
    for (id, project) in [("a1", "team-a"), ("b1", "team-b")] {
        let res = app
            .clone()
            .oneshot(post_json(
                "/api/v1/clusters",
                HOST,
                &admin,
                create_body(id, project),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "seed {id}");
    }

    // alice (team-a only) sees exactly the team-a cluster: read-scoping (#49)
    // follows the group-derived project role.
    let alice = idp_token_named(&idp, "alice-sub", "alice", &["team-a"]);
    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters", HOST, Some(&alice)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let list = body_json(res).await;
    let projects: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["project"].as_str().unwrap())
        .collect();
    assert_eq!(projects, vec!["team-a"], "alice sees only team-a");
}

#[tokio::test]
async fn no_group_no_assignment_is_denied_by_default() {
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_selfservice(&idp, store).await;

    // A caller in NO group and with no assignment authenticates but is
    // authorized for nothing — deny-by-default is preserved.
    let nobody = idp_token_named(&idp, "nobody-sub", "nobody", &[]);
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &nobody,
            create_body("x", "team-a"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = app
        .clone()
        .oneshot(get("/api/v1/clusters", HOST, Some(&nobody)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn global_admin_creates_in_any_project() {
    // The group-derived project role is additive: a global admin still creates
    // anywhere, group membership or not.
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_selfservice(&idp, store).await;

    let admin = idp_token_named(&idp, "admin-sub", "admin", &["mobula-admins"]);
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &admin,
            create_body("anywhere", "some-other-project"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

// ----------------------------------------------------------------- #88 ------

#[tokio::test]
async fn assignment_to_username_authorizes_the_caller() {
    // authed_app_with_store's validator maps /platform-admins -> Admin and has
    // NO project_roles, so the ONLY path for alice here is the stored
    // assignment — which is granted to her username, not her sub.
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;

    let admin = idp_token_named(&idp, "admin-sub", "admin", &["/platform-admins"]);

    // Grant operator on project:proj-x to the human username "alice".
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/access/assignments/alice",
            HOST,
            &admin,
            serde_json::json!({"role": "operator", "scope": "project:proj-x"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "grant to username");

    // alice's token carries sub=UUID, preferred_username=alice. #88: the grant
    // matches via preferred_username, so she can create in proj-x.
    let alice = idp_token_named(&idp, "alice-8c3f-uuid", "alice", &[]);
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &alice,
            create_body("px", "proj-x"),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "username grant takes effect"
    );

    // Control: the grant is scoped to proj-x only — proj-y is still denied.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &alice,
            create_body("py", "proj-y"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN, "scope is respected");
}

#[tokio::test]
async fn assignment_by_sub_still_matches() {
    // Regression guard: granting by the opaque sub keeps working (the historic
    // path), so #88 adds the username key without removing the sub key.
    let idp = spawn_idp().await;
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new());
    let app = authed_app_with_store(&idp, store).await;

    let admin = idp_token_named(&idp, "admin-sub", "admin", &["/platform-admins"]);
    let res = app
        .clone()
        .oneshot(put_json(
            "/api/v1/access/assignments/bob-sub-uuid",
            HOST,
            &admin,
            serde_json::json!({"role": "operator", "scope": "project:proj-z"}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bob = idp_token_named(&idp, "bob-sub-uuid", "bob", &[]);
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/clusters",
            HOST,
            &bob,
            create_body("pz", "proj-z"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}
