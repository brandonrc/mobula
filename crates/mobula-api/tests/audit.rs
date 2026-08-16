//! Audit trail endpoint tests (api-v1.md §5.9): events are seeded by driving
//! REAL requests through the authed app (a denied viewer write, an admin
//! cluster create, a proxied gateway request, a token-less call), then
//! filtered, paginated, and CSV-exported through `GET /api/v1/audit`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use mobula_controller::Store;
use mobula_core::{ClusterEndpoint, ClusterId, ClusterRegistry};
use tower::ServiceExt;

const CP_HOST: &str = "mobula.example.com";

/// A mock Ray head that answers every proxied call 200 with canned JSON.
async fn spawn_mock_ray_head() -> SocketAddr {
    let app = Router::new().fallback(|| async {
        (
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"mock":"ray-head"}"#,
        )
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Authed app with a store AND a registered cluster whose api_base_url is
/// the mock Ray head, so gateway traffic produces audit rows.
async fn app(idp: &common::Idp, store: Arc<dyn Store>, head: SocketAddr) -> Router {
    let config = mobula_auth::AuthConfig {
        issuer: idp.issuer.clone(),
        audience: "mobula".into(),
        groups_claim: "groups".into(),
        roles: mobula_auth::RoleMappings {
            admin: vec!["/platform-admins".into()],
            operator: vec!["/sre".into()],
            developer: vec!["/ml-eng".into()],
            viewer: vec!["/observers".into()],
        },
    };
    let validator = mobula_auth::Validator::discover(config, reqwest::Client::new(), true)
        .await
        .unwrap();
    mobula_api::build_app_full(
        ClusterRegistry {
            clusters: vec![ClusterEndpoint {
                id: ClusterId("demo".into()),
                hostname: "demo.ray.test".into(),
                api_base_url: format!("http://{head}"),
                auth_token: None,
            }],
        },
        Some(Arc::new(validator)),
        Some(store),
        Default::default(),
    )
}

fn create_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "spec": {
            "name": id, "project": "demo", "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0", "head_cpu": "1",
            "head_memory": "2Gi", "worker_groups": [], "ttl_seconds": null
        }
    })
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Seed four events in order: (1) a denied viewer write, (2) an admin
/// cluster create, (3) a proxied gateway request, (4) a token-less call.
async fn seed_events(app: &Router, admin: &str, viewer: &str) {
    let res = app
        .clone()
        .oneshot(common::post_json(
            "/api/v1/clusters",
            CP_HOST,
            viewer,
            create_body("denied-c"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    let res = app
        .clone()
        .oneshot(common::post_json(
            "/api/v1/clusters",
            CP_HOST,
            admin,
            create_body("audit-c"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let res = app
        .clone()
        .oneshot(
            Request::get("/api/jobs/?filter=running")
                .header(header::HOST, "demo.ray.test")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(common::get("/api/v1/clusters", CP_HOST, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

async fn audit_query(app: &Router, admin: &str, query: &str) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(common::get(
            &format!("/api/v1/audit{query}"),
            CP_HOST,
            Some(admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "query {query}");
    body_json(res).await
}

#[tokio::test]
async fn seeded_requests_become_filtered_audit_rows() {
    let idp = common::spawn_idp().await;
    let admin = common::idp_token(&idp, &["/platform-admins"]);
    let viewer = common::idp_token(&idp, &["/observers"]);
    let store: Arc<dyn Store> = Arc::new(mobula_controller::InMemoryStore::new());
    let head = spawn_mock_ray_head().await;
    let app = app(&idp, store, head).await;
    seed_events(&app, &admin, &viewer).await;

    // Full list: 4 rows, newest first (missing-token, gateway, create,
    // viewer denial); the envelope carries next_cursor.
    let page = audit_query(&app, &admin, "").await;
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 4, "{page}");
    assert!(page["next_cursor"].is_null());

    // Row 4 (newest): authn failure — subject is null, never invented.
    assert_eq!(items[0]["decision"], "deny");
    assert_eq!(items[0]["reason"], "missing_token");
    assert!(items[0]["subject"].is_null());
    assert_eq!(items[0]["status"], 401);
    assert_eq!(items[0]["path"], "/api/v1/clusters");

    // Row 3: the proxied gateway request, with method/path/status/latency.
    assert_eq!(items[1]["decision"], "allow");
    assert_eq!(items[1]["cluster"], "demo");
    assert_eq!(items[1]["method"], "GET");
    assert_eq!(items[1]["path"], "/api/jobs/");
    assert_eq!(items[1]["status"], 200);
    assert!(items[1]["latency_ms"].is_number());
    assert!(items[1]["action"].is_null());
    assert!(items[1]["reason"].is_null());

    // Row 2: the admin cluster create.
    assert_eq!(items[2]["decision"], "allow");
    assert_eq!(items[2]["action"], "create_cluster");
    assert_eq!(items[2]["cluster"], "audit-c");
    assert_eq!(items[2]["subject"], "user-123");
    assert_eq!(items[2]["status"], 201);

    // Row 1 (oldest): the denied viewer write, with required/granted detail.
    assert_eq!(items[3]["decision"], "deny");
    assert_eq!(items[3]["reason"], "insufficient_permission");
    assert_eq!(items[3]["subject"], "user-123");
    assert_eq!(items[3]["status"], 403);
    assert_eq!(items[3]["required"]["action"], "write");
    assert_eq!(items[3]["required"]["target"], "cluster");
    assert_eq!(items[3]["granted_roles"], serde_json::json!(["viewer"]));

    // Filters.
    let deny = audit_query(&app, &admin, "?decision=deny").await;
    assert_eq!(deny["items"].as_array().unwrap().len(), 2);
    let allow = audit_query(&app, &admin, "?decision=allow").await;
    assert_eq!(allow["items"].as_array().unwrap().len(), 2);

    let by_subject = audit_query(&app, &admin, "?subject=user-123").await;
    assert_eq!(by_subject["items"].as_array().unwrap().len(), 3);

    // min_status excludes status-less rows; the 200/201 rows fall out.
    let errors = audit_query(&app, &admin, "?min_status=400").await;
    let statuses: Vec<u64> = errors["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["status"].as_u64().unwrap())
        .collect();
    assert_eq!(statuses, [401, 403]);

    let gw = audit_query(&app, &admin, "?cluster=demo").await;
    assert_eq!(gw["items"].as_array().unwrap().len(), 1);
    // method=GET matches the gateway row AND the token-less GET 401.
    let gets = audit_query(&app, &admin, "?method=GET").await;
    assert_eq!(gets["items"].as_array().unwrap().len(), 2);
    // Handler-emitted rows (authorize denials, mutations) carry action/
    // cluster, not method/path — those live on gateway and authn rows.
    let posts = audit_query(&app, &admin, "?method=POST").await;
    assert_eq!(posts["items"].as_array().unwrap().len(), 0);
    let gw = audit_query(&app, &admin, "?path_prefix=/api/jobs").await;
    assert_eq!(gw["items"].as_array().unwrap().len(), 1);
    let mt = audit_query(&app, &admin, "?reason=missing_token").await;
    assert_eq!(mt["items"].as_array().unwrap().len(), 1);

    // Time windows: everything happened "now".
    let now = mobula_controller::now_unix();
    let future = audit_query(&app, &admin, &format!("?from={}", now + 3600)).await;
    assert!(future["items"].as_array().unwrap().is_empty());
    let past = audit_query(&app, &admin, "?to=1000").await;
    assert!(past["items"].as_array().unwrap().is_empty());
    let window = audit_query(&app, &admin, &format!("?from={}&to={}", now - 60, now + 60)).await;
    assert_eq!(window["items"].as_array().unwrap().len(), 4);
}

#[tokio::test]
async fn bad_query_params_are_400() {
    let idp = common::spawn_idp().await;
    let admin = common::idp_token(&idp, &["/platform-admins"]);
    let store: Arc<dyn Store> = Arc::new(mobula_controller::InMemoryStore::new());
    let head = spawn_mock_ray_head().await;
    let app = app(&idp, store, head).await;

    for query in [
        "?from=5&to=1",      // window inverted
        "?decision=bogus",   // unknown enum value
        "?limit=abc",        // non-numeric
        "?cursor=-1",        // wrong type
        "?format=json",      // unknown export format
        "?min_status=99999", // out of u16 range
    ] {
        let res = app
            .clone()
            .oneshot(common::get(
                &format!("/api/v1/audit{query}"),
                CP_HOST,
                Some(&admin),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST, "query {query}");
    }
}

#[tokio::test]
async fn cursor_pagination_walks_pages_without_overlap() {
    let idp = common::spawn_idp().await;
    let admin = common::idp_token(&idp, &["/platform-admins"]);
    let viewer = common::idp_token(&idp, &["/observers"]);
    let store: Arc<dyn Store> = Arc::new(mobula_controller::InMemoryStore::new());
    let head = spawn_mock_ray_head().await;
    let app = app(&idp, store, head).await;
    seed_events(&app, &admin, &viewer).await;

    // Page 1: two newest rows plus a cursor.
    let page1 = audit_query(&app, &admin, "?limit=2").await;
    let items1 = page1["items"].as_array().unwrap();
    assert_eq!(items1.len(), 2);
    let cursor = page1["next_cursor"].as_u64().expect("more rows exist");

    // Page 2 from the cursor: the remaining two, no overlap, end of stream.
    let page2 = audit_query(&app, &admin, &format!("?limit=2&cursor={cursor}")).await;
    let items2 = page2["items"].as_array().unwrap();
    assert_eq!(items2.len(), 2);
    assert!(page2["next_cursor"].is_null());

    // Page 1 rows both carry a path (authn failure, gateway); page 2 holds
    // the handler rows (create allow, viewer deny) which use action/reason.
    let paths1: Vec<&str> = items1.iter().filter_map(|i| i["path"].as_str()).collect();
    assert_eq!(paths1, ["/api/v1/clusters", "/api/jobs/"]);
    assert_eq!(items2[0]["action"], "create_cluster");
    assert_eq!(items2[1]["reason"], "insufficient_permission");
    // The union covers every seeded row exactly once.
    let all: Vec<&serde_json::Value> = items1.iter().chain(items2.iter()).collect();
    assert_eq!(all.len(), 4);
    let decisions: Vec<&str> = all.iter().filter_map(|i| i["decision"].as_str()).collect();
    assert_eq!(decisions, ["deny", "allow", "allow", "deny"]);
}

#[tokio::test]
async fn csv_export_has_a_header_and_one_line_per_row() {
    let idp = common::spawn_idp().await;
    let admin = common::idp_token(&idp, &["/platform-admins"]);
    let viewer = common::idp_token(&idp, &["/observers"]);
    let store: Arc<dyn Store> = Arc::new(mobula_controller::InMemoryStore::new());
    let head = spawn_mock_ray_head().await;
    let app = app(&idp, store, head).await;
    seed_events(&app, &admin, &viewer).await;

    let res = app
        .oneshot(common::get(
            "/api/v1/audit?format=csv&decision=deny",
            CP_HOST,
            Some(&admin),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()[header::CONTENT_TYPE],
        "text/csv; charset=utf-8"
    );
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[0],
        "seq,ts,subject,decision,reason,action,cluster,method,path,status,latency_ms,required_action,required_target,granted_roles"
    );
    // decision=deny → two data rows (missing_token, viewer denial).
    assert_eq!(lines.len(), 3, "{text}");
    assert!(lines[1].contains(",deny,missing_token,"), "{}", lines[1]);
    assert!(
        lines[2].contains(",deny,insufficient_permission,")
            && lines[2].ends_with(",write,cluster,viewer"),
        "{}",
        lines[2]
    );
}

#[tokio::test]
async fn audit_endpoint_is_admin_only() {
    let idp = common::spawn_idp().await;
    let admin = common::idp_token(&idp, &["/platform-admins"]);
    let store: Arc<dyn Store> = Arc::new(mobula_controller::InMemoryStore::new());
    let head = spawn_mock_ray_head().await;
    let app = app(&idp, store, head).await;

    // No token → 401; every non-admin role → 403.
    let res = app
        .clone()
        .oneshot(common::get("/api/v1/audit", CP_HOST, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    for groups in [&["/sre"][..], &["/ml-eng"][..], &["/observers"][..]] {
        let token = common::idp_token(&idp, groups);
        let res = app
            .clone()
            .oneshot(common::get("/api/v1/audit", CP_HOST, Some(&token)))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "groups {groups:?} must not read the audit trail"
        );
    }

    // The denials themselves are audit rows: three insufficient_permission
    // entries (one per non-admin probe), readable by the admin.
    let page = audit_query(
        &app,
        &admin,
        "?decision=deny&reason=insufficient_permission",
    )
    .await;
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "{page}");
    assert_eq!(items[0]["required"]["action"], "admin");
    assert_eq!(items[0]["required"]["target"], "cluster");
    assert_eq!(items[0]["granted_roles"], serde_json::json!(["viewer"]));
}

#[tokio::test]
async fn store_failures_degrade_not_break_requests() {
    let idp = common::spawn_idp().await;
    let admin = common::idp_token(&idp, &["/platform-admins"]);
    let store = Arc::new(common::FailingStore::new());
    let head = spawn_mock_ray_head().await;
    let app = app(&idp, store.clone(), head).await;

    // A failed audit write must NEVER fail the audited request.
    store.fail("record_audit");
    let res = app
        .clone()
        .oneshot(common::post_json(
            "/api/v1/clusters",
            CP_HOST,
            &admin,
            create_body("audit-c"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // A failed audit read is a 500 on the audit endpoint.
    store.fail("list_audit");
    let res = app
        .oneshot(common::get("/api/v1/audit", CP_HOST, Some(&admin)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
