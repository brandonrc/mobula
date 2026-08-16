//! Full control-loop integration test: the real HTTP API, a real store, and
//! a live reconcile loop wired together in one process — the "everything
//! works together" proof that per-component tests don't give. Drives the
//! actual `/api/v1/clusters` surface and asserts the background reconciler
//! converges the cluster, all through the same store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use mobula_controller::{InMemoryStore, Reconciler};
use mobula_core::{ClusterId, ClusterSpec, ClusterState};
use mobula_provision::{ObservedCluster, ProvisionError, Provisioner};
use tower::ServiceExt;

/// Mock provisioner: `apply` brings a cluster to Running, `observe` reports
/// current state. Stands in for KubeRay so the test needs no cluster.
#[derive(Default)]
struct MockProvisioner {
    state: Mutex<HashMap<String, ClusterState>>,
}

#[async_trait]
impl Provisioner for MockProvisioner {
    async fn apply(&self, id: &ClusterId, _: &ClusterSpec, _: &str) -> Result<(), ProvisionError> {
        self.state
            .lock()
            .unwrap()
            .insert(id.0.clone(), ClusterState::Running);
        Ok(())
    }
    async fn terminate(&self, id: &ClusterId) -> Result<(), ProvisionError> {
        self.state
            .lock()
            .unwrap()
            .insert(id.0.clone(), ClusterState::Terminated);
        Ok(())
    }
    async fn observe(&self, id: &ClusterId) -> Result<ObservedCluster, ProvisionError> {
        match self.state.lock().unwrap().get(&id.0) {
            Some(state) => Ok(ObservedCluster {
                id: id.clone(),
                state: *state,
                api_base_url: None,
            }),
            None => Err(ProvisionError::NotFound(id.clone())),
        }
    }
    async fn list(&self) -> Result<Vec<ObservedCluster>, ProvisionError> {
        Ok(vec![])
    }
}

fn create_body() -> serde_json::Value {
    serde_json::json!({
        "id": "loop-demo",
        "spec": {
            "name": "loop-demo", "project": "demo", "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0", "head_cpu": "1", "head_memory": "2Gi",
            "worker_groups": [], "ttl_seconds": null
        }
    })
}

#[tokio::test]
async fn api_create_flows_through_store_and_reconcile_to_running() {
    // One store shared by the API and the reconcile loop — exactly the CLI's
    // wiring, minus the KubeRay provisioner.
    let store = Arc::new(InMemoryStore::new());
    let prov = Arc::new(MockProvisioner::default());
    let reconciler = Reconciler::new(store.clone(), prov.clone());

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let loop_handle = tokio::spawn(async move {
        reconciler
            .run(Duration::from_millis(20), async {
                let _ = rx.await;
            })
            .await;
    });

    // Dev/no-auth app (validator None) mounted on the shared store.
    let app = mobula_api::build_app_full(
        mobula_core::ClusterRegistry::default(),
        None,
        Some(store.clone()),
        Default::default(),
    );

    // 1. Create a cluster via the real HTTP API.
    let res = app
        .clone()
        .oneshot(
            Request::post("/api/v1/clusters")
                .header(header::HOST, "mobula.local")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(create_body().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create accepted");

    // 2. The background reconcile loop should converge it to Running without
    //    any further API call — poll GET until it does (or time out).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut observed = None;
    while std::time::Instant::now() < deadline {
        let res = app
            .clone()
            .oneshot(
                Request::get("/api/v1/clusters/loop-demo")
                    .header(header::HOST, "mobula.local")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        if res.status() == StatusCode::OK {
            let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if v["observed_state"] == "running" {
                observed = Some(v);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let v = observed.expect("reconcile loop should drive the cluster to running via the API");
    assert_eq!(v["observed_state"], "running");
    assert_eq!(v["desired"], "running");

    // 3. Delete via the API → reconcile loop tears it down.
    let res = app
        .clone()
        .oneshot(
            Request::delete("/api/v1/clusters/loop-demo")
                .header(header::HOST, "mobula.local")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut terminated = false;
    while std::time::Instant::now() < deadline {
        if prov.state.lock().unwrap().get("loop-demo") == Some(&ClusterState::Terminated) {
            terminated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        terminated,
        "delete should flow through the loop to terminate"
    );

    let _ = store;
    tx.send(()).ok();
    let _ = tokio::time::timeout(Duration::from_secs(2), loop_handle).await;
}
