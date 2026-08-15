//! Serve-service API tests against a mock ServiceProvisioner (no cluster
//! needed), covering the Target::Service RBAC: Developer deploys code,
//! Operator/Viewer are read-only.

mod common;
use common::{authed_app_with_services, get, idp_token, post_json, spawn_idp};

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::http::StatusCode;
use mobula_core::{ClusterState, ServiceSpec};
use mobula_provision::{ObservedService, ProvisionError, ServiceProvisioner};
use tower::ServiceExt;

#[derive(Default)]
struct MockServices {
    deployed: Mutex<Vec<String>>,
}

#[async_trait]
impl ServiceProvisioner for MockServices {
    async fn deploy(&self, name: &str, _spec: &ServiceSpec) -> Result<(), ProvisionError> {
        self.deployed.lock().unwrap().push(name.to_string());
        Ok(())
    }
    async fn get(&self, name: &str) -> Result<Option<ObservedService>, ProvisionError> {
        Ok(Some(ObservedService {
            name: name.to_string(),
            state: ClusterState::Running,
            url: Some(format!("http://{name}-serve-svc:8000")),
        }))
    }
    async fn delete(&self, _name: &str) -> Result<(), ProvisionError> {
        Ok(())
    }
    async fn list(&self) -> Result<Vec<ObservedService>, ProvisionError> {
        Ok(self
            .deployed
            .lock()
            .unwrap()
            .iter()
            .map(|n| ObservedService {
                name: n.clone(),
                state: ClusterState::Running,
                url: None,
            })
            .collect())
    }
}

fn deploy_body(name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "spec": {
            "name": name, "project": "demo", "ray_version": "2.57.0",
            "image": "rayproject/ray:2.57.0",
            "serve_config_v2": "applications:\n  - name: app\n",
            "head_cpu": "1", "head_memory": "2Gi",
            "worker_replicas": 1, "worker_cpu": "1", "worker_memory": "2Gi",
            "upgrade": "canary"
        }
    })
}

#[tokio::test]
async fn developer_deploys_service_operator_cannot() {
    let idp = spawn_idp().await;
    let prov = Arc::new(MockServices::default());
    let app = authed_app_with_services(&idp, prov.clone()).await;

    let developer = idp_token(&idp, &["/ml-eng"]);
    let operator = idp_token(&idp, &["/sre"]);

    // Operator (lifecycle, not code) cannot deploy a Serve app.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/services",
            "mobula.example.com",
            &operator,
            deploy_body("op-attempt"),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "operator cannot deploy code"
    );

    // Developer can.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/services",
            "mobula.example.com",
            &developer,
            deploy_body("recommender"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(prov.deployed.lock().unwrap().as_slice(), &["recommender"]);

    // Operator CAN read (list).
    let res = app
        .oneshot(get(
            "/api/v1/services",
            "mobula.example.com",
            Some(&operator),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn service_get_and_auth_gates() {
    let idp = spawn_idp().await;
    let prov = Arc::new(MockServices::default());
    let app = authed_app_with_services(&idp, prov).await;

    // No token → 401.
    let res = app
        .clone()
        .oneshot(get("/api/v1/services/x", "mobula.example.com", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Viewer can read a service.
    let viewer = idp_token(&idp, &["/observers"]);
    let res = app
        .oneshot(get(
            "/api/v1/services/recommender",
            "mobula.example.com",
            Some(&viewer),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["name"], "recommender");
    assert_eq!(v["state"], "running");
}
