//! A mock `kube::Client` for unit tests (feature `kuberay`, test-only).
//!
//! `kube::Client::new` accepts any `tower::Service<Request<Body>>`, so instead
//! of talking to a real API server we hand it a `service_fn` that answers
//! canned Kubernetes JSON keyed by (HTTP method, resource in the URL path).
//! Every request is also recorded, so a test can assert *which* backend a
//! [`crate::router::EngineRouter`] call actually dispatched to (Ray touches
//! `/rayclusters`, Dask touches `/daskclusters` + `/pods`).
//!
//! This is what lets `router.rs` and the I/O glue in `dask_client.rs` be
//! covered without a live cluster; the `kuberay-e2e`/`kueue-e2e` workflows
//! exercise the real API server.

use std::sync::{Arc, Mutex};

use http::{Request, Response};
use kube::client::Body;
use kube::Client;
use serde_json::{json, Value};

/// Recorded requests as `(method, path?query)`, newest last.
pub type Recorder = Arc<Mutex<Vec<(String, String)>>>;

/// What the mock API server "contains". Every field defaults to empty/absent.
#[derive(Clone, Default)]
pub struct Fixture {
    /// The single DaskCluster a `GET .../daskclusters/<id>` returns; `None`
    /// ⇒ 404 (the CRD is served but the object is absent, or — from the
    /// router's point of view — this is not a Dask cluster).
    pub daskcluster: Option<Value>,
    /// The single RayCluster a `GET .../rayclusters/<id>` returns; `None` ⇒ 404.
    pub raycluster: Option<Value>,
    /// Pods returned by any `GET .../pods` list (the operator-owned pods).
    pub pods: Vec<Value>,
    /// Items returned by `GET .../daskclusters` (list, no name in the path).
    pub dask_list: Vec<Value>,
    /// Items returned by `GET .../rayclusters` (list).
    pub ray_list: Vec<Value>,
}

/// Build a mock [`Client`] over `fx`, plus the [`Recorder`] capturing every
/// request the client makes. The client's default namespace is `test-ns`.
pub fn mock_client(fx: Fixture) -> (Client, Recorder) {
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let rec = recorder.clone();
    let service = tower::service_fn(move |req: Request<Body>| {
        let fx = fx.clone();
        let rec = rec.clone();
        async move {
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let full = match req.uri().query() {
                Some(q) => format!("{path}?{q}"),
                None => path.clone(),
            };
            rec.lock()
                .expect("recorder lock")
                .push((method.clone(), full));
            let (code, body) = route(&fx, &method, &path);
            let resp = Response::builder()
                .status(code)
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&body).expect("serialize body"),
                ))
                .expect("build response");
            Ok::<_, std::convert::Infallible>(resp)
        }
    });
    (Client::new(service, "test-ns"), recorder)
}

/// Canned k8s response for one request, keyed on the resource in the path.
fn route(fx: &Fixture, method: &str, path: &str) -> (u16, Value) {
    if path.contains("/daskclusters") {
        let single = path.contains("/daskclusters/");
        match method {
            "GET" if single => match &fx.daskcluster {
                Some(v) => (200, v.clone()),
                None => (404, status_not_found("daskclusters")),
            },
            "GET" => (200, list_of("DaskClusterList", &fx.dask_list)),
            "PATCH" => (200, object("kubernetes.dask.org/v1", "DaskCluster")),
            "DELETE" => (200, object("kubernetes.dask.org/v1", "DaskCluster")),
            _ => (200, json!({})),
        }
    } else if path.contains("/rayclusters") {
        let single = path.contains("/rayclusters/");
        match method {
            "GET" if single => match &fx.raycluster {
                Some(v) => (200, v.clone()),
                None => (404, status_not_found("rayclusters")),
            },
            "GET" => (200, list_of("RayClusterList", &fx.ray_list)),
            "PATCH" => (200, object("ray.io/v1", "RayCluster")),
            "DELETE" => (200, object("ray.io/v1", "RayCluster")),
            _ => (200, json!({})),
        }
    } else if path.contains("/networkpolicies") {
        match method {
            // No admin-managed default-deny present ⇒ Mobula manages posture.
            "GET" => (200, list_of("NetworkPolicyList", &[])),
            "PATCH" => (200, object("networking.k8s.io/v1", "NetworkPolicy")),
            "DELETE" => (200, object("networking.k8s.io/v1", "NetworkPolicy")),
            _ => (200, json!({})),
        }
    } else if path.contains("/pods") {
        (200, list_of("PodList", &fx.pods))
    } else {
        (200, json!({}))
    }
}

/// A minimal valid object (apiVersion/kind/metadata) that deserializes as a
/// `DynamicObject`. Content is irrelevant to the callers that ignore the
/// returned object (apply/delete).
fn object(api_version: &str, kind: &str) -> Value {
    json!({
        "apiVersion": api_version,
        "kind": kind,
        "metadata": { "name": "mock", "namespace": "test-ns" },
    })
}

/// An `ObjectList` wrapper the dynamic API deserializes.
fn list_of(kind: &str, items: &[Value]) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": kind,
        "metadata": { "resourceVersion": "1" },
        "items": items,
    })
}

/// A `Status` body for a 404 so `get_opt` maps it to `None` / a 404 delete is
/// treated as already-gone.
fn status_not_found(resource: &str) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Status",
        "status": "Failure",
        "message": format!("{resource} not found"),
        "reason": "NotFound",
        "code": 404,
    })
}

/// A DaskCluster CR value carrying a generation annotation, an owned-field
/// spec (so `fingerprint_from_cr` projects one), and an optional status phase.
pub fn daskcluster_cr(name: &str, generation: u64, phase: Option<&str>) -> Value {
    let mut cr = json!({
        "apiVersion": "kubernetes.dask.org/v1",
        "kind": "DaskCluster",
        "metadata": {
            "name": name,
            "namespace": "test-ns",
            "annotations": { "mobula.dev/generation": generation.to_string() },
        },
        "spec": {
            "scheduler": { "spec": { "containers": [ {
                "image": "ghcr.io/dask/dask:latest",
                "resources": { "requests": { "cpu": "1", "memory": "2Gi" } },
            } ] } },
            "worker": { "spec": { "containers": [ {
                "image": "ghcr.io/dask/dask:latest",
                "resources": { "requests": { "cpu": "2", "memory": "4Gi" } },
            } ] } },
        },
    });
    if let Some(phase) = phase {
        cr["status"] = json!({ "phase": phase });
    }
    cr
}

/// A dask operator-owned pod value (scheduler or worker) for the pod-based
/// readiness / node-breakdown paths.
pub fn dask_pod(cluster: &str, component: &str, phase: &str, ready: bool) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": format!("{cluster}-{component}"),
            "namespace": "test-ns",
            "labels": {
                "dask.org/cluster-name": cluster,
                "dask.org/component": component,
                "mobula.dev/cluster-id": cluster,
            },
        },
        "status": {
            "phase": phase,
            "conditions": [ { "type": "Ready", "status": if ready { "True" } else { "False" } } ],
        },
    })
}
