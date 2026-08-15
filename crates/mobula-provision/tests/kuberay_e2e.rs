//! Live KubeRay e2e — requires a Kubernetes cluster with the KubeRay
//! operator installed. Ignored by default; the `kuberay-e2e` workflow runs
//! it with `--ignored` against a kind cluster. It exercises the full
//! provisioner contract: apply → observe-until-ready → terminate.

use std::time::{Duration, Instant};

use mobula_core::{ClusterId, ClusterSpec, ClusterState, WorkerGroup};
use mobula_provision::{KubeRayProvisioner, Provisioner};

fn tiny_spec() -> ClusterSpec {
    ClusterSpec {
        name: "e2e-demo".into(),
        project: "e2e".into(),
        ray_version: "2.57.0".into(),
        image: "rayproject/ray:2.57.0".into(),
        // Ray's head reserves object-store/GCS memory; too little makes the
        // head pod crash-loop. 2.5Gi is a safe floor on a kind node.
        head_cpu: "1".into(),
        head_memory: "2560Mi".into(),
        // One real worker so the e2e actually exercises the worker path
        // (a prior worker-image bug was masked by a zero-worker e2e —
        // review R2#1). RayService/RayCluster only reports Running once the
        // worker schedules, so this asserts the worker manifest is valid.
        worker_groups: vec![WorkerGroup {
            name: "cpu".into(),
            cpu: "500m".into(),
            memory: "1Gi".into(),
            gpu: None,
            min_replicas: 1,
            max_replicas: 2,
            replicas: 1,
        }],
        ttl_seconds: None,
    }
}

#[tokio::test]
#[ignore = "requires a cluster with the KubeRay operator"]
async fn provisions_observes_and_terminates() {
    let ns = std::env::var("MOBULA_E2E_NAMESPACE").unwrap_or_else(|_| "default".into());
    let prov = KubeRayProvisioner::connect(ns, false)
        .await
        .expect("connect to cluster");
    let id = ClusterId("e2e-demo".into());

    // Idempotent apply.
    prov.apply(&id, &tiny_spec(), "e2e/1").await.expect("apply");
    prov.apply(&id, &tiny_spec(), "e2e/1")
        .await
        .expect("second apply is idempotent");

    // It should appear in the field-manager-scoped list immediately.
    let listed = prov.list().await.expect("list");
    assert!(
        listed.iter().any(|c| c.id == id),
        "applied cluster must be listed"
    );

    // Poll observe until the head reports Running (image pulls are slow).
    let deadline = Instant::now() + Duration::from_secs(420);
    let last;
    loop {
        let obs = prov.observe(&id).await.expect("observe");
        let state = obs.state;
        // The gateway target should be well-formed.
        assert!(obs
            .api_base_url
            .as_deref()
            .unwrap()
            .contains("e2e-demo-head-svc"));
        if state == ClusterState::Running {
            last = state;
            break;
        }
        assert!(
            Instant::now() < deadline,
            "cluster never reached Running (last: {state:?})"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    assert_eq!(last, ClusterState::Running);

    // Teardown is idempotent.
    prov.terminate(&id).await.expect("terminate");
    prov.terminate(&id)
        .await
        .expect("terminate again is a no-op");
}
