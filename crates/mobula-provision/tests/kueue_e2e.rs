//! Live Kueue e2e — requires a Kubernetes cluster with Kueue (v0.19.1) and
//! the KubeRay operator installed. Ignored by default; the `kueue-e2e`
//! workflow runs it with `--ignored` against a kind cluster. It exercises
//! the pool contract: apply a pool → quota admission admits the first
//! RayCluster and queues the second (combined demand exceeds nominal) →
//! delete the pool and observe cleanup.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use mobula_core::{
    AllocationSpec, ClusterId, ClusterSpec, ClusterState, FlavorSpec, PoolSpec, WorkerGroup,
};
use mobula_provision::{
    KubeRayProvisioner, KueueClient, PoolProvisioner, Provisioner, QueueAssignment,
};

fn pool() -> PoolSpec {
    PoolSpec {
        name: "e2e-pool".into(),
        flavors: vec![FlavorSpec {
            name: "cpu".into(),
            // Nominal 4 CPU; each cluster below demands 3 (head 1 + worker
            // 2), so the first admits and the second must queue.
            resources: BTreeMap::from([("cpu".to_string(), "4".to_string())]),
            node_labels: BTreeMap::new(),
            taints: vec![],
        }],
        cohort: "e2e-cohort".into(),
        fair_sharing_weight: 1.0,
        elastic: false,
    }
}

fn alloc(project: &str, namespace: &str) -> AllocationSpec {
    AllocationSpec {
        pool: "e2e-pool".into(),
        project: project.into(),
        namespace: namespace.into(),
        nominal: BTreeMap::new(),
        borrowing_limit: BTreeMap::new(),
        lending_limit: BTreeMap::new(),
    }
}

fn cluster_spec(name: &str, project: &str) -> ClusterSpec {
    ClusterSpec {
        name: name.into(),
        project: project.into(),
        ray_version: "2.57.0".into(),
        image: "rayproject/ray:2.57.0".into(),
        head_cpu: "1".into(),
        // Ray's head reserves object-store/GCS memory; 2.5Gi is a safe
        // floor on a kind node (same as the kuberay e2e).
        head_memory: "2560Mi".into(),
        worker_groups: vec![WorkerGroup {
            name: "cpu".into(),
            cpu: "2".into(),
            memory: "1Gi".into(),
            gpu: None,
            min_replicas: 1,
            max_replicas: 1,
            replicas: 1,
        }],
        ttl_seconds: None,
    }
}

async fn poll<T, Fut: std::future::Future<Output = Option<T>>>(
    what: &str,
    timeout: Duration,
    mut f: impl FnMut() -> Fut,
    step: Duration,
) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f().await {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(step).await;
    }
}

#[tokio::test]
#[ignore = "requires a cluster with Kueue and the KubeRay operator"]
async fn pool_admits_first_cluster_and_queues_the_second() {
    let ns = std::env::var("MOBULA_E2E_NAMESPACE").unwrap_or_else(|_| "default".into());
    let kueue = KueueClient::connect().await.expect("connect to cluster");
    let ray = KubeRayProvisioner::connect(ns.clone(), false)
        .await
        .expect("connect for KubeRay");

    assert!(
        kueue.kueue_present().await,
        "Kueue CRDs must be served (install Kueue first)"
    );

    // Apply the pool (idempotent: a second apply is a no-op at the API).
    let allocs = vec![alloc("e2e-a", &ns), alloc("e2e-b", &ns)];
    kueue
        .apply_pool(&pool(), &allocs)
        .await
        .expect("apply pool");
    kueue
        .apply_pool(&pool(), &allocs)
        .await
        .expect("second pool apply is idempotent");

    let id_a = ClusterId("e2e-pool-a".into());
    let id_b = ClusterId("e2e-pool-b".into());
    let qa = QueueAssignment {
        queue_name: "e2e-a".into(),
        elastic: false,
    };
    let qb = QueueAssignment {
        queue_name: "e2e-b".into(),
        elastic: false,
    };

    // Cluster A (3 CPU) fits within nominal 4 → admitted; its pods
    // schedule and KubeRay drives it to Running.
    ray.apply(
        &id_a,
        &cluster_spec("e2e-pool-a", "e2e-a"),
        1,
        "e2e/a/1",
        Some(&qa),
    )
    .await
    .expect("apply cluster A");
    poll(
        "cluster A admission",
        Duration::from_secs(180),
        || async {
            match kueue.observe_pool("e2e-pool").await {
                Ok(Some(o)) if o.admitted_workloads >= 1 => Some(o),
                _ => None,
            }
        },
        Duration::from_secs(5),
    )
    .await;
    // Image pulls dominate here (same budget as the kuberay e2e).
    poll(
        "cluster A running",
        Duration::from_secs(420),
        || async {
            match ray.observe(&id_a).await {
                Ok(o) if o.state == ClusterState::Running => Some(o),
                _ => None,
            }
        },
        Duration::from_secs(10),
    )
    .await;

    // Cluster B (another 3 CPU) exceeds the nominal quota → Kueue keeps its
    // Workload pending and the RayCluster suspended.
    ray.apply(
        &id_b,
        &cluster_spec("e2e-pool-b", "e2e-b"),
        1,
        "e2e/b/1",
        Some(&qb),
    )
    .await
    .expect("apply cluster B");
    let ledger = poll(
        "cluster B queueing",
        Duration::from_secs(120),
        || async {
            match kueue.observe_pool("e2e-pool").await {
                Ok(Some(o)) if o.pending_workloads >= 1 => Some(o),
                _ => None,
            }
        },
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        ledger.admitted_workloads, 1,
        "the second cluster must not be admitted over nominal quota"
    );
    let obs_b = ray.observe(&id_b).await.expect("observe cluster B");
    assert!(
        matches!(
            obs_b.state,
            ClusterState::Suspended | ClusterState::Provisioning
        ),
        "queued cluster stays pod-less (got {:?})",
        obs_b.state
    );

    // Teardown: clusters first, then the pool; the ClusterQueue must be
    // gone afterwards.
    ray.terminate(&id_a).await.expect("terminate A");
    ray.terminate(&id_b).await.expect("terminate B");
    kueue.delete_pool("e2e-pool").await.expect("delete pool");
    // Idempotent teardown.
    kueue
        .delete_pool("e2e-pool")
        .await
        .expect("delete pool again");
    poll(
        "pool cleanup",
        Duration::from_secs(60),
        || async {
            match kueue.observe_pool("e2e-pool").await {
                Ok(None) => Some(()),
                _ => None,
            }
        },
        Duration::from_secs(2),
    )
    .await;
}
