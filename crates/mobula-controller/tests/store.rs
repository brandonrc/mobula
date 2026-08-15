//! Store-conformance tests run against BOTH the in-memory and SQLite
//! implementations, so the sqlx-backed store is proven behaviourally
//! identical to the reference impl.

use mobula_controller::{DesiredState, InMemoryStore, SqliteStore, Store};
use mobula_core::{ClusterId, ClusterSpec, ClusterState, WorkerGroup};

fn spec(name: &str, replicas: u32) -> ClusterSpec {
    ClusterSpec {
        name: name.into(),
        project: "demo".into(),
        ray_version: "2.57.0".into(),
        image: "rayproject/ray:2.57.0".into(),
        head_cpu: "1".into(),
        head_memory: "2Gi".into(),
        worker_groups: vec![WorkerGroup {
            name: "cpu".into(),
            cpu: "1".into(),
            memory: "2Gi".into(),
            gpu: None,
            min_replicas: 0,
            max_replicas: 4,
            replicas,
        }],
        ttl_seconds: None,
    }
}

async fn conformance(store: &dyn Store) {
    let id = ClusterId("demo".into());

    // Insert → generation 1.
    assert_eq!(store.upsert_desired(&id, spec("demo", 1)).await.unwrap(), 1);
    // Same spec → generation unchanged.
    assert_eq!(store.upsert_desired(&id, spec("demo", 1)).await.unwrap(), 1);
    // Changed spec → generation bumps.
    assert_eq!(store.upsert_desired(&id, spec("demo", 3)).await.unwrap(), 2);

    let got = store.get(&id).await.unwrap().unwrap();
    assert_eq!(got.generation, 2);
    assert_eq!(got.desired, DesiredState::Running);
    assert_eq!(got.spec.worker_groups[0].replicas, 3);
    assert!(got.observed_state.is_none());

    // Observation round-trips.
    store
        .record_observation(&id, Some(ClusterState::Running), 2)
        .await
        .unwrap();
    let got = store.get(&id).await.unwrap().unwrap();
    assert_eq!(got.observed_state, Some(ClusterState::Running));
    assert_eq!(got.observed_generation, 2);

    // Desired flip.
    store
        .set_desired(&id, DesiredState::Terminated)
        .await
        .unwrap();
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().desired,
        DesiredState::Terminated
    );

    // list.
    assert_eq!(store.list().await.unwrap().len(), 1);

    // Intent outbox: first claim true, repeat false (stable key dedup).
    assert!(store.record_intent("demo/2").await.unwrap());
    assert!(!store.record_intent("demo/2").await.unwrap());
    assert!(store.record_intent("demo/3").await.unwrap());

    // set_desired on a missing cluster errors.
    assert!(store
        .set_desired(&ClusterId("ghost".into()), DesiredState::Running)
        .await
        .is_err());
}

#[tokio::test]
async fn in_memory_store_conforms() {
    conformance(&InMemoryStore::new()).await;
}

#[tokio::test]
async fn sqlite_store_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    conformance(&store).await;
}

#[tokio::test]
async fn sqlite_persists_across_reopen() {
    let dir = std::env::temp_dir().join(format!("mobula-store-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("state.db");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let id = ClusterId("demo".into());

    {
        let store = SqliteStore::connect(&url).await.unwrap();
        store.upsert_desired(&id, spec("demo", 2)).await.unwrap();
        store
            .record_observation(&id, Some(ClusterState::Running), 1)
            .await
            .unwrap();
    }
    // Reopen: desired state and observation survive (ADR-0004: durable).
    {
        let store = SqliteStore::connect(&url).await.unwrap();
        let got = store.get(&id).await.unwrap().unwrap();
        assert_eq!(got.spec.worker_groups[0].replicas, 2);
        assert_eq!(got.observed_state, Some(ClusterState::Running));
    }
    std::fs::remove_dir_all(&dir).ok();
}
