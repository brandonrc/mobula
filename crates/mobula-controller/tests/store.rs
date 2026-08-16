//! Store-conformance tests run against BOTH the in-memory and SQLite
//! implementations, so the sqlx-backed store is proven behaviourally
//! identical to the reference impl.

use mobula_controller::{
    DesiredState, InMemoryStore, IntentOutcome, IntentStatus, SqliteStore, Store,
};
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

    // Transactional outbox (ADR-0007, #39): a fresh key proceeds; a
    // same-fingerprint re-open proceeds as a replay (drift/crash re-apply);
    // a different fingerprint for the same key is a stale/conflicting
    // generation and is rejected.
    assert_eq!(
        store.begin_intent("demo/2", "fp-a").await.unwrap(),
        IntentOutcome::Proceed { replay: false }
    );
    assert_eq!(
        store.begin_intent("demo/2", "fp-a").await.unwrap(),
        IntentOutcome::Proceed { replay: true }
    );
    assert_eq!(
        store.begin_intent("demo/2", "fp-b").await.unwrap(),
        IntentOutcome::ParamMismatch
    );
    // Completing stores the provider response and flips status → Applied.
    store
        .complete_intent("demo/2", "{\"generation\":2}")
        .await
        .unwrap();
    let rec = store.get_intent("demo/2").await.unwrap().unwrap();
    assert_eq!(rec.status, IntentStatus::Applied);
    assert_eq!(rec.response_json.as_deref(), Some("{\"generation\":2}"));
    assert_eq!(rec.params_fingerprint, "fp-a");
    // Reap only removes Applied rows older than the cutoff. completed_at is
    // ~now, so a cutoff of 0 removes nothing; a far-future cutoff removes it.
    assert_eq!(store.reap_intents(0).await.unwrap(), 0);
    assert_eq!(store.reap_intents(32_503_680_000).await.unwrap(), 1);
    assert!(store.get_intent("demo/2").await.unwrap().is_none());

    // Monotonic observed-generation fence (#41): a stale (older) observation
    // must not roll the stored generation backwards.
    store
        .record_observation(&id, Some(ClusterState::Running), 5)
        .await
        .unwrap();
    store
        .record_observation(&id, Some(ClusterState::Running), 2)
        .await
        .unwrap();
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().observed_generation,
        5,
        "stale observation must not roll observed_generation back"
    );

    // Drift condition round-trips (#41/#47).
    store
        .set_condition(&id, Some(mobula_core::DriftCondition::SpecDrift))
        .await
        .unwrap();
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().condition,
        Some(mobula_core::DriftCondition::SpecDrift)
    );
    store.set_condition(&id, None).await.unwrap();
    assert_eq!(store.get(&id).await.unwrap().unwrap().condition, None);

    // Quarantine flag round-trips (#41).
    assert!(!store.is_quarantined().await.unwrap());
    store.set_quarantine(true).await.unwrap();
    assert!(store.is_quarantined().await.unwrap());
    store.set_quarantine(false).await.unwrap();
    assert!(!store.is_quarantined().await.unwrap());

    // Backoff state round-trips (#43).
    store.record_attempt(&id, 3, 12_345).await.unwrap();
    let got = store.get(&id).await.unwrap().unwrap();
    assert_eq!(got.failure_count, 3);
    assert_eq!(got.next_attempt_at, 12_345);
    // A fresh upsert (unchanged spec) preserves the backoff state.
    store.upsert_desired(&id, spec("demo", 3)).await.unwrap();
    assert_eq!(store.get(&id).await.unwrap().unwrap().failure_count, 3);

    // Job history round-trips and is independent of clusters (#20/Phase 3).
    store
        .record_job(mobula_core::JobRecord {
            id: "raysubmit_1".into(),
            cluster: "gone-cluster".into(),
            submitter: "user@x".into(),
            status: "RUNNING".into(),
            duration_secs: None,
            submitted_at: 1000,
        })
        .await
        .unwrap();
    // Re-record with the same id updates status/duration (terminal).
    store
        .record_job(mobula_core::JobRecord {
            id: "raysubmit_1".into(),
            cluster: "gone-cluster".into(),
            submitter: "user@x".into(),
            status: "SUCCEEDED".into(),
            duration_secs: Some(42),
            submitted_at: 1000,
        })
        .await
        .unwrap();
    let jobs = store.list_jobs().await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "SUCCEEDED");
    assert_eq!(jobs[0].duration_secs, Some(42));
    assert_eq!(jobs[0].cluster, "gone-cluster");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_distinct_upserts_do_not_collapse_generation() {
    // #42: two concurrent upserts of DIFFERENT specs on the same id must
    // produce two distinct generation bumps (1 → 3), not collapse into one
    // (or throw SQLITE_BUSY). A file-backed pool with the default
    // (multi-connection) options lets the two upserts run on separate
    // connections; `in_memory()` pins max_connections=1 and so can't race.
    let dir = std::env::temp_dir().join(format!("mobula-upsert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("race.db");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let store = std::sync::Arc::new(SqliteStore::connect(&url).await.unwrap());
    let id = ClusterId("demo".into());
    store.upsert_desired(&id, spec("demo", 1)).await.unwrap(); // gen 1

    let (s1, s2) = (store.clone(), store.clone());
    let (i1, i2) = (id.clone(), id.clone());
    let a = tokio::spawn(async move { s1.upsert_desired(&i1, spec("demo", 2)).await });
    let b = tokio::spawn(async move { s2.upsert_desired(&i2, spec("demo", 5)).await });
    a.await.unwrap().unwrap();
    b.await.unwrap().unwrap();

    // Both changed the spec; BEGIN IMMEDIATE serializes them so each sees the
    // other's committed bump. Under the old DEFERRED tx both read gen=1 and
    // wrote gen=2 (collapsed) or the second threw SQLITE_BUSY.
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().generation,
        3,
        "two distinct concurrent spec changes must yield two generation bumps"
    );
    std::fs::remove_dir_all(&dir).ok();
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
