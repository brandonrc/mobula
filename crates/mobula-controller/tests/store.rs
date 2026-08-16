//! Store-conformance tests run against BOTH the in-memory and SQLite
//! implementations, so the sqlx-backed store is proven behaviourally
//! identical to the reference impl.

use mobula_controller::{
    DesiredState, InMemoryStore, IntentOutcome, IntentStatus, SqliteStore, Store,
};
use mobula_core::{
    AllocationSpec, ClusterId, ClusterSpec, ClusterState, FlavorSpec, PoolSpec, WorkerGroup,
};
use std::collections::BTreeMap;

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

fn pool_spec(name: &str, weight: f64) -> PoolSpec {
    PoolSpec {
        name: name.into(),
        flavors: vec![FlavorSpec {
            name: "a100".into(),
            resources: BTreeMap::from([
                ("cpu".to_string(), "64".to_string()),
                ("nvidia.com/gpu".to_string(), "8".to_string()),
            ]),
            node_labels: BTreeMap::new(),
            taints: vec![],
        }],
        cohort: "research".into(),
        fair_sharing_weight: weight,
        elastic: true,
    }
}

fn alloc(pool: &str, project: &str) -> AllocationSpec {
    AllocationSpec {
        pool: pool.into(),
        project: project.into(),
        namespace: project.into(),
        nominal: BTreeMap::from([("cpu".to_string(), "16".to_string())]),
        borrowing_limit: BTreeMap::new(),
        lending_limit: BTreeMap::new(),
    }
}

/// Pool persistence conformance (ADR-0004/ADR-0010), run against BOTH impls.
async fn pool_conformance(store: &dyn Store) {
    // Upsert → get round-trip; first insert is generation 1.
    assert_eq!(
        store
            .upsert_pool("gpu", pool_spec("gpu", 1.0))
            .await
            .unwrap(),
        1
    );
    let got = store.get_pool("gpu").await.unwrap().unwrap();
    assert_eq!(got.name, "gpu");
    assert_eq!(got.generation, 1);
    assert_eq!(got.spec, pool_spec("gpu", 1.0));
    assert!(got.created_at > 0);

    // Identical re-upsert keeps the generation stable.
    assert_eq!(
        store
            .upsert_pool("gpu", pool_spec("gpu", 1.0))
            .await
            .unwrap(),
        1
    );
    // A changed spec bumps it.
    assert_eq!(
        store
            .upsert_pool("gpu", pool_spec("gpu", 2.0))
            .await
            .unwrap(),
        2
    );
    assert_eq!(store.get_pool("gpu").await.unwrap().unwrap().generation, 2);
    // created_at survives updates.
    assert_eq!(
        store.get_pool("gpu").await.unwrap().unwrap().created_at,
        got.created_at
    );

    // Pool observation (ADR-0010; the Slice 4 metering loop reads this):
    // None until the pool reconcile loop records one, then round-trips and
    // survives spec updates.
    assert!(store
        .get_pool("gpu")
        .await
        .unwrap()
        .unwrap()
        .observed_json
        .is_none());
    store
        .record_pool_observation("gpu", "{\"admitted_workloads\":1}")
        .await
        .unwrap();
    assert_eq!(
        store
            .get_pool("gpu")
            .await
            .unwrap()
            .unwrap()
            .observed_json
            .as_deref(),
        Some("{\"admitted_workloads\":1}")
    );
    assert!(
        store
            .get_pool("gpu")
            .await
            .unwrap()
            .unwrap()
            .observed_at
            .is_some(),
        "recording an observation stamps observed_at"
    );
    store
        .upsert_pool("gpu", pool_spec("gpu", 3.0))
        .await
        .unwrap();
    assert!(
        store
            .get_pool("gpu")
            .await
            .unwrap()
            .unwrap()
            .observed_json
            .is_some(),
        "observation survives a spec update"
    );

    // list_pools sees all pools.
    store
        .upsert_pool("cpu", pool_spec("cpu", 1.0))
        .await
        .unwrap();
    let mut names: Vec<String> = store
        .list_pools()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.name)
        .collect();
    names.sort();
    assert_eq!(names, ["cpu", "gpu"]);

    // Missing pool reads as None; deleting a missing pool errors.
    assert!(store.get_pool("ghost").await.unwrap().is_none());
    let err = store.delete_pool("ghost").await.unwrap_err().to_string();
    assert!(err.contains("no such pool ghost"), "{err}");

    // Allocation upsert/list/delete, scoped per pool.
    store
        .upsert_allocation(alloc("gpu", "proj-a"))
        .await
        .unwrap();
    store
        .upsert_allocation(alloc("gpu", "proj-b"))
        .await
        .unwrap();
    store
        .upsert_allocation(alloc("cpu", "proj-c"))
        .await
        .unwrap();
    // Re-upsert of the same key updates in place (no duplicate).
    let mut updated = alloc("gpu", "proj-a");
    updated
        .nominal
        .insert("memory".to_string(), "64Gi".to_string());
    store.upsert_allocation(updated).await.unwrap();

    let mut gpu_projects: Vec<String> = store
        .list_allocations("gpu")
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.project)
        .collect();
    gpu_projects.sort();
    assert_eq!(gpu_projects, ["proj-a", "proj-b"]);
    // Scoped per pool: proj-c lives under "cpu" only.
    assert_eq!(store.list_allocations("cpu").await.unwrap().len(), 1);
    assert!(store.list_allocations("ghost").await.unwrap().is_empty());

    store.delete_allocation("gpu", "proj-a").await.unwrap();
    let remaining: Vec<String> = store
        .list_allocations("gpu")
        .await
        .unwrap()
        .into_iter()
        .map(|a| a.project)
        .collect();
    assert_eq!(remaining, ["proj-b"]);
    let err = store
        .delete_allocation("gpu", "proj-a")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no such allocation gpu/proj-a"), "{err}");

    // Hard delete removes the pool.
    store.delete_pool("cpu").await.unwrap();
    assert!(store.get_pool("cpu").await.unwrap().is_none());
}

#[tokio::test]
async fn in_memory_store_pool_conforms() {
    pool_conformance(&InMemoryStore::new()).await;
}

/// Usage-sample timeseries conformance (Slice 4), run against BOTH impls.
async fn usage_conformance(store: &dyn Store) {
    use mobula_controller::{UsageSample, UsageSource};
    let sample = |ts: u64, project: &str, pool: &str, resource: &str, qty: f64| UsageSample {
        ts,
        project: project.into(),
        pool: pool.into(),
        resource: resource.into(),
        quantity: qty,
        source: if pool.is_empty() {
            UsageSource::ObservedSpec
        } else {
            UsageSource::KueueLedger
        },
    };

    // Append in non-chronological order; reads come back ts-ordered.
    store
        .record_usage_samples(&[
            sample(300, "proj-a", "gpu", "cpu", 8.0),
            sample(100, "proj-a", "gpu", "cpu", 4.0),
            sample(200, "proj-a", "gpu", "cpu", 6.0),
            sample(150, "proj-b", "gpu", "cpu", 2.0),
            sample(150, "proj-a", "gpu", "memory", 16.0),
            sample(150, "proj-a", "cpu-pool", "cpu", 1.0),
            sample(150, "proj-c", "", "cpu", 3.0), // no allocation → pool ""
        ])
        .await
        .unwrap();

    // Full range, no filters: everything, ordered by ts.
    let all = store.usage_samples(None, None, 0, u64::MAX).await.unwrap();
    assert_eq!(all.len(), 7);
    let ts: Vec<u64> = all.iter().map(|s| s.ts).collect();
    assert_eq!(ts, [100, 150, 150, 150, 150, 200, 300]);

    // Range query is inclusive on both ends.
    let window = store.usage_samples(None, None, 150, 200).await.unwrap();
    assert_eq!(window.len(), 5);

    // Project filter.
    let a = store
        .usage_samples(Some("proj-a"), None, 0, u64::MAX)
        .await
        .unwrap();
    assert_eq!(a.len(), 5);
    assert!(a.iter().all(|s| s.project == "proj-a"));

    // Pool filter.
    let gpu = store
        .usage_samples(None, Some("gpu"), 0, u64::MAX)
        .await
        .unwrap();
    assert_eq!(gpu.len(), 5);
    assert!(gpu.iter().all(|s| s.pool == "gpu"));

    // Both filters + range, and the source enum round-trips.
    let one = store
        .usage_samples(Some("proj-a"), Some("gpu"), 100, 100)
        .await
        .unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].quantity, 4.0);
    assert_eq!(one[0].source, UsageSource::KueueLedger);
    assert_eq!(
        store
            .usage_samples(Some("proj-c"), None, 0, u64::MAX)
            .await
            .unwrap()[0]
            .source,
        UsageSource::ObservedSpec
    );

    // Empty range / no match.
    assert!(store
        .usage_samples(None, None, 1000, 2000)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .usage_samples(Some("ghost"), None, 0, u64::MAX)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn in_memory_store_usage_conforms() {
    usage_conformance(&InMemoryStore::new()).await;
}

#[tokio::test]
async fn sqlite_store_usage_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    usage_conformance(&store).await;
}

/// Audit-trail conformance (api-v1.md §5.9), run against BOTH impls.
async fn audit_conformance(store: &dyn Store) {
    use mobula_core::{AuditDecision, AuditEvent, AuditFilter, AuditRequired};
    let event =
        |ts: u64, subject: Option<&str>, decision: AuditDecision, status: Option<u16>| AuditEvent {
            ts,
            subject: subject.map(String::from),
            decision,
            status,
            ..Default::default()
        };
    let filter = |f: &mut AuditFilter| std::mem::take(f);

    // Append: seq is 1-based and monotonic; rows round-trip intact.
    let s1 = store
        .record_audit(&AuditEvent {
            ts: 100,
            subject: Some("alice".into()),
            decision: AuditDecision::Deny,
            reason: Some("insufficient_permission".into()),
            action: Some("create_cluster".into()),
            cluster: Some("demo".into()),
            method: Some("POST".into()),
            path: Some("/api/v1/clusters".into()),
            status: Some(403),
            latency_ms: Some(4),
            required: Some(AuditRequired {
                action: "write".into(),
                target: "cluster".into(),
            }),
            granted_roles: vec!["viewer".into()],
        })
        .await
        .unwrap();
    let s2 = store
        .record_audit(&event(200, Some("bob"), AuditDecision::Allow, Some(200)))
        .await
        .unwrap();
    // Authn failure: no subject/status — nulls round-trip, never invented.
    let s3 = store
        .record_audit(&AuditEvent {
            ts: 300,
            decision: AuditDecision::Deny,
            reason: Some("missing_token".into()),
            path: Some("/api/v1/clusters".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!([s1, s2, s3], [1, 2, 3]);

    // Full read: newest-first by seq, no next page.
    let (rows, next) = store.list_audit(&AuditFilter::default()).await.unwrap();
    assert_eq!(rows.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [3, 2, 1]);
    assert_eq!(next, None);
    let full = &rows[2].1;
    assert_eq!(full.subject.as_deref(), Some("alice"));
    assert_eq!(full.decision, AuditDecision::Deny);
    assert_eq!(
        full.required,
        Some(AuditRequired {
            action: "write".into(),
            target: "cluster".into()
        })
    );
    assert_eq!(full.granted_roles, ["viewer"]);
    assert_eq!(full.latency_ms, Some(4));
    // Null-absent fields stay null-absent.
    assert!(rows[0].1.subject.is_none());
    assert!(rows[0].1.status.is_none());
    assert!(rows[0].1.granted_roles.is_empty());

    // Filters: from/to inclusive, subject, min_status, decision.
    let (rows, _) = store
        .list_audit(&filter(&mut AuditFilter {
            from: Some(200),
            to: Some(200),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.ts, 200);

    let (rows, _) = store
        .list_audit(&filter(&mut AuditFilter {
            subject: Some("alice".into()),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, 1);

    // min_status excludes rows with no status at all (NULL semantics).
    let (rows, _) = store
        .list_audit(&filter(&mut AuditFilter {
            min_status: Some(400),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, 1);

    let (rows, _) = store
        .list_audit(&filter(&mut AuditFilter {
            decision: Some(AuditDecision::Deny),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(rows.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [3, 1]);

    let (rows, _) = store
        .list_audit(&filter(&mut AuditFilter {
            cluster: Some("demo".into()),
            method: Some("POST".into()),
            path_prefix: Some("/api/v1".into()),
            reason: Some("insufficient_permission".into()),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, 1);

    // Limit + cursor round-trip across two pages, no overlap, no gap.
    let (page1, next) = store
        .list_audit(&filter(&mut AuditFilter {
            limit: Some(2),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(page1.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [3, 2]);
    assert_eq!(next, Some(2));
    let (page2, next) = store
        .list_audit(&filter(&mut AuditFilter {
            limit: Some(2),
            cursor: next,
            ..Default::default()
        }))
        .await
        .unwrap();
    assert_eq!(page2.iter().map(|(s, _)| *s).collect::<Vec<_>>(), [1]);
    assert_eq!(next, None);

    // A cursor beyond the oldest row paginates to nothing.
    let (page, next) = store
        .list_audit(&filter(&mut AuditFilter {
            cursor: Some(1),
            ..Default::default()
        }))
        .await
        .unwrap();
    assert!(page.is_empty());
    assert_eq!(next, None);
}

#[tokio::test]
async fn in_memory_store_audit_conforms() {
    audit_conformance(&InMemoryStore::new()).await;
}

#[tokio::test]
async fn sqlite_store_audit_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    audit_conformance(&store).await;
}

#[tokio::test]
async fn sqlite_store_pool_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    pool_conformance(&store).await;
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
