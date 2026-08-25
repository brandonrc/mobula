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
        engine: Default::default(),
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
        owner: None,
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
    let got = store.get(&id).await.unwrap().unwrap();
    assert_eq!(got.desired, DesiredState::Terminated);
    // Terminating stamps the tombstone-retention clock (Truthful Console).
    assert!(got.terminated_at.is_some());

    // #51: the Suspended desired state round-trips too (persisted as the
    // string "suspended" by the sqlx stores; old "running"/"terminated"
    // rows still parse).
    store
        .set_desired(&id, DesiredState::Suspended)
        .await
        .unwrap();
    assert_eq!(
        store.get(&id).await.unwrap().unwrap().desired,
        DesiredState::Suspended
    );
    store.set_desired(&id, DesiredState::Running).await.unwrap();
    let got = store.get(&id).await.unwrap().unwrap();
    assert_eq!(got.desired, DesiredState::Running);
    // Moving away from Terminated clears the retention clock: a resumed
    // cluster is never a tombstone.
    assert_eq!(got.terminated_at, None);

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

    // remove_cluster hard-deletes the row and reports whether one existed
    // (Truthful Console tombstone purge).
    assert!(store.remove_cluster(&id).await.unwrap());
    assert!(store.get(&id).await.unwrap().is_none());
    // Idempotent: removing an absent row is Ok(false), not an error.
    assert!(!store.remove_cluster(&id).await.unwrap());
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
        gpu_sharing: None,
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

    // #59 tamper-evidence chain: every appended row carries a chain hash,
    // ascending replay from genesis verifies, and a mid-trail window chains
    // from the preceding row's hash.
    let window = store.audit_chain(None, 100).await.unwrap();
    assert_eq!(window.head, mobula_controller::AUDIT_GENESIS_HASH);
    assert_eq!(
        window.rows.iter().map(|(s, _, _)| *s).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(window.rows.iter().all(|(_, _, h)| h.len() == 64));
    let v = mobula_controller::verify_audit_chain(&window.head, &window.rows);
    assert!(v.ok() && v.events_checked == 3, "{v:?}");

    // Window [2, 3]: head is row 1's hash; limit bounds the window.
    let window = store.audit_chain(Some(2), 100).await.unwrap();
    let full = store.audit_chain(None, 100).await.unwrap();
    assert_eq!(window.head, full.rows[0].2);
    assert_eq!(
        window.rows.iter().map(|(s, _, _)| *s).collect::<Vec<_>>(),
        [2, 3]
    );
    assert!(mobula_controller::verify_audit_chain(&window.head, &window.rows).ok());
    let one = store.audit_chain(Some(2), 1).await.unwrap();
    assert_eq!(one.rows.len(), 1);
    assert_eq!(one.rows[0].0, 2);
    assert!(mobula_controller::verify_audit_chain(&one.head, &one.rows).ok());
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

/// #59 migration: a database written by the pre-chain schema (audit_events
/// WITHOUT `chain_hash`) gets the column added and every legacy row chained
/// in seq order on first boot.
#[tokio::test]
async fn sqlite_audit_chain_backfills_pre_migration_rows() {
    use mobula_core::{AuditDecision, AuditEvent};
    let path = std::env::temp_dir().join(format!(
        "mobula-audit-chain-migration-{}-{}.db",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let url = format!("sqlite:{}?mode=rwc", path.display());

    // Write two rows through the OLD schema (no chain_hash column).
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    sqlx::query(
        "CREATE TABLE audit_events (
            seq           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            INTEGER NOT NULL,
            subject       TEXT,
            decision      TEXT NOT NULL,
            reason        TEXT,
            action        TEXT,
            cluster       TEXT,
            method        TEXT,
            path          TEXT,
            status        INTEGER,
            latency_ms    INTEGER,
            required_json TEXT,
            granted_roles TEXT NOT NULL DEFAULT '[]'
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (ts, subject) in [(100, "alice"), (200, "bob")] {
        sqlx::query("INSERT INTO audit_events (ts, subject, decision) VALUES (?, ?, 'allow')")
            .bind(ts)
            .bind(subject)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;

    // First boot on the new binary: column migration + backfill.
    let store = SqliteStore::connect(&url).await.unwrap();
    let window = store.audit_chain(None, 100).await.unwrap();
    assert_eq!(window.rows.len(), 2);
    assert!(window.rows.iter().all(|(_, _, h)| h.len() == 64));
    let v = mobula_controller::verify_audit_chain(&window.head, &window.rows);
    assert!(v.ok() && v.events_checked == 2, "{v:?}");
    assert_eq!(window.rows[0].1.decision, AuditDecision::Allow);
    assert_eq!(window.rows[1].1.subject.as_deref(), Some("bob"));

    // A row appended after the migration chains from the backfilled tail.
    store
        .record_audit(&AuditEvent {
            ts: 300,
            ..Default::default()
        })
        .await
        .unwrap();
    let window = store.audit_chain(None, 100).await.unwrap();
    let v = mobula_controller::verify_audit_chain(&window.head, &window.rows);
    assert!(v.ok() && v.events_checked == 3, "{v:?}");

    drop(store);
    let _ = std::fs::remove_file(&path);
}

/// Local-auth conformance (ADR-0011): user CRUD, lockout counters, and
/// token lifecycle — run against BOTH impls.
async fn local_auth_conformance(store: &dyn Store) {
    use mobula_core::{ApiTokenRecord, LocalRole};

    // Create → get → list round-trip; the hash stays inside the record.
    store
        .create_local_user(
            "alice",
            Some("alice@x.io"),
            "$2b$hash-a",
            LocalRole::Developer,
        )
        .await
        .unwrap();
    store
        .create_local_user("bob", None, "$2b$hash-b", LocalRole::Viewer)
        .await
        .unwrap();
    let alice = store.get_local_user("alice").await.unwrap().unwrap();
    assert_eq!(alice.email.as_deref(), Some("alice@x.io"));
    assert_eq!(alice.role, LocalRole::Developer);
    assert_eq!(alice.password_hash, "$2b$hash-a");
    assert!(!alice.disabled);
    assert!(alice.created_at > 0);
    assert_eq!(alice.failed_logins, 0);
    assert_eq!(alice.locked_until, None);

    // Duplicate username errors; unknown user reads as None.
    assert!(store
        .create_local_user("alice", None, "x", LocalRole::Viewer)
        .await
        .is_err());
    assert!(store.get_local_user("ghost").await.unwrap().is_none());

    // list is username-ordered.
    let names: Vec<String> = store
        .list_local_users()
        .await
        .unwrap()
        .into_iter()
        .map(|u| u.username)
        .collect();
    assert_eq!(names, ["alice", "bob"]);

    // Password/role/disabled updates round-trip and error on missing users.
    store
        .set_local_user_password("alice", "$2b$hash-a2")
        .await
        .unwrap();
    store
        .set_local_user_role("alice", LocalRole::Admin)
        .await
        .unwrap();
    store.set_local_user_disabled("bob", true).await.unwrap();
    let alice = store.get_local_user("alice").await.unwrap().unwrap();
    assert_eq!(alice.password_hash, "$2b$hash-a2");
    assert_eq!(alice.role, LocalRole::Admin);
    assert!(store.get_local_user("bob").await.unwrap().unwrap().disabled);
    for r in [
        store.set_local_user_password("ghost", "x").await,
        store.set_local_user_role("ghost", LocalRole::Viewer).await,
        store.set_local_user_disabled("ghost", false).await,
    ] {
        assert!(r.is_err());
    }

    // Lockout state machine (5 failures → locked; success clears).
    for _ in 0..4 {
        store.record_login_failure("alice").await.unwrap();
    }
    let alice = store.get_local_user("alice").await.unwrap().unwrap();
    assert_eq!(alice.failed_logins, 4);
    assert_eq!(alice.locked_until, None);
    store.record_login_failure("alice").await.unwrap();
    let alice = store.get_local_user("alice").await.unwrap().unwrap();
    assert_eq!(alice.failed_logins, 0, "counter resets when the lock trips");
    let locked_until = alice.locked_until.expect("5th failure locks");
    let now = mobula_controller::now_unix();
    assert!(
        locked_until >= now + mobula_controller::LOCKOUT_SECS - 5
            && locked_until <= now + mobula_controller::LOCKOUT_SECS + 5,
        "locked_until ≈ now + 300, got {locked_until} at {now}"
    );
    // (While locked the authenticator short-circuits before calling
    // record_login_failure, so the store never sees failures-under-lock.)
    store.record_login_success("alice").await.unwrap();
    let alice = store.get_local_user("alice").await.unwrap().unwrap();
    assert_eq!(alice.failed_logins, 0);
    assert_eq!(alice.locked_until, None);
    assert!(store.record_login_failure("ghost").await.is_err());

    // Token lifecycle: create → lookup → list → touch → revoke.
    let token = |prefix: &str, username: &str| ApiTokenRecord {
        prefix: prefix.into(),
        token_hash: format!("$2b$hash-{prefix}"),
        username: username.into(),
        label: "ci".into(),
        created_at: 100,
        expires_at: 200,
        revoked: false,
        last_used_at: None,
    };
    store
        .create_api_token(token("aaaa1111", "alice"))
        .await
        .unwrap();
    store
        .create_api_token(token("bbbb2222", "alice"))
        .await
        .unwrap();
    store
        .create_api_token(token("cccc3333", "bob"))
        .await
        .unwrap();
    // Prefix collision errors.
    assert!(store
        .create_api_token(token("aaaa1111", "alice"))
        .await
        .is_err());

    let got = store
        .get_api_token_by_prefix("aaaa1111")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.token_hash, "$2b$hash-aaaa1111");
    assert_eq!(got.username, "alice");
    assert_eq!(got.expires_at, 200);
    assert!(!got.revoked);
    assert_eq!(got.last_used_at, None);
    assert!(store
        .get_api_token_by_prefix("zzzz9999")
        .await
        .unwrap()
        .is_none());

    // list is owner-scoped and newest-first.
    let alice_tokens = store.list_api_tokens("alice").await.unwrap();
    assert_eq!(alice_tokens.len(), 2);
    assert!(alice_tokens.iter().all(|t| t.username == "alice"));
    assert!(store.list_api_tokens("ghost").await.unwrap().is_empty());

    // touch stamps last_used_at.
    store.touch_api_token("aaaa1111", 150).await.unwrap();
    assert_eq!(
        store
            .get_api_token_by_prefix("aaaa1111")
            .await
            .unwrap()
            .unwrap()
            .last_used_at,
        Some(150)
    );

    // Revoke is owner-scoped: bob cannot revoke alice's token (same error
    // as a nonexistent prefix — no ownership probing).
    assert!(store.revoke_api_token("bbbb2222", "bob").await.is_err());
    assert!(store.revoke_api_token("zzzz9999", "bob").await.is_err());
    store.revoke_api_token("bbbb2222", "alice").await.unwrap();
    assert!(
        store
            .get_api_token_by_prefix("bbbb2222")
            .await
            .unwrap()
            .unwrap()
            .revoked
    );
    // Idempotent re-revoke of one's own token.
    store.revoke_api_token("bbbb2222", "alice").await.unwrap();
}

#[tokio::test]
async fn in_memory_store_local_auth_conforms() {
    local_auth_conformance(&InMemoryStore::new()).await;
}

#[tokio::test]
async fn sqlite_store_local_auth_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    local_auth_conformance(&store).await;
}

#[tokio::test]
async fn sqlite_store_pool_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    pool_conformance(&store).await;
}

/// Scoped-role-assignment conformance (ADR-0009 addendum, #49), run against
/// BOTH impls (and Postgres in CI): upsert/list/delete keyed by
/// (principal, role, scope), per-principal filter, created_at stability.
async fn assignment_conformance(store: &dyn Store) {
    // Empty by default; per-principal filter.
    assert!(store.list_role_assignments(None).await.unwrap().is_empty());
    assert!(store
        .list_role_assignments(Some("alice"))
        .await
        .unwrap()
        .is_empty());

    store
        .upsert_role_assignment("alice", "operator", "project:ml-team")
        .await
        .unwrap();
    store
        .upsert_role_assignment("alice", "viewer", "*")
        .await
        .unwrap();
    store
        .upsert_role_assignment("bob", "developer", "project:data")
        .await
        .unwrap();

    // Per-principal list is ordered by (principal, scope, role); "*" sorts
    // before "project:…".
    let alice = store.list_role_assignments(Some("alice")).await.unwrap();
    assert_eq!(alice.len(), 2);
    assert_eq!(alice[0].scope, "*");
    assert_eq!(alice[0].role, "viewer");
    assert_eq!(alice[1].scope, "project:ml-team");
    assert!(alice.iter().all(|a| a.principal == "alice"));
    assert!(alice.iter().all(|a| a.created_at > 0));

    // Re-upsert of the same triple replaces in place (no duplicate) and
    // preserves the original created_at.
    let first = alice[1].created_at;
    store
        .upsert_role_assignment("alice", "operator", "project:ml-team")
        .await
        .unwrap();
    let again = store.list_role_assignments(Some("alice")).await.unwrap();
    assert_eq!(again.len(), 2);
    assert_eq!(again[1].created_at, first);

    // Unfiltered list covers all principals, ordered.
    let all = store.list_role_assignments(None).await.unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].principal, "alice");
    assert_eq!(all[2].principal, "bob");

    // Delete round-trips; deleting a missing triple errors naming it.
    store
        .delete_role_assignment("alice", "viewer", "*")
        .await
        .unwrap();
    assert_eq!(
        store
            .list_role_assignments(Some("alice"))
            .await
            .unwrap()
            .len(),
        1
    );
    let err = store
        .delete_role_assignment("alice", "viewer", "*")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("no such assignment alice/viewer/*"), "{err}");
}

#[tokio::test]
async fn in_memory_store_assignment_conforms() {
    assignment_conformance(&InMemoryStore::new()).await;
}

#[tokio::test]
async fn sqlite_store_assignment_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    assignment_conformance(&store).await;
}

/// Governance-policy conformance (api-v1.md §5.16): unset reads as `None`;
/// set round-trips the full record (prices, quotas, provenance flag);
/// overwrite replaces the row; `seed_policy` is insert-if-absent.
async fn policy_conformance(store: &dyn Store) {
    use mobula_controller::StoredPolicy;

    let policy = |cpu_price: f64, seed: bool| StoredPolicy {
        prices: Some(BTreeMap::from([("cpu".to_string(), cpu_price)])),
        quotas: BTreeMap::from([(
            "ml-team".to_string(),
            BTreeMap::from([("cpu".to_string(), 500.0)]),
        )]),
        from_file_seed: seed,
    };

    // Unset → None.
    assert_eq!(store.get_policy().await.unwrap(), None);

    // Round-trip.
    store.set_policy(&policy(0.048, true)).await.unwrap();
    assert_eq!(store.get_policy().await.unwrap(), Some(policy(0.048, true)));

    // Overwrite (the settings PUT path).
    store.set_policy(&policy(0.05, false)).await.unwrap();
    assert_eq!(store.get_policy().await.unwrap(), Some(policy(0.05, false)));

    // seed_policy never clobbers an existing row (a concurrent edit or a
    // second boot loses; the existing row — seed or edit — wins).
    assert!(!store.seed_policy(&policy(9.9, true)).await.unwrap());
    assert_eq!(store.get_policy().await.unwrap(), Some(policy(0.05, false)));
}

/// seed_policy on an EMPTY store inserts and reports the insertion (both
/// impls; kept separate from `policy_conformance` which ends non-empty).
async fn policy_seed_conformance(store: &dyn Store) {
    use mobula_controller::StoredPolicy;

    let seed = StoredPolicy {
        prices: None,
        quotas: BTreeMap::from([(
            "demo".to_string(),
            BTreeMap::from([("cpu".to_string(), 5.0)]),
        )]),
        from_file_seed: true,
    };
    assert!(store.seed_policy(&seed).await.unwrap());
    assert_eq!(store.get_policy().await.unwrap(), Some(seed.clone()));
    // A second seed (e.g. a concurrent boot) is a no-op.
    assert!(!store.seed_policy(&seed).await.unwrap());
    assert_eq!(store.get_policy().await.unwrap(), Some(seed));
}

#[tokio::test]
async fn in_memory_store_policy_conforms() {
    let store = InMemoryStore::new();
    policy_conformance(&store).await;
    policy_seed_conformance(&InMemoryStore::new()).await;
}

#[tokio::test]
async fn sqlite_store_policy_conforms() {
    let store = SqliteStore::in_memory().await.unwrap();
    policy_conformance(&store).await;
    let fresh = SqliteStore::in_memory().await.unwrap();
    policy_seed_conformance(&fresh).await;
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

// --- Postgres conformance (#48): the SAME scenarios run against
// PostgresStore when MOBULA_TEST_POSTGRES_URL points at a Postgres (e.g.
// `docker run -p 5432:5432 -e POSTGRES_PASSWORD=mobula postgres:16-alpine`);
// otherwise they skip with a clear message. CI's test job runs a postgres
// service and sets the env var, so this is exercised on every PR.
#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use mobula_controller::PostgresStore;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

    /// Connect in a fresh per-test schema (set as every connection's
    /// search_path) so parallel scenarios never share rows. `None` — with a
    /// clear message — when MOBULA_TEST_POSTGRES_URL is unset.
    async fn postgres_store() -> Option<PostgresStore> {
        let url = match std::env::var("MOBULA_TEST_POSTGRES_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => {
                eprintln!(
                    "skipping PostgresStore conformance: MOBULA_TEST_POSTGRES_URL is not set \
                     (e.g. postgres://mobula:mobula@localhost:5432/mobula)"
                );
                return None;
            }
        };
        let schema = format!(
            "conf_{}_{}",
            std::process::id(),
            NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
        );
        let pool = PgPoolOptions::new()
            .after_connect(move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query(&format!("SET search_path TO {schema}"))
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("connect to MOBULA_TEST_POSTGRES_URL");
        Some(PostgresStore::from_pool(pool).await.expect("apply schema"))
    }

    macro_rules! pg_conformance {
        ($name:ident, $scenario:ident) => {
            #[tokio::test]
            async fn $name() {
                if let Some(store) = postgres_store().await {
                    $scenario(&store).await;
                }
            }
        };
    }

    pg_conformance!(postgres_store_conforms, conformance);
    pg_conformance!(postgres_store_pool_conforms, pool_conformance);
    pg_conformance!(postgres_store_usage_conforms, usage_conformance);
    pg_conformance!(postgres_store_audit_conforms, audit_conformance);
    pg_conformance!(postgres_store_local_auth_conforms, local_auth_conformance);
    pg_conformance!(postgres_store_assignment_conforms, assignment_conformance);

    /// #59 migration, Postgres side: a schema written by the pre-chain
    /// binary (audit_events WITHOUT `chain_hash`) gets the column via
    /// `ALTER … IF NOT EXISTS` and every legacy row chained in seq order on
    /// first boot.
    #[tokio::test]
    async fn postgres_audit_chain_backfills_pre_migration_rows() {
        let url = match std::env::var("MOBULA_TEST_POSTGRES_URL") {
            Ok(u) if !u.is_empty() => u,
            _ => return,
        };
        let schema = format!(
            "legacy_{}_{}",
            std::process::id(),
            NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
        );
        let pool = PgPoolOptions::new()
            .after_connect(move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
                        .execute(&mut *conn)
                        .await?;
                    sqlx::query(&format!("SET search_path TO {schema}"))
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .expect("connect to MOBULA_TEST_POSTGRES_URL");
        // The OLD table shape (no chain_hash) with two legacy rows.
        sqlx::query(
            "CREATE TABLE audit_events (
                seq           BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
                ts            BIGINT NOT NULL,
                subject       TEXT,
                decision      TEXT NOT NULL,
                reason        TEXT,
                action        TEXT,
                cluster       TEXT,
                method        TEXT,
                path          TEXT,
                status        BIGINT,
                latency_ms    BIGINT,
                required_json TEXT,
                granted_roles TEXT NOT NULL DEFAULT '[]'
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (ts, subject) in [(100, "alice"), (200, "bob")] {
            sqlx::query(
                "INSERT INTO audit_events (ts, subject, decision) VALUES ($1, $2, 'allow')",
            )
            .bind(ts)
            .bind(subject)
            .execute(&pool)
            .await
            .unwrap();
        }

        // First boot on the new binary: ALTER + backfill.
        let store = PostgresStore::from_pool(pool).await.unwrap();
        let window = store.audit_chain(None, 100).await.unwrap();
        assert_eq!(window.rows.len(), 2);
        assert!(window.rows.iter().all(|(_, _, h)| h.len() == 64));
        let v = mobula_controller::verify_audit_chain(&window.head, &window.rows);
        assert!(v.ok() && v.events_checked == 2, "{v:?}");
        assert_eq!(window.rows[1].1.subject.as_deref(), Some("bob"));
    }

    /// #59: concurrent audit appends serialize on the advisory lock, so the
    /// chain never forks — every appended row chains from the true previous
    /// row and the full trail verifies.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_concurrent_audit_appends_keep_one_chain() {
        let Some(store) = postgres_store().await else {
            return;
        };
        let store = std::sync::Arc::new(store);
        let mut handles = Vec::new();
        for i in 0..20u64 {
            let s = store.clone();
            handles.push(tokio::spawn(async move {
                s.record_audit(&mobula_core::AuditEvent {
                    ts: i,
                    ..Default::default()
                })
                .await
            }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }
        let window = store.audit_chain(None, 100).await.unwrap();
        assert_eq!(window.rows.len(), 20);
        assert_eq!(
            window.rows.iter().map(|(s, _, _)| *s).collect::<Vec<_>>(),
            (1..=20).collect::<Vec<_>>()
        );
        let v = mobula_controller::verify_audit_chain(&window.head, &window.rows);
        assert!(v.ok() && v.events_checked == 20, "{v:?}");
    }

    #[tokio::test]
    async fn postgres_store_policy_conforms() {
        if let Some(store) = postgres_store().await {
            policy_conformance(&store).await;
        }
        // seed_policy on an EMPTY store (a second, fresh schema).
        if let Some(fresh) = postgres_store().await {
            policy_seed_conformance(&fresh).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_concurrent_distinct_upserts_do_not_collapse_generation() {
        // #42, Postgres side: the advisory-lock transaction must serialize
        // two concurrent spec changes so each sees the other's bump.
        let Some(store) = postgres_store().await else {
            return;
        };
        let store = std::sync::Arc::new(store);
        let id = ClusterId("demo".into());
        store.upsert_desired(&id, spec("demo", 1)).await.unwrap(); // gen 1

        let (s1, s2) = (store.clone(), store.clone());
        let (i1, i2) = (id.clone(), id.clone());
        let a = tokio::spawn(async move { s1.upsert_desired(&i1, spec("demo", 2)).await });
        let b = tokio::spawn(async move { s2.upsert_desired(&i2, spec("demo", 5)).await });
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();

        assert_eq!(
            store.get(&id).await.unwrap().unwrap().generation,
            3,
            "two distinct concurrent spec changes must yield two generation bumps"
        );
    }
}
