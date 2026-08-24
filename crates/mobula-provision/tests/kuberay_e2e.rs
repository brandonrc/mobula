//! Live KubeRay e2e — requires a Kubernetes cluster with the KubeRay
//! operator installed. Ignored by default; the `kuberay-e2e` workflow runs
//! it with `--ignored` against a kind cluster. It exercises the full
//! provisioner contract: apply → observe-until-ready → terminate.

use std::time::{Duration, Instant};

use kube::api::{Api, ListParams};
use kube::core::DynamicObject;
use kube::discovery::ApiResource;
use kube::Client;
use mobula_core::{ClusterId, ClusterSpec, ClusterState, WorkerGroup};
use mobula_provision::kuberay::{
    cluster_allow_policy_name, CLUSTER_ID_LABEL, DEFAULT_DENY_POLICY_NAME, PSS_ENFORCE_LABEL,
    TENANT_ALLOW_POLICY_NAME,
};
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
    let prov = KubeRayProvisioner::connect(ns.clone(), false)
        .await
        .expect("connect to cluster");
    let id = ClusterId("e2e-demo".into());

    // #56/#62: cluster creation ensures the namespace security posture.
    // Idempotent; a second call must be a no-op. (kind's kindnet does not
    // enforce NetworkPolicy, so this cannot break pod traffic in CI.)
    prov.ensure_namespace_posture(&ns)
        .await
        .expect("ensure namespace posture");
    prov.ensure_namespace_posture(&ns)
        .await
        .expect("re-ensure is idempotent");

    // Assert the posture landed: both policies exist and the namespace
    // carries the PSS labels.
    let client = Client::try_default().await.expect("kube client");
    let np_resource = ApiResource::from_gvk(&kube::core::GroupVersionKind {
        group: "networking.k8s.io".into(),
        version: "v1".into(),
        kind: "NetworkPolicy".into(),
    });
    let policies: Api<DynamicObject> = Api::namespaced_with(client.clone(), &ns, &np_resource);
    let listed = policies
        .list(&ListParams::default())
        .await
        .expect("list networkpolicies");
    let names: Vec<String> = listed
        .items
        .iter()
        .filter_map(|p| p.metadata.name.clone())
        .collect();
    assert!(
        names.iter().any(|n| n == DEFAULT_DENY_POLICY_NAME),
        "default-deny policy must exist (found: {names:?})"
    );
    assert!(
        names.iter().any(|n| n == TENANT_ALLOW_POLICY_NAME),
        "tenant-allow policy must exist (found: {names:?})"
    );
    // #86: no Mobula policy may be namespace-wide — the deny/allow pair
    // selects only tenant pods (cluster-id label), so the control plane and
    // any colocated non-Ray pod stay unaffected.
    let ours = |p: &&DynamicObject| {
        p.metadata
            .labels
            .as_ref()
            .and_then(|l| l.get("app.kubernetes.io/managed-by"))
            .is_some_and(|v| v == "mobula")
    };
    for p in listed.items.iter().filter(ours) {
        let sel = &p.data["spec"]["podSelector"];
        assert_ne!(
            sel,
            &serde_json::json!({}),
            "policy {:?} must not select the whole namespace",
            p.metadata.name
        );
        assert!(
            serde_json::to_string(sel)
                .expect("serialize selector")
                .contains(CLUSTER_ID_LABEL),
            "policy {:?} must scope to the tenant pod label (selector: {sel})",
            p.metadata.name
        );
    }
    let ns_resource = ApiResource::from_gvk(&kube::core::GroupVersionKind {
        group: "".into(),
        version: "v1".into(),
        kind: "Namespace".into(),
    });
    let namespaces: Api<DynamicObject> = Api::all_with(client, &ns_resource);
    let ns_obj = namespaces.get(&ns).await.expect("get namespace");
    let labels = ns_obj.metadata.labels.unwrap_or_default();
    assert_eq!(
        labels.get(PSS_ENFORCE_LABEL).map(String::as_str),
        Some("baseline"),
        "namespace must enforce PSS baseline (labels: {labels:?})"
    );

    // Idempotent apply (generation 1).
    prov.apply(&id, &tiny_spec(), 1, "e2e/1", None)
        .await
        .expect("apply");
    prov.apply(&id, &tiny_spec(), 1, "e2e/1", None)
        .await
        .expect("second apply is idempotent");

    // It should appear in the field-manager-scoped list immediately.
    let clusters = prov.list().await.expect("list");
    assert!(
        clusters.iter().any(|c| c.id == id),
        "applied cluster must be listed"
    );

    // #86: the apply also ensured the per-cluster intra-tenant allow.
    let allow_name = cluster_allow_policy_name(&id.0);
    let allow = policies
        .get_opt(&allow_name)
        .await
        .expect("get per-cluster allow policy")
        .unwrap_or_else(|| panic!("{allow_name} must exist after apply"));
    assert_eq!(
        allow.data["spec"]["podSelector"]["matchLabels"][CLUSTER_ID_LABEL],
        serde_json::json!(id.0),
        "per-cluster allow must select exactly this cluster's pods"
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
            // #40: the generation Mobula stamped must round-trip back through
            // observe() from the CR annotation.
            assert_eq!(
                obs.observed_generation,
                Some(1),
                "observed generation must be read back from the applied CR"
            );
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

    // Teardown is idempotent, and takes the per-cluster allow policy with
    // it (#86).
    prov.terminate(&id).await.expect("terminate");
    prov.terminate(&id)
        .await
        .expect("terminate again is a no-op");
    assert!(
        policies
            .get_opt(&allow_name)
            .await
            .expect("get per-cluster allow policy after terminate")
            .is_none(),
        "{allow_name} must be deleted with the cluster"
    );
}
