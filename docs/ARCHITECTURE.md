# Mobula Architecture

How the pieces fit together. Decisions and their evidence live in
[../PLAN.md](../PLAN.md) and [adr/](adr/); this document is the map.

## System context

Mobula is a control plane *beside* Ray, never inside it: it manages cluster
lifecycle, identity, pools, and access, while Ray schedules tasks
(ADR-0001). In Nebari mode the platform supplies browser SSO, ingress, and
TLS; Mobula supplies everything identity-shaped that involves a bearer token.

```mermaid
flowchart LR
    subgraph clients ["Clients"]
        browser["Browser<br/>(dashboards, UI)"]
        rayjob["ray job submit /<br/>JobSubmissionClient"]
        cli["mobula CLI"]
    end

    subgraph platform ["Nebari platform (NIC)"]
        envoy["Envoy Gateway<br/>TLS + routing"]
        keycloak["Keycloak<br/>OIDC IdP"]
        operator["nebari-operator<br/>NebariApp reconcilers"]
    end

    subgraph mobula ["Mobula control plane"]
        api["mobula-api<br/>REST + job gateway"]
        authz["authz endpoint<br/>(ext_authz target)"]
        recon["reconcilers<br/>clusters + pools + metering"]
        db[("Postgres / SQLite<br/>desired state, job history,<br/>usage samples")]
    end

    subgraph dataplane ["Data plane — one per cluster"]
        kuberay["KubeRay operator"]
        kueue["Kueue<br/>(pool engine)"]
        head["Ray head<br/>dashboard + job API<br/>static token auth"]
        workers["Ray workers"]
    end

    browser -->|"redirect SSO (cookies)"| envoy
    envoy -->|ext_authz| authz
    envoy --> api
    envoy -.->|OIDC| keycloak
    operator -.->|"provisions routes,<br/>TLS, OIDC clients"| envoy
    rayjob -->|"bearer JWT,<br/>per-cluster hostname"| api
    cli -->|device-code flow| api
    api -->|"injects static<br/>Ray token"| head
    api --> db
    recon -->|RayCluster CRs| kuberay
    recon -->|CQ/LQ/Flavor/Cohort CRs| kueue
    kuberay -.->|gang admission| kueue
    kuberay --> head
    head --> workers
```

Key invariant (ADR-0003): a caller's credential terminates at Mobula; only
the cluster's static Ray token travels southbound. Nothing in the task
dispatch path goes through Mobula — Serve traffic is authorized via Envoy
`ext_authz`, not proxied inline.

## Crate map

Edges are real Cargo dependencies (each crate's `[dependencies]`). The two
dependency-poor anchors are `mobula-core` (no cloud/K8s deps, ADR-0002) and
`mobula-policy` (pure functions over domain types).

```mermaid
flowchart TD
    cli["mobula-cli<br/><i>the mobula binary</i>"] --> api
    cli --> controller
    cli --> provision
    api["mobula-api<br/><i>REST + job gateway + authz endpoint</i>"] --> auth
    api --> controller
    api --> policy
    api --> provision
    controller["mobula-controller<br/><i>Store, cluster reconcile,<br/>pool reconcile, metering</i>"] --> provision
    controller --> policy
    provision["mobula-provision<br/><i>Provisioner traits; pure translators<br/>kuberay + kueue live clients</i>"] --> policy
    proxy["mobula-proxy<br/><i>standalone-mode identity proxy</i><br/>(stub — #17)"] -.-> core
    policy["mobula-policy<br/><i>quota admission, price sheets,<br/>usage aggregation — pure</i>"] --> core
    provision --> core
    controller --> core
    auth["mobula-auth<br/><i>OIDC discovery, JWT validation,<br/>RBAC permission sets</i>"] --> core
    api --> core
    cli --> core
    core["mobula-core<br/><i>domain model, state machine,<br/>pool specs, cluster registry</i><br/>NO cloud/K8s deps"]
```

Pools follow the same split (ADR-0010): pool topology (`PoolSpec`,
flavors, allocations) lives in `mobula-core::pool`; translation to Kueue
objects is pure in `mobula-provision::kueue` with the live client in
`mobula-provision::kueue_client`; convergence (including the Kueue-absent
fallback) is `mobula-controller::pool_reconcile`; usage attribution is
`mobula-controller::metering` over `mobula-policy::usage`.

## Identity and access enforcement

Every surface is deny-by-default; the two modes differ only in *where* the
bearer check happens. The permission model is `PermissionType
{Read, Write, Delete, Admin}` × `Target {Job, Cluster, Service, Pool}`
(ADR-0009).

```mermaid
flowchart LR
    caller["Caller<br/>browser / CLI / ray client"]

    subgraph nebari ["Nebari mode"]
        envoy["Envoy Gateway"] -->|ext_authz| authz["Mobula authz endpoint<br/>/api/v1/authz/check"]
    end

    subgraph standalone ["Standalone mode"]
        mw["In-process auth middleware<br/>on mobula-api"]
    end

    caller --> envoy
    caller --> mw
    authz --> grants["Role grants matrix<br/>deny by default"]
    mw --> grants
    grants -->|allow| api["Route handler<br/>per-route (action, target) check"]
    grants -->|deny| deny["401 / 403 + audit event"]
```

The credential swap (ADR-0003): the caller's JWT is validated and dropped
at this layer; only the cluster's static Ray token continues southbound, so
no user credential ever reaches a Ray cluster.

## Cluster lifecycle

The state machine in `mobula-core::cluster` — reconcilers may only move
clusters along these edges; anything else is a `TransitionError`:

```mermaid
stateDiagram-v2
    [*] --> Pending
    Pending --> Provisioning
    Pending --> Terminating
    Provisioning --> Running
    Provisioning --> Degraded
    Provisioning --> Terminating
    Running --> Degraded
    Running --> Updating
    Running --> Suspending
    Running --> Terminating
    Degraded --> Running
    Degraded --> Terminating
    Updating --> Running
    Updating --> Degraded
    Suspending --> Suspended
    Suspended --> Provisioning: resume = reprovision
    Suspended --> Terminating
    Terminating --> Terminated
    Terminated --> [*]
```

Note the resume edge: suspended clusters released their compute, so they
re-enter `Provisioning` — there is no `Suspended --> Running` shortcut.

Observed state is reconstructed every pass, never stored as truth
(ADR-0006); drift raises a condition/alarm instead of a silent stomp
(ADR-0004), and every actuation carries a derived idempotency key
`{id}/{generation}` through the transactional outbox (ADR-0007).

## Resource pools — shared capacity (ADR-0010)

A Mobula `ResourcePool` is a thin control/attribution layer over **Kueue**:
Kueue enforces admission, cohort borrowing, and fair sharing; Mobula owns
the pool topology, the admission UX, and usage attribution. When the Kueue
CRDs are absent, pools degrade to the in-process quota path in
`mobula-policy` (REQUIREMENTS §3.2).

### Object mapping

```mermaid
flowchart LR
    subgraph mobulaSide ["Mobula objects — Store is truth (ADR-0004)"]
        pool["ResourcePool<br/>gpu-pool (elastic)"]
        fla["FlavorSpec a100<br/>nvidia.com/gpu = 8"]
        flb["FlavorSpec mig<br/>nvidia.com/mig-1g.10gb = 14"]
        alloc["AllocationSpec<br/>project = ml-team"]
        pool --> fla
        pool --> flb
        pool --> alloc
    end

    subgraph kueueSide ["Kueue objects — actuation (kueue.x-k8s.io/v1beta2)"]
        cq["ClusterQueue gpu-pool<br/>nominalQuota per flavor+resource<br/>fairSharing weight"]
        cohort["Cohort<br/>shared borrowing envelope"]
        rfa["ResourceFlavor a100<br/>nodeLabels + taints"]
        rfb["ResourceFlavor mig<br/>nodeLabels + taints"]
        lq["LocalQueue ml-team<br/>namespaced tenant handle"]
        cq -->|cohortName| cohort
        cq --> rfa
        cq --> rfb
        lq -->|clusterQueue| cq
    end

    pool ==>|to_cluster_queue| cq
    pool ==>|to_cohort| cohort
    fla ==>|to_resource_flavor| rfa
    flb ==>|to_resource_flavor| rfb
    alloc ==>|to_local_queue| lq
```

Resource keys are arbitrary K8s resource names (`cpu`, `memory`,
`nvidia.com/gpu`, MIG slice resources, custom extended resources) — adding
a resource to a pool is a spec edit, not a code change. Kueue rejects
workloads that request a resource the ClusterQueue doesn't quota, and Ray
pods always request memory, so every flavor must cover `memory` too.

### Admission flow

```mermaid
sequenceDiagram
    participant U as Operator (CLI/UI)
    participant A as mobula-api
    participant S as Store
    participant R as Reconcilers
    participant Q as Kueue
    participant K as KubeRay

    U->>A: POST /api/v1/clusters
    A->>A: RBAC Write on Cluster, quota pre-flight — 409 on exceed
    A->>S: upsert desired state (generation bump)
    Note over R: every tick, observation-first (ADR-0006)
    R->>Q: pool reconcile — apply Cohort/CQ/Flavors/LQs
    R->>K: cluster reconcile — apply RayCluster with queue-name label
    Q->>K: webhook holds RayCluster suspended, Workload created
    alt quota available (nominal, or borrowed from the cohort)
        Q->>K: admit Workload, unsuspend
        K->>K: create head + worker pods
    else pool exhausted
        Q->>Q: Workload pends, cluster stays Suspended
        Note over R: queued is not drift — the reconciler must not repair it
    end
```

### Who owns which scaling decision

```mermaid
flowchart TB
    subgraph chain ["The four layers, each with its own signal"]
        demand["Pending Ray tasks/actors"] --> rayas["Ray autoscaler v2<br/>owns worker-group replicas,<br/>graceful drain on scale-down"]
        rayas --> krc["KubeRay<br/>owns pod create/delete"]
        krc --> kueue["Kueue<br/>owns quota admission + the ledger<br/>elastic scale re-accounted via Workload Slices"]
        kueue --> sched["kube-scheduler<br/>owns pod-to-node placement"]
        sched -->|unschedulable pods| ca["cluster-autoscaler / Karpenter<br/>owns nodes/VMs"]
    end
    mob["Mobula"] -.->|"min/max bounds only — never replicas (ADR-0007)"| rayas
    mob -.->|pool topology + allocations| kueue
    kueue -.->|status ledger sampled| mob
```

### Usage attribution (billing-grade GPU-hours)

Kueue's `flavorsUsage` is a *reservation* ledger (what was admitted), not
measured consumption — so Mobula meters attribution itself:

```mermaid
flowchart LR
    subgraph sources ["Sampled every interval (default 60s)"]
        lq["Kueue LocalQueue status<br/>flavorsUsage per project"]
        spec["Observed Running clusters<br/>min-demand — Kueue-absent fallback"]
    end
    meter["Metering loop<br/>mobula-controller::metering"]
    samples[("usage_samples<br/>append-only timeseries")]
    subgraph surfaces ["Attribution surfaces"]
        usage["GET /api/v1/usage<br/>resource-hours + cost<br/>per project/pool, any window"]
        poolu["GET /api/v1/pools/name/usage<br/>live allocation + utilization"]
        prom["GET /api/v1/metrics<br/>Prometheus gauges"]
    end
    lq --> meter
    spec --> meter
    meter -->|append| samples
    samples -->|"step-integral with carry-in<br/>mobula-policy::usage"| usage
    meter -->|latest observation| poolu
    meter -->|latest sample| prom
```

## Job gateway request flow

The federating gateway (ADR-0002): northbound it is client-compatible with
the Ray Jobs API; southbound it proxies each cluster's real dashboard head.
One hostname per cluster because the stock client's paths carry no cluster
identity.

```mermaid
sequenceDiagram
    participant C as ray job submit<br/>(stock client)
    participant G as Mobula gateway<br/>(demo.ray.example.com)
    participant P as Postgres
    participant H as Ray head<br/>(demo cluster)

    C->>G: GET /api/version
    G->>H: GET /api/version + Bearer ray-token
    H-->>G: {"version": "4", ...}
    G-->>C: passthrough
    C->>G: PUT /api/packages/gcs/{pkg}.zip<br/>Authorization: Bearer user-JWT
    Note over G: authn caller (Phase 2),<br/>RBAC check,<br/>strip user credential
    G->>H: PUT ... + Bearer ray-token
    C->>G: POST /api/jobs/ {entrypoint, runtime_env}
    G->>H: POST /api/jobs/ + Bearer ray-token
    H-->>G: {job_id, submission_id}
    G->>P: record submission (audit + history)
    G-->>C: {job_id, submission_id}
    C->>G: GET /api/jobs/{id}/logs/tail (websocket)
    G->>H: proxied tail (follow-up work)
```

What the gateway deliberately does **not** do: reimplement any job endpoint
server-side (job records and packages live in Ray's internal GCS KV — see
PLAN.md review finding S2), or treat Postgres as the source of truth for
live job state (it holds registry + post-mortem history only, ADR-0004).

## Testing strategy

- **Unit**: state-machine legality, spec validation, pure translators
  (`kuberay.rs`, `kueue.rs`), quota/usage math — in each crate.
- **Store conformance** (`crates/mobula-controller/tests/store.rs`): the
  same scenarios (clusters, pools, allocations, usage samples) run against
  both the in-memory and SQLite stores.
- **Gateway integration** (`crates/mobula-api/tests/gateway.rs`): a mock
  Ray head records everything it receives; tests assert host routing,
  credential swap (user JWT never reaches the cluster), body passthrough,
  fallthrough to control-plane routes, and 502 on unreachable clusters.
  Runs in CI with no cluster required.
- **Contract tests** (`contract.yml`, weekly cron + on change): replay the
  real Python `JobSubmissionClient` against the gateway fronting a live Ray
  head — the drift alarm KubeRay's history says we need (PLAN.md, gate S4).
- **E2E** (gated, on demand + weekly): `kuberay-e2e.yml` provisions a real
  RayCluster through the KubeRay backend on kind; `kueue-e2e.yml` adds Kueue
  and proves the pool contract (first cluster admitted, second queued on
  exhausted quota, clean teardown).
