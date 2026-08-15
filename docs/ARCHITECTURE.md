# Mobula Architecture

How the pieces fit together. Decisions and their evidence live in
[../PLAN.md](../PLAN.md) and [adr/](adr/); this document is the map.

## System context

Mobula is a control plane *beside* Ray, never inside it: it manages cluster
lifecycle, identity, and access, while Ray schedules tasks (ADR-0001). In
Nebari mode the platform supplies browser SSO, ingress, and TLS; Mobula
supplies everything identity-shaped that involves a bearer token.

```mermaid
flowchart LR
    subgraph clients [Clients]
        browser["Browser<br/>(dashboards, UI)"]
        rayjob["ray job submit /<br/>JobSubmissionClient"]
        cli["mobula CLI"]
    end

    subgraph platform ["Nebari platform (NIC)"]
        envoy["Envoy Gateway<br/>TLS + routing"]
        keycloak["Keycloak<br/>OIDC IdP"]
        operator["nebari-operator<br/>NebariApp reconcilers"]
    end

    subgraph mobula [Mobula control plane]
        api["mobula-api<br/>REST + job gateway"]
        authz["authz endpoint<br/>(ext_authz target)"]
        recon["reconcilers<br/>(Phase 3)"]
        db[("Postgres<br/>desired state,<br/>job history")]
    end

    subgraph dataplane [Data plane - one per cluster]
        kuberay["KubeRay operator"]
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
    kuberay --> head
    head --> workers
```

Key invariant (ADR-0003): a caller's credential terminates at Mobula; only
the cluster's static Ray token travels southbound. Nothing in the task
dispatch path goes through Mobula — Serve traffic is authorized via Envoy
`ext_authz`, not proxied inline.

## Crate map

```mermaid
flowchart TD
    cli["mobula-cli<br/><i>the `mobula` binary</i>"] --> api
    api["mobula-api<br/><i>HTTP surface + job gateway</i>"] --> core
    provision["mobula-provision<br/><i>Provisioner trait;<br/>kuberay backend first</i>"] --> core
    proxy["mobula-proxy<br/><i>standalone-mode<br/>identity proxy (Phase 2)</i>"] --> core
    core["mobula-core<br/><i>domain model, state machine,<br/>cluster registry</i><br/>NO cloud/K8s deps"]
```

`mobula-core` is dependency-poor by rule (ADR-0002): cloud SDKs and
Kubernetes clients live only behind the `Provisioner` trait in
`mobula-provision`.

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

- **Unit**: state-machine legality, registry host matching, token
  non-serialization — in each crate.
- **Gateway integration** (`crates/mobula-api/tests/gateway.rs`): a mock
  Ray head records everything it receives; tests assert host routing,
  credential swap (user JWT never reaches the cluster), body passthrough,
  fallthrough to control-plane routes, and 502 on unreachable clusters.
  Runs in CI with no cluster required.
- **Contract tests** (next): replay the real Python `JobSubmissionClient`
  against the gateway fronting each supported Ray minor — the drift alarm
  KubeRay's history says we need (PLAN.md, gate S4).
- **E2E** (later): kind + KubeRay via the rayserve-pack chart.
