# Mobula — Requirements

**A FOSS alternative to Anyscale: a Rust control plane for Ray clusters with dynamic resource management and cloud-agnostic SSO/RBAC.**

Status: pre-design draft · License: Apache-2.0

---

## 1. Problem statement

Ray is open source, but the operational layer around it is not. Anyscale sells the
control plane: cluster lifecycle, autoscaling policy, job/service management,
workspaces, identity, quotas, and observability — while the Ray runtime itself does
the compute. Teams that can't (or won't) buy Anyscale end up hand-rolling KubeRay +
scripts + reverse proxies + ad-hoc auth. Mobula is that missing control plane,
open source, written in Rust.

**Non-goal:** reimplementing Ray. We orchestrate stock upstream Ray; the data plane
is always vanilla Ray clusters we launch and manage.

## 1.1 Landscape / prior art (and why the gap exists)

| Layer | Existing option | What it gives you | What it doesn't |
|---|---|---|---|
| K8s operator | **KubeRay** (RayCluster/RayJob/RayService CRDs, Kueue for quota) | Declarative lifecycle on any K8s | No identity, no RBAC beyond K8s's own, no UI/API for humans, K8s-only |
| Enterprise K8s distro | **Red Hat OpenShift AI** | Network isolation, mTLS, enterprise auth around Ray | Tied to OpenShift; not standalone FOSS you can run anywhere |
| Managed platform | **Anyscale** | Full control plane: autoscaling, multi-tenancy governance, cost, observability | Proprietary, hosted control plane |
| Data platform | **Ray on Databricks** | Ray + Spark + Unity Catalog governance + MLflow | Locked to Databricks; governance is Unity Catalog's, not yours |
| Cloud-native | GKE/AKS managed Ray options | Autoscaling pools, private networking | Single-cloud, thin on multi-tenancy and RBAC |

**The gap:** everything below the line (KubeRay) is FOSS but headless; everything
above it (Anyscale, OpenShift AI, Databricks) adds identity, governance, and a
human-facing control plane — but is proprietary or platform-locked. Mobula
is the FOSS layer *between* them: KubeRay/Kueue as the K8s substrate, with the
Anyscale-grade control plane (SSO, RBAC, quotas, cost, multi-cloud, durable
observability) open and self-hostable. We compose with KubeRay and Kueue rather
than compete with them, and we stay installable outside OpenShift/Databricks.

## 1.2 Ecosystem strategy: Nebari Infrastructure Core (NIC) as the home platform

We do not build this in a vacuum — the primary deployment target is a **Nebari
software pack** running on a full new-Nebari (NIC) deployment. NIC already
provides, as controlled primitives we operate today:

| Anyscale capability | NIC primitive we reuse |
|---|---|
| SSO / user management | **Keycloak** (platform IdP) — OIDC clients auto-provisioned by nebari-operator's Auth Reconciler |
| Authenticated ingress + TLS | **Envoy Gateway** + cert-manager, declared via one `NebariApp` CR per exposed surface |
| App catalog / discoverability | nebari-landing registration (NebariApp Landing Page Reconciler) |
| GitOps delivery | ArgoCD Applications (sync-wave ordering, as in rayserve-pack) |
| Ray data plane | **KubeRay** operator (RayCluster/RayJob/RayService CRDs) |
| Quota/queueing on K8s | Kueue + ResourceQuota/LimitRange (already templated in rayserve-pack) |

**Relationship to rayserve-pack:** rayserve-pack is the static precursor — one
Helm release = one RayService, auth optional via NebariApp. Mobula is the
dynamic generalization: the Rust control plane is itself deployed as a pack
(`chart/` + `pack-metadata.yaml`, `nebariapp_integration: full`,
`standalone-supported: yes`), and at runtime it *creates and destroys* KubeRay
CRs per project/user — many clusters, jobs, and services — stamping out a
`NebariApp` for each surface that needs authenticated external access (per-cluster
Ray dashboard, per-service Serve endpoint). What is hand-written YAML in
rayserve-pack becomes an API call here.

**Two operating modes, one codebase:**
1. **Nebari-native mode (primary):** delegate SSO brokering, ingress, TLS, and
   client provisioning to Keycloak + nebari-operator. Our Rust backend consumes
   OIDC tokens (Keycloak groups → our RBAC roles) and focuses on what NIC does
   NOT have: Ray cluster lifecycle, dynamic resource allocation, quotas, cost,
   durable observability.
2. **Standalone mode:** the same binary against any OIDC IdP and any K8s ingress,
   for adoption outside Nebari (this keeps the project honest as generic FOSS
   rather than a Nebari-only add-on, and matches the pack template's
   standalone-supported contract).

Design consequence: sections 3.6/3.7 (SSO/RBAC) specify the *contract*. In
Nebari-native mode the platform primitives satisfy the **browser-facing** parts
of 3.6 (redirect SSO, client provisioning, ingress, TLS); Mobula itself owns
JWT validation, CLI device-code flow, service accounts, and all of 3.7 in both
modes, because NebariApp's SecurityPolicy auth is cookie/redirect-based and
cannot serve bearer-token clients.

## 2. Architecture principles

- **Control plane / data plane split.** The Rust backend never sits in the task
  dispatch path. Ray-internal scheduling stays Ray's job; we manage cluster
  lifecycle, capacity, identity, and access from outside.
- **Rust for the control plane.** Single static binary, low idle footprint, strong
  concurrency for reconciliation loops, no GC pauses in the proxy path.
- **Reconciliation model, not imperative scripts.** Desired state in a store;
  controllers converge actual state toward it (Kubernetes-operator mental model,
  whether or not K8s is present).
- **Provider-agnostic core.** Cloud specifics live behind traits (`Provisioner`,
  `IdentityBroker`, `SecretStore`, `ObjectStore`); the core never imports an AWS SDK.
- **API-first.** Everything the UI/CLI can do goes through the same versioned public
  API (REST + gRPC). No hidden admin paths.

## 3. Functional requirements

### 3.1 Cluster lifecycle management
- CRUD for Ray clusters from declarative specs (YAML/JSON): head/worker groups,
  instance shapes, min/max counts, Ray version, container image, env, volumes.
- Provision on: Kubernetes (via KubeRay CRDs as the first provisioner backend),
  raw VMs (AWS EC2, GCP GCE, Azure VM), and bare metal/static node pools.
- Cluster states with a real machine: `Pending → Provisioning → Running →
  Updating → Suspending → Suspended → Terminating → Terminated` (+ `Degraded`).
- Suspend/resume: park a cluster (release compute, keep spec + state) and restore it.
- Rolling upgrade of Ray version / image with drain semantics for worker groups.
- Idle-cluster reaping with per-cluster and per-project TTL policies.

### 3.2 Dynamic resource allocation (the core differentiator)
- **Autoscaler integration (re-scoped per adversarial review):** v0 actuates
  capacity **only via KubeRay CRD fields** (worker-group `replicas`/`minReplicas`/
  `maxReplicas`); demand sensing stays inside Ray's own autoscaler. Reading
  resource demands from GCS directly requires an unstable internal protocol and
  is out of scope; Ray's `NodeProvider` interface is `@DeveloperAPI` (autoscaler
  v2 in flux) and is likewise not a build surface until it stabilizes.
- Scale-to-zero for worker groups; fast cold-start path (pre-pulled images,
  optional warm pools).
- **Heterogeneous pools:** CPU / GPU (by SKU) / high-mem worker groups with
  per-group scaling rules; GPU fractional awareness passthrough.
- **Spot/preemptible strategy:** spot-first with on-demand fallback, preemption
  signal handling (drain before reclaim where the cloud allows it).
- **Quotas & fair share:** hard quotas per org/project (vCPU, GPU-by-type, RAM,
  $/hr estimate); optional weighted fair-share arbitration when aggregate demand
  exceeds capacity. On Kubernetes, delegate queueing/admission to **Kueue** where
  present (map our org/project quotas onto ClusterQueues/LocalQueues) instead of
  reinventing it; our own admission layer is the fallback for VM/static backends.
- Bin-packing / consolidation: prefer filling existing nodes before provisioning;
  compact under-utilized groups on a configurable cadence.
- Cost model: per-cluster and per-job cost estimation from provider price sheets
  (pluggable; static price file acceptable at v0).

### 3.3 Jobs
- Submit, queue, monitor, cancel batch jobs against managed clusters (wraps the Ray
  Job Submission API); jobs may target an existing cluster or request an ephemeral
  per-job cluster (create → run → tear down).
- Retry policy, max runtime, priority classes, and queue-per-project with
  quota-aware admission.
- Log capture to durable storage (object store) so logs outlive the cluster.
- Cron/scheduled jobs.

### 3.4 Services (serving)
- Deploy Ray Serve applications as long-lived managed services: versioned deploys,
  canary %/rollback, health checks, zero-downtime config updates.
- Ingress with per-service authn (see 3.6) and per-service rate limits.

### 3.5 Workspaces (post-v1, but design for it)
- Dev environments attached to a managed cluster (Jupyter/VS Code server pods)
  with the user's identity propagated into the workspace.

### 3.6 SSO — cloud- and IdP-agnostic
- **OIDC as the contract.** Any compliant IdP (Keycloak, Okta, Entra ID, Google,
  Dex, Authentik). No IdP-specific code paths in core.
- Web UI: Authorization Code + PKCE. CLI: device-code flow. Machines: OAuth2
  client-credentials service accounts + scoped, expiring API tokens.
- SCIM 2.0 (or IdP group claims at minimum) for user/group sync.
- **Identity-aware proxy in front of every data-plane surface:** Ray dashboards,
  Serve endpoints, Grafana, workspace UIs all sit behind the Rust proxy. Ray
  ≥2.52 provides only a single static, non-expiring, cluster-wide token (no
  per-user identity); Mobula holds that token per cluster and brokers
  **per-user, SSO-authenticated, RBAC-checked** access on top of it — this
  token-to-identity exchange is the core differentiator.
- Session management: revocation, max lifetime, refresh; audit every auth event.

### 3.7 RBAC
- Model: `Org → Project → Resource (cluster | job | service | workspace)`.
- Built-in roles: `org-admin`, `project-admin`, `developer` (submit/attach),
  `operator` (lifecycle but not code), `viewer`. Custom roles = permission sets.
- Bindings assignable to users, IdP groups, and service accounts.
- Enforcement at the API gateway AND at the proxy (a dashboard URL is not a
  bypass). Deny by default.
- Full audit log: who, what, when, from where, decision — append-only, exportable.

### 3.8 Multi-cloud / provider abstraction
- `Provisioner` trait: `provision`, `terminate`, `list`, `resize`, `preempt_notice`,
  price hints. Backends: `kuberay` (v0), `aws-ec2`, `gcp-gce`, `azure-vm`,
  `static` (bring-your-own nodes).
- Cloud credentials via each cloud's native workload identity where possible
  (IRSA, GCP WI Federation, Azure MI); static keys only as a fallback.
- One control plane may manage clusters across multiple providers/regions
  simultaneously.

### 3.9 Observability
- Prometheus metrics for control plane and per-cluster Ray metrics scrape/relabel.
- Durable job/service logs and Ray event export (object store) — survives cluster
  teardown.
- Structured audit + operational event stream (webhooks / NATS subject).
- Bundled optional Grafana dashboards; no proprietary telemetry, no phone-home.

## 4. Non-functional requirements

- **FOSS:** Apache-2.0, no open-core feature gating of anything in this
  document; governance docs (CONTRIBUTING, DCO) from day one. (Chosen to match
  the nebari-dev org convention — every active NIC-era repo is Apache-2.0 —
  and it carries the explicit patent grant MIT lacks.)
- **Single-binary control plane** (embedded UI assets), plus optional HA mode:
  N replicas, leader-elected controllers, Postgres as the state store (SQLite for
  single-node dev).
- Horizontal scale target: 500 concurrent clusters / 10k nodes per control plane
  at v1 without architectural change.
- Security: TLS everywhere, mTLS control↔cluster agents, secrets never in specs
  (references into `SecretStore`), SBOM + signed releases.
- Compatibility: track latest two Ray minor releases; KubeRay CRD compatibility
  documented per release.
- Ops: `helm install` and `docker compose up` both give a working stack in <10 min.

## 5. Explicit non-goals (v1)

- No fork or patch of Ray core.
- No custom scheduler inside Ray (we shape capacity, Ray schedules tasks).
- No proprietary/enterprise tier — features land in main or not at all.
- No multi-tenancy *inside* one Ray cluster (isolation boundary = cluster).

## 6. Rust stack (proposed, not binding)

| Concern | Choice |
|---|---|
| Async runtime | tokio |
| HTTP/REST + proxy | axum + tower (+ hyper for the IAP layer) |
| gRPC (Ray GCS/API + our API) | tonic + prost |
| Kubernetes/KubeRay | kube-rs (derived CRD types) |
| State | sqlx → Postgres (SQLite dev mode) |
| AuthN | openidconnect + jsonwebtoken; SCIM via own crate |
| AuthZ | cedar-policy (or casbin-rs) evaluated in-process |
| Cloud SDKs | aws-sdk-rust, gcloud-sdk, azure-sdk-for-rust behind the Provisioner trait |
| Events | NATS (optional) / Postgres LISTEN-NOTIFY (default) |

## 7. Open questions

1. KubeRay-first vs VM-first? (Proposal: KubeRay-first — fastest credible v0,
   biggest existing install base.)
2. Do we run our own external autoscaler from day one, or delegate to KubeRay's
   and only own quotas/policy at v0?
3. Ray version skew policy for the GCS/gRPC surfaces we consume (they are not a
   stable public API).
4. ~~Trademark posture~~ Settled: the project is **Mobula** (the devil-ray
   genus) — a ray theme with no "Ray" in the mark. Descriptive wording like
   "a control plane for Ray®" remains subject to Anyscale's trademark
   guidelines.
