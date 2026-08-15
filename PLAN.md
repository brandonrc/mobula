# Mobula — Execution Plan

Status: draft, under adversarial review · Companion to [REQUIREMENTS.md](REQUIREMENTS.md)

## Decision record

**D1 — No full Rust rewrite of Ray.** Ray's hot path is already ~240k lines of
C++ (raylet, GCS, core worker, object manager); its public API is a
Python-embedded programming model (cloudpickle + Cython binding), and its
internal gRPC protos (35 files, 13 services) are explicitly unstable. There is
no uv-style speedup or spec-frozen contract to rewrite against. We orchestrate
stock Ray; we never fork or reimplement it.

**D2 — Build at the stable seams only.** Mobula touches Ray *only* through
external contracts, which come in two tiers (per adversarial review S1/S5):
- **Stable:** KubeRay CRDs (v1, versioned) and Ray Serve HTTP ingress
  (user-defined). Primary integration surface.
- **Convention-stable:** Job Submission REST API (`/api/jobs/…`, OpenAPI'd,
  API version "4", but spec sync is manual) — consumed via a *federating
  gateway*, never reimplemented, and guarded by contract tests per Ray
  version. The autoscaler `NodeProvider` interface is `@DeveloperAPI` and
  autoscaler v2 is churning — **not** a seam we build on in v0; capacity is
  actuated through KubeRay CRD fields only.

**D3 — uv-role, not CPython-role.** In the uv↔pip analogy, Ray core is
CPython; Mobula is uv — a Rust rewrite of the slow, operationally clunky
tooling *around* the runtime: control plane, identity, quotas, lifecycle.

**D4 — Nebari-native first, standalone always.** Ship as a Nebari software
pack (Keycloak SSO, NebariApp-provisioned ingress/OIDC, ArgoCD delivery);
maintain a standalone mode (any OIDC IdP, any K8s) in the same binary.

## Phases

### Phase 0 — Foundations
- Cargo workspace: `mobula-api` (REST/gRPC surface), `mobula-core` (domain +
  reconcilers), `mobula-provision` (Provisioner trait + `kuberay` backend),
  `mobula-proxy` (identity-aware proxy), `mobula-cli`.
- CI (fmt, clippy, test, cargo-deny), Apache-2.0 LICENSE (in place; matches
  the nebari-dev org convention for a future org transfer), DCO, ADR
  directory.
- Postgres schema v0 (SQLite dev mode); config loading; structured logging.

### Phase 1 — Multi-cluster job gateway (first drop-in artifact)

> Progress 2026-08-15: static registry, host-routed proxy with token
> injection, and websocket log-tail bridging landed. **Exit criterion met:**
> the contract workflow replays the real Python `JobSubmissionClient`
> (Ray 2.57.0) through the gateway against a live `ray start --head` —
> package upload, submit, status, logs, websocket tail, stop/delete all
> pass (weekly cron = drift alarm). Coverage gated at 90% lines in CI
> (currently 92.7%). Outstanding: durable log capture to object store;
> pin the two-minor Ray version matrix in contract.yml; Nebari pack
> integration lives in the decoupled brandonrc/mobula-pack repo.
- Serve the Ray Job Submission REST surface in Rust as a **gateway in front of
  each cluster's native job API** — never a reimplementation of the dashboard
  head (its endpoints write GCS KV and spawn JobSupervisor actors internally;
  replacing it would mean speaking unstable internal protocols, violating D2).
- Gateway owns: client-compatible surface, routing by cluster, queueing,
  durable log capture to object store, job records in Postgres. Package
  upload and supervisor mechanics pass through to the real head.
- Routing model: **one base URL per cluster** (the stock client's fixed root
  paths leave no cluster-id slot; per-cluster NebariApp hostnames provide
  this naturally). The gateway holds and forwards each cluster's static Ray
  auth token (Ray ≥2.52). Durable log capture happens cluster-side to object
  store — never via the `/api/jobs/{id}/logs` endpoint.
- Includes a minimal static cluster registry (config file), pulled forward
  from Phase 3.
- Gate: record/replay contract tests of the Python `JobSubmissionClient`
  across the supported Ray version matrix (websocket log tail, package
  GET-then-PUT, token auth on/off).
- Exit criterion: `ray job submit --address http://mobula…` works unmodified
  against a KubeRay cluster, including log streaming and package upload.
- P1 ships unauthenticated — multi-tenant deployment is gated on Phase 2.

### Phase 2 — Identity + RBAC

> Progress 2026-08-15: core landed — `mobula-auth` crate (OIDC discovery →
> JWKS with rotation-aware refresh → RS256 JWT validation, iss/aud/exp),
> deny-by-default middleware on control plane AND gateway (cluster hosts
> are never public), three-role matrix (GET/WS→Viewer, mutating→Developer),
> Envoy `ext_authz` check endpoint at /api/v1/authz/check, `serve
> --auth-config` (fail-fast discovery; enables non-loopback binds without
> the dev flag). Six e2e tests against a mock OIDC issuer with real
> RSA-signed tokens: 401 (missing/garbage/expired/wrong-aud), 403
> (viewer-write, unmapped groups), 200 (developer submit), public-path
> narrowing, ext_authz matrix. Outstanding: device-code flow for CLI,
> service-account tokens, durable audit records, FIPS crypto provider.
- Mobula owns JWT validation, device-code flow for CLI, and service-account
  tokens **in both modes** — NebariApp/SecurityPolicy auth is browser-only
  (redirect OIDC + cookies) and would break bearer clients. Nebari mode
  contributes browser SSO brokering, Keycloak client provisioning, ingress,
  and TLS; the Mobula API's own NebariApp sets `auth.enabled: false` with
  bearer auth enforced in-process.
- Deny-by-default RBAC (org → project → resource); audit log.
- Enforcement split by mode: Nebari mode uses Envoy `ext_authz` calling a
  stateless Mobula authz endpoint (no double proxy, no inference-outage
  coupling to control-plane deploys); the inline `mobula-proxy` is the
  standalone-mode path and deploys separately from the control plane.
- Prerequisite gate: wildcard DNS + wildcard-cert listener strategy for
  dynamically stamped surfaces; prefer per-project hostnames with path
  routing; sweep reconciler for orphaned Keycloak clients.

### Phase 3 — Cluster lifecycle controller
- Reconciler over KubeRay CRs: declarative cluster specs, state machine,
  suspend/resume, TTL reaping, per-project quotas (Kueue delegation where
  present).
- Per-surface NebariApp stamping for authenticated external access.

### Phase 4 — Dynamic allocation + services
- Autoscaler policy engine (spot strategy, fair share, cost model), ephemeral
  per-job clusters, Ray Serve service management (canary/rollback).

## Verification gates (why we believe each phase is buildable)

- P1 gate: the job API is served by the dashboard head (aiohttp) — confirm the
  endpoint list against the shipped Ray version at implementation time and
  pin a supported-versions matrix (latest two minors).
- P2 gate: NebariApp Auth Reconciler provisions the Keycloak client — reuse
  the exact pattern proven in rayserve-pack.
- P3 gate: KubeRay CRD compatibility documented per release.

## Prior art (web + ray-source verified, 2026-08-14)

Findings from the Rust-rewrite prior-art sweep; each reinforces a decision:

- **Ray's own co-founder already ran the full-rewrite experiment — and its
  numbers close the case for D1.** Upstream branches `cc-to-rust` /
  `cc-to-rust-experimental` (Ion Stoica, Feb–Apr 2026; PR #61413 closed
  unmerged) ported GCS/raylet/core-worker/object-store to a 16-crate Rust
  workspace, reaching true drop-in status (rebuilt `_raylet.so`, `import ray`
  unchanged, RDT suite parity). His own analysis: Rust GCS is **1.1–1.8×**
  C++, further optimization bought ~nothing; the spectacular early wins were
  latent C++ bugs (one TCP_NODELAY fix: 420×). If the co-founder's drop-in
  rewrite is unmerged and yields <2×, an outside one is not a product.
- **The Jobs REST API is the one deliberate public surface** (in-tree OpenAPI
  3.1 spec, own version constant `"4"`, feature-gated to Ray 1.9) — but it is
  labeled Beta and the spec is hand-synced. **KubeRay's Go dashboard client
  is the only prior reimplementation** and paid a ratcheting version floor
  (2.0→2.8→2.38) with hand-copied structs. Confirms the gateway-not-server
  framing and the S4 contract-test gate; KubeRay's client is our reference
  implementation for the Phase 1 southbound.
- **~110 control-plane RPCs across the internal protos carry no stability
  statement**; the only proto stability contract (`src/ray/protobuf/public/`)
  covers telemetry/export events exclusively. Confirms D2's tiering.
- **No third-party Ray runtime exists** — no `import ray` shim, no `ray://`
  or raylet reimplementation anywhere. Nearest neighbors: PyTorch Monarch
  (Rust hyperactor backend — a Ray Core *competitor*, not replacement) and
  Daft/Flotilla (runs *on top of* Ray). Rust actor crates (ractor, kameo)
  offer no object store/autoscaler/libraries. The control-plane lane Mobula
  occupies is empty.
- **Even uv wasn't drop-in** — it replaced pip's *artifact* contract (the
  PEPs) and openly declined its CLI contract (`pip.conf`, index defaults),
  and its speed is mostly what it *doesn't* do, not Rust. Justifies dropping
  "drop-in" from Mobula's vocabulary in favor of "client-compatible at the
  Jobs API".

## Adversarial review log

- 2026-08-14: plan submitted to three independent Fable reviewers
  (seam-stability, architecture/state, product/adoption). Findings recorded
  below with dispositions.

### Review 1 — architecture/state (2026-08-14)

| # | Finding | Disposition |
|---|---|---|
| A1 | Phase 1 as "endpoint-for-endpoint reimplementation" violates D2: the dashboard head's job endpoints write runtime-env packages into GCS KV and spawn JobSupervisor actors via internal APIs — replacing it means speaking unstable internal protocols. | **Accepted.** Phase 1 reframed as a **multi-cluster job gateway**: authn, routing, queueing, durable logs/records *in front of* each cluster's native job API. Exit criterion unchanged. |
| A2 | NebariApp/SecurityPolicy auth is browser-only (redirect OIDC + cookies); bearer/CLI/device-flow requests would get HTML redirects. Nebari mode saves less of §3.6 than claimed. | **Accepted.** §1.2 narrowed: platform primitives cover *browser* surfaces only; Mobula owns JWT validation, device-code flow, and service accounts in both modes. Mobula API's own NebariApp sets `auth.enabled: false`, bearer auth enforced in-process (or verify SecurityPolicy JWT passthrough first). |
| A3 | Dynamic per-cluster NebariApp stamping needs wildcard DNS/cert strategy (each CR needs concrete hostname/redirectURI); ephemeral clusters churn Keycloak clients; failed deletes orphan them silently. | **Accepted.** Per-project hostnames with path routing where possible; orphaned-client sweep reconciler; wildcard-cert listed as explicit P2/P3 gate prerequisite. |
| A4 | Postgres-truth vs KubeRay-CR-truth split-brain: kubectl edits stomped or silently drifting; Postgres restore mass-terminates; HA failover double-provisions VMs. | **Accepted (mitigations, not redesign).** Postgres stays truth. Server-side-apply with `mobula` field manager + drift alarms (never silent stomps); idempotency keys persisted transactionally for provisioner calls; documented contract: Mobula-owned CRs are not hand-editable and are invisible to GitOps by design. |
| A5 | Inline mobula-proxy in front of Serve double-proxies in Nebari mode and makes control-plane deploys an inference-outage risk — contradicts the no-dispatch-path principle. | **Accepted.** Nebari mode: RBAC via Envoy `ext_authz` calling a stateless Mobula authz endpoint. Inline proxy reserved for standalone mode, deployed separately from the control plane. |
| A6 | Phase 1 needs a minimal cluster registry (from P3) pulled forward, and ships unauthenticated until P2. | **Accepted.** P1 includes a static config-file cluster registry; multi-tenant deployment explicitly gated on P2. |

### Review 2 — seam stability (2026-08-14, verified against ray source)

| # | Finding | Disposition |
|---|---|---|
| S1 | Job API stability is strong convention, not contract: OpenAPI spec sync is manual and unchecked (`job_head.py:219-227`), client only enforces `min_version="1.9"`. | **Accepted.** D2 annotated; contract-test gate added (S4). |
| S2 | Reimplementation is unbounded — job records and uploaded packages live in GCS internal KV (`job_head.py:774`, `packaging.py:402,440`); submit/stop/logs proxy to the undocumented job-agent API (`job_head.py:136-186`); log tail is a websocket proxy. Confirms A1 independently. | **Accepted.** Phase 1 is a federating gateway; Postgres is registry + post-mortem history, never live-job truth. |
| S3 | Multi-cluster routing breaks the stock client — `--address` hits fixed root paths, no cluster-id slot; package GET-then-PUT must land on one cluster. | **Accepted.** Per-cluster base URL is the Phase 1 routing model (one hostname per cluster, which per-cluster NebariApp provides anyway). |
| S4 | No parity guarantee across Ray versions. | **Accepted.** P1 gate: record/replay contract tests of the Python `JobSubmissionClient` against the supported version matrix — websocket tail, package GET-then-PUT, Ray token auth on/off. |
| S5 | Autoscaler seam OVERSTATED: `NodeProvider` is `@DeveloperAPI`, autoscaler v2 is churning, and "read demands from GCS" (REQ §3.2) is an internal protocol — violates D2. | **Accepted.** §3.2 re-scoped: v0 actuates only via KubeRay CRD fields (worker-group replicas/min/max); demand sensing stays inside Ray/KubeRay; GCS demand-reading marked out-of-scope. |
| S6 | Ray ≥2.52 ships its own token auth on dashboard/job API; the gateway must hold and forward cluster tokens. Big logs/packages through Envoy + gateway risk body-size/timeout limits; durable capture must not rely on the logs endpoint. | **Accepted.** Token brokering added to P1; durable logs collected from the cluster side (object store), not via `/api/jobs/{id}/logs`. |

### Review 3 — product/adoption (2026-08-14, web-verified)

| # | Finding | Disposition |
|---|---|---|
| P1 | Verdict BUILD-BUT-CUT: the gap is real but narrowing — KubeRay v1.4 has an experimental dashboard + alpha APIServer v2, and Ray joined the PyTorch Foundation, so expect a funded official incumbent for "FOSS Ray UI" within 12–24 months. | **Accepted.** Positioning is identity/governance-first ("per-user SSO, RBAC, quotas, audit across clusters"), never "a UI for KubeRay". |
| P2 | Stale premise: Ray 2.52+ has built-in token auth (single static, non-expiring, cluster-wide secret — no per-user identity). "Unauthenticated dashboard" wording corrected; the *identity* gap survives and is the killer feature: Mobula holds the static token, users get per-user SSO'd access. | **Accepted.** REQUIREMENTS §3.6 updated. |
| P3 | Maintenance treadmill ≈ 0.5–1 FTE across four upstream tracks (Ray biweekly w/ churning auth surface, KubeRay quarterly, nebari-operator "APIs may change", Keycloak majors). | **Accepted as standing cost.** Version-matrix contract tests (S4) are the mitigation; supported-versions policy stays at two Ray minors, no more. |
| P4 | v1 scope as written is 3–5 person-years. | **Accepted.** "v0 cut line" section added below; REQUIREMENTS v1 targets stand as direction, not commitment. |
| P5 | Trademark: "Mobula, a control plane for Ray®" is correct nominative form; add LF attribution to README; keep "ray" out of domains. | **Accepted.** README updated. |

### Review 4 — distributed-systems literature audit (2026-08-15, web + ray-source verified)

Full reading list: [docs/READING.md](docs/READING.md).

| # | Finding | Disposition |
|---|---|---|
| L1 | Enforced cluster state machine conflicts with K8s design principles ("status must be 100% reconstructable by observation"; `phase` enums deprecated) — `can_transition` would reject observed reality (out-of-band deletion = Running→Terminated = TransitionError). | **Accepted — ADR-0006.** Level-triggered reconcile with resync + backoff workqueue; status = Conditions + observedGeneration reconstructed from observation; the enum survives only to validate user lifecycle *commands* and as reporting vocabulary. |
| L2 | `.spec.workerGroupSpecs[].replicas` is owned by Ray's autoscaler sidecar (pairs decrements with `workersToDelete`); external writers fight it (Ray ArgoCD guide, ray#55736, ray#50868). CA FAQ: never run a second autoscaler over the same capacity. | **Accepted — ADR-0007.** Field partition: autoscaling on → Mobula owns min/max bounds only, `replicas` excluded from SSA; autoscaling off → Mobula owns `replicas`. Scale-down via Ray's rejectable drain only. |
| L3 | Idempotency under-specified; leader election doesn't fence (client-go docs, Kleppmann); Postgres+CR is a dual write. | **Accepted — ADR-0007.** Keys derived as `{cluster_uid}/{spec_generation}`; transactional-outbox intent rows; stale-generation writes rejected; restored DBs boot in read-only quarantine. |
| L4 | "Weighted fair share" conflicts with DRF (NSDI'11 — weighted slot fairness violates sharing incentive); Borg: quota is admission control, priority-banded and oversold, and "reduces the need for policies like DRF". H-DRF starvation if hierarchies sum raw. | **Accepted.** REQUIREMENTS §3.2 rewritten: quota + priority bands first; where arbitration is needed, Kueue Fair Sharing / weighted DRF — never home-grown weighted fair share. |
| L5 | Spot-first is unsafe as a blanket default for Ray: `ray.put` objects unrecoverable, owner death = `OwnerDiedError` not reschedule, Train `max_failures` defaults to 0; 120s best-effort notice vs 600s drain defaults. | **Accepted.** §3.2 rewritten: head/driver on-demand always; do-not-disrupt semantics for object-holding workers; drain+checkpoint budget ≤120s; spot only for stateless/reconstructable tasks. |
| L6 | Kueue caveats: autoscaling RayClusters escape quota without elastic Workload Slices (v0.15.2+, gated); Kueue-managed RayJob can't target an existing RayCluster. | **Accepted.** Documented as constraints in §3.2/§3.3. |
| L7 | Cluster-as-only-grouping repeats Borg's §8.1 regret (job-name topology encoding); add labels/selectors early. | **Accepted.** Labels + label queries on clusters/jobs pulled into the v0 domain model. |
| L8 | Autoscaling cost function must be explicit and asymmetric (Autopilot): under-provision ≫ waste, churn priced, fast-up/slow-down with deadband; warm pools via balloon pods ≥ priority −10. | **Accepted.** Recorded as the Phase 4 policy-engine spec baseline. |

### Review 5 — red-team security review (issues #1–#8, triaged 2026-08-15)

Converges with Review 4 on one redesign theme: **fail closed, treat config
as security input, and make auditability a first-class output.** The
registry is not "just config" — it is the credential-routing table, and in
Phase 3 it becomes a dynamically written one (SSRF surface).

| Issue | Disposition |
|---|---|
| #1 unauthenticated gateway = RCE | **Gated + guarded now.** `serve` refuses non-loopback binds without `--dev-allow-unauthenticated`; Phase 2 authn is the release gate for any networked deployment; negative tests (401/403) land with it. Issue stays open as the P2 gate tracker. |
| #2 no southbound TLS / unvalidated api_base_url | **Fixed (partial).** Registry validation at startup: scheme allowlist, no userinfo/fragment, token+http refused without `--allow-insecure-transport`. Remaining (open): CA bundle knob, mTLS, link-local denylist for the Phase 3 dynamic registry. |
| #3 DoS: 256MiB buffering, no timeouts | **Fixed (partial).** Southbound connect (10s) + read (120s) timeouts, redirects off. Remaining (open): streaming upload passthrough, concurrency caps, ws idle/message limits — scheduled with the Envoy `ext_authz` split (rate limiting is Envoy's in Nebari mode; standalone needs tower limits). |
| #4 token leaks via Debug; file perms | **Fixed.** Manual `Debug` redacts `auth_token` (tested); registry validation fails fast. Remaining (open): perms check + `auth_token_env`/SecretStore indirection — tracked for the K8s-Secret story in the pack. |
| #5 proxy protocol: redirects, Connection-nominated smuggling, URL-bearing logs | **Fixed.** `redirect::Policy::none()` (3xx passes through raw — tested against a 169.254 Location), Connection-nominated names stripped both directions (smuggling test), upstream errors logged via `without_url()`. |
| #6 supply chain: unpinned images/actions, no SBOM/signing | **Partially fixed.** `packages: write` scoped to image/manifest jobs only; workflow default is `contents: read`. Open: digest-pinned bases, SHA-pinned actions (Dependabot now enabled will surface bumps), rustup checksum, SBOM + cosign + provenance — grouped as the "release engineering" work item before any v0 tag. |
| #7 repo governance | **Fixed.** Branch protection on main (required checks test/coverage/deny/hygiene, no force pushes), SECURITY.md + private vulnerability reporting enabled, Dependabot alerts + security fixes enabled, dependabot.yml (cargo/actions/docker), CODEOWNERS with security-sensitive paths. |
| #8 no audit log; registry not validated | **Fixed (partial).** Structured `mobula::audit` event per proxied request (cluster, method, path, status, latency); duplicate hostname/id + URL validation fails startup; (id, hostname) pairs logged at boot. Remaining (open): durable Postgres audit records with caller identity — lands with Phase 2. |

## v0 cut line (one quarter, 1–3 people)

**In:** KubeRay backend only; single binary; SQLite/Postgres, no HA. Cluster
CRUD + TTL reaping via RayCluster CRs. OIDC login + three fixed roles
(admin/developer/viewer), deny-by-default, audit log. **Killer feature:**
identity-aware proxy for Ray dashboards and the job API — Mobula holds each
cluster's static Ray token, users get per-user SSO'd access no FOSS option
offers. Jobs submit/list/logs *proxied* with durable logs to object store.
Ship as Nebari pack + plain Helm chart.

**Deferred:** VM/static provisioners, Serve management, autoscaler policy,
cost model, SCIM, fair share, workspaces, HA, and any "endpoint-for-endpoint
drop-in" claim beyond what the gateway proxies (reimplement behind the same
URL later only if a reason emerges).
