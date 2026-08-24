# Mobula v1 Management API — Proposal

**Status:** DRAFT / Proposal — 2026-08-15 — not yet ratified; nothing here is a
commitment until this header flips to Accepted.
**Author:** mobula-ui working session
**Reviewers:** TBD (control-plane maintainer, gateway/auth maintainer, UI lead)
**Consumes:** `mobula-ui/docs/ui-ux-spec.md` §8 (which this document
supersedes in detail) and §5 (screen backing). Grounded in
`crates/mobula-api`, `mobula-core`, `mobula-auth`, `mobula-controller`,
`mobula-provision` as of this date.

---

## 1. Scope and ground rules

**This is the control-plane, path-based API.** Everything below lives under
`/api/v1/` on the control-plane host. Cluster-bound traffic (the Ray Jobs API,
log tails, dashboard data) continues to be **hostname-routed through the
federating gateway** (ADR-0002): one hostname per cluster, because the stock
`ray job submit` client has no cluster-id slot. The browser never constructs
cluster hostnames and never sees them in API responses — the UI reaches
per-cluster data exclusively through the path-based proxy endpoints in §5.6,
which perform the same credential swap as the gateway (caller JWT terminates
at Mobula; the cluster's static Ray token travels southbound, ADR-0003).

**API-first.** Everything the UI or CLI can do goes through this versioned
surface; no hidden admin paths (REQUIREMENTS §2). Enforcement is deny-by-default
at the outer middleware, with per-route permission checks inside handlers
(`auth_layer.rs:120`), not the method→permission heuristic — that heuristic is
for the proxied Ray surface only (#26).

**OpenAPI is the contract.** Every new endpoint MUST carry `#[utoipa::path]`
decorators, register in `ApiDoc` (`mobula-api/src/lib.rs:24`), and register its
schemas under `components(...)`. The vendored `openapi.json`
(`cargo test -p mobula-api export_openapi`) is what mobula-ui generates its
TypeScript types from in CI — an endpoint that isn't in the OpenAPI document
does not exist as far as the UI is concerned.

**What exists today.** `GET/POST /api/v1/clusters`, `GET/DELETE
/api/v1/clusters/{id}`, and `POST /api/v1/clusters/{id}/suspend` + `/resume`
(#51) are already implemented behind `Store`
(`clusters.rs`), with quota admission wired. Everything else in this document
is greenfield. Where the proposal changes existing behavior, §8 calls it out.

## 2. Conventions

### 2.1 Serialization

- JSON everywhere; field names are the serde defaults of the Rust types —
  snake_case, exactly as in `mobula-core`.
- Timestamps are **unix seconds** (`u64`), matching `StoredCluster.created_at`
  and `now_unix()`. The UI renders relative-with-absolute-tooltip; the API
  does not carry RFC 3339 strings.
- Enums serialize snake_case (`ClusterState` has
  `#[serde(rename_all = "snake_case")]`). Roles serialize snake_case:
  `viewer`, `developer`, `operator`, `admin`, `auditor`.
- `Option<T>` fields are always present in responses, serialized as `null`
  when absent — generated clients should never have to guess field presence.

### 2.2 RBAC: who may call what

The code's model (ADR-0009, `mobula-auth/src/lib.rs`) is **permission-sets**,
not an ordinal rank: `PermissionType {Read, Write, Delete, Admin}` ×
`Target {Job, Cluster, Service, Pool, Audit}`, five built-in roles. The
baseline is
flat group→role mapping (a group-derived role applies globally); on top of
that, **scoped role bindings** (below) grant roles per principal at a scope.

Effective v1 matrix (from `Role::grants`):

| Endpoint class | Required permission | Roles that pass |
|---|---|---|
| Any `GET` on cluster data | `Read` on the route's target | Viewer and above |
| Cluster lifecycle mutations (create, patch, suspend, resume, terminate) | `Write`/`Delete` on `Target::Cluster` | Operator, Admin |
| Job-surface mutations (submit, stop, delete via proxy) | `Write` on `Target::Job` | Developer, Admin |
| Pool topology reads (`GET /api/v1/pools…`) | `Read` on `Target::Pool` | Viewer and above |
| Pool/allocation mutations (`POST`/`DELETE /api/v1/pools…`) | `Write`/`Delete` on `Target::Pool` | Admin only |
| Registry, access-control surfaces | Admin | Admin only |
| Audit trail reads (`/api/v1/audit…`, §5.9) | `Read` on `Target::Audit` | Admin, Auditor |
| Settings (governance policy) reads & edits (`/api/v1/settings/policy`) | Admin (classified with `Target::Cluster`) | Admin only |

Pools and allocations are **platform configuration** (capacity topology), not
app lifecycle — hence Admin-only mutations where clusters are Operator+Admin.

#### Scoped role bindings (ADR-0009 addendum, #49)

A binding `(principal, role, scope)` grants `role` to `principal` (the
Identity `sub` / local username) at `scope`: `"*"` (global — same coverage as
a group-derived role) or `"project:<name>"`. Bindings are stored in the
`role_assignments` table and administered via:

| Route | Authz | Effect |
|---|---|---|
| `GET /api/v1/access/assignments` | Admin | List all bindings |
| `PUT /api/v1/access/assignments/{principal}` `{ "role", "scope" }` | Admin | Upsert one binding (400 on unknown role / bad scope grammar) |
| `DELETE /api/v1/access/assignments/{principal}?role=&scope=` | Admin | Remove one binding (404 if absent) |

Semantics are **additive grants only** — a binding can add permissions, never
subtract; there are no deny rules. A principal with no bindings gets exactly
the flat group→role mapping above; a principal with bindings gets the union
of their group-derived roles and the binding roles whose scope covers the
target's project. Enforced in v0 only on the cluster routes
(`POST/GET/DELETE /api/v1/clusters…` — the check is scoped to the spec's /
stored cluster's project; `GET /api/v1/clusters` is filtered per-project for
callers without global `Read`). All other routes keep the flat checks;
extending enforcement (and group-principal bindings, which belong to the
OIDC-mapping layer) is follow-up work. Evaluation is one indexed
`role_assignments` read per request that fails the flat fast path.

> **Delta vs ui-ux-spec §5.3:** the spec's persona table has *Developers*
> creating clusters. Current code grants `Developer` only `Read` on
> `Target::Cluster` — cluster create requires `Operator` or `Admin`. This
> proposal follows the code. If the product decision is that Developers create
> clusters, that's an RBAC change in `mobula-auth`, not an API change; the
> endpoints and error shapes below are unaffected. Tracked in §8.

### 2.3 Error envelope

All 4xx/5xx from control-plane routes return one shape (the proxied Ray
surface in §5.6 excepted — it passes upstream bodies through):

```json
{
  "error": {
    "code": "forbidden",
    "message": "insufficient permission",
    "details": { }
  }
}
```

`code` is a stable, machine-consumable string; `message` is the human string
(usually the `thiserror` Display of the underlying error); `details` is
code-specific. Defined codes:

| HTTP | code | When | `details` |
|---|---|---|---|
| 400 | `invalid_spec` | Spec validation failed (`min_replicas ≤ replicas ≤ max_replicas`, non-empty names, parseable quantities) | `{ "field": "worker_groups[0].replicas", "reason": "..." }` |
| 401 | `unauthenticated` | Missing/invalid token. Keeps today's `WWW-Authenticate: Bearer` header. | — |
| 403 | `forbidden` | Authenticated but lacking the permission. Carries what the audit event already records. | `{ "required": { "action": "write", "target": "cluster" }, "granted_roles": ["viewer"] }` |
| 404 | `not_found` | No such cluster/job/registry entry. | — |
| 409 | `illegal_state_transition` | Lifecycle action rejected by `ClusterState::can_transition`. | `{ "from": "terminated", "to": "suspending" }` |
| 409 | `quota_exceeded` | Project quota admission failure (existing behavior, `clusters.rs:191`). | `{ "project": "...", "limit": {...}, "in_use": {...}, "requested": {...} }` |
| 409 | `duplicate_hostname`, `duplicate_id` | Registry write conflicts (§5.4). | offending value |
| 422 | `invalid_url`, `invalid_hostname`, `cleartext_token` | Registry validation (`RegistryError`, §5.4). | variant fields |
| 502 | `cluster_unreachable` | Southbound connect/transport failure on a proxy endpoint (§2.6). | — |
| 500 | `internal` | Store/provisioner backend errors. Never leaks internals beyond a log-correlatable message. | — |

The structured 403 replaces today's bare `"insufficient permission"` text body
(§8). The UI's denial page (ui-ux-spec §6: "fail-closed mirrors backend")
renders from `details.required` / `details.granted_roles`.

### 2.4 Idempotency (ADR-0007)

No client-minted `Idempotency-Key` headers. Keys are **derived**:
`{cluster_uid}/{spec_generation}` — the same desired state always produces the
same intent key (`StoredCluster::intent_key`), so:

- `POST /api/v1/clusters` is an **upsert**. Resubmitting the wizard after a
  network failure is safe: an unchanged spec returns the existing generation,
  a changed spec bumps it. Double-create is impossible by construction.
- `PATCH` has the same property (§5.2).
- Lifecycle action endpoints (`suspend`, `resume`, `terminate`) are naturally
  idempotent: repeating an action against a cluster already in (or heading
  to) the target state succeeds; only a *different* illegal transition is a
  409.

Replays that reach the provisioner compare parameters and return the stored
response, per the transactional-outbox design in ADR-0007.

### 2.5 Pagination

List endpoints take `?limit=` (default 50, max 200) and `?cursor=` (opaque),
and return an envelope:

```json
{ "items": [ ], "next_cursor": null }
```

`next_cursor: null` means exhausted. Cursor order is stable (creation time,
then id) but the cursor value itself is opaque — clients must not parse it.

Applies to: `GET /clusters`, `GET /registry/clusters`, `GET /jobs`,
`GET /audit`. **Milestone-A implementations backed by the static registry
return everything with `next_cursor: null`** — the envelope shape is what the
UI codes against, so the Phase-3 Postgres swap is invisible to clients.

### 2.6 Cluster-unreachable semantics (502)

Proxy endpoints (§5.6, §5.7) inherit the gateway's rules
(`gateway.rs`): a southbound connect/transport failure is
`502 cluster_unreachable` — for websockets, the southbound connection is
established *before* the client upgrade is accepted, so an unreachable
cluster is a clean 502, never a dead socket. Upstream Ray responses (404s,
validation errors, log bodies) pass through **byte-for-byte with their
original status** — Mobula does not wrap, re-encode, or retry Ray's own
errors into a different cluster. The UI treats 502 as the "backend
unreachable" empty-state variant, distinct from a 404 (no such job) or 403.

### 2.7 Versioning policy

- The version lives in the path: `/api/v1/`. Breaking changes ship as
  `/api/v2/` mounted **alongside** v1; v1 is removed only after a deprecation
  window announced in release notes.
- Additive changes (new fields, new endpoints, new enum values) land in v1
  without ceremony. Clients must tolerate unknown fields.
- `ClusterState` is an **open vocabulary to clients**: new variants may
  appear in v1. The UI must render unknown states with a generic badge, never
  crash on an exhaustive match. (ADR-0006 already demotes the enum to
  reporting vocabulary derived from Conditions; a `ClusterCondition[]`
  surface may be added later — additive.)
- `GET /api/v1/version` (existing) reports the control-plane semver; the
  UI's health indicator consumes it plus `/healthz` (both public,
  `auth_layer.rs:26`).

## 3. Wire types

These are the serde projections of the real Rust types; the Rust source is
authoritative and the OpenAPI components are generated from it.

### 3.1 `ClusterSpec` (`mobula-core/src/cluster.rs:24`)

```json
{
  "name": "string",
  "project": "string",
  "ray_version": "2.52.0",
  "image": "rayproject/ray:2.52.0-py311",
  "head_cpu": "4",
  "head_memory": "16Gi",
  "worker_groups": [ { "…": "WorkerGroup" } ],
  "ttl_seconds": 3600
}
```

`ttl_seconds: null` disables idle reaping. CPU/memory/gpu are **strings**
(K8s quantity syntax, e.g. `"4"`, `"16Gi"`, `"nvidia.com/gpu: 4"`) — they map
onto RayCluster CR fields; the API does not reinterpret them. Labels, env,
volumes are *planned* fields (ui-ux-spec §5.3): they are not in the type
today; when added they are additive optional fields.

### 3.2 `WorkerGroup` (`cluster.rs:42`)

```json
{
  "name": "gpu-a100",
  "cpu": "16",
  "memory": "64Gi",
  "gpu": "nvidia.com/gpu: 4",
  "min_replicas": 2,
  "max_replicas": 8,
  "replicas": 3
}
```

Server-side validation mirrors the wizard: non-empty `name`,
`min_replicas ≤ replicas ≤ max_replicas`. Field ownership (ADR-0007): with
in-tree autoscaling enabled Mobula owns only `min_replicas`/`max_replicas` —
the API still accepts `replicas` (it's the initial/desired count for
non-autoscaled groups), but the UI disables the field when autoscaling is on,
and the reconciler excludes it from its server-side-apply field set. Scale is
group-level only (decision D2): there is no per-node mutation anywhere in
this API.

### 3.3 `ClusterState` (`cluster.rs:55`)

Nine values, snake_case: `pending`, `provisioning`, `running`, `degraded`,
`updating`, `suspending`, `suspended`, `terminating`, `terminated`.

`can_transition` validates **user-issued lifecycle commands against desired
state only** (ADR-0006) — observed reality is recorded, never rejected. The
resume edge is `suspended → provisioning` (reprovision); there is no
`suspended → running` shortcut, and `terminated` is terminal. The action
endpoints in §5.3 map onto these edges and return 409
`illegal_state_transition` off them.

### 3.4 `ClusterView` (`mobula-api/src/clusters.rs:53`, extended)

The one cluster representation, used by list, detail, and action responses.
**Additive extensions over the current type** marked ✱ (§8):

```json
{
  "id": "demo",
  "generation": 3,
  "desired": "running",
  "observed_state": "running",
  "observed_generation": 2,
  "project": "ml-platform",
  "ray_version": "2.52.0",
  "spec": { "…": "ClusterSpec" },          ✱
  "created_at": 1755280000,                ✱ unix seconds
  "est_min_hourly": 4.21,
  "est_max_hourly": 18.40
}
```

- `desired`: operator intent — `"running" | "terminated"` today;
  `"suspended"` arrives with the `DesiredState::Suspended` variant (§8).
- `generation` vs `observed_generation` is the drift signal (K8s convention):
  divergence means a reconcile is in flight. The detail header's
  "spec generation N → observed generation M" indicator renders exactly this.
- `observed_state: null` = never reconciled (or, in Milestone A, sourced from
  the static registry which has no observation).
- `project` and `ray_version` are denormalized conveniences duplicated from
  `spec` (kept for back-compat with the existing schema); `spec` is
  authoritative.
- `est_*_hourly` are `null` unless a price sheet is configured
  (`PolicyConfig`); the UI hides cost affordances on `null`.

### 3.5 `RegistryClusterView` (projection of `ClusterEndpoint`, `registry.rs:11`)

```json
{
  "id": "demo",
  "hostname": "demo.ray.example.com",
  "api_base_url": "https://demo-head-svc:8265",
  "token_set": true,
  "validation": null
}
```

`auth_token` is **write-only**: the type has `skip_serializing`
(`registry.rs:21`) and a redacting `Debug`. The API exposes only
`token_set`. There is no reveal endpoint and there never will be one;
rotation is a replace-write (§5.4, Phase 3).

### 3.6 `Identity` (`mobula-auth/src/lib.rs:76`)

```json
{
  "subject": "u1234",
  "email": "ada@example.com",
  "groups": ["/ml-eng", "/platform-admins"],
  "roles": ["developer", "viewer"]
}
```

`roles` is the caller's full role set (union semantics — `Identity::permits`
is an `any` over held roles). The UI renders role-gated affordances from this
array, never from hardcoded assumptions.

## 4. Milestone A — the minimal read-only slice (implementable today)

Three endpoints, all servable against Phase-2 code with **no persistence**:

| Endpoint | Source today | Phase-3 source | Breaks on swap? |
|---|---|---|---|
| `GET /api/v1/identity` | request `Identity` extension | same | no |
| `GET /api/v1/registry/clusters` | static `ClusterRegistry` (TOML) | dynamic registry table | no — same schema |
| `GET /api/v1/clusters` | static registry, each entry mapped to a `ClusterView` | `Store::list()` + observation | no — same envelope |

The Milestone-A `GET /clusters` synthesizes views from registry entries:
`id` from the entry, `desired: "running"`, `observed_state: null`,
`generation: 0`, `spec` unknown → **this is the one wrinkle**: `ClusterView.spec`
must be nullable in the wire schema (`spec: ClusterSpec | null`) precisely so
the registry-backed slice and the store-backed slice share one type. The UI
already has a "registry-only entry" visual state (the empty-state copy in
ui-ux-spec §5.2 distinguishes *registered* from *managed* clusters), so
`spec: null` is rendered as "registered, unmanaged — spec not available".

Pagination envelope (§2.5) and error envelope (§2.3) apply from day one, so
nothing about the response shape changes when Postgres lands. Full
definitions in §5.1, §5.4, §5.8.

## 5. Endpoints

Existing public routes (`GET /healthz`, `GET /api/v1/version`,
`GET /api/v1/openapi.json`, `/docs`) are unchanged. All routes below require
a Bearer JWT and sit behind the deny-by-default middleware.

### 5.1 Clusters

#### `GET /api/v1/clusters`

List clusters. Backs the cluster list (ui-ux-spec §5.2) and, degraded, the
Milestone-A list.

- **Auth:** `Read` on `Target::Cluster` (Viewer+).
- **Query:** `limit`, `cursor` (§2.5); `?project=` and `?state=` filters
  (server-side once the store exists; Milestone A ignores them — the UI
  filters client-side and must keep that fallback).
- **Response 200:** `{ "items": [ClusterView], "next_cursor": null }`.
- **Errors:** 401, 403.

#### `POST /api/v1/clusters`

Create (upsert) a managed cluster. Backs the wizard (§5.3). **Implemented**
(`clusters.rs:158`), including quota admission → 409 `quota_exceeded`.

- **Auth:** `Write` on `Target::Cluster` (Operator, Admin).
- **Body:** `CreateCluster` — `{ "id": "string", "spec": ClusterSpec }`.
  `id` is the stable cluster id, also the gateway routing key / RayCluster
  name; DNS-label-safe (validated, 400 `invalid_spec` otherwise).
- **Idempotency:** upsert; unchanged spec returns the current generation,
  changed spec bumps it (§2.4). Resubmission-safe by construction.
- **Response 201:** `{ "id": "demo", "generation": 1 }`.
- **Errors:** 400 `invalid_spec`, 403, 409 `quota_exceeded`.

#### `GET /api/v1/clusters/{id}`

Cluster detail. Backs the detail page (ui-ux-spec §5.4). **Implemented**
(`clusters.rs:136`); gains the ✱ fields of §3.4.

- **Auth:** `Read` on `Target::Cluster`.
- **Response 200:** `ClusterView` (full, including `spec`).
- **Errors:** 404 `not_found`.

#### `PATCH /api/v1/clusters/{id}`

Spec update → new generation. Backs the config-edit flow (wizard pre-filled +
diff review, §5.4). **New.**

- **Auth:** `Write` on `Target::Cluster`.
- **Body:** full `ClusterSpec` (**replace semantics**, not JSON-merge). The
  declarative model treats the spec as an artifact (ui-ux-spec §5.3 step 6):
  the client submits the complete reviewed spec, the server diffs it
  (`spec_changed`, `store.rs:61`) and bumps `generation` only on real change.
  Same idempotency story as POST.
- **Response 200:** `{ "id": "demo", "generation": 4 }` — 200 even when the
  spec was unchanged (generation returned unbumped).
- **Errors:** 400 `invalid_spec`, 403, 404, 409 `quota_exceeded`.

#### `POST /api/v1/clusters/{id}/suspend` · `/resume` · `/terminate`

Lifecycle actions. Back the detail-page action buttons and list-page action
menus, rendered from `can_transition()` client-side and enforced server-side.
**`suspend` and `resume` are implemented** (`clusters.rs`, #51);
`terminate` remains the DELETE route below.

- **Auth:** `Write` on `Target::Cluster` (Operator, Admin).
- **Semantics:** each sets desired state along a legal edge of
  `ClusterState::can_transition`:
  - `suspend`: `running → suspending` (compute released, spec + state kept).
    The reconciler actuates `spec.suspend: true` through the provisioner's
    suspend call — Mobula owns that field (ADR-0007).
  - `resume`: `suspended → provisioning` — reprovision; no fast path to
    running (the tooltip copy in ui-ux-spec §6 is exactly this rule). The
    reconciler converges via the normal generation-keyed apply, which writes
    `suspend: false`.
  - `terminate`: any non-terminal state → `terminating`; `terminated` is
    terminal, so terminating a `terminated` cluster is a 409, not a no-op.
- **Kueue interaction (ADR-0010):** for a cluster whose project is admitted
  through a pool queue, Kueue owns `spec.suspend` (gang scheduling holds
  unadmitted workloads suspended). `suspend`/`resume` on such a cluster are
  rejected with **409 `queue_owned_suspend`** — detach the project's pool
  allocation first if a manual suspend is really wanted. The reconciler
  likewise never "repairs" a queued cluster's Suspended state.
- **Response 202:** `{ "id": "demo", "state": "suspending", "generation": 4 }`.
  Actions are long-running: the UI transitions optimistically to the
  intermediate state and polls `GET /clusters/{id}` (SSE later) until
  `observed_state` settles (ui-ux-spec §6 async-action pattern).
- **Errors:** 403, 404, 409 `illegal_state_transition` with
  `{ "from": ..., "to": ... }` (meaningless commands — e.g. suspending an
  already-suspended or not-yet-provisioned cluster, resuming a running one),
  409 `queue_owned_suspend` (above). Both 409s are audited as denies.
- **Note:** the existing `DELETE /api/v1/clusters/{id}` (`clusters.rs:228`)
  is terminate-equivalent (desired = Terminated). It stays for CLI
  back-compat; the POST action is canonical for the UI. Same permission,
  same 409 behavior (§8).

#### Provisioned security posture (#56, #62)

Cluster creation is not just a RayCluster: with the KubeRay backend, every
actuating apply first ensures the **namespace-level** security posture
(`Provisioner::ensure_namespace_posture`, called by the reconciler — one
posture covers every cluster in the namespace). This is the tenant network
isolation + STIG pod-security floor (compliance gap assessment §4.3/§4.7;
K8s STIG V-242437). Posture failures are **fail-closed**: the RayCluster
apply does not proceed.

What Mobula ensures (server-side apply, field manager `mobula`):

- **`mobula-default-deny` NetworkPolicy** — selects all pods in the
  namespace, denies all ingress+egress.
- **`mobula-tenant-allow` NetworkPolicy** — the minimal Ray allows:
  same-namespace pod-to-pod (head↔workers: GCS 6379, dashboard 8265,
  client 10001, raylet dynamic ports); ingress from namespaces labeled
  `mobula.dev/control-plane=true` (documented constant
  `CONTROL_PLANE_NAMESPACE_LABEL` — operators label the control-plane
  namespace once) to the head's TCP 8265/10001 only; egress to kube-dns
  (`kube-system`, `k8s-app: kube-dns`, 53 UDP/TCP).
- **Pod Security Standards labels on the namespace** —
  `pod-security.kubernetes.io/enforce: baseline` plus `warn`/`audit:
  restricted`. Enforce is baseline, not restricted, because
  KubeRay-generated Ray pods do not carry the full restricted
  `securityContext` (`runAsNonRoot`, seccomp, drop-all capabilities) and
  would be rejected; warn/audit at restricted keep the gap visible.

What admins can tighten — check-then-apply never weakens a stricter
posture:

- A default-deny NetworkPolicy **not** managed by Mobula (any name) means
  the admin owns the network posture: Mobula leaves all NetworkPolicies in
  the namespace untouched, including its own allow rules (which could only
  widen an admin's tighter policy set).
- A namespace already at `enforce: restricted` is never downgraded.
- Admins may add further allow policies (tenant egress to object stores,
  registries) — NetworkPolicies are additive, so Mobula's floor composes.

Requirements and limits: NetworkPolicy needs a CNI that enforces it
(kind's kindnet does not; Cilium/Calico do); node-local and `hostNetwork`
traffic bypasses policy. Demo mode (`--demo`) provisions nothing and
ensures no posture.

### 5.2 (reserved — see §5.1/PATCH)

### 5.3 Nodes — `GET /api/v1/clusters/{id}/nodes`

Aggregated node/worker-group view for the nodes tab (ui-ux-spec §5.4).
Observability only (D2): no per-node mutation exists or is planned.
**Implemented** (Milestone C, `cluster_obs.rs`).

- **Auth:** `Read` on `Target::Cluster`, read-scoped (#49): a project-scoped
  developer sees only their projects' clusters; a cluster outside scope is
  404 (existence is not leaked), matching `GET /clusters/{id}`.
- **Source (refinement of the draft):** **Kubernetes**, not the Ray API. The
  breakdown is read from the RayCluster (`spec.workerGroupSpecs` for group
  names + desired replicas) and the pods KubeRay owns for it
  (`ray.io/cluster=<id>`), via the cluster provisioner. Kubernetes is the
  authority for "what pods exist and where", and it answers even when the Ray
  dashboard is unreachable — which is exactly when the nodes tab is most
  needed. It follows that `NodeView` reports Kubernetes facts (pod
  phase/readiness, scheduling, **requested** compute), not Ray runtime usage;
  live per-node utilization stays a later Ray-API concern.
- **Response 200:**

```json
{
  "cluster_id": "team-b-scoring",
  "head": { "…": "NodeView" },
  "worker_groups": [
    {
      "name": "gpu-a100",
      "desired": 2,
      "ready": 1,
      "nodes": [ { "…": "NodeView" } ]
    }
  ]
}
```

`head` is absent until KubeRay creates the head pod. `desired` is the
group's `replicas`, or `minReplicas` when autoscaling leaves `replicas`
unmanaged (ADR-0007); `ready` counts pods that are `Running` and `Ready`.

```json
// NodeView (Kubernetes-sourced; omitted keys carry no value)
{
  "pod_name": "team-b-scoring-worker-cpu-abc12",
  "group": "gpu-a100",
  "is_head": false,
  "phase": "Running",
  "ready": true,
  "node_ip": "10.42.1.7",
  "host": "ip-10-0-3-21",
  "cpu": 16.0,
  "memory_bytes": 68719476736,
  "gpu": 4.0
}
```

- `group` is absent for the head. `cpu`/`memory_bytes`/`gpu` are the pod's
  container **requests**, summed and parsed from K8s quantities (`500m` →
  0.5, `2Gi` → 2147483648); absent when unset.
- **Errors:** 403; 404 (cluster unknown to Mobula, or the backend exposes no
  node breakdown — gateway-only / demo); 503 when the node source
  (Kubernetes) can't be reached (a graceful degrade, never a panic).

### 5.4 Registry — `GET /api/v1/registry/clusters` (+ Phase-3 writes)

Backs the registry admin screen (ui-ux-spec §5.6). **Read-only in v1
(decision D5)** — edits stay in `clusters.toml` + restart until the
dynamic-registry work and its southbound SSRF hardening (CA bundle knob,
link-local denylist) land. The write surface is specified now so the UI's
Phase-3 form is settled, but ships disabled.

#### `GET /api/v1/registry/clusters` — **Milestone A**

- **Auth:** Admin.
- **Response 200:**

```json
{
  "items": [ { "…": "RegistryClusterView" } ],
  "next_cursor": null,
  "read_only": true,
  "source": "file"
}
```

`read_only: true` tells the UI to render the "restart required after edit"
note and no edit affordances. When the dynamic registry lands, the same
fields become `read_only: false, source: "database"` and the write endpoints
below activate — no schema break. Token values are never present (§3.5).

#### Phase-3 write surface (specified, not built — D5)

`POST /api/v1/registry/clusters`, `PATCH /api/v1/registry/clusters/{id}`,
`DELETE /api/v1/registry/clusters/{id}`. All Admin-only. Bodies use
`RegistryClusterInput`:

```json
{
  "id": "demo",
  "hostname": "demo.ray.example.com",
  "api_base_url": "https://demo-head-svc:8265",
  "auth_token": "write-only-on-input"
}
```

`auth_token` is accepted on input, never returned (write-only password field
with replace semantics in the UI). Validation errors map `RegistryError`
variants 1:1 (`registry.rs:50-70`) so the form can render them inline:

| Variant | HTTP | code | details |
|---|---|---|---|
| `DuplicateHostname(h)` | 409 | `duplicate_hostname` | `{ "hostname": h }` |
| `DuplicateId(i)` | 409 | `duplicate_id` | `{ "id": i }` |
| `InvalidUrl { id, url, reason }` | 422 | `invalid_url` | `{ "id", "url", "reason" }` — reason is one of `scheme must be http or https` / `missing host` / `userinfo not allowed` / `fragment not allowed` |
| `InvalidHostname { id, hostname }` | 422 | `invalid_hostname` | `{ "id", "hostname" }` |
| `CleartextToken(id)` | 422 | `cleartext_token` | `{ "id" }` |

Matching is case-insensitive for hostname/id (`validate()`,
`registry.rs:90`). The `message` field carries the full `thiserror` string
for display.

### 5.5 Overview — `GET /api/v1/overview`

Fleet-at-a-glance aggregate for the dashboard (ui-ux-spec §5.1). **New;
Milestone B.** Until then the UI composes the dashboard from `GET /clusters`.

- **Auth:** `Read` on `Target::Cluster` (Viewer+).
- **Response 200:**

```json
{
  "state_counts": {
    "pending": 0, "provisioning": 1, "running": 6, "degraded": 1,
    "updating": 0, "suspending": 0, "suspended": 2,
    "terminating": 0, "terminated": 14
  },
  "resource_totals": { "cpu_cores": 512.0, "gpu": 32.0, "memory_bytes": 2199023255552 },
  "active_jobs": 12,
  "failed_jobs_24h": 2,
  "unhealthy": [ { "id": "train-7", "reason": "degraded" } ],
  "recent_events": [ { "…": "AuditEvent (§5.9)" } ]
}
```

- `state_counts` always carries all nine keys (zero-filled) so the donut
  chart has a stable key set.
- `resource_totals` sums desired `replicas × cpu/gpu/memory` across
  non-terminal clusters; quantities are parsed per K8s syntax, unparseable
  values contribute 0 (spec strings stay authoritative; this is display math).
- `active_jobs` / `failed_jobs_24h` come from the job-history store (§5.7);
  before Phase 3 they are `null` and the UI hides those cards.
- `recent_events` is the newest N (default 20, `?events_limit=`) audit
  events, Admin-visible fields included only for Admin callers; non-Admin
  callers get the same shape minus `subject` (audit subjects are Admin data).

### 5.6 Jobs proxy — `/api/v1/clusters/{id}/jobs…`

Path-based proxy to the cluster's Ray Jobs API, for the jobs tab
(ui-ux-spec §5.4). **New; Milestone C.** This is the *same* southbound as the
gateway — registry lookup by cluster id, credential swap, streaming body
passthrough — addressed by path instead of hostname so the browser never
needs cluster hostnames (ADR-0002 scope discipline, §1).

| Route | Proxied Ray call | Permission |
|---|---|---|
| `GET /api/v1/clusters/{id}/jobs` | `GET /api/jobs/` | `Read` on `Job` — **implemented** (Milestone C, `cluster_obs.rs`) |
| `POST /api/v1/clusters/{id}/jobs` | `POST /api/jobs/` | `Write` on `Job` |
| `GET /api/v1/clusters/{id}/jobs/{job_id}` | `GET /api/jobs/{job_id}` | `Read` on `Job` |
| `POST /api/v1/clusters/{id}/jobs/{job_id}/stop` | `POST /api/jobs/{job_id}/stop` | `Write` on `Job` |
| `DELETE /api/v1/clusters/{id}/jobs/{job_id}` | `DELETE /api/jobs/{job_id}` | `Write` on `Job` (matches the gateway's method mapping — job deletion is a Developer action, `auth_layer.rs:36`) |
| `GET /api/v1/clusters/{id}/jobs/{job_id}/logs` | `GET /api/jobs/{job_id}/logs` | `Read` on `Job` |

- **Bodies:** opaque passthrough for the write/detail routes — Ray's job
  records live in GCS internal KV and Mobula deliberately does not
  reimplement them (ADR-0002, PLAN.md S2). Documented in OpenAPI as
  `application/json` opaque objects with a stability note ("shaped by the
  cluster's Ray version; two-minor support window"), not as Mobula-owned
  schemas. Mobula-owned history is §5.7.
  - **Refinement for `GET .../jobs` (the list, Milestone C):** the response
    is **normalized** to a stable Mobula shape, a JSON array of `RayJobSummary`
    (`{ job_id?, submission_id?, status?, entrypoint?, start_time?, end_time?,
    message? }`), rather than opaque passthrough — the nodes/jobs tab codes
    against one schema across Ray minors. `status` stays Ray's vocabulary
    verbatim (`PENDING | RUNNING | SUCCEEDED | FAILED | STOPPED`, §5.7);
    `start_time`/`end_time` are Ray's unix-millis. Read-scoped like §5.3.
- **Southbound resolution:** a registered cluster uses the registry's
  `api_base_url` + static token; a lifecycle-managed cluster uses the
  provisioner-derived head-service dashboard (`…-head-svc:8265`, no token —
  reached over the tenant network). The credential swap is the gateway's
  (caller JWT terminates at Mobula; the cluster's Ray token, if any, travels
  southbound), with the gateway's body/inflight caps.
- **Statuses:** upstream status passes through untouched for the opaque
  routes. For the normalized `GET .../jobs`, a non-2xx upstream still passes
  through with its body; a southbound transport failure is **503
  `cluster_unreachable`** — a deliberate refinement of §2.6's 502 for this
  browser-consumable control-plane view, so the UI's "backend unreachable"
  empty state is a graceful degrade, never a crash.
- **404 disambiguation:** `{id}` unknown to Mobula → Mobula's 404 envelope;
  job unknown to Ray → Ray's 404 body, passed through. The UI distinguishes
  by content-type/envelope, which is why the control-plane envelope is
  uniform (§2.3).

### 5.6a Events — `GET /api/v1/clusters/{id}/events`

Kubernetes Events for the cluster's objects, for the events tab
(ui-ux-spec §5.4/§5.8). **Implemented** (Milestone C, `cluster_obs.rs`).
The highest-value drill-down for "why won't this cluster come up" — it
surfaces scheduling, image-pull, and probe failures.

- **Auth:** `Read` on `Target::Cluster`, read-scoped (#49) — identical to
  §5.3.
- **Source:** **Kubernetes**, not the Ray API. Core `v1` Events in the
  cluster's namespace are listed via the provisioner and filtered to the
  cluster's objects (the RayCluster itself, plus everything KubeRay names
  under it — the `<id>-` prefix that catches head/worker pods and the head
  service). Works even when the Ray dashboard is down — which is exactly when
  events matter most. Both Event schemas (core/v1 `involvedObject` and
  events.k8s.io/v1 `regarding`/`note`/`series`) are normalized to one shape.
- **Response 200:**

```json
{
  "cluster_id": "team-b-scoring",
  "events": [
    {
      "type": "Warning",
      "reason": "FailedScheduling",
      "message": "0/3 nodes available: 3 Insufficient nvidia.com/gpu",
      "count": 4,
      "first_seen": "2026-08-22T10:00:00Z",
      "last_seen": "2026-08-22T10:05:00Z",
      "object": "Pod/team-b-scoring-head-abc12"
    }
  ]
}
```

Newest-first by `last_seen`, capped at 200. `type` is `Normal` | `Warning`
verbatim; `count` collapses K8s's own repeat-count (default 1); `object` is
`Kind/name`. Optional keys are omitted when the source has no value.
- **Errors:** 403; 404 (cluster unknown, or the backend exposes no events —
  gateway-only / demo); 503 when the event source (Kubernetes) can't be
  reached (graceful degrade, never a panic).

### 5.6b Logs — `GET /api/v1/clusters/{id}/logs`

Tail-capped pod logs for the logs tab (ui-ux-spec §5.4). **Implemented as a
non-streaming first cut** (Milestone C, `cluster_obs.rs`). The eventual
design is a control-plane WS tail (§5.6 / this section's TODO); the GET-tail
form removes the pending-backend stub now.

- **Auth:** `Read` on `Target::Cluster`, read-scoped (#49).
- **Source:** **Kubernetes** — the kubectl-logs equivalent through the K8s
  API (`GET …/pods/{name}/log`, `tailLines`). The tailable pod set is exactly
  the pods KubeRay owns for the cluster (`ray.io/cluster=<id>`); a pod outside
  that set is never tailed (404).
- **Query:** `node=<pod>` selects a pod (defaults to the head pod);
  `tail=<N>` bounds the returned lines (default 200, clamped to 5000).
- **Response 200:**

```json
{
  "cluster_id": "team-b-scoring",
  "pods": ["team-b-scoring-head-abc12", "team-b-scoring-worker-gpu-1"],
  "pod": "team-b-scoring-head-abc12",
  "tail": 200,
  "lines": ["2026-08-22T10:00:00Z ray start --head", "…"],
  "truncated": true
}
```

`pods` lets the UI offer a pod selector; `pod` is the one these `lines` came
from; `truncated` is `true` when the tail was filled (older lines may exist
beyond it).
- **Errors:** 403; 404 (cluster unknown, requested pod not in the cluster, or
  the backend exposes no logs); 503 when the log source (Kubernetes) can't be
  reached.
- **TODO (Milestone C):** upgrade to a WS streaming tail
  (`WS …/logs/tail`) — this GET-tail is the pragmatic first cut. Container
  selection, `previous` (crashed container), and `since` are also deferred.

### 5.7 Job history — `GET /api/v1/jobs` (+ `GET /api/v1/jobs/{job_id}`)

Cross-cluster, persistent job records (ui-ux-spec §5.5) — the "history
survives clusters" screen. **New; Milestone C, Postgres-backed** (ADR-0004:
Postgres holds post-mortem history, never live job truth). Records are
written by the gateway on submission and completed by observation.

- **Auth:** `Read` on `Target::Job` (Viewer+).
- **Query:** `limit`, `cursor`; filters `cluster_id`, `status`, `subject`,
  `submitted_since`, `submitted_until` (unix seconds).
- **Response 200:** `{ "items": [JobRecord], "next_cursor": "…" }`

```json
// JobRecord
{
  "job_id": "raysubmit_abc123",
  "submission_id": "raysubmit_abc123",
  "cluster_id": "demo",
  "subject": "u1234",
  "entrypoint": "python train.py --epochs 10",
  "status": "SUCCEEDED",
  "submitted_at": 1755280000,
  "started_at": 1755280010,
  "ended_at": 1755281900,
  "duration_ms": 1890000
}
```

`status` is Ray's vocabulary: `PENDING | RUNNING | SUCCEEDED | FAILED |
STOPPED` (uppercase, Ray's own serialization — do not snake_case these; they
are Ray's strings, not ours). `subject` is shown to all roles here (it is the
submitter of record, unlike raw audit rows). Job detail/logs continue to come
from §5.6 while the cluster lives; after teardown, this record is what
remains (durable log capture is REQUIREMENTS §3.9, later).

### 5.8 Identity & access

#### `GET /api/v1/identity` — **Milestone A**

"Who am I" for the shell's identity chip and role-gated rendering
(ui-ux-spec §5.8, §5.10). **Implemented** (2026-08-17, `access.rs`;
mounted unconditionally).

- **Auth:** any authenticated caller.
- **Response 200:** `Identity` (§3.6) — `{subject, email, groups, roles}`
  with snake_case role names.
- **Dev mode:** with no validator configured (`--dev-allow-unauthenticated`)
  returns `{ "subject": "dev", "email": null, "groups": [], "roles":
  ["admin"] }` so the unauthenticated dev loop renders the full console.

#### `GET /api/v1/access/roles`

Effective role mappings for the access page (ui-ux-spec §5.8).
**Implemented** (2026-08-17, `access.rs`; mounted unconditionally,
Admin-only). v1 is read-only from `auth.toml`; editing stays in the config
file + restart.

- **Auth:** Admin.
- **Response 200:**

```json
{
  "mappings": {
    "admin": ["/platform-admins"],
    "operator": ["/sre"],
    "developer": ["/ml-eng", "/data-sci"],
    "viewer": ["*"]
  },
  "source": "file",
  "editable": false
}
```

Shape mirrors `RoleMappings` (`mobula-auth/src/lib.rs:98`). `editable`
flips with the Phase-3 `role_assignments` work (ADR-0009); a `"*"` entry is
the wildcard the validator already warns about.

> **Local-mode deviation (additive):** when NO OIDC validator is configured
> (pure local-auth mode, ADR-0011 — or dev mode), group→role mappings are
> meaningless because local users carry their role as a column on the user
> row. The endpoint then returns `{ "mappings": null, "source": "local",
> "editable": false }` — `mappings` is `Option<RoleMappings>`, always
> present but null. Role management in that mode is per-user via
> `/api/v1/auth/users` (§5.15).

### 5.9 Audit — `GET /api/v1/audit`

Audit viewer (ui-ux-spec §5.7). **Implemented** (2026-08-16, Milestone B):
events persist to the store (`audit_events` table; SQLite now, the SQL is
Postgres-portable) AND keep flowing to the `mobula::audit` tracing target,
so the `--audit-log` JSONL export is unchanged. Every audit-emitting site —
gateway per-request rows, authn failures, authz denials, cluster/pool
mutations — goes through `mobula_api::audit::emit`. The route mounts only
when a store is configured (gateway-only deployments stay trace-only).

- **Auth:** `Read` on `Target::Audit` — granted to **Admin** (catch-all)
  and **Auditor** (#59, separation of duties: a compliance reader who holds
  Read on the audit surface and *nothing* else — no cluster reads, no
  registry, no writes anywhere). The Auditor role is granted via the
  `auditor` group list in the auth config's role mappings (serde-defaulted
  to empty, so existing `auth.toml` files keep working); scoped role
  bindings don't apply — the trail isn't project-scoped. Viewer's
  read-everything explicitly excludes the audit target: audit subjects are
  Admin data (§2.2).
- **Query:** `limit` (default 100, max 1000), `cursor`; filters `from`,
  `to` (unix seconds, inclusive), `subject`, `cluster`, `method`,
  `path_prefix`, `min_status`, `decision` (`allow|deny`), `reason`.
  `?format=csv` exports the page as `text/csv` with a header row (RFC 4180
  quoting; `granted_roles` joins with `;`). `from > to`, an unknown
  `decision`/`format`, or a mistyped number is a 400.
- **Response 200:** `{ "items": [AuditEvent], "next_cursor": 41 }` — this
  endpoint is the ONE list route that wraps items in an envelope, because
  the cursor has to live somewhere.
- **Pagination:** rows are newest-first by an autoincrement `seq`;
  `cursor` means "only rows with `seq` strictly before this value";
  `next_cursor` is the oldest returned row's `seq` when more rows exist,
  `null` at the end. Pass it back as `cursor` for the next (older) page.
- **Decision policy:** `deny` rows are emitted at the point of refusal
  (authn failures, authz denials, quota denials). Gateway per-request rows
  are always `allow` — a request Mobula refuses never reaches the gateway,
  and an upstream 4xx/5xx is the cluster's answer to an allowed request,
  carried in `status`.
- **Missing context is `null`, never invented** (§2.1): authn failures
  have no `subject`; gateway rows have no `action`/`reason`; handler rows
  (mutations, `authorize` denials) carry `action`/`cluster` instead of
  `method`/`path`; `required`/`granted_roles` appear on authz denials only.

#### Tamper-evidence: the hash chain (#59)

Every row carries a `chain_hash`: `sha256(prev_row.chain_hash ‖
canonical_json(row))`, computed in the store at append time. The genesis
row (seq 1) chains from 64 zero hex chars. The canonical serialization is
`serde_json` over the `AuditEvent` struct (fixed field order, `Option`
fields always present as `null`), shared by all store backends and the
verifier via one pure function (`mobula_controller::audit_chain_hash`). A
single `chain_hash` column suffices — the previous row's hash is an input
to this row's, so a separate `prev_hash` column would be redundant.

This is tamper-**evidence**, not tamper-proofing: the chain holds no secret,
so an attacker with table write access can rewrite history and recompute
hashes — but any edit/insert/delete of a middle row breaks every later
hash, which verification exposes. Deleting the *newest* rows leaves no gap
to detect; ship the `--audit-log` JSONL export off-box for non-repudiation.

**Migration:** rows written before the chain existed carry `chain_hash =
''` and are chained at boot, in seq order, each from its (by then chained)
predecessor. No data is rewritten beyond filling the column.

**Concurrency:** appends serialize — an in-process mutex (SQLite) or a
transaction-scoped `pg_advisory_xact_lock(hashtext('audit_chain'))`
(Postgres) — so read-prev/compute/insert never interleaves into a forked
chain.

#### Chain verification — `GET /api/v1/audit/verify`

Replays the chain over a window and reports the first broken link.

- **Auth:** same as the list endpoint (`Read` on `Target::Audit`).
- **Query:** `from_seq` (default 1 — the whole trail from genesis; a
  mid-trail window chains from the newest preceding row's stored hash),
  `limit` (default 100 000, max 1 000 000 — bounded so a huge table can't
  OOM the process; verify larger trails in successive windows).
- **Response 200:** `{ "ok": true, "events_checked": 4182,
  "first_broken_seq": null }`. `ok` is false and `first_broken_seq` is the
  offending row's `seq` at the first mismatch; `events_checked` counts the
  rows that verified before the replay stopped. Everything after a broken
  link is untrustworthy by construction, so the replay stops there.

#### Audit-read logging (#59)

Every successful read of the audit surface — the JSON list, CSV exports,
and `verify` — itself appends an `audit_read` event: handler-styled
(`action`, no `method`), `decision: allow`, `status: 200`, the caller's
`subject`, and `path` carrying the request's **query string** (an exception
to the no-query-string convention: the filter params are the payload worth
auditing, and `format=csv` in the query distinguishes exports). The
recursion is deliberate — audit access is itself audited (SOC 2 CC7.2).
The row is appended *after* the read completes, so a `verify` never
perturbs the window it just checked. Failed reads (400/403/500) leave no
`audit_read` row (403s are already denial rows of their own).

```json
// AuditEvent — superset of the fields already emitted to mobula::audit
{
  "ts": 1755280000,
  "subject": "u1234",
  "decision": "deny",
  "reason": "insufficient_permission",
  "action": "create_cluster",
  "cluster": "demo",
  "method": "POST",
  "path": "/api/v1/clusters",
  "status": 403,
  "latency_ms": 4,
  "required": { "action": "write", "target": "cluster" },
  "granted_roles": ["viewer"]
}
```

Authz denials are first-class rows (they carry required/granted, matching the
403 envelope) — the viewer renders them as "access denied" entries.

### 5.10 Events — `GET /api/v1/events` (SSE)

**Forward-looking sketch — Phase 3.9 (REQUIREMENTS §3.9). Not a v1
commitment.** Included now so list/detail screens are built polling-first
with a clean SSE upgrade path (ui-ux-spec §5.1, §6).

- **Auth:** `Read` on `Target::Cluster`.
- **Protocol:** `text/event-stream`. Clients send `Last-Event-ID` to resume;
  server replays from the Postgres event log.
- **Query:** `cluster`, `types` (comma-separated).
- **Event envelope** (`data:` is JSON, `id:` is the sequence):

```
id: 4812
event: cluster.state_changed
data: {"seq":4812,"ts":1755280000,"type":"cluster.state_changed","cluster_id":"demo","payload":{"from":"provisioning","to":"running","observed_generation":4}}

```

Initial types: `cluster.state_changed`, `cluster.spec_changed`,
`job.status_changed`, `audit.appended` (Admin only). Transport is Postgres
LISTEN/NOTIFY by default (REQUIREMENTS §6), NATS optional. Until this lands,
the UI polls: lists 15–30s, detail 5–15s.

### 5.11 Browser auth — PKCE endpoints

**Critical path, currently absent** (ui-ux-spec §5.10). Web login is
Authorization Code + PKCE against the configured OIDC issuer (REQUIREMENTS
§3.6). Thin sketch — the token-custody details are an open question (§8):

| Route | Purpose |
|---|---|
| `GET /api/v1/auth/login?redirect_uri=…` | 302 to the IdP authorize URL with PKCE challenge |
| `GET /api/v1/auth/callback?code=…&state=…` | Code exchange; establishes the session, redirects back to the SPA |
| `POST /api/v1/auth/refresh` | Silent refresh (or 401 → re-login with deep-link return) |
| `POST /api/v1/auth/logout` | Session teardown |

These are the only control-plane routes outside the Bearer-JWT model (the
login flow is how you get one). In Nebari-native mode, Envoy/Keycloak may
satisfy the browser-facing parts instead — the endpoints are the standalone
mode contract. Dev mode uses `--dev-allow-unauthenticated` and needs none of
this.

### 5.12 Pools — `/api/v1/pools`

Capacity pools and per-project allocations ([ADR-0010](adr/0010-pool-engine-kueue.md)
— Kueue is the pool engine). **Implemented** (`pools.rs`) against the `Store`,
with Kueue actuation (ResourceFlavor / ClusterQueue / Cohort / LocalQueue)
applied by the pool reconcile loop when the Kueue CRDs are present — absent
them, pools are in-process quota only (ADR-0010's fallback). Pools are
platform configuration, not app lifecycle (§2.2): reads are Viewer+,
mutations Admin-only.

#### `GET /api/v1/pools`

- **Auth:** `Read` on `Target::Pool` (Viewer+).
- **Response 200:** `[PoolView]` — each item is
  `{ name, generation, created_at, flavors, cohort, fair_sharing_weight,
  elastic, total_nominal }`, where `total_nominal` sums each flavor's
  resource quantities per resource key (a key whose quantity fails to parse
  on any flavor is omitted — display math only; the spec stays
  authoritative).

#### `POST /api/v1/pools`

- **Auth:** `Write` on `Target::Pool` (Admin only).
- **Body:** `{ "spec": PoolSpec }`. Shape-validated by `PoolSpec::validate`
  plus quantity-parse validation at the edge → 400 `invalid_spec`.
- **Cover every resource a workload requests.** Kueue refuses admission when
  a pod requests a resource the ClusterQueue doesn't quota (e.g.
  `resource memory unavailable`), and Ray pods always request `memory` — a
  pool that quotas only `cpu` admits nothing. (Found by the kueue-e2e
  workflow.)
- **Create-only in v0:** a pool that already exists is 409, never an upsert;
  spec update arrives with a later PATCH.
- **Response 201:** `{ "name": "gpu-pool", "generation": 1 }`.

#### `GET /api/v1/pools/{name}` · `DELETE /api/v1/pools/{name}`

- **Auth:** `Read` / `Delete` on `Target::Pool`.
- **Responses:** 200 `PoolView`; 202 on delete; 404 when absent.

#### `PUT /api/v1/pools/{name}/allocations/{project}`

- **Auth:** `Write` on `Target::Pool` (Admin only).
- **Body:** `AllocationSpec` minus `pool`/`project` — path params win; a
  contradicting body is 400. The named pool must exist (404) and the
  allocation must validate (400).
- **Response 200:** `{ "pool": "gpu-pool", "project": "proj-a" }`.

#### `GET /api/v1/pools/{name}/allocations` · `DELETE …/allocations/{project}`

- **Auth:** `Read` / `Delete` on `Target::Pool`.
- **Responses:** 200 `[AllocationSpec]`; 202 on delete; 404 when absent.

#### `GET /api/v1/pools/{name}/usage` — live pool utilization (Slice 4)

Point-in-time view built from the pool's latest stored Kueue observation
(ClusterQueue + LocalQueue statuses) and the spec's nominal quotas. Not a
timeseries — for history use §5.13's `/api/v1/usage`.

- **Auth:** `Read` on `Target::Pool` (Viewer+).
- **Response 200:** `PoolUsageView`:

```json
{
  "pool": "gpu-pool",
  "sampled_at": 1755280000,
  "utilization": {
    "cpu": { "allocated": 16.0, "nominal": 64.0, "pct": 25.0 }
  },
  "projects": { "proj-a": { "cpu": 10.0 } }
}
```

- `sampled_at` is `null` until the pool reconcile loop has observed the pool.
- `allocated` is Kueue's **reservation ledger** (what was admitted against
  quota), not measured consumption — ADR-0010's documented divergence.
  `pct` is `0.0` when `nominal` is 0.
- **Errors:** 404 unknown pool.

### 5.13 Usage — `/api/v1/usage` + `/api/v1/metrics` (Slice 4)

The metering loop (`mobula-controller::Metering`) appends usage samples to
the store on an interval (`--metering-interval-secs`, default 60). Sources:
when Kueue is present, ClusterQueue/LocalQueue `status.flavorsUsage`
(`source: kueue_ledger`); otherwise the min-demand baseline of Running
cluster specs (`source: observed_spec`).

#### `GET /api/v1/usage`

Consumption **reporting**, so the permission is `Read` on `Target::Cluster`
(Viewer+) — the same as reading cluster cost estimates — not
`Target::Pool`.

- **Query:** `project`, `pool` (filters), `from`, `to` (unix seconds;
  defaults: `to` = now, `from` = `to − 86400`). `from < to` required → 400.
- **Response 200:** `UsageReport` — `{ from, to, groups: [UsageGroup] }`,
  one group per (project, pool):

```json
{
  "from": 1755280000, "to": 1755366400,
  "groups": [
    {
      "project": "proj-a", "pool": "gpu-pool",
      "resource_hours": { "cpu": 4.667, "memory": 21.33 },
      "cost_usd": 0.2933
    }
  ]
}
```

- `resource_hours` integrates the sample series as a **step function** (a
  sample's quantity holds until the next sample); the last sample
  at-or-before `from` carries into the window. Sampler gaps hold the last
  known state — the gap is visible in sample density, not papered over.
- `cost_usd` is `null` unless a price sheet is configured (`PolicyConfig`).
- `project: ""` marks the pool-level aggregate row (Kueue path only); it
  OVERLAPS the per-project rows — never sum across project boundaries.
  `pool: ""` means the project has no allocation.

#### `GET /api/v1/metrics`

Prometheus text exposition (no client library — hand-rendered gauges):

```
# HELP mobula_pool_resource_usage Latest metered resource usage …
# TYPE mobula_pool_resource_usage gauge
mobula_pool_resource_usage{pool="gpu-pool",project="proj-a",resource="cpu"} 10
# HELP mobula_clusters_total Managed clusters by observed state …
# TYPE mobula_clusters_total gauge
mobula_clusters_total{state="running"} 3
# TYPE mobula_clusters_by_project gauge
mobula_clusters_by_project{project="proj-a"} 2
# TYPE mobula_pool_nominal gauge
mobula_pool_nominal{pool="gpu-pool",resource="cpu"} 64
```

- **Auth:** `Read` on `Target::Cluster` (a scrape token is a Bearer JWT).
- `mobula_pool_resource_usage` values are the latest sample per (pool,
  project, resource) label set.
- **Control-plane gauges (#52)** are computed from the store at scrape time:
  - `mobula_clusters_total{state}` — managed clusters by **observed** state
    (`unknown` until the reconcile engine's first observation); Terminated
    rows count until the store reaps them.
  - `mobula_clusters_by_project{project}` — managed clusters per spec
    project.
  - `mobula_pool_nominal{pool,resource}` — each pool's nominal quota summed
    across flavor specs (`parse_quantity`, same math as
    `PoolView.total_nominal`); a resource key that fails to parse on any
    flavor is omitted entirely rather than summed partially.

#### `GET /api/v1/clusters/{id}/metrics` — cluster resource summary (#52)

A **normalized cluster resource summary** for the metrics tab's stat tiles
(ui-ux-spec §5.4). **Implemented** (Milestone C, `cluster_obs.rs`). This
replaces the earlier raw-Prometheus passthrough (#52 first slice): the browser
wants CPU/GPU/mem capacity tiles, not a 4MiB exposition to parse, and —
critically — an unreachable head now degrades to a clean **503**, never the
502/panic the passthrough produced.

- **Auth:** `Read` on `Target::Cluster` (Viewer+), read-scoped (#49).
- **Source:** the Ray **state API `GET /api/v0/nodes`** is the primary source
  — it reports each node's `resources_total` and liveness, and answers on
  **every live Ray, autoscaler or not**. (The autoscaler's
  `/api/cluster_status` is `null` on a static KubeRay cluster, so it is used
  only as a best-effort enrichment for the live `used` half of each stat.)
  Capacity is summed across `ALIVE` nodes.
- **Southbound resolution + credential discipline:** identical to the jobs
  proxy (§5.6) — a registered cluster uses the registry's `api_base_url` +
  static token; a lifecycle-managed cluster uses the provisioner-derived
  head-service dashboard (`…-head-svc:8265`, no token). Requests are built
  from scratch (caller JWT never travels southbound); 5s connect / 30s read;
  body capped at 4MiB; redirects never followed. When no endpoint can be named
  (gateway-only / demo) → **404 `metrics unavailable`**.
- **Response 200:**

```json
{
  "cluster_id": "team-b-scoring",
  "cpu": { "used": 3.0, "total": 4.0 },
  "gpu": { "total": 2.0 },
  "memory": { "total": 17179869184 },
  "object_store_memory": { "total": 4294967296 },
  "active_nodes": 2,
  "failed_nodes": 0
}
```

CPU is cores, GPU is device count, memory is bytes. `total` is the reported
capacity; `used` is present **only when the autoscaler report carries a live
usage figure** (omitted otherwise — the tile then shows capacity only). A
resource with no capacity reported (e.g. `gpu` on a CPU-only cluster) is
omitted entirely, so the UI renders only the tiles that apply. `active_nodes`
counts `ALIVE` nodes; `failed_nodes` counts `DEAD` ones (omitted when none).
- **Errors:** 403; 404 (no reachable dashboard to name); **503** when the Ray
  state API can't be reached, answers non-2xx, or returns an unparseable body
  — the UI's cluster-unreachable state, never a crash.
- **Deferred:** live per-resource `used` on non-autoscaling clusters (needs
  Ray's per-node `resources_available`, or the Prometheus scrape); raw
  Prometheus exposition (the old passthrough); SSE/event streaming;
  OpenTelemetry export; Grafana deep-links.

### 5.14 Registry — `GET /api/v1/registry/clusters`

The job gateway's routing table (ADR-0002). **Implemented**
(`registry.rs`), mounted unconditionally (gateway-only deployments have a
registry even without a store).

- **Auth:** **Admin only** — the registry is the credential-routing table
  (§2.2). The route enforces `Admin` on `Target::Cluster`; `ext_authz` maps
  the prefix to `Cluster` for the verb check.
- **Response 200:** `[RegistryEntryView]` —
  `{ id, hostname, api_base_url, token_set, validation }`.
- `token_set` is the only token fact exposed: static Ray tokens are
  `skip_serializing` on `ClusterEndpoint` and must never appear in a
  response (security issue #4).
- Registry TOML entries should set `auth_token_env` (name of an env var
  read at startup, resolved fail-fast) instead of a plaintext
  `auth_token`; exactly one of the two may be set per entry (issue #57).
- `validation` is always `null` today (reserved for per-entry
  health/reachability): registry validation is fail-fast at startup, so
  served entries are valid by construction.
- Static config only — managed clusters from the Store do not get routing
  entries automatically; dynamic registration is a follow-up (security
  review #2 treats the dynamic registry as an SSRF surface).

### 5.15 Local auth — `/api/v1/auth/*` (ADR-0011)

IdP-free authentication: username/password login issuing **opaque** tokens
(`mob_<prefix>_<hex>`, bcrypt-hashed at rest — Mobula stores credentials,
never signs them). **Implemented** (`local_auth.rs`) behind
`serve --local-auth`. OIDC remains the production path; when both are
configured, JWT-shaped bearers go to the OIDC validator and everything else
to the token store.

- `POST /api/v1/auth/login` — **public**. `{username, password}` → 200
  `{token, token_type: "bearer", expires_at, identity: {subject, roles}}`.
  Every failure (unknown user, wrong password, locked, disabled) is the same
  401 `invalid_credentials`; the distinction lives only in the audit trail.
  Five failures lock the account for 300s.
- `GET /api/v1/auth/providers` — **public**. `{local: bool, oidc: {issuer} | null}`
  so the login page knows which form(s) to render.
- `POST /api/v1/auth/tokens` — any authenticated identity; `{label,
  expires_in_days}` (≤ 90) → 201 with the full token **shown once**.
  `GET /api/v1/auth/tokens` lists the caller's own (hashes never serialize);
  `DELETE /api/v1/auth/tokens/{prefix}` revokes own only (404 otherwise — no
  ownership probing). `POST /api/v1/auth/logout` revokes the caller's PAT.
- Local users carry one of the four built-in roles as a column, resolved per
  request — role changes apply live, nothing is stamped into tokens.
- **User management (Admin-only; implemented 2026-08-17):**
  `GET /api/v1/auth/users` lists all users as `[LocalUserView]`
  (`{username, email, role, disabled, created_at}` — hashes never
  serialize). `POST /api/v1/auth/users` `{username, email?, password,
  role}` → 201; the username must be RFC 1123 (k8s-name-safe) and untaken
  (409), the password ≥ 8 chars, the role one of the four. `PUT
  /api/v1/auth/users/{username}` `{role?, disabled?, password?}` → 200 with
  the updated view; 404 for an unknown user. Every mutation emits an audit
  event (`create_user` / `update_user`). Changing your OWN role/disabled is
  allowed in v0 — no footgun guard — but is logged loudly
  (`tracing::warn!`).
- Bootstrap: first `--local-auth` boot with an empty user table creates
  `admin` with a random password written 0600 to
  `<db-dir>/local-admin-password` (or `MOBULA_LOCAL_ADMIN_PASSWORD` for
  demos).
- CLI: `mobula login --local --username X --password-stdin`; `mobula logout`
  revokes the PAT server-side before dropping the local credentials file.

### 5.16 Settings — `/api/v1/settings/policy`

Settings page (ui-ux-spec §5.9): view the effective governance policy and
edit per-project quotas and the price sheet. **Implemented** (2026-08-16,
`settings.rs`) — Admin-only (§2.2); mounted only when a store is configured.

**Precedence: the `--policy` TOML file is the boot-time DEFAULT; the store
wins once edited.** The effective policy is a single store row (JSON in the
`control` KV table). A store with no row is seeded from `--policy`
(insert-if-absent, so a concurrent edit is never clobbered); that seeded row
reports `source: "file"` until the first PUT, which rewrites it as
`"store"`. Every consumer — quota admission in `POST /api/v1/clusters`, the
`est_*_hourly` fields on `ClusterView`, and the `cost_usd` roll-up in
`GET /api/v1/usage` — reads the store row per request, so edits take effect
immediately, with no restart.

- `GET /api/v1/settings/policy` → 200
  ```json
  {
    "prices": { "cpu": 0.048, "memory": 0.005, "nvidia.com/gpu": 2.50 } ,
    "quotas": { "ml-team": { "cpu": 500, "memory": 1000 } },
    "source": "file",
    "editable": true
  }
  ```
  `prices` is `null` when no price sheet is configured; `quotas` is `{}`
  when no project has a limit. `source` is `"file"` (the untouched
  `--policy` boot seed), `"store"` (edited via PUT), or `"none"` (no policy
  configured at all — `prices: null`, `quotas: {}`).
- `PUT /api/v1/settings/policy` `{ prices?, quotas? }` → 200 with the
  policy after the update (`source` is now `"store"`). **Section-replace**
  semantics: a present key replaces that whole section — `prices: null`
  clears the price sheet, `quotas: {}` clears all quotas; an absent key
  leaves that section untouched. Prices and quota values must be
  non-negative finite numbers → 400 with a message naming the key. Every
  accepted edit emits an `update_policy` audit event (§5.9).

Concurrent PUTs are last-writer-wins (v1; multi-replica compare-and-swap is
a follow-up, same tracking as the quota-admission transaction note in
`clusters.rs`).

## 6. Endpoint × milestone summary

| Endpoint | Milestone | Backs (ui-ux-spec) | Status in code |
|---|---|---|---|
| `GET /api/v1/identity` | **A** | shell, §5.8 | **exists** (access.rs, incl. dev identity) |
| `GET /api/v1/registry/clusters` | **A** | §5.6 (read-only, D5) | **exists** (registry.rs, Admin-only) |
| `GET /api/v1/clusters` (registry-backed) | **A** | §5.2 | new fallback path; store-backed exists |
| `GET /api/v1/clusters/{id}` | B | §5.4 | exists (+ ✱ fields) |
| `POST /api/v1/clusters` | B | §5.3 | exists (incl. quota admission) |
| `PATCH /api/v1/clusters/{id}` | B | §5.3/§5.4 edit | new |
| `POST …/suspend` `/resume` `/terminate` | B | §5.4 actions | suspend/resume **exist** (#51); terminate = DELETE (exists) |
| `GET /api/v1/overview` | B | §5.1 | new |
| `GET /api/v1/audit` | B | §5.7 | **exists** (audit.rs, persisted + CSV) |
| `GET /api/v1/access/roles` | B | §5.8 | **exists** (access.rs; `mappings: null`/`source: "local"` without OIDC) |
| `GET`/`PUT /api/v1/settings/policy` | B | §5.9 | **exists** (settings.rs, Admin-only; store-backed, `--policy` is the boot seed) |
| PKCE auth endpoints | B | §5.10 | UI does SPA-direct PKCE; backend endpoints still new |
| Local auth (`/api/v1/auth/*`) | B | §5.10 | **exists** (local_auth.rs, ADR-0011; incl. Admin-only user management) |
| `GET /api/v1/clusters/{id}/nodes` | B/C | §5.4 nodes tab | new |
| `/api/v1/clusters/{id}/jobs…` proxy + WS tail | C | §5.4 jobs/logs | new (southbound exists in gateway) |
| `GET /api/v1/jobs[/{job_id}]` | C | §5.5 | new |
| Registry writes (POST/PATCH/DELETE) | Phase 3 (D5-gated) | §5.6 | specified, disabled |
| `GET /api/v1/events` (SSE) | Phase 3.9 sketch | §5.1 refresh | not committed |

## 7. Out of scope (v1)

Explicitly not in this API, with the decision that excludes it:

- **Ray Serve management** (deploy/canary/rollback) — Phase 4 per the parity
  matrix; Serve traffic is Envoy `ext_authz`, never proxied inline
  (ARCHITECTURE.md).
- **Form-based job submission** — D4: the UI ships a `ray job submit` +
  `RAY_JOB_HEADERS` command helper; the proxy's `POST …/jobs` exists for
  completeness and CLI parity, not as a form backend.
- **Registry writes** — D5: specified in §5.4 but disabled until the
  dynamic-registry SSRF hardening lands.
- **Per-node add/remove** — D2: capacity is worker-group replica bounds;
  the nodes endpoint is observability-only.
- **Workspaces** (hosted IDE), **SCIM**, **fair-share scheduling**, **custom
  roles** — PLAN.md v0 cut line / post-v1.
- **Cost/billing surfaces** — the `est_*_hourly` fields exist when a price
  sheet is configured, but no usage/cost dashboards API (Phase 4).
- **Metrics query API** — v1 metrics are native Ray-API views (via §5.3/§5.6
  data) plus new-tab Grafana deep-links (D3: no iframes); a Prometheus-backed
  API arrives with REQUIREMENTS §3.9.
- **UI-issued API keys / service-account management** — v1 documents
  `mobula token`; management endpoints are Phase 3+.
- **Webhooks/notifications** — the SSE sketch (§5.10) is the only push
  channel proposed.

## 8. Deltas from current code & open questions

Changes this proposal makes to existing behavior, for the reviewer to ratify:

1. **Structured 403.** `auth_layer::authorize` returns bare text today; §2.3
   makes it a JSON envelope carrying `required`/`granted_roles` (data the
   audit event already has). Touches every handler using `authorize`.
2. **`ClusterView` extension.** Add `spec: ClusterSpec | null` and
   `created_at` (§3.4). Additive; the nullability exists for Milestone A's
   registry-backed slice.
3. **`DesiredState::Suspended`.** Suspend/resume need a third desired variant
   (today: `Running | Terminated`, `store.rs:20`). Type change in
   `mobula-controller`, reconciler support, `desired` wire value
   `"suspended"`.
4. **`Role` serialization.** `Role` doesn't derive `Serialize` today;
   `GET /identity` needs it (snake_case names, §2.1).
5. **Developer cluster-create.** ui-ux-spec §5.3 implies Developers create
   clusters; code grants them only `Read` on `Target::Cluster`. Proposal
   follows code (Operator/Admin). If product wants Developer-create, change
   `Role::grants`, not this API. **Open question.**
6. **PKCE token custody.** Cookie session vs in-memory token + IdP refresh
   (ui-ux-spec §7 leans in-memory; §5.11 above is custody-agnostic). **Open
   question**, resolved before Milestone B.
7. **DELETE vs POST terminate.** Both kept; POST is canonical for the UI
   (§5.1). If reviewers prefer one verb, DELETE deprecates in v2.

## 9. Implementation checklist

Ordered by milestone (mirrors ui-ux-spec §9). Each item includes its
`#[utoipa::path]` decorator, `ApiDoc` registration, and an
`openapi.json` re-export — that is the definition of done for every endpoint.

**Milestone A — read-only slice (Phase-2 code, no persistence):**

1. Structured error envelope + 403 `forbidden` with required/granted (§2.3,
   delta #1).
2. `GET /api/v1/identity` incl. dev-mode identity (§5.8, delta #4).
3. `GET /api/v1/registry/clusters` — serialize `ClusterRegistry` through
   `RegistryClusterView` (§5.4).
4. `GET /api/v1/clusters` registry-backed fallback: when no `Store` is
   configured, synthesize `ClusterView`s (`spec: null`, delta #2) from
   registry entries (§4).
5. UI codegen spike: `cargo test -p mobula-api export_openapi` →
   mobula-ui type generation in CI.

**Milestone B — lifecycle + persistence (Phase 3):**

6. Sqlite/Postgres `Store` wired into `serve` (exists: `store_sqlite.rs`;
   mount via `ServeOptions.store`).
7. `ClusterView` ✱ fields; `GET /clusters/{id}` detail complete.
8. `PATCH /api/v1/clusters/{id}` (full-spec replace, generation bump).
9. `DesiredState::Suspended` + reconciler support (delta #3);
   `POST …/suspend|resume|terminate` with `can_transition` 409s.
10. `GET /api/v1/overview` aggregate (§5.5).
11. `GET /api/v1/audit` over the Postgres audit table (JSONL import path
    for pre-existing audit lines).
12. `GET /api/v1/access/roles` (§5.8).
13. PKCE login/callback/refresh (§5.11) — critical path for the browser UI.

**Milestone C — jobs proxy + history (Phase 3):**

14. Path-based jobs proxy `/api/v1/clusters/{id}/jobs…` reusing the
    gateway's southbound client + credential swap (§5.6).
15. `WS /api/v1/clusters/{id}/jobs/{job_id}/logs/tail` — southbound-first
    connect, 502-before-upgrade (§2.6).
16. `GET /api/v1/clusters/{id}/nodes` aggregation (§5.3).
17. Job-history capture in the gateway (record on submit, complete on
    observation) + `GET /api/v1/jobs[/{job_id}]` (§5.7).
18. Registry write endpoints behind `read_only: false` once the
    dynamic-registry + SSRF-hardening items close (§5.4, D5).

**Phase 3.9 / later (not committed):** SSE event stream (§5.10), durable
log capture, Prometheus-backed metrics API, native metrics endpoints.
