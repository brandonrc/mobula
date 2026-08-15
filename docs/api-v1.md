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
/api/v1/clusters/{id}` are already implemented behind `Store`
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
  `viewer`, `developer`, `operator`, `admin`.
- `Option<T>` fields are always present in responses, serialized as `null`
  when absent — generated clients should never have to guess field presence.

### 2.2 RBAC: who may call what

The code's model (ADR-0009, `mobula-auth/src/lib.rs`) is **permission-sets**,
not an ordinal rank: `PermissionType {Read, Write, Delete, Admin}` ×
`Target {Job, Cluster}`, four built-in roles. Enforcement is flat in v0 (a
role applies globally); cluster/project-scoped bindings land with the Phase 3
`role_assignments` tables without changing the wire contract.

Effective v1 matrix (from `Role::grants`):

| Endpoint class | Required permission | Roles that pass |
|---|---|---|
| Any `GET` on cluster/registry/audit data | `Read` on the route's target | Viewer and above |
| Cluster lifecycle mutations (create, patch, suspend, resume, terminate) | `Write`/`Delete` on `Target::Cluster` | Operator, Admin |
| Job-surface mutations (submit, stop, delete via proxy) | `Write` on `Target::Job` | Developer, Admin |
| Registry, audit, access-control surfaces | Admin | Admin only |

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
  "token_set": true
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
**New.**

- **Auth:** `Write` on `Target::Cluster` (Operator, Admin).
- **Semantics:** each sets desired state along a legal edge of
  `ClusterState::can_transition`:
  - `suspend`: `running → suspending` (compute released, spec + state kept).
  - `resume`: `suspended → provisioning` — reprovision; no fast path to
    running (the tooltip copy in ui-ux-spec §6 is exactly this rule).
  - `terminate`: any non-terminal state → `terminating`; `terminated` is
    terminal, so terminating a `terminated` cluster is a 409, not a no-op.
- **Response 202:** `{ "id": "demo", "state": "suspending", "generation": 4 }`.
  Actions are long-running: the UI transitions optimistically to the
  intermediate state and polls `GET /clusters/{id}` (SSE later) until
  `observed_state` settles (ui-ux-spec §6 async-action pattern).
- **Errors:** 403, 404, 409 `illegal_state_transition` with
  `{ "from": ..., "to": ... }`.
- **Note:** the existing `DELETE /api/v1/clusters/{id}` (`clusters.rs:228`)
  is terminate-equivalent (desired = Terminated). It stays for CLI
  back-compat; the POST action is canonical for the UI. Same permission,
  same 409 behavior (§8).

### 5.2 (reserved — see §5.1/PATCH)

### 5.3 Nodes — `GET /api/v1/clusters/{id}/nodes`

Aggregated node/worker-group view for the nodes tab (ui-ux-spec §5.4).
Observability only (D2): no per-node mutation exists or is planned. **New.**

- **Auth:** `Read` on `Target::Cluster`.
- **Source:** the cluster's own Ray API (node summary / autoscaler status),
  fetched southbound through the registry/observed `api_base_url` with the
  credential swap — never a user-facing hostname.
- **Response 200:**

```json
{
  "cluster_id": "demo",
  "head": { "…": "NodeView" },
  "worker_groups": [
    {
      "name": "gpu-a100",
      "bounds": { "min_replicas": 2, "max_replicas": 8 },
      "nodes": [ { "…": "NodeView" } ]
    }
  ]
}
```

```json
// NodeView
{
  "node_id": "abc123",
  "group": "gpu-a100",
  "is_head": false,
  "status": "alive",
  "cpu_total": 16.0, "cpu_used": 3.5,
  "gpu_total": 4.0, "gpu_used": 1.0,
  "memory_bytes_total": 68719476736, "memory_bytes_used": 1073741824
}
```

- **Errors:** 403, 404 (cluster unknown to Mobula), 502
  `cluster_unreachable` (§2.6).

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
| `GET /api/v1/clusters/{id}/jobs` | `GET /api/jobs/` | `Read` on `Job` |
| `POST /api/v1/clusters/{id}/jobs` | `POST /api/jobs/` | `Write` on `Job` |
| `GET /api/v1/clusters/{id}/jobs/{job_id}` | `GET /api/jobs/{job_id}` | `Read` on `Job` |
| `POST /api/v1/clusters/{id}/jobs/{job_id}/stop` | `POST /api/jobs/{job_id}/stop` | `Write` on `Job` |
| `DELETE /api/v1/clusters/{id}/jobs/{job_id}` | `DELETE /api/jobs/{job_id}` | `Write` on `Job` (matches the gateway's method mapping — job deletion is a Developer action, `auth_layer.rs:36`) |
| `GET /api/v1/clusters/{id}/jobs/{job_id}/logs` | `GET /api/jobs/{job_id}/logs` | `Read` on `Job` |

- **Bodies:** opaque passthrough — Ray's job records live in GCS internal KV
  and Mobula deliberately does not reimplement them (ADR-0002, PLAN.md S2).
  These routes are documented in OpenAPI as `application/json` opaque objects
  with a stability note ("shaped by the cluster's Ray version; two-minor
  support window"), not as Mobula-owned schemas. Mobula-owned history is
  §5.7.
- **Statuses:** upstream status passes through untouched; southbound
  transport failure is 502 `cluster_unreachable` (§2.6).
- **404 disambiguation:** `{id}` unknown to Mobula → Mobula's 404 envelope;
  job unknown to Ray → Ray's 404 body, passed through. The UI distinguishes
  by content-type/envelope, which is why the control-plane envelope is
  uniform (§2.3).

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
(ui-ux-spec §5.8, §5.10).

- **Auth:** any authenticated caller.
- **Response 200:** `Identity` (§3.6).
- **Dev mode:** with no validator configured (`--dev-allow-unauthenticated`)
  returns `{ "subject": "dev", "email": null, "groups": [], "roles":
  ["admin"] }` so the unauthenticated dev loop renders the full console.

#### `GET /api/v1/access/roles`

Effective role mappings for the access page (ui-ux-spec §5.8). **New;
Milestone B.** v1 is read-only from `auth.toml`; editing stays in the config
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

### 5.9 Audit — `GET /api/v1/audit`

Audit viewer (ui-ux-spec §5.7). **New; Milestone B.** JSONL audit target
today (`mobula::audit` tracing target), Postgres-backed with filtering in
Phase 3.

- **Auth:** Admin.
- **Query:** `limit`, `cursor`; filters `from`, `to` (unix seconds),
  `subject`, `cluster`, `method`, `path_prefix`, `min_status`,
  `decision` (`allow|deny`), `reason`. `?format=csv` exports.
- **Response 200:** `{ "items": [AuditEvent], "next_cursor": "…" }`

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

## 6. Endpoint × milestone summary

| Endpoint | Milestone | Backs (ui-ux-spec) | Status in code |
|---|---|---|---|
| `GET /api/v1/identity` | **A** | shell, §5.8 | new, trivial |
| `GET /api/v1/registry/clusters` | **A** | §5.6 (read-only, D5) | new |
| `GET /api/v1/clusters` (registry-backed) | **A** | §5.2 | new fallback path; store-backed exists |
| `GET /api/v1/clusters/{id}` | B | §5.4 | exists (+ ✱ fields) |
| `POST /api/v1/clusters` | B | §5.3 | exists (incl. quota admission) |
| `PATCH /api/v1/clusters/{id}` | B | §5.3/§5.4 edit | new |
| `POST …/suspend` `/resume` `/terminate` | B | §5.4 actions | new (DELETE exists) |
| `GET /api/v1/overview` | B | §5.1 | new |
| `GET /api/v1/audit` | B | §5.7 | new |
| `GET /api/v1/access/roles` | B | §5.8 | new |
| PKCE auth endpoints | B | §5.10 | new, critical path |
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
