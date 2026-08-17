# ADR-0009: RBAC model follows artifact-keeper (permission-sets + scoped bindings)

Status: accepted (2026-08-15) — resolves review issues #24, #25, #26

## Context
REQUIREMENTS §3.7 specifies `Org → Project → Resource`, five built-in
roles, custom roles as permission sets, and bindings to users, IdP groups,
and service accounts. Phase 2 shipped a flat 3-variant ordinal enum with
`permits() = self >= required`, which review #24/#25/#26 correctly flagged
as under-powered: no scoping, `operator` inexpressible, `Admin` a no-op.

Two external facts shape the decision:
- **NIC/Keycloak authz is flat group membership.** The nebari-operator's
  auth reconciler hardcodes `groups` claim with `full.path=false`; NebariApp
  gates on `RequiredGroups`. There is no project/namespace taxonomy in NIC
  to scope against today.
- **artifact-keeper (nebari-dev's Rust artifact registry) already solved
  this.** Its model: `PermissionType {Read, Write, Delete, Admin}`; roles
  as named DB rows (`is_system` for built-ins) carrying a permission set;
  a `permissions` table keyed on `principal_type ∈ {user, service_account,
  group}` × `target_type ∈ {project, repository}` × actions; and
  `role_assignments` scoped to an optional `repository_id` (null = global).
  Admin always wins. This is REQUIREMENTS §3.7, already in Rust, in-ecosystem.

## Decision
Adopt artifact-keeper's RBAC model as Mobula's target, with `repository →
cluster` and `project → project`:

- **Permission vocabulary:** `PermissionType {Read, Write, Delete, Admin}`
  (identical to artifact-keeper).
- **Roles are permission-sets, not an ordinal rank.** Built-in roles
  (viewer/developer/operator/admin) are permission sets; `Operator` =
  lifecycle-not-code (no `Write` on the job surface). Custom roles become
  named rows in Phase 3.
- **Scoping is by target (cluster, then project), and bindings are by
  principal (user, service account, group).** This is the "Resource" and
  "Project" of §3.7. Group principals map directly onto Keycloak groups.

## Phasing
- **v0 (now, config era):** ship the type vocabulary — `PermissionType`,
  named-role permission-sets, group→role mapping. Enforcement is flat
  (a role applies globally), because NIC has no project taxonomy yet and
  Mobula has no storage layer. This matches how NIC itself does authz.
- **Phase 3 (with Postgres):** the `roles`, `permissions`, and
  `role_assignments` tables — cluster/project-scoped bindings to users,
  service accounts, and groups — mirroring artifact-keeper's schema and
  its `check_repository_action` resolution (admin wins; principal-scoped
  rules; project→resource inheritance). Per-route required permissions
  replace the method→permission heuristic (#26).

## Consequences
The flat-vs-scoped tension dissolves: v0 is honestly flat (declared, not
accidental), the vocabulary is already the scoped one, and Phase 3 fills in
tables without a type-system rewrite. REQUIREMENTS §3.7's org/project
dimension is realized only when a deployment (or NIC) defines project
groups; until then `target = cluster` is the enforced scope.

## Addendum (2026-08-17, #49): scoped bindings landed, additive-only

The deferred `role_assignments` half shipped ahead of the full Phase 3
table set, in the smallest form that delivers value:

- **Schema:** `role_assignments (principal TEXT, role TEXT, scope TEXT)`,
  keyed by the triple. `principal` is the Identity `sub` (or local-auth
  username); `role` is a built-in role name; `scope` is `"*"` (global —
  today's flat behavior) or `"project:<name>"`. Cluster-scoped bindings and
  custom-role rows remain Phase 3.
- **Semantics — additive grants only.** A binding can add permissions, never
  subtract; there are no deny rules. A principal with **no** bindings falls
  back to exactly the flat group→role mapping. A principal **with** bindings
  gets the union of (flat global roles from groups) and (binding roles whose
  scope covers the target's project). Evaluation: `Identity::permits` stays
  the global fast path; `permits_scoped(action, target, assignments,
  project)` ORs in bindings with `scope == "*"` or `scope == "project:<name>"`.
- **Lookup cost:** bindings are resolved per request from the store via an
  `AssignmentSource` trait (`mobula-auth`), implemented over `Store` in
  mobula-api's `auth_layer` — one indexed row read per request that misses
  the flat fast path. Caching is a deliberate follow-up, not built.
- **Enforcement rollout:** v0 wires scoped checks into the cluster routes
  only (`create`/`get`/`delete` scoped to the cluster's project; `list`
  filters per-project for callers lacking global `Read`). All other routes
  keep flat checks; the admin API is `GET/PUT/DELETE
  /api/v1/access/assignments…` (Admin-only, audited — api-v1.md §2.2).
- **Out of scope, by design:** group-principal bindings are the OIDC-mapping
  layer's job (they collapse into group→role mapping), and per-cluster
  bindings wait for the Phase 3 `permissions`/`roles` tables.
