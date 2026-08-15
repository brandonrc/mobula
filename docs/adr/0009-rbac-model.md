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
