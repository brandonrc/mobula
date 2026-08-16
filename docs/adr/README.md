# Architecture Decision Records

Decisions frozen after the 2026-08-14 adversarial review (see ../../PLAN.md
for the full review log with evidence and dispositions).

| ADR | Decision |
|---|---|
| [0001](0001-no-ray-rewrite.md) | Orchestrate stock Ray; never rewrite or fork it |
| [0002](0002-stable-seams-and-job-gateway.md) | Integrate only at stable seams; Jobs API via federating gateway |
| [0003](0003-identity-model.md) | Mobula owns bearer identity in both modes; ext_authz in Nebari mode |
| [0004](0004-state-ownership.md) | Postgres is truth; SSA field manager; idempotency keys |
| [0005](0005-license-apache-2.md) | Apache-2.0, matching nebari-dev convention |
| [0006](0006-observation-first-reconciliation.md) | Observation-first reconciliation; state machine is vocabulary, not law |
| [0007](0007-capacity-field-ownership-and-fencing.md) | One writer per capacity field; fenced side effects |
| [0008](0008-ubi-stig-containers.md) | UBI-only, STIG-postured container images |
| [0009](0009-rbac-model.md) | RBAC follows artifact-keeper: permission-sets + scoped bindings |
| [0010](0010-pool-engine-kueue.md) | Kueue is the pool engine; Mobula owns pool topology, admission UX, attribution |
