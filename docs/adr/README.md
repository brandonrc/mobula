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
