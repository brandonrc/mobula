# ADR-0004: Postgres is truth; SSA field manager; idempotency keys

Status: accepted (2026-08-14)

## Context
Cluster specs live in Postgres while KubeRay CRs are also declarative -
a split-brain risk (hand-edited CRs, backup restores, HA failover
double-provisioning). Going full K8s-operator-with-CRDs would fix drift
but break VM/static backends and one-control-plane/many-clusters.

## Decision
- Postgres (SQLite in dev) is the source of truth for desired state.
  Live job state is never mirrored as truth - the gateway reads it from
  clusters; Postgres keeps registry + post-mortem history.
- Kubernetes writes use server-side apply with the `mobula` field
  manager; drift raises alarms, never silent stomps. Mobula-owned CRs are
  documented as not hand-editable.
- Every mutating provisioner call carries an idempotency key persisted
  transactionally with the state change that motivated it.

## Consequences
Mobula-managed clusters are invisible to GitOps by design - "what is YAML
in rayserve-pack becomes an API call" is the product thesis. Restores of
the control-plane DB require a reconciliation review step before
controllers act.
