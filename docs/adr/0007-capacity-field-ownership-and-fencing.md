# ADR-0007: One writer per capacity field; fenced external side effects

Status: accepted (2026-08-15) - amends ADR-0002 and ADR-0004

## Context
The literature audit (PLAN.md Review 4) flagged our most likely production
incident: `.spec.workerGroupSpecs[].replicas` is owned by Ray's autoscaler
sidecar, which pairs decrements with `scaleStrategy.workersToDelete`.
Ray's own ArgoCD guide documents external writers fighting it (see also
ray#55736, ray#50868); the cluster-autoscaler FAQ is categorical: never
run a second autoscaler over the same capacity. Separately, client-go
leader election explicitly does not fence, and provisioning VMs is a
correctness lock (Kleppmann).

## Decision
**Field ownership partition:**
- `enableInTreeAutoscaling: true` -> Mobula owns `minReplicas`/`maxReplicas`
  and policy only; it never writes `replicas` or `scaleStrategy`, and
  excludes `replicas` from its server-side-apply field set.
- `enableInTreeAutoscaling: false` -> Mobula owns `replicas`.
- Never both. Scale-down always goes through Ray's rejectable graceful
  drain, never pod deletion or raw replica decrements.

**Fencing and idempotency:**
- Idempotency keys are derived, not minted: `{cluster_uid}/{spec_generation}`,
  so a level-triggered loop reproduces the same key for the same desired
  state. Intent rows are committed transactionally before any provider
  call (transactional outbox); replays compare parameters and return the
  stored response.
- Leader election is treated as an optimization, not a guarantee: stale-
  generation writes are rejected at the store, and a restored database
  starts in read-only quarantine until reconciled against observation.

## Consequences
The Phase 4 "autoscaler policy engine" shrinks to bounds-and-policy
management plus drain orchestration - demand sensing and replica counts
stay inside Ray/KubeRay. Provisioner trait docs already require
idempotency keys; this ADR fixes their derivation.
