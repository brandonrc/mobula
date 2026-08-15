# ADR-0006: Observation-first reconciliation; the state machine is vocabulary, not law

Status: accepted (2026-08-15) - amends ADR-0004

## Context
The distsys literature audit (PLAN.md Review 4) found our largest design
conflict: Kubernetes design principles prohibit "comprehensive state
machines for objects with... states that cannot be ascertained by
observation," and deprecate `phase`-style enums; status must be 100%
reconstructable by observation. `ClusterState::transition` as written
would raise `TransitionError` against *observed reality* (e.g. observe()
reports Terminated while the store says Provisioning) - observed reality
is never invalid.

## Decision
- Reconcilers are **level-triggered** with periodic resync and a
  backoff+token-bucket workqueue; edge triggers (watches) are an
  optimization only.
- Cluster **status is reconstructed from observation** every reconcile:
  Conditions + observedGeneration, never a stored phase that can disagree
  with the world.
- The `ClusterState` enum and its transition table survive only as (a)
  validation of **user-issued lifecycle commands** against desired state
  (you cannot ask a Terminated cluster to Suspend) and (b) reporting
  vocabulary derived from conditions. It is never enforced against
  observations.

## Consequences
Phase 3 reconcilers get a resync loop and requeue-with-backoff from day
one. `cluster.rs` docs updated; the enforcement seam moves to the command
API. Drift between desired and observed is a Condition, not an error.
