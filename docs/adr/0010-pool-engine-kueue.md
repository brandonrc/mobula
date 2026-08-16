# ADR-0010: Kueue is the pool engine; Mobula owns pool topology, admission UX, and attribution

Status: accepted (2026-08-16)

## Context
REQUIREMENTS §3.2 calls for shared resource pools across projects with
borrowing, fair sharing, and gang admission of Ray workloads. The literature
audit (PLAN.md Review 4, L4) already ruled out home-grown weighted fair share
(it violates DRF's sharing incentive; Borg treats quota as admission control).
The remaining question was whether Mobula implements its own allocation
accounting over raw KubeRay + ResourceQuota, or delegates to Kueue. The
research sweep
([kueue-pool-substrate](../research/RESEARCH-2026-08-kueue-pool-substrate.md),
with companions [anyscale-capacity-model](../research/anyscale-capacity-model.md)
and [vertical-autoscaling-stack](../research/RESEARCH-2026-08-vertical-autoscaling-stack.md))
shows Kueue's object model *is* the pool model: ClusterQueue (per-flavor
quotas + fair-sharing weight), Cohort (shared envelope with borrowing), and
LocalQueue (namespaced tenant handle).

## Decision
**Kueue is the pool engine; Mobula owns pool topology, admission UX, and
attribution.** A Mobula `ResourcePool` translates to Kueue objects
(`kueue.x-k8s.io/v1beta2`):

- one `ResourceFlavor` per pool flavor (node labels + taints);
- one `ClusterQueue` per pool, with `spec.cohortName` pointing at a shared
  cohort so pools in the same envelope borrow elastically;
- one `LocalQueue` per project allocation, namespaced, pointing at the
  pool's ClusterQueue.

Diagrams of the mapping, admission flow, scaling ownership, and attribution
pipeline: [ARCHITECTURE.md — Resource pools](../ARCHITECTURE.md#resource-pools--shared-capacity-adr-0010).

Why not our own allocation accounting: Kueue already provides cohort
borrowing with `lendingLimit` (GA in v0.17), fair sharing (preemption-based
stable since v0.7, no gate), gang admission of all three KubeRay CRDs
(RayJob/RayCluster/RayService) via whole-workload suspend, a machine-readable
quota ledger in `ClusterQueue.status.flavorsReservation`/`flavorsUsage`, and
Prometheus metrics. Rebuilding that on ResourceQuota would give us static
per-namespace caps with no queueing, no borrowing, and no fair sharing —
exactly the features the pool concept exists for.

**Fallback:** when the Kueue CRDs are absent from a cluster, the existing
in-process `mobula-policy` quota admission (`admit()` against per-project
limits) remains the enforcement — REQUIREMENTS §3.2's "delegate to Kueue
where present."

### Known divergences (accepted, not bugs)
- **Reject-fast vs queue.** Mobula's pre-flight `admit()` rejects
  over-quota creates with 409 where Kueue would queue the workload. Kept in
  v0: a synchronous create API owes the caller an immediate answer.
- **Ledger vs consumption.** Kueue's `flavorsUsage` is a *reservation*
  ledger (sums of admitted workload requests), not measured consumption.
  Mobula meters real consumption itself for attribution/chargeback (later
  slice).

### Deferred (with the one-line why)
- **Warm pools** — needs balloon pods / priority-band policy; a Phase 4
  policy-engine concern, not pool-topology translation.
- **MultiKueue external dispatch** — still beta and dispatch-shaped (no
  spanning pool); revisit when Mobula places clusters across multiple K8s
  clusters.
- **DRA-native flavors** — no documented KubeRay DRA path
  (kuberay#4749); Kueue's DRA quota is beta and ExactCount-only.
- **Graceful-shrink-before-preemption** — blocked upstream by
  [kueue#7569](https://github.com/kubernetes-sigs/kueue/issues/7569);
  preemption is whole-workload and destroys the Ray head.
- **Queue-instead-of-409 semantics** — requires an async admission surface
  (pending cluster state + notifications), out of v0 scope.

## Consequences
Mobula's build surface shrinks to: tenant→LocalQueue mapping, cohort/CQ
topology management (pure translation in `mobula-provision::kueue`), and an
attribution layer over Kueue status + own metering. Pool resource keys are
arbitrary Kubernetes resource names (extended resources like
`nvidia.com/gpu` or `example.com/license` included), so `mobula-policy`'s
fixed `ResourceVector {cpu,gpu,mem_gib}` generalizes to a `ResourceMap`
keyed by resource name. Without Kueue installed, behavior is unchanged from
today (in-process quota admission only).
