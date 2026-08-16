# Can Kueue be Mobula's capacity-pool engine? (2026-08 research)

Research question: should Mobula's "shared resource pool" be a thin
control/attribution layer over Kueue, or its own allocation accounting on
top of raw KubeRay + ResourceQuota? Companion docs:
[Anyscale capacity model](anyscale-capacity-model.md) (what we're copying)
and [vertical autoscaling stack](RESEARCH-2026-08-vertical-autoscaling-stack.md)
(who owns each scaling layer).

Method: web research sweep on 2026-08-15/16 against kueue.sigs.k8s.io,
docs.ray.io, kubernetes-sigs KEPs, and release notes. Version numbers and
stability levels are stated per claim; a "flagged unverifiable / conflicting"
list closes the doc.

**Version correction up front:** the current Kueue line is **v0.19.1**
(API `kueue.x-k8s.io/v1beta2`, supported on K8s >= 1.34) and KubeRay is
**v1.6.x**. Several features assumed alpha-grade in earlier planning docs
have graduated since. Sources:
[Kueue releases](https://github.com/kubernetes-sigs/kueue/releases),
[Kueue installation](https://kueue.sigs.k8s.io/docs/installation/).

---

## 1. Core model fit — a Cohort *is* the shared capacity envelope

- **ClusterQueue** is the cluster-scoped object governing a resource pool
  with per-flavor quotas and fair-sharing rules; **LocalQueue** is the
  namespaced tenant handle pointing at one ClusterQueue; **ResourceFlavor**
  models node variations (GPU model, spot vs on-demand) via
  `nodeLabels`/`nodeTaints`/`tolerations`, with Kueue injecting flavor
  labels/tolerations into admitted pods; **Cohort** groups ClusterQueues so
  they can borrow each other's unused quota.
  ([cluster_queue](https://kueue.sigs.k8s.io/docs/concepts/cluster_queue/),
  [local_queue](https://kueue.sigs.k8s.io/docs/concepts/local_queue/),
  [resource_flavor](https://kueue.sigs.k8s.io/docs/concepts/resource_flavor/),
  [cohort](https://kueue.sigs.k8s.io/docs/concepts/cohort/))
- Since **hierarchical cohorts (KEP-79)**, Cohort is a first-class API
  object that can itself hold `nominalQuota` (a shared pool layered on top
  of member CQs' quotas) and form a CohortTree via `parentName`. So "many
  tenants draw from one shared envelope with admission, borrowing, and fair
  sharing" is exactly the cohort model.
  ([cohort](https://kueue.sigs.k8s.io/docs/concepts/cohort/),
  [KEP-79](https://github.com/kubernetes-sigs/kueue/tree/main/keps/79-hierarchical-cohorts))
- **nominalQuota vs borrowingLimit vs lendingLimit** (per flavor+resource
  in `.spec.resourceGroups[].flavors[].resources[]`):
  - `nominalQuota` — the CQ's own guaranteed amount; borrowing = fitting
    within unused *cohort* nominal quota up to `nominalQuota + borrowingLimit`.
  - `borrowingLimit` — caps how much *this* CQ borrows; unset = up to the
    sum of all nominal quotas in the cohort (effectively unlimited).
  - `lendingLimit` — caps how much *others* may borrow from this CQ's
    unused quota; unset = lends everything. Alpha in v0.6 (gate
    `LendingLimit`), beta/default-on in v0.9, **GA in v0.17**.
    ([KEP-1224](https://github.com/kubernetes-sigs/kueue/tree/main/keps/1224-lending-limit))
  - With hierarchical cohorts both limits also exist on Cohort objects
    (valid only when the Cohort has a parent). To borrow from a
    Cohort-level shared pool, a CQ must declare nominalQuota for that
    resource/flavor even if 0. ([KEP-79](https://github.com/kubernetes-sigs/kueue/tree/main/keps/79-hierarchical-cohorts))
- **Fair sharing** — two distinct mechanisms:
  - *Preemption-based fair sharing* (dominant resource share across cohort
    members): **stable since v0.7, no feature gate** — enabled via
    `fairSharing.enable: true` + `preemptionStrategies` in the Kueue
    Configuration; weight per CQ via `.spec.fairSharing.weight`.
    Compatible with hierarchical cohorts since v0.11. Incompatible with
    `borrowWithinCohort`.
    ([preemption](https://kueue.sigs.k8s.io/docs/concepts/preemption/))
  - *Admission Fair Sharing* (orders pending workloads by LocalQueues'
    historical usage with half-life decay): gate `AdmissionFairSharing`,
    alpha in v0.12, **beta + default-on since v0.15**.
    ([admission_fair_sharing](https://kueue.sigs.k8s.io/docs/concepts/admission_fair_sharing/))
  - `HierarchicalCohorts` gate: beta/default-on since v0.11, **GA in
    v0.17**; Cohort object served as `v1alpha1` in v0.11–v0.12, `v1beta1`
    from v0.13.
- **Resource types**: quotas cover `cpu`, `memory`, `pods`,
  `nvidia.com/gpu`-style extended resources, and **arbitrary extended/
  custom resources** — the official example quotas a literal `foo.com/gpu`
  and a `bar.com/license`. Any resource name in pod requests is coverable.
  ([cluster_queue](https://kueue.sigs.k8s.io/docs/concepts/cluster_queue/))
- **Caveat**: Kueue quotas are static reservation envelopes, not dynamic
  node allocation — Kueue admits/evicts against quota but does not
  provision nodes (that pairs with cluster-autoscaler/ProvisioningRequest).

## 2. KubeRay integration — first-class, gang, whole-cluster suspend

- Built-in integrations: **RayJob since Kueue v0.4.0** (#667), **RayCluster
  since v0.6.0** (#1520), **RayService natively top-level since v0.17.0**
  (#9973; before that managed indirectly via its RayCluster).
  ([v0.4.0](https://github.com/kubernetes-sigs/kueue/releases/tag/v0.4.0),
  [v0.6.0](https://github.com/kubernetes-sigs/kueue/releases/tag/v0.6.0),
  [v0.17.0](https://github.com/kubernetes-sigs/kueue/releases/tag/v0.17.0),
  [RayService task](https://kueue.sigs.k8s.io/docs/tasks/run/rayservices/))
- Documented floors: Kueue >= v0.6.0 + KubeRay >= v1.1.0 for
  RayCluster/RayJob; KubeRay >= v1.3.0 for RayService.
  ([rayclusters](https://kueue.sigs.k8s.io/docs/tasks/run/rayclusters/))
- **Admission is gang / all-or-nothing**: a RayCluster becomes one Workload
  with one PodSet for the head + one per worker group; "Kueue always admits
  workloads in 'gang' mode ... Kubernetes never partially provisions a
  RayJob or RayCluster." `PartialAdmission` exists only for batch/v1 Job —
  **no partial admission of worker groups for Ray**. Structural cap: max 18
  PodSets → **max 17 workerGroupSpecs** currently (was 7 in v0.12).
  ([KubeRay Kueue guide](https://docs.ray.io/en/latest/cluster/kubernetes/k8s-ecosystem/kueue.html),
  [rayclusters limitations](https://kueue.sigs.k8s.io/docs/tasks/run/rayclusters/))
- **Suspend semantics**: Kueue owns `spec.suspend` on the
  RayCluster/RayJob (and `spec.rayClusterConfig.suspend` for RayService),
  holding the whole CR pod-less until admitted; eviction reverses it and
  KubeRay deletes head + all workers. KubeRay-side baseline: `spec.suspend`
  added in **KubeRay v1.1.0**; `managedBy` (for MultiKueue) + per-worker-
  group suspend in **v1.3.0**; no Kueue-facing changes in v1.4/v1.5 (v1.4
  added an alternative gang path via scheduler-plugins); `managedBy` on
  RayService in **v1.6.0**.
  ([KubeRay v1.1.0](https://github.com/ray-project/kuberay/releases/tag/v1.1.0),
  [v1.3.0](https://github.com/ray-project/kuberay/releases/tag/v1.3.0),
  [v1.6.0](https://github.com/ray-project/kuberay/releases/tag/v1.6.0))
- **Autoscaler interaction** — the critical point for Mobula:
  - In **default (non-elastic) mode, the in-tree Ray autoscaler escapes
    Kueue accounting and is unsupported**: v0.12-era docs required it
    disabled; current docs only describe autoscaling for elastic clusters.
    ([v0.12 rayclusters.md](https://raw.githubusercontent.com/kubernetes-sigs/kueue/v0.12.0/site/content/en/docs/tasks/run/rayclusters.md))
  - In **elastic mode** (gate `ElasticJobsViaWorkloadSlices` + annotation
    `kueue.x-k8s.io/elastic-job: "true"` + `enableInTreeAutoscaling: true`),
    post-admission scaling is re-accounted: scale-up creates a
    WorkloadSlice that must pass quota admission; scale-down releases quota
    in place. RayJob autoscaling supported from Kueue v0.15.2.
    ([elastic_workload](https://kueue.sigs.k8s.io/docs/concepts/elastic_workload/))
  - Open hazard: suspend→requeue→re-admit on shape change can unsafely
    terminate the Ray head — [kueue#7569](https://github.com/kubernetes-sigs/kueue/issues/7569)
    (open since Nov 2025).

## 3. Elastic workloads — Beta since v0.18; Ray autoscaling is the headline use case

- The feature is **KEP-77 "Dynamically Sized Jobs"**, surfaced as "Elastic
  Workloads (Workload Slices)": in-place horizontal resize of admitted
  workloads without suspension/requeue, via extra Workload objects owned by
  the original. Scale-up = new slice needing admission; scale-down =
  in-place pod-count update releasing quota; new pods held by a scheduling
  gate until their slice admits.
  ([KEP-77](https://github.com/kubernetes-sigs/kueue/tree/main/keps/77-dynamically-sized-jobs),
  [elastic_workload](https://kueue.sigs.k8s.io/docs/concepts/elastic_workload/))
- Timeline: **alpha in v0.13.0** (batch Job only, gate
  `ElasticJobsViaWorkloadSlices` default-off); **v0.14.0** added RayCluster
  in-tree-autoscaler support (#6662); RayJob autoscaling per Ray docs
  requires >= v0.15.2; **Beta + enabled by default in v0.18**; still
  **not GA** in v0.19 (KEP-77 GA criteria all unchecked — no slice GC, no
  production-scale proof).
- Supported elastic kinds: `batch/v1.Job`, `ray.io/v1.RayJob`,
  `ray.io/v1.RayCluster` (RayService indirectly via its managed
  RayCluster). This **does** cover "worker count changing within quota
  after admission" — the Ray docs walk through a RayJob scaling workers
  1→5 inside admitted quota.
- Production-usability assessment: Beta and default-on, but v0.17–v0.19
  patch streams carry a steady flow of correctness fixes specific to this
  gate (quota leaks on scale-up, duplicate admitted slices, pods stuck
  `SchedulingGated`, stale `reclaimablePods` accounting). Usable if pinned
  to latest v0.18+/v0.19 patch; still maturing.
- Limitations: incompatible with PartialAdmission; **sticky flavor**
  (scale-up must reuse the originally assigned ResourceFlavor); no TAS in
  the base feature (separate alpha gate
  `ElasticJobsViaWorkloadSlicesWithTAS` since v0.17, unconstrained mode
  only); finished slices retained indefinitely; Kueue never initiates
  scaling itself. MultiKueue support is **contradictory across sources** —
  v0.14 notes claim elastic batch-Job MultiKueue support and v0.19
  propagates elastic RayCluster resizes to worker clusters (#12885), while
  the concept doc still says "No MultiKueue support" and
  [#6335](https://github.com/kubernetes-sigs/kueue/issues/6335) tracks it
  as future work.

## 4. Preemption — whole-workload only; a preempted RayCluster is destroyed

- Core model (KEP-83, no gate): preemption evicts already-admitted
  Workloads for a pending one, triggered when a same-CQ preemptee has lower
  priority, or a same-cohort CQ is over nominal quota. Policies on
  `.spec.preemption`: `withinClusterQueue`
  (`Never`/`LowerPriority`/`LowerOrNewerEqualPriority`),
  `reclaimWithinCohort` (`Never`/`LowerPriority`/`Any`), and
  `borrowWithinCohort` (v0.6+, classic preemption only, not with fair
  sharing).
  ([KEP-83](https://github.com/kubernetes-sigs/kueue/tree/main/keps/83-workload-preemption))
- **Fair-sharing preemption**: stable since v0.7 (KEP-1714) — preempts
  from the highest-share CQ until the preemptor reaches its weighted share;
  strategies `LessThanOrEqualToFinalShare`/`LessThanInitialShare`. Provably
  loop-free between two workloads; hierarchical-cohort case still listed as
  a limitation.
  ([KEP-1714](https://github.com/kubernetes-sigs/kueue/tree/main/keps/1714-fair-sharing))
- Semantics: preempted Workload gets `Evicted=True`/`Preempted=True`, pods
  are deleted by the job controller, and the Workload is **requeued**
  automatically.
- **Granularity: whole-workload only.** For a RayCluster, preemption sets
  `spec.suspend=true` and KubeRay tears down head + all workers including
  GCS state. **There is no way to reclaim only some workers** — partial
  preemption is explicitly unsupported even for elastic workloads
  ([kueue#7569](https://github.com/kubernetes-sigs/kueue/issues/7569)).
  The closest adjacent mechanisms are partial *admission* (batch Job only)
  and Dynamic Reclaim (`reclaimablePods`, voluntary, beta since v0.15).
- Newer gates: `FairSharingPreemptWithinNominal` and
  `FairSharingPrioritizeNonBorrowing` beta since v0.17;
  `MultiKueueOrchestratedPreemption` alpha since v0.17 (KEP-8303).

## 5. Accounting — Kueue status *is* the quota ledger; MultiKueue is dispatch, not a spanning queue

- **Readable status**: `ClusterQueue.status.flavorsReservation` /
  `flavorsUsage` give per-flavor, per-resource `total`/`borrowed` plus
  `pendingWorkloads`/`reservingWorkloads`/`admittedWorkloads`;
  `LocalQueue.status` mirrors this per tenant (flavors in LQ status since
  v0.9).
  ([v1beta1 API reference](https://github.com/kubernetes-sigs/kueue/blob/main/site/content/en/docs/reference/kueue.v1beta1.md))
- **Authoritative for the quota ledger, not for live consumption**: these
  fields sum podSet requests of admitted/reserved Workloads — the exact
  numbers Kueue admits against. They do not track actual running pod
  requests (a mutated workload is still fully counted until
  eviction/finish; non-Kueue pods are invisible). Pod-request summing is
  only needed if Mobula wants real consumption *distinct from* Kueue's
  ledger. (Inference from API semantics — no doc states it verbatim;
  flagged as unverifiable.)
- **Prometheus**: `kueue_cluster_queue_resource_usage`,
  `_resource_reservation`, `_nominal_quota`, `_borrowing_limit`,
  `_lending_limit` (opt-in via `metrics.enableClusterQueueResources:
  true`); always-on gauges `kueue_admitted_active_workloads`,
  `kueue_pending_workloads`, etc. LocalQueue resource metrics are **alpha
  since v0.10** behind `LocalQueueMetrics`.
  ([metrics reference](https://kueue.sigs.k8s.io/docs/reference/metrics/))
- **MultiKueue**: **beta since v0.9, still not GA in v0.19 docs.** Shape:
  a manager-cluster ClusterQueue does *not* span clusters — it carries an
  AdmissionCheck backed by `MultiKueueConfig` listing worker clusters;
  manager quota gates dispatch eligibility, worker-cluster Kueue does real
  admission; the dispatcher copies the Workload, syncs status back, and
  records placement in `status.clusterName`. Dispatch algorithms:
  `AllAtOnce`, `Incremental` (beta since v0.16), and `External` (custom
  controller nominates clusters — relevant if Mobula wants its own
  placement).
  ([multikueue](https://kueue.sigs.k8s.io/docs/concepts/multikueue/),
  [setup](https://kueue.sigs.k8s.io/docs/tasks/manage/setup_multikueue/))
- **KubeRay dispatch**: RayJob and RayCluster since **Kueue v0.11.0**,
  recommended with **KubeRay >= v1.3.1** (`spec.managedBy` mechanism);
  RayService via managedBy. Manager cannot be its own worker.
  ([v0.11.0 notes](https://github.com/kubernetes-sigs/kueue/releases/tag/v0.11.0),
  [MultiKueue KubeRay task](https://kueue.sigs.k8s.io/docs/tasks/run/multikueue/kuberay/))
- Note: RayJobs against an *existing* RayCluster (`spec.clusterSelector`)
  are explicitly out of Kueue's scope
  ([kueue#7219](https://github.com/kubernetes-sigs/kueue/issues/7219)) —
  relevant because Mobula's dominant pattern is job submission onto
  long-lived clusters.

## 6. Alternatives (why the pool engine is Kueue, not a second scheduler)

- **Namespace ResourceQuota**: GA forever, limits aggregate consumption per
  namespace including GPU extended resources — but enforcement is
  admission-time 403 rejection with **no queueing**, quotas are static
  absolute units independent of cluster capacity, each namespace is capped
  independently with **no borrowing/lending and no fair sharing**
  (over-subscription resolves first-come-first-served). Fine as a static
  safety rail; cannot implement pooled capacity alone.
  ([kubernetes.io Resource Quotas](https://kubernetes.io/docs/concepts/policy/resource-quotas/))
- **NVIDIA KAI Scheduler** (OSS run:ai, ~v0.17.0): provides all four pool
  primitives — gang, hierarchical queues with quotas/over-quota weights,
  DRF fairness + reclamation, preemption, fractional GPU, DRA support — and
  **native KubeRay integration** (`batchScheduler.name=kai-scheduler`;
  RayCluster/RayService/RayJob from KubeRay v1.6, KAI >= v0.10). Caveat: it
  is a **pod-level scheduler** — no job suspension; gang-failed pods exist
  and pend; pre-1.0 versioning with breaking changes; single-vendor
  governance.
  ([KAI README](https://github.com/NVIDIA/KAI-Scheduler),
  [Ray KAI docs](https://docs.ray.io/en/latest/cluster/kubernetes/k8s-ecosystem/kai-scheduler.html))
- **Volcano** (CNCF incubating, v1.15.0): gang + queues with
  `capability`/`weight`/`reclaimable` + preemption, and the deepest Ray
  story of the four — KubeRay operator support for all three CRDs
  (~v1.5.1–v1.6.0; sources conflict) plus a native `ray` vcjob plugin. But
  queues are cluster-scoped only, no nominal-quota/cohort borrowing model,
  and it's again a pod scheduler — unschedulable gangs sit as Pending pods.
  ([volcano.sh RayOnVolcano](https://volcano.sh/docs/ecosystem/rayonvolcano/))
- **Apache YuniKorn** (TLP, v1.9.0): hierarchical queues with
  min/guaranteed + max/quota, fairness, gang with reservations, explicit
  queueing on max-capacity — conceptually close to the pool model. But
  KubeRay integration is label-driven and stated by Ray docs to be "in
  alpha testing," queues live in a scheduler ConfigMap (`queues.yaml`)
  rather than CRDs (awkward for a control plane CRUD-ing tenant pools), and
  it replaces kube-scheduler with a non-SIG-Scheduling codebase.
  ([YuniKorn features](https://yunikorn.apache.org/docs/get_started/core_features/))
- Framing: KAI/Volcano/YuniKorn are second schedulers doing gang+quota at
  pod level; **Kueue is the only job-level admission controller** (suspends
  workloads before pods exist) and can delegate pod-level gang to a
  scheduler underneath — its stated goal is verbatim Mobula's: "manage
  access to a limited pool of resources shared by multiple tenants."
  ([Introducing Kueue](https://kubernetes.io/blog/2022/10/04/introducing-kueue/))

## 7. DRA — quota accounting ships today (beta), via device-class mapping

- Baseline: DRA core GA in **Kubernetes 1.34** (Aug 2025); sub-features:
  extended-resource mapping (KEP-5004) alpha 1.34 → beta 1.36;
  partitionable devices (KEP-4815) beta 1.36; admin access GA 1.36.
  ([K8s 1.34 DRA blog](https://kubernetes.io/blog/2025/09/01/kubernetes-v1-34-dra-updates/))
- Kueue integration is **KEP-2941**, and it is **shipping, not roadmap**:
  admins map `DeviceClass` names to logical resource names via
  `deviceClassMappings` in Kueue config, then quota those names in
  ClusterQueues — borrowing, cohorts, preemption, and fair sharing all
  apply. Gates: `KueueDRAIntegration` alpha v0.14 → **beta/default-on
  v0.18** (ResourceClaimTemplate device-count quota);
  `...ExtendedResource` alpha v0.17 → **beta v0.19** (quota on
  `nvidia.com/gpu: 1`-style requests backed by a DeviceClass);
  `...PartitionableDevices` alpha v0.18 → **beta v0.19** (counter-based
  quota, e.g. MIG memory); `...ConsumableCapacity` **alpha v0.19**
  (time-slicing/MPS).
  ([KEP-2941](https://github.com/kubernetes-sigs/kueue/blob/main/keps/2941-DRA/README.md),
  [Kueue v0.19 DRA docs](https://kueue.sigs.k8s.io/v0.19/docs/concepts/dynamic_resource_allocation/))
- Limits: **direct ResourceClaim references are unsupported** (marked
  inadmissible); only `AllocationMode=ExactCount` is quota-accounted; no
  TAS accounting for DRA; admission-scheduling gap remains (Kueue checks
  quota without knowing the device picked; `WaitForPodsReady` is the safety
  net). Beta tracking: [#8243](https://github.com/kubernetes-sigs/kueue/issues/8243).
- **KubeRay + DRA: not officially supported/documented** —
  [kuberay#4749](https://github.com/ray-project/kuberay/issues/4749)
  (Apr 2026) says docs/examples don't cover DRA; pod templates could carry
  `resourceClaims` manually but this is unverified.

## Verdict: can Kueue be Mobula's pool engine?

**Mostly yes.** Kueue gives Mobula the pool substrate out of the box:
cohort-level shared envelopes with nominal/borrowing/lending quotas (GA'd
semantics), fair sharing (preemption-based stable since v0.7,
admission-based beta), gang admission + whole-cluster suspension for all
three KubeRay CRDs, elastic Ray autoscaling re-accounted against quota
(beta since v0.18), a machine-readable quota ledger in
`ClusterQueue.status`/`LocalQueue.status` plus Prometheus, and MultiKueue
(beta) for multi-cluster dispatch including Ray. Mobula's build surface is
then: tenant→LocalQueue mapping, cohort/CQ topology management, an
attribution/chargeback layer reading `flavorsUsage`, and optionally an
`External` MultiKueue dispatcher for its own placement.

**Gaps that force Mobula-side work:**

1. **No partial preemption / no graceful shrink.** Reclaiming capacity from
   a RayCluster destroys the entire cluster (head included); there is no
   "evict N workers, keep the head" path, even for elastic workloads
   ([#7569](https://github.com/kubernetes-sigs/kueue/issues/7569), open).
   If Mobula needs non-destructive capacity reclaim, it must implement its
   own worker-group scale-down (via elastic scale-down, which *is*
   in-place) *before* Kueue preemption fires, or accept teardown semantics.
2. **Ledger vs. consumption divergence.** `flavorsUsage` is Kueue's quota
   ledger, not measured consumption; non-elastic autoscaled or mutated
   workloads can drift from it. For billing-grade attribution Mobula still
   needs its own consumption metering (e.g. pod-request metrics) alongside
   Kueue status — and no Kueue doc states authoritatively how
   post-admission changes reconcile outside elastic mode (unverifiable).
3. **Elastic mode maturity and constraints.** Workload Slices are
   beta-not-GA with an active bug-fix stream, sticky-flavor scale-up, no
   TAS, no slice GC, and contradictory MultiKueue support — pin latest
   patches and treat elastic+MultiKueue as uncertain.
4. **MultiKueue is dispatch, not a spanning pool.** A ClusterQueue never
   spans clusters; cross-cluster capacity is two-level accounting (manager
   eligibility + worker admission), still beta, with the manager unable to
   serve as its own worker.
5. **DRA quotas are young.** Usable today at beta for ExactCount claim
   templates and extended-resource mapping, but no direct-ResourceClaim
   quota, no non-ExactCount modes, and KubeRay itself has no documented DRA
   path — if Mobula's pool is DRA-native GPU allocation, expect
   co-development with upstream.
6. **Static envelopes.** Quotas don't follow cluster capacity; resizing the
   pool with node count requires either cluster-autoscaler/ProvisioningRequest
   integration or Mobula rewriting `nominalQuota` itself.

**Flagged unverifiable / conflicting:** whether preemption-based fair
sharing ever had a labeled alpha period (docs say "stable since v0.7" with
no earlier label); MultiKueue × elastic-workload support (release notes vs.
concept doc disagree); exact KubeRay version for full Volcano RayJob
support (v1.5.1 vs v1.6.0 across sources); KAI Scheduler's LTS policy
(secondary source only); WorkloadSlice's served API version (absent from
the v1beta1 API reference); v0.13 docs' `HierarchicalCohort` (singular)
gate name is a typo — source says `HierarchicalCohorts`; a CNCF blog's
"DRA GA in 1.35" is wrong — the kubernetes.io 1.34 blog is authoritative.
