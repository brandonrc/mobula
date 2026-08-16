# Vertical autoscaling stack & edge cases (2026-08 research)

Research question: for Mobula's shared multi-tenant capacity pool over
KubeRay-managed Ray clusters, who owns what in the vertical autoscaling
stack (Ray autoscaler → K8s scheduler/Kueue → node provisioner), and what
is the state of the hard edges: admission-aware node provisioning, elastic
cross-cluster reclaim, multi-cluster pooling, and GPU sub-allocation.

Method: six parallel research sweeps on 2026-08-16, preferring official
sources (kubernetes.io, karpenter.sh, kueue.sigs.k8s.io, docs.ray.io,
KubeRay, sig-autoscaling repos). Time context: mid-2026. Version reality
check: **Kueue latest is v0.19.1 (2026-08-12)** — the "v0.11/0.12 current"
assumption in the original brief was outdated, and several features below
moved alpha→beta→GA between v0.13 and v0.19.

---

## 1. The four layers — triggers, visibility, ownership

### (a) Ray autoscaler v2 (in KubeRay)

- **Trigger:** Ray *logical* resource demands (from `@ray.remote`
  annotations on tasks/actors/placement groups), not physical utilization.
  A GCS-served snapshot (pending demands, node states, idle durations)
  feeds a reconciliation loop (default ~5s, `AUTOSCALER_UPDATE_INTERVAL_S`)
  that bin-packs demands against worker-group configs.
  <https://docs.ray.io/en/latest/cluster/kubernetes/user-guides/configuring-autoscaling.html>,
  <https://docs.ray.io/en/latest/ray-core/internals/autoscaler-v2.html>
- **Sees:** Ray cluster-internal state only — pending demands, node
  idleness (`idle_duration_ms`), `request_resources()` constraints. Not
  K8s nodes, cloud quota, or other tenants.
- **Owns:** `workerGroupSpecs[].replicas` (scale-up) and `workersToDelete`
  (scale-down) on the RayCluster CR. It never creates pods; the KubeRay
  operator reconciles pods to match `replicas`. Scale-down selects specific
  pods and uses graceful Ray draining in v2 (`RAY_STOP_REQUESTED`; a drain
  can be *rejected* if the node became active again, transitioning back to
  `RAY_RUNNING` — fixing the v1 race).
  <https://docs.ray.io/en/latest/cluster/kubernetes/user-guides/k8s-autoscaler.html>
- Requires the autoscaler sidecar (`enableInTreeAutoscaling: true`); v2
  via `autoscalerOptions.version: v2` requires KubeRay ≥ v1.4.0. v2
  shipped as alpha in Ray 2.10.0 and **the docs still carry the alpha
  banner**, but per the KubeRay API reference **v2 is the default since
  Ray 2.47.0** — de facto GA, formal label unverified.
  <https://ray-project.github.io/kuberay/reference/api/>
- `upscalingMode`: `Default`/`Aggressive` vs `Conservative` (pending
  workers ≤ connected workers). `idleTimeoutSeconds` default 60s.

### (b) Kubernetes scheduler + Kueue admission

- kube-scheduler binds pods to existing nodes and marks them unschedulable
  otherwise — that mark is the signal layer (c) consumes. It owns only
  pod-to-node binding.
- Kueue: quota-based admission before pods exist; gang (all-or-nothing)
  admission; controls `spec.suspend` on RayCluster. Requires Kueue ≥ v0.6,
  KubeRay ≥ v1.1. A RayCluster **holds its quota for its entire lifetime**;
  max 17 worker groups (18 PodSets per Workload).
  <https://kueue.sigs.k8s.io/docs/tasks/run/rayclusters/>,
  <https://docs.ray.io/en/latest/cluster/kubernetes/k8s-ecosystem/kueue.html>
- Kueue + Ray in-tree autoscaling together is supported only via
  `kueue.x-k8s.io/elastic-job: "true"` and the
  **`ElasticJobsViaWorkloadSlices` gate — alpha since v0.13, beta and
  default-on since v0.18**; RayJob autoscaling from Kueue v0.15.2. Kueue
  creates WorkloadSlices per scale step so autoscaling stays within
  admitted quota.
  <https://kueue.sigs.k8s.io/docs/concepts/elastic_workload/>

### (c) Node provisioners

- **Cluster-autoscaler** (GA): reacts to scheduler-marked unschedulable
  pods (scan every 10s); scale-down below 50% requested utilization for 10
  min. SLO ~30–60s *excluding* cloud VM provisioning; gives up on
  unregistered nodes after 15 min (`--max-node-provision-time`).
  <https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/FAQ.md>
- **Karpenter** (v1 stable): provisions nodes for unschedulable pods,
  batching/bin-packing them onto instance types; owns node lifecycle
  including **consolidation and drift — it actively evicts running pods**
  to repack (mitigate with PDBs, `karpenter.sh/do-not-disrupt`, NodePool
  disruption budgets). Node Auto Repair alpha in v1.1.0.
  <https://karpenter.sh/docs/concepts/disruption/>, <https://karpenter.sh/v1.0/faq/>
- Never run CA and Karpenter against the same capacity. CA FAQ: "Do not
  run any additional node group autoscalers."

### The Pending-pods chain — confirmed

Yes: the Ray autoscaler increments `replicas` → KubeRay creates worker
pods → pods with no fitting node go **Pending** → both CA and Karpenter
react to those Pending pods. Ray docs explicitly describe this third level
and state *"You must configure the Kubernetes Autoscaler yourself."*
<https://docs.ray.io/en/latest/cluster/kubernetes/user-guides/configuring-autoscaling.html>,
<https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/FAQ.md>,
<https://karpenter.sh/v1.0/faq/>

### Known failure modes

1. **Ray autoscaler ↔ node autoscaler mismatch.** Ray's guidance is "one
   Ray pod per Kubernetes node" so pod-scale maps ~1:1 to node-scale; no
   official doc forbids the combination, but node autoscalers are blind to
   Ray logical state, and Karpenter consolidation/drift can evict Ray pods
   on bin-packing economics (known bugs evicted even `do-not-disrupt` pods:
   <https://github.com/aws/karpenter-provider-aws/issues/6407>,
   <https://github.com/aws/karpenter-provider-aws/issues/5786>).
2. **Scale-up latency couples into the Ray control loop.** Autoscaler v2
   **hangs when maxReplicas changes while pods are Pending** (instances
   stuck ALLOCATED): <https://github.com/ray-project/ray/issues/50868>.
   Other v2 bugs: stalls scaling multiple workers
   (<https://github.com/ray-project/kuberay/issues/2759>), Conservative
   upscaling not honored (<https://github.com/ray-project/ray/issues/50259>),
   `workersToDelete` counting race (<https://github.com/ray-project/ray/issues/52264>),
   sidecar crash taking down the head pod when demand exceeds maxReplicas
   (<https://github.com/ray-project/kuberay/issues/2385>).
3. **Kueue-admitted-but-no-nodes.** Quota admission is logical, not
   physical; without an admission check, admitted pods pend. The
   ProvisioningRequest admission check (GA, Kueue v0.14) closes this —
   **only with cluster-autoscaler** (see §2).
4. **Overprovisioning workaround.** Official CA pattern: low-priority
   (-10) pause pods preempted by real pods, sized via
   cluster-proportional-autoscaler (CA FAQ); Karpenter equivalent is
   pre-warmed pause pods per zone (Karpenter FAQ).

## 2. Kueue ↔ node provisioning

### ProvisioningRequest admission check (cluster-autoscaler) — GA

- Two-phase admission: **(1) quota reservation** against ClusterQueue
  quota/flavors, then **(2) capacity guarantee** — Kueue creates a
  `ProvisioningRequest` (autoscaling.x-k8s.io) attaching the Workload's
  PodTemplates; CA consumes it and reports conditions
  (`Provisioned`/`Failed`/`BookingExpired`/`CapacityRevoked`). Only on
  `Provisioned=true` does Kueue mark the check Ready and unsuspend the job;
  on failure quota is released and the workload retries with backoff
  (defaults: limit 3, base 60s, max 1800s).
  <https://kueue.sigs.k8s.io/docs/concepts/admission_check/provisioning_request/>,
  <https://kueue.sigs.k8s.io/docs/admission-check-controllers/provisioning/>
- `podSetUpdates` injects nodeSelectors pinning pods onto the newly
  provisioned nodes (requires the provisioning class to label them).
- Feature gate history: alpha v0.5–v0.6, **beta v0.7–v0.13, GA v0.14**
  (gate removed in v0.15, always on).
  <https://kueue.sigs.k8s.io/docs/tasks/troubleshooting/troubleshooting_provreq/>
- ProvisioningRequest is a **SIG-Autoscaling CRD owned by
  cluster-autoscaler, not an in-tree K8s API** (no KEP-1613 — that number
  is an unrelated scheduler item). Requires CA ≥ 1.30.1 with
  `--enable-provisioning-requests=true`; CRD serves `v1` on master with
  `v1beta1` deprecated; up to 32 PodSets per request.
  <https://github.com/kubernetes/autoscaler/blob/master/cluster-autoscaler/proposals/provisioning-request.md>
- Provisioning classes: `check-capacity.autoscaling.x-k8s.io` (one-off
  check, no reservation) and `best-effort-atomic-scale-up.autoscaling.x-k8s.io`
  (atomic scale-up, cleanup of partial failures, `ValidUntilSeconds`
  timeout). Provider classes exist, e.g. GKE `queued-provisioning.gke.io` —
  **caveat: GKE queued-provisioning currently supports only a single
  PodSet per request, breaking RayJob gang via ProvReq on GKE**
  (<https://github.com/ray-project/ray/issues/57839>).

### Karpenter — no equivalent (mid-2026)

- Karpenter's model is purely reactive: it provisions nodes for pods the
  scheduler marked unschedulable; **there is no admission/pre-provisioning
  hook**. <https://karpenter.sh/docs/faq/>
- Karpenter does **not** implement ProvisioningRequest. Maintainer
  (jonathan-innis, 2025-05): "We don't have a way to do that right now
  outside of negative priority pods… There's a separate proposal called
  **Buffer** that I think more folks are aligned with."
  <https://github.com/kubernetes-sigs/kueue/issues/5133#issuecomment-2878727421>
- De-facto workaround: oversize ClusterQueue nominal quota so Kueue admits
  → pods pend → Karpenter scales reactively. Consequences: admission is
  not a capacity guarantee, gang semantics are lost (a RayCluster can
  partially schedule), and scale-up latency lands on the job's start path.
- The emerging path is the **CapacityBuffer API** (SIG Autoscaling design,
  <https://github.com/kubernetes/autoscaler/pull/8151>): Karpenter shipped
  alpha support in **v1.14.0** (gate `CapacityBuffer`, default off;
  <https://karpenter.sh/docs/concepts/capacitybuffers/>), working via
  virtual placeholder pods in scheduling simulation. A Kueue admission
  check for CapacityBuffer is **proposed, not shipped** as of 2026-08
  (<https://github.com/kubernetes-sigs/kueue/issues/5133#issuecomment-5221755871>).

## 3. Pinned vs shared capacity — elastic reclaim

**Short answer: reclaim of *idle* workers is achievable today; reclaim of
*busy* workers is always a kill.** The practical 2026 model is whole-
workload preemption as the enforcement floor, plus fine-grained scale-down
of idle capacity as the elastic fast path.

- **Single-cluster shrink works.** The Ray autoscaler decrements
  `replicas` + adds pods to `workersToDelete`; only genuinely idle workers
  (no active tasks/actors/referenced objects) are eligible
  (`idleTimeoutSeconds`, default 60s), and v2's graceful drain is
  rejection-capable. The head pod, Service, and CR persist — cluster-level
  idle teardown is still an open request
  (<https://github.com/ray-project/kuberay/issues/4768>).
  <https://docs.ray.io/en/latest/cluster/kubernetes/user-guides/configuring-autoscaling.html>
- **Kueue preemption unit = the whole Workload.** No per-pod/partial
  preemption; the algorithm only minimizes the *set of Workloads* evicted.
  Eviction re-suspends the RayCluster, **deleting all its pods, head
  included**. Classic preemption (`withinClusterQueue`,
  `reclaimWithinCohort`, `borrowWithinCohort`) and Fair Sharing (stable
  since v0.7) both operate at this granularity.
  <https://kueue.sigs.k8s.io/docs/concepts/preemption/>
- **The elastic carve-out — Workload Slices.** `ElasticJobsViaWorkloadSlices`
  (beta, default-on since v0.18; supports RayJob and RayCluster):
  **scale-down releases quota in the existing Workload without suspension**;
  scale-up creates a new Workload Slice that must be admitted. Preemption
  of elastic jobs still evicts whole workloads. Limitations: no MultiKueue,
  no TAS, incompatible with PartialAdmission, scale-up must reuse the
  original flavor. <https://kueue.sigs.k8s.io/docs/concepts/elastic_workload/>
- **Ray fault tolerance is lossy.** Worker loss kills that node's
  tasks/actors/objects; tasks retry (default 3), **actors are dead by
  default** (`max_restarts=0`), `ray.put` objects are unrecoverable, owner
  failure is fatal (`OwnerDiedError`), and head failure kills the cluster
  without GCS FT (recommended only for RayService).
  <https://docs.ray.io/en/latest/ray-core/fault_tolerance/nodes.html>,
  <https://docs.ray.io/en/latest/ray-core/fault_tolerance/actors.html>,
  <https://docs.ray.io/en/latest/ray-core/fault_tolerance/objects.html>
- **KAI Scheduler** (run:ai open-sourced by NVIDIA; CNCF sandbox; native
  KubeRay integration added Oct 2025) is the one system offering pod-level
  reclaim of elastic workloads: continuous allocation/consolidation/
  reclamation across hierarchical queues, elastic jobs shrinkable down to
  a minimum pod count, protected by a MinRuntime plugin.
  <https://github.com/kai-scheduler/KAI-scheduler>,
  <https://github.com/kai-scheduler/KAI-scheduler/blob/main/docs/fairness/README.md>

**Conclusion:** no 2026 mechanism (Kueue, KAI, Volcano, KubeRay) safely
force-reclaims *busy* Ray workers. Mobula's model should be: quota +
whole-workload preemption as the floor; autoscaler v2 + Workload Slices as
the idle-reclaim fast path.

## 4. Multi-cluster capacity pool

**KubeRay cannot span clusters.** A RayCluster lives in one K8s cluster;
the federation feature request is open and unimplemented:
<https://github.com/ray-project/kuberay/issues/4561> ("Current KubeRay is
limited to single Kubernetes cluster deployment"). MultiKueue's design
(dispatch whole RayJobs to one worker cluster) reflects this constraint.

| Option | Status (mid-2026) | Batch/ML fit | "Adding a cluster's capacity" means |
|---|---|---|---|
| **Kueue MultiKueue** | **Beta since v0.9**, default on (still beta at v0.19); supports **KubeRay RayJob/RayCluster/RayService** via `managedBy: kueue.x-k8s.io/multikueue` (Kueue ≥ v0.11 + KubeRay ≥ v1.3.1); dispatch algorithms AllAtOnce (default), Incremental (beta v0.16), External | Production-real. Manager cluster holds user-facing queues; mirrors Workloads to worker clusters, delegates admission, syncs status back | Install full Kueue stack in the worker; create kubeconfig Secret + `MultiKueueCluster` in manager; append to `MultiKueueConfig.spec.clusters` |
| **Karmada** | CNCF **Incubating** (graduation application open since Mar 2025); v1.16 (Dec 2025) added multi-component workload scheduling | Placement/propagation plane, no native quota/gang/preemption; batch story is Volcano Global on top; **no verified Kueue integration** | `karmadactl join` (push) or `karmadactl register` (pull) |
| **KubeStellar** | CNCF **Sandbox**, v0.x releases | Placement/binding engine only — no queueing, quota, or gang semantics; could transport a KubeRay CR but provides no capacity-pool semantics | OCM `clusteradm join` of the cluster as a WEC into the ITS; label for BindingPolicy |
| **Armada** | Actively developed (v0.22.x, mid-2026); production at G-Research and NRP Nautilus; not CNCF | True multi-cluster batch meta-scheduler (control plane + executor per cluster over Pulsar); **no Ray/KubeRay integration found** | Deploy an Armada executor in the new cluster pointed at the control plane |

Sources: <https://kueue.sigs.k8s.io/docs/concepts/multikueue/>,
<https://kueue.sigs.k8s.io/docs/tasks/run/multikueue/kuberay/>,
<https://kueue.sigs.k8s.io/docs/tasks/manage/setup_multikueue/>,
<https://www.cncf.io/projects/karmada/>,
<https://volcano.sh/docs/keyfeatures/multiclusterscheduling/>,
<https://www.cncf.io/projects/kubestellar/>,
<https://kubestellar.io/docs/what-is-kubestellar/architecture>,
<https://armadaproject.io/understanding-armada/architecture>,
<https://armadaproject.io/user-guide/integrations>,
<https://nrp.ai/documentation/userdocs/running/scheduling>

**Verdict:** for a Ray-centric pool, MultiKueue is the only production-real
option with native KubeRay support. Armada is proven at scale but would
mean replacing (not extending) the KubeRay/Kueue stack. Karmada/KubeStellar
are placement planes without admission semantics.

## 5. GPU sub-allocation (mid-2026)

| Mechanism | How requested | How counted in Kueue quota | Isolation | Maturity |
|---|---|---|---|---|
| **NVIDIA MIG** (A100/H100/H200/B200; device plugin + GPU Operator) | Extended resource per slice: `nvidia.com/mig-1g.10gb: 1` (mixed strategy) or `nvidia.com/gpu: 1` mapped to slices (single); geometry via `nvidia.com/mig.config` node label | Plain extended resources — `nominalQuota` on `nvidia.com/mig-*` works directly; ResourceFlavor `nodeLabels` select MIG nodes; DRA-published MIG → counter-based quota (beta, Kueue v0.19) | **Hardware**: dedicated SMs, L2 slice, memory controllers, DRAM; fault isolation | GA/stable for years (K8s support since 2020); B200 profiles `1g.23gb`…`7g.180gb` |
| **HAMi vGPU** (software fractional) | `nvidia.com/gpu: 1` + `nvidia.com/gpumem: <MiB>` + `nvidia.com/gpucores: <%>` | `gpumem`/`gpucores` are extended resources, quotable; HAMi+Kueue lab demonstrates per-vGPU accounting; DRA mode exists | **Software**: HAMi-core CUDA interception enforces memory OOM cap and compute throttling; not silicon-level | CNCF **Incubating since 2026-07-02** (sandbox since 2024-08) |
| **NVIDIA time-slicing** (device plugin) | Plain `nvidia.com/gpu: 1` against oversubscribed capacity (`replicas: N`); optionally renamed `nvidia.com/gpu.shared` | Counted as `nvidia.com/gpu` — quota sees **replicas, not physical GPUs** | **None** — no memory/fault isolation; equal time-share; DCGM can't attribute metrics per container | Stable/mature feature of GPU Operator |
| **Kubernetes DRA** | `spec.resourceClaims` → ResourceClaim/ResourceClaimTemplate with CEL selectors (`resource.k8s.io/v1`); extended-resource path via DeviceClass `extendedResourceName` | Kueue DRA integration: `deviceClassMappings` (beta v0.18), extended-resource path (beta v0.19, default on), counter-based quota for MIG-like partitioned devices (beta v0.19), capacity-based for time-slicing/MPS-style sharing (alpha v0.19, needs K8s 1.36+) | None by itself — allocation API; isolation is the driver's/device's property | Core DRA **GA in K8s v1.34** (2025-08-27); NVIDIA DRA driver GPU allocation **still not officially supported** (ComputeDomains supported; GPU plugin off by default; not yet bundled in GPU Operator) |

Key sources: <https://docs.nvidia.com/datacenter/cloud-native/kubernetes/latest/index.html>,
<https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-operator-mig.html>,
<https://docs.nvidia.com/datacenter/tesla/mig-user-guide/latest/supported-mig-profiles.html>,
<https://github.com/project-hami/hami>,
<https://www.cncf.io/blog/2026/07/15/hami-becomes-a-cncf-incubating-project/>,
<https://project-hami.io/blog/hami-core-adopted-by-nvidia-kai-scheduler>,
<https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/gpu-sharing.html>,
<https://kubernetes.io/blog/2025/08/27/kubernetes-v1-34-release/>,
<https://kubernetes.io/docs/concepts/scheduling-eviction/dynamic-resource-allocation/>,
<https://github.com/kubernetes-sigs/dra-driver-nvidia-gpu>,
<https://kueue.sigs.k8s.io/v0.19/docs/concepts/dynamic_resource_allocation/>

Notes: KAI scheduler's own `gpu-fraction` annotation is cooperative (no
memory enforcement) by itself; since KAI v0.16.4 it integrates **HAMi-core
only** (`hamicore` binder + `libvgpu.so` injection). DRA scheduler-side
limitation worth noting: **no preemption for DRA resources**.

## 6. Ray's view — fractional GPUs are advisory

**Confirmed, from Ray's own docs:** "Ray resources are **logical** … mainly
used for **admission control during scheduling**"; "Resource requirements
… do NOT impose limits on actual physical resource usage… It's your
responsibility to make sure tasks or actors use no more resources than
specified." The only GPU "isolation" is `CUDA_VISIBLE_DEVICES` being set
automatically. Two `num_gpus=0.5` actors get the *same*
`CUDA_VISIBLE_DEVICES`. "It is certainly possible for the person to ignore
assigned accelerators and to use all of the accelerators on the machine."
<https://docs.ray.io/en/latest/ray-core/scheduling/resources.html>,
<https://docs.ray.io/en/latest/ray-core/scheduling/accelerators.html>

Fractional requirements >1 must be whole numbers; precision 0.0001; not
supported for TPU/Neuron/Gaudi. Fractional GPU bugs remain active in Ray
Serve (e.g. <https://github.com/ray-project/ray/issues/58328>,
<https://github.com/ray-project/ray/issues/63875>).

**The working platform-layer pattern:** give a pod a real slice — one MIG
slice exposed as one extended-resource unit, or a time-sliced GPU — and
Ray treats it as a whole GPU. KubeRay automatically advertises container
GPU limits to Ray via `ray start --num-gpus` (one pod = one GPU =
`num_gpus=1`). The documented KubeRay fractional path is KAI scheduler
GPU sharing (`gpu-fraction: "0.5"` annotation + time-slicing), and the doc
is explicit: "The scheduler doesn't enforce memory isolation, so
applications must manage their own usage."
<https://docs.ray.io/en/latest/cluster/kubernetes/user-guides/gpu.html>,
<https://docs.ray.io/en/latest/cluster/kubernetes/k8s-ecosystem/kai-scheduler.html>

Ray + MIG quirks: Ray originally undercounted MIG devices and MIG needs
UUIDs in `CUDA_VISIBLE_DEVICES` (<https://github.com/ray-project/ray/issues/12413>);
static MIG works (auto-detect at start) but **dynamic MIG reconfiguration
is an open feature request** (<https://github.com/ray-project/ray/issues/41092>)
whose stated motivation is exactly "GPU sharing with strong isolation,
instead of logical isolation which Ray current does." On K8s the UUID
problem disappears when each pod gets exactly one MIG slice — the runtime
injects the device and Ray sees one GPU.

Autoscaler v2 aggregates demands "load-by-shape" with float quantities, so
fractional `{GPU: 0.5}` shapes bin-pack correctly in the simulation —
by design; bug-free operation not independently verified.
<https://docs.ray.io/en/latest/ray-core/internals/autoscaler-v2.html>

## 7. Owner map — what Mobula should treat as authoritative

- **(a) Admission/allocation → Kueue (ClusterQueue/cohort quota, augmented
  by Mobula's own policy).** It is the only layer with tenant-aware quota,
  gang semantics, and preemption; everything below it is tenant-blind and
  everything above it is quota-blind.
- **(b) Scale-out within a cluster → Ray autoscaler v2 via KubeRay.** Only
  it sees Ray logical demand and worker idleness; Mobula should bound it
  (min/max replicas, idle timeouts) rather than replace it, and couple it
  to Kueue via Workload Slices where quota must follow.
- **(c) Node provisioning → the cluster's node autoscaler, with the Kueue
  ProvisioningRequest admission check as the contract.** CA gives GA
  admit-then-provision with gang semantics; on Karpenter, accept the
  reactive pending-pods model (oversized quota) until the CapacityBuffer
  admission check ships — do not build a custom bridge as more than a
  stopgap.
- **(d) Usage attribution → Mobula itself.** No layer below attributes
  consumption to tenants over time: Kueue quota is instantaneous
  reservation, Ray demands are logical, node autoscalers see pods. Mobula
  must meter (DCGM/pod-level usage + Ray job metadata) and reconcile
  against Kueue admission records.

## 8. Could not verify / flagged

- Whether Ray autoscaler v2 is *formally* GA — docs still carry the alpha
  banner while v2 has been the default since Ray 2.47.0.
- Any official Ray/KubeRay doc explicitly forbidding Karpenter
  consolidation with Ray — guidance is indirect (one-pod-per-node,
  do-not-disrupt/PDBs).
- Whether the ProvisioningRequest CRD `v1` has shipped in a tagged CA
  release, and whether `--enable-provisioning-requests` is still required
  in CA 1.33/1.34 (FAQ still documents the flag).
- CapacityBuffer API version drift: Karpenter v1.14.0 release notes say
  v1beta1, docs still say v1alpha1/alpha/gate-off; Kueue-side admission
  check is proposed, not merged (recheck at Kueue v0.20+).
- Cloud-provider ProvReq class availability beyond GKE (AWS/Azure) —
  not verified per provider.
- Any official Karmada↔Kueue or Armada↔Ray integration — absence found,
  not proof of non-existence.
- DRA GA badge inconsistency: K8s v1.34 release blog says core DRA GA;
  kubernetes.io page badge and a CNCF blog say v1.35. Treated as "core
  APIs GA 1.34".
- NVIDIA DRA driver release versioning (v0.4.1 claim comes from a single
  vendor blog) and GPU Operator bundling timeline ("in the future").
- KAI Scheduler's exact current version beyond v0.10.0/v0.17-era and the
  precise mechanics of pod-level reclaim for Ray workloads.
- Behavior of Kueue eviction for autoscaled RayClusters mid-scale (edge
  cases between Workload Slice replacement and Ray-side scale-down) —
  undocumented.
- No KubeRay docs page dedicated to MIG; the MIG-as-extended-resource
  pattern works via generic `nvidia.com/mig-*` + `rayStartParams` but
  lacks an official KubeRay example.
