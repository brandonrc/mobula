# Is Ray still the right substrate? (2026-08 landscape research)

Research question: for distributed GPU job running (batch training, RL
post-training, serving), is Ray the best data-plane substrate for Mobula to
build its control plane on — or is there a better foundation we should be
building up from?

Scope note: this revisits the *substrate* bet, one level below the decisions
already recorded in [ADR-0001](../adr/0001-no-ray-rewrite.md) (orchestrate
stock Ray) and [ADR-0002](../adr/0002-stable-seams-and-job-gateway.md)
(integrate only at stable seams). The scheduling-theory literature audit
lives in [READING.md](../READING.md); this doc covers the 2025–2026 systems
landscape and the GPU-sharing paper cluster.

Method: three parallel research sweeps on 2026-08-14 (Ray project health,
alternatives landscape, verification of five suggested papers). GitHub
stats are point-in-time from that date.

---

## TL;DR — recommendation

**Stay on Ray. No course change.** The evidence since our ADRs were written
has strengthened, not weakened, the bet:

1. **Governance risk collapsed.** Anyscale donated Ray to the PyTorch
   Foundation (2025-10-22), putting it under neutral Linux Foundation
   governance alongside PyTorch and vLLM. When Nscale then agreed to acquire
   Anyscale (~$1.65B, 2026-07-30), Ray itself was already out of reach —
   the acquisition concentrates risk in Anyscale's *proprietary control
   plane*, which is exactly the layer Mobula replaces. Analyst commentary
   ("Ray is open source; the control plane above it isn't") is literally
   Mobula's thesis.
2. **No credible alternative unifies what Ray unifies.** Nothing else in
   FOSS covers interactive clusters + batch training + data + RL + serving
   on one runtime. The closest alternative stack (Kubeflow Trainer v2 +
   Kueue + JobSet, with KServe/llm-d for serving) is batch-only and would
   leave Mobula orchestrating two or three disjoint CRD families.
3. **Adoption momentum is toward Ray, not away.** 237M+ downloads; Discord,
   Uber, Spotify, Pinterest, Amazon (exabyte Spark→Ray migration), OpenAI;
   the LLM RL post-training ecosystem (verl, OpenRLHF) has standardized on
   Ray. No public migrate-away case study was found.
4. **Ray's real weaknesses are Mobula's product surface.** Single static
   token with no per-user identity, no safe multi-tenancy inside a cluster,
   advisory-only fractional GPUs, unrecoverable owner death — each maps to
   a control-plane feature we already have in REQUIREMENTS.md (identity
   proxy, cluster-per-tenant isolation, platform-layer GPU sharing,
   job-level retry above Ray). If Ray fixed all of these, Mobula would have
   *less* reason to exist.

Two honest hedges, both watch-items rather than course changes:

- **PyTorch Monarch** (Meta, announced 2025-10-22, same foundation as Ray)
  is the first serious post-Ray programming model: single-controller,
  Python frontend on a **Rust** backend, K8s CRD (`MonarchMesh`) landed
  2026. It is pre-1.0, training-only, with no serving/multi-tenancy story —
  not a substrate today, but Mobula's job abstraction should stay
  substrate-agnostic enough to add a Monarch backend in 2–3 years the same
  way a Kubeflow TrainJob backend could be added.
- **LLM serving's center of gravity is drifting K8s-native** (llm-d in CNCF
  sandbox 2026-03, NVIDIA Dynamo 1.0 2026-03, KServe's LLMInferenceService
  now built *on* llm-d). Ray Serve remains right for multi-model Python
  composition and train+serve unification, but Mobula's serving abstraction
  should not assume Ray Serve forever — the alternatives share the Envoy
  Gateway substrate Nebari already runs.

---

## 1. Ray project health (as of 2026-08)

| Signal | Evidence |
|---|---|
| Governance | Donated to PyTorch Foundation 2025-10-22 — neutral governance, alongside PyTorch/vLLM/DeepSpeed ([announcement](https://pytorch.org/blog/pytorch-foundation-welcomes-ray-to-deliver-a-unified-open-source-ai-compute-stack/)) |
| Commercial | Nscale to acquire Anyscale ~$1.65B (2026-07-30); Ray governance unaffected (pre-donated); risk concentrated in the proprietary Anyscale platform ([TechCrunch](https://techcrunch.com/2026/07/30/nscale-buys-anyscale-as-it-seeks-to-own-more-of-the-ai-compute-stack/), [vendor-risk analysis](https://www.beri.net/article/nscale-anyscale-acquisition-ray-commercial-platform-vendor-risk)) |
| Cadence | ~monthly minors; 2.57.0 current; `3.0.0.dev0` branch exists (watch for breaking changes); 2.57 adds embedded-RocksDB GCS fault tolerance, removing the external-Redis HA dependency ([releases](https://github.com/ray-project/ray/releases)) |
| Auth | Ray ≥ 2.52 ships built-in token auth (single static cluster token; off by default — disputed CVE-2025-34351 pressures a default-on future) ([docs](https://docs.ray.io/en/latest/ray-security/token-auth.html)) |
| KubeRay | v1.5 (2025-12): token auth, RayService incremental upgrades, RayJob sidecar submission, Kueue + KAI integration; load-tested to 10,000 pods / 100 clusters; contributors incl. Google, Alibaba, NVIDIA, Roblox, Bloomberg. v1.6 adds alpha Ray History Server. Not a CNCF project — lives under ray-project / PyTorch Foundation umbrella ([v1.5](https://www.anyscale.com/blog/kuberay-v1-5)) |
| Performance track | Compiled Graphs (beta, ~50µs dispatch, used by vLLM); **Ray Direct Transport** (alpha, 2025-11): native RDMA/NCCL/NIXL, GPU objects stay in GPU memory ([RDT](https://www.anyscale.com/blog/ray-direct-transport-rdma-support-in-ray-core)) |
| Autoscaler | v2 is default on KubeRay since Ray 2.48 — consistent with our D2 stance of actuating via CRD fields only |
| Adoption | Uber Michelangelo (20k models/month trained), Discord (InfoQ 2025-12), Spotify, Pinterest, Ant Group, Amazon Spark→Ray at exabyte scale, OpenAI; verl (ByteDance) and OpenRLHF make Ray near-mandatory in LLM RL post-training. No public migrations away found. |

Telling detail: Discord, Pinterest, and Spotify **each built an in-house Ray
control plane** (templating, lifecycle, log/metric centralization, custom
UI) to make Ray tolerable at org scale. That is independent confirmation of
demand for the exact product Mobula is.

## 2. Ray's known weaknesses — and where they're handled

These are real, confirmed, and none of them argues for a different
substrate; each is either at Mobula's layer (fixable by us) or below the
isolation boundary (fixable by K8s-layer tooling).

| Weakness | Evidence | Mobula's answer |
|---|---|---|
| No per-user identity — one static, non-expiring cluster token | Ray ≥ 2.52 token auth docs | The identity-aware proxy / token-exchange in REQUIREMENTS §3.6 is the core differentiator |
| Actively exploited when exposed | ShadowRay (CVE-2023-48022, "won't fix by design"); **ShadowRay 2.0** (2025-11): self-propagating botnet over exposed Ray clusters, 200k+ internet-exposed servers ([Oligo](https://www.oligo.security/blog/shadowray-2-0-attackers-turn-ai-against-itself-in-global-campaign-that-hijacks-ai-into-self-propagating-botnet)); CVE-2025-62593 (CVSS 9.4, DNS-rebinding RCE, fixed 2.52) | Never expose a Ray endpoint directly; enforce token auth ≥ 2.52 + NetworkPolicy; every surface behind the proxy |
| No multi-tenancy inside a cluster (no isolation, no priorities, any job has full cluster access) | [Ray FAQ](https://docs.ray.io/en/latest/cluster/faq.html) | Already a non-goal: isolation boundary = cluster; cluster-per-tenant/per-job |
| Fractional GPUs are advisory bookkeeping, zero enforcement | [Ray resources docs](https://docs.ray.io/en/latest/ray-core/scheduling/resources.html) | GPU sharing belongs at the platform layer (MIG / HAMi / KAI) *under* Ray — see §4. Never sell Ray fractional GPUs as tenant isolation |
| Owner death is unrecoverable (`OwnerDiedError`); no transparent checkpoint/migration of running work | [Ownership fault-tolerance docs](https://docs.ray.io/en/latest/ray-core/fault_tolerance/objects.html) | Already encoded in REQUIREMENTS §3.2 spot policy; job-level retry/checkpoint conventions above Ray, not object lineage |
| Head-node memory growth on long-lived clusters | [Ray head-node memory docs](https://docs.ray.io/en/latest/ray-core/head-node-memory-management.html) | Idle reaping + suspend/resume (§3.1) favor shorter-lived clusters; 2.57 RocksDB GCS improves head FT |

## 3. Alternatives landscape

By layer, with the composes/competes verdict. Only the first row is a
genuine substrate alternative.

| Option | Layer | Verdict for Mobula |
|---|---|---|
| **Kubeflow Trainer v2 + Kueue + JobSet** (v2.2 2026-03; CNCF) | Training-job operator on K8s primitives | The only fully credible FOSS alternative — but batch-only: no interactive clusters, no Python distributed runtime (Data/Tune/RLlib), serving is a separate stack. Would trade one substrate for 2–3 disjoint CRD families |
| **PyTorch Monarch** (Meta, 2025-10; pre-1.0) | Single-controller distributed runtime, Rust backend, `MonarchMesh` CRD | The credible *future* alternative; training-only, no serving/tenancy today. Watch; keep job API substrate-agnostic. Same foundation as Ray — InfoQ frames them as complementary |
| **SkyPilot** (v0.13, $20M seed 2026-07) | Multi-cloud provisioning/launcher *above* clusters | Competitor for UX mindshare, not a substrate — and it uses Ray internally as its executor, which is an endorsement |
| **Dask** (+ dask-kubernetes, 324★, sparse) | Python task scheduler | Plateaued at this layer; no DL-training or serving story. Not an alternative |
| **Spark + RAPIDS** | Data engine | ETL acceleration, wrong shape for DL train/serve. A future *hosted workload*, not a substrate |
| **JAX / xpk / Pathways** | Compiler/programming model | A framework to host (KubeRay or TrainJob runs it), Google-cloud gravity. Not a substrate |
| **Flyte 2** (GA 2026-08) / **Metaflow** | Workflow/DAG orchestration | Compose *above* Mobula (both have Ray plugins). Note Flyte 1 is security-fixes-only through 2026 — their community is mid-migration |
| **Volcano** (v1.15, CNCF incubating) | Pod-level batch scheduler | Composes: KubeRay ≥ 1.5.1 supports Volcano gang + topology-aware scheduling. Optional placement engine under Kueue |
| **NVIDIA KAI Scheduler** (open-sourced Run:ai, CNCF sandbox; v0.16.4 merged HAMi-core for hard fractional-GPU isolation) | Pod scheduler + fractional GPU | Composes: auto-detects Ray CRDs for gang scheduling. Strongest emerging option for the *scheduler slot*; single-vendor governance risk |
| **Apache YuniKorn** | Pod scheduler | Big-data multi-tenancy DNA, no first-class KubeRay story. Not preferred |
| **Armada** (CNCF sandbox) | Multi-K8s-cluster batch federation | Niche; only relevant if Mobula ever federates many K8s clusters |
| **Slurm / Slinky (SchedMD→NVIDIA)** | HPC scheduler, now with K8s CRDs | The non-K8s counterfactual; wrong fit for Nebari's K8s-native, multi-tenant, OIDC world |
| **Modal** ($4.65B valuation 2026-05) | Proprietary serverless GPU | Closed; useful only as the UX bar for "submit Python, get GPUs" |

Design consequence worth keeping: **the scheduler slot should be pluggable.**
Kueue stays the quota/admission API (vendor-neutral kubernetes-sigs, first-
class RayJob support — already our D-level choice), with Volcano or KAI as
optional placement engines underneath. Kueue's Elastic Workload Slices are
still alpha-grade in practice (quota-leak fixes as recent as v0.18/v0.19) —
consistent with REQUIREMENTS §3.2's caution about autoscaling escaping
Kueue accounting.

Serving-specific: llm-d (CNCF sandbox 2026-03, Red Hat/Google/IBM),
NVIDIA Dynamo 1.0 + Grove, and KServe's llm-d-based `LLMInferenceService`
form a K8s-native LLM-inference lane with more 2026 momentum than Ray Serve
for *pure* LLM serving. Ray Serve LLM (vLLM engine underneath) reached
parity-class performance in 2025–26 and stays the right default where
serving mixes classic ML + LLM or shares a substrate with training. Treat
"Ray Serve vs vLLM" as a category error — Serve orchestrates engines.

## 4. Kubernetes DRA and platform-layer GPU sharing

- **DRA went GA in K8s 1.34 (2025-09).** Structured device claims replace
  the count-based device-plugin model over the next couple of years. HAMi,
  Kueue, and YuniKorn all have DRA adaptation on 2026 roadmaps. Mobula
  should not hard-code the device-plugin count model in the Provisioner
  trait's resource shapes.
- **HAMi** (CNCF incubating 2026-07): software fractional-GPU with hard
  memory/core isolation; HAMi-core is now embedded in NVIDIA's KAI
  scheduler; DaoCloud runs it on 10k+ GPUs. CNCF's own guidance (2026-08):
  DRA and HAMi are complementary — DRA is the request API, HAMi the
  isolation layer.
- **MIG** is the hard-partition option (A100/H100/B200 class only); Ray
  sees MIG instances only statically at `ray start`
  ([ray#41092](https://github.com/ray-project/ray/issues/41092)) — so the
  working pattern is: platform carves slices, each Ray worker pod receives
  one slice as "1 GPU." **MPS** has no memory isolation and one fatal
  client kills all; **time-slicing** has no isolation at all — dev tiers
  only.

Conclusion: GPU sharing is a *platform-layer feature tier under Ray*, not
an argument against Ray. This slots into REQUIREMENTS §3.2's "GPU
fractional awareness passthrough" — the passthrough should eventually name
MIG/HAMi/KAI flavors, surfaced as Kueue resource flavors.

## 5. The suggested papers, verified

Corrections first: GPUnion is now peer-reviewed (HotNets '25, not just
arXiv); GPUPool is **PACT 2022**, not ACM 2025; the NSDI '25 system is
named **Prism** (Alibaba + HKUST); the edge study is ETRI Journal (Wiley);
**"MMK" could not be found at all** and needs re-sourcing.

| Paper | What it is | Layer / relevance to Mobula |
|---|---|---|
| **GPUnion** — Li et al., HKUST(GZ), HotNets '25 ([arXiv:2507.18928](https://arxiv.org/abs/2507.18928), [ACM](https://dl.acm.org/doi/10.1145/3772356.3772403)) | Campus-scale volunteer GPU sharing; providers can reclaim hardware anytime; containerized dispatch + automatic checkpoint/migration (94% successful migration on provider departure) | **Same layer as Mobula** — the one directly comparable system. Provider-autonomy is irrelevant to enterprise clusters, but it treats transparent checkpoint/migration as a *control-plane* responsibility — the strongest pointer at a capability worth adding above stock Ray (CRIU/CRIUgpu container checkpointing, or checkpoint conventions + KubeRay resubmission) for spot capacity and Kueue preemption |
| **"MMK" (2026)** — **not found** | Searched web, dblp, arXiv API, ACM DL, citation trails — no such paper. Closest real matches: [HAS-GPU](https://arxiv.org/abs/2505.01968) (Euro-Par '25), [STAO](https://www.sciencedirect.com/science/article/abs/pii/S0167739X26003687) (FGCS '26), [HuntKTm](https://dl.acm.org/doi/10.1145/3774652) (TACO), [gShare](https://dl.acm.org/doi/abs/10.1145/3779212.3790168) (ASPLOS '26) | Every candidate is intra-GPU / kernel-partition scheduling — below our isolation boundary. Control-plane translation is "MIG/MPS/HAMi + placement policy," nothing that touches Ray |
| **GPUPool** — Tan et al., U Toronto, **PACT '22** ([ACM](https://dl.acm.org/doi/10.1145/3559009.3569650)) | GBDT-predicted kernel-slowdown under co-execution; job pairing as maximum-cardinality matching; 21–31% fewer GPUs — but targets *simulated next-gen* hardware sharing, not shipping GPUs | Kernel-level, below our layer, simulation-based. Motivation/ceiling analysis for interference-aware placement; the deployable equivalents are MIG/MPS/HAMi under K8s |
| **Prism** — Yang et al., Alibaba + HKUST, **NSDI '25** ([usenix](https://www.usenix.org/conference/nsdi25/presentation/yang)) | Production GPU-disaggregated DLRM serving: auto-partitions model graphs into CPU/GPU subgraphs over RDMA pools; −53%/−27% CPU/GPU fragmentation; 2+ years on 10k+ GPUs | Mechanism lives *inside the serving runtime* — out of scope by our non-goals. The transferable diagnosis: fixed CPU:GPU node ratios strand GPUs → independently-sized heterogeneous KubeRay worker groups (CPU-only + GPU groups) and Kueue cohort borrowing are the control-plane analog. Ray's ecosystem is moving the same direction at app level (prefill/decode disaggregation in vLLM/Ray Serve) |
| **Edge GPU sharing** — Woo et al., ETRI Journal 47(5) 2025 ([Wiley](https://onlinelibrary.wiley.com/doi/10.4218/etrij.2025-0065)) | Threading (shared CUDA context) vs multiprocessing for concurrent YOLOv8 on Jetson AGX Orin | **Low relevance** — single edge device, no cluster/scheduler; Jetson lacks MIG. Only takeaway: "GPU sharing" claims are hardware-dependent. Safe to deprioritize |

Cross-cutting: the papers collectively point at three capabilities stock Ray
lacks — transparent checkpoint/migration (GPUnion), interference-aware
fine-grained sharing (GPUPool et al.), CPU/GPU disaggregation (Prism). All
three are addressable at or below Mobula's layer without violating
ADR-0001; none argues for a different substrate.

## 6. Watch list

Revisit this document if any of these move:

1. **PyTorch Monarch** hits 1.0 / grows a serving or tenancy story, or
   `MonarchMesh` sees real multi-org adoption → consider a second
   Provisioner-style backend for the job API.
2. **Nscale's stewardship** of Anyscale's OSS engineering after the deal
   closes (H2 2026+) — a Ray contribution slowdown would raise maintenance
   risk on the seams we depend on.
3. **Ray 3.0** scope (a `3.0.0.dev0` branch exists) — breaking changes to
   the Jobs REST surface or KubeRay CRDs would hit our contract tests
   first; that's the alarm working as designed (ADR-0002).
4. **Token auth default-on** in Ray (CVE-2025-34351 pressure) — simplifies
   our provisioning path slightly; no design change.
5. **Kueue Elastic Workload Slices** reaching beta/GA — closes the
   autoscaling-escapes-quota gap noted in REQUIREMENTS §3.2.
6. **DRA-native GPU requests** in KubeRay/Kueue/HAMi — when that lands,
   the Provisioner trait's resource model should speak DRA claims.
7. **llm-d / Dynamo consolidation** — if Nebari users demand pure LLM
   serving at scale, a non-Ray serving backend behind the same Mobula
   surface becomes worth an ADR.

## 7. Bottom line

The radical options (new substrate, custom scheduler, Ray fork) remain
wrong, and the boring option is well-supported: **KubeRay + Kueue + stock
Ray, exactly as decided in ADR-0001/0002**. What this research adds is not
a course change but three refinements to carry into later phases:
keep the scheduler slot pluggable (Volcano/KAI under Kueue), keep the job
and serving abstractions substrate-agnostic enough to add Monarch or llm-d
backends later, and treat platform-layer GPU sharing (MIG/HAMi/KAI, DRA)
plus checkpoint-based preemption tolerance as the two genuinely new
capability tiers the literature argues for.
