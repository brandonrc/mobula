# GPU sharing and tenant isolation

Mobula capacity pools (ADR-0010) are shared by multiple projects. How a
pool's GPUs are *subdivided* determines whether that sharing is safe — so
the policy engine encodes the rule rather than trusting pool/cluster
authors to get it right.

## Threat model

Three ways to share a GPU, two of them isolation-safe:

- **Time-slicing** (NVIDIA device-plugin `replicas > 1`, and equivalently
  **fractional `nvidia.com/gpu` requests**): processes from different
  workloads are co-scheduled on the same SMs with no hardware isolation.
  Co-resident tenants share L2 cache, DRAM bandwidth, and the same failure
  domain, and can observe or starve one another (side channels on shared
  SM/cache state are documented in the literature). Acceptable *within*
  one tenant that trusts its own workloads; not across tenants.
- **MIG** (Multi-Instance GPU): hardware partitioning — each slice gets
  dedicated SMs, memory, and L2. Isolation-safe; slices appear as separate
  resources (`nvidia.com/mig-1g.10gb`, …) and quota like any extended
  resource key.
- **Whole-GPU**: one workload per device. Nothing shared.

The failure mode this prevents is silent: a pool admin enables
time-slicing (or a cluster requests `gpu: "0.5"`) on a pool that already
serves two projects, and cross-tenant SM sharing appears with no error
anywhere. Admission-time validation makes the misconfiguration loud.

## Policy semantics

Two knobs, one rule:

- **Per-pool**: `gpu_sharing` on the pool spec — `"whole-gpu"` (default),
  `"mig"`, or `"time-slice"`.
- **Platform default**: `[gpu] default_sharing` in the `--policy` TOML,
  applied when a pool spec leaves `gpu_sharing` unset; itself defaults to
  `"whole-gpu"`. Boot-time only (not editable via
  `PUT /api/v1/settings/policy`, unlike prices/quotas).

The rule, enforced at admission (`PUT /api/v1/pools/{name}/allocations/…`
and `POST /api/v1/clusters`, both 400 with a `tenant isolation: …`
message and a `gpu_tenant_isolation` audit denial):

| Pool tenancy | `whole-gpu` / `mig` | `time-slice` | Fractional GPU request |
| --- | --- | --- | --- |
| 0–1 projects | allowed | allowed (explicit opt-in) | allowed |
| ≥2 projects | allowed | **rejected** | **rejected** |

Tenancy = the pool's allocations (one per project). A project with no pool
allocation is queue-free and unchecked. Clusters are additionally refused
admission into any multi-tenant pool that somehow already resolves to
`time-slice` (e.g. rows predating the rule) — fail closed.

MIG slice quotas are just extended resource keys (`nvidia.com/mig-1g.10gb`)
on flavors and quotas — no special casing anywhere, per ADR-0010's
arbitrary-key model.

## Example

```toml
# policy.toml — platform default for pools that don't say otherwise.
[gpu]
default_sharing = "whole-gpu"
```

```jsonc
// POST /api/v1/pools — a multi-tenant pool serving MIG slices.
{ "spec": {
    "name": "gpu-pool", "cohort": "main",
    "fair_sharing_weight": 1.0, "elastic": true,
    "gpu_sharing": "mig",
    "flavors": [
      { "name": "a100", "resources": {"nvidia.com/gpu": "8", ...}, ... },
      { "name": "mig-slice",
        "resources": {"nvidia.com/mig-1g.10gb": "14", ...},
        "node_labels": {"nvidia.com/mig.strategy": "mixed"}, ... }
    ] } }

// A single-tenant pool may opt into time-slicing explicitly.
{ "spec": { "name": "dev-pool", "gpu_sharing": "time-slice", ... } }
// …but the second allocation on it is rejected:
// PUT /api/v1/pools/dev-pool/allocations/proj-b → 400
// "tenant isolation: pool \"dev-pool\" is shared by 2 projects, so
//  gpu_sharing = \"time-slice\" is forbidden …"
```

Implementation: the rule lives in `mobula_policy::gpu`
(`check_pool_gpu_isolation`, `check_cluster_gpu_isolation`); the knob type
is `mobula_core::GpuSharing`; enforcement is wired into
`mobula-api/src/pools.rs` (allocation writes) and
`mobula-api/src/clusters.rs` (cluster creates).
