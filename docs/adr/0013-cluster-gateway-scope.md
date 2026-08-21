# ADR-0013: Mobula is the Cluster Gateway, and its scope stays Ray-only

Status: proposed (2026-08-21) — records the response to the Ray architecture
discussion (18 Aug 2026); awaiting explicit sign-off from Dharhas/Kim (#64)

## Context

The 18 Aug meeting recorded a preference for a generic **"Cluster Gateway"**
supporting Ray, Dask, and potentially MPI — "the fundamental problem Dask
Gateway solves is no different from what we need to solve" — motivated by
existing Dask commitments (NASA, SMSU) and the wish to build the launcher
once. This ADR proposes the narrower answer and is deliberately the place
to disagree before more surface accretes.

Facts that shape the decision:

- The substrate is KubeRay CRDs and Kueue (ADR-0002, ADR-0010). That
  coupling is what makes the v0 provisioner a thin translation instead of
  an orchestration engine. A Dask backend reuses none of it: `DaskCluster`
  CRDs, a different scheduler/worker topology, and the `distributed`
  client protocol rather than the Ray Jobs API. MPI is a third shape.
- Dask Gateway upstream is in maintenance mode: last substantive release
  2026.3.1; commits since are Dependabot/pre-commit only. Parity with it
  is a shrinking target; if Dask support ever lands here, the realistic
  goal is a migration path off Dask Gateway, not feature parity.
- `nebari-dev/dask-gateway-pack` exists today and is the answer for the
  NASA/SMSU Dask commitments in the meantime.
- A `framework` discriminant with exactly one implementation is
  speculative generality: a variant split across `ClusterSpec`, the
  provisioner traits, the store schema, the OpenAPI contract, and the UI,
  buying nothing testable.

## Decision

Mobula's product scope is Ray. No Dask backend, no MPI backend, no
`framework` enum, no abstraction refactor in anticipation of either.

**What we commit to in exchange — neutrality where it is free:**

- `Provisioner` / `ServiceProvisioner` trait signatures stay free of
  Ray-specific types (already true; keep it true).
- No `ray_` prefix on new API fields unless the field genuinely is
  Ray-specific (`ray_version` is; a scale request is not).
- `mobula-core` domain naming stays framework-neutral where it costs
  nothing (`ClusterSpec`, `WorkerGroup`, `ResourcePool` already are).
- The self-service option-schema (#74), pod-shaping catalog (#66),
  credential tiers (#73 doc), budgets (#77), and environment recipes
  (#79) are all framework-agnostic *designs* — the general "cluster
  gateway problem" is being solved; only the provisioner binding is
  Ray-only. A future Dask decision inherits the whole policy plane and
  writes one provisioner + one client-protocol gateway.

## Consequences

- The Dask answer for current clients remains `dask-gateway-pack`; we do
  not validate against Dask in this cycle.
- Deployment target for this cycle is **local** (`scripts/dev-stack.sh`);
  packaging maturity stays parked (epic #55, milestone M5).
- If a funded Dask or MPI requirement lands, the revisit path is a new
  ADR proposing a second provisioner — not a reopening of this one's
  naming and trait commitments, which are designed to make that ADR small.

## Rollout

- [ ] REQUIREMENTS.md §1.2 notes the Ray-only constraint
- [ ] PLAN.md decision record links this ADR
- [ ] README scope sentence states Ray-only explicitly
