# ADR-0002: Integrate only at stable seams; Jobs API via federating gateway

Status: accepted (2026-08-14)

## Context
Seam tiers established by adversarial review: KubeRay CRDs (v1, versioned)
and Serve HTTP ingress are stable; the Jobs REST API is convention-stable
(OpenAPI'd, API version "4", but hand-synced spec); the autoscaler
NodeProvider is @DeveloperAPI with v2 in flux; GCS/raylet protos are
internal. The dashboard job endpoints store packages and job records in GCS
internal KV and proxy to an undocumented job-agent API, so a server-side
reimplementation is unbounded.

## Decision
- Touch Ray only through: KubeRay CRDs, Serve ingress, and the Jobs REST
  API as a **federating gateway** (northbound client-compatible, southbound
  proxying each cluster's native API). One base URL per cluster (the stock
  client has no cluster-id slot).
- Autoscaling is actuated exclusively via KubeRay CRD replica fields; no
  GCS demand reading; no NodeProvider dependency until it stabilizes.
- `mobula-core` never imports a cloud SDK or Kubernetes client; backends
  live behind the `Provisioner` trait in `mobula-provision`.

## Consequences
Contract tests replay the Python `JobSubmissionClient` against the
supported Ray version matrix (two minors) in CI; version drift is a
first-class, tested concern (KubeRay's Go client history: floor ratcheted
2.0 -> 2.8 -> 2.38).
