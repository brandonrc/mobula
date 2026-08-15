# Mobula

**A FOSS, Anyscale-grade control plane for Ray clusters** — Rust backend for
dynamic resource management, with cloud-agnostic SSO/RBAC. Named for the devil
ray genus *Mobula*, which schools in the thousands.

Mobula composes with, rather than competes against, the open Ray stack:
[KubeRay](https://github.com/ray-project/kuberay) is the Kubernetes substrate,
[Kueue](https://kueue.sigs.k8s.io/) handles admission where present, and the
primary deployment target is a [Nebari](https://nebari.dev) software pack on a
full Nebari Infrastructure Core (NIC) deployment — Keycloak SSO, Envoy Gateway
ingress, and `NebariApp`-driven OIDC client provisioning come from the platform.
A standalone mode (any OIDC IdP, any Kubernetes) keeps it useful outside Nebari.

Status: **Phase 0 — scaffolding**. See [REQUIREMENTS.md](REQUIREMENTS.md),
[PLAN.md](PLAN.md), and [docs/adr/](docs/adr/) for decisions and their evidence.

## Quickstart (dev)

```bash
cargo run -p mobula-cli -- serve   # API on 127.0.0.1:8484
curl localhost:8484/healthz
curl localhost:8484/api/v1/version
```

Workspace layout: `mobula-core` (domain model, no cloud/K8s deps) ·
`mobula-provision` (Provisioner trait; KubeRay backend first) · `mobula-api`
(HTTP surface + future Jobs gateway) · `mobula-proxy` (standalone-mode
identity proxy) · `mobula-cli` (the `mobula` binary).

License: [Apache-2.0](LICENSE) — matching the nebari-dev org convention.

Ray is a registered trademark of LF Projects, LLC. Mobula is an independent
project and is not affiliated with or endorsed by LF Projects or Anyscale.
