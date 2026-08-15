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

Status: **pre-design**. See [REQUIREMENTS.md](REQUIREMENTS.md).

License: [Apache-2.0](LICENSE) — matching the nebari-dev org convention.

Ray is a registered trademark of LF Projects, LLC. Mobula is an independent
project and is not affiliated with or endorsed by LF Projects or Anyscale.
