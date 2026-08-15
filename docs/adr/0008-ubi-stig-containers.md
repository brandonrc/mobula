# ADR-0008: UBI-only, STIG-postured container images

Status: accepted (2026-08-15)

## Context
Deployment targets include DISA-regulated environments. Container images
must use Red Hat UBI bases, carry minimal tooling, and survive hardened-
registry substitution (Iron Bank registry1 mirrors).

## Decision
- **UBI only, multi-stage:** builder is `ubi9/ubi` with a pinned rustup
  toolchain (build-time only); runtime is `ubi9/ubi-micro` - no package
  manager, no added tools, just glibc and the stripped `mobula` binary.
- Base registry and image names are Dockerfile `ARG`s so Iron Bank or
  other hardened mirrors substitute without edits.
- **Numeric non-root `USER 1001`** so `runAsNonRoot` admission can verify
  identity; `/licenses/LICENSE` and Red Hat-style labels included.
- **Trivy gate in CI:** CRITICAL/HIGH (fixed) vulnerabilities block the
  multi-arch manifest from publishing.
- Chart defaults (mobula-pack) run with the K8s restricted profile:
  `runAsNonRoot`, `allowPrivilegeEscalation: false`, all capabilities
  dropped, read-only root filesystem, RuntimeDefault seccomp.

## Consequences
Image is ~41MB and shell-less debugging applies (use ephemeral debug
containers). **Open item - FIPS:** the rustls default crypto provider is
not FIPS-validated; DISA environments requiring FIPS 140-3 need the
aws-lc-rs FIPS provider wired into reqwest/tokio-tungstenite before any
accreditation claim. Tracked for Phase 2 (it must land with identity).
