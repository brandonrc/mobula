# ADR-0003: Mobula owns bearer identity in both modes; ext_authz in Nebari mode

Status: accepted (2026-08-14)

## Context
NebariApp's SecurityPolicy auth is redirect-OIDC with cookie sessions -
browser-only. Bearer/CLI/device-flow clients would receive HTML redirects.
Ray >= 2.52 ships token auth, but it is a single static, non-expiring,
cluster-wide secret with no per-user identity.

## Decision
- Mobula owns JWT validation, CLI device-code flow, and service-account
  tokens in BOTH Nebari-native and standalone modes. Nebari mode
  contributes browser SSO brokering, Keycloak client provisioning,
  ingress, and TLS only.
- Serve/dashboard RBAC in Nebari mode is enforced via Envoy `ext_authz`
  calling a stateless Mobula authz endpoint - never a second inline proxy
  in the data path. The inline `mobula-proxy` is the standalone-mode path
  and deploys separately from the control plane.
- Core exchange: Mobula holds each cluster's static Ray token and brokers
  per-user, SSO-authenticated, RBAC-checked access on top of it.

## Consequences
The Mobula API's own NebariApp sets `auth.enabled: false`; bearer auth is
enforced in-process. Wildcard DNS/cert strategy is a prerequisite for
dynamically stamped per-cluster surfaces; a sweep reconciler cleans
orphaned Keycloak clients.
