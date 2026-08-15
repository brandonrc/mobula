//! Identity-aware proxy (Phase 2).
//!
//! Two enforcement paths, decided in ADR-0003:
//! - Nebari mode: Envoy `ext_authz` calls a stateless authz endpoint served
//!   by `mobula-api`; no second proxy hop in the Serve data path.
//! - Standalone mode: this crate is the inline proxy, deployed separately
//!   from the control plane so control-plane deploys can't interrupt
//!   inference traffic.
//!
//! The core exchange in both paths: Mobula holds each cluster's static Ray
//! token (Ray >= 2.52) and brokers per-user, SSO-authenticated,
//! RBAC-checked access on top of it.
