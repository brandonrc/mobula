# ADR-0001: Orchestrate stock Ray; never rewrite or fork it

Status: accepted (2026-08-14)

## Context
A full Rust rewrite of Ray ("uv for Ray") was considered and investigated.
Ray's hot path is ~240k lines of C++; its public API is a Python-embedded
programming model (cloudpickle + Cython); ~110 internal control-plane RPCs
carry no stability statement. Decisively: Ray co-founder Ion Stoica's own
upstream `cc-to-rust` branches reached drop-in status (rebuilt `_raylet.so`,
test parity) and benchmarked at only 1.1-1.8x over the C++ - and remain
unmerged.

## Decision
Mobula orchestrates stock upstream Ray. No fork, no patched builds, no
reimplementation of Ray internals in any language.

## Consequences
All value lives in the control plane: lifecycle, identity, quotas, cost,
durable observability. Compatibility work is bounded to Ray's external
surfaces (ADR-0002).
