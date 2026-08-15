# ADR-0005: Apache-2.0

Status: accepted (2026-08-14)

## Context
MIT was the initial preference. Every active NIC-era nebari-dev repo is
Apache-2.0, and the project is likely to transfer there. Relicensing after
external contributions requires contributor consent.

## Decision
Apache-2.0 from the first commit line of code. Copyright line and final
org placement to be confirmed with OpenTeams.

## Consequences
Explicit patent grant; org transfer needs no relicensing; dependencies are
vetted by cargo-deny against a permissive-only allowlist.
