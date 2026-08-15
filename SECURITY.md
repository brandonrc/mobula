# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for suspected vulnerabilities.
Use GitHub's private vulnerability reporting on this repository
("Security" tab → "Report a vulnerability"), or contact the maintainer
directly. You should receive an acknowledgement within 72 hours.

## Scope notes

- Mobula proxies Ray's Jobs API with injected cluster credentials; the
  gateway and registry code paths (`crates/mobula-api/src/gateway.rs`,
  `crates/mobula-core/src/registry.rs`) are the most security-sensitive
  surfaces.
- Until Phase 2 (identity) ships, the gateway performs no caller
  authentication and refuses non-loopback binds without an explicit
  `--dev-allow-unauthenticated` override. Do not expose it beyond
  localhost or a trusted network.

## Supported versions

Pre-1.0: only the latest release is supported.
