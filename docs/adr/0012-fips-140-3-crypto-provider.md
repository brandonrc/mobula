# ADR-0012: FIPS 140-3 crypto option — rustls on aws-lc-rs, fail-closed startup

Status: accepted (2026-08-17)

## Context
Security issue #61: some deployments (federal, regulated) require TLS
cryptography from a FIPS 140-3 validated module. Mobula's TLS stack is
rustls everywhere — reqwest (OIDC discovery, gateway proxying), kube-rs
(Kubernetes API), sqlx (Postgres) — defaulting to the pure-Rust `ring`
provider (ADR-0008's no-C-toolchain posture for UBI9/STIG-minimal images).
rustls 0.23 supports the aws-lc-rs provider, whose `fips` feature builds
the FIPS-validated AWS-LC module. The switch must not change the default
build: `ring` stays the default and aws-lc-rs must not appear in a default
dependency tree.

## Decision
- **A `fips` cargo feature** (off by default everywhere) selects the crypto
  provider. `mobula-core/fips` pulls `rustls` with its `fips` feature
  (aws-lc-rs + FIPS module); cargo feature unification puts the single
  workspace rustls build on it. `mobula-provision/fips` and
  `mobula-controller/fips` forward it; `mobula-cli/fips` is the user-facing
  entry point.
- **Fail-closed startup**: `mobula_core::crypto::enforce_fips_startup()`
  (compiled only under `fips`) is called at the top of the `mobula` binary
  before any TLS is initialized. It installs the aws-lc-rs provider as
  rustls' process default, then verifies the *active* provider reports FIPS
  mode — `CryptoProvider::fips()` is a runtime check
  (`aws_lc_rs::try_fips_mode()`), covering the module's power-on
  self-tests — and **panics, aborting startup, otherwise**. The
  verdict logic (`FipsStatus::enforce`) is pure and unit-tested without the
  FIPS module build.
- **sqlx needed explicit handling**: it pins its rustls provider at compile
  time (`sqlx-core/src/net/tls/tls_rustls.rs`), and `runtime-tokio-rustls`
  always selects `ring`. mobula-controller now selects the provider via
  features — `tls-ring` (default) or `tls-aws-lc-rs` — and, because cargo
  features are additive and cannot remove `tls-ring`, **a FIPS build is
  `--no-default-features --features "fips,postgres"`** on `mobula-cli`
  (dependency edges are `default-features = false` with the old defaults
  forwarded explicitly, so the default build resolves exactly as before).
- **Scope**: FIPS mode covers TLS in motion only. At-rest encryption is a
  separate concern (issue #60). OIDC token signatures, bcrypt password
  hashing (ADR-0011), and the audit hash chain (#59) use their own
  non-aws-lc-rs implementations and are not FIPS-covered. `ring` remains
  linked in FIPS builds (reqwest/mobula-provision still request it) but is
  never the active provider — startup fails closed if it somehow is.

## Build & verify
```
# default (unchanged): ring, no aws-lc-rs in the tree
cargo build --release -p mobula-cli
cargo tree -p mobula-cli -e no-dev | grep aws-lc   # -> no matches

# FIPS build: needs cmake, perl, and Go (aws-lc-rs FIPS module compiles
# from C). The Dockerfile has an opt-in path for this:
docker build --build-arg FIPS=true .
cargo build --release -p mobula-cli --no-default-features --features "fips,postgres"
mobula serve ...   # logs "FIPS 140-3 mode: rustls on the aws-lc-rs
                   # FIPS-validated crypto provider"; aborts on startup if
                   # the active provider is not FIPS
```
(macOS local dev only: aws-lc-fips-sys builds shared libraries without an
rpath, so run the binary with
`DYLD_FALLBACK_LIBRARY_PATH=target/debug/build/aws-lc-fips-sys-*/out/build/artifacts`
or via `cargo run`. Linux/container builds are unaffected.)

## Consequences
- Default images/builds are untouched: same deps, same behavior, no C
  toolchain.
- FIPS images are heavier (cmake/perl/Go in the builder only; the
  ubi9-micro runtime is unchanged) and opt-in via `--build-arg FIPS=true`.
- `CryptoProvider::fips()` returning false anywhere at startup is fatal by
  design: a mis-built FIPS binary never runs with non-FIPS TLS.
