# UBI-only multi-stage build (DISA/STIG posture, Mobula ADR-0008):
# - Builder: ubi9 + pinned rustup toolchain; exists only at build time.
# - Runtime: ubi9-micro - no package manager, no shell tooling beyond the
#   base, nothing but glibc + our binary. Numeric non-root user so
#   runAsNonRoot admission checks can verify identity.
# - Bases are ARG-swappable so hardened mirrors (Iron Bank registry1)
#   drop in without editing this file.
ARG BASE_REGISTRY=registry.access.redhat.com
ARG BUILDER_IMAGE=ubi9/ubi:latest
ARG RUNTIME_IMAGE=ubi9/ubi-micro:latest

FROM ${BASE_REGISTRY}/${BUILDER_IMAGE} AS builder
RUN dnf install -y --nodocs gcc && dnf clean all
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:${PATH}
ARG RUST_VERSION=1.94.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION}
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# FIPS 140-3 build (#61, ADR-0012), opt-in: --build-arg FIPS=true. aws-lc-rs'
# FIPS module compiles from C and needs cmake/perl/Go, so the toolchain is
# installed only on this path — the default image stays minimal and keeps
# the pure-Rust ring provider.
ARG FIPS=false
RUN if [ "$FIPS" = "true" ]; then dnf install -y --nodocs cmake perl golang && dnf clean all; fi
RUN if [ "$FIPS" = "true" ]; then \
      cargo build --release -p mobula-cli --no-default-features --features "fips,postgres"; \
    else \
      cargo build --release -p mobula-cli; \
    fi && strip target/release/mobula

ARG BASE_REGISTRY=registry.access.redhat.com
ARG RUNTIME_IMAGE=ubi9/ubi-micro:latest
FROM ${BASE_REGISTRY}/${RUNTIME_IMAGE}
LABEL name="mobula" \
      vendor="Mobula Contributors" \
      summary="FOSS control plane for Ray clusters" \
      description="Mobula control plane: federating Ray job gateway, cluster lifecycle, SSO/RBAC" \
      io.k8s.display-name="Mobula" \
      url="https://github.com/brandonrc/mobula"
COPY LICENSE /licenses/LICENSE
COPY --from=builder /build/target/release/mobula /usr/local/bin/mobula
USER 1001
EXPOSE 8484
ENTRYPOINT ["/usr/local/bin/mobula"]
CMD ["serve", "--bind", "0.0.0.0:8484"]
