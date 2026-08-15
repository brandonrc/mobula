FROM rust:1-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p mobula-cli

# rustls-only TLS stack: no OpenSSL, distroless cc is enough.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/mobula /usr/local/bin/mobula
EXPOSE 8484
ENTRYPOINT ["/usr/local/bin/mobula"]
CMD ["serve", "--bind", "0.0.0.0:8484"]
