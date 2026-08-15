# Contributing to Mobula

Thanks for your interest! Mobula is early - read PLAN.md for where the
project is headed and docs/adr/ for decisions already made (and why).

## Ground rules
- License: Apache-2.0. Contributions are accepted under the Developer
  Certificate of Origin (https://developercertificate.org/) - sign off
  your commits with `git commit -s`.
- CI must pass: `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, and the coverage
  gate (90% lines on library code via `cargo llvm-cov`).
- Install the pre-commit hooks once per clone — they run the same fmt and
  clippy commands as CI, plus whitespace/YAML/TOML hygiene, private-key
  detection, and gitleaks secret scanning:

  ```bash
  uv tool install pre-commit   # or: pipx install pre-commit
  pre-commit install
  pre-commit run --all-files   # first run downloads hook environments
  ```
- Architectural changes that touch an ADR need a superseding ADR, not a
  silent edit.

## Trademark note
Ray is a registered trademark of LF Projects, LLC. Keep the word "ray"
out of crate names, binary names, and domains; "for Ray" nominative
phrasing only.
