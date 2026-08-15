# Contributing to Mobula

Thanks for your interest! Mobula is early - read PLAN.md for where the
project is headed and docs/adr/ for decisions already made (and why).

## Ground rules
- License: Apache-2.0. Contributions are accepted under the Developer
  Certificate of Origin (https://developercertificate.org/) - sign off
  your commits with `git commit -s`.
- CI must pass: `cargo fmt --all --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`.
- Architectural changes that touch an ADR need a superseding ADR, not a
  silent edit.

## Trademark note
Ray is a registered trademark of LF Projects, LLC. Keep the word "ray"
out of crate names, binary names, and domains; "for Ray" nominative
phrasing only.
