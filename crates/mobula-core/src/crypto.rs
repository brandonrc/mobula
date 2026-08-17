//! FIPS 140-3 crypto provider enforcement (#61, ADR-0012).
//!
//! Default builds use rustls' pure-Rust `ring` provider. The `fips` cargo
//! feature instead builds rustls on the aws-lc-rs FIPS-validated module and
//! makes process startup fail closed unless that provider is confirmed
//! active. This module holds the shared check so every binary enforces it
//! identically; only the `mobula` CLI is a binary today, so it is the one
//! call site (mobula-cli/src/main.rs).

/// Verdict of the startup FIPS check. Pure (no rustls types) so the
/// fail-closed logic is unit-testable without the aws-lc-rs FIPS module
/// build (which needs a cmake/perl/Go toolchain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FipsStatus {
    /// The process-level rustls `CryptoProvider` reports FIPS mode.
    Active,
    /// A process-level provider is installed but is NOT operating in FIPS
    /// mode (e.g. ring, or aws-lc-rs built without its `fips` feature).
    NotFips,
    /// No process-level provider could be installed at all.
    NoProvider,
}

impl FipsStatus {
    /// Fail closed: only `Active` passes.
    pub fn enforce(self) -> Result<(), String> {
        match self {
            FipsStatus::Active => Ok(()),
            FipsStatus::NotFips => Err(
                "FIPS mode required (built with the `fips` feature) but the active rustls \
                 CryptoProvider is not the aws-lc-rs FIPS provider; refusing to start"
                    .to_string(),
            ),
            FipsStatus::NoProvider => Err(
                "FIPS mode required (built with the `fips` feature) but no rustls \
                 CryptoProvider could be installed; refusing to start"
                    .to_string(),
            ),
        }
    }
}

/// Inspect the installed process-level provider. Split from
/// [`enforce_fips_startup`] so the verdict mapping stays a pure function of
/// the observed provider state.
#[cfg(feature = "fips")]
fn installed_provider_status() -> FipsStatus {
    match rustls::crypto::CryptoProvider::get_default() {
        Some(provider) if provider.fips() => FipsStatus::Active,
        Some(_) => FipsStatus::NotFips,
        None => FipsStatus::NoProvider,
    }
}

/// FIPS fail-closed startup check (#61): install the aws-lc-rs FIPS provider
/// as rustls' process default, then verify the ACTIVE provider really is
/// operating in FIPS mode — `CryptoProvider::fips()` is a runtime check
/// (`aws_lc_rs::try_fips_mode()`), so it also covers the module's power-on
/// self-tests. Panics — aborting startup — otherwise.
///
/// Call once at the top of every binary before any TLS is initialized.
/// Non-fips builds do not compile this; there is nothing to enforce.
#[cfg(feature = "fips")]
pub fn enforce_fips_startup() {
    // If another provider was installed first this is a no-op and the
    // status check below fails closed on the wrong provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    if let Err(msg) = installed_provider_status().enforce() {
        panic!("{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_provider_passes() {
        assert_eq!(FipsStatus::Active.enforce(), Ok(()));
    }

    #[test]
    fn non_fips_provider_fails_closed() {
        let msg = FipsStatus::NotFips.enforce().unwrap_err();
        assert!(msg.contains("not the aws-lc-rs FIPS provider"));
        assert!(msg.contains("refusing to start"));
    }

    #[test]
    fn missing_provider_fails_closed() {
        let msg = FipsStatus::NoProvider.enforce().unwrap_err();
        assert!(msg.contains("no rustls"));
        assert!(msg.contains("refusing to start"));
    }
}
