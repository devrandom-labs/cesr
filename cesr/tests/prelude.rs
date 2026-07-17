//! Resolution tests for the flattened public surface (#31).
//! These prove import paths exist; failure mode is a compile error.

// Tier-1: module-root flagship paths must resolve.
#[cfg(feature = "core")]
#[test]
fn core_module_root_paths_resolve() {
    // Type-level use is enough; we only assert these names resolve.
    #[allow(
        unused_imports,
        reason = "resolution test: the import proves the path resolves; the binding is intentionally unused"
    )]
    use cesr::core::{Diger, Matter, Signer, Verfer};
    let _: Option<Matter<'_, cesr::core::matter::code::VerKeyCode>> = None;
}

// Tier-2: crate-root flat paths must resolve.
#[cfg(feature = "core")]
#[test]
fn crate_root_core_types_resolve() {
    #[allow(
        unused_imports,
        reason = "resolution test: the import proves the path resolves; the binding is intentionally unused"
    )]
    use cesr::{Diger, Matter, Signer, Verfer};
}

#[cfg(feature = "crypto")]
#[test]
fn crate_root_crypto_types_resolve() {
    #[allow(
        unused_imports,
        reason = "resolution test: the import proves the path resolves; the binding is intentionally unused"
    )]
    use cesr::{Ed25519, KeyPair, Secp256k1, Secp256r1};
}

// One `CesrVersion` (#spine-1): the crate root re-exports the single
// `core::version::CesrVersion`; the former `StreamCesrVersion` alias is gone.
#[cfg(feature = "core")]
#[test]
fn cesr_version_resolves_from_core_and_crate_root() {
    #[allow(
        unused_imports,
        reason = "resolution test: the import proves the path resolves; the binding is intentionally unused"
    )]
    use cesr::CesrVersion;
    #[allow(
        unused_imports,
        reason = "resolution test: the import proves the path resolves; the binding is intentionally unused"
    )]
    use cesr::core::version::CesrVersion as CoreCesrVersion;
}
