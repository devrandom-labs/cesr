//! Resolution tests for the flattened public surface (#31).
//! These prove import paths exist; failure mode is a compile error.

// Tier-1: module-root flagship paths must resolve.
#[cfg(feature = "core")]
#[test]
fn core_module_root_paths_resolve() {
    // Type-level use is enough; we only assert these names resolve.
    #[allow(unused_imports)]
    use cesr::core::{Diger, Matter, Signer, Verfer};
    let _ = core::any::type_name::<Matter<'_, cesr::core::matter::code::VerKeyCode>>();
}

// Tier-2: crate-root flat paths must resolve.
#[cfg(feature = "core")]
#[test]
fn crate_root_core_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{Diger, Matter, Signer, Verfer};
}

#[cfg(feature = "crypto")]
#[test]
fn crate_root_crypto_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{Ed25519, KeyPair, Secp256k1, Secp256r1};
}

#[cfg(feature = "stream")]
#[test]
fn crate_root_stream_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{CesrGroup, CesrMessage, ColdCode};
}

#[cfg(feature = "keri")]
#[test]
fn crate_root_keri_types_resolve() {
    #[allow(unused_imports)]
    use cesr::{Identifier, Ilk, KeriEvent, Role, Seal};
}

// The one real collision: core keeps the bare name, stream is prefixed.
// core::CesrVersion is itself stream-gated, so both exist only when stream is on.
#[cfg(all(feature = "core", feature = "stream"))]
#[test]
fn cesr_version_collision_is_disambiguated() {
    #[allow(unused_imports)]
    use cesr::{CesrVersion, StreamCesrVersion};
}

#[cfg(all(feature = "core", feature = "stream"))]
#[test]
fn prelude_glob_resolves() {
    // Glob import must not error and must bring the headliner types + traits in.
    #[allow(unused_imports)]
    use cesr::prelude::*;
    // Reference a couple of headliners to prove they are in scope via the glob.
    #[allow(unused_imports)]
    use cesr::prelude::{CesrGroup, Matter};
}
