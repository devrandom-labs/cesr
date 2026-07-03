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
