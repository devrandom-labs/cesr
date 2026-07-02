//! Compile-time assertion that the frozen public API is reachable at the
//! new `cesr::<module>::*` paths. If any path stops resolving, a downstream
//! consumer's mechanical migration would break — this test catches that.
//!
//! Coverage: all six modules (b64, core, crypto, stream, keri, serder).
//!
//! This test asserts the surface of every module, so it is only meaningful with
//! all module features enabled. Under a reduced feature set the modules are
//! `cfg`'d out, so the whole test compiles to nothing rather than failing a
//! plain `cargo test`. CI runs it via `--all-features`.
#![cfg(all(
    feature = "b64",
    feature = "core",
    feature = "crypto",
    feature = "stream",
    feature = "keri",
    feature = "serder"
))]
#![allow(
    unused_imports,
    reason = "these paths are asserted by name resolution at compile time, not by use"
)]

// b64 — decode/encode helpers (was cesr_utils::* / cesr::utils::*)
use cesr::b64::decode::decode_to_int;
use cesr::b64::encode::{encode_binary, encode_int};

// core — Matter, counter codes, CesrVersion, MatterCode (was cesr_core::*)
use cesr::core::CesrVersion as CoreCesrVersion;
use cesr::core::counter::{CounterCodeV1, CounterCodeV2};
use cesr::core::matter::code::MatterCode;
use cesr::core::matter::matter::Matter;

// crypto — Algorithm + concrete impls, KeyPair, digest (was cesr_crypto::*)
use cesr::crypto::algo::{Algorithm, Ed25519, Secp256k1, Secp256r1};
use cesr::crypto::digest::digest;
use cesr::crypto::keypair::KeyPair;
use cesr::crypto::verify::verify;

// stream — CesrGroup, CesrCodec, CesrMessage (was cesr_stream::*)
use cesr::stream::codec::CesrCodec;
use cesr::stream::group::types::CesrGroup;
use cesr::stream::message::CesrMessage;
use cesr::stream::version::{V1, V2};

// keri — KeriEvent variants, Identifier, Ilk, Seal, KeyState (was keri_core::*)
use cesr::keri::event::{InceptionEvent, KeriEvent};
use cesr::keri::identifier::Identifier;
use cesr::keri::ilk::Ilk;
use cesr::keri::seal::Seal;
use cesr::keri::state::KeyState;

// serder — builders, serialize/deserialize, KeriSerialize/KeriDeserialize traits (was keri_serder::*)
use cesr::serder::builder::InceptionBuilder;
use cesr::serder::serialize::SerializedEvent;
use cesr::serder::traits::{KeriDeserialize, KeriSerialize};

#[test]
fn frozen_paths_resolve() {
    // Verify representative types from each module are addressable by name.
    // All assertions are type-name lookups — no runtime behaviour tested here.
    let _ = core::any::type_name::<Matter<'_, MatterCode>>();
    let _ = core::any::type_name::<CounterCodeV1>();
    let _ = core::any::type_name::<CounterCodeV2>();
    let _ = core::any::type_name::<CoreCesrVersion>();
    let _ = core::any::type_name::<KeyPair<Ed25519>>();
    let _ = core::any::type_name::<Ed25519>();
    let _ = core::any::type_name::<Secp256k1>();
    let _ = core::any::type_name::<Secp256r1>();
    let _ = core::any::type_name::<CesrCodec<V1>>();
    let _ = core::any::type_name::<CesrCodec<V2>>();
    let _ = core::any::type_name::<CesrGroup>();
    let _ = core::any::type_name::<CesrMessage>();
    let _ = core::any::type_name::<KeriEvent>();
    let _ = core::any::type_name::<InceptionEvent>();
    let _ = core::any::type_name::<Identifier>();
    let _ = core::any::type_name::<Ilk>();
    let _ = core::any::type_name::<Seal>();
    let _ = core::any::type_name::<KeyState>();
    let _ = core::any::type_name::<InceptionBuilder>();
    let _ = core::any::type_name::<SerializedEvent>();
}
