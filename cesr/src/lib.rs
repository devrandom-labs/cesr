//! CESR + KERI primitives for Rust as a single feature-gated crate.
//!
//! # Architecture: one wire message, four modules
//!
//! A KERI key event message is a serialized event body followed by
//! CESR-framed attachments:
//!
//! ```text
//! {"v":"KERI10JSON000189_","t":"icp","d":"EAgi…",…} -VAt -AAC AADB_mVj…88ch ABAN5tRO…88ch
//! └──────────────────── body ─────────────────────┘└─────────── attachments ────────────┘
//!                                                   │    │    └ two indexed Ed25519 sigs
//!                                                   │    └ `-A` ControllerIdxSigs, count 2
//!                                                   └ `-V` attachment frame, size in quadlets
//! ```
//!
//! Each module owns one verb over that message:
//!
//! - [`stream`] **finds** it — cold-start detection and version-string
//!   framing slice the body span; counters delimit the attachment groups.
//! - [`serder`] **decodes** it — the strict canonical body codec parses the
//!   JSON and verifies the SAID in place; the builders write keripy's exact
//!   bytes back.
//! - [`keri`] **names** it — the typed domain: events, identifiers, seals,
//!   thresholds. Pure data, no serialization of its own.
//! - [`core`] **spells** it — the CESR primitive alphabet (`Matter`,
//!   indexers, counters) that every layer above composes; [`b64`] is its
//!   Base64 codec, [`crypto`] its digests, keypairs, and verifiers.
//!
//! The front door is [`serder::EventMessage::parse`]: wire bytes in — typed
//! event, exact signed byte span, indexed signatures, and the unconsumed
//! remainder out. Its write mirror is [`serder::SerializedEvent::frame_v1`]:
//! built event + [`stream::ControllerIdxSigs::from_sigers`] (and optional
//! witness receipts) in — the keripy-byte-identical framed message out.
//!
//! # Features
//!
//! Each former separate crate is now a module gated by a cargo feature:
//! `b64`, `core`, `crypto`, `stream`, `keri`, `serder`, reachable as
//! `cesr::core::*`, `cesr::crypto::*`, etc. (The former `utils` module — the
//! CESR Base64 codec — is now `b64`.)
//!
//! The crate is `no_std`-capable: `std` (on by default) gives the std-backed
//! surface; build `--no-default-features --features alloc,…` for embedded/wasm.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "b64")]
pub mod b64;
#[cfg(feature = "core")]
pub mod core;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "keri")]
pub mod keri;
#[cfg(feature = "serder")]
pub mod serder;
#[cfg(feature = "stream")]
pub mod stream;

#[cfg(feature = "core")]
#[doc(inline)]
pub use core::{
    CesrVersion, Cigar, Dater, Diger, Labeler, Matter, Noncer, Number, Prefixer, Saider, Seqner,
    Siger, Signer, Texter, Verfer, Verser,
};
#[cfg(feature = "crypto")]
#[doc(inline)]
pub use crypto::{Algorithm, Ed25519, KeyPair, Secp256k1, Secp256r1};
#[cfg(feature = "keri")]
#[doc(inline)]
pub use keri::{Identifier, Ilk, KeriError, KeriEvent, Role, Seal};
#[cfg(feature = "serder")]
#[doc(inline)]
pub use serder::{
    EventMessage, EventMessageError, InceptionBuilder, InteractionBuilder, KeriDeserialize,
    KeriSerialize, RotationBuilder, SerderError,
};
#[cfg(all(feature = "stream", feature = "async"))]
#[doc(inline)]
pub use stream::CesrCodec;
#[cfg(feature = "stream")]
#[doc(inline)]
pub use stream::{
    CesrEncode, CesrGroup, CesrMessage, ColdCode, Groups, GroupsV2, ParseError, Tritet, V1, V2,
};

/// The common imports for working with `cesr`.
///
/// `use cesr::prelude::*;` brings the traits you need in scope for method
/// resolution, plus a handful of headliner types so you can write code from the
/// glob alone. Every other public type is reachable at the crate root
/// (`cesr::Matter`) or its module path (`cesr::core::Matter`).
pub mod prelude {
    // Traits — the primary payload (needed implicitly for method resolution).
    #[cfg(feature = "crypto")]
    #[doc(no_inline)]
    pub use crate::crypto::Algorithm;
    #[cfg(feature = "keri")]
    #[doc(no_inline)]
    pub use crate::keri::ConfigTrait;
    #[cfg(feature = "serder")]
    #[doc(no_inline)]
    pub use crate::serder::{KeriDeserialize, KeriSerialize};
    #[cfg(feature = "stream")]
    #[doc(no_inline)]
    pub use crate::stream::CesrEncode;

    // Headliner types — enough to write code from the glob alone.
    #[cfg(feature = "core")]
    #[doc(no_inline)]
    pub use crate::core::{Diger, Matter, Signer, Verfer};
    #[cfg(feature = "keri")]
    #[doc(no_inline)]
    pub use crate::keri::{Identifier, KeriEvent};
    #[cfg(feature = "stream")]
    #[doc(no_inline)]
    pub use crate::stream::{CesrGroup, CesrMessage};
}

#[cfg(test)]
#[cfg(all(feature = "serder", feature = "std"))]
mod keripy_diff;

#[cfg(test)]
#[cfg(all(feature = "serder", feature = "std"))]
mod keripy_parity;
