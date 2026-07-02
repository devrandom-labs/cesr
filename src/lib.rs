//! CESR + KERI primitives for Rust as a single feature-gated crate.
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

#[cfg(test)]
#[cfg(all(feature = "serder", feature = "std"))]
mod keripy_diff;
