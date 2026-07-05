/// CESR counter code definitions for V1.0 and V2.0 code tables.
#[cfg(feature = "stream")]
pub mod code;
/// V2.0 counter code table (59 codes).
#[cfg(feature = "stream")]
pub mod v2;

#[cfg(feature = "stream")]
pub use code::CounterCodeV1;
#[cfg(feature = "stream")]
pub use v2::CounterCodeV2;
