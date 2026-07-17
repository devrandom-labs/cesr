/// CESR counter code definitions for V1.0 and V2.0 code tables.
pub mod code;
/// V2.0 counter code table (59 codes).
pub mod v2;

pub use code::CounterCodeV1;
pub use v2::CounterCodeV2;
