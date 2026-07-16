//! CESR/KERI version knowledge — the single owner.
//!
//! This module owns every version-related wire fact: the [`CesrVersion`]
//! code-table selector, the [`Protocol`] and [`SerializationKind`] code
//! tables, and both version-string frames:
//!
//! V1 format ([`VersionString`], 17 bytes): `PPPPmmKKKKssssss_`
//! - 4 chars protocol (`KERI` or `ACDC`)
//! - 1 hex char major version, 1 hex char minor version
//! - 4 chars serialization kind (`JSON`, `CBOR`, `MGPK`, `CESR`)
//! - 6 hex chars size (zero-padded)
//! - `_` terminator
//!
//! V2 format ([`VersionStringV2`], 19 bytes): `PPPPpmmgmmKKKKssss.`
//! - 4 chars protocol
//! - 1 Base64 char protocol major (must decode to 2), 2 Base64 chars
//!   protocol minor
//! - 1 Base64 char genus major (must decode to 2), 2 Base64 chars genus
//!   minor
//! - 4 chars serialization kind
//! - 4 Base64 chars size
//! - `.` terminator
//!
//! Both frames enforce their fixed-width field invariants at construction,
//! so rendering is infallible and `parse(render(x)) == x` holds by
//! construction.

use crate::b64::decode_int;
use crate::b64::encode_int;
use crate::b64::error::Error as B64Error;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String};
use core::num::NonZeroUsize;
use num_traits::{PrimInt, Unsigned, ops::checked::CheckedShl};

/// Total length of a V1 version string in bytes.
pub const VERSION_STRING_LEN: usize = 17;

/// Total length of a V2 version string in bytes.
pub const VERSION_STRING_V2_LEN: usize = 19;

/// Width of the V1 hex size field in characters.
const SIZE_LEN: usize = 6;

/// Largest event size encodable in the fixed [`SIZE_LEN`]-hex-digit size field.
pub(crate) const VERSION_SIZE_MAX: u32 = 0x00FF_FFFF;

/// Largest major/minor version encodable in one hex digit.
const VERSION_DIGIT_MAX: u8 = 0xF;

/// The only protocol/genus major version a V2 version string may carry.
const V2_MAJOR: u8 = 2;

/// Largest minor version encodable in two Base64 characters (64^2 - 1).
const V2_MINOR_MAX: u16 = 4095;

/// Largest event size encodable in four Base64 characters (64^4 - 1).
const VERSION_V2_SIZE_MAX: u32 = 16_777_215;

/// V1 version string terminator byte.
const V1_TERMINATOR: u8 = b'_';

/// V2 version string terminator byte.
const V2_TERMINATOR: u8 = b'.';

/// CESR protocol version for code table selection.
///
/// V1 and V2 use different counter code tables — the same wire code
/// (e.g. `-A`) maps to different semantic groups depending on version.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum CesrVersion {
    /// CESR V1.0 — 22 counter codes.
    V1,
    /// CESR V2.0 — 59 counter codes (default).
    #[default]
    V2,
}

/// Errors from version-string parsing and construction.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum VersionError {
    /// Input shorter than the fixed version-string frame.
    #[error("version string truncated: need {needed} more bytes")]
    Truncated {
        /// Additional bytes required to complete the frame.
        needed: usize,
    },

    /// The 4-byte protocol field is not a recognized protocol.
    #[error("unknown protocol: {}", .found.escape_ascii())]
    UnknownProtocol {
        /// The offending protocol bytes.
        found: [u8; 4],
    },

    /// A major/minor version byte is not a hex digit (V1 frame).
    #[error("invalid {field} version hex digit: {}", .found.escape_ascii())]
    InvalidVersionDigit {
        /// The version field that failed: `"major"` or `"minor"`.
        field: &'static str,
        /// The offending byte.
        found: u8,
    },

    /// The 4-byte serialization-kind field is not a recognized kind.
    #[error("unknown serialization kind: {}", .found.escape_ascii())]
    UnknownKind {
        /// The offending kind bytes.
        found: [u8; 4],
    },

    /// The 6-byte V1 size field contains a non-hex byte.
    #[error("invalid size hex: {}", .found.escape_ascii())]
    InvalidSizeHex {
        /// The offending size-field bytes.
        found: [u8; SIZE_LEN],
    },

    /// The terminator byte is missing or wrong.
    #[error("expected {expected:?} terminator, found {}", .found.escape_ascii())]
    MissingTerminator {
        /// The terminator the frame requires (`'_'` for V1, `'.'` for V2).
        expected: char,
        /// The byte actually found.
        found: u8,
    },

    /// A field value does not fit its fixed-width encoding — rendering it
    /// anyway would widen the string and corrupt the fixed-length frame.
    #[error("version string field '{field}' exceeds its fixed-width capacity of {max}")]
    FieldOverflow {
        /// The version-string field that does not fit.
        field: &'static str,
        /// The largest value the field's fixed width can encode.
        max: u32,
    },

    /// A V2 protocol/genus major version other than 2.
    #[error("unsupported {field}: expected {V2_MAJOR}, found {found}")]
    UnsupportedMajor {
        /// The major field that failed: `"proto_major"` or `"genus_major"`.
        field: &'static str,
        /// The major version actually found.
        found: u8,
    },

    /// A V2 Base64-encoded field failed to decode.
    #[error("invalid base64 in version string field '{field}'")]
    Base64 {
        /// The V2 field that failed to decode.
        field: &'static str,
        /// The underlying Base64 decode error.
        #[source]
        source: B64Error,
    },
}

/// Serialization format for the event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationKind {
    /// JSON encoding.
    Json,
    /// CBOR encoding.
    Cbor,
    /// `MessagePack` encoding.
    Mgpk,
    /// Native CESR encoding.
    Cesr,
}

impl SerializationKind {
    /// The 4-character wire representation — the single kind↔bytes table.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Cbor => "CBOR",
            Self::Mgpk => "MGPK",
            Self::Cesr => "CESR",
        }
    }

    /// Parse from a 4-character wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::UnknownKind`] if the input is not a
    /// recognized serialization kind.
    pub fn from_repr(repr: &str) -> Result<Self, VersionError> {
        match repr.as_bytes() {
            &[c0, c1, c2, c3] => Self::from_wire([c0, c1, c2, c3]),
            other => Err(VersionError::UnknownKind {
                found: first4(other),
            }),
        }
    }

    /// Parse from the exact 4 wire bytes.
    const fn from_wire(wire: [u8; 4]) -> Result<Self, VersionError> {
        match &wire {
            b"JSON" => Ok(Self::Json),
            b"CBOR" => Ok(Self::Cbor),
            b"MGPK" => Ok(Self::Mgpk),
            b"CESR" => Ok(Self::Cesr),
            _ => Err(VersionError::UnknownKind { found: wire }),
        }
    }
}

/// Protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Key Event Receipt Infrastructure.
    Keri,
    /// Authentic Chained Data Container.
    Acdc,
}

impl Protocol {
    /// The 4-character wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keri => "KERI",
            Self::Acdc => "ACDC",
        }
    }

    /// Parse from a 4-character wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::UnknownProtocol`] if the input is not a
    /// recognized protocol.
    pub fn from_repr(repr: &str) -> Result<Self, VersionError> {
        match repr.as_bytes() {
            &[c0, c1, c2, c3] => Self::from_wire([c0, c1, c2, c3]),
            other => Err(VersionError::UnknownProtocol {
                found: first4(other),
            }),
        }
    }

    /// Parse from the exact 4 wire bytes.
    const fn from_wire(wire: [u8; 4]) -> Result<Self, VersionError> {
        match &wire {
            b"KERI" => Ok(Self::Keri),
            b"ACDC" => Ok(Self::Acdc),
            _ => Err(VersionError::UnknownProtocol { found: wire }),
        }
    }
}

/// A parsed V1 KERI version string.
///
/// Encodes the protocol, version, serialization kind, and total serialized
/// size of a KERI event message. Fields are validated at construction:
/// `major` and `minor` fit one hex digit and `size` fits the six-hex-digit
/// size field, so rendering can never widen the 17-byte frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionString {
    proto: Protocol,
    major: u8,
    minor: u8,
    kind: SerializationKind,
    size: u32,
}

impl VersionString {
    /// Create a new version string with the given parameters.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::FieldOverflow`] if `major`, `minor`, or
    /// `size` does not fit its fixed-width hex field.
    pub fn new(
        proto: Protocol,
        major: u8,
        minor: u8,
        kind: SerializationKind,
        size: u32,
    ) -> Result<Self, VersionError> {
        if major > VERSION_DIGIT_MAX {
            return Err(VersionError::FieldOverflow {
                field: "major",
                max: u32::from(VERSION_DIGIT_MAX),
            });
        }
        if minor > VERSION_DIGIT_MAX {
            return Err(VersionError::FieldOverflow {
                field: "minor",
                max: u32::from(VERSION_DIGIT_MAX),
            });
        }
        if size > VERSION_SIZE_MAX {
            return Err(VersionError::FieldOverflow {
                field: "size",
                max: VERSION_SIZE_MAX,
            });
        }
        Ok(Self {
            proto,
            major,
            minor,
            kind,
            size,
        })
    }

    /// KERI v1.0 JSON with zero size (to be filled after serialization).
    #[must_use]
    pub const fn keri_json_v1() -> Self {
        Self {
            proto: Protocol::Keri,
            major: 1,
            minor: 0,
            kind: SerializationKind::Json,
            size: 0,
        }
    }

    /// Return a copy with the size field updated.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::FieldOverflow`] if `size` does not fit the
    /// six-hex-digit size field.
    pub fn with_size(self, size: u32) -> Result<Self, VersionError> {
        Self::new(self.proto, self.major, self.minor, self.kind, size)
    }

    /// The protocol identifier.
    #[must_use]
    pub const fn proto(&self) -> Protocol {
        self.proto
    }

    /// Major version number (0..=15).
    #[must_use]
    pub const fn major(&self) -> u8 {
        self.major
    }

    /// Minor version number (0..=15).
    #[must_use]
    pub const fn minor(&self) -> u8 {
        self.minor
    }

    /// Serialization format.
    #[must_use]
    pub const fn kind(&self) -> SerializationKind {
        self.kind
    }

    /// Total serialized message size in bytes.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// Render the 17-byte version string.
    ///
    /// Infallible: construction already guaranteed every field fits its
    /// fixed-width hex slot.
    #[must_use]
    pub fn to_str(&self) -> String {
        format!(
            "{}{:x}{:x}{}{:06x}_",
            self.proto.as_str(),
            self.major,
            self.minor,
            self.kind.as_str(),
            self.size,
        )
    }

    /// Parse a version string from the first 17 bytes of `input`, returning
    /// the parsed value and the remainder of the input.
    ///
    /// Major/minor accept any hex digit (upper- or lowercase), matching the
    /// historical `from_str_radix` behavior of the serder parser.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Truncated`] if `input` is shorter than 17
    /// bytes, or the field-specific [`VersionError`] variant for an
    /// unrecognized protocol/kind, a non-hex version or size digit, or a
    /// missing `_` terminator.
    pub fn parse(input: &[u8]) -> Result<(Self, &[u8]), VersionError> {
        let (frame, rest) = split_frame(input, VERSION_STRING_LEN)?;
        let &[
            p0,
            p1,
            p2,
            p3,
            major_b,
            minor_b,
            k0,
            k1,
            k2,
            k3,
            s0,
            s1,
            s2,
            s3,
            s4,
            s5,
            term,
        ] = frame
        else {
            return Err(VersionError::Truncated {
                needed: VERSION_STRING_LEN,
            });
        };

        let proto = Protocol::from_wire([p0, p1, p2, p3])?;
        let major = decode_hex_digit(major_b).ok_or(VersionError::InvalidVersionDigit {
            field: "major",
            found: major_b,
        })?;
        let minor = decode_hex_digit(minor_b).ok_or(VersionError::InvalidVersionDigit {
            field: "minor",
            found: minor_b,
        })?;
        let kind = SerializationKind::from_wire([k0, k1, k2, k3])?;
        let size = decode_hex_size([s0, s1, s2, s3, s4, s5])?;
        if term != V1_TERMINATOR {
            return Err(VersionError::MissingTerminator {
                expected: '_',
                found: term,
            });
        }

        Ok((
            Self {
                proto,
                major,
                minor,
                kind,
                size,
            },
            rest,
        ))
    }
}

/// A parsed V2 CESR version string.
///
/// Carries the protocol major/minor AND the genus major/minor alongside the
/// serialization kind and size. The V2 frame fixes both majors at 2 —
/// parsing rejects anything else — so the majors are not stored: invalid
/// states are unrepresentable and [`Self::proto_major`] /
/// [`Self::genus_major`] return the format constant. Minors and `size` are
/// validated at construction to fit their fixed-width Base64 fields, so
/// rendering can never widen the 19-byte frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionStringV2 {
    proto: Protocol,
    proto_minor: u16,
    genus_minor: u16,
    kind: SerializationKind,
    size: u32,
}

impl VersionStringV2 {
    /// Create a new V2 version string with the given parameters. The
    /// protocol and genus major versions are fixed at 2 by the V2 frame.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::FieldOverflow`] if `proto_minor`,
    /// `genus_minor`, or `size` does not fit its fixed-width Base64 field.
    pub fn new(
        proto: Protocol,
        proto_minor: u16,
        genus_minor: u16,
        kind: SerializationKind,
        size: u32,
    ) -> Result<Self, VersionError> {
        if proto_minor > V2_MINOR_MAX {
            return Err(VersionError::FieldOverflow {
                field: "proto_minor",
                max: u32::from(V2_MINOR_MAX),
            });
        }
        if genus_minor > V2_MINOR_MAX {
            return Err(VersionError::FieldOverflow {
                field: "genus_minor",
                max: u32::from(V2_MINOR_MAX),
            });
        }
        if size > VERSION_V2_SIZE_MAX {
            return Err(VersionError::FieldOverflow {
                field: "size",
                max: VERSION_V2_SIZE_MAX,
            });
        }
        Ok(Self {
            proto,
            proto_minor,
            genus_minor,
            kind,
            size,
        })
    }

    /// The protocol identifier.
    #[must_use]
    pub const fn proto(&self) -> Protocol {
        self.proto
    }

    /// Protocol major version number — always 2 in the V2 frame.
    #[must_use]
    pub const fn proto_major(&self) -> u8 {
        V2_MAJOR
    }

    /// Protocol minor version number (0..=4095).
    #[must_use]
    pub const fn proto_minor(&self) -> u16 {
        self.proto_minor
    }

    /// Genus major version number — always 2 in the V2 frame.
    #[must_use]
    pub const fn genus_major(&self) -> u8 {
        V2_MAJOR
    }

    /// Genus minor version number (0..=4095).
    #[must_use]
    pub const fn genus_minor(&self) -> u16 {
        self.genus_minor
    }

    /// Serialization format.
    #[must_use]
    pub const fn kind(&self) -> SerializationKind {
        self.kind
    }

    /// Total serialized message size in bytes.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// Render the 19-byte V2 version string.
    ///
    /// Infallible: construction already guaranteed every field fits its
    /// fixed-width Base64 slot.
    #[must_use]
    pub fn to_str(&self) -> String {
        let mut out = String::with_capacity(VERSION_STRING_V2_LEN);
        out.push_str(self.proto.as_str());
        push_b64_fixed(&mut out, u32::from(V2_MAJOR), 1);
        push_b64_fixed(&mut out, u32::from(self.proto_minor), 2);
        push_b64_fixed(&mut out, u32::from(V2_MAJOR), 1);
        push_b64_fixed(&mut out, u32::from(self.genus_minor), 2);
        out.push_str(self.kind.as_str());
        push_b64_fixed(&mut out, self.size, 4);
        out.push(char::from(V2_TERMINATOR));
        out
    }

    /// Parse a V2 version string from the first 19 bytes of `input`,
    /// returning the parsed value and the remainder of the input.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError::Truncated`] if `input` is shorter than 19
    /// bytes, or the field-specific [`VersionError`] variant for an
    /// unrecognized protocol/kind, a non-Base64 version or size character,
    /// a major version other than 2, or a missing `.` terminator.
    pub fn parse(input: &[u8]) -> Result<(Self, &[u8]), VersionError> {
        let (frame, rest) = split_frame(input, VERSION_STRING_V2_LEN)?;
        let &[
            p0,
            p1,
            p2,
            p3,
            pj,
            pmin0,
            pmin1,
            gj,
            gmin0,
            gmin1,
            k0,
            k1,
            k2,
            k3,
            z0,
            z1,
            z2,
            z3,
            term,
        ] = frame
        else {
            return Err(VersionError::Truncated {
                needed: VERSION_STRING_V2_LEN,
            });
        };

        let proto = Protocol::from_wire([p0, p1, p2, p3])?;
        let proto_major: u8 = decode_b64_field(&[pj], "proto_major")?;
        if proto_major != V2_MAJOR {
            return Err(VersionError::UnsupportedMajor {
                field: "proto_major",
                found: proto_major,
            });
        }
        let proto_minor: u16 = decode_b64_field(&[pmin0, pmin1], "proto_minor")?;
        let genus_major: u8 = decode_b64_field(&[gj], "genus_major")?;
        if genus_major != V2_MAJOR {
            return Err(VersionError::UnsupportedMajor {
                field: "genus_major",
                found: genus_major,
            });
        }
        let genus_minor: u16 = decode_b64_field(&[gmin0, gmin1], "genus_minor")?;
        let kind = SerializationKind::from_wire([k0, k1, k2, k3])?;
        let size: u32 = decode_b64_field(&[z0, z1, z2, z3], "size")?;
        if term != V2_TERMINATOR {
            return Err(VersionError::MissingTerminator {
                expected: '.',
                found: term,
            });
        }

        Ok((
            Self {
                proto,
                proto_minor,
                genus_minor,
                kind,
                size,
            },
            rest,
        ))
    }
}

/// Split `input` into a fixed-length frame and the remainder.
fn split_frame(input: &[u8], frame_len: usize) -> Result<(&[u8], &[u8]), VersionError> {
    if let Some(needed) = frame_len.checked_sub(input.len())
        && needed > 0
    {
        return Err(VersionError::Truncated { needed });
    }
    // Unreachable fallback: the guard above returned for every shorter input.
    input
        .split_at_checked(frame_len)
        .ok_or(VersionError::Truncated { needed: frame_len })
}

/// Decode one ASCII hex digit (either case), or `None`.
const fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode the six-hex-digit V1 size field.
fn decode_hex_size(bytes: [u8; SIZE_LEN]) -> Result<u32, VersionError> {
    bytes.iter().try_fold(0_u32, |acc, &byte| {
        let digit = decode_hex_digit(byte).ok_or(VersionError::InvalidSizeHex { found: bytes })?;
        // Unreachable overflow arm: six nibbles occupy at most 24 bits.
        acc.checked_mul(16)
            .and_then(|shifted| shifted.checked_add(u32::from(digit)))
            .ok_or(VersionError::FieldOverflow {
                field: "size",
                max: VERSION_SIZE_MAX,
            })
    })
}

/// Decode a fixed-width Base64 field of a V2 version string.
fn decode_b64_field<N>(bytes: &[u8], field: &'static str) -> Result<N, VersionError>
where
    N: PrimInt + Unsigned + CheckedShl + 'static,
{
    decode_int(bytes).map_err(|source| VersionError::Base64 { field, source })
}

/// Append `value` as exactly `width` Base64 characters (left-padded with
/// `'A'`). The caller guarantees `value` fits `width` characters — enforced
/// by the version-string constructors.
fn push_b64_fixed(out: &mut String, value: u32, width: usize) {
    let digits = encode_int(value, NonZeroUsize::MIN);
    (digits.len()..width).for_each(|_| out.push('A'));
    out.push_str(&digits);
}

/// The first four bytes of `bytes`, right-padded with spaces.
const fn first4(bytes: &[u8]) -> [u8; 4] {
    let mut out = [b' '; 4];
    let mut i = 0;
    while i < bytes.len() && i < 4 {
        out[i] = bytes[i];
        i += 1;
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: panics acceptable"
)]
mod tests {
    use super::*;

    // ── CesrVersion ──────────────────────────────────────────────────────

    #[test]
    fn default_is_v2() {
        assert_eq!(CesrVersion::default(), CesrVersion::V2);
    }

    #[test]
    fn equality() {
        assert_eq!(CesrVersion::V1, CesrVersion::V1);
        assert_ne!(CesrVersion::V1, CesrVersion::V2);
    }

    // ── VersionString construction & rendering ──────────────────────────

    #[test]
    fn keri_json_v1_defaults() {
        let vs = VersionString::keri_json_v1();
        assert_eq!(vs.proto(), Protocol::Keri);
        assert_eq!(vs.major(), 1);
        assert_eq!(vs.minor(), 0);
        assert_eq!(vs.kind(), SerializationKind::Json);
        assert_eq!(vs.size(), 0);
    }

    #[test]
    fn to_str_zero_size() {
        let vs = VersionString::keri_json_v1();
        assert_eq!(vs.to_str(), "KERI10JSON000000_");
    }

    #[test]
    fn to_str_nonzero_size() {
        let vs = VersionString::keri_json_v1().with_size(0x25d).unwrap();
        assert_eq!(vs.to_str(), "KERI10JSON00025d_");
    }

    #[test]
    fn to_str_renders_max_size_at_fixed_width() {
        let vs = VersionString::keri_json_v1()
            .with_size(VERSION_SIZE_MAX)
            .unwrap();
        let rendered = vs.to_str();
        assert_eq!(rendered, "KERI10JSONffffff_");
        assert_eq!(rendered.len(), VERSION_STRING_LEN);
    }

    #[test]
    fn rejects_size_beyond_fixed_width_at_construction() {
        // Bug probe (relocated from `to_str`): sizes above VERSION_SIZE_MAX
        // would render a widened 7-hex-digit size field, corrupting the
        // 17-byte frame — construction must refuse them.
        let result = VersionString::keri_json_v1().with_size(VERSION_SIZE_MAX + 1);
        assert_eq!(
            result.unwrap_err(),
            VersionError::FieldOverflow {
                field: "size",
                max: VERSION_SIZE_MAX,
            }
        );
    }

    #[test]
    fn to_str_renders_max_versions_at_fixed_width() {
        let vs = VersionString::new(Protocol::Keri, 0xF, 0xF, SerializationKind::Json, 0).unwrap();
        let rendered = vs.to_str();
        assert_eq!(rendered, "KERIffJSON000000_");
        assert_eq!(rendered.len(), VERSION_STRING_LEN);
    }

    #[test]
    fn rejects_major_beyond_one_hex_digit_at_construction() {
        let result = VersionString::new(Protocol::Keri, 0x10, 0, SerializationKind::Json, 0);
        assert!(matches!(
            result.unwrap_err(),
            VersionError::FieldOverflow { field: "major", .. }
        ));
    }

    #[test]
    fn rejects_minor_beyond_one_hex_digit_at_construction() {
        let result = VersionString::new(Protocol::Keri, 0, 0x10, SerializationKind::Json, 0);
        assert!(matches!(
            result.unwrap_err(),
            VersionError::FieldOverflow { field: "minor", .. }
        ));
    }

    #[test]
    fn size_capacity_matches_size_field_width() {
        let width = u32::try_from(SIZE_LEN).unwrap();
        assert_eq!(VERSION_SIZE_MAX, (1_u32 << (4 * width)) - 1);
    }

    // ── VersionString parsing ────────────────────────────────────────────

    #[test]
    fn parse_valid() {
        let (vs, rest) = VersionString::parse(b"KERI10JSON00025d_").unwrap();
        assert_eq!(vs.proto(), Protocol::Keri);
        assert_eq!(vs.major(), 1);
        assert_eq!(vs.minor(), 0);
        assert_eq!(vs.kind(), SerializationKind::Json);
        assert_eq!(vs.size(), 0x25d);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_keri_v1_json_returns_rest() {
        let (parsed, rest) = VersionString::parse(b"KERI10JSON000123_rest").unwrap();
        assert_eq!(parsed.proto(), Protocol::Keri);
        assert_eq!(parsed.major(), 1);
        assert_eq!(parsed.minor(), 0);
        assert_eq!(parsed.kind(), SerializationKind::Json);
        assert_eq!(parsed.size(), 0x123);
        assert_eq!(rest, b"rest");
    }

    #[test]
    fn parse_acdc_v1_cbor() {
        let (parsed, rest) = VersionString::parse(b"ACDC10CBOR000050_").unwrap();
        assert_eq!(parsed.proto(), Protocol::Acdc);
        assert_eq!(parsed.kind(), SerializationKind::Cbor);
        assert_eq!(parsed.size(), 0x50);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_keri_v2_msgpack() {
        let (parsed, _) = VersionString::parse(b"KERI20MGPK0000ff_").unwrap();
        assert_eq!(parsed.major(), 2);
        assert_eq!(parsed.minor(), 0);
        assert_eq!(parsed.kind(), SerializationKind::Mgpk);
        assert_eq!(parsed.size(), 0xff);
    }

    #[test]
    fn parse_cesr_kind() {
        let (parsed, _) = VersionString::parse(b"KERI10CESR000000_").unwrap();
        assert_eq!(parsed.kind(), SerializationKind::Cesr);
        assert_eq!(parsed.size(), 0);
    }

    #[test]
    fn parse_max_size() {
        let (parsed, _) = VersionString::parse(b"KERI10JSONffffff_").unwrap();
        assert_eq!(parsed.size(), 0x00ff_ffff);
    }

    #[test]
    fn parse_uppercase_size_hex_accepted() {
        // from_str_radix historically accepted uppercase hex in the size
        // field; the byte parser preserves that acceptance.
        let (parsed, _) = VersionString::parse(b"KERI10JSONFFFFFF_").unwrap();
        assert_eq!(parsed.size(), 0x00ff_ffff);
    }

    #[test]
    fn parse_too_short_reports_missing_bytes() {
        let result = VersionString::parse(b"KERI10JSON");
        assert_eq!(result.unwrap_err(), VersionError::Truncated { needed: 7 });
    }

    #[test]
    fn parse_too_short_twelve_bytes() {
        let result = VersionString::parse(b"KERI10JSON00");
        assert_eq!(result.unwrap_err(), VersionError::Truncated { needed: 5 });
    }

    #[test]
    fn parse_unknown_protocol() {
        let result = VersionString::parse(b"XXXX10JSON000000_");
        assert_eq!(
            result.unwrap_err(),
            VersionError::UnknownProtocol { found: *b"XXXX" }
        );
    }

    #[test]
    fn parse_unknown_kind() {
        let result = VersionString::parse(b"KERI10YAML000000_");
        assert_eq!(
            result.unwrap_err(),
            VersionError::UnknownKind { found: *b"YAML" }
        );
    }

    #[test]
    fn parse_invalid_version_digit() {
        let result = VersionString::parse(b"KERIx0JSON000000_");
        assert_eq!(
            result.unwrap_err(),
            VersionError::InvalidVersionDigit {
                field: "major",
                found: b'x',
            }
        );
    }

    #[test]
    fn parse_invalid_hex_size() {
        let result = VersionString::parse(b"KERI10JSON00ZZZZ_");
        assert_eq!(
            result.unwrap_err(),
            VersionError::InvalidSizeHex { found: *b"00ZZZZ" }
        );
    }

    #[test]
    fn parse_missing_terminator() {
        let result = VersionString::parse(b"KERI10JSON000000X");
        assert_eq!(
            result.unwrap_err(),
            VersionError::MissingTerminator {
                expected: '_',
                found: b'X',
            }
        );
    }

    #[test]
    fn parse_multibyte_char_in_proto_is_error_not_panic() {
        // 'é' occupies bytes 3..5 — a non-ASCII protocol field must be a
        // typed error, never a panic.
        let input = "KER\u{e9}AJSONAAAAAA_";
        assert_eq!(input.len(), VERSION_STRING_LEN);
        assert!(matches!(
            VersionString::parse(input.as_bytes()),
            Err(VersionError::UnknownProtocol { .. })
        ));
    }

    #[test]
    fn parse_multibyte_char_in_size_is_error_not_panic() {
        // 'é' occupies bytes 15..17, corrupting the size field.
        let input = "KERI10JSONAAAAA\u{e9}";
        assert_eq!(input.len(), VERSION_STRING_LEN);
        assert!(matches!(
            VersionString::parse(input.as_bytes()),
            Err(VersionError::InvalidSizeHex { .. })
        ));
    }

    // ── VersionString round-trips ────────────────────────────────────────

    #[test]
    fn parse_roundtrip() {
        let original =
            VersionString::new(Protocol::Acdc, 2, 5, SerializationKind::Cbor, 0x001a_2b3c).unwrap();
        let rendered = original.to_str();
        let (parsed, rest) = VersionString::parse(rendered.as_bytes()).unwrap();
        assert_eq!(original, parsed);
        assert!(rest.is_empty());
    }

    #[test]
    fn roundtrip_boundary_sizes() {
        for size in [0, 1, VERSION_SIZE_MAX - 1, VERSION_SIZE_MAX] {
            let original =
                VersionString::new(Protocol::Keri, 1, 0, SerializationKind::Json, size).unwrap();
            let (parsed, _) = VersionString::parse(original.to_str().as_bytes()).unwrap();
            assert_eq!(original, parsed, "size {size} must round-trip");
        }
    }

    #[test]
    fn roundtrip_all_protocols_and_kinds() {
        for proto in [Protocol::Keri, Protocol::Acdc] {
            for kind in [
                SerializationKind::Json,
                SerializationKind::Cbor,
                SerializationKind::Mgpk,
                SerializationKind::Cesr,
            ] {
                for (major, minor) in [(0, 0), (1, 0), (0xF, 0xF)] {
                    let original = VersionString::new(proto, major, minor, kind, 42).unwrap();
                    let (parsed, _) = VersionString::parse(original.to_str().as_bytes()).unwrap();
                    assert_eq!(original, parsed);
                }
            }
        }
    }

    #[test]
    fn serialization_kind_roundtrip() {
        for kind in [
            SerializationKind::Json,
            SerializationKind::Cbor,
            SerializationKind::Mgpk,
            SerializationKind::Cesr,
        ] {
            let repr = kind.as_str();
            let parsed = SerializationKind::from_repr(repr).unwrap();
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn protocol_roundtrip() {
        for proto in [Protocol::Keri, Protocol::Acdc] {
            let repr = proto.as_str();
            let parsed = Protocol::from_repr(repr).unwrap();
            assert_eq!(proto, parsed);
        }
    }

    // ── VersionStringV2 parsing (keripy test vectors) ────────────────────

    #[test]
    fn parse_v2_keri_json_size_zero() {
        let (parsed, rest) = VersionStringV2::parse(b"KERICAACAAJSONAAAA.").unwrap();
        assert_eq!(parsed.proto(), Protocol::Keri);
        assert_eq!(parsed.proto_major(), 2);
        assert_eq!(parsed.proto_minor(), 0);
        assert_eq!(parsed.genus_major(), 2);
        assert_eq!(parsed.genus_minor(), 0);
        assert_eq!(parsed.kind(), SerializationKind::Json);
        assert_eq!(parsed.size(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_keri_json_size_65() {
        let (parsed, rest) = VersionStringV2::parse(b"KERICAACAAJSONAABB.").unwrap();
        assert_eq!(parsed.proto(), Protocol::Keri);
        assert_eq!(parsed.proto_major(), 2);
        assert_eq!(parsed.proto_minor(), 0);
        assert_eq!(parsed.genus_major(), 2);
        assert_eq!(parsed.genus_minor(), 0);
        assert_eq!(parsed.kind(), SerializationKind::Json);
        assert_eq!(parsed.size(), 65);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_acdc_json_size_86() {
        let (parsed, rest) = VersionStringV2::parse(b"ACDCCAACAAJSONAABW.").unwrap();
        assert_eq!(parsed.proto(), Protocol::Acdc);
        assert_eq!(parsed.proto_major(), 2);
        assert_eq!(parsed.proto_minor(), 0);
        assert_eq!(parsed.genus_major(), 2);
        assert_eq!(parsed.genus_minor(), 0);
        assert_eq!(parsed.kind(), SerializationKind::Json);
        assert_eq!(parsed.size(), 86);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_keri_mgpk_size_zero() {
        let (parsed, rest) = VersionStringV2::parse(b"KERICAACAAMGPKAAAA.").unwrap();
        assert_eq!(parsed.proto(), Protocol::Keri);
        assert_eq!(parsed.proto_major(), 2);
        assert_eq!(parsed.proto_minor(), 0);
        assert_eq!(parsed.genus_major(), 2);
        assert_eq!(parsed.genus_minor(), 0);
        assert_eq!(parsed.kind(), SerializationKind::Mgpk);
        assert_eq!(parsed.size(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_keri_json_versioned() {
        // pvrsn=(2,1), gvrsn=(2,1)
        let (parsed, rest) = VersionStringV2::parse(b"KERICABCABJSONAAAA.").unwrap();
        assert_eq!(parsed.proto(), Protocol::Keri);
        assert_eq!(parsed.proto_major(), 2);
        assert_eq!(parsed.proto_minor(), 1);
        assert_eq!(parsed.genus_major(), 2);
        assert_eq!(parsed.genus_minor(), 1);
        assert_eq!(parsed.kind(), SerializationKind::Json);
        assert_eq!(parsed.size(), 0);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_v2_returns_rest() {
        let (_, rest) = VersionStringV2::parse(b"KERICAACAAJSONAAAA.trailing").unwrap();
        assert_eq!(rest, b"trailing");
    }

    #[test]
    fn parse_v2_too_short_reports_missing_bytes() {
        let result = VersionStringV2::parse(b"KERICAACAAJSON");
        assert_eq!(result.unwrap_err(), VersionError::Truncated { needed: 5 });
    }

    #[test]
    fn parse_v2_wrong_proto_major() {
        // proto_major = 1 (B64 'B') instead of 2 (B64 'C')
        let result = VersionStringV2::parse(b"KERIBAACAAJSONAAAA.");
        assert_eq!(
            result.unwrap_err(),
            VersionError::UnsupportedMajor {
                field: "proto_major",
                found: 1,
            }
        );
    }

    #[test]
    fn parse_v2_wrong_genus_major() {
        // genus_major = 1 (B64 'B') instead of 2 (B64 'C')
        let result = VersionStringV2::parse(b"KERICAABAAJSONAAAA.");
        assert_eq!(
            result.unwrap_err(),
            VersionError::UnsupportedMajor {
                field: "genus_major",
                found: 1,
            }
        );
    }

    #[test]
    fn parse_v2_unknown_kind() {
        let result = VersionStringV2::parse(b"KERICAACAAXXXXAAAA.");
        assert_eq!(
            result.unwrap_err(),
            VersionError::UnknownKind { found: *b"XXXX" }
        );
    }

    #[test]
    fn parse_v2_wrong_terminator() {
        let result = VersionStringV2::parse(b"KERICAACAAJSONAAAA_");
        assert_eq!(
            result.unwrap_err(),
            VersionError::MissingTerminator {
                expected: '.',
                found: b'_',
            }
        );
    }

    #[test]
    fn parse_v2_invalid_base64_size() {
        let result = VersionStringV2::parse(b"KERICAACAAJSONAA+A.");
        assert!(matches!(
            result.unwrap_err(),
            VersionError::Base64 { field: "size", .. }
        ));
    }

    #[test]
    fn parse_v2_cesr_kind() {
        let (parsed, _) = VersionStringV2::parse(b"KERICAACAACESRAAAA.").unwrap();
        assert_eq!(parsed.kind(), SerializationKind::Cesr);
    }

    #[test]
    fn parse_v2_cbor_kind() {
        let (parsed, _) = VersionStringV2::parse(b"KERICAACAACBORAAAA.").unwrap();
        assert_eq!(parsed.kind(), SerializationKind::Cbor);
    }

    // ── VersionStringV2 construction & rendering ─────────────────────────

    fn make_v2(
        proto: Protocol,
        proto_minor: u16,
        genus_minor: u16,
        kind: SerializationKind,
        size: u32,
    ) -> VersionStringV2 {
        VersionStringV2::new(proto, proto_minor, genus_minor, kind, size).unwrap()
    }

    #[test]
    fn v2_to_str_keri_json_size_zero() {
        let vs = make_v2(Protocol::Keri, 0, 0, SerializationKind::Json, 0);
        assert_eq!(vs.to_str(), "KERICAACAAJSONAAAA.");
    }

    #[test]
    fn v2_to_str_keri_json_size_65() {
        let vs = make_v2(Protocol::Keri, 0, 0, SerializationKind::Json, 65);
        assert_eq!(vs.to_str(), "KERICAACAAJSONAABB.");
    }

    #[test]
    fn v2_to_str_acdc_json_size_86() {
        let vs = make_v2(Protocol::Acdc, 0, 0, SerializationKind::Json, 86);
        assert_eq!(vs.to_str(), "ACDCCAACAAJSONAABW.");
    }

    #[test]
    fn v2_to_str_keri_mgpk_size_zero() {
        let vs = make_v2(Protocol::Keri, 0, 0, SerializationKind::Mgpk, 0);
        assert_eq!(vs.to_str(), "KERICAACAAMGPKAAAA.");
    }

    #[test]
    fn v2_to_str_versioned() {
        let vs = make_v2(Protocol::Keri, 1, 1, SerializationKind::Json, 0);
        assert_eq!(vs.to_str(), "KERICABCABJSONAAAA.");
    }

    #[test]
    fn v2_to_str_length_is_19() {
        let vs = make_v2(Protocol::Keri, 0, 0, SerializationKind::Json, 0);
        assert_eq!(vs.to_str().len(), VERSION_STRING_V2_LEN);
    }

    #[test]
    fn v2_to_str_cbor() {
        let vs = make_v2(Protocol::Keri, 0, 0, SerializationKind::Cbor, 0);
        assert_eq!(vs.to_str(), "KERICAACAACBORAAAA.");
    }

    #[test]
    fn v2_to_str_cesr() {
        let vs = make_v2(Protocol::Keri, 0, 0, SerializationKind::Cesr, 0);
        assert_eq!(vs.to_str(), "KERICAACAACESRAAAA.");
    }

    #[test]
    fn v2_majors_are_fixed_at_two() {
        let vs = make_v2(Protocol::Keri, 0, 0, SerializationKind::Json, 0);
        assert_eq!(vs.proto_major(), 2);
        assert_eq!(vs.genus_major(), 2);
    }

    #[test]
    fn v2_rejects_oversize_minor_at_construction() {
        let result = VersionStringV2::new(
            Protocol::Keri,
            V2_MINOR_MAX + 1,
            0,
            SerializationKind::Json,
            0,
        );
        assert_eq!(
            result.unwrap_err(),
            VersionError::FieldOverflow {
                field: "proto_minor",
                max: u32::from(V2_MINOR_MAX),
            }
        );
    }

    #[test]
    fn v2_rejects_oversize_size_at_construction() {
        let result = VersionStringV2::new(
            Protocol::Keri,
            0,
            0,
            SerializationKind::Json,
            VERSION_V2_SIZE_MAX + 1,
        );
        assert_eq!(
            result.unwrap_err(),
            VersionError::FieldOverflow {
                field: "size",
                max: VERSION_V2_SIZE_MAX,
            }
        );
    }

    // ── VersionStringV2 round-trips ──────────────────────────────────────

    #[test]
    fn v2_roundtrip_keri_json_size_zero() {
        let original = make_v2(Protocol::Keri, 0, 0, SerializationKind::Json, 0);
        let rendered = original.to_str();
        let (parsed, rest) = VersionStringV2::parse(rendered.as_bytes()).unwrap();
        assert_eq!(original, parsed);
        assert!(rest.is_empty());
    }

    #[test]
    fn v2_roundtrip_boundary_sizes() {
        for size in [0, 1, VERSION_V2_SIZE_MAX - 1, VERSION_V2_SIZE_MAX] {
            let original = make_v2(Protocol::Keri, 0, 0, SerializationKind::Json, size);
            let (parsed, _) = VersionStringV2::parse(original.to_str().as_bytes()).unwrap();
            assert_eq!(original, parsed, "size {size} must round-trip");
        }
    }

    #[test]
    fn v2_roundtrip_boundary_minors() {
        for minor in [0, 1, V2_MINOR_MAX - 1, V2_MINOR_MAX] {
            let original = make_v2(Protocol::Acdc, minor, minor, SerializationKind::Cbor, 86);
            let (parsed, _) = VersionStringV2::parse(original.to_str().as_bytes()).unwrap();
            assert_eq!(original, parsed, "minor {minor} must round-trip");
        }
    }
}
