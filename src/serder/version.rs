//! KERI version string parsing and generation.
//!
//! Version strings are 17-byte ASCII headers that identify the protocol,
//! version, serialization kind, and serialized size of a KERI event.
//!
//! V1 format: `KERI10JSON00025d_`
//! - 4 chars protocol (`KERI` or `ACDC`)
//! - 1 hex char major version
//! - 1 hex char minor version
//! - 4 chars serialization kind (`JSON`, `CBOR`, `MGPK`, `CESR`)
//! - 6 hex chars size (zero-padded)
//! - `_` terminator

use crate::serder::error::SerderError;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{format, string::String};

/// Total length of a V1 version string in bytes.
pub const VERSION_STRING_LEN: usize = 17;

const PROTO_LEN: usize = 4;
const VERSION_LEN: usize = 2;
const KIND_LEN: usize = 4;
const SIZE_LEN: usize = 6;

/// Serialization format for the event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerKind {
    /// JSON encoding.
    Json,
    /// CBOR encoding.
    Cbor,
    /// `MessagePack` encoding.
    Mgpk,
    /// Native CESR encoding.
    Cesr,
}

impl SerKind {
    /// The 4-character wire representation.
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
    /// Returns [`SerderError::InvalidVersionString`] if the input is not a
    /// recognized serialization kind.
    pub fn from_repr(s: &str) -> Result<Self, SerderError> {
        match s {
            "JSON" => Ok(Self::Json),
            "CBOR" => Ok(Self::Cbor),
            "MGPK" => Ok(Self::Mgpk),
            "CESR" => Ok(Self::Cesr),
            _ => Err(SerderError::InvalidVersionString(format!(
                "unknown serialization kind: {s}"
            ))),
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
    /// Returns [`SerderError::InvalidVersionString`] if the input is not a
    /// recognized protocol.
    pub fn from_repr(s: &str) -> Result<Self, SerderError> {
        match s {
            "KERI" => Ok(Self::Keri),
            "ACDC" => Ok(Self::Acdc),
            _ => Err(SerderError::InvalidVersionString(format!(
                "unknown protocol: {s}"
            ))),
        }
    }
}

/// A parsed KERI version string.
///
/// Encodes the protocol, version, serialization kind, and total serialized
/// size of a KERI event message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionString {
    /// The protocol identifier.
    pub proto: Protocol,
    /// Major version number (0..=15).
    pub major: u8,
    /// Minor version number (0..=15).
    pub minor: u8,
    /// Serialization format.
    pub kind: SerKind,
    /// Total serialized message size in bytes.
    pub size: u32,
}

impl VersionString {
    /// Create a new version string with the given parameters.
    #[must_use]
    pub const fn new(proto: Protocol, major: u8, minor: u8, kind: SerKind, size: u32) -> Self {
        Self {
            proto,
            major,
            minor,
            kind,
            size,
        }
    }

    /// KERI v1.0 JSON with zero size (to be filled after serialization).
    #[must_use]
    pub const fn keri_json_v1() -> Self {
        Self::new(Protocol::Keri, 1, 0, SerKind::Json, 0)
    }

    /// Return a copy with the size field updated.
    #[must_use]
    pub const fn with_size(self, size: u32) -> Self {
        Self {
            proto: self.proto,
            major: self.major,
            minor: self.minor,
            kind: self.kind,
            size,
        }
    }

    /// Render the 17-byte version string.
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

    /// Parse a version string from the first 17 bytes of `input`.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::InvalidVersionString`] if the input is too
    /// short, contains unrecognized fields, or is missing the terminator.
    pub fn parse(input: &str) -> Result<Self, SerderError> {
        if input.len() < VERSION_STRING_LEN {
            return Err(SerderError::InvalidVersionString(format!(
                "input too short: expected {VERSION_STRING_LEN} bytes, got {}",
                input.len()
            )));
        }

        let vs = &input[..VERSION_STRING_LEN];

        let proto_str = &vs[..PROTO_LEN];
        let proto = Protocol::from_repr(proto_str)?;

        let version_start = PROTO_LEN;
        let major_ch = &vs[version_start..=version_start];
        let minor_ch = &vs[version_start + 1..version_start + VERSION_LEN];

        let major = u8::from_str_radix(major_ch, 16).map_err(|_| {
            SerderError::InvalidVersionString(format!(
                "invalid major version hex digit: {major_ch}"
            ))
        })?;

        let minor = u8::from_str_radix(minor_ch, 16).map_err(|_| {
            SerderError::InvalidVersionString(format!(
                "invalid minor version hex digit: {minor_ch}"
            ))
        })?;

        let kind_start = PROTO_LEN + VERSION_LEN;
        let kind_str = &vs[kind_start..kind_start + KIND_LEN];
        let kind = SerKind::from_repr(kind_str)?;

        let size_start = kind_start + KIND_LEN;
        let size_str = &vs[size_start..size_start + SIZE_LEN];
        let size = u32::from_str_radix(size_str, 16).map_err(|_| {
            SerderError::InvalidVersionString(format!("invalid size hex: {size_str}"))
        })?;

        let terminator = &vs[VERSION_STRING_LEN - 1..VERSION_STRING_LEN];
        if terminator != "_" {
            return Err(SerderError::InvalidVersionString(format!(
                "missing terminator '_', found '{terminator}'"
            )));
        }

        Ok(Self {
            proto,
            major,
            minor,
            kind,
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keri_json_v1_defaults() {
        let vs = VersionString::keri_json_v1();
        assert_eq!(vs.proto, Protocol::Keri);
        assert_eq!(vs.major, 1);
        assert_eq!(vs.minor, 0);
        assert_eq!(vs.kind, SerKind::Json);
        assert_eq!(vs.size, 0);
    }

    #[test]
    fn to_str_zero_size() {
        let vs = VersionString::keri_json_v1();
        assert_eq!(vs.to_str(), "KERI10JSON000000_");
    }

    #[test]
    fn to_str_nonzero_size() {
        let vs = VersionString::keri_json_v1().with_size(0x25d);
        assert_eq!(vs.to_str(), "KERI10JSON00025d_");
    }

    #[test]
    fn parse_valid() {
        let vs = VersionString::parse("KERI10JSON00025d_").unwrap();
        assert_eq!(vs.proto, Protocol::Keri);
        assert_eq!(vs.major, 1);
        assert_eq!(vs.minor, 0);
        assert_eq!(vs.kind, SerKind::Json);
        assert_eq!(vs.size, 0x25d);
    }

    #[test]
    fn parse_roundtrip() {
        let original = VersionString::new(Protocol::Acdc, 2, 5, SerKind::Cbor, 0x001a_2b3c);
        let rendered = original.to_str();
        let parsed = VersionString::parse(&rendered).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn parse_too_short() {
        let result = VersionString::parse("KERI10JSON");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too short"));
    }

    #[test]
    fn parse_unknown_protocol() {
        let result = VersionString::parse("XXXX10JSON000000_");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unknown protocol"));
    }

    #[test]
    fn parse_unknown_kind() {
        let result = VersionString::parse("KERI10YAML000000_");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unknown serialization kind"));
    }

    #[test]
    fn parse_missing_terminator() {
        let result = VersionString::parse("KERI10JSON000000X");
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("terminator"));
    }

    #[test]
    fn ser_kind_roundtrip() {
        for kind in [SerKind::Json, SerKind::Cbor, SerKind::Mgpk, SerKind::Cesr] {
            let repr = kind.as_str();
            let parsed = SerKind::from_repr(repr).unwrap();
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
}
