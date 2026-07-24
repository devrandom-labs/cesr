#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString};
use cesr::b64::error::Error as CesrUtilsError;
use cesr::core::counter::code::CounterCodeError;
use cesr::core::indexer::error::IndexerParseError;
use cesr::core::indexer::error::IndexerValidationError;
use cesr::core::matter::error::ParsingError;
use cesr::core::matter::error::ValidationError;
use cesr::core::version::CesrVersion;
use cesr::core::version::VersionError;
use core::str::Utf8Error;

/// Which span computation failed.
///
/// Fieldless on purpose: the diagnostic set is a closed, exhaustively
/// matchable type at zero runtime cost, and two call sites cannot drift to
/// different spellings of the same condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    /// The start offset of a group within its backing buffer.
    GroupStart,
    /// The total byte span of a group.
    GroupSpan,
    /// The offset of a group's body past its counter.
    GroupOffset,
    /// The quadlet tally of a group payload.
    QuadletCount,
    /// The byte span implied by a quadlet count.
    QuadletSpan,
    /// The byte span of one element within a group.
    ElementSpan,
    /// The number of elements in a group.
    ElementCount,
    /// A `TextStream` cursor position.
    CursorPosition,
    /// The payload size declared by a version string.
    EventSize,
    /// The soft-field width of a counter code.
    CounterSoftSize,
}

impl SpanKind {
    /// The human-readable name used in [`ParseError::Overflow`]'s message.
    const fn as_str(self) -> &'static str {
        match self {
            Self::GroupStart => "group start",
            Self::GroupSpan => "group span",
            Self::GroupOffset => "group offset",
            Self::QuadletCount => "quadlet count",
            Self::QuadletSpan => "quadlet span",
            Self::ElementSpan => "element span",
            Self::ElementCount => "element count",
            Self::CursorPosition => "cursor position",
            Self::EventSize => "event size",
            Self::CounterSoftSize => "counter soft size",
        }
    }
}

impl core::fmt::Display for SpanKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors during CESR stream parsing.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Not enough bytes; caller should buffer more data and retry.
    #[error("need {0} more bytes")]
    NeedBytes(usize),

    /// Unrecognized Matter code prefix.
    #[error("unknown matter code: {0}")]
    UnknownMatterCode(String),

    /// Unrecognized counter code prefix.
    #[error("unknown counter code: {0}")]
    UnknownCounterCode(String),

    /// A primitive had the wrong code type for its position.
    #[error("unexpected code type: expected {expected}, got {got}")]
    UnexpectedCodeType {
        /// The code type that was expected at this position.
        expected: &'static str,
        /// The code type that was actually found.
        got: String,
    },

    /// Structurally invalid stream data.
    #[error("malformed CESR: {0}")]
    Malformed(String),

    /// A span, offset, or count computation overflowed or underflowed.
    #[error("span arithmetic failed for {0}")]
    Overflow(SpanKind),

    /// The lead byte is not a counter head (`-`).
    #[error(
        "expected counter code '-'{}",
        got.map_or_else(String::new, |b| format!(", got '{}'", char::from(b)))
    )]
    NotACounter {
        /// The offending lead byte, when the layer that rejected it had one.
        got: Option<u8>,
    },

    /// A nested sub-group carried the wrong counter code.
    #[error("expected {expected} counter inside {outer} group, got {got}")]
    NestedCounterMismatch {
        /// Wire letters of the enclosing group.
        outer: &'static str,
        /// The counter code the enclosing group requires.
        expected: &'static str,
        /// The counter code actually found.
        got: &'static str,
    },

    /// A genus-version code appeared where an attachment group was expected.
    #[error("genus version codes are not attachment groups")]
    GenusVersionNotAGroup,

    /// A length was not a whole multiple of its encoding unit.
    #[error("length {len} is not a multiple of {unit}")]
    Misaligned {
        /// The offending length in bytes.
        len: usize,
        /// The required multiple (4 for qb64/quadlets, 3 for qb2).
        unit: usize,
    },

    /// A field that must be UTF-8 text was not.
    #[error("invalid UTF-8 in {field}")]
    InvalidUtf8 {
        /// Name of the offending field.
        field: &'static str,
        /// The underlying decode failure, carrying the offset at which the
        /// field stopped being valid UTF-8.
        #[source]
        source: Utf8Error,
    },

    /// A count exceeded what its counter's soft field can encode.
    #[error("count {count} exceeds counter capacity {capacity}")]
    CountExceedsCapacity {
        /// The requested count.
        count: u64,
        /// The largest value the counter can carry.
        capacity: u64,
    },

    /// Group nesting exceeded the unwrapping depth limit.
    #[error("max nesting depth {max} exceeded")]
    DepthExceeded {
        /// The configured limit.
        max: usize,
    },

    /// The first byte of the stream starts no known encoding domain.
    #[error("unrecognized stream byte: 0x{byte:02x}")]
    UnknownColdStart {
        /// The offending first byte.
        byte: u8,
    },

    /// The genus version's major number selects no known parsing mode.
    #[error("unsupported genus version major={major}")]
    UnsupportedGenusVersion {
        /// The decoded major version.
        major: u32,
    },

    /// A V2-only group type was encoded with V1 counter codes.
    #[error("{group} cannot be encoded with {version:?} counters")]
    VersionMismatch {
        /// Name of the group type.
        group: &'static str,
        /// The counter version that was attempted.
        version: CesrVersion,
    },

    /// No version string was found within the search range.
    #[error("version string not found")]
    MissingVersionString,

    /// A matter primitive failed to parse.
    ///
    /// `#[error("{0}")]` + `#[source]` rather than `#[error(transparent)]`:
    /// transparent forwards `source()` to the *inner* error's own source
    /// (one hop too far — see `thiserror_impl::expand`'s `transparent.as_dyn_error()`
    /// path), so `Error::source()` would never resolve to the [`ParsingError`]
    /// itself. The explicit `#[source]` field keeps the identical
    /// transparent-style `Display` text while making `source()` return the
    /// typed error directly, which is the entire point of #208.
    #[error("{0}")]
    Matter(#[source] ParsingError),

    /// A matter primitive parsed but failed validation. See [`Self::Matter`]
    /// for why this is `#[source]` rather than `#[error(transparent)]`.
    #[error("{0}")]
    MatterValidation(#[source] ValidationError),

    /// An indexed primitive failed to parse. See [`Self::Matter`] for why
    /// this is `#[source]` rather than `#[error(transparent)]`.
    #[error("{0}")]
    Indexer(#[source] IndexerParseError),

    /// An indexed primitive parsed but failed validation. See [`Self::Matter`]
    /// for why this is `#[source]` rather than `#[error(transparent)]`.
    #[error("{0}")]
    IndexerValidation(#[source] IndexerValidationError),

    /// A CESR Base64 operation failed. See [`Self::Matter`] for why this is
    /// `#[source]` rather than `#[error(transparent)]`.
    #[error("{0}")]
    Base64(#[source] CesrUtilsError),

    /// An I/O failure surfaced through the async `Decoder` bound.
    ///
    /// Stringified because [`std::io::Error`] is not [`PartialEq`], which
    /// [`ParseError`] must remain.
    #[error("io error: {0}")]
    Io(String),

    /// Malformed version string. A truncated version string maps to
    /// [`ParseError::NeedBytes`] instead — see the `From<VersionError>`
    /// impl — so this variant never carries [`VersionError::Truncated`].
    /// See [`Self::Matter`] for why this is `#[source]` rather than
    /// `#[error(transparent)]`.
    #[error("{0}")]
    Version(#[source] VersionError),
}

impl From<VersionError> for ParseError {
    fn from(e: VersionError) -> Self {
        match e {
            VersionError::Truncated { needed } => Self::NeedBytes(needed),
            other => Self::Version(other),
        }
    }
}

impl From<ParsingError> for ParseError {
    fn from(e: ParsingError) -> Self {
        match e {
            ParsingError::EmptyStream | ParsingError::StreamTooShort(_) => Self::NeedBytes(1),
            ParsingError::UnknownMatterCode(s) => Self::UnknownMatterCode(s),
            other => Self::Matter(other),
        }
    }
}

impl From<ValidationError> for ParseError {
    fn from(e: ValidationError) -> Self {
        Self::MatterValidation(e)
    }
}

impl From<CounterCodeError> for ParseError {
    fn from(e: CounterCodeError) -> Self {
        match e {
            CounterCodeError::StreamTooShort { need } => Self::NeedBytes(need),
            CounterCodeError::NotACounter => Self::NotACounter { got: None },
            CounterCodeError::UnknownCode(s) => Self::UnknownCounterCode(s),
        }
    }
}

impl From<IndexerParseError> for ParseError {
    fn from(e: IndexerParseError) -> Self {
        match e {
            IndexerParseError::EmptyStream => Self::NeedBytes(1),
            IndexerParseError::StreamTooShort { need, .. } => Self::NeedBytes(need),
            other => Self::Indexer(other),
        }
    }
}

impl From<IndexerValidationError> for ParseError {
    fn from(e: IndexerValidationError) -> Self {
        Self::IndexerValidation(e)
    }
}

impl From<CesrUtilsError> for ParseError {
    fn from(e: CesrUtilsError) -> Self {
        Self::Base64(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    reason = "test code: panics and type conversions acceptable"
)]
mod tests {
    use super::*;
    use cesr::core::matter::MatterPart;

    #[test]
    fn from_parsing_error_empty_stream() {
        let e: ParseError = ParsingError::EmptyStream.into();
        assert!(matches!(e, ParseError::NeedBytes(1)));
    }

    #[test]
    fn from_parsing_error_stream_too_short() {
        let e: ParseError = ParsingError::StreamTooShort(MatterPart::Head).into();
        assert!(matches!(e, ParseError::NeedBytes(1)));
    }

    #[test]
    fn from_parsing_error_unknown_code() {
        let e: ParseError = ParsingError::UnknownMatterCode("XY".to_owned()).into();
        assert_eq!(e, ParseError::UnknownMatterCode("XY".to_owned()));
    }

    #[test]
    fn from_counter_code_error() {
        let e: ParseError = CounterCodeError::UnknownCode("-Z".to_owned()).into();
        assert_eq!(e, ParseError::UnknownCounterCode("-Z".to_owned()));
    }

    #[test]
    fn from_counter_code_error_stream_too_short() {
        let e: ParseError = CounterCodeError::StreamTooShort { need: 3 }.into();
        assert_eq!(e, ParseError::NeedBytes(3));
    }

    #[test]
    fn from_indexer_parse_error_empty() {
        let e: ParseError = IndexerParseError::EmptyStream.into();
        assert!(matches!(e, ParseError::NeedBytes(1)));
    }

    #[test]
    fn from_indexer_parse_error_too_short() {
        let e: ParseError = IndexerParseError::StreamTooShort { need: 4, got: 2 }.into();
        assert!(matches!(e, ParseError::NeedBytes(4)));
    }

    #[test]
    fn from_version_error_truncated_is_need_bytes() {
        let e: ParseError = VersionError::Truncated { needed: 5 }.into();
        assert_eq!(e, ParseError::NeedBytes(5));
    }

    #[test]
    fn from_version_error_other_is_version() {
        let e: ParseError = VersionError::UnknownProtocol { found: *b"XXXX" }.into();
        assert_eq!(
            e,
            ParseError::Version(VersionError::UnknownProtocol { found: *b"XXXX" })
        );
    }

    #[test]
    fn display_need_bytes() {
        let e = ParseError::NeedBytes(42);
        assert_eq!(e.to_string(), "need 42 more bytes");
    }

    #[test]
    fn display_malformed() {
        let e = ParseError::Malformed("bad data".to_owned());
        assert_eq!(e.to_string(), "malformed CESR: bad data");
    }

    #[test]
    fn display_unexpected_code_type() {
        let e = ParseError::UnexpectedCodeType {
            expected: "Ed25519",
            got: "ECDSA".to_owned(),
        };
        assert_eq!(
            e.to_string(),
            "unexpected code type: expected Ed25519, got ECDSA"
        );
    }

    #[test]
    fn display_span_kinds_are_distinct_and_named() {
        assert_eq!(
            ParseError::Overflow(SpanKind::GroupStart).to_string(),
            "span arithmetic failed for group start"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::GroupSpan).to_string(),
            "span arithmetic failed for group span"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::GroupOffset).to_string(),
            "span arithmetic failed for group offset"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::QuadletCount).to_string(),
            "span arithmetic failed for quadlet count"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::QuadletSpan).to_string(),
            "span arithmetic failed for quadlet span"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::ElementSpan).to_string(),
            "span arithmetic failed for element span"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::ElementCount).to_string(),
            "span arithmetic failed for element count"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::CursorPosition).to_string(),
            "span arithmetic failed for cursor position"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::EventSize).to_string(),
            "span arithmetic failed for event size"
        );
        assert_eq!(
            ParseError::Overflow(SpanKind::CounterSoftSize).to_string(),
            "span arithmetic failed for counter soft size"
        );
    }

    #[test]
    fn display_structural_variants() {
        assert_eq!(
            ParseError::Misaligned { len: 7, unit: 4 }.to_string(),
            "length 7 is not a multiple of 4"
        );
        assert_eq!(
            ParseError::InvalidUtf8 {
                field: "counter soft field",
                source: core::str::from_utf8(&core::hint::black_box([0xff])).unwrap_err(),
            }
            .to_string(),
            "invalid UTF-8 in counter soft field"
        );
        assert_eq!(
            ParseError::CountExceedsCapacity {
                count: 4096,
                capacity: 4095
            }
            .to_string(),
            "count 4096 exceeds counter capacity 4095"
        );
        assert_eq!(
            ParseError::DepthExceeded { max: 8 }.to_string(),
            "max nesting depth 8 exceeded"
        );
        assert_eq!(
            ParseError::UnknownColdStart { byte: 0x7f }.to_string(),
            "unrecognized stream byte: 0x7f"
        );
        assert_eq!(
            ParseError::UnsupportedGenusVersion { major: 3 }.to_string(),
            "unsupported genus version major=3"
        );
        assert_eq!(
            ParseError::MissingVersionString.to_string(),
            "version string not found"
        );
        assert_eq!(
            ParseError::GenusVersionNotAGroup.to_string(),
            "genus version codes are not attachment groups"
        );
    }

    #[test]
    fn display_not_a_counter_with_and_without_byte() {
        assert_eq!(
            ParseError::NotACounter { got: Some(b'A') }.to_string(),
            "expected counter code '-', got 'A'"
        );
        assert_eq!(
            ParseError::NotACounter { got: None }.to_string(),
            "expected counter code '-'"
        );
    }

    #[test]
    fn display_nested_counter_mismatch() {
        assert_eq!(
            ParseError::NestedCounterMismatch {
                outer: "-F",
                expected: "-A",
                got: "-B",
            }
            .to_string(),
            "expected -A counter inside -F group, got -B"
        );
    }

    // `CesrVersion` has no `Display`, so this message renders via `Debug`.
    // Asserting the exact string makes that a tested contract rather than an
    // accident of the current derive.
    #[test]
    fn display_version_mismatch() {
        assert_eq!(
            ParseError::VersionMismatch {
                group: "V2-only group type",
                version: CesrVersion::V1,
            }
            .to_string(),
            "V2-only group type cannot be encoded with V1 counters"
        );
    }

    #[test]
    fn parsing_error_keeps_typed_source() {
        let original = ValidationError::MissingRaw {
            code: "A".to_owned(),
        };
        let e: ParseError = ValidationError::MissingRaw {
            code: "A".to_owned(),
        }
        .into();
        assert_eq!(e, ParseError::MatterValidation(original));
    }

    #[test]
    fn indexer_unknown_code_keeps_typed_source() {
        let original = IndexerParseError::UnknownCode("ZZ".to_owned());
        let e: ParseError = IndexerParseError::UnknownCode("ZZ".to_owned()).into();
        assert_eq!(e, ParseError::Indexer(original));
    }

    #[test]
    fn indexer_validation_keeps_typed_source() {
        use cesr::core::indexer::code::IndexedSigCode;

        let original = IndexerValidationError::IndexTooLarge {
            code: IndexedSigCode::Ed25519,
            index: 999,
            max: 63,
        };
        let e: ParseError = IndexerValidationError::IndexTooLarge {
            code: IndexedSigCode::Ed25519,
            index: 999,
            max: 63,
        }
        .into();
        assert_eq!(e, ParseError::IndexerValidation(original));
    }

    #[test]
    fn base64_error_keeps_typed_source() {
        let e: ParseError = CesrUtilsError::IntegerOverflow.into();
        assert_eq!(e, ParseError::Base64(CesrUtilsError::IntegerOverflow));
    }

    #[test]
    fn not_a_counter_has_no_byte_at_the_from_boundary() {
        let e: ParseError = CounterCodeError::NotACounter.into();
        assert_eq!(e, ParseError::NotACounter { got: None });
    }

    // The `source()` chain is the whole point of #208: before this change
    // every one of these returned `None` because the error was a String.
    #[cfg(feature = "std")]
    #[test]
    fn typed_variants_expose_their_source() {
        use std::error::Error as StdError;

        let e: ParseError = ValidationError::MissingRaw {
            code: "A".to_owned(),
        }
        .into();
        let src = e.source().expect("MatterValidation must expose a source");
        assert!(src.downcast_ref::<ValidationError>().is_some());
    }

    // The original design discarded `Utf8Error` on the (false) assumption it
    // wasn't `PartialEq`. It is, so the source is now carried and its
    // decode offset is recoverable via `source()`.
    #[cfg(feature = "std")]
    #[test]
    fn invalid_utf8_exposes_the_decode_offset() {
        use std::error::Error as StdError;

        let utf8_err = core::str::from_utf8(&core::hint::black_box([0x41, 0xff])).unwrap_err();
        let e = ParseError::InvalidUtf8 {
            field: "counter soft field",
            source: utf8_err,
        };
        assert_eq!(e.to_string(), "invalid UTF-8 in counter soft field");
        let src = e.source().expect("InvalidUtf8 must expose its source");
        let recovered = src
            .downcast_ref::<core::str::Utf8Error>()
            .expect("source must be a Utf8Error");
        assert_eq!(recovered.valid_up_to(), 1);
    }

    // Truncation is backpressure, not an error. Every upstream "need more
    // bytes" shape must still land on NeedBytes and never on a typed source
    // variant — this is the streaming invariant the `#[from]` derive would
    // have silently broken.
    #[test]
    fn truncation_still_maps_to_need_bytes() {
        assert_eq!(
            ParseError::from(ParsingError::EmptyStream),
            ParseError::NeedBytes(1)
        );
        assert_eq!(
            ParseError::from(ParsingError::StreamTooShort(MatterPart::Head)),
            ParseError::NeedBytes(1)
        );
        assert_eq!(
            ParseError::from(IndexerParseError::EmptyStream),
            ParseError::NeedBytes(1)
        );
        assert_eq!(
            ParseError::from(IndexerParseError::StreamTooShort { need: 4, got: 2 }),
            ParseError::NeedBytes(4)
        );
        assert_eq!(
            ParseError::from(CounterCodeError::StreamTooShort { need: 3 }),
            ParseError::NeedBytes(3)
        );
        assert_eq!(
            ParseError::from(VersionError::Truncated { needed: 5 }),
            ParseError::NeedBytes(5)
        );
    }
}
