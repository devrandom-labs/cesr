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
use cesr::core::version::VersionError;

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

    /// Malformed version string. A truncated version string maps to
    /// [`ParseError::NeedBytes`] instead — see the `From<VersionError>`
    /// impl — so this variant never carries [`VersionError::Truncated`].
    #[error(transparent)]
    Version(VersionError),
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
            _ => Self::Malformed(e.to_string()),
        }
    }
}

impl From<ValidationError> for ParseError {
    fn from(e: ValidationError) -> Self {
        Self::Malformed(e.to_string())
    }
}

impl From<CounterCodeError> for ParseError {
    fn from(e: CounterCodeError) -> Self {
        match e {
            CounterCodeError::StreamTooShort { need } => Self::NeedBytes(need),
            CounterCodeError::NotACounter => {
                Self::Malformed("expected counter code '-'".to_owned())
            }
            CounterCodeError::UnknownCode(s) => Self::UnknownCounterCode(s),
        }
    }
}

impl From<IndexerParseError> for ParseError {
    fn from(e: IndexerParseError) -> Self {
        match e {
            IndexerParseError::EmptyStream => Self::NeedBytes(1),
            IndexerParseError::StreamTooShort { need, .. } => Self::NeedBytes(need),
            IndexerParseError::UnknownCode(s) => {
                Self::Malformed(format!("unknown indexer code: {s}"))
            }
            _ => Self::Malformed(e.to_string()),
        }
    }
}

impl From<IndexerValidationError> for ParseError {
    fn from(e: IndexerValidationError) -> Self {
        Self::Malformed(e.to_string())
    }
}

impl From<CesrUtilsError> for ParseError {
    fn from(e: CesrUtilsError) -> Self {
        Self::Malformed(e.to_string())
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        Self::Malformed(e.to_string())
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
    fn from_validation_error() {
        let e: ParseError = ValidationError::MissingRaw {
            code: "A".to_owned(),
        }
        .into();
        assert!(matches!(e, ParseError::Malformed(_)));
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
    fn from_counter_code_error_not_a_counter() {
        let e: ParseError = CounterCodeError::NotACounter.into();
        assert!(matches!(e, ParseError::Malformed(_)));
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
    fn from_indexer_validation_error() {
        use cesr::core::indexer::code::IndexedSigCode;

        let e: ParseError = IndexerValidationError::IndexTooLarge {
            code: IndexedSigCode::Ed25519,
            index: 999,
            max: 63,
        }
        .into();
        assert!(matches!(e, ParseError::Malformed(_)));
    }

    #[test]
    fn from_cesr_utils_error() {
        let e: ParseError = CesrUtilsError::IntegerOverflow.into();
        assert!(matches!(e, ParseError::Malformed(_)));
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
}
