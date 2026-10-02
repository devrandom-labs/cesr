use cesr::core::version::{
    CesrVersion, SerializationKind, VERSION_STRING_LEN, VERSION_STRING_V2_LEN, VersionString,
    VersionStringV2,
};

use crate::cold::ColdCode;
use crate::error::ParseError;
use crate::error::SpanKind;

/// Match the first encoded map field without accepting a later `v` string.
/// A matching short prefix remains incomplete; a differing byte is malformed.
fn first_field_prefix(input: &[u8], start: usize, expected: &[u8]) -> Result<usize, ParseError> {
    let available = input.get(start..).ok_or(ParseError::NeedBytes(1))?;
    let compared = available.len().min(expected.len());
    if available[..compared] != expected[..compared] {
        return Err(ParseError::MissingVersionString);
    }
    if available.len() < expected.len() {
        return Err(ParseError::NeedBytes(expected.len() - available.len()));
    }
    start
        .checked_add(expected.len())
        .ok_or(ParseError::Overflow(SpanKind::EventSize))
}

fn binary_map_start(input: &[u8], cold: ColdCode) -> Result<usize, ParseError> {
    let first = *input.first().ok_or(ParseError::NeedBytes(1))?;
    let header = match (cold, first) {
        (ColdCode::Cbor, 0xa1..=0xb7 | 0xbf) | (ColdCode::MessagePack, 0x81..=0x8f) => 1,
        (ColdCode::Cbor, 0xb8) => 2,
        (ColdCode::Cbor, 0xb9) | (ColdCode::MessagePack, 0xde) => 3,
        (ColdCode::Cbor, 0xba) | (ColdCode::MessagePack, 0xdf) => 5,
        (ColdCode::Cbor, 0xbb) => 9,
        _ => return Err(ParseError::MissingVersionString),
    };
    let head = input
        .get(..header)
        .ok_or_else(|| ParseError::NeedBytes(header - input.len()))?;
    if header > 1 && head[1..].iter().all(|byte| *byte == 0) {
        return Err(ParseError::MissingVersionString);
    }
    Ok(header)
}

fn binary_version_offset(input: &[u8], cold: ColdCode) -> Result<usize, ParseError> {
    let start = binary_map_start(input, cold)?;
    let key_start = binary_text_start(input, start, cold, 1)?;
    let value_start = first_field_prefix(input, key_start, b"v")?;
    binary_text_start(input, value_start, cold, VERSION_STRING_LEN)
}

/// Size a CBOR or `MessagePack` text header without decoding the field value.
/// Both formats allow compact and extended length spellings for the same text.
fn binary_text_start(
    input: &[u8],
    start: usize,
    cold: ColdCode,
    expected: usize,
) -> Result<usize, ParseError> {
    let first = *input.get(start).ok_or(ParseError::NeedBytes(1))?;
    let (short_len, width) = match (cold, first) {
        (ColdCode::Cbor, 0x60..=0x77) => (u64::from(first - 0x60), 0),
        (ColdCode::Cbor, 0x78) | (ColdCode::MessagePack, 0xd9) => (0, 1),
        (ColdCode::Cbor, 0x79) | (ColdCode::MessagePack, 0xda) => (0, 2),
        (ColdCode::Cbor, 0x7a) | (ColdCode::MessagePack, 0xdb) => (0, 4),
        (ColdCode::Cbor, 0x7b) => (0, 8),
        (ColdCode::MessagePack, 0xa0..=0xbf) => (u64::from(first - 0xa0), 0),
        _ => return Err(ParseError::MissingVersionString),
    };
    let end = start
        .checked_add(1 + width)
        .ok_or(ParseError::Overflow(SpanKind::EventSize))?;
    let length = if width == 0 {
        short_len
    } else {
        let header = input
            .get(start + 1..end)
            .ok_or_else(|| ParseError::NeedBytes(end - input.len()))?;
        header
            .iter()
            .fold(0_u64, |length, byte| (length << 8) | u64::from(*byte))
    };
    if length != u64::try_from(expected).unwrap_or(u64::MAX) {
        return Err(ParseError::MissingVersionString);
    }
    Ok(end)
}

/// Cursor over the first JSON field name and separator. Only `v` is valid.
/// A partially received whitespace run is scanned once across calls.
pub(crate) struct JsonVersionHead {
    offset: usize,
    state: JsonHeadState,
}

#[derive(Clone, Copy)]
enum JsonHeadState {
    BeforeKey,
    KeyV,
    KeyClose,
    BeforeColon,
    BeforeValue,
    Complete,
}

impl JsonVersionHead {
    pub(crate) const fn new() -> Self {
        Self {
            offset: 1,
            state: JsonHeadState::BeforeKey,
        }
    }

    pub(crate) fn advance(&mut self, input: &[u8]) -> Result<usize, ParseError> {
        if input.len() < self.offset {
            return Err(ParseError::Truncated {
                missing: self.offset - input.len(),
            });
        }
        loop {
            if matches!(self.state, JsonHeadState::Complete) {
                return Ok(self.offset);
            }
            let Some(byte) = input.get(self.offset).copied() else {
                return Err(ParseError::NeedBytes(1));
            };
            let whitespace = matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
            self.state = match (self.state, byte) {
                (JsonHeadState::BeforeKey, b'"') => JsonHeadState::KeyV,
                (JsonHeadState::KeyV, b'v') => JsonHeadState::KeyClose,
                (JsonHeadState::KeyClose, b'"') => JsonHeadState::BeforeColon,
                (JsonHeadState::BeforeColon, b':') => JsonHeadState::BeforeValue,
                (JsonHeadState::BeforeValue, b'"') => JsonHeadState::Complete,
                (
                    JsonHeadState::BeforeKey
                    | JsonHeadState::BeforeColon
                    | JsonHeadState::BeforeValue,
                    _,
                ) if whitespace => self.state,
                _ => return Err(ParseError::MissingVersionString),
            };
            self.offset = self
                .offset
                .checked_add(1)
                .ok_or(ParseError::Overflow(SpanKind::EventSize))?;
        }
    }

    /// Read only the first-field length declaration; the body may still be
    /// incomplete. The framer uses this for JSON, CBOR and `MessagePack`.
    pub(crate) fn event_size(input: &[u8], cold: ColdCode) -> Result<usize, ParseError> {
        let vs_offset = if matches!(cold, ColdCode::Json) {
            Self::new().advance(input)?
        } else {
            binary_version_offset(input, cold)?
        };
        Self::event_size_at(input, vs_offset, cold)
    }

    /// Check the declared size once the first field's value offset is known.
    pub(crate) fn event_size_at(
        input: &[u8],
        vs_offset: usize,
        cold: ColdCode,
    ) -> Result<usize, ParseError> {
        let tail = input
            .get(vs_offset..)
            .ok_or_else(|| ParseError::Truncated {
                missing: vs_offset.saturating_sub(input.len()),
            })?;
        let (vs, _) = match VersionString::parse(tail) {
            Ok(parsed) => parsed,
            Err(v1_error) => {
                if VersionStringV2::parse(tail).is_ok() {
                    return Err(ParseError::UnsupportedVersion {
                        version: CesrVersion::V2,
                    });
                }
                // A valid V2 header is still incomplete until its full
                // 19-byte version string arrives. Do not turn an incremental
                // read into a malformed V1 error at byte 17 or 18.
                if tail.len() < VERSION_STRING_V2_LEN
                    && tail.get(4) == Some(&b'C')
                    && tail.get(7) == Some(&b'C')
                    && tail.get(10..14).is_some_and(|kind| {
                        [
                            SerializationKind::Json,
                            SerializationKind::Cbor,
                            SerializationKind::Mgpk,
                            SerializationKind::Cesr,
                        ]
                        .iter()
                        .any(|candidate| kind == candidate.as_str().as_bytes())
                    })
                {
                    return Err(ParseError::NeedBytes(VERSION_STRING_V2_LEN - tail.len()));
                }
                return Err(v1_error.into());
            }
        };
        if !matches!(
            (cold, vs.kind()),
            (ColdCode::Json, SerializationKind::Json)
                | (ColdCode::Cbor, SerializationKind::Cbor)
                | (ColdCode::MessagePack, SerializationKind::Mgpk)
        ) {
            return Err(ParseError::VersionKindMismatch {
                cold,
                kind: vs.kind(),
            });
        }
        let size =
            usize::try_from(vs.size()).map_err(|_| ParseError::Overflow(SpanKind::EventSize))?;
        let minimum = vs_offset
            .checked_add(VERSION_STRING_LEN)
            .ok_or(ParseError::Overflow(SpanKind::EventSize))?;
        if size < minimum {
            return Err(ParseError::InvalidEventSize {
                declared: size,
                minimum,
            });
        }
        Ok(size)
    }
}
