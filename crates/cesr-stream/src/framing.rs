//! Sans-I/O framing of one V1 CESR message from a caller-owned growing prefix.
//!
//! The framer stores offsets and counters, never the input bytes. The caller
//! keeps the prefix stable while appending, then removes exactly `FrameSpan`'s
//! length after a successful return. A body with unframed attachments needs
//! either the next top-level body or explicit EOF to establish its boundary.

use crate::cold::ColdCode;
use crate::error::{LimitKind, ParseError};
use crate::group::{GroupFrameCursor, UnwrapGeneric};
use crate::message::JsonVersionHead;
use crate::parse::TextStream;
use alloc::vec;
use cesr::core::matter::code::{MatterCode, SignatureCode};
use cesr::core::version::CesrVersion;

/// Caller-selected limits for V1 messages and V1/V2 attachment groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    /// Maximum serialized body size declared by a version string.
    pub max_body_bytes: usize,
    /// Maximum bytes of attachments after one body, or one bare group.
    pub max_attachment_bytes: usize,
    /// Maximum number of top-level groups following one body.
    pub max_attachment_groups: usize,
    /// Maximum element count declared by any one group.
    pub max_group_elements: usize,
    /// Maximum recognized signature primitives across direct groups and V1
    /// universal enclosures, including nested table switches.
    pub max_signatures: usize,
    /// Maximum child groups inside each universal enclosure.
    pub max_nested_groups: usize,
    /// Maximum universal-enclosure nesting depth (outer enclosure is one).
    pub max_nesting_depth: usize,
}

impl FrameLimits {
    pub(crate) fn scan_enclosure(
        self,
        payload: &[u8],
        prior_signatures: usize,
        version: CesrVersion,
    ) -> Result<usize, ParseError> {
        if self.max_nesting_depth == 0 {
            return Err(ParseError::LimitExceeded {
                kind: LimitKind::NestingDepth,
                limit: 0,
                actual: 1,
            });
        }
        let (initial_version, initial_offset) = Self::enclosed_version(payload, version)?;
        let mut stack = vec![(payload, initial_offset, 1usize, initial_version)];
        let mut nested_groups = 0usize;
        let mut signatures = prior_signatures;
        while let Some((bytes, cursor, depth, level_version)) = stack.pop() {
            if cursor == bytes.len() {
                continue;
            }
            let tail = bytes
                .get(cursor..)
                .ok_or(ParseError::Overflow(crate::error::SpanKind::GroupSpan))?;
            if tail.first() != Some(&b'-') {
                let (consumed, atom_signatures) = self.skip_enclosed_atom(tail)?;
                signatures = signatures.saturating_add(atom_signatures);
                if signatures > self.max_signatures {
                    return Err(ParseError::LimitExceeded {
                        kind: LimitKind::Signatures,
                        limit: self.max_signatures,
                        actual: signatures,
                    });
                }
                stack.push((bytes, cursor + consumed, depth, level_version));
                continue;
            }
            self.enter_nested_group(&mut nested_groups)?;
            let next = match level_version {
                CesrVersion::V1 => GroupFrameCursor::new_v1(tail),
                CesrVersion::V2 => GroupFrameCursor::new_v2(tail),
            };
            let mut group = next.map_err(|error| match error {
                ParseError::NeedBytes(missing) => ParseError::Truncated { missing },
                other => other,
            })?;
            self.check_elements(&group)?;
            let end = group
                .advance_limited(
                    tail,
                    usize::MAX,
                    self.max_group_elements,
                    self.max_signatures.saturating_sub(signatures),
                )
                .map_err(|error| match error {
                    ParseError::NeedBytes(missing) => ParseError::Truncated { missing },
                    ParseError::LimitExceeded {
                        kind: LimitKind::Signatures,
                        actual,
                        ..
                    } => ParseError::LimitExceeded {
                        kind: LimitKind::Signatures,
                        limit: self.max_signatures,
                        actual: signatures.saturating_add(actual),
                    },
                    other => other,
                })?;
            signatures = signatures.saturating_add(group.signature_count());
            stack.push((bytes, cursor + end, depth, level_version));
            if let Some(inner) = group.enclosing_payload(tail)? {
                let next_depth = depth.saturating_add(1);
                if next_depth > self.max_nesting_depth {
                    return Err(ParseError::LimitExceeded {
                        kind: LimitKind::NestingDepth,
                        limit: self.max_nesting_depth,
                        actual: next_depth,
                    });
                }
                let (inner_version, inner_offset) = Self::enclosed_version(inner, level_version)?;
                stack.push((inner, inner_offset, next_depth, inner_version));
            }
        }
        Ok(signatures - prior_signatures)
    }

    fn skip_enclosed_atom(self, input: &[u8]) -> Result<(usize, usize), ParseError> {
        let first = input.first().ok_or(ParseError::NeedBytes(1))?;
        match ColdCode::detect(*first)? {
            cold @ (ColdCode::Json | ColdCode::Cbor | ColdCode::MessagePack) => {
                let size = JsonVersionHead::event_size(input, cold)?;
                if size > self.max_body_bytes {
                    return Err(ParseError::LimitExceeded {
                        kind: LimitKind::BodyBytes,
                        limit: self.max_body_bytes,
                        actual: size,
                    });
                }
                if size > input.len() {
                    return Err(ParseError::Truncated {
                        missing: size - input.len(),
                    });
                }
                Ok((size, 0))
            }
            ColdCode::CesrBase64 => {
                let code = MatterCode::from_base64_stream(input)?;
                let mut primitive = TextStream::new(input);
                primitive.skip_matter()?;
                Ok((
                    primitive.offset(),
                    usize::from(SignatureCode::try_from(code).is_ok()),
                ))
            }
            cold @ ColdCode::CesrBinary => Err(ParseError::UnsupportedColdStart { domain: cold }),
        }
    }

    const fn enter_nested_group(self, count: &mut usize) -> Result<(), ParseError> {
        *count = count.saturating_add(1);
        if *count > self.max_nested_groups {
            return Err(ParseError::LimitExceeded {
                kind: LimitKind::NestedGroups,
                limit: self.max_nested_groups,
                actual: *count,
            });
        }
        Ok(())
    }

    fn enclosed_version(
        payload: &[u8],
        version: CesrVersion,
    ) -> Result<(CesrVersion, usize), ParseError> {
        UnwrapGeneric::check_genus_version_offset(payload, version).map_err(|error| match error {
            ParseError::NeedBytes(missing) => ParseError::Truncated { missing },
            other => other,
        })
    }
    pub(crate) fn check_elements(self, group: &GroupFrameCursor) -> Result<(), ParseError> {
        let Some(declared) = group.element_count() else {
            return Ok(());
        };
        let actual = usize::try_from(declared).unwrap_or(usize::MAX);
        if actual > self.max_group_elements {
            return Err(ParseError::LimitExceeded {
                kind: LimitKind::GroupElements,
                limit: self.max_group_elements,
                actual,
            });
        }
        Ok(())
    }

    pub(crate) const fn check_pending_attachment(
        self,
        used: usize,
        available: usize,
        missing: usize,
    ) -> Result<(), ParseError> {
        let buffered = used.saturating_add(available);
        if buffered >= self.max_attachment_bytes {
            return Err(ParseError::LimitExceeded {
                kind: LimitKind::AttachmentBytes,
                limit: self.max_attachment_bytes,
                actual: buffered.saturating_add(missing),
            });
        }
        Ok(())
    }
}

/// The exact span of one framed message at the head of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSpan {
    /// Body byte count; `None` identifies a standalone CESR group.
    pub body_len: Option<usize>,
    /// Total consumed bytes, including any attachments.
    pub total_len: usize,
}

struct EventProgress {
    body_len: usize,
    cursor: usize,
    groups: usize,
    signatures: usize,
    group: Option<GroupFrameCursor>,
}

enum State {
    Event(EventProgress),
    Bare(GroupFrameCursor),
}

/// Incremental V1 message framer over a caller-owned byte buffer.
///
/// A complete bare group and a body followed by a complete `-V` attachment
/// envelope emit immediately. A body followed by unframed groups emits at the
/// next serialized body or at explicit EOF. A body alone on an open stream
/// remains pending because attachments may still arrive.
pub struct MessageFramer {
    limits: FrameLimits,
    state: Option<State>,
    json_head: JsonVersionHead,
}

impl MessageFramer {
    /// Create a framer with explicit caller limits.
    #[must_use]
    pub const fn new(limits: FrameLimits) -> Self {
        Self {
            limits,
            state: None,
            json_head: JsonVersionHead::new(),
        }
    }

    /// Advance framing over the same prefix extended with newly arrived bytes.
    /// On success, consume `FrameSpan::total_len` bytes from the caller buffer
    /// before using this framer for the next frame. `end_of_input` is a real
    /// stream boundary, not a temporary pause in transport delivery.
    ///
    /// # Errors
    ///
    /// Returns typed malformed, truncation, or policy errors. An incomplete
    /// open frame returns `Ok(None)` and retains its framing state.
    pub fn advance(
        &mut self,
        input: &[u8],
        end_of_input: bool,
    ) -> Result<Option<FrameSpan>, ParseError> {
        if self.state.is_none() {
            self.state = self.start(input, end_of_input)?;
            if self.state.is_none() {
                return Ok(None);
            }
        }
        let result = match self.state.as_mut() {
            Some(State::Event(event)) => event.advance(input, end_of_input, self.limits),
            Some(State::Bare(group)) => {
                match group.advance_limited(
                    input,
                    self.limits.max_attachment_bytes,
                    self.limits.max_group_elements,
                    self.limits.max_signatures,
                ) {
                    Ok(total_len) => {
                        if let Some(payload) = group.enclosing_payload(input)? {
                            self.limits.scan_enclosure(
                                payload,
                                group.signature_count(),
                                CesrVersion::V1,
                            )?;
                        }
                        Ok(Some(FrameSpan {
                            body_len: None,
                            total_len,
                        }))
                    }
                    Err(ParseError::NeedBytes(missing)) if end_of_input => {
                        Err(ParseError::Truncated { missing })
                    }
                    Err(ParseError::NeedBytes(_)) => Ok(None),
                    Err(error) => Err(error),
                }
            }
            None => Ok(None),
        }?;
        if result.is_some() {
            self.state = None;
            self.json_head = JsonVersionHead::new();
        }
        Ok(result)
    }
    fn start(&mut self, input: &[u8], end_of_input: bool) -> Result<Option<State>, ParseError> {
        let Some(first) = input.first() else {
            return Ok(None);
        };
        let cold = ColdCode::detect(*first)?;
        let state = match cold {
            ColdCode::Json | ColdCode::Cbor | ColdCode::MessagePack => {
                let declared = if matches!(cold, ColdCode::Json) {
                    self.json_head
                        .advance(input)
                        .and_then(|offset| JsonVersionHead::event_size_at(input, offset, cold))
                } else {
                    JsonVersionHead::event_size(input, cold)
                };
                let body_len = match declared {
                    Ok(size) => size,
                    Err(ParseError::NeedBytes(missing))
                        if input.len() >= self.limits.max_body_bytes =>
                    {
                        return Err(ParseError::LimitExceeded {
                            kind: LimitKind::BodyBytes,
                            limit: self.limits.max_body_bytes,
                            actual: input.len().saturating_add(missing),
                        });
                    }
                    Err(ParseError::NeedBytes(missing)) if end_of_input => {
                        return Err(ParseError::Truncated { missing });
                    }
                    Err(ParseError::NeedBytes(_)) => return Ok(None),
                    Err(error) => return Err(error),
                };
                if body_len > self.limits.max_body_bytes {
                    return Err(ParseError::LimitExceeded {
                        kind: LimitKind::BodyBytes,
                        limit: self.limits.max_body_bytes,
                        actual: body_len,
                    });
                }
                State::Event(EventProgress {
                    body_len,
                    cursor: body_len,
                    groups: 0,
                    signatures: 0,
                    group: None,
                })
            }
            ColdCode::CesrBase64 => {
                let group = match GroupFrameCursor::new_v1(input) {
                    Ok(group) => group,
                    Err(ParseError::NeedBytes(missing)) => {
                        self.limits
                            .check_pending_attachment(0, input.len(), missing)?;
                        if end_of_input {
                            return Err(ParseError::Truncated { missing });
                        }
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                };
                self.limits.check_elements(&group)?;
                State::Bare(group)
            }
            ColdCode::CesrBinary => {
                return Err(ParseError::UnsupportedColdStart { domain: cold });
            }
        };
        Ok(Some(state))
    }
}

impl EventProgress {
    fn advance(
        &mut self,
        input: &[u8],
        end_of_input: bool,
        limits: FrameLimits,
    ) -> Result<Option<FrameSpan>, ParseError> {
        if input.len() < self.body_len {
            return if end_of_input {
                Err(ParseError::Truncated {
                    missing: self.body_len - input.len(),
                })
            } else {
                Ok(None)
            };
        }
        if input.len() < self.cursor {
            return Err(ParseError::Truncated {
                missing: self.cursor - input.len(),
            });
        }
        loop {
            if self.group.is_some() {
                let Some(envelope) = self.advance_group(input, end_of_input, limits)? else {
                    return Ok(None);
                };
                if envelope {
                    return Ok(Some(FrameSpan {
                        body_len: Some(self.body_len),
                        total_len: self.cursor,
                    }));
                }
                continue;
            }
            let Some(next) = input.get(self.cursor) else {
                return if end_of_input {
                    Ok(Some(FrameSpan {
                        body_len: Some(self.body_len),
                        total_len: self.cursor,
                    }))
                } else {
                    Ok(None)
                };
            };
            match ColdCode::detect(*next)? {
                ColdCode::Json | ColdCode::Cbor | ColdCode::MessagePack => {
                    return Ok(Some(FrameSpan {
                        body_len: Some(self.body_len),
                        total_len: self.cursor,
                    }));
                }
                ColdCode::CesrBase64 => {
                    if !self.begin_group(input, end_of_input, limits)? {
                        return Ok(None);
                    }
                }
                cold @ ColdCode::CesrBinary => {
                    return Err(ParseError::UnsupportedColdStart { domain: cold });
                }
            }
        }
    }

    /// `None` means the active group is incomplete; `Some` carries whether a
    /// completed group is the attachment envelope ending this message.
    fn advance_group(
        &mut self,
        input: &[u8],
        end_of_input: bool,
        limits: FrameLimits,
    ) -> Result<Option<bool>, ParseError> {
        let Some(group) = self.group.as_mut() else {
            return Ok(None);
        };
        let used = self.cursor - self.body_len;
        let remaining_limit =
            limits
                .max_attachment_bytes
                .checked_sub(used)
                .ok_or(ParseError::LimitExceeded {
                    kind: LimitKind::AttachmentBytes,
                    limit: limits.max_attachment_bytes,
                    actual: used,
                })?;
        let end = match group.advance_limited(
            &input[self.cursor..],
            remaining_limit,
            limits.max_group_elements,
            limits.max_signatures.saturating_sub(self.signatures),
        ) {
            Ok(end) => end,
            Err(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                actual,
                ..
            }) => {
                return Err(ParseError::LimitExceeded {
                    kind: LimitKind::Signatures,
                    limit: limits.max_signatures,
                    actual: self.signatures.saturating_add(actual),
                });
            }
            Err(ParseError::NeedBytes(missing)) if end_of_input => {
                return Err(ParseError::Truncated { missing });
            }
            Err(ParseError::NeedBytes(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let envelope = group.is_attachment_envelope();
        let direct = group.signature_count();
        let nested = match group.enclosing_payload(&input[self.cursor..])? {
            Some(payload) => limits.scan_enclosure(
                payload,
                self.signatures.saturating_add(direct),
                CesrVersion::V1,
            )?,
            None => 0,
        };
        self.signatures = self
            .signatures
            .checked_add(direct)
            .and_then(|count| count.checked_add(nested))
            .ok_or(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                limit: limits.max_signatures,
                actual: usize::MAX,
            })?;
        self.cursor += end;
        self.groups += 1;
        self.group = None;
        Ok(Some(envelope))
    }

    fn begin_group(
        &mut self,
        input: &[u8],
        end_of_input: bool,
        limits: FrameLimits,
    ) -> Result<bool, ParseError> {
        if self.groups >= limits.max_attachment_groups {
            return Err(ParseError::LimitExceeded {
                kind: LimitKind::AttachmentGroups,
                limit: limits.max_attachment_groups,
                actual: self.groups + 1,
            });
        }
        let tail = input
            .get(self.cursor..)
            .ok_or_else(|| ParseError::Truncated {
                missing: self.cursor - input.len(),
            })?;
        let group = match GroupFrameCursor::new_v1(tail) {
            Ok(group) => group,
            Err(ParseError::NeedBytes(missing)) => {
                limits.check_pending_attachment(
                    self.cursor - self.body_len,
                    tail.len(),
                    missing,
                )?;
                if end_of_input {
                    return Err(ParseError::Truncated { missing });
                }
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        limits.check_elements(&group)?;
        self.group = Some(group);
        Ok(true)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixture construction and assertions"
)]
mod tests {
    use alloc::{format, vec, vec::Vec};
    use cesr::core::counter::{CounterCodeV1, CounterCodeV2};
    use cesr::core::indexer::IndexerBuilder;
    use cesr::core::indexer::code::IndexedSigCode;
    use core::num::NonZeroUsize;

    use super::*;

    fn limits() -> FrameLimits {
        FrameLimits {
            max_body_bytes: 4096,
            max_attachment_bytes: 4096,
            max_attachment_groups: 4,
            max_group_elements: 4,
            max_signatures: 4,
            max_nested_groups: 8,
            max_nesting_depth: 2,
        }
    }

    fn body() -> Vec<u8> {
        let mut bytes = b"{\"v\":\"KERI10JSON000000_\",\"t\":\"icp\"}".to_vec();
        let size = format!("{:06x}", bytes.len());
        bytes[16..22].copy_from_slice(size.as_bytes());
        bytes
    }

    fn counter(code: CounterCodeV1, count: u32) -> Vec<u8> {
        let soft = cesr::b64::encode_int(count, NonZeroUsize::new(code.soft_size()).unwrap());
        format!("{}{soft}", code.as_str()).into_bytes()
    }

    fn counter_v2(code: CounterCodeV2, count: u32) -> Vec<u8> {
        let soft = cesr::b64::encode_int(count, NonZeroUsize::new(code.soft_size()).unwrap());
        format!("{}{soft}", code.as_str()).into_bytes()
    }

    fn signatures() -> Vec<u8> {
        let mut group = counter(CounterCodeV1::ControllerIdxSigs, 1);
        let signature = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(0)
            .unwrap()
            .with_raw(&[0; 64])
            .unwrap()
            .to_qb64();
        group.extend_from_slice(signature.as_bytes());
        group
    }

    fn nested_signatures(kind: CounterCodeV1, count: u32) -> Vec<u8> {
        let mut group = counter(kind, 1);
        let matters = if kind == CounterCodeV1::TransIdxSigGroups {
            3
        } else {
            1
        };
        for _ in 0..matters {
            group.push(b'D');
            group.extend_from_slice(&[b'A'; 43]);
        }
        group.extend_from_slice(&counter(CounterCodeV1::ControllerIdxSigs, count));
        let signature = signatures();
        for _ in 0..count {
            group.extend_from_slice(&signature[4..]);
        }
        group
    }

    #[test]
    fn nested_signatures_frame_at_every_split_and_preserve_remainder() {
        for kind in [
            CounterCodeV1::TransIdxSigGroups,
            CounterCodeV1::TransLastIdxSigGroups,
        ] {
            let group = nested_signatures(kind, 3);
            let mut with_tail = group.clone();
            with_tail.extend_from_slice(b"tail");
            for split in 0..group.len() {
                let mut framer = MessageFramer::new(limits());
                assert_eq!(framer.advance(&group[..split], false).unwrap(), None);
                assert_eq!(
                    framer.advance(&with_tail, false).unwrap(),
                    Some(FrameSpan {
                        body_len: None,
                        total_len: group.len()
                    }),
                    "{kind:?}, split {split}"
                );
            }
            let mut framer = MessageFramer::new(limits());
            for end in 1..group.len() {
                assert_eq!(framer.advance(&group[..end], false).unwrap(), None);
            }
            assert!(matches!(
                framer.advance(&group[..group.len() - 1], true),
                Err(ParseError::Truncated { missing: 1 })
            ));
            assert_eq!(
                framer.advance(&with_tail, false).unwrap(),
                Some(FrameSpan {
                    body_len: None,
                    total_len: group.len()
                })
            );
        }
    }

    #[test]
    fn nested_signature_counter_obeys_element_budget_before_payload() {
        let mut policy = limits();
        policy.max_group_elements = 1;
        for (kind, matters) in [
            (CounterCodeV1::TransIdxSigGroups, 3),
            (CounterCodeV1::TransLastIdxSigGroups, 1),
        ] {
            let wire = nested_signatures(kind, 2);
            let counter_end = 4 + matters * 44 + 4;
            let mut framer = MessageFramer::new(policy);
            assert!(matches!(
                framer.advance(&wire[..counter_end], false),
                Err(ParseError::LimitExceeded {
                    kind: LimitKind::GroupElements,
                    limit: 1,
                    actual: 2
                })
            ));
        }
    }

    #[test]
    fn signature_budget_rejects_direct_nested_and_cumulative_declarations() {
        let mut policy = limits();
        policy.max_signatures = 1;
        let mut bare = MessageFramer::new(policy);
        assert!(matches!(
            bare.advance(&counter(CounterCodeV1::ControllerIdxSigs, 2), false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                limit: 1,
                actual: 2
            })
        ));

        let nested = nested_signatures(CounterCodeV1::TransIdxSigGroups, 2);
        let mut bare_nested = MessageFramer::new(policy);
        assert!(matches!(
            bare_nested.advance(&nested[..4 + 3 * 44 + 4], false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                limit: 1,
                actual: 2
            })
        ));

        let mut wire = body();
        wire.extend_from_slice(&signatures());
        wire.extend_from_slice(&counter(CounterCodeV1::WitnessIdxSigs, 1));
        let mut attached = MessageFramer::new(policy);
        assert!(matches!(
            attached.advance(&wire, false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                limit: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn signature_budget_applies_inside_attachment_envelope() {
        let mut policy = limits();
        policy.max_signatures = 1;
        let mut payload = counter(CounterCodeV1::ControllerIdxSigs, 2);
        let signature = signatures();
        payload.extend_from_slice(&signature[4..]);
        payload.extend_from_slice(&signature[4..]);
        let mut envelope = counter(
            CounterCodeV1::AttachmentGroup,
            u32::try_from(payload.len() / 4).unwrap(),
        );
        envelope.extend_from_slice(&payload);
        let mut wire = body();
        wire.extend_from_slice(&envelope);
        let mut framer = MessageFramer::new(policy);
        assert!(matches!(
            framer.advance(&wire, false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                limit: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn attachment_envelope_obeys_nested_group_and_depth_limits() {
        let zero = counter(CounterCodeV1::ControllerIdxSigs, 0);
        let mut two_groups = zero.clone();
        two_groups.extend_from_slice(&zero);
        let mut envelope = counter(CounterCodeV1::AttachmentGroup, 2);
        envelope.extend_from_slice(&two_groups);
        let mut group_policy = limits();
        group_policy.max_nested_groups = 1;
        assert!(matches!(
            MessageFramer::new(group_policy).advance(&envelope, false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::NestedGroups,
                limit: 1,
                actual: 2
            })
        ));

        let mut inner = counter(CounterCodeV1::AttachmentGroup, 1);
        inner.extend_from_slice(&zero);
        let mut outer = counter(CounterCodeV1::AttachmentGroup, 2);
        outer.extend_from_slice(&inner);
        let mut depth_policy = limits();
        depth_policy.max_nesting_depth = 1;
        assert!(matches!(
            MessageFramer::new(depth_policy).advance(&outer, false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::NestingDepth,
                limit: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn generic_pipeline_with_genus_switch_cannot_hide_signatures() {
        let signature = signatures();
        let mut inner = b"-_AAACAA".to_vec();
        inner.extend_from_slice(&counter_v2(CounterCodeV2::ControllerIdxSigs, 2));
        inner.extend_from_slice(&signature[4..]);
        inner.extend_from_slice(&signature[4..]);
        let mut pipeline = counter(
            CounterCodeV1::GenericGroup,
            u32::try_from(inner.len() / 4).unwrap(),
        );
        pipeline.extend_from_slice(&inner);

        let (parsed, rest) = crate::group::CesrGroup::parse(&pipeline).unwrap();
        assert!(rest.is_empty());
        let crate::group::CesrGroup::GenericGroup(generic) = parsed else {
            panic!("expected generic group");
        };
        assert_eq!(generic.raw_bytes(), inner);
        let (decoded, inner_rest) =
            crate::group::CesrGroup::parse_bytes_v2(&bytes::Bytes::copy_from_slice(&inner[8..]))
                .unwrap();
        assert!(inner_rest.is_empty());
        assert!(matches!(
            decoded,
            crate::group::CesrGroup::ControllerIdxSigs(_)
        ));

        let mut policy = limits();
        policy.max_signatures = 1;
        let mut framer = MessageFramer::new(policy);
        assert!(matches!(
            framer.advance(&pipeline, false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                limit: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn generic_pipeline_counts_standalone_signature_matters() {
        let mut signature = b"0B".to_vec();
        signature.extend_from_slice(&[b'A'; 86]);
        let mut pipeline = counter(CounterCodeV1::GenericGroup, 44);
        pipeline.extend_from_slice(&signature);
        pipeline.extend_from_slice(&signature);
        let mut policy = limits();
        policy.max_signatures = 1;
        assert!(matches!(
            MessageFramer::new(policy).advance(&pipeline, false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::Signatures,
                limit: 1,
                actual: 2
            })
        ));
    }

    #[test]
    fn enclosing_groups_keep_mixed_atoms_and_embedded_body_frameable() {
        let mut primitive = vec![b'D'];
        primitive.extend_from_slice(&[b'A'; 43]);
        let mut generic = counter(CounterCodeV1::GenericGroup, 12);
        generic.extend_from_slice(&primitive);
        generic.extend_from_slice(&counter(CounterCodeV1::ControllerIdxSigs, 0));
        assert_eq!(
            MessageFramer::new(limits())
                .advance(&generic, false)
                .unwrap(),
            Some(FrameSpan {
                body_len: None,
                total_len: generic.len()
            })
        );

        let mut embedded = b"{\"v\":\"KERI10JSON000000_\",\"t\":\"icpx\"}".to_vec();
        let size = format!("{:06x}", embedded.len());
        embedded[16..22].copy_from_slice(size.as_bytes());
        assert_eq!(embedded.len() % 4, 0);
        embedded.extend_from_slice(&counter(CounterCodeV1::ControllerIdxSigs, 0));
        let mut message_group = counter(
            CounterCodeV1::BodyWithAttachmentGroup,
            u32::try_from(embedded.len() / 4).unwrap(),
        );
        message_group.extend_from_slice(&embedded);
        assert_eq!(
            MessageFramer::new(limits())
                .advance(&message_group, false)
                .unwrap(),
            Some(FrameSpan {
                body_len: None,
                total_len: message_group.len()
            })
        );
    }

    #[test]
    fn complete_enclosure_with_partial_genus_selector_is_truncated() {
        let mut pipeline = counter(CounterCodeV1::GenericGroup, 1);
        pipeline.extend_from_slice(b"-_AA");
        assert!(matches!(
            MessageFramer::new(limits()).advance(&pipeline, false),
            Err(ParseError::Truncated { missing: 4 })
        ));
    }

    #[test]
    #[ignore = "release-mode scaling evidence; run explicitly"]
    #[allow(
        clippy::print_stderr,
        reason = "explicit release-only timing probe reports measured durations"
    )]
    fn bench_bytewise_nested_signatures() {
        use std::eprintln;
        use std::time::Instant;

        for count in [64, 256] {
            let wire = nested_signatures(CounterCodeV1::TransIdxSigGroups, count);
            let mut policy = limits();
            policy.max_attachment_bytes = 64 * 1024;
            policy.max_group_elements = usize::try_from(count).unwrap();
            policy.max_signatures = usize::try_from(count).unwrap();
            let started = Instant::now();
            for _ in 0..3 {
                let mut framer = MessageFramer::new(policy);
                for end in 1..=wire.len() {
                    let outcome = framer.advance(&wire[..end], true);
                    if end < wire.len() {
                        assert!(matches!(outcome, Err(ParseError::Truncated { .. })));
                    } else {
                        assert_eq!(outcome.unwrap().unwrap().total_len, wire.len());
                    }
                }
            }
            eprintln!(
                "nested signatures {count}: {} bytes, {:?} / 3",
                wire.len(),
                started.elapsed()
            );
        }
    }

    #[test]
    fn body_without_boundary_waits_until_eof() {
        let body = body();
        let mut framer = MessageFramer::new(limits());
        assert_eq!(framer.advance(&body, false).unwrap(), None);
        assert_eq!(
            framer.advance(&body, true).unwrap(),
            Some(FrameSpan {
                body_len: Some(body.len()),
                total_len: body.len(),
            })
        );
    }

    #[test]
    fn partial_attachment_waits_then_eof_is_typed_truncation() {
        let body = body();
        let group = signatures();
        let mut frame = body;
        frame.extend_from_slice(&group[..group.len() - 1]);
        let mut framer = MessageFramer::new(limits());
        assert_eq!(framer.advance(&frame, false).unwrap(), None);
        assert!(matches!(
            framer.advance(&frame, true),
            Err(ParseError::Truncated { missing: 1 })
        ));
    }

    #[test]
    fn replacing_a_retained_prefix_returns_error_without_panicking() {
        let body = body();
        let group = signatures();
        let mut wire = body.clone();
        wire.extend_from_slice(&group);
        let mut framer = MessageFramer::new(limits());
        assert_eq!(framer.advance(&wire, false).unwrap(), None);
        assert!(matches!(
            framer.advance(&body, false),
            Err(ParseError::Truncated { missing }) if missing == group.len()
        ));
    }

    #[test]
    fn shortening_partial_version_head_returns_typed_truncation() {
        let mut framer = MessageFramer::new(limits());
        assert_eq!(framer.advance(b"{\"v\":\"KERI", false).unwrap(), None);
        assert!(matches!(
            framer.advance(b"{", false),
            Err(ParseError::Truncated { missing: 5 })
        ));

        let mut whitespace = MessageFramer::new(limits());
        assert_eq!(whitespace.advance(b"{  ", false).unwrap(), None);
        assert!(matches!(
            whitespace.advance(b"{", false),
            Err(ParseError::Truncated { missing: 2 })
        ));
    }

    #[test]
    fn all_two_message_splits_consume_exact_attachment_boundary() {
        let body = body();
        let group = signatures();
        let first_len = body.len() + group.len();
        let mut wire = body.clone();
        wire.extend_from_slice(&group);
        wire.extend_from_slice(&body);
        for split in 0..=wire.len() {
            let mut framer = MessageFramer::new(limits());
            let first = framer.advance(&wire[..split], false).unwrap();
            if split < first_len + 1 {
                assert_eq!(first, None, "split {split}");
            } else {
                assert_eq!(first.unwrap().total_len, first_len, "split {split}");
            }
            if first.is_none() {
                assert_eq!(
                    framer.advance(&wire, false).unwrap().unwrap().total_len,
                    first_len,
                    "split {split}"
                );
            }
            assert_eq!(
                framer.advance(&wire[first_len..], true).unwrap(),
                Some(FrameSpan {
                    body_len: Some(body.len()),
                    total_len: body.len(),
                })
            );
        }
    }

    #[test]
    fn complete_attachment_envelope_and_bare_group_emit_immediately() {
        let group = signatures();
        let mut envelope = counter(
            CounterCodeV1::AttachmentGroup,
            u32::try_from(group.len() / 4).unwrap(),
        );
        envelope.extend_from_slice(&group);
        let body = body();
        let mut wire = body.clone();
        wire.extend_from_slice(&envelope);
        wire.extend_from_slice(b"tail");
        let mut framer = MessageFramer::new(limits());
        assert_eq!(
            framer.advance(&wire, false).unwrap(),
            Some(FrameSpan {
                body_len: Some(body.len()),
                total_len: body.len() + envelope.len(),
            })
        );
        let mut bare = group.clone();
        bare.extend_from_slice(b"tail");
        assert_eq!(
            framer.advance(&bare, false).unwrap(),
            Some(FrameSpan {
                body_len: None,
                total_len: group.len(),
            })
        );
    }

    #[test]
    fn declared_body_and_group_count_limits_fail_before_buffering_payload() {
        let mut body_limits = limits();
        body_limits.max_body_bytes = 16;
        let mut framer = MessageFramer::new(body_limits);
        assert!(matches!(
            framer.advance(&body()[..24], false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::BodyBytes,
                ..
            })
        ));

        let mut group_limits = limits();
        group_limits.max_group_elements = 1;
        let mut group_framer = MessageFramer::new(group_limits);
        assert!(matches!(
            group_framer.advance(&counter(CounterCodeV1::ControllerIdxSigs, 4095), false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::GroupElements,
                actual: 4095,
                ..
            })
        ));
    }

    #[test]
    fn incomplete_counter_head_cannot_buffer_past_attachment_limit() {
        let mut policy = limits();
        policy.max_attachment_bytes = 2;
        let mut bare = MessageFramer::new(policy);
        assert!(matches!(
            bare.advance(b"-A", false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::AttachmentBytes,
                limit: 2,
                ..
            })
        ));

        let mut wire = body();
        wire.extend_from_slice(b"-A");
        let mut attached = MessageFramer::new(policy);
        assert!(matches!(
            attached.advance(&wire, false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::AttachmentBytes,
                limit: 2,
                ..
            })
        ));
    }

    #[test]
    fn fragmented_json_header_and_oversized_whitespace_are_bounded() {
        let mut body = vec![b'{'];
        body.extend_from_slice(&[b' '; 512]);
        body.extend_from_slice(b"\"v\":\"KERI10JSON000000_\"}");
        let size = format!("{:06x}", body.len());
        let at = body.windows(6).position(|part| part == b"000000").unwrap();
        body[at..at + 6].copy_from_slice(size.as_bytes());

        let mut allowed = limits();
        allowed.max_body_bytes = body.len();
        let mut framer = MessageFramer::new(allowed);
        for end in 1..body.len() {
            assert_eq!(framer.advance(&body[..end], false).unwrap(), None);
        }
        assert_eq!(
            framer.advance(&body, true).unwrap().unwrap().total_len,
            body.len()
        );

        let mut bounded = limits();
        bounded.max_body_bytes = 64;
        let mut bounded_framer = MessageFramer::new(bounded);
        assert!(matches!(
            bounded_framer.advance(&body[..64], false),
            Err(ParseError::LimitExceeded {
                kind: LimitKind::BodyBytes,
                limit: 64,
                ..
            })
        ));
    }

    #[test]
    #[ignore = "release-mode hostile JSON header scaling evidence; run explicitly"]
    #[allow(
        clippy::print_stderr,
        reason = "explicit release-only timing probe reports measured durations"
    )]
    fn bench_bytewise_json_version_head() {
        use std::eprintln;
        use std::hint::black_box;
        use std::time::Instant;

        for whitespace in [1024, 4096] {
            let mut body = vec![b'{'];
            body.extend(core::iter::repeat_n(b' ', whitespace));
            body.extend_from_slice(b"\"v\":\"KERI10JSON000000_\"}");
            let size = format!("{:06x}", body.len());
            let at = body.windows(6).position(|part| part == b"000000").unwrap();
            body[at..at + 6].copy_from_slice(size.as_bytes());
            let mut policy = limits();
            policy.max_body_bytes = body.len();

            let mut samples = Vec::new();
            for _ in 0..21 {
                let started = Instant::now();
                for _ in 0..20 {
                    let mut framer = MessageFramer::new(policy);
                    for end in 1..body.len() {
                        black_box(framer.advance(&body[..end], false).unwrap());
                    }
                    assert_eq!(
                        framer.advance(&body, true).unwrap().unwrap().total_len,
                        body.len()
                    );
                }
                samples.push(started.elapsed().as_nanos());
            }
            samples.sort_unstable();
            eprintln!(
                "bytewise JSON head {} bytes: p10={} ns, median={} ns, p90={} ns / 20 passes",
                body.len(),
                samples[2],
                samples[10],
                samples[18]
            );
        }
    }

    #[test]
    fn cbor_and_msgpack_version_heads_frame_in_every_chunking() {
        for (head, version) in [
            (&[0xa1, 0x61, b'v', 0x71][..], &b"KERI10CBOR000015_"[..]),
            (&[0x81, 0xa1, b'v', 0xb1][..], &b"KERI10MGPK000015_"[..]),
        ] {
            let mut body = head.to_vec();
            body.extend_from_slice(version);
            for split in 0..body.len() {
                let mut framer = MessageFramer::new(limits());
                assert_eq!(framer.advance(&body[..split], false).unwrap(), None);
                assert_eq!(
                    framer.advance(&body, true).unwrap(),
                    Some(FrameSpan {
                        body_len: Some(body.len()),
                        total_len: body.len(),
                    })
                );
            }
        }
    }

    #[test]
    fn first_version_field_rejects_reordering_and_kind_mismatch() {
        let reordered_json = b"{\"x\":0,\"v\":\"KERI10JSON000021_\"}";
        assert!(matches!(
            MessageFramer::new(limits()).advance(reordered_json, true),
            Err(ParseError::MissingVersionString)
        ));
        for (head, version) in [
            (
                &[0xa2, 0x61, b'x', 0x61, b'y', 0x61, b'v', 0x71][..],
                &b"KERI10CBOR000019_"[..],
            ),
            (
                &[0x82, 0xa1, b'x', 0xa1, b'y', 0xa1, b'v', 0xb1][..],
                &b"KERI10MGPK000019_"[..],
            ),
        ] {
            let mut body = head.to_vec();
            body.extend_from_slice(version);
            assert!(matches!(
                MessageFramer::new(limits()).advance(&body, true),
                Err(ParseError::MissingVersionString)
            ));
        }
        let mut wrong_kind = [0xa1, 0x61, b'v', 0x71].to_vec();
        wrong_kind.extend_from_slice(b"KERI10JSON000015_");
        assert!(matches!(
            MessageFramer::new(limits()).advance(&wrong_kind, true),
            Err(ParseError::VersionKindMismatch {
                cold: ColdCode::Cbor,
                ..
            })
        ));
        assert!(matches!(
            MessageFramer::new(limits()).advance(b"{\"v\":\"KERI10JSON000000_\"}", true),
            Err(ParseError::InvalidEventSize { declared: 0, .. })
        ));
    }

    #[test]
    fn extended_binary_version_heads_frame_under_all_two_way_splits() {
        for (head, version) in [
            (
                &[0xa1, 0x78, 0x01, b'v', 0x78, 0x11][..],
                &b"KERI10CBOR000017_"[..],
            ),
            (
                &[0x81, 0xd9, 0x01, b'v', 0xd9, 0x11][..],
                &b"KERI10MGPK000017_"[..],
            ),
        ] {
            let mut body = head.to_vec();
            body.extend_from_slice(version);
            for split in 0..=body.len() {
                let mut framer = MessageFramer::new(limits());
                assert_eq!(framer.advance(&body[..split], false).unwrap(), None);
                assert_eq!(
                    framer.advance(&body, true).unwrap(),
                    Some(FrameSpan {
                        body_len: Some(body.len()),
                        total_len: body.len(),
                    })
                );
            }
        }
    }
}
