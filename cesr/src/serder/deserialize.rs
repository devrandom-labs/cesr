//! KERI event deserialization from strict canonical JSON with SAID
//! verification.
//!
//! Parses the five fixed canonical event grammars via the single-pass
//! [`canonical`] parser, reconstructing [`crate::keri`] domain types. Every
//! deserialized event's SAID is verified in place over the raw bytes (span
//! fill + hash) before being returned.

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::{DigestCode, MatterCode, VerKeyCode};
use crate::core::matter::error::{MatterBuildError, ValidationError};
use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
use crate::keri::{
    ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, InceptionEvent,
    InteractionEvent, KeriEvent, RotationEvent, Seal,
};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};

use self::canonical::{
    ParsedCount, ParsedDip, ParsedEvent, ParsedIcp, ParsedIxn, ParsedRot, ParsedSeal,
    ParsedTholder, Spanned,
};
use crate::serder::error::SerderError;
use crate::serder::said::verify_said_spans;

pub(crate) mod canonical;

#[cfg(test)]
pub(crate) mod reference;

// ---------------------------------------------------------------------------
// Public deserialization entry points
// ---------------------------------------------------------------------------

/// Deserialize any KERI event from strict canonical JSON bytes.
///
/// Dispatches on the wire `t` (ilk) field, then verifies the SAID in place
/// over the raw bytes before building the domain event.
///
/// # Errors
///
/// Returns [`SerderError::NonCanonical`] if the input deviates from the
/// strict canonical grammar (whitespace, reordered or duplicate fields,
/// escapes, trailing bytes), [`SerderError::InvalidVersionString`] if the
/// version string is malformed or inconsistent with the input length,
/// [`SerderError::UnknownIlk`] if `t` is not a KEL ilk, or another
/// [`SerderError`] if a field is invalid or the SAID does not verify.
pub fn deserialize_event(raw: &[u8]) -> Result<KeriEvent, SerderError> {
    match canonical::parse_event(raw)? {
        ParsedEvent::Inception(p) => {
            verify_inception_said(raw, &p)?;
            Ok(KeriEvent::Inception(build_inception(&p)?))
        }
        ParsedEvent::Rotation(p) => {
            verify_single_said(raw, &p.said)?;
            Ok(KeriEvent::Rotation(build_rotation(&p)?))
        }
        ParsedEvent::Interaction(p) => {
            verify_single_said(raw, &p.said)?;
            Ok(KeriEvent::Interaction(build_interaction(&p)?))
        }
        ParsedEvent::DelegatedInception(p) => {
            verify_inception_said(raw, &p.icp)?;
            Ok(KeriEvent::DelegatedInception(build_delegated_inception(
                &p,
            )?))
        }
        ParsedEvent::DelegatedRotation(p) => {
            verify_single_said(raw, &p.said)?;
            Ok(KeriEvent::DelegatedRotation(DelegatedRotationEvent::new(
                build_rotation(&p)?,
            )))
        }
    }
}

/// Deserialize an inception event from strict canonical JSON bytes.
///
/// Verifies the double-SAID property when `d == i`: both spans are filled
/// with placeholders in place over the raw bytes before hashing.
///
/// # Errors
///
/// Returns [`SerderError::NonCanonical`] if the input deviates from the
/// strict canonical grammar or its ilk is not `icp`,
/// [`SerderError::InvalidVersionString`] if the version string is malformed
/// or inconsistent with the input length, or another [`SerderError`] if a
/// field is invalid or the SAID does not verify.
pub fn deserialize_inception(raw: &[u8]) -> Result<InceptionEvent, SerderError> {
    let parsed = canonical::parse_inception(raw)?;
    verify_inception_said(raw, &parsed)?;
    build_inception(&parsed)
}

/// Deserialize a rotation event from strict canonical JSON bytes.
///
/// The SAID is verified in place over the raw bytes.
///
/// # Errors
///
/// Returns [`SerderError::NonCanonical`] if the input deviates from the
/// strict canonical grammar or its ilk is not `rot`,
/// [`SerderError::InvalidVersionString`] if the version string is malformed
/// or inconsistent with the input length, or another [`SerderError`] if a
/// field is invalid or the SAID does not verify.
pub fn deserialize_rotation(raw: &[u8]) -> Result<RotationEvent, SerderError> {
    let parsed = canonical::parse_rotation(raw)?;
    verify_single_said(raw, &parsed.said)?;
    build_rotation(&parsed)
}

/// Deserialize an interaction event from strict canonical JSON bytes.
///
/// The SAID is verified in place over the raw bytes.
///
/// # Errors
///
/// Returns [`SerderError::NonCanonical`] if the input deviates from the
/// strict canonical grammar or its ilk is not `ixn`,
/// [`SerderError::InvalidVersionString`] if the version string is malformed
/// or inconsistent with the input length, or another [`SerderError`] if a
/// field is invalid or the SAID does not verify.
pub fn deserialize_interaction(raw: &[u8]) -> Result<InteractionEvent, SerderError> {
    let parsed = canonical::parse_interaction(raw)?;
    verify_single_said(raw, &parsed.said)?;
    build_interaction(&parsed)
}

/// Deserialize a delegated inception event from strict canonical JSON bytes.
///
/// Verifies the double-SAID property when `d == i`: both spans are filled
/// with placeholders in place over the raw bytes before hashing.
///
/// # Errors
///
/// Returns [`SerderError::NonCanonical`] if the input deviates from the
/// strict canonical grammar or its ilk is not `dip`,
/// [`SerderError::InvalidVersionString`] if the version string is malformed
/// or inconsistent with the input length, or another [`SerderError`] if a
/// field is invalid or the SAID does not verify.
pub fn deserialize_delegated_inception(raw: &[u8]) -> Result<DelegatedInceptionEvent, SerderError> {
    let parsed = canonical::parse_delegated_inception(raw)?;
    verify_inception_said(raw, &parsed.icp)?;
    build_delegated_inception(&parsed)
}

/// Deserialize a delegated rotation event from strict canonical JSON bytes.
///
/// The SAID is verified in place over the raw bytes.
///
/// # Errors
///
/// Returns [`SerderError::NonCanonical`] if the input deviates from the
/// strict canonical grammar or its ilk is not `drt`,
/// [`SerderError::InvalidVersionString`] if the version string is malformed
/// or inconsistent with the input length, or another [`SerderError`] if a
/// field is invalid or the SAID does not verify.
pub fn deserialize_delegated_rotation(raw: &[u8]) -> Result<DelegatedRotationEvent, SerderError> {
    let parsed = canonical::parse_delegated_rotation(raw)?;
    verify_single_said(raw, &parsed.said)?;
    Ok(DelegatedRotationEvent::new(build_rotation(&parsed)?))
}

// ---------------------------------------------------------------------------
// SAID verification over parsed spans
// ---------------------------------------------------------------------------

fn verify_single_said(raw: &[u8], said: &Spanned<'_>) -> Result<(), SerderError> {
    let code = infer_digest_code(said.value)?;
    verify_said_spans(raw, said, None, code)
}

/// Double-SAID fill (both `d` and `i`) applies only when the prefix is
/// self-addressing, i.e. `d == i` — matching the write path and keripy.
fn verify_inception_said(raw: &[u8], parsed: &ParsedIcp<'_>) -> Result<(), SerderError> {
    let code = infer_digest_code(parsed.said.value)?;
    let prefix = (parsed.said.value == parsed.prefix.value).then_some(&parsed.prefix);
    verify_said_spans(raw, &parsed.said, prefix, code)
}

// ---------------------------------------------------------------------------
// Domain-event builders over parsed views
// ---------------------------------------------------------------------------

fn build_inception(p: &ParsedIcp<'_>) -> Result<InceptionEvent, SerderError> {
    Ok(InceptionEvent::new(
        parse_qb64_identifier(p.prefix.value, "i")?,
        Seqner::new(parse_sn(p.sn)?),
        parse_qb64_diger(p.said.value, "d")?,
        verfers_from_parsed(&p.keys, "k")?,
        tholder_from_parsed(&p.threshold)?,
        digers_from_parsed(&p.next_keys, "n")?,
        tholder_from_parsed(&p.next_threshold)?,
        prefixers_from_parsed(&p.witnesses, "b")?,
        witness_threshold_from_parsed(&p.witness_threshold)?,
        config_from_parsed(&p.config)?,
        anchors_from_parsed(&p.anchors)?,
    ))
}

fn build_delegated_inception(p: &ParsedDip<'_>) -> Result<DelegatedInceptionEvent, SerderError> {
    Ok(DelegatedInceptionEvent::new(
        build_inception(&p.icp)?,
        parse_qb64_identifier(p.delegator, "di")?,
    ))
}

/// `rot`/`drt` carry no `c` field on the wire; the config is always empty.
fn build_rotation(p: &ParsedRot<'_>) -> Result<RotationEvent, SerderError> {
    Ok(RotationEvent::new(
        parse_qb64_identifier(p.prefix, "i")?,
        Seqner::new(parse_sn(p.sn)?),
        parse_qb64_diger(p.said.value, "d")?,
        parse_qb64_diger(p.prior, "p")?,
        verfers_from_parsed(&p.keys, "k")?,
        tholder_from_parsed(&p.threshold)?,
        digers_from_parsed(&p.next_keys, "n")?,
        tholder_from_parsed(&p.next_threshold)?,
        prefixers_from_parsed(&p.witness_additions, "ba")?,
        prefixers_from_parsed(&p.witness_removals, "br")?,
        witness_threshold_from_parsed(&p.witness_threshold)?,
        vec![],
        anchors_from_parsed(&p.anchors)?,
    ))
}

fn build_interaction(p: &ParsedIxn<'_>) -> Result<InteractionEvent, SerderError> {
    Ok(InteractionEvent::new(
        parse_qb64_identifier(p.prefix, "i")?,
        Seqner::new(parse_sn(p.sn)?),
        parse_qb64_diger(p.said.value, "d")?,
        parse_qb64_diger(p.prior, "p")?,
        anchors_from_parsed(&p.anchors)?,
    ))
}

// ---------------------------------------------------------------------------
// Strict conversion layer: parsed wire views -> domain primitives
// ---------------------------------------------------------------------------

fn tholder_from_parsed(t: &ParsedTholder<'_>) -> Result<Tholder, SerderError> {
    match t {
        ParsedTholder::Hex(s) => {
            let n = u64::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
                field: "kt",
                source: ValidationError::UnknownMatterCode(format!("invalid hex threshold: {s}")),
            })?;
            Ok(Tholder::Simple(n))
        }
        ParsedTholder::Number(s) => {
            let n = s
                .parse::<u64>()
                .map_err(|_| SerderError::InvalidPrimitive {
                    field: "kt",
                    source: ValidationError::UnknownMatterCode(format!(
                        "invalid integer threshold: {s}"
                    )),
                })?;
            Ok(Tholder::Simple(n))
        }
        ParsedTholder::Weighted(clauses) => {
            let parsed: Result<Vec<Vec<(u64, u64)>>, SerderError> = clauses
                .iter()
                .map(|clause| clause.iter().map(|w| parse_weight(w)).collect())
                .collect();
            Ok(Tholder::Weighted(parsed?))
        }
    }
}

fn witness_threshold_from_parsed(c: &ParsedCount<'_>) -> Result<u32, SerderError> {
    let n = match c {
        ParsedCount::Hex(s) => {
            u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
                field: "bt",
                source: ValidationError::UnknownMatterCode(format!("invalid hex bt: {s}")),
            })?
        }
        ParsedCount::Number(s) => s
            .parse::<u128>()
            .map_err(|_| SerderError::InvalidPrimitive {
                field: "bt",
                source: ValidationError::UnknownMatterCode(format!("invalid integer bt: {s}")),
            })?,
    };
    u32::try_from(n).map_err(|_| SerderError::InvalidPrimitive {
        field: "bt",
        source: ValidationError::UnknownMatterCode(format!(
            "witness threshold {n} exceeds u32::MAX"
        )),
    })
}

fn seal_from_parsed(seal: &ParsedSeal<'_>) -> Result<Seal, SerderError> {
    match seal {
        ParsedSeal::Digest { d } => Ok(Seal::Digest {
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Root { rd } => Ok(Seal::Root {
            rd: parse_qb64_saider(rd, "rd")?,
        }),
        ParsedSeal::Source { s, d } => Ok(Seal::Source {
            s: Seqner::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Event { i, s, d } => Ok(Seal::Event {
            i: parse_qb64_prefixer(i, "i")?,
            s: Seqner::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Last { i } => Ok(Seal::Last {
            i: parse_qb64_prefixer(i, "i")?,
        }),
    }
}

// `UnknownIlk` for a bad config code replicates the tolerant path's exact
// behavior (see `reference::parse_config_array`) — kept for parity even
// though the variant name is odd.
fn config_from_parsed(config: &[&str]) -> Result<Vec<ConfigTrait>, SerderError> {
    config
        .iter()
        .map(|s| ConfigTrait::from_code(s).map_err(|_| SerderError::UnknownIlk((*s).to_owned())))
        .collect()
}

fn verfers_from_parsed(
    items: &[&str],
    field: &'static str,
) -> Result<Vec<Verfer<'static>>, SerderError> {
    items.iter().map(|s| parse_qb64_verfer(s, field)).collect()
}

fn prefixers_from_parsed(
    items: &[&str],
    field: &'static str,
) -> Result<Vec<Prefixer<'static>>, SerderError> {
    items
        .iter()
        .map(|s| parse_qb64_prefixer(s, field))
        .collect()
}

fn digers_from_parsed(
    items: &[&str],
    field: &'static str,
) -> Result<Vec<Diger<'static>>, SerderError> {
    items.iter().map(|s| parse_qb64_diger(s, field)).collect()
}

fn anchors_from_parsed(anchors: &[ParsedSeal<'_>]) -> Result<Vec<Seal>, SerderError> {
    anchors.iter().map(seal_from_parsed).collect()
}

// ---------------------------------------------------------------------------
// Digest code inference
// ---------------------------------------------------------------------------

/// Infer the [`DigestCode`] from a qb64 SAID string by parsing its code prefix.
fn infer_digest_code(qb64_said: &str) -> Result<DigestCode, SerderError> {
    let matter_code = MatterCode::from_base64_stream(qb64_said.as_bytes()).map_err(|e| {
        SerderError::InvalidPrimitive {
            field: "d",
            source: ValidationError::UnknownMatterCode(e.to_string()),
        }
    })?;
    DigestCode::try_from(matter_code).map_err(|e| SerderError::InvalidPrimitive {
        field: "d",
        source: e,
    })
}

// ---------------------------------------------------------------------------
// Primitive parsing helpers
// ---------------------------------------------------------------------------

fn parse_qb64_prefixer(s: &str, field: &'static str) -> Result<Prefixer<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let narrowed = matter
        .narrow::<VerKeyCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(narrowed.into_static())
}

/// Parse a qb64 string as a KERI identifier prefix, which may be either a
/// verification key (basic derivation) or a digest (self-addressing derivation).
///
/// Tries `VerKeyCode` first (basic derivation like `D`); if that fails, tries
/// `DigestCode` (self-addressing like `E`). Returns the typed [`Identifier`]
/// enum preserving the original code.
fn parse_qb64_identifier(s: &str, field: &'static str) -> Result<Identifier<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;

    if let Ok(narrowed) = matter.narrow::<VerKeyCode>() {
        return Ok(Identifier::Basic(narrowed.into_static()));
    }

    let digest_matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let saider = digest_matter
        .narrow::<DigestCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(Identifier::SelfAddressing(saider.into_static()))
}

fn parse_qb64_verfer(s: &str, field: &'static str) -> Result<Verfer<'static>, SerderError> {
    parse_qb64_prefixer(s, field)
}

fn parse_qb64_diger(s: &str, field: &'static str) -> Result<Diger<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let narrowed = matter
        .narrow::<DigestCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(narrowed.into_static())
}

fn parse_qb64_saider(s: &str, field: &'static str) -> Result<Saider<'static>, SerderError> {
    parse_qb64_diger(s, field)
}

fn map_qb64_error(field: &'static str, err: MatterBuildError) -> SerderError {
    match err {
        MatterBuildError::Validation(source) => SerderError::InvalidPrimitive { field, source },
        MatterBuildError::Parsing(source) => SerderError::UnparseablePrimitive { field, source },
    }
}

fn parse_sn(s: &str) -> Result<u128, SerderError> {
    u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
        field: "s",
        source: ValidationError::UnknownMatterCode(format!("invalid hex sn: {s}")),
    })
}

fn parse_weight(s: &str) -> Result<(u64, u64), SerderError> {
    if let Some((num_s, den_s)) = s.split_once('/') {
        let num: u64 = num_s.parse().map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!("invalid fraction numerator: {s}")),
        })?;
        let den: u64 = den_s.parse().map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!(
                "invalid fraction denominator: {s}"
            )),
        })?;
        if den == 0 {
            return Err(SerderError::InvalidPrimitive {
                field: "kt",
                source: ValidationError::UnknownMatterCode(format!(
                    "zero denominator in weight: {s}"
                )),
            });
        }
        Ok((num, den))
    } else {
        let val: u64 = s.parse().map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!("invalid weight: {s}")),
        })?;
        Ok((val, 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{CesrCode, DigestCode, VerKeyCode};
    use crate::core::matter::error::ParsingError;
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer};
    use crate::keri::{
        DelegatedInceptionEvent, DelegatedRotationEvent, InceptionEvent, InteractionEvent,
        RotationEvent,
    };
    use crate::serder::primitives::to_qb64_string;
    use crate::serder::said::{compute_digest, said_placeholder};
    use crate::serder::serialize::{
        serialize, serialize_delegated_inception, serialize_delegated_rotation,
        serialize_inception, serialize_interaction, serialize_rotation,
    };
    use alloc::borrow::Cow;
    use serde_json::Value;

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_verfer() -> Verfer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![1u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_diger() -> Diger<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![2u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn qb64(m: &crate::core::matter::matter::Matter<'_, impl CesrCode>) -> String {
        crate::serder::primitives::to_qb64_string(m)
    }

    // -----------------------------------------------------------------------
    // Roundtrip tests: serialize -> deserialize -> compare fields
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_icp() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            1,
            vec![ConfigTrait::EstOnly],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.sn().value(), 0);
        assert_eq!(deserialized.keys().len(), 1);
        assert_eq!(deserialized.next_keys().len(), 1);
        assert_eq!(*deserialized.threshold(), Tholder::Simple(1));
        assert_eq!(*deserialized.next_threshold(), Tholder::Simple(1));
        assert_eq!(deserialized.witnesses().len(), 1);
        assert_eq!(deserialized.witness_threshold(), 1);
        assert_eq!(deserialized.config(), [ConfigTrait::EstOnly]);
        assert!(deserialized.anchors().is_empty());
        assert_eq!(qb64(deserialized.said()), qb64(serialized.said()));
        assert_eq!(
            deserialized.prefix().as_saider().unwrap().raw(),
            deserialized.said().raw(),
            "self-addressing prefix raw bytes should match SAID raw bytes"
        );
    }

    #[test]
    fn roundtrip_rot() {
        let event = RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            vec![],
            1,
            vec![],
            vec![],
        );
        let serialized = serialize_rotation(&event).unwrap();
        let deserialized = deserialize_rotation(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.sn().value(), 1);
        assert_eq!(deserialized.keys().len(), 1);
        assert_eq!(deserialized.next_keys().len(), 1);
        assert_eq!(*deserialized.threshold(), Tholder::Simple(1));
        assert_eq!(deserialized.witness_additions().len(), 1);
        assert!(deserialized.witness_removals().is_empty());
        assert_eq!(deserialized.witness_threshold(), 1);
        assert!(deserialized.config().is_empty());
        assert!(deserialized.anchors().is_empty());
        assert_eq!(qb64(deserialized.said()), qb64(serialized.said()));
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.prefix()),
            crate::serder::primitives::identifier_to_qb64_string(event.prefix())
        );
    }

    #[test]
    fn roundtrip_ixn() {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(3),
            make_saider(),
            make_saider(),
            vec![
                Seal::Digest { d: make_saider() },
                Seal::Source {
                    s: Seqner::new(1),
                    d: make_saider(),
                },
            ],
        );
        let serialized = serialize_interaction(&event).unwrap();
        let deserialized = deserialize_interaction(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.sn().value(), 3);
        assert_eq!(deserialized.anchors().len(), 2);
        assert_eq!(qb64(deserialized.said()), qb64(serialized.said()));
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.prefix()),
            crate::serder::primitives::identifier_to_qb64_string(event.prefix())
        );
    }

    #[test]
    fn roundtrip_dip() {
        let event = DelegatedInceptionEvent::new(
            InceptionEvent::new(
                make_prefixer().into(),
                Seqner::new(0),
                make_saider(),
                vec![make_verfer()],
                Tholder::Simple(1),
                vec![make_diger()],
                Tholder::Simple(1),
                vec![make_prefixer()],
                1,
                vec![],
                vec![],
            ),
            make_prefixer().into(),
        );
        let serialized = serialize_delegated_inception(&event).unwrap();
        let deserialized = deserialize_delegated_inception(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.inception().sn().value(), 0);
        assert_eq!(deserialized.inception().keys().len(), 1);
        assert_eq!(deserialized.inception().witnesses().len(), 1);
        assert_eq!(deserialized.inception().witness_threshold(), 1);
        assert_eq!(
            qb64(deserialized.inception().said()),
            qb64(serialized.said())
        );
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.delegator()),
            crate::serder::primitives::identifier_to_qb64_string(event.delegator())
        );
    }

    #[test]
    fn roundtrip_drt() {
        let event = DelegatedRotationEvent::new(RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            vec![],
            1,
            vec![],
            vec![],
        ));
        let serialized = serialize_delegated_rotation(&event).unwrap();
        let deserialized = deserialize_delegated_rotation(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.rotation().sn().value(), 1);
        assert_eq!(deserialized.rotation().keys().len(), 1);
        assert_eq!(deserialized.rotation().witness_additions().len(), 1);
        assert!(deserialized.rotation().witness_removals().is_empty());
        assert_eq!(
            qb64(deserialized.rotation().said()),
            qb64(serialized.said())
        );
        assert_eq!(
            crate::serder::primitives::identifier_to_qb64_string(deserialized.rotation().prefix()),
            crate::serder::primitives::identifier_to_qb64_string(event.rotation().prefix())
        );
    }

    // -----------------------------------------------------------------------
    // Unified dispatch via deserialize_event
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_event_dispatches_icp() {
        let icp = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let ser = serialize(&KeriEvent::Inception(icp)).unwrap();
        let deser = deserialize_event(ser.as_bytes()).unwrap();
        assert!(matches!(deser, KeriEvent::Inception(_)));
    }

    #[test]
    fn deserialize_event_dispatches_rot() {
        let rot = RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            vec![],
            0,
            vec![],
            vec![],
        );
        let ser = serialize(&KeriEvent::Rotation(rot)).unwrap();
        let deser = deserialize_event(ser.as_bytes()).unwrap();
        assert!(matches!(deser, KeriEvent::Rotation(_)));
    }

    #[test]
    fn deserialize_event_dispatches_ixn() {
        let ixn = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![],
        );
        let ser = serialize(&KeriEvent::Interaction(ixn)).unwrap();
        let deser = deserialize_event(ser.as_bytes()).unwrap();
        assert!(matches!(deser, KeriEvent::Interaction(_)));
    }

    // -----------------------------------------------------------------------
    // SAID tamper detection
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_said_fails_verification() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let mut json_str = String::from_utf8(serialized.as_bytes().to_vec()).unwrap();

        // Tamper with the JSON by modifying the sn value
        json_str = json_str.replace("\"s\":\"0\"", "\"s\":\"1\"");

        let result = deserialize_inception(json_str.as_bytes());
        assert!(
            result.is_err(),
            "tampered event should fail SAID verification"
        );
        let err = result.err().unwrap();
        assert!(matches!(err, SerderError::SaidMismatch { .. }));
    }

    #[test]
    fn tampered_rot_said_fails() {
        let event = RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            vec![],
            0,
            vec![],
            vec![],
        );
        let serialized = serialize_rotation(&event).unwrap();
        let mut json_str = String::from_utf8(serialized.as_bytes().to_vec()).unwrap();

        json_str = json_str.replace("\"s\":\"1\"", "\"s\":\"2\"");

        let result = deserialize_rotation(json_str.as_bytes());
        assert!(
            result.is_err(),
            "tampered rotation should fail SAID verification"
        );
    }

    // -----------------------------------------------------------------------
    // Seal roundtrips through serialize/deserialize
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_all_seal_types() {
        let seals = vec![
            Seal::Digest { d: make_saider() },
            Seal::Root { rd: make_saider() },
            Seal::Source {
                s: Seqner::new(5),
                d: make_saider(),
            },
            Seal::Event {
                i: make_prefixer(),
                s: Seqner::new(0xff),
                d: make_saider(),
            },
            Seal::Last { i: make_prefixer() },
        ];
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(2),
            make_saider(),
            make_saider(),
            seals,
        );
        let serialized = serialize_interaction(&event).unwrap();
        let deserialized = deserialize_interaction(serialized.as_bytes()).unwrap();

        assert_eq!(deserialized.anchors().len(), 5);

        let Seal::Digest { d: dig_d } = &deserialized.anchors()[0] else {
            unreachable!()
        };
        assert_eq!(*dig_d.code(), DigestCode::Blake3_256);

        let Seal::Root { rd: root_rd } = &deserialized.anchors()[1] else {
            unreachable!()
        };
        assert_eq!(*root_rd.code(), DigestCode::Blake3_256);

        let Seal::Source { s: src_s, d: src_d } = &deserialized.anchors()[2] else {
            unreachable!()
        };
        assert_eq!(src_s.value(), 5);
        assert_eq!(*src_d.code(), DigestCode::Blake3_256);

        let Seal::Event {
            i: ev_i,
            s: ev_sn,
            d: ev_d,
        } = &deserialized.anchors()[3]
        else {
            unreachable!()
        };
        assert_eq!(*ev_i.code(), VerKeyCode::Ed25519);
        assert_eq!(ev_sn.value(), 0xff);
        assert_eq!(*ev_d.code(), DigestCode::Blake3_256);

        let Seal::Last { i: last_i } = &deserialized.anchors()[4] else {
            unreachable!()
        };
        assert_eq!(*last_i.code(), VerKeyCode::Ed25519);
    }

    // -----------------------------------------------------------------------
    // Weighted threshold roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_weighted_threshold() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer()],
            Tholder::Weighted(vec![vec![(1, 2), (1, 2)]]),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();

        assert_eq!(
            *deserialized.threshold(),
            Tholder::Weighted(vec![vec![(1, 2), (1, 2)]])
        );
    }

    // -----------------------------------------------------------------------
    // Config trait roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_config_traits() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![ConfigTrait::EstOnly, ConfigTrait::DoNotDelegate],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();

        assert_eq!(
            deserialized.config(),
            [ConfigTrait::EstOnly, ConfigTrait::DoNotDelegate]
        );
    }

    // -----------------------------------------------------------------------
    // Weighted threshold boundary values (0 and 1)
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_weighted_threshold_boundary_values() {
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer(), make_verfer(), make_verfer()],
            Tholder::Weighted(vec![vec![(0, 1), (1, 2), (1, 1)]]),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(serialized.as_bytes()).expect("valid json");
        let kt = json["kt"].as_array().expect("kt is array");

        assert_eq!(kt[0].as_str().expect("0 boundary"), "0");
        assert_eq!(kt[1].as_str().expect("fraction"), "1/2");
        assert_eq!(kt[2].as_str().expect("1 boundary"), "1");

        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();
        assert_eq!(
            *deserialized.threshold(),
            Tholder::Weighted(vec![vec![(0, 1), (1, 2), (1, 1)]])
        );
    }

    // -----------------------------------------------------------------------
    // parse_weight handles boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn parse_weight_fraction() {
        let (n, d) = parse_weight("1/3").unwrap();
        assert_eq!((n, d), (1, 3));
    }

    #[test]
    fn parse_weight_zero() {
        let (n, d) = parse_weight("0").unwrap();
        assert_eq!((n, d), (0, 1));
    }

    #[test]
    fn parse_weight_one() {
        let (n, d) = parse_weight("1").unwrap();
        assert_eq!((n, d), (1, 1));
    }

    #[test]
    fn parse_weight_rejects_zero_denominator() {
        // Bug probe: "0/0" and "1/0" previously parsed into (0,0)/(1,0), and
        // a (0,0) weight made re-serialization divide by zero (panic on
        // untrusted-derived data).
        assert!(matches!(
            parse_weight("0/0"),
            Err(SerderError::InvalidPrimitive { field: "kt", .. })
        ));
        assert!(matches!(
            parse_weight("1/0"),
            Err(SerderError::InvalidPrimitive { field: "kt", .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Version-string validation at every public entry point
    // -----------------------------------------------------------------------

    /// Insert one space after the first comma: the parsed JSON (and therefore
    /// the SAID computed over its compact re-serialization) is unchanged, but
    /// the raw length no longer matches the version-string size field.
    fn whitespace_padded(raw: &[u8]) -> Vec<u8> {
        let idx = raw
            .iter()
            .position(|b| *b == b',')
            .expect("event JSON has a comma");
        let mut padded = Vec::with_capacity(raw.len() + 1);
        padded.extend_from_slice(&raw[..=idx]);
        padded.push(b' ');
        padded.extend_from_slice(&raw[idx + 1..]);
        padded
    }

    fn probe_icp() -> InceptionEvent {
        InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            0,
            vec![],
            vec![],
        )
    }

    fn probe_rot() -> RotationEvent {
        RotationEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            vec![],
            0,
            vec![],
            vec![],
        )
    }

    #[test]
    fn deserialize_inception_rejects_length_mismatched_raw() {
        let raw = serialize_inception(&probe_icp()).unwrap();
        let padded = whitespace_padded(raw.as_bytes());
        // Precondition making this a real probe: the padded bytes are still
        // valid JSON with an intact SAID — only the length lies.
        assert!(serde_json::from_slice::<Value>(&padded).is_ok());
        assert!(
            matches!(
                deserialize_inception(&padded),
                Err(SerderError::InvalidVersionString(_))
            ),
            "deserialize_inception must reject raw whose length contradicts its version string"
        );
    }

    #[test]
    fn deserialize_event_rejects_length_mismatched_raw() {
        let raw = serialize_inception(&probe_icp()).unwrap();
        let padded = whitespace_padded(raw.as_bytes());
        assert!(
            matches!(
                deserialize_event(&padded),
                Err(SerderError::InvalidVersionString(_))
            ),
            "deserialize_event must keep rejecting length-mismatched raw"
        );
    }

    #[test]
    fn deserialize_rotation_rejects_length_mismatched_raw() {
        let raw = serialize_rotation(&probe_rot()).unwrap();
        assert!(
            matches!(
                deserialize_rotation(&whitespace_padded(raw.as_bytes())),
                Err(SerderError::InvalidVersionString(_))
            ),
            "deserialize_rotation must reject length-mismatched raw"
        );
    }

    #[test]
    fn deserialize_interaction_rejects_length_mismatched_raw() {
        let event = InteractionEvent::new(
            make_prefixer().into(),
            Seqner::new(1),
            make_saider(),
            make_saider(),
            vec![],
        );
        let raw = serialize_interaction(&event).unwrap();
        assert!(
            matches!(
                deserialize_interaction(&whitespace_padded(raw.as_bytes())),
                Err(SerderError::InvalidVersionString(_))
            ),
            "deserialize_interaction must reject length-mismatched raw"
        );
    }

    #[test]
    fn deserialize_delegated_inception_rejects_length_mismatched_raw() {
        let event = DelegatedInceptionEvent::new(probe_icp(), make_prefixer().into());
        let raw = serialize_delegated_inception(&event).unwrap();
        assert!(
            matches!(
                deserialize_delegated_inception(&whitespace_padded(raw.as_bytes())),
                Err(SerderError::InvalidVersionString(_))
            ),
            "deserialize_delegated_inception must reject length-mismatched raw"
        );
    }

    #[test]
    fn deserialize_delegated_rotation_rejects_length_mismatched_raw() {
        let event = DelegatedRotationEvent::new(probe_rot());
        let raw = serialize_delegated_rotation(&event).unwrap();
        assert!(
            matches!(
                deserialize_delegated_rotation(&whitespace_padded(raw.as_bytes())),
                Err(SerderError::InvalidVersionString(_))
            ),
            "deserialize_delegated_rotation must reject length-mismatched raw"
        );
    }

    // -----------------------------------------------------------------------
    // Strict-path behavior probes: intive acceptance and per-ilk rejection
    // -----------------------------------------------------------------------

    /// Rewrite the size field and recompute + splice the SAID so byte-level
    /// surgery on a serialized event stays canonical and verifiable.
    /// Single-SAID recomputation — valid for icp probes only when d != i
    /// (`probe_icp` uses a basic prefix, so that holds).
    fn resaid(mut raw: Vec<u8>) -> Vec<u8> {
        let size = raw.len();
        let hex = format!("{size:06x}");
        raw[16..22].copy_from_slice(hex.as_bytes());
        let d_pos = raw.windows(5).position(|w| w == b"\"d\":\"").unwrap() + 5;
        let span = d_pos..d_pos + 44;
        let placeholder = said_placeholder(DigestCode::Blake3_256).unwrap();
        let mut scratch = raw.clone();
        scratch[span.clone()].copy_from_slice(placeholder.as_bytes());
        let computed = compute_digest(&scratch, DigestCode::Blake3_256).unwrap();
        let qb64_said = to_qb64_string(&computed);
        raw[span].copy_from_slice(qb64_said.as_bytes());
        raw
    }

    #[test]
    fn intive_integer_bt_is_accepted() {
        let raw = serialize_inception(&probe_icp())
            .unwrap()
            .as_bytes()
            .to_vec();
        let pos = raw.windows(9).position(|w| w == b"\"bt\":\"0\",").unwrap();
        let mut mutated = Vec::with_capacity(raw.len());
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b"\"bt\":0,");
        mutated.extend_from_slice(&raw[pos + 9..]);
        let canonical_intive = resaid(mutated);
        let event = deserialize_inception(&canonical_intive)
            .expect("keripy intive=True integer bt must deserialize");
        assert_eq!(event.witness_threshold(), 0);
    }

    #[test]
    fn intive_integer_kt_is_accepted() {
        let raw = serialize_inception(&probe_icp())
            .unwrap()
            .as_bytes()
            .to_vec();
        let pos = raw.windows(9).position(|w| w == b"\"kt\":\"1\",").unwrap();
        let mut mutated = Vec::with_capacity(raw.len());
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b"\"kt\":1,");
        mutated.extend_from_slice(&raw[pos + 9..]);
        let canonical_intive = resaid(mutated);
        let event = deserialize_inception(&canonical_intive)
            .expect("keripy intive=True integer kt must deserialize");
        assert_eq!(*event.threshold(), Tholder::Simple(1));
    }

    #[test]
    fn deserialize_rotation_rejects_drt_bytes() {
        let drt = DelegatedRotationEvent::new(probe_rot());
        let raw = serialize_delegated_rotation(&drt).unwrap();
        assert!(matches!(
            deserialize_rotation(raw.as_bytes()),
            Err(SerderError::NonCanonical {
                expected: "rot",
                ..
            })
        ));
    }

    #[test]
    fn deserialize_inception_rejects_dip_bytes() {
        let dip = DelegatedInceptionEvent::new(probe_icp(), make_prefixer().into());
        let raw = serialize_delegated_inception(&dip).unwrap();
        assert!(
            deserialize_inception(raw.as_bytes()).is_err(),
            "dip bytes must not silently deserialize as icp (delegator dropped)"
        );
    }

    // -----------------------------------------------------------------------
    // Parse-failure routing: a malformed qb64 code is a parsing-domain error
    // -----------------------------------------------------------------------

    #[test]
    fn unparseable_qb64_field_surfaces_as_parsing_domain_error() {
        // A malformed qb64 primitive (bad code) is a parse failure, not a
        // validation failure — it must not be collapsed into a ValidationError.
        // `Diger`/`Matter` does not implement `Debug`, so `matches!` on the
        // whole `Result` avoids requiring the `Ok` value to be printable.
        let result = parse_qb64_diger("!!not-qb64!!", "d");
        assert!(
            matches!(
                result,
                Err(SerderError::UnparseablePrimitive { field: "d", .. })
            ),
            "expected UnparseablePrimitive parse-domain error"
        );
    }

    #[test]
    fn map_qb64_error_routes_validation_to_invalid_primitive() {
        // The Validation arm must land in InvalidPrimitive — the other half of the
        // routing the bug corrupted (it previously misrouted Parsing into a
        // stringified ValidationError). Pin both directions.
        let err = map_qb64_error(
            "d",
            MatterBuildError::Validation(ValidationError::StructuralIntegrityError),
        );
        assert!(
            matches!(err, SerderError::InvalidPrimitive { field: "d", .. }),
            "expected InvalidPrimitive, got {err:?}"
        );
    }

    #[test]
    fn map_qb64_error_routes_parsing_to_unparseable_primitive() {
        let err = map_qb64_error("d", MatterBuildError::Parsing(ParsingError::EmptyStream));
        assert!(
            matches!(err, SerderError::UnparseablePrimitive { field: "d", .. }),
            "expected UnparseablePrimitive, got {err:?}"
        );
    }
}
