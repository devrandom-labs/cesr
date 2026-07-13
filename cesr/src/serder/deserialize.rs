//! KERI event deserialization from canonical JSON with SAID verification.
//!
//! The read path is a strict single-pass canonical parser
//! ([`canonical`]): compact JSON, spec field order, no escapes — any
//! deviation is a typed [`SerderError::NonCanonical`]. SAID verification
//! is offset-based: one scratch copy of the raw bytes, the `d` (and `i`
//! for `icp`/`dip`) spans overwritten with `#`, one hash — no
//! parse-mutate-re-render.

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::{DigestCode, MatterCode, VerKeyCode, VerserCode};
use crate::core::matter::error::{MatterBuildError, ValidationError};
use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer, Verser};
use crate::keri::toad::Toad;
use crate::keri::{
    ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, InceptionEvent,
    InteractionEvent, KeriEvent, OpaqueSeal, RotationEvent, Seal,
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
    let witnesses = prefixers_from_parsed(&p.witnesses, "b")?;
    let witness_threshold = Toad::exact(
        witness_threshold_wire(&p.witness_threshold)?,
        witnesses.len(),
    )?;
    Ok(InceptionEvent::new(
        parse_qb64_identifier(p.prefix.value, "i")?,
        Seqner::new(parse_sn(p.sn)?),
        parse_qb64_diger(p.said.value, "d")?,
        verfers_from_parsed(&p.keys, "k")?,
        tholder_from_parsed(&p.threshold)?,
        digers_from_parsed(&p.next_keys, "n")?,
        tholder_from_parsed(&p.next_threshold)?,
        witnesses,
        witness_threshold,
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
        Toad::from_wire(witness_threshold_wire(&p.witness_threshold)?),
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

fn witness_threshold_wire(c: &ParsedCount<'_>) -> Result<u32, SerderError> {
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
        ParsedSeal::Back { bi, d } => Ok(Seal::Back {
            bi: parse_qb64_prefixer(bi, "bi")?,
            d: parse_qb64_saider(d, "d")?,
        }),
        ParsedSeal::Kind { t, d } => Ok(Seal::Kind {
            t: parse_qb64_verser(t, "t")?,
            d: parse_qb64_saider(d, "d")?,
        }),
        // Defensively re-validated: the scanner already proved the span is
        // one well-formed compact object, so this construction cannot fail
        // on scanner-produced input.
        ParsedSeal::Opaque { raw } => Ok(Seal::Opaque(
            OpaqueSeal::new((*raw).to_owned())
                .map_err(|source| SerderError::InvalidAnchor { offset: 0, source })?,
        )),
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

fn parse_qb64_verser(s: &str, field: &'static str) -> Result<Verser<'static>, SerderError> {
    let matter = MatterBuilder::new()
        .from_qualified_base64(s.as_bytes())
        .map_err(|e| map_qb64_error(field, e))?;
    let narrowed = matter
        .narrow::<VerserCode>()
        .map_err(|e| SerderError::InvalidPrimitive { field, source: e })?;
    Ok(narrowed.into_static())
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
    use crate::core::matter::code::{CesrCode, DigestCode, VerKeyCode, VerserCode};
    use crate::core::matter::error::ParsingError;
    use crate::core::primitives::{Diger, Prefixer, Saider, Seqner, Tholder, Verfer, Verser};
    use crate::keri::toad::ToadError;
    use crate::keri::{
        DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, InceptionEvent,
        InteractionEvent, OpaqueSeal, RotationEvent,
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

    fn make_verser() -> Verser<'static> {
        MatterBuilder::new()
            .from_qualified_base64(b"YKERIBAA")
            .unwrap()
            .narrow::<VerserCode>()
            .unwrap()
            .into_static()
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
            Identifier::SelfAddressing(make_saider()),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
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
        assert_eq!(deserialized.witness_threshold().value(), 1);
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
    fn roundtrip_icp_basic_derivation() {
        // A basic-derivation inception (#144): `i` is the public key, not the
        // SAID. The writer must carry it verbatim and the reader must narrow
        // it back to Identifier::Basic with the same qb64.
        let event = InceptionEvent::new(
            make_prefixer().into(),
            Seqner::new(0),
            make_saider(),
            vec![make_verfer()],
            Tholder::Simple(1),
            vec![make_diger()],
            Tholder::Simple(1),
            vec![],
            Toad::exact(0, 0).unwrap(),
            vec![],
            vec![],
        );
        let serialized = serialize_inception(&event).unwrap();
        let deserialized = deserialize_inception(serialized.as_bytes()).unwrap();

        let prefixer = deserialized
            .prefix()
            .as_prefixer()
            .expect("basic-derivation prefix must deserialize as Identifier::Basic");
        assert_eq!(qb64(prefixer), qb64(&make_prefixer()));
        assert_eq!(qb64(deserialized.said()), qb64(serialized.said()));
        assert_ne!(
            qb64(prefixer),
            qb64(deserialized.said()),
            "basic inception is single-SAID: i != d"
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
            Toad::from_wire(1),
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
        assert_eq!(deserialized.witness_threshold().value(), 1);
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
                Toad::exact(1, 1).unwrap(),
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
        assert_eq!(deserialized.inception().witness_threshold().value(), 1);
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
            Toad::from_wire(1),
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
            Toad::exact(0, 0).unwrap(),
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
            Toad::from_wire(0),
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
            Toad::exact(0, 0).unwrap(),
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
            Toad::from_wire(0),
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
            Toad::exact(0, 0).unwrap(),
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
            Toad::exact(0, 0).unwrap(),
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
            Toad::exact(0, 0).unwrap(),
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
            Toad::exact(0, 0).unwrap(),
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
            Toad::from_wire(0),
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

    /// Bug-probe #150: a SAID-valid rot carrying a `c` field must be
    /// rejected by BOTH read paths — the v1 rot grammar has no `c` slot.
    #[test]
    fn rot_with_config_field_is_rejected_by_both_paths() {
        let raw = serialize_rotation(&probe_rot())
            .unwrap()
            .as_bytes()
            .to_vec();
        let pos = raw.windows(5).position(|w| w == b",\"a\":").unwrap();
        let mut mutated = Vec::with_capacity(raw.len() + 7);
        mutated.extend_from_slice(&raw[..pos]);
        mutated.extend_from_slice(b",\"c\":[]");
        mutated.extend_from_slice(&raw[pos..]);
        let canonical = resaid(mutated);

        assert!(matches!(
            deserialize_rotation(&canonical),
            Err(SerderError::NonCanonical { .. })
        ));
        assert!(matches!(
            reference::deserialize_rotation(&canonical),
            Err(SerderError::UnexpectedField("c"))
        ));
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
        assert_eq!(event.witness_threshold().value(), 0);
    }

    /// #171: icp TOAD is validated against the wire witness count at parse
    /// time (`Toad::exact` in `build_inception`), and the differential
    /// proptests `prop_assume!` that region away — so strict/reference
    /// agreement on REJECTING it needs its own deterministic probe. A
    /// SAID-valid icp with `bt` out of range (1 with no witnesses) must be
    /// rejected by BOTH read paths with the same typed payload.
    #[test]
    fn invalid_toad_icp_is_rejected_by_both_paths() {
        let raw = serialize_inception(&probe_icp())
            .unwrap()
            .as_bytes()
            .to_vec();
        let pos = raw.windows(9).position(|w| w == b"\"bt\":\"0\",").unwrap();
        let mut mutated = raw;
        mutated[pos + 6] = b'1';
        let canonical = resaid(mutated);

        assert!(
            matches!(
                deserialize_inception(&canonical),
                Err(SerderError::Toad(ToadError::OutOfRange {
                    toad: 1,
                    witnesses: 0
                }))
            ),
            "strict path must reject an out-of-range icp toad"
        );
        assert!(
            matches!(
                reference::deserialize_inception(&canonical),
                Err(SerderError::Toad(ToadError::OutOfRange {
                    toad: 1,
                    witnesses: 0
                }))
            ),
            "reference path must reject an out-of-range icp toad with the same payload"
        );
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
        assert!(matches!(
            deserialize_inception(raw.as_bytes()),
            Err(SerderError::NonCanonical {
                expected: "icp",
                ..
            })
        ));
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

    // -----------------------------------------------------------------------
    // Overflow boundaries: the conversion layer between parsed decimal/hex
    // text and fixed-width integers must reject overflow as a typed error,
    // never wrap or saturate.
    // -----------------------------------------------------------------------

    #[test]
    fn tholder_number_overflow_is_invalid_primitive() {
        let over_u64 = "18446744073709551616"; // u64::MAX + 1
        assert!(matches!(
            tholder_from_parsed(&ParsedTholder::Number(over_u64)),
            Err(SerderError::InvalidPrimitive { field: "kt", .. })
        ));
        let max_u64 = "18446744073709551615";
        assert!(matches!(
            tholder_from_parsed(&ParsedTholder::Number(max_u64)),
            Ok(Tholder::Simple(u64::MAX))
        ));
    }

    #[test]
    fn witness_threshold_overflow_is_invalid_primitive() {
        assert!(matches!(
            witness_threshold_wire(&ParsedCount::Number("4294967296")), // u32::MAX + 1
            Err(SerderError::InvalidPrimitive { field: "bt", .. })
        ));
        assert_eq!(
            witness_threshold_wire(&ParsedCount::Number("4294967295")).unwrap(),
            u32::MAX
        );
        assert!(matches!(
            witness_threshold_wire(&ParsedCount::Number(
                "340282366920938463463374607431768211456"
            )), // u128::MAX + 1
            Err(SerderError::InvalidPrimitive { field: "bt", .. })
        ));
        assert!(matches!(
            witness_threshold_wire(&ParsedCount::Hex("100000000")), // > u32::MAX in hex
            Err(SerderError::InvalidPrimitive { field: "bt", .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Differential: strict canonical parser vs. the pre-#142 tolerant oracle
    // -----------------------------------------------------------------------

    mod differential {
        use super::super::reference;
        use super::*;
        use crate::serder::event_strategies::{
            IdSpec, TholderSpec, build_icp, build_identifier, build_ixn, build_rot, icp_strategy,
            ixn_strategy, rot_strategy,
        };
        use crate::serder::serialize::{EventRef, SerdeJson, serialize_with};
        use proptest::prelude::*;

        /// The reference oracle is the single source of validity truth: a
        /// `TholderSpec` is only usable in a differential test if the oracle
        /// itself would accept the weighted clauses it produces (rejects
        /// zero-denominator fractions via `parse_weight`, shared by both
        /// parsers). Filtering here keeps that rule in one place instead of
        /// duplicating `parse_weight`'s validity logic in the strategy layer.
        fn has_valid_weights(spec: &TholderSpec) -> bool {
            let (simple, _, clauses) = spec;
            *simple || clauses.iter().flatten().all(|(_, den)| *den != 0)
        }

        /// `build_inception` now validates `bt` against the wire witness
        /// count via [`Toad::exact`] (icp/dip are read-time-validated;
        /// rotation stays [`Toad::from_wire`], unvalidated). The icp/dip
        /// differential strategies draw `bt` and the witness list
        /// independently, so an arbitrary draw is out of range far more
        /// often than not — filter to the domain `deserialize_inception`
        /// actually accepts.
        fn has_valid_toad(bt: u32, witness_count: usize) -> bool {
            Toad::exact(bt, witness_count).is_ok()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn icp_strict_equals_reference(spec in icp_strategy()) {
                prop_assume!(has_valid_weights(&spec.4) && has_valid_weights(&spec.6));
                prop_assume!(has_valid_toad(spec.8, spec.7.len()));
                let event = build_icp(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Inception(&event)).unwrap();
                let strict = deserialize_inception(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_inception(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_inception(&strict).unwrap();
                let oracle_bytes = serialize_inception(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn rot_strict_equals_reference(spec in rot_strategy()) {
                prop_assume!(has_valid_weights(&spec.5) && has_valid_weights(&spec.7));
                let event = build_rot(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Rotation(&event)).unwrap();
                let strict = deserialize_rotation(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_rotation(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_rotation(&strict).unwrap();
                let oracle_bytes = serialize_rotation(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn ixn_strict_equals_reference(spec in ixn_strategy()) {
                let event = build_ixn(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Interaction(&event)).unwrap();
                let strict = deserialize_interaction(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_interaction(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_interaction(&strict).unwrap();
                let oracle_bytes = serialize_interaction(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn dip_strict_equals_reference(spec in icp_strategy(), delegator in any::<IdSpec>()) {
                prop_assume!(has_valid_weights(&spec.4) && has_valid_weights(&spec.6));
                prop_assume!(has_valid_toad(spec.8, spec.7.len()));
                let dip = DelegatedInceptionEvent::new(build_icp(spec), build_identifier(delegator));
                let bytes = serialize_with(&SerdeJson, EventRef::DelegatedInception(&dip)).unwrap();
                let strict = deserialize_delegated_inception(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_delegated_inception(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_delegated_inception(&strict).unwrap();
                let oracle_bytes = serialize_delegated_inception(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            #[test]
            fn drt_strict_equals_reference(spec in rot_strategy()) {
                prop_assume!(has_valid_weights(&spec.5) && has_valid_weights(&spec.7));
                let drt = DelegatedRotationEvent::new(build_rot(spec));
                let bytes = serialize_with(&SerdeJson, EventRef::DelegatedRotation(&drt)).unwrap();
                let strict = deserialize_delegated_rotation(bytes.as_bytes()).unwrap();
                let oracle = reference::deserialize_delegated_rotation(bytes.as_bytes()).unwrap();
                let strict_bytes = serialize_delegated_rotation(&strict).unwrap();
                let oracle_bytes = serialize_delegated_rotation(&oracle).unwrap();
                prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                prop_assert_eq!(strict_bytes.as_bytes(), bytes.as_bytes());
            }

            /// Strict acceptance is a subset of tolerant acceptance: any
            /// single-byte mutation the strict parser accepts, the reference
            /// oracle must also accept — and both must see the same event.
            #[test]
            fn strict_acceptance_is_subset_of_reference(
                spec in ixn_strategy(),
                idx in any::<prop::sample::Index>(),
                byte in any::<u8>(),
            ) {
                let event = build_ixn(spec);
                let bytes = serialize_with(&SerdeJson, EventRef::Interaction(&event)).unwrap();
                let mut mutated = bytes.as_bytes().to_vec();
                let i = idx.index(mutated.len());
                mutated[i] = byte;
                if let Ok(strict) = deserialize_interaction(&mutated) {
                    let oracle = reference::deserialize_interaction(&mutated);
                    prop_assert!(
                        oracle.is_ok(),
                        "strict accepted a mutation the tolerant oracle rejects"
                    );
                    let strict_bytes = serialize_interaction(&strict).unwrap();
                    let oracle_bytes = serialize_interaction(&oracle.unwrap()).unwrap();
                    prop_assert_eq!(strict_bytes.as_bytes(), oracle_bytes.as_bytes());
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Deterministic per-variant coverage matrix (#142, Task 15).
    //
    // The `differential` proptests above hit enum variants by RANDOM draw.
    // This module pins EVERY variant and EVERY SAID branch explicitly, once,
    // deterministically: each builds a canonical serialized event embedding
    // exactly one variant, then asserts strict == oracle == original-bytes
    // AND pattern-matches the specific parsed arm. This is the guaranteed
    // complement to the probabilistic differential suite.
    // -----------------------------------------------------------------------
    mod variant_matrix {
        use super::super::reference;
        use super::*;

        // Per-ilk equivalence helpers: assert strict accepts, oracle accepts,
        // and both re-serialize to each other and to the original bytes.
        // Return the strict-parsed event so the caller can pin its variant.

        fn ixn_strict_eq_oracle(bytes: &[u8]) -> InteractionEvent {
            let strict = deserialize_interaction(bytes).expect("strict must accept");
            let oracle = reference::deserialize_interaction(bytes).expect("oracle must accept");
            let sb = serialize_interaction(&strict).unwrap();
            let ob = serialize_interaction(&oracle).unwrap();
            assert_eq!(sb.as_bytes(), ob.as_bytes(), "strict vs oracle divergence");
            assert_eq!(
                sb.as_bytes(),
                bytes,
                "re-serialization must reproduce original"
            );
            strict
        }

        fn icp_strict_eq_oracle(bytes: &[u8]) -> InceptionEvent {
            let strict = deserialize_inception(bytes).expect("strict must accept");
            let oracle = reference::deserialize_inception(bytes).expect("oracle must accept");
            let sb = serialize_inception(&strict).unwrap();
            let ob = serialize_inception(&oracle).unwrap();
            assert_eq!(sb.as_bytes(), ob.as_bytes(), "strict vs oracle divergence");
            assert_eq!(
                sb.as_bytes(),
                bytes,
                "re-serialization must reproduce original"
            );
            strict
        }

        fn ixn_with_anchor(seal: Seal) -> Vec<u8> {
            let event = InteractionEvent::new(
                make_prefixer().into(),
                Seqner::new(2),
                make_saider(),
                make_saider(),
                vec![seal],
            );
            serialize_interaction(&event).unwrap().as_bytes().to_vec()
        }

        fn icp_with_kt(kt: Tholder, key_count: usize) -> Vec<u8> {
            let keys: Vec<Verfer<'static>> = (0..key_count).map(|_| make_verfer()).collect();
            let event = InceptionEvent::new(
                make_prefixer().into(),
                Seqner::new(0),
                make_saider(),
                keys,
                kt,
                vec![make_diger()],
                Tholder::Simple(1),
                vec![],
                Toad::exact(0, 0).unwrap(),
                vec![],
                vec![],
            );
            serialize_inception(&event).unwrap().as_bytes().to_vec()
        }

        // -------------------------------------------------------------------
        // Matrix A — every `ParsedSeal` / `seal_from_parsed` arm (all 8),
        // driven through the ixn `a` array, one deterministic seal per test.
        // -------------------------------------------------------------------

        #[test]
        fn seal_digest_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Digest { d: make_saider() });
            let strict = ixn_strict_eq_oracle(&bytes);
            assert!(matches!(strict.anchors()[0], Seal::Digest { .. }));
        }

        #[test]
        fn seal_root_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Root { rd: make_saider() });
            let strict = ixn_strict_eq_oracle(&bytes);
            assert!(matches!(strict.anchors()[0], Seal::Root { .. }));
        }

        #[test]
        fn seal_source_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Source {
                s: Seqner::new(5),
                d: make_saider(),
            });
            let strict = ixn_strict_eq_oracle(&bytes);
            let Seal::Source { s, .. } = &strict.anchors()[0] else {
                unreachable!("expected Source seal")
            };
            assert_eq!(s.value(), 5);
        }

        #[test]
        fn seal_event_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Event {
                i: make_prefixer(),
                s: Seqner::new(0xff),
                d: make_saider(),
            });
            let strict = ixn_strict_eq_oracle(&bytes);
            let Seal::Event { s, .. } = &strict.anchors()[0] else {
                unreachable!("expected Event seal")
            };
            assert_eq!(s.value(), 0xff);
        }

        #[test]
        fn seal_last_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Last { i: make_prefixer() });
            let strict = ixn_strict_eq_oracle(&bytes);
            assert!(matches!(strict.anchors()[0], Seal::Last { .. }));
        }

        #[test]
        fn seal_back_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Back {
                bi: make_prefixer(),
                d: make_saider(),
            });
            let strict = ixn_strict_eq_oracle(&bytes);
            assert!(matches!(strict.anchors()[0], Seal::Back { .. }));
        }

        #[test]
        fn seal_kind_variant_is_pinned() {
            let bytes = ixn_with_anchor(Seal::Kind {
                t: make_verser(),
                d: make_saider(),
            });
            let strict = ixn_strict_eq_oracle(&bytes);
            assert!(matches!(strict.anchors()[0], Seal::Kind { .. }));
        }

        #[test]
        fn seal_opaque_variant_is_pinned() {
            let raw = "{\"purpose\":\"demo\",\"nested\":{\"n\":[1,null,true]}}";
            let bytes = ixn_with_anchor(Seal::Opaque(OpaqueSeal::new(raw.to_owned()).unwrap()));
            let strict = ixn_strict_eq_oracle(&bytes);
            let Seal::Opaque(opaque) = &strict.anchors()[0] else {
                unreachable!("expected Opaque seal")
            };
            assert_eq!(opaque.as_str(), raw);
        }

        /// A codex-SHAPED seal whose primitive fails to parse is an error,
        /// not an opaque fallback: `{"d":"!..."}` still parses as a codex
        /// SHAPE at the scanner layer (the digest is a well-formed JSON
        /// string), so the primitive failure surfaces from the conversion
        /// layer (`seal_from_parsed`) — never as an `Opaque` success.
        #[test]
        fn codex_shaped_seal_with_bad_primitive_errors() {
            let good = ixn_with_anchor(Seal::Digest { d: make_saider() });
            // Find the anchor array first, then corrupt the digest INSIDE it
            // (the event's own `d` field appears earlier and must stay valid).
            let a_pos = good.windows(5).position(|w| w == b"\"a\":[").unwrap();
            let d_rel = good[a_pos..]
                .windows(6)
                .position(|w| w == b"\"d\":\"E")
                .unwrap();
            let mut mutated = good;
            mutated[a_pos + d_rel + 5] = b'!';
            let resealed = resaid(mutated);
            assert!(matches!(
                deserialize_interaction(&resealed),
                Err(SerderError::UnparseablePrimitive { .. } | SerderError::InvalidPrimitive { .. })
            ));
        }

        /// A codex key SET whose values are not all JSON strings is a shape
        /// mismatch, not a typed seal: both paths must capture it verbatim
        /// as `Opaque` (strict: `string()` fails and the scanner rewinds;
        /// oracle: typed branches require string values).
        #[test]
        fn mistyped_codex_key_sets_are_opaque_on_both_paths() {
            let d = qb64(&make_saider());
            let cases = [
                "{\"bi\":123}".to_owned(),
                format!("{{\"bi\":123,\"d\":\"{d}\"}}"),
                "{\"d\":5}".to_owned(),
            ];
            for raw in cases {
                let bytes = ixn_with_anchor(Seal::Opaque(OpaqueSeal::new(raw.clone()).unwrap()));
                let strict = ixn_strict_eq_oracle(&bytes);
                let Seal::Opaque(opaque) = &strict.anchors()[0] else {
                    unreachable!("expected Opaque seal for {raw}")
                };
                assert_eq!(opaque.as_str(), raw);
            }
        }

        /// A Kind-SHAPED anchor (all-string `t`+`d`) whose `t` is not a
        /// valid Verser shape-matches on BOTH paths and then errors in
        /// conversion on field `t` — documented policy: no opaque fallback
        /// for a shape-matched seal with an invalid primitive.
        #[test]
        fn kind_shaped_anchor_with_invalid_verser_errors_on_both_paths() {
            let d = qb64(&make_saider());
            let raw = format!("{{\"t\":\"icp\",\"d\":\"{d}\"}}");
            let bytes = ixn_with_anchor(Seal::Opaque(OpaqueSeal::new(raw).unwrap()));
            assert!(matches!(
                deserialize_interaction(&bytes),
                Err(SerderError::UnparseablePrimitive { field: "t", .. }
                    | SerderError::InvalidPrimitive { field: "t", .. })
            ));
            assert!(matches!(
                reference::deserialize_interaction(&bytes),
                Err(SerderError::UnparseablePrimitive { field: "t", .. }
                    | SerderError::InvalidPrimitive { field: "t", .. })
            ));
        }

        // -------------------------------------------------------------------
        // Matrix B — Identifier prefix + SAID single/double, both branches
        // of `verify_inception_said`'s `d == i` gate.
        // -------------------------------------------------------------------

        /// Splice a genuine basic-derivation prefix into the `i` field of a
        /// canonical icp, then re-SAID single-SAID (only `d` placeholdered).
        /// The write path ALWAYS forces `i == d` (double-SAID) for icp/dip
        /// (`EventRef::is_double_said`), so a single-SAID (d != i) icp is not
        /// reachable through `serialize_inception`; byte surgery is the only
        /// way to construct one, and `super::resaid` recomputes the
        /// single-SAID form.
        fn splice_basic_prefix_icp() -> Vec<u8> {
            let mut raw = serialize_inception(&probe_icp())
                .unwrap()
                .as_bytes()
                .to_vec();
            // A basic Ed25519 prefix is 44 qb64 chars, exactly the width of a
            // Blake3_256 SAID, so the `i` span width is preserved.
            let basic = crate::serder::primitives::to_qb64_string(&make_prefixer());
            assert_eq!(basic.len(), 44, "basic prefix must be 44 qb64 chars");
            let i_key = raw.windows(6).position(|w| w == b",\"i\":\"").unwrap();
            let i_val = i_key + 6;
            raw[i_val..i_val + 44].copy_from_slice(basic.as_bytes());
            super::resaid(raw)
        }

        /// single-SAID (d != i): a basic-derivation prefix. Exercises the
        /// FALSE branch of `verify_inception_said` (only `d` placeholdered).
        ///
        /// The write path is lossy for a single-SAID icp — re-serializing
        /// forces `i == d` (double-SAID) again — so this cannot assert
        /// re-serialization reproduces the spliced original. It asserts
        /// instead that strict and oracle build the SAME event (identical
        /// re-serialization to each other), plus the Basic-prefix arm.
        #[test]
        fn identifier_basic_single_said_is_pinned() {
            let bytes = splice_basic_prefix_icp();
            let strict = deserialize_inception(&bytes).expect("strict must accept");
            let oracle = reference::deserialize_inception(&bytes).expect("oracle must accept");
            let sb = serialize_inception(&strict).unwrap();
            let ob = serialize_inception(&oracle).unwrap();
            assert_eq!(sb.as_bytes(), ob.as_bytes(), "strict vs oracle divergence");
            assert!(matches!(strict.prefix(), Identifier::Basic(_)));
            // d != i for a basic prefix: the SAID and the prefix differ.
            let said_qb64 = qb64(strict.said());
            let prefix_qb64 = crate::serder::primitives::identifier_to_qb64_string(strict.prefix());
            assert_ne!(said_qb64, prefix_qb64, "basic prefix must differ from SAID");
        }

        /// double-SAID (d == i): a self-addressing inception where prefix ==
        /// said, produced by the write path's `InceptionBuilder`. Exercises
        /// the TRUE branch of `verify_inception_said` (both `d` and `i`
        /// placeholdered) — today hit only by chance in the differential.
        #[test]
        fn identifier_self_addressing_double_said_is_pinned() {
            use crate::serder::builder::icp::InceptionBuilder;

            let built = InceptionBuilder::new()
                .keys(vec![make_verfer()])
                .build()
                .unwrap();
            let bytes = built.as_bytes().to_vec();
            let strict = icp_strict_eq_oracle(&bytes);
            assert!(matches!(strict.prefix(), Identifier::SelfAddressing(_)));
            assert_eq!(
                strict.prefix().as_saider().unwrap().raw(),
                strict.said().raw(),
                "self-addressing prefix raw bytes must equal SAID raw bytes"
            );
        }

        /// dip with a basic (single-SAID) prefix, spliced the same way as the
        /// icp single-SAID case (the write path forces `i == d` here too).
        /// The double-SAID dip path shares `verify_inception_said` with the
        /// icp double case: `deserialize_delegated_inception` calls the same
        /// `verify_inception_said` over `p.icp`, so the double (TRUE) branch
        /// is covered structurally by
        /// `identifier_self_addressing_double_said_is_pinned`; this pins the
        /// single (FALSE) branch reaching the dip build path.
        #[test]
        fn dip_basic_single_said_is_pinned() {
            let dip = DelegatedInceptionEvent::new(probe_icp(), make_prefixer().into());
            let mut raw = serialize_delegated_inception(&dip)
                .unwrap()
                .as_bytes()
                .to_vec();
            let basic = crate::serder::primitives::to_qb64_string(&make_prefixer());
            let i_key = raw.windows(6).position(|w| w == b",\"i\":\"").unwrap();
            let i_val = i_key + 6;
            raw[i_val..i_val + 44].copy_from_slice(basic.as_bytes());
            let bytes = super::resaid(raw);

            let strict = deserialize_delegated_inception(&bytes).expect("strict must accept");
            let oracle =
                reference::deserialize_delegated_inception(&bytes).expect("oracle must accept");
            let sb = serialize_delegated_inception(&strict).unwrap();
            let ob = serialize_delegated_inception(&oracle).unwrap();
            // Write path is lossy for a single-SAID dip (re-forces i == d), so
            // assert strict/oracle agreement only, not reproduction of the
            // spliced original.
            assert_eq!(sb.as_bytes(), ob.as_bytes(), "strict vs oracle divergence");
            assert!(matches!(strict.inception().prefix(), Identifier::Basic(_)));
        }

        // -------------------------------------------------------------------
        // Matrix C — every `ParsedTholder` rendering through kt.
        // -------------------------------------------------------------------

        #[test]
        fn tholder_simple_one_is_pinned() {
            let bytes = icp_with_kt(Tholder::Simple(1), 1);
            // kt renders as hex: 1 -> "1".
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["kt"].as_str().unwrap(), "1");
            let strict = icp_strict_eq_oracle(&bytes);
            assert_eq!(*strict.threshold(), Tholder::Simple(1));
        }

        #[test]
        fn tholder_simple_ten_renders_hex_not_decimal() {
            let bytes = icp_with_kt(Tholder::Simple(10), 10);
            // Hex-not-decimal: 10 -> "a", never "10".
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["kt"].as_str().unwrap(), "a");
            let strict = icp_strict_eq_oracle(&bytes);
            assert_eq!(*strict.threshold(), Tholder::Simple(10));
        }

        #[test]
        fn tholder_weighted_single_clause_is_flat_array() {
            let expected = Tholder::Weighted(vec![vec![(1, 2), (1, 2)]]);
            let bytes = icp_with_kt(expected.clone(), 2);
            // Single clause flattens to a flat array of fraction strings.
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            let kt = json["kt"].as_array().expect("kt flat array");
            assert_eq!(kt[0].as_str().unwrap(), "1/2");
            assert_eq!(kt[1].as_str().unwrap(), "1/2");
            let strict = icp_strict_eq_oracle(&bytes);
            assert_eq!(*strict.threshold(), expected);
        }

        #[test]
        fn tholder_weighted_multi_clause_is_nested_array() {
            let expected = Tholder::Weighted(vec![vec![(1, 2), (1, 2)], vec![(1, 1)]]);
            let bytes = icp_with_kt(expected.clone(), 3);
            // Multi-clause stays a nested array of arrays.
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            let kt = json["kt"].as_array().expect("kt nested array");
            assert!(kt[0].is_array(), "first clause is a nested array");
            assert!(kt[1].is_array(), "second clause is a nested array");
            let strict = icp_strict_eq_oracle(&bytes);
            assert_eq!(*strict.threshold(), expected);
        }

        // -------------------------------------------------------------------
        // Matrix D — `ParsedCount::Hex` through a non-trivial bt.
        // (intive `bt` Number is covered by `intive_integer_bt_is_accepted`.)
        // -------------------------------------------------------------------

        #[test]
        fn count_hex_bt_ten_renders_hex_and_roundtrips() {
            // Toad::exact requires a governing witness set of exactly 10 for
            // bt=10 to be in range; the read path now validates this at
            // `build_inception`, so the wire witness count must agree.
            let event = InceptionEvent::new(
                make_prefixer().into(),
                Seqner::new(0),
                make_saider(),
                vec![make_verfer()],
                Tholder::Simple(1),
                vec![make_diger()],
                Tholder::Simple(1),
                vec![make_prefixer(); 10],
                Toad::exact(10, 10).unwrap(),
                vec![],
                vec![],
            );
            let bytes = serialize_inception(&event).unwrap().as_bytes().to_vec();
            // bt renders as hex: 10 -> "a".
            let json: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["bt"].as_str().unwrap(), "a");
            let strict = icp_strict_eq_oracle(&bytes);
            assert_eq!(strict.witness_threshold().value(), 10);
        }

        // -------------------------------------------------------------------
        // Matrix E — `config_from_parsed` for both known codes.
        // -------------------------------------------------------------------

        /// Extends the pre-existing `roundtrip_config_traits` with oracle equivalence.
        #[test]
        fn config_both_known_codes_are_pinned() {
            let event = InceptionEvent::new(
                make_prefixer().into(),
                Seqner::new(0),
                make_saider(),
                vec![make_verfer()],
                Tholder::Simple(1),
                vec![make_diger()],
                Tholder::Simple(1),
                vec![],
                Toad::exact(0, 0).unwrap(),
                vec![ConfigTrait::EstOnly, ConfigTrait::DoNotDelegate],
                vec![],
            );
            let bytes = serialize_inception(&event).unwrap().as_bytes().to_vec();
            let strict = icp_strict_eq_oracle(&bytes);
            assert_eq!(
                strict.config(),
                [ConfigTrait::EstOnly, ConfigTrait::DoNotDelegate]
            );
        }

        // -------------------------------------------------------------------
        // Matrix F — `deserialize_event` ilk dispatch, all 5 arms.
        // -------------------------------------------------------------------

        /// Extends `deserialize_event_dispatches_icp` with byte-reproduction of the original.
        #[test]
        fn dispatch_icp_arm_is_pinned() {
            let bytes = serialize(&KeriEvent::Inception(probe_icp()))
                .unwrap()
                .as_bytes()
                .to_vec();
            let event = deserialize_event(&bytes).unwrap();
            assert!(matches!(event, KeriEvent::Inception(_)));
            let re = serialize(&event).unwrap();
            assert_eq!(re.as_bytes(), bytes, "dispatch re-serializes to original");
        }

        /// Extends `deserialize_event_dispatches_rot` with byte-reproduction of the original.
        #[test]
        fn dispatch_rot_arm_is_pinned() {
            let bytes = serialize(&KeriEvent::Rotation(probe_rot()))
                .unwrap()
                .as_bytes()
                .to_vec();
            let event = deserialize_event(&bytes).unwrap();
            assert!(matches!(event, KeriEvent::Rotation(_)));
            let re = serialize(&event).unwrap();
            assert_eq!(re.as_bytes(), bytes, "dispatch re-serializes to original");
        }

        /// Extends `deserialize_event_dispatches_ixn` with byte-reproduction of the original.
        #[test]
        fn dispatch_ixn_arm_is_pinned() {
            let ixn = InteractionEvent::new(
                make_prefixer().into(),
                Seqner::new(1),
                make_saider(),
                make_saider(),
                vec![],
            );
            let bytes = serialize(&KeriEvent::Interaction(ixn))
                .unwrap()
                .as_bytes()
                .to_vec();
            let event = deserialize_event(&bytes).unwrap();
            assert!(matches!(event, KeriEvent::Interaction(_)));
            let re = serialize(&event).unwrap();
            assert_eq!(re.as_bytes(), bytes, "dispatch re-serializes to original");
        }

        #[test]
        fn dispatch_dip_arm_is_pinned() {
            let dip = DelegatedInceptionEvent::new(probe_icp(), make_prefixer().into());
            let bytes = serialize(&KeriEvent::DelegatedInception(dip))
                .unwrap()
                .as_bytes()
                .to_vec();
            let event = deserialize_event(&bytes).unwrap();
            assert!(matches!(event, KeriEvent::DelegatedInception(_)));
            let re = serialize(&event).unwrap();
            assert_eq!(re.as_bytes(), bytes, "dispatch re-serializes to original");
        }

        #[test]
        fn dispatch_drt_arm_is_pinned() {
            let drt = DelegatedRotationEvent::new(probe_rot());
            let bytes = serialize(&KeriEvent::DelegatedRotation(drt))
                .unwrap()
                .as_bytes()
                .to_vec();
            let event = deserialize_event(&bytes).unwrap();
            assert!(matches!(event, KeriEvent::DelegatedRotation(_)));
            let re = serialize(&event).unwrap();
            assert_eq!(re.as_bytes(), bytes, "dispatch re-serializes to original");
        }

        // -------------------------------------------------------------------
        // Matrix G — reachability of each read-path error variant.
        //
        // Invariant of the #142 rewrite: the STRICT read path never returns
        // `MissingField` — in the fixed canonical grammar a missing/absent
        // field is a `NonCanonical` (the grammar expected a literal at that
        // byte). `MissingField` is now oracle-only. `InvalidEventLayout` and
        // `VersionStringOverflow` are internal / write-path signals, not
        // reachable from untrusted read input, so they are NOT probed here.
        // -------------------------------------------------------------------

        /// `NonCanonical`: a reordered field name (same length keeps the size
        /// field consistent) through a public `deserialize_*` entry point.
        #[test]
        fn error_non_canonical_from_reordered_field() {
            let mut bytes = serialize_interaction(&InteractionEvent::new(
                make_prefixer().into(),
                Seqner::new(3),
                make_saider(),
                make_saider(),
                vec![],
            ))
            .unwrap()
            .as_bytes()
            .to_vec();
            // Swap the `"s"` and `"p"` key names (equal length).
            let s_pos = bytes.windows(5).position(|w| w == b",\"s\":").unwrap();
            let p_pos = bytes.windows(5).position(|w| w == b",\"p\":").unwrap();
            bytes[s_pos + 2] = b'p';
            bytes[p_pos + 2] = b's';
            assert!(matches!(
                deserialize_interaction(&bytes),
                Err(SerderError::NonCanonical { .. })
            ));
        }

        /// The strict read path returns `NonCanonical`, NOT `MissingField`,
        /// when a field is deleted: the grammar expected a literal at that
        /// byte offset. This is the distinguishing property of the rewrite.
        #[test]
        fn field_deletion_is_non_canonical_never_missing_field() {
            let bytes = serialize_interaction(&InteractionEvent::new(
                make_prefixer().into(),
                Seqner::new(3),
                make_saider(),
                make_saider(),
                vec![],
            ))
            .unwrap()
            .as_bytes()
            .to_vec();
            // Delete the `,"p":"..."` field entirely (find `,"p":"` .. next `"`).
            let p_key = bytes.windows(6).position(|w| w == b",\"p\":\"").unwrap();
            let val_start = p_key + 6;
            let val_end =
                val_start + bytes[val_start..].iter().position(|b| *b == b'"').unwrap() + 1;
            let mut mutated = Vec::new();
            mutated.extend_from_slice(&bytes[..p_key]);
            mutated.extend_from_slice(&bytes[val_end..]);
            // Fix the version-string size field so the length check passes and
            // the grammar itself is what rejects the missing field — otherwise
            // `InvalidVersionString` (the length lie) would fire first.
            let hex = format!("{:06x}", mutated.len());
            mutated[16..22].copy_from_slice(hex.as_bytes());
            let Err(err) = deserialize_interaction(&mutated) else {
                unreachable!("field deletion must not deserialize")
            };
            assert!(
                matches!(err, SerderError::NonCanonical { .. }),
                "strict deletion must be NonCanonical, got {err:?}"
            );
            assert!(
                !matches!(err, SerderError::MissingField(_)),
                "strict read path must never return MissingField"
            );
        }

        /// `InvalidVersionString`: a non-JSON serialization kind in the
        /// version string. `deserialize_*_rejects_length_mismatched_raw`
        /// already pins the length-mismatch route; this pins the wrong-kind
        /// route through the strict path.
        #[test]
        fn error_invalid_version_string_wrong_kind() {
            let mut mutated = serialize_interaction(&InteractionEvent::new(
                make_prefixer().into(),
                Seqner::new(1),
                make_saider(),
                make_saider(),
                vec![],
            ))
            .unwrap()
            .as_bytes()
            .to_vec();
            // The version string is `KERI10JSON......_`; overwrite `JSON`
            // (bytes 6..10) with `CBOR` — a different, valid serialization
            // kind. Length is unchanged, so the size check still passes and
            // the kind check is what fires.
            mutated[6..10].copy_from_slice(b"CBOR");
            assert!(
                matches!(
                    deserialize_interaction(&mutated),
                    Err(SerderError::InvalidVersionString(_))
                ),
                "wrong version-string kind must be InvalidVersionString"
            );
        }

        /// `SaidMismatch`: `tampered_said_fails_verification` already pins
        /// this for icp via the strict path. Re-assert here for ixn to keep
        /// the map complete (tamper a byte OUTSIDE the SAID span — the `s`
        /// value — so the SAID no longer matches).
        #[test]
        fn error_said_mismatch_on_tampered_field() {
            let mut mutated = serialize_interaction(&InteractionEvent::new(
                make_prefixer().into(),
                Seqner::new(1),
                make_saider(),
                make_saider(),
                vec![],
            ))
            .unwrap()
            .as_bytes()
            .to_vec();
            // Replace sn value "1" with "2": same length, SAID span untouched.
            let pos = mutated
                .windows(8)
                .position(|w| w == b",\"s\":\"1\"")
                .unwrap();
            mutated[pos + 6] = b'2';
            assert!(matches!(
                deserialize_interaction(&mutated),
                Err(SerderError::SaidMismatch { .. })
            ));
        }

        /// `UnknownIlk` at the PUBLIC `deserialize_event` layer: an unknown
        /// (but correctly-lengthed) ilk code. `canonical.rs::unknown_ilk_is_typed`
        /// pins the parse layer; this pins the public dispatch layer.
        #[test]
        fn error_unknown_ilk_at_public_dispatch() {
            let mut bytes = serialize(&KeriEvent::Interaction(InteractionEvent::new(
                make_prefixer().into(),
                Seqner::new(1),
                make_saider(),
                make_saider(),
                vec![],
            )))
            .unwrap()
            .as_bytes()
            .to_vec();
            let pos = bytes.windows(5).position(|w| w == b"\"ixn\"").unwrap();
            bytes[pos + 1..pos + 4].copy_from_slice(b"xxx");
            assert!(matches!(
                deserialize_event(&bytes),
                Err(SerderError::UnknownIlk(ref s)) if s == "xxx"
            ));
        }

        /// `InvalidPrimitive`: a structurally-scannable but invalid field
        /// value — a non-hex `s` (sequence number). The scanner accepts it as
        /// a canonical string; `parse_sn` rejects it. Re-SAID first so the
        /// mutation reaches the build layer (SAID verification passes over the
        /// literal bytes).
        #[test]
        fn error_invalid_primitive_bad_hex_sn() {
            let mut raw = serialize_inception(&probe_icp())
                .unwrap()
                .as_bytes()
                .to_vec();
            let pos = raw.windows(8).position(|w| w == b",\"s\":\"0\"").unwrap();
            // "0" -> "z": same length; not a hex digit.
            raw[pos + 6] = b'z';
            let canonical = super::resaid(raw);
            assert!(matches!(
                deserialize_inception(&canonical),
                Err(SerderError::InvalidPrimitive { field: "s", .. })
            ));
        }

        /// `UnparseablePrimitive`: a malformed qb64 code in a field. The
        /// unit test `unparseable_qb64_field_surfaces_as_parsing_domain_error`
        /// already pins this directly on `parse_qb64_diger`; here we drive it
        /// through the public read path by corrupting a key's leading code
        /// character to an unparseable code, then re-SAID.
        #[test]
        fn error_unparseable_primitive_bad_qb64_key() {
            let mut raw = serialize_inception(&probe_icp())
                .unwrap()
                .as_bytes()
                .to_vec();
            // Corrupt the first key's leading code char: the `k` array is
            // `"k":["D..."]`; overwrite the `D` with `-` (a count-code lead,
            // not a Matter primitive code) to force a parse-domain failure.
            let k_pos = raw.windows(6).position(|w| w == b"\"k\":[\"").unwrap();
            let code_pos = k_pos + 6;
            raw[code_pos] = b'-';
            let canonical = super::resaid(raw);
            let Err(err) = deserialize_inception(&canonical) else {
                unreachable!("corrupt key code must not deserialize")
            };
            assert!(
                matches!(err, SerderError::UnparseablePrimitive { field: "k", .. }),
                "corrupt key code must be UnparseablePrimitive, got {err:?}"
            );
        }
    }
}
