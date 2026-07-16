//! The pre-#142 tolerant read path (`serde_json::Value` + re-render SAID
//! verification), preserved verbatim as the differential-test oracle for
//! the strict canonical parser. Test-only: never compiled into production.

use super::{
    infer_digest_code, parse_qb64_diger, parse_qb64_identifier, parse_qb64_prefixer,
    parse_qb64_saider, parse_qb64_verfer, parse_qb64_verser, parse_sn, parse_weight,
};
use crate::core::matter::code::DigestCode;
use crate::core::matter::error::ValidationError;
use crate::core::primitives::{Diger, Prefixer, Verfer};
use crate::keri::threshold_form::ThresholdForm;
use crate::keri::toad::Toad;
use crate::keri::{
    ConfigTrait, DelegatedInceptionEvent, DelegatedRotationEvent, Ilk, InceptionEvent,
    InteractionEvent, KeriEvent, OpaqueSeal, RotationEvent, Seal, SequenceNumber, SigningThreshold,
    WeightedThreshold,
};
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};
use serde_json::Value;

use crate::serder::error::SerderError;
use crate::serder::primitives::to_qb64_string;
use crate::serder::said::{compute_digest, said_placeholder};
use crate::serder::version::{SerializationKind, VERSION_STRING_LEN, VersionString};

// ---------------------------------------------------------------------------
// Tolerant deserialization entry points (oracle)
// ---------------------------------------------------------------------------

/// Deserialize any KERI event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_event(raw: &[u8]) -> Result<KeriEvent, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let ilk_str = get_str(&val, "t")?;
    let ilk = Ilk::from_code(ilk_str).map_err(|_| SerderError::UnknownIlk(ilk_str.to_owned()))?;

    match ilk {
        Ilk::Icp => Ok(KeriEvent::Inception(deserialize_inception(raw)?)),
        Ilk::Rot => Ok(KeriEvent::Rotation(deserialize_rotation(raw)?)),
        Ilk::Ixn => Ok(KeriEvent::Interaction(deserialize_interaction(raw)?)),
        Ilk::Dip => Ok(KeriEvent::DelegatedInception(
            deserialize_delegated_inception(raw)?,
        )),
        Ilk::Drt => Ok(KeriEvent::DelegatedRotation(
            deserialize_delegated_rotation(raw)?,
        )),
        _ => Err(SerderError::UnknownIlk(ilk_str.to_owned())),
    }
}

/// Deserialize an inception event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_inception(raw: &[u8]) -> Result<InceptionEvent, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;
    let d_str = get_str(&val, "d")?;
    let i_str = get_str(&val, "i")?;

    if d_str == i_str {
        verify_said_double(raw, digest_code)?;
    } else {
        verify_said_single(raw, digest_code)?;
    }

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let kt = get_field(&val, "kt")?;
    let nt = get_field(&val, "nt")?;
    let bt = get_field(&val, "bt")?;
    let form = threshold_form_of(bt);
    check_form_consistency("kt", kt, form)?;
    check_form_consistency("nt", nt, form)?;
    let threshold = tholder_from_json(kt, "signing")?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(nt, "next signing")?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    let witness_threshold_wire = parse_witness_threshold(bt)?;
    let witnesses = parse_qb64_prefixer_array(get_field(&val, "b")?)?;
    let config = parse_config_array(get_field(&val, "c")?)?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;
    let witness_threshold = Toad::exact(witness_threshold_wire, witnesses.len())?;

    Ok(InceptionEvent::new(
        prefix,
        SequenceNumber::new(sn),
        said,
        keys,
        threshold,
        next_keys,
        next_threshold,
        witnesses,
        witness_threshold,
        config,
        anchors,
        form,
    ))
}

/// Deserialize a rotation event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_rotation(raw: &[u8]) -> Result<RotationEvent, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;

    verify_said_single(raw, digest_code)?;

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let prior_event_said = parse_qb64_diger(get_str(&val, "p")?, "p")?;
    let kt = get_field(&val, "kt")?;
    let nt = get_field(&val, "nt")?;
    let bt = get_field(&val, "bt")?;
    let form = threshold_form_of(bt);
    check_form_consistency("kt", kt, form)?;
    check_form_consistency("nt", nt, form)?;
    let threshold = tholder_from_json(kt, "signing")?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(nt, "next signing")?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    let witness_threshold = parse_witness_threshold(bt)?;
    let witness_removals = parse_qb64_prefixer_array(get_field(&val, "br")?)?;
    let witness_additions = parse_qb64_prefixer_array(get_field(&val, "ba")?)?;
    if val.get("c").is_some() {
        return Err(SerderError::UnexpectedField("c"));
    }
    let anchors = parse_seal_array(get_field(&val, "a")?)?;

    Ok(RotationEvent::new(
        prefix,
        SequenceNumber::new(sn),
        said,
        prior_event_said,
        keys,
        threshold,
        next_keys,
        next_threshold,
        witness_additions,
        witness_removals,
        Toad::from_wire(witness_threshold),
        anchors,
        form,
    ))
}

/// Deserialize an interaction event from canonical JSON bytes (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_interaction(raw: &[u8]) -> Result<InteractionEvent, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;

    verify_said_single(raw, digest_code)?;

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let prior_event_said = parse_qb64_diger(get_str(&val, "p")?, "p")?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;

    Ok(InteractionEvent::new(
        prefix,
        SequenceNumber::new(sn),
        said,
        prior_event_said,
        anchors,
    ))
}

/// Deserialize a delegated inception event from canonical JSON bytes
/// (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_delegated_inception(
    raw: &[u8],
) -> Result<DelegatedInceptionEvent, SerderError> {
    validate_version_string(raw)?;
    let val: Value = serde_json::from_slice(raw)?;
    let digest_code = infer_digest_code(get_str(&val, "d")?)?;
    let d_str = get_str(&val, "d")?;
    let i_str = get_str(&val, "i")?;

    if d_str == i_str {
        verify_said_double(raw, digest_code)?;
    } else {
        verify_said_single(raw, digest_code)?;
    }

    let said = parse_qb64_diger(get_str(&val, "d")?, "d")?;
    let prefix = parse_qb64_identifier(get_str(&val, "i")?, "i")?;
    let sn = parse_sn(get_str(&val, "s")?)?;
    let kt = get_field(&val, "kt")?;
    let nt = get_field(&val, "nt")?;
    let bt = get_field(&val, "bt")?;
    let form = threshold_form_of(bt);
    check_form_consistency("kt", kt, form)?;
    check_form_consistency("nt", nt, form)?;
    let threshold = tholder_from_json(kt, "signing")?;
    let keys = parse_qb64_verfer_array(get_field(&val, "k")?)?;
    let next_threshold = tholder_from_json(nt, "next signing")?;
    let next_keys = parse_qb64_diger_array(get_field(&val, "n")?)?;
    let witness_threshold_wire = parse_witness_threshold(bt)?;
    let witnesses = parse_qb64_prefixer_array(get_field(&val, "b")?)?;
    let config = parse_config_array(get_field(&val, "c")?)?;
    let anchors = parse_seal_array(get_field(&val, "a")?)?;
    let delegator = parse_qb64_identifier(get_str(&val, "di")?, "di")?;
    let witness_threshold = Toad::exact(witness_threshold_wire, witnesses.len())?;

    Ok(DelegatedInceptionEvent::new(
        InceptionEvent::new(
            prefix,
            SequenceNumber::new(sn),
            said,
            keys,
            threshold,
            next_keys,
            next_threshold,
            witnesses,
            witness_threshold,
            config,
            anchors,
            form,
        ),
        delegator,
    ))
}

/// Deserialize a delegated rotation event from canonical JSON bytes
/// (tolerant oracle).
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn deserialize_delegated_rotation(
    raw: &[u8],
) -> Result<DelegatedRotationEvent, SerderError> {
    let rotation = deserialize_rotation(raw)?;
    Ok(DelegatedRotationEvent::new(rotation))
}

// ---------------------------------------------------------------------------
// Version string validation
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn validate_version_string(raw: &[u8]) -> Result<(), SerderError> {
    let val: Value = serde_json::from_slice(raw)?;
    let vs_str = val
        .get("v")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("v"))?;

    if vs_str.len() < VERSION_STRING_LEN {
        return Err(SerderError::InvalidVersionString(format!(
            "version string too short: {}",
            vs_str.len()
        )));
    }
    let vs = VersionString::parse(vs_str)?;
    if vs.kind != SerializationKind::Json {
        return Err(SerderError::InvalidVersionString(format!(
            "expected JSON, got {}",
            vs.kind.as_str()
        )));
    }
    let expected_size =
        usize::try_from(vs.size).map_err(|e| SerderError::InvalidVersionString(e.to_string()))?;
    if expected_size != raw.len() {
        return Err(SerderError::InvalidVersionString(format!(
            "version string size {} does not match actual size {}",
            expected_size,
            raw.len()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SAID verification helpers
// ---------------------------------------------------------------------------

/// Verify a single-SAID event (rot, ixn, drt): only `d` is replaced with a
/// placeholder before computing the digest.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn verify_said_single(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let obj = value
        .as_object_mut()
        .ok_or(SerderError::MissingField("d"))?;

    let original_said = obj
        .get("d")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("d"))?
        .to_owned();

    let placeholder = said_placeholder(code)?;
    obj.insert("d".to_owned(), Value::String(placeholder));

    let reser = serde_json::to_string(&value)?;
    let computed = compute_digest(reser.as_bytes(), code)?;
    let computed_qb64 = to_qb64_string(&computed);

    if original_said != computed_qb64 {
        return Err(SerderError::SaidMismatch {
            expected: original_said,
            computed: computed_qb64,
        });
    }
    Ok(())
}

/// Verify a double-SAID event (icp, dip): both `d` and `i` are replaced with
/// placeholders before computing the digest.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn verify_said_double(raw: &[u8], code: DigestCode) -> Result<(), SerderError> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let obj = value
        .as_object_mut()
        .ok_or(SerderError::MissingField("d"))?;

    let original_said = obj
        .get("d")
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField("d"))?
        .to_owned();

    let placeholder = said_placeholder(code)?;
    obj.insert("d".to_owned(), Value::String(placeholder.clone()));
    obj.insert("i".to_owned(), Value::String(placeholder));

    let reser = serde_json::to_string(&value)?;
    let computed = compute_digest(reser.as_bytes(), code)?;
    let computed_qb64 = to_qb64_string(&computed);

    if original_said != computed_qb64 {
        return Err(SerderError::SaidMismatch {
            expected: original_said,
            computed: computed_qb64,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Array parsing helpers
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_qb64_prefixer_array(
    val: &Value,
) -> Result<Vec<Prefixer<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("b"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("b"))?;
            parse_qb64_prefixer(s, "b")
        })
        .collect()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_qb64_verfer_array(val: &Value) -> Result<Vec<Verfer<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("k"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("k"))?;
            parse_qb64_verfer(s, "k")
        })
        .collect()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_qb64_diger_array(val: &Value) -> Result<Vec<Diger<'static>>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("n"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("n"))?;
            parse_qb64_diger(s, "n")
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Signing-threshold parsing
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn tholder_from_json(
    val: &Value,
    field: &'static str,
) -> Result<SigningThreshold, SerderError> {
    if let Some(s) = val.as_str() {
        let n = u64::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
            field: "kt",
            source: ValidationError::UnknownMatterCode(format!("invalid hex threshold: {s}")),
        })?;
        return Ok(SigningThreshold::Simple(n));
    }

    if let Some(n) = val.as_u64() {
        return Ok(SigningThreshold::Simple(n));
    }

    if let Some(outer) = val.as_array() {
        // keripy flattens single-clause weighted thresholds: [["1/2","1/2"]]
        // becomes ["1/2","1/2"]. Detect flat vs nested by checking if the
        // first element is a string (flat) or an array (nested).
        let is_flat = outer.first().is_some_and(Value::is_string);

        let clauses: Result<Vec<Vec<(u64, u64)>>, SerderError> = if is_flat {
            // Flat list of fraction strings → single clause
            let clause: Result<Vec<(u64, u64)>, SerderError> = outer
                .iter()
                .map(|frac_val| {
                    let frac_str = frac_val.as_str().ok_or(SerderError::MissingField("kt"))?;
                    parse_weight(frac_str)
                })
                .collect();
            Ok(vec![clause?])
        } else {
            // Nested list of lists
            outer
                .iter()
                .map(|clause_val| {
                    let clause_arr = clause_val
                        .as_array()
                        .ok_or(SerderError::MissingField("kt"))?;
                    clause_arr
                        .iter()
                        .map(|frac_val| {
                            let frac_str =
                                frac_val.as_str().ok_or(SerderError::MissingField("kt"))?;
                            parse_weight(frac_str)
                        })
                        .collect()
                })
                .collect()
        };
        let weighted = WeightedThreshold::from_nested(clauses?)
            .map_err(|source| SerderError::SigningThresholdOutOfRange { field, source })?;
        return Ok(SigningThreshold::Weighted(weighted));
    }

    Err(SerderError::MissingField("kt"))
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_witness_threshold(val: &Value) -> Result<u32, SerderError> {
    if let Some(n) = val.as_u64() {
        return u32::try_from(n).map_err(|_| SerderError::InvalidPrimitive {
            field: "bt",
            source: ValidationError::UnknownMatterCode(format!(
                "witness threshold {n} exceeds u32::MAX"
            )),
        });
    }
    let s = val.as_str().ok_or(SerderError::MissingField("bt"))?;
    let n = u128::from_str_radix(s, 16).map_err(|_| SerderError::InvalidPrimitive {
        field: "bt",
        source: ValidationError::UnknownMatterCode(format!("invalid hex bt: {s}")),
    })?;
    u32::try_from(n).map_err(|_| SerderError::InvalidPrimitive {
        field: "bt",
        source: ValidationError::UnknownMatterCode(format!(
            "witness threshold {n} exceeds u32::MAX"
        )),
    })
}

/// Mirror of the strict path's `threshold_form_of`: a JSON-number `bt`
/// signals keripy `intive=True`, a JSON-string `bt` signals hex. Anything
/// else is treated as hex (the downstream `parse_witness_threshold` rejects
/// truly malformed `bt`).
fn threshold_form_of(bt: &Value) -> ThresholdForm {
    if bt.is_number() {
        ThresholdForm::Integer
    } else {
        ThresholdForm::HexString
    }
}

/// Mirror of the strict path's `check_form_consistency`: a simple-numeric
/// `kt`/`nt` must agree with `bt`'s wire form; weighted (array) thresholds
/// are exempt. An integer-form value above `u32::MAX` is a disagreement
/// (keripy's `MaxIntThold` would have forced hex).
fn check_form_consistency(
    field: &'static str,
    t: &Value,
    form: ThresholdForm,
) -> Result<(), SerderError> {
    let consistent = if t.is_array() {
        true
    } else {
        match form {
            ThresholdForm::HexString => t.is_string(),
            ThresholdForm::Integer => t.as_u64().is_some_and(|n| u32::try_from(n).is_ok()),
        }
    };
    if consistent {
        Ok(())
    } else {
        Err(SerderError::MixedThresholdForms { field })
    }
}

// ---------------------------------------------------------------------------
// Seal parsing
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn seal_from_json(val: &Value) -> Result<Seal, SerderError> {
    let obj = val.as_object().ok_or(SerderError::MissingField("a"))?;

    let n = obj.len();
    let str_field = |k: &str| obj.get(k).and_then(Value::as_str);

    // A typed branch matches on key set, field count, AND all matched
    // values being JSON strings — mirroring the strict scanner, where a
    // non-string value fails `string()` and the whole object falls back
    // to the opaque capture below.
    if n == 3
        && let (Some(i), Some(s), Some(d)) = (str_field("i"), str_field("s"), str_field("d"))
    {
        return Ok(Seal::Event {
            i: parse_qb64_prefixer(i, "i")?,
            s: SequenceNumber::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        });
    }
    if n == 2
        && let (Some(s), Some(d)) = (str_field("s"), str_field("d"))
    {
        return Ok(Seal::Source {
            s: SequenceNumber::new(parse_sn(s)?),
            d: parse_qb64_saider(d, "d")?,
        });
    }
    if n == 2
        && let (Some(bi), Some(d)) = (str_field("bi"), str_field("d"))
    {
        return Ok(Seal::Back {
            bi: parse_qb64_prefixer(bi, "bi")?,
            d: parse_qb64_saider(d, "d")?,
        });
    }
    if n == 2
        && let (Some(t), Some(d)) = (str_field("t"), str_field("d"))
    {
        return Ok(Seal::Kind {
            t: parse_qb64_verser(t, "t")?,
            d: parse_qb64_saider(d, "d")?,
        });
    }
    if n == 1
        && let Some(rd) = str_field("rd")
    {
        return Ok(Seal::Root {
            rd: parse_qb64_saider(rd, "rd")?,
        });
    }
    if n == 1
        && let Some(d) = str_field("d")
    {
        return Ok(Seal::Digest {
            d: parse_qb64_saider(d, "d")?,
        });
    }
    if n == 1
        && let Some(i) = str_field("i")
    {
        return Ok(Seal::Last {
            i: parse_qb64_prefixer(i, "i")?,
        });
    }
    // Non-codex anchor: keep it verbatim. `preserve_order` keeps the
    // wire key order through the serde_json round-trip; note the oracle
    // NORMALIZES exotic number/escape spellings (it re-serializes a
    // parsed `Value`), so strict-vs-oracle comparisons must use
    // normalization-stable payloads (integers, minimal escaping). The
    // strict path is the wire-fidelity authority.
    let raw = serde_json::to_string(val).map_err(SerderError::from)?;
    let opaque =
        OpaqueSeal::new(raw).map_err(|source| SerderError::InvalidAnchor { offset: 0, source })?;
    Ok(Seal::Opaque(opaque))
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_seal_array(val: &Value) -> Result<Vec<Seal>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("a"))?;
    arr.iter().map(seal_from_json).collect()
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn parse_config_array(val: &Value) -> Result<Vec<ConfigTrait>, SerderError> {
    let arr = val.as_array().ok_or(SerderError::MissingField("c"))?;
    arr.iter()
        .map(|v| {
            let s = v.as_str().ok_or(SerderError::MissingField("c"))?;
            ConfigTrait::from_code(s).map_err(|_| SerderError::UnknownIlk(s.to_owned()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// JSON field access helpers
// ---------------------------------------------------------------------------

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn get_str<'a>(val: &'a Value, field: &'static str) -> Result<&'a str, SerderError> {
    val.get(field)
        .and_then(Value::as_str)
        .ok_or(SerderError::MissingField(field))
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn get_field<'a>(val: &'a Value, field: &'static str) -> Result<&'a Value, SerderError> {
    val.get(field).ok_or(SerderError::MissingField(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{CesrCode, DigestCode, VerKeyCode};
    use crate::core::primitives::{Prefixer, Saider};
    use crate::serder::serialize::{
        serialize_delegated_inception, serialize_delegated_rotation, serialize_inception,
        serialize_interaction, serialize_rotation,
    };
    use alloc::borrow::Cow;

    fn weighted(clauses: Vec<Vec<(u64, u64)>>) -> SigningThreshold {
        SigningThreshold::Weighted(WeightedThreshold::from_nested(clauses).unwrap())
    }

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

    fn qb64(m: &crate::core::matter::matter::Matter<'_, impl CesrCode>) -> String {
        crate::serder::primitives::to_qb64_string(m)
    }

    fn probe_icp() -> InceptionEvent {
        InceptionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(0),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: make_saider() }],
            ThresholdForm::HexString,
        )
    }

    fn probe_rot() -> RotationEvent {
        RotationEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(2),
            make_saider(),
            make_saider(),
            vec![make_verfer()],
            SigningThreshold::Simple(1),
            vec![make_saider()],
            SigningThreshold::Simple(1),
            vec![make_prefixer()],
            vec![],
            Toad::from_wire(1),
            vec![],
            ThresholdForm::HexString,
        )
    }

    // -----------------------------------------------------------------------
    // Oracle round-trips: every tolerant entry point stays green on writer
    // output (the property the differential suite diffs the strict path
    // against).
    // -----------------------------------------------------------------------

    #[test]
    fn oracle_roundtrips_icp() {
        let ser = serialize_inception(&probe_icp()).unwrap();
        let event = deserialize_inception(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::Inception(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_rot() {
        let ser = serialize_rotation(&probe_rot()).unwrap();
        let event = deserialize_rotation(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::Rotation(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_ixn() {
        let ixn = InteractionEvent::new(
            make_prefixer().into(),
            SequenceNumber::new(3),
            make_saider(),
            make_saider(),
            vec![Seal::Digest { d: make_saider() }],
        );
        let ser = serialize_interaction(&ixn).unwrap();
        let event = deserialize_interaction(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::Interaction(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_dip() {
        let dip = DelegatedInceptionEvent::new(probe_icp(), make_prefixer().into());
        let ser = serialize_delegated_inception(&dip).unwrap();
        let event = deserialize_delegated_inception(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.inception().said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::DelegatedInception(_)
        ));
    }

    #[test]
    fn oracle_roundtrips_drt() {
        let drt = DelegatedRotationEvent::new(probe_rot());
        let ser = serialize_delegated_rotation(&drt).unwrap();
        let event = deserialize_delegated_rotation(ser.as_bytes()).unwrap();
        assert_eq!(qb64(event.rotation().said()), qb64(ser.said()));
        assert!(matches!(
            deserialize_event(ser.as_bytes()).unwrap(),
            KeriEvent::DelegatedRotation(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Signing-threshold parsing
    // -----------------------------------------------------------------------

    #[test]
    fn tholder_simple_from_json() {
        let val = Value::String("3".to_owned());
        let th = tholder_from_json(&val, "signing").unwrap();
        assert_eq!(th, SigningThreshold::Simple(3));
    }

    #[test]
    fn tholder_weighted_from_json() {
        let val = serde_json::json!([["1/2", "1/2"], ["1/3", "1/3", "1/3"]]);
        let th = tholder_from_json(&val, "signing").unwrap();
        assert_eq!(
            th,
            weighted(vec![vec![(1, 2), (1, 2)], vec![(1, 3), (1, 3), (1, 3)],])
        );
    }

    #[test]
    fn tholder_invalid_returns_error() {
        let val = Value::Bool(true);
        let result = tholder_from_json(&val, "signing");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Seal parsing
    // -----------------------------------------------------------------------

    #[test]
    fn seal_digest_from_json() {
        let saider = make_saider();
        let qb64_str = qb64(&saider);
        let val = serde_json::json!({"d": qb64_str});
        let seal = seal_from_json(&val).unwrap();
        assert!(matches!(seal, Seal::Digest { .. }));
    }

    #[test]
    fn seal_root_from_json() {
        let saider = make_saider();
        let qb64_str = qb64(&saider);
        let val = serde_json::json!({"rd": qb64_str});
        let seal = seal_from_json(&val).unwrap();
        assert!(matches!(seal, Seal::Root { .. }));
    }

    #[test]
    fn seal_source_from_json() {
        let saider = make_saider();
        let qb64_str = qb64(&saider);
        let val = serde_json::json!({"s": "1", "d": qb64_str});
        let seal = seal_from_json(&val).unwrap();
        let Seal::Source { s, d } = seal else {
            unreachable!()
        };
        assert_eq!(s.value(), 1);
        assert_eq!(qb64(&d), qb64_str);
    }

    #[test]
    fn seal_event_from_json() {
        let saider = make_saider();
        let prefixer = make_prefixer();
        let d_str = qb64(&saider);
        let i_str = qb64(&prefixer);
        let val = serde_json::json!({"i": i_str, "s": "a", "d": d_str});
        let seal = seal_from_json(&val).unwrap();
        let Seal::Event { i, s, d } = seal else {
            unreachable!()
        };
        assert_eq!(qb64(&i), i_str);
        assert_eq!(s.value(), 10);
        assert_eq!(qb64(&d), d_str);
    }

    #[test]
    fn seal_last_from_json() {
        let prefixer = make_prefixer();
        let i_str = qb64(&prefixer);
        let val = serde_json::json!({"i": i_str});
        let seal = seal_from_json(&val).unwrap();
        let Seal::Last { i } = seal else {
            unreachable!()
        };
        assert_eq!(qb64(&i), i_str);
    }

    // -----------------------------------------------------------------------
    // intive=True integer threshold deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn tholder_from_json_integer() {
        let val = serde_json::json!(2);
        let tholder = tholder_from_json(&val, "signing").unwrap();
        assert_eq!(tholder, SigningThreshold::Simple(2));
    }

    #[test]
    fn parse_witness_threshold_integer() {
        let val = serde_json::json!(3);
        let bt = parse_witness_threshold(&val).unwrap();
        assert_eq!(bt, 3);
    }
}
