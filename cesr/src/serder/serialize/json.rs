//! Canonical JSON body writer: the [`SerializationKind::Json`] codec.
//!
//! Emits the five fixed KERI event grammars straight into the caller's
//! buffer — no intermediate tree or `String` per render — recording the
//! backpatchable slot offsets by construction as it writes, never by
//! re-scanning the buffer. A future CBOR/MGPK codec is a sibling module
//! (`cbor.rs`) plus a match arm in [`SerializationKind::render`].
//!
//! Field names and framing are compile-time constants per ilk; values are
//! qb64/hex/ASCII strings written through a full RFC 8259 escaper (the
//! escaper is defense-in-depth — no current value class needs escaping).

use crate::core::matter::code::CesrCode;
use crate::core::matter::matter::Matter;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};
use core::ops::Range;

use super::{EventLayout, EventRef};
use crate::core::version::{Protocol, SerializationKind, VersionString};
use crate::keri::{
    ConfigTrait, Identifier, Ilk, InceptionEvent, InteractionEvent, RotationEvent, Seal,
    SigningThreshold, ThresholdForm, Toad,
};
use crate::serder::error::SerderError;
use crate::serder::primitives::{identifier_to_qb64_string, to_qb64_string};

/// Render one event's canonical JSON body into `buf` (appending),
/// reporting the backpatchable slot layout. Slots are recorded by
/// construction as the writer emits them — never by re-scanning.
pub(super) fn render(
    event: EventRef<'_>,
    said_placeholder: &str,
    buf: &mut Vec<u8>,
) -> Result<EventLayout, SerderError> {
    match event {
        EventRef::Inception(e) => render_icp(buf, e, said_placeholder, Ilk::Icp, None),
        EventRef::Rotation(e) => render_rot(buf, e, said_placeholder, Ilk::Rot),
        EventRef::Interaction(e) => render_ixn(buf, e, said_placeholder),
        EventRef::DelegatedInception(e) => {
            let delegator = identifier_to_qb64_string(e.delegator());
            render_icp(
                buf,
                e.inception(),
                said_placeholder,
                Ilk::Dip,
                Some(&delegator),
            )
        }
        EventRef::DelegatedRotation(e) => render_rot(buf, e.rotation(), said_placeholder, Ilk::Drt),
    }
}

/// Write the shared `{"v":"<zero-size vstring>","t":"<ilk>","d":"<placeholder>`
/// head and return the size slot plus the `d` slot.
fn write_head(
    buf: &mut Vec<u8>,
    ilk: Ilk,
    placeholder: &str,
    kind: SerializationKind,
) -> Result<(Range<usize>, Range<usize>), SerderError> {
    let vs = VersionString::new(Protocol::Keri, 1, 0, kind, 0)?.to_str();
    buf.extend_from_slice(b"{\"v\":\"");
    let vs_start = buf.len();
    buf.extend_from_slice(vs.as_bytes());
    let size_start = vs_start
        .checked_add(10)
        .ok_or(SerderError::InvalidEventLayout("size slot offset overflow"))?;
    let size_end = size_start
        .checked_add(6)
        .ok_or(SerderError::InvalidEventLayout("size slot offset overflow"))?;

    buf.extend_from_slice(b"\",\"t\":");
    write_str(buf, ilk.code());
    buf.extend_from_slice(b",\"d\":\"");
    let d_start = buf.len();
    buf.extend_from_slice(placeholder.as_bytes());
    let d_end = buf.len();
    buf.push(b'"');
    Ok((size_start..size_end, d_start..d_end))
}

fn render_icp(
    buf: &mut Vec<u8>,
    e: &InceptionEvent,
    placeholder: &str,
    ilk: Ilk,
    delegator: Option<&str>,
) -> Result<EventLayout, SerderError> {
    let form = e.threshold_form();
    let (size_slot, said_slot) = write_head(buf, ilk, placeholder, SerializationKind::Json)?;

    let prefix_slot = match e.prefix() {
        Identifier::SelfAddressing(_) => {
            buf.extend_from_slice(b",\"i\":\"");
            let i_start = buf.len();
            buf.extend_from_slice(placeholder.as_bytes());
            let slot = i_start..buf.len();
            buf.push(b'"');
            Some(slot)
        }
        Identifier::Basic(p) => {
            buf.extend_from_slice(b",\"i\":");
            write_str(buf, &to_qb64_string(p));
            None
        }
    };

    buf.extend_from_slice(b",\"s\":");
    write_str(buf, &e.sn().to_string());
    buf.extend_from_slice(b",\"kt\":");
    write_tholder(buf, e.threshold(), form);
    buf.extend_from_slice(b",\"k\":");
    write_qb64_array(buf, e.keys());
    buf.extend_from_slice(b",\"nt\":");
    write_tholder(buf, e.next_threshold(), form);
    buf.extend_from_slice(b",\"n\":");
    write_qb64_array(buf, e.next_keys());
    buf.extend_from_slice(b",\"bt\":");
    write_toad(buf, e.witness_threshold(), form);
    buf.extend_from_slice(b",\"b\":");
    write_qb64_array(buf, e.witnesses());
    buf.extend_from_slice(b",\"c\":");
    write_config_array(buf, e.config());
    buf.extend_from_slice(b",\"a\":");
    write_seal_array(buf, e.anchors());
    if let Some(di) = delegator {
        buf.extend_from_slice(b",\"di\":");
        write_str(buf, di);
    }
    buf.push(b'}');

    Ok(EventLayout {
        size: size_slot,
        said: said_slot,
        prefix: prefix_slot,
    })
}

fn render_rot(
    buf: &mut Vec<u8>,
    e: &RotationEvent,
    placeholder: &str,
    ilk: Ilk,
) -> Result<EventLayout, SerderError> {
    let form = e.threshold_form();
    let (size_slot, said_slot) = write_head(buf, ilk, placeholder, SerializationKind::Json)?;

    buf.extend_from_slice(b",\"i\":");
    write_str(buf, &identifier_to_qb64_string(e.prefix()));
    buf.extend_from_slice(b",\"s\":");
    write_str(buf, &e.sn().to_string());
    buf.extend_from_slice(b",\"p\":");
    write_str(buf, &to_qb64_string(e.prior_event_said()));
    buf.extend_from_slice(b",\"kt\":");
    write_tholder(buf, e.threshold(), form);
    buf.extend_from_slice(b",\"k\":");
    write_qb64_array(buf, e.keys());
    buf.extend_from_slice(b",\"nt\":");
    write_tholder(buf, e.next_threshold(), form);
    buf.extend_from_slice(b",\"n\":");
    write_qb64_array(buf, e.next_keys());
    buf.extend_from_slice(b",\"bt\":");
    write_toad(buf, e.witness_threshold(), form);
    buf.extend_from_slice(b",\"br\":");
    write_qb64_array(buf, e.witness_removals());
    buf.extend_from_slice(b",\"ba\":");
    write_qb64_array(buf, e.witness_additions());
    buf.extend_from_slice(b",\"a\":");
    write_seal_array(buf, e.anchors());
    buf.push(b'}');

    Ok(EventLayout {
        size: size_slot,
        said: said_slot,
        prefix: None,
    })
}

fn render_ixn(
    buf: &mut Vec<u8>,
    e: &InteractionEvent,
    placeholder: &str,
) -> Result<EventLayout, SerderError> {
    let (size_slot, said_slot) = write_head(buf, Ilk::Ixn, placeholder, SerializationKind::Json)?;

    buf.extend_from_slice(b",\"i\":");
    write_str(buf, &identifier_to_qb64_string(e.prefix()));
    buf.extend_from_slice(b",\"s\":");
    write_str(buf, &e.sn().to_string());
    buf.extend_from_slice(b",\"p\":");
    write_str(buf, &to_qb64_string(e.prior_event_said()));
    buf.extend_from_slice(b",\"a\":");
    write_seal_array(buf, e.anchors());
    buf.push(b'}');

    Ok(EventLayout {
        size: size_slot,
        said: said_slot,
        prefix: None,
    })
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// Write `s` as a JSON string with RFC 8259 escaping, byte-identical to
/// `serde_json`'s escaper: `"`, `\`, and control characters below 0x20 are
/// escaped (short forms where they exist, `\u00xx` otherwise); everything
/// else — including multi-byte UTF-8 — passes through raw.
fn write_str(buf: &mut Vec<u8>, s: &str) {
    buf.push(b'"');
    for &byte in s.as_bytes() {
        match byte {
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\\' => buf.extend_from_slice(b"\\\\"),
            0x08 => buf.extend_from_slice(b"\\b"),
            0x09 => buf.extend_from_slice(b"\\t"),
            0x0A => buf.extend_from_slice(b"\\n"),
            0x0C => buf.extend_from_slice(b"\\f"),
            0x0D => buf.extend_from_slice(b"\\r"),
            b if b < 0x20 => {
                buf.extend_from_slice(b"\\u00");
                buf.push(HEX[usize::from(b >> 4)]);
                buf.push(HEX[usize::from(b & 0x0F)]);
            }
            b => buf.push(b),
        }
    }
    buf.push(b'"');
}

/// Write a slice of [`Matter`] primitives as a JSON array of qb64 strings.
fn write_qb64_array<C: CesrCode>(buf: &mut Vec<u8>, matters: &[Matter<'_, C>]) {
    buf.push(b'[');
    for (idx, m) in matters.iter().enumerate() {
        if idx > 0 {
            buf.push(b',');
        }
        write_str(buf, &to_qb64_string(m));
    }
    buf.push(b']');
}

/// A simple threshold renders as a
/// quoted hex string under [`ThresholdForm::HexString`] or as bare ASCII
/// decimal (no quotes) under [`ThresholdForm::Integer`]; single weighted
/// clauses are flattened and multiple clauses nested, always as an array
/// regardless of form. An integer-form value is guaranteed `<= u32::MAX` by
/// the parse/build validation
/// ([`SerderError::MixedThresholdForms`]/[`SerderError::IntegerFormOverflow`]);
/// the `debug_assert` documents that invariant without silently capping.
fn write_tholder(buf: &mut Vec<u8>, tholder: &SigningThreshold, form: ThresholdForm) {
    match tholder {
        SigningThreshold::Simple(n) => match form {
            ThresholdForm::HexString => write_str(buf, &format!("{n:x}")),
            ThresholdForm::Integer => {
                debug_assert!(
                    u32::try_from(*n).is_ok(),
                    "integer-form threshold exceeds keripy MaxIntThold"
                );
                buf.extend_from_slice(format!("{n}").as_bytes());
            }
        },
        SigningThreshold::Weighted(w) => {
            let mut clauses = w.clauses();
            match (clauses.next(), clauses.next()) {
                (Some(single), None) => write_weight_clause(buf, single),
                (Some(first), Some(second)) => {
                    buf.push(b'[');
                    write_weight_clause(buf, first);
                    buf.push(b',');
                    write_weight_clause(buf, second);
                    for clause in clauses {
                        buf.push(b',');
                        write_weight_clause(buf, clause);
                    }
                    buf.push(b']');
                }
                (None, _) => buf.extend_from_slice(b"[]"),
            }
        }
    }
}

/// Render the witness threshold (`bt`) into `buf`: a quoted lowercase-hex
/// string under [`ThresholdForm::HexString`], bare ASCII decimal (no quotes)
/// under [`ThresholdForm::Integer`]. `Toad` is a `u32`, so the integer always
/// fits.
fn write_toad(buf: &mut Vec<u8>, toad: Toad, form: ThresholdForm) {
    match form {
        ThresholdForm::HexString => write_str(buf, &format!("{:x}", toad.value())),
        ThresholdForm::Integer => buf.extend_from_slice(format!("{}", toad.value()).as_bytes()),
    }
}

/// Render one weight fraction the way keripy's `Tholder.sith` does: whole
/// values collapse to their integer string (`0`, `1`), everything else stays
/// `num/den`. A zero denominator is malformed (rejected by both
/// `SigningThreshold::check_well_formed` and the deserializer) but must render as a
/// plain fraction rather than dividing by zero.
fn weight_to_string(num: u64, den: u64) -> String {
    if den != 0 && (num == 0 || num == den) {
        format!("{}", num / den)
    } else {
        format!("{num}/{den}")
    }
}

fn write_weight_clause(buf: &mut Vec<u8>, clause: &[(u64, u64)]) {
    buf.push(b'[');
    for (idx, (num, den)) in clause.iter().enumerate() {
        if idx > 0 {
            buf.push(b',');
        }
        write_str(buf, &weight_to_string(*num, *den));
    }
    buf.push(b']');
}

fn write_config_array(buf: &mut Vec<u8>, config: &[ConfigTrait]) {
    buf.push(b'[');
    for (idx, c) in config.iter().enumerate() {
        if idx > 0 {
            buf.push(b',');
        }
        write_str(buf, c.code());
    }
    buf.push(b']');
}

/// Write one seal in its variant's fixed field order.
fn write_seal(buf: &mut Vec<u8>, seal: &Seal) {
    match seal {
        Seal::Digest { d } => {
            buf.extend_from_slice(b"{\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        Seal::Root { rd } => {
            buf.extend_from_slice(b"{\"rd\":");
            write_str(buf, &to_qb64_string(rd));
            buf.push(b'}');
        }
        Seal::Source { s, d } => {
            buf.extend_from_slice(b"{\"s\":");
            write_str(buf, &s.to_string());
            buf.extend_from_slice(b",\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        Seal::Event { i, s, d } => {
            buf.extend_from_slice(b"{\"i\":");
            write_str(buf, &to_qb64_string(i));
            buf.extend_from_slice(b",\"s\":");
            write_str(buf, &s.to_string());
            buf.extend_from_slice(b",\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        Seal::Last { i } => {
            buf.extend_from_slice(b"{\"i\":");
            write_str(buf, &to_qb64_string(i));
            buf.push(b'}');
        }
        Seal::Back { bi, d } => {
            buf.extend_from_slice(b"{\"bi\":");
            write_str(buf, &to_qb64_string(bi));
            buf.extend_from_slice(b",\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        Seal::Kind { t, d } => {
            buf.extend_from_slice(b"{\"t\":");
            write_str(buf, &to_qb64_string(t));
            buf.extend_from_slice(b",\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        // Verbatim: the payload is pre-validated compact JSON; re-escaping
        // through `write_str` would corrupt it.
        Seal::Opaque(raw) => buf.extend_from_slice(raw.as_str().as_bytes()),
    }
}

fn write_seal_array(buf: &mut Vec<u8>, seals: &[Seal]) {
    buf.push(b'[');
    for (idx, seal) in seals.iter().enumerate() {
        if idx > 0 {
            buf.push(b',');
        }
        write_seal(buf, seal);
    }
    buf.push(b']');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keri::sequence::SequenceNumber;
    use crate::keri::threshold_form::ThresholdForm;
    use crate::keri::toad::Toad;
    use crate::keri::{
        DelegatedInceptionEvent, DelegatedRotationEvent, Identifier, WeightedThreshold,
    };
    use crate::serder::deserialize::deserialize_event;
    use crate::serder::deserialize::deserialize_inception;
    use crate::serder::event_strategies::{
        IdSpec, build_icp, build_identifier, build_ixn, build_rot, icp_strategy, ixn_strategy,
        prefixer, rot_strategy, saider,
    };
    use crate::serder::serialize::{
        SerializedEvent, serialize_delegated_inception, serialize_delegated_rotation,
        serialize_inception, serialize_interaction, serialize_rotation,
    };
    use proptest::prelude::*;
    use serde_json::{Value, json};

    fn weighted(clauses: Vec<Vec<(u64, u64)>>) -> SigningThreshold {
        SigningThreshold::Weighted(WeightedThreshold::from_nested(clauses).unwrap())
    }

    // ------------------------------------------------------------------
    // Structural oracle: an INDEPENDENT rendering of each event as a
    // serde_json::Value tree, built from domain fields in test code. The
    // writer's output must parse (via serde_json — no shared code with the
    // writer) to exactly this tree. The tree construction does reuse the
    // shared value encoders — qb64 (`to_qb64_string`/
    // `identifier_to_qb64_string`), `SequenceNumber`'s hex `Display`, and
    // `ConfigTrait::code()` — all core/keri-tested elsewhere, none part of
    // this writer. `fraction` deliberately re-states the
    // weight-rendering rule rather than calling `weight_to_string`; that
    // duplication IS the oracle. Byte-level canonical form (field order,
    // framing) is asserted by the fixpoint tests
    // (`back_kind_and_opaque_seals_render_verbatim_and_fixpoint` here, the
    // `*_strict_equals_reference` suite in deserialize.rs) and keripy
    // corpora, which Value equality cannot see.
    // ------------------------------------------------------------------

    fn fraction(num: u64, den: u64) -> String {
        if den != 0 && (num == 0 || num == den) {
            format!("{}", num / den)
        } else {
            format!("{num}/{den}")
        }
    }

    fn hex_tholder(t: &SigningThreshold) -> Value {
        match t {
            SigningThreshold::Simple(n) => Value::String(format!("{n:x}")),
            SigningThreshold::Weighted(w) => {
                let clauses: Vec<Value> = w
                    .clauses()
                    .map(|clause| {
                        Value::Array(
                            clause
                                .iter()
                                .map(|(n, d)| Value::String(fraction(*n, *d)))
                                .collect(),
                        )
                    })
                    .collect();
                match <[Value; 1]>::try_from(clauses) {
                    Ok([single]) => single,
                    Err(multiple) => Value::Array(multiple),
                }
            }
        }
    }

    fn qb64_values<C: CesrCode>(matters: &[Matter<'_, C>]) -> Value {
        Value::Array(
            matters
                .iter()
                .map(|m| Value::String(to_qb64_string(m)))
                .collect(),
        )
    }

    fn seal_value(seal: &Seal) -> Value {
        match seal {
            Seal::Digest { d } => json!({"d": to_qb64_string(d)}),
            Seal::Root { rd } => json!({"rd": to_qb64_string(rd)}),
            Seal::Source { s, d } => json!({"s": s.to_string(), "d": to_qb64_string(d)}),
            Seal::Event { i, s, d } => {
                json!({"i": to_qb64_string(i), "s": s.to_string(), "d": to_qb64_string(d)})
            }
            Seal::Last { i } => json!({"i": to_qb64_string(i)}),
            Seal::Back { bi, d } => json!({"bi": to_qb64_string(bi), "d": to_qb64_string(d)}),
            Seal::Kind { t, d } => json!({"t": to_qb64_string(t), "d": to_qb64_string(d)}),
            Seal::Opaque(raw) => serde_json::from_str(raw.as_str())
                .expect("OpaqueSeal payloads are valid JSON by construction"),
        }
    }

    fn seal_values(seals: &[Seal]) -> Value {
        Value::Array(seals.iter().map(seal_value).collect())
    }

    // `v`, `d`, and (for double-SAID events) `i` are backpatched by the
    // orchestration, so they are taken from the output rather than the
    // event; the circularity is closed by the dedicated size assertion in
    // each proptest and SAID verification in the fixpoint tests
    // (`back_kind_and_opaque_seals_render_verbatim_and_fixpoint`, plus the
    // `*_strict_equals_reference` suite in deserialize.rs).
    fn expected_icp_tree(e: &InceptionEvent, out: &SerializedEvent, ilk: &str) -> Value {
        let prefix = match e.prefix() {
            Identifier::SelfAddressing(_) => to_qb64_string(out.said()),
            Identifier::Basic(p) => to_qb64_string(p),
        };
        json!({
            "v": format!("KERI10JSON{:06x}_", out.size()),
            "t": ilk,
            "d": to_qb64_string(out.said()),
            "i": prefix,
            "s": e.sn().to_string(),
            "kt": hex_tholder(e.threshold()),
            "k": qb64_values(e.keys()),
            "nt": hex_tholder(e.next_threshold()),
            "n": qb64_values(e.next_keys()),
            "bt": format!("{:x}", e.witness_threshold().value()),
            "b": qb64_values(e.witnesses()),
            "c": Value::Array(
                e.config().iter().map(|c| Value::String(c.code().to_owned())).collect()
            ),
            "a": seal_values(e.anchors()),
        })
    }

    fn expected_rot_tree(e: &RotationEvent, out: &SerializedEvent, ilk: &str) -> Value {
        json!({
            "v": format!("KERI10JSON{:06x}_", out.size()),
            "t": ilk,
            "d": to_qb64_string(out.said()),
            "i": identifier_to_qb64_string(e.prefix()),
            "s": e.sn().to_string(),
            "p": to_qb64_string(e.prior_event_said()),
            "kt": hex_tholder(e.threshold()),
            "k": qb64_values(e.keys()),
            "nt": hex_tholder(e.next_threshold()),
            "n": qb64_values(e.next_keys()),
            "bt": format!("{:x}", e.witness_threshold().value()),
            "br": qb64_values(e.witness_removals()),
            "ba": qb64_values(e.witness_additions()),
            "a": seal_values(e.anchors()),
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn icp_output_matches_independent_tree(spec in icp_strategy()) {
            let event = build_icp(spec);
            let out = serialize_inception(&event).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_icp_tree(&event, &out, "icp"));
        }

        #[test]
        fn rot_output_matches_independent_tree(spec in rot_strategy()) {
            let event = build_rot(spec);
            let out = serialize_rotation(&event).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_rot_tree(&event, &out, "rot"));
        }

        #[test]
        fn ixn_output_matches_independent_tree(spec in ixn_strategy()) {
            let event = build_ixn(spec);
            let out = serialize_interaction(&event).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            let expected = json!({
                "v": format!("KERI10JSON{:06x}_", out.size()),
                "t": "ixn",
                "d": to_qb64_string(out.said()),
                "i": identifier_to_qb64_string(event.prefix()),
                "s": event.sn().to_string(),
                "p": to_qb64_string(event.prior_event_said()),
                "a": seal_values(event.anchors()),
            });
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn dip_output_matches_independent_tree(
            spec in icp_strategy(),
            delegator in any::<IdSpec>(),
        ) {
            let dip = DelegatedInceptionEvent::new(build_icp(spec), build_identifier(delegator));
            let out = serialize_delegated_inception(&dip).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            let mut expected = expected_icp_tree(dip.inception(), &out, "dip");
            expected.as_object_mut().unwrap().insert(
                "di".to_owned(),
                Value::String(identifier_to_qb64_string(dip.delegator())),
            );
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn drt_output_matches_independent_tree(spec in rot_strategy()) {
            let drt = DelegatedRotationEvent::new(build_rot(spec));
            let out = serialize_delegated_rotation(&drt).unwrap();
            prop_assert_eq!(out.size(), out.as_bytes().len());
            let got: Value = serde_json::from_slice(out.as_bytes()).unwrap();
            prop_assert_eq!(got, expected_rot_tree(drt.rotation(), &out, "drt"));
        }

        #[test]
        fn escaper_matches_serde_json_arbitrary_unicode(s in any::<String>()) {
            // any::<String>() reaches control characters and unpaired-surrogate
            // -adjacent code points that the ".*" regex strategy under-samples.
            let mut buf = Vec::new();
            write_str(&mut buf, &s);
            let expected =
                serde_json::to_string(&serde_json::Value::String(s.clone())).unwrap();
            prop_assert_eq!(core::str::from_utf8(&buf).unwrap(), expected.as_str());
        }

        #[test]
        fn escaper_matches_serde_json(s in ".*") {
            let mut buf = Vec::new();
            write_str(&mut buf, &s);
            let expected =
                serde_json::to_string(&serde_json::Value::String(s.clone())).unwrap();
            prop_assert_eq!(core::str::from_utf8(&buf).unwrap(), expected.as_str());
        }
    }

    #[test]
    fn escaper_covers_every_escape_class() {
        // One deterministic probe per escape class: quote, backslash, the
        // five short escapes, \u00xx fallbacks (NUL, 0x1F), the unescaped
        // DEL boundary (0x7F), and multi-byte UTF-8 passthrough.
        let s = "q\" b\\ \u{8}\t\n\u{c}\r \u{0}\u{1f}\u{7f} héllo → 日本";
        let mut buf = Vec::new();
        write_str(&mut buf, s);
        let expected = serde_json::to_string(&serde_json::Value::String(s.to_owned())).unwrap();
        assert_eq!(core::str::from_utf8(&buf).unwrap(), expected);
    }

    // write_tholder — canonical location for flatten/nest/empty rendering.

    #[test]
    fn write_tholder_empty_weighted_shapes() {
        // Boundary shapes the strategies under-sample: an empty clause list
        // and a single empty clause both flatten to "[]"; two empty clauses
        // stay nested.
        for (kt, expected) in [
            (weighted(vec![]), "[]"),
            (weighted(vec![vec![]]), "[]"),
            (weighted(vec![vec![], vec![]]), "[[],[]]"),
        ] {
            let mut buf = Vec::new();
            write_tholder(&mut buf, &kt, ThresholdForm::HexString);
            assert_eq!(core::str::from_utf8(&buf).unwrap(), expected);
        }
    }

    #[test]
    fn write_tholder_zero_denominator_renders_without_panicking() {
        // Bug probe (ported from the deleted tholder_to_json test): a (0, 0)
        // weight previously hit `0 / 0` and panicked. Malformed weights must
        // render as a plain fraction; rejection happens at parse/validation.
        let tholder = weighted(vec![vec![(0, 0), (1, 0)]]);
        let mut buf = Vec::new();
        write_tholder(&mut buf, &tholder, ThresholdForm::HexString);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"["0/0","1/0"]"#);
    }

    #[test]
    fn write_tholder_single_clause_flattens_and_multi_nests() {
        let single = weighted(vec![vec![(1, 2), (1, 2)]]);
        let mut buf = Vec::new();
        write_tholder(&mut buf, &single, ThresholdForm::HexString);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"["1/2","1/2"]"#);

        let multi = weighted(vec![vec![(1, 2)], vec![(1, 1)]]);
        buf.clear();
        write_tholder(&mut buf, &multi, ThresholdForm::HexString);
        assert_eq!(core::str::from_utf8(&buf).unwrap(), r#"[["1/2"],["1"]]"#);
    }

    // weight_to_string — exact mapping table.

    #[test]
    fn weight_to_string_exact_mapping() {
        // Whole values collapse to their integer string; everything else —
        // including malformed zero denominators and unreduced fractions —
        // stays num/den verbatim (keripy does not reduce).
        assert_eq!(weight_to_string(0, 1), "0");
        assert_eq!(weight_to_string(1, 1), "1");
        assert_eq!(weight_to_string(2, 2), "1");
        assert_eq!(weight_to_string(u64::MAX, u64::MAX), "1");
        assert_eq!(weight_to_string(1, 2), "1/2");
        assert_eq!(weight_to_string(2, 4), "2/4");
        assert_eq!(weight_to_string(3, 2), "3/2");
        assert_eq!(weight_to_string(0, 0), "0/0");
        assert_eq!(weight_to_string(1, 0), "1/0");
        assert_eq!(weight_to_string(u64::MAX, 1), "18446744073709551615/1");
    }

    #[test]
    fn render_into_prefilled_buffer_reports_absolute_slots() {
        let event = build_ixn(((true, [0; 32]), 1, [1; 32], [2; 32], vec![]));
        let placeholder = "#".repeat(44);
        let mut buf = b"JUNK".to_vec();
        let layout = render(EventRef::Interaction(&event), &placeholder, &mut buf).unwrap();
        assert_eq!(&buf[..4], b"JUNK", "render must append, not overwrite");
        assert_eq!(&buf[layout.size], b"000000");
        assert_eq!(&buf[layout.said], placeholder.as_bytes());
        assert!(layout.prefix.is_none(), "ixn is single-SAID");
    }

    // The read path is now the strict canonical parser (#142); the assertion
    // is unchanged — the writer's output must still SAID-verify through it.
    #[test]
    fn output_verifies_through_unchanged_read_path() {
        let event = InceptionEvent::new(
            Identifier::Basic(prefixer([0; 32])),
            SequenceNumber::new(0),
            saider([1; 32]),
            vec![prefixer([2; 32])],
            SigningThreshold::Simple(1),
            vec![saider([3; 32])],
            SigningThreshold::Simple(1),
            vec![prefixer([4; 32])],
            Toad::exact(1, 1).unwrap(),
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: saider([5; 32]) }],
            ThresholdForm::HexString,
        );
        let out = serialize_inception(&event).unwrap();
        let parsed = deserialize_inception(out.as_bytes()).unwrap();
        assert_eq!(
            to_qb64_string(parsed.said()),
            to_qb64_string(out.said()),
            "rendered event must SAID-verify through the strict canonical read path"
        );
    }

    #[test]
    fn back_kind_and_opaque_seals_render_verbatim_and_fixpoint() {
        use crate::core::matter::builder::MatterBuilder;
        use crate::core::matter::code::VerserCode;
        use crate::keri::OpaqueSeal;
        use crate::serder::traits::KeriSerialize;

        // The reviewer counterexample: a Value round-trip rewrites `1e2` as
        // `100.0` and the `é` escape as a raw `é` — the writer must emit the
        // validated payload untouched, and the strict reader must hand it
        // back byte-identical.
        let payload = "{\"x\":1e2,\"u\":\"\\u00e9\"}";
        let verser = MatterBuilder::new()
            .from_qualified_base64(b"YKERIBAA")
            .unwrap()
            .narrow::<VerserCode>()
            .unwrap()
            .into_static();
        let event = InteractionEvent::new(
            Identifier::Basic(prefixer([0; 32])),
            SequenceNumber::new(1),
            saider([1; 32]),
            saider([2; 32]),
            vec![
                Seal::Back {
                    bi: prefixer([3; 32]),
                    d: saider([4; 32]),
                },
                Seal::Kind {
                    t: verser,
                    d: saider([5; 32]),
                },
                Seal::Opaque(OpaqueSeal::new(payload.to_owned()).unwrap()),
            ],
        );
        let out = serialize_interaction(&event).unwrap();
        let text = core::str::from_utf8(out.as_bytes()).unwrap();
        assert!(
            text.contains(payload),
            "opaque payload must be emitted verbatim: {text}"
        );
        let parsed = deserialize_event(out.as_bytes()).unwrap();
        let again = parsed.serialize().unwrap();
        assert_eq!(out.as_bytes(), again.as_bytes());
    }
}
