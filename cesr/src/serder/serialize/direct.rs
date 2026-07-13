//! Direct serialization backend: a hand-rolled canonical JSON writer.
//!
//! Emits the five fixed KERI event grammars straight into the caller's
//! buffer — no `serde_json::Value` tree, no intermediate `String` per
//! render — recording the backpatchable slot offsets as it writes. Output
//! is byte-identical to the [`SerdeJson`](super::SerdeJson) reference
//! backend; the cross-backend property tests in this module are the gate.

use crate::core::matter::code::CesrCode;
use crate::core::matter::matter::Matter;
use crate::core::primitives::Tholder;
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec};
use core::ops::Range;

use super::{EventLayout, EventRef, EventSerializer, weight_to_string};
use crate::keri::{ConfigTrait, Identifier, InceptionEvent, InteractionEvent, RotationEvent, Seal};
use crate::serder::error::SerderError;
use crate::serder::primitives::{identifier_to_qb64_string, sn_to_hex, to_qb64_string};
use crate::serder::version::VersionString;

/// The direct backend: writes canonical JSON straight into the caller's
/// buffer.
///
/// Field names and framing are compile-time constants per ilk; values are
/// qb64/hex/ASCII strings written through a full RFC 8259 escaper (the
/// escaper is defense-in-depth — no current value class needs escaping).
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectJson;

impl EventSerializer for DirectJson {
    fn render(
        &self,
        event: EventRef<'_>,
        said_placeholder: &str,
        buf: &mut Vec<u8>,
    ) -> Result<EventLayout, SerderError> {
        match event {
            EventRef::Inception(e) => render_icp(buf, e, said_placeholder, "icp", None),
            EventRef::Rotation(e) => render_rot(buf, e, said_placeholder, "rot"),
            EventRef::Interaction(e) => render_ixn(buf, e, said_placeholder),
            EventRef::DelegatedInception(e) => {
                let delegator = identifier_to_qb64_string(e.delegator());
                render_icp(
                    buf,
                    e.inception(),
                    said_placeholder,
                    "dip",
                    Some(&delegator),
                )
            }
            EventRef::DelegatedRotation(e) => {
                render_rot(buf, e.rotation(), said_placeholder, "drt")
            }
        }
    }
}

/// Write the shared `{"v":"<zero-size vstring>","t":"<ilk>","d":"<placeholder>`
/// head and return the size slot plus the `d` slot.
fn write_head(
    buf: &mut Vec<u8>,
    ilk: &str,
    placeholder: &str,
) -> Result<(Range<usize>, Range<usize>), SerderError> {
    let vs = VersionString::keri_json_v1().to_str()?;
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
    write_str(buf, ilk);
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
    ilk: &str,
    delegator: Option<&str>,
) -> Result<EventLayout, SerderError> {
    let (size_slot, said_slot) = write_head(buf, ilk, placeholder)?;

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
    write_str(buf, &sn_to_hex(e.sn().value()));
    buf.extend_from_slice(b",\"kt\":");
    write_tholder(buf, e.threshold());
    buf.extend_from_slice(b",\"k\":");
    write_qb64_array(buf, e.keys());
    buf.extend_from_slice(b",\"nt\":");
    write_tholder(buf, e.next_threshold());
    buf.extend_from_slice(b",\"n\":");
    write_qb64_array(buf, e.next_keys());
    buf.extend_from_slice(b",\"bt\":");
    write_str(buf, &sn_to_hex(u128::from(e.witness_threshold())));
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
        size_slot,
        said_slot,
        prefix_slot,
    })
}

fn render_rot(
    buf: &mut Vec<u8>,
    e: &RotationEvent,
    placeholder: &str,
    ilk: &str,
) -> Result<EventLayout, SerderError> {
    let (size_slot, said_slot) = write_head(buf, ilk, placeholder)?;

    buf.extend_from_slice(b",\"i\":");
    write_str(buf, &identifier_to_qb64_string(e.prefix()));
    buf.extend_from_slice(b",\"s\":");
    write_str(buf, &sn_to_hex(e.sn().value()));
    buf.extend_from_slice(b",\"p\":");
    write_str(buf, &to_qb64_string(e.prior_event_said()));
    buf.extend_from_slice(b",\"kt\":");
    write_tholder(buf, e.threshold());
    buf.extend_from_slice(b",\"k\":");
    write_qb64_array(buf, e.keys());
    buf.extend_from_slice(b",\"nt\":");
    write_tholder(buf, e.next_threshold());
    buf.extend_from_slice(b",\"n\":");
    write_qb64_array(buf, e.next_keys());
    buf.extend_from_slice(b",\"bt\":");
    write_str(buf, &sn_to_hex(u128::from(e.witness_threshold())));
    buf.extend_from_slice(b",\"br\":");
    write_qb64_array(buf, e.witness_removals());
    buf.extend_from_slice(b",\"ba\":");
    write_qb64_array(buf, e.witness_additions());
    buf.extend_from_slice(b",\"a\":");
    write_seal_array(buf, e.anchors());
    buf.push(b'}');

    Ok(EventLayout {
        size_slot,
        said_slot,
        prefix_slot: None,
    })
}

fn render_ixn(
    buf: &mut Vec<u8>,
    e: &InteractionEvent,
    placeholder: &str,
) -> Result<EventLayout, SerderError> {
    let (size_slot, said_slot) = write_head(buf, "ixn", placeholder)?;

    buf.extend_from_slice(b",\"i\":");
    write_str(buf, &identifier_to_qb64_string(e.prefix()));
    buf.extend_from_slice(b",\"s\":");
    write_str(buf, &sn_to_hex(e.sn().value()));
    buf.extend_from_slice(b",\"p\":");
    write_str(buf, &to_qb64_string(e.prior_event_said()));
    buf.extend_from_slice(b",\"a\":");
    write_seal_array(buf, e.anchors());
    buf.push(b'}');

    Ok(EventLayout {
        size_slot,
        said_slot,
        prefix_slot: None,
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

/// Mirror of [`super::matters_to_json_array`]: a JSON array of qb64 strings.
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

/// Mirror of [`super::tholder_to_json`]: simple thresholds as hex strings,
/// single weighted clauses flattened, multiple clauses nested.
fn write_tholder(buf: &mut Vec<u8>, tholder: &Tholder) {
    match tholder {
        Tholder::Simple(n) => write_str(buf, &format!("{n:x}")),
        Tholder::Weighted(clauses) => {
            if let [single] = clauses.as_slice() {
                write_weight_clause(buf, single);
            } else {
                buf.push(b'[');
                for (idx, clause) in clauses.iter().enumerate() {
                    if idx > 0 {
                        buf.push(b',');
                    }
                    write_weight_clause(buf, clause);
                }
                buf.push(b']');
            }
        }
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

/// Mirror of [`super::seal_to_json`]: each seal variant's fixed field order.
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
            write_str(buf, &sn_to_hex(s.value()));
            buf.extend_from_slice(b",\"d\":");
            write_str(buf, &to_qb64_string(d));
            buf.push(b'}');
        }
        Seal::Event { i, s, d } => {
            buf.extend_from_slice(b"{\"i\":");
            write_str(buf, &to_qb64_string(i));
            buf.extend_from_slice(b",\"s\":");
            write_str(buf, &sn_to_hex(s.value()));
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
    use super::super::{SerdeJson, serialize_with};
    use super::*;
    use crate::core::primitives::Seqner;
    use crate::keri::{DelegatedInceptionEvent, DelegatedRotationEvent, Identifier};
    use crate::serder::deserialize::deserialize_inception;
    use crate::serder::event_strategies::{
        IdSpec, build_icp, build_identifier, build_ixn, build_rot, icp_strategy, ixn_strategy,
        prefixer, rot_strategy, saider,
    };
    use proptest::prelude::*;

    fn assert_backends_identical(event: EventRef<'_>) {
        let reference = serialize_with(&SerdeJson, event).unwrap();
        let direct = serialize_with(&DirectJson, event).unwrap();
        assert_eq!(
            core::str::from_utf8(reference.as_bytes()).unwrap(),
            core::str::from_utf8(direct.as_bytes()).unwrap(),
            "direct backend must be byte-identical to the serde_json reference"
        );
        assert_eq!(
            to_qb64_string(reference.said()),
            to_qb64_string(direct.said())
        );
        assert_eq!(reference.size(), direct.size());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn icp_backends_byte_identical(spec in icp_strategy()) {
            let event = build_icp(spec);
            assert_backends_identical(EventRef::Inception(&event));
        }

        #[test]
        fn rot_backends_byte_identical(spec in rot_strategy()) {
            let event = build_rot(spec);
            assert_backends_identical(EventRef::Rotation(&event));
        }

        #[test]
        fn ixn_backends_byte_identical(spec in ixn_strategy()) {
            let event = build_ixn(spec);
            assert_backends_identical(EventRef::Interaction(&event));
        }

        #[test]
        fn dip_backends_byte_identical(
            spec in icp_strategy(),
            delegator in any::<IdSpec>(),
        ) {
            let dip =
                DelegatedInceptionEvent::new(build_icp(spec), build_identifier(delegator));
            assert_backends_identical(EventRef::DelegatedInception(&dip));
        }

        #[test]
        fn drt_backends_byte_identical(spec in rot_strategy()) {
            let drt = DelegatedRotationEvent::new(build_rot(spec));
            assert_backends_identical(EventRef::DelegatedRotation(&drt));
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

    #[test]
    fn empty_weighted_thresholds_are_byte_identical_across_backends() {
        // Boundary shapes the strategies can under-sample: an empty clause
        // list and a single empty clause both render as "[]" on both
        // backends (single-clause flattening applies to the empty clause).
        for kt in [
            Tholder::Weighted(vec![]),
            Tholder::Weighted(vec![vec![]]),
            Tholder::Weighted(vec![vec![], vec![]]),
        ] {
            let event = InceptionEvent::new(
                Identifier::Basic(prefixer([0; 32])),
                Seqner::new(0),
                saider([1; 32]),
                vec![prefixer([2; 32])],
                kt,
                vec![saider([3; 32])],
                Tholder::Simple(1),
                vec![],
                0,
                vec![],
                vec![],
            );
            assert_backends_identical(EventRef::Inception(&event));
        }
    }

    #[test]
    fn direct_render_into_prefilled_buffer_reports_absolute_slots() {
        let event = build_ixn(((true, [0; 32]), 1, [1; 32], [2; 32], vec![]));
        let placeholder = "#".repeat(44);
        let mut buf = b"JUNK".to_vec();
        let layout = DirectJson
            .render(EventRef::Interaction(&event), &placeholder, &mut buf)
            .unwrap();
        assert_eq!(&buf[..4], b"JUNK", "render must append, not overwrite");
        assert_eq!(&buf[layout.size_slot], b"000000");
        assert_eq!(&buf[layout.said_slot], placeholder.as_bytes());
        assert!(layout.prefix_slot.is_none(), "ixn is single-SAID");
    }

    // The read path is now the strict canonical parser (#142); the assertion
    // is unchanged — direct output must still SAID-verify through it.
    #[test]
    fn direct_output_verifies_through_unchanged_read_path() {
        let event = InceptionEvent::new(
            Identifier::Basic(prefixer([0; 32])),
            Seqner::new(0),
            saider([1; 32]),
            vec![prefixer([2; 32])],
            Tholder::Simple(1),
            vec![saider([3; 32])],
            Tholder::Simple(1),
            vec![prefixer([4; 32])],
            1,
            vec![ConfigTrait::EstOnly],
            vec![Seal::Digest { d: saider([5; 32]) }],
        );
        let direct = serialize_with(&DirectJson, EventRef::Inception(&event)).unwrap();
        let parsed = deserialize_inception(direct.as_bytes()).unwrap();
        assert_eq!(
            to_qb64_string(parsed.said()),
            to_qb64_string(direct.said()),
            "direct-rendered event must SAID-verify through the strict canonical read path"
        );
    }

    #[test]
    fn back_kind_and_opaque_seals_byte_identical_and_verbatim() {
        use crate::core::matter::builder::MatterBuilder;
        use crate::core::matter::code::VerserCode;
        use crate::keri::OpaqueSeal;

        // The reviewer counterexample: a Value round-trip rewrites `1e2` as
        // `100.0` and the `é` escape as a raw `é` — the raw-injection
        // path must keep both untouched on the SerdeJson backend.
        let payload = "{\"x\":1e2,\"u\":\"\\u00e9\"}";
        let verser = MatterBuilder::new()
            .from_qualified_base64(b"YKERIBAA")
            .unwrap()
            .narrow::<VerserCode>()
            .unwrap()
            .into_static();
        let event = InteractionEvent::new(
            Identifier::Basic(prefixer([0; 32])),
            Seqner::new(1),
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
        let event_ref = EventRef::Interaction(&event);
        assert_backends_identical(event_ref);
        let reference = serialize_with(&SerdeJson, event_ref).unwrap();
        let text = core::str::from_utf8(reference.as_bytes()).unwrap();
        assert!(
            text.contains(payload),
            "opaque payload must be emitted verbatim on both backends: {text}"
        );
    }
}
