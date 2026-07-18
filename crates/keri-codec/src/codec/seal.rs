//! The seal wire grammar — both directions in one place.
//!
//! Each `Seal` variant's write form lives in [`Encode`]; the matching read
//! form joins as `ParsedSeal`'s [`Decode`](crate::codec::Decode) (#193
//! step-2 task 3), keeping the grammar stated once per direction, adjacent.

#[cfg(feature = "alloc")]
use alloc::{string::ToString, vec::Vec};
use core::str;

use crate::codec::{Decode, Encode, JsonWriter};
use crate::deserialize::canonical::{ParsedSeal, Scanner};
use crate::deserialize::opaque_scan::OpaqueScan;
use crate::error::SerderError;
use crate::primitives::to_qb64_string;
use keri_events::Seal;

impl Encode for Seal<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Seal::Digest { d } => {
                out.extend_from_slice(b"{\"d\":");
                JsonWriter::write_str(out, &to_qb64_string(d));
                out.push(b'}');
            }
            Seal::Root { rd } => {
                out.extend_from_slice(b"{\"rd\":");
                JsonWriter::write_str(out, &to_qb64_string(rd));
                out.push(b'}');
            }
            Seal::Source { s, d } => {
                out.extend_from_slice(b"{\"s\":");
                JsonWriter::write_str(out, &s.to_string());
                out.extend_from_slice(b",\"d\":");
                JsonWriter::write_str(out, &to_qb64_string(d));
                out.push(b'}');
            }
            Seal::Event { i, s, d } => {
                out.extend_from_slice(b"{\"i\":");
                JsonWriter::write_str(out, &to_qb64_string(i));
                out.extend_from_slice(b",\"s\":");
                JsonWriter::write_str(out, &s.to_string());
                out.extend_from_slice(b",\"d\":");
                JsonWriter::write_str(out, &to_qb64_string(d));
                out.push(b'}');
            }
            Seal::Last { i } => {
                out.extend_from_slice(b"{\"i\":");
                JsonWriter::write_str(out, &to_qb64_string(i));
                out.push(b'}');
            }
            Seal::Back { bi, d } => {
                out.extend_from_slice(b"{\"bi\":");
                JsonWriter::write_str(out, &to_qb64_string(bi));
                out.extend_from_slice(b",\"d\":");
                JsonWriter::write_str(out, &to_qb64_string(d));
                out.push(b'}');
            }
            Seal::Kind { t, d } => {
                out.extend_from_slice(b"{\"t\":");
                JsonWriter::write_str(out, &to_qb64_string(t));
                out.extend_from_slice(b",\"d\":");
                JsonWriter::write_str(out, &to_qb64_string(d));
                out.push(b'}');
            }
            // Verbatim: the payload is compact JSON by `new_unchecked`'s caller
            // contract (the strict reader enforces it via `OpaqueScan` before
            // construction); re-escaping through `write_str` would corrupt it.
            Seal::Opaque(raw) => out.extend_from_slice(raw.as_str().as_bytes()),
        }
    }
}

impl Encode for [Seal<'_>] {
    /// A canonical JSON array of seals — compact, no trailing comma.
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(b'[');
        for (idx, seal) in self.iter().enumerate() {
            if idx > 0 {
                out.push(b',');
            }
            seal.encode(out);
        }
        out.push(b']');
    }
}

impl<'a> Decode<'a> for ParsedSeal<'a> {
    /// One seal object: the seven codex shapes parse typed; anything else
    /// falls back to a verbatim opaque capture of the whole object. A codex
    /// parse failure rewinds — the codex attempt and the opaque scan both
    /// start from the object's first byte.
    fn decode(sc: &mut Scanner<'a>) -> Result<Self, SerderError> {
        let start = sc.pos;
        // The codex error is deliberately superseded: the opaque scan is the
        // outermost interpretation and produces its own typed error on failure.
        if let Ok(parsed) = codex(sc) {
            return Ok(parsed);
        }
        sc.pos = start;
        opaque(sc)
    }
}

/// The seven fixed codex shapes, dispatched on the first key. Field order
/// per variant is fixed (matches the writer and keripy's namedtuple
/// serialization order). The `"i"` key is shared by `Last` (closes
/// immediately) and `Event` (continues with `"s"`/`"d"`) — the chain order
/// is grammar, not style.
fn codex<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
    sc.expect("{")?;
    if sc.take_lit("\"d\":") {
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Digest { d });
    }
    if sc.take_lit("\"rd\":") {
        let rd = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Root { rd });
    }
    if sc.take_lit("\"s\":") {
        let s = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Source { s, d });
    }
    if sc.take_lit("\"i\":") {
        let i = sc.string()?.value;
        if sc.take_lit("}") {
            return Ok(ParsedSeal::Last { i });
        }
        sc.expect(",\"s\":")?;
        let s = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Event { i, s, d });
    }
    if sc.take_lit("\"bi\":") {
        let bi = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Back { bi, d });
    }
    if sc.take_lit("\"t\":") {
        let t = sc.string()?.value;
        sc.expect(",\"d\":")?;
        let d = sc.string()?.value;
        sc.expect("}")?;
        return Ok(ParsedSeal::Kind { t, d });
    }
    Err(sc.err("seal object key (\"d\", \"rd\", \"s\", \"i\", \"bi\", or \"t\")"))
}

/// Capture a non-codex anchor object verbatim.
fn opaque<'a>(sc: &mut Scanner<'a>) -> Result<ParsedSeal<'a>, SerderError> {
    let start = sc.pos;
    let rest = sc
        .input
        .get(start..)
        .ok_or(SerderError::InvalidEventLayout("anchor span out of bounds"))?;
    let len = OpaqueScan::object_len(rest).map_err(|source| SerderError::InvalidAnchor {
        offset: start,
        source,
    })?;
    let end = start
        .checked_add(len)
        .ok_or(SerderError::InvalidEventLayout("anchor span overflow"))?;
    let bytes = sc
        .input
        .get(start..end)
        .ok_or(SerderError::InvalidEventLayout("anchor span out of bounds"))?;
    let raw = str::from_utf8(bytes).map_err(|e| {
        start.checked_add(e.valid_up_to()).map_or(
            SerderError::InvalidEventLayout("UTF-8 error offset overflow"),
            |offset| sc.err_at(offset, "UTF-8 anchor object"),
        )
    })?;
    sc.pos = end;
    Ok(ParsedSeal::Opaque { raw })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OpaqueScanError;
    use alloc::borrow::Cow;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode, VerserCode};
    use cesr::core::primitives::{Prefixer, Saider, Verser};
    use keri_events::{OpaqueSeal, SequenceNumber};

    fn make_saider() -> Saider<'static> {
        MatterBuilder::new()
            .with_code(DigestCode::Blake3_256)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    fn make_prefixer() -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![0u8; 32]))
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

    fn encoded(seal: &Seal) -> String {
        let mut buf = Vec::new();
        seal.encode(&mut buf);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn encode_matches_golden_wire_form_per_variant() {
        let d = to_qb64_string(&make_saider());
        let i = to_qb64_string(&make_prefixer());
        let t = to_qb64_string(&make_verser());

        assert_eq!(
            encoded(&Seal::Digest { d: make_saider() }),
            format!("{{\"d\":\"{d}\"}}")
        );
        assert_eq!(
            encoded(&Seal::Root { rd: make_saider() }),
            format!("{{\"rd\":\"{d}\"}}")
        );
        assert_eq!(
            encoded(&Seal::Source {
                s: SequenceNumber::new(10),
                d: make_saider(),
            }),
            format!("{{\"s\":\"a\",\"d\":\"{d}\"}}"),
            "sequence renders lowercase hex"
        );
        assert_eq!(
            encoded(&Seal::Event {
                i: make_prefixer(),
                s: SequenceNumber::new(1),
                d: make_saider(),
            }),
            format!("{{\"i\":\"{i}\",\"s\":\"1\",\"d\":\"{d}\"}}")
        );
        assert_eq!(
            encoded(&Seal::Last { i: make_prefixer() }),
            format!("{{\"i\":\"{i}\"}}")
        );
        assert_eq!(
            encoded(&Seal::Back {
                bi: make_prefixer(),
                d: make_saider(),
            }),
            format!("{{\"bi\":\"{i}\",\"d\":\"{d}\"}}")
        );
        assert_eq!(
            encoded(&Seal::Kind {
                t: make_verser(),
                d: make_saider(),
            }),
            format!("{{\"t\":\"{t}\",\"d\":\"{d}\"}}")
        );
    }

    #[test]
    fn encode_opaque_splices_verbatim_without_escaping() {
        // `1e2` and the `é` escape are exactly the spellings a
        // serde_json round-trip would normalize away — verbatim splicing
        // must preserve them byte-for-byte.
        let payload = "{\"x\":1e2,\"u\":\"\\u00e9\"}";
        assert_eq!(
            encoded(&Seal::Opaque(OpaqueSeal::new_unchecked(payload))),
            payload
        );
    }

    #[test]
    #[allow(clippy::panic, reason = "panics are expected in test assertions")]
    fn decode_roundtrips_every_encoded_variant() {
        let d = to_qb64_string(&make_saider());
        let i = to_qb64_string(&make_prefixer());
        let t = to_qb64_string(&make_verser());
        let seals = [
            Seal::Digest { d: make_saider() },
            Seal::Root { rd: make_saider() },
            Seal::Source {
                s: SequenceNumber::new(7),
                d: make_saider(),
            },
            Seal::Event {
                i: make_prefixer(),
                s: SequenceNumber::new(1),
                d: make_saider(),
            },
            Seal::Last { i: make_prefixer() },
            Seal::Back {
                bi: make_prefixer(),
                d: make_saider(),
            },
            Seal::Kind {
                t: make_verser(),
                d: make_saider(),
            },
            Seal::Opaque(OpaqueSeal::new_unchecked("{\"app\":[1,2]}")),
        ];
        for seal in &seals {
            let mut buf = Vec::new();
            seal.encode(&mut buf);
            let mut sc = Scanner::new(&buf);
            let parsed = ParsedSeal::decode(&mut sc).unwrap();
            sc.finish().unwrap();
            match (seal, &parsed) {
                (Seal::Digest { .. }, ParsedSeal::Digest { d: pd }) => assert_eq!(*pd, d),
                (Seal::Root { .. }, ParsedSeal::Root { rd }) => assert_eq!(*rd, d),
                (Seal::Source { .. }, ParsedSeal::Source { s, d: pd }) => {
                    assert_eq!(*s, "7");
                    assert_eq!(*pd, d);
                }
                (Seal::Event { .. }, ParsedSeal::Event { i: pi, s, d: pd }) => {
                    assert_eq!(*pi, i);
                    assert_eq!(*s, "1");
                    assert_eq!(*pd, d);
                }
                (Seal::Last { .. }, ParsedSeal::Last { i: pi }) => assert_eq!(*pi, i),
                (Seal::Back { .. }, ParsedSeal::Back { bi, d: pd }) => {
                    assert_eq!(*bi, i);
                    assert_eq!(*pd, d);
                }
                (Seal::Kind { .. }, ParsedSeal::Kind { t: pt, d: pd }) => {
                    assert_eq!(*pt, t);
                    assert_eq!(*pd, d);
                }
                (Seal::Opaque(raw), ParsedSeal::Opaque { raw: praw }) => {
                    assert_eq!(*praw, raw.as_str());
                }
                (_, wrong) => panic!("decoded into the wrong variant: {wrong:?}"),
            }
        }
    }

    #[test]
    fn seal_shapes() {
        assert!(matches!(
            ParsedSeal::decode(&mut Scanner::new(b"{\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Digest { d: "X" }
        ));
        assert!(matches!(
            ParsedSeal::decode(&mut Scanner::new(b"{\"rd\":\"X\"}")).unwrap(),
            ParsedSeal::Root { rd: "X" }
        ));
        assert!(matches!(
            ParsedSeal::decode(&mut Scanner::new(b"{\"s\":\"1\",\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Source { s: "1", d: "X" }
        ));
        assert!(matches!(
            ParsedSeal::decode(&mut Scanner::new(b"{\"i\":\"I\",\"s\":\"1\",\"d\":\"X\"}"))
                .unwrap(),
            ParsedSeal::Event {
                i: "I",
                s: "1",
                d: "X"
            }
        ));
        assert!(matches!(
            ParsedSeal::decode(&mut Scanner::new(b"{\"i\":\"I\"}")).unwrap(),
            ParsedSeal::Last { i: "I" }
        ));
        assert!(matches!(
            ParsedSeal::decode(&mut Scanner::new(b"{\"bi\":\"B\",\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Back { bi: "B", d: "X" }
        ));
        assert!(matches!(
            ParsedSeal::decode(&mut Scanner::new(b"{\"t\":\"T\",\"d\":\"X\"}")).unwrap(),
            ParsedSeal::Kind { t: "T", d: "X" }
        ));
        assert!(
            matches!(
                ParsedSeal::decode(&mut Scanner::new(b"{\"d\":\"X\",\"s\":\"1\"}")).unwrap(),
                ParsedSeal::Opaque {
                    raw: "{\"d\":\"X\",\"s\":\"1\"}"
                }
            ),
            "out-of-order codex fields fall back to a verbatim opaque capture"
        );
        assert!(
            matches!(
                ParsedSeal::decode(&mut Scanner::new(b"{\"x\":\"X\"}")).unwrap(),
                ParsedSeal::Opaque {
                    raw: "{\"x\":\"X\"}"
                }
            ),
            "unknown seal keys fall back to a verbatim opaque capture"
        );
        assert!(
            matches!(
                ParsedSeal::decode(&mut Scanner::new(b"{\"bi\":123}")).unwrap(),
                ParsedSeal::Opaque {
                    raw: "{\"bi\":123}"
                }
            ),
            "a codex key set with a non-string value is a shape mismatch — opaque"
        );
        assert!(
            matches!(
                ParsedSeal::decode(&mut Scanner::new(b"{\"x\":}")),
                Err(SerderError::InvalidAnchor { offset: 0, .. })
            ),
            "a malformed anchor object is rejected, not captured"
        );
    }

    #[test]
    fn truncated_opaque_anchor_is_invalid_anchor() {
        let mut sc = Scanner::new(b"{\"x\":{\"y\":1");
        let err = ParsedSeal::decode(&mut sc).expect_err("truncated anchor must be rejected");
        assert!(matches!(
            err,
            SerderError::InvalidAnchor {
                offset: 0,
                source: OpaqueScanError::Truncated,
            }
        ));
    }

    #[test]
    fn encode_seal_array_is_compact() {
        let d = to_qb64_string(&make_saider());
        let seals = [
            Seal::Digest { d: make_saider() },
            Seal::Last { i: make_prefixer() },
        ];
        let mut buf = Vec::new();
        seals.encode(&mut buf);
        let i = to_qb64_string(&make_prefixer());
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            format!("[{{\"d\":\"{d}\"}},{{\"i\":\"{i}\"}}]")
        );

        let mut empty = Vec::new();
        let none: &[Seal] = &[];
        none.encode(&mut empty);
        assert_eq!(empty, b"[]", "empty anchor array renders as []");
    }
}
