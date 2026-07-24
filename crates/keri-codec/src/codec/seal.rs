//! The seal wire grammar — both directions in one place.
//!
//! Each `Seal` variant's write form lives in [`Encode`]; the matching read
//! form joins as `ParsedSeal`'s [`Decode`](crate::codec::Decode) (#193
//! step-2 task 3), keeping the grammar stated once per direction, adjacent.

#[cfg(feature = "alloc")]
use alloc::{string::ToString, vec::Vec};
use core::str;

use crate::codec::event::ParsedSeal;
use crate::codec::field::{Field, FromWire};
use crate::codec::scanner::Scanner;
use crate::codec::{Decode, Encode, JsonWriter};
use crate::deserialize::opaque_scan::OpaqueScan;
use crate::error::DeserializeError;
use keri_events::{OpaqueSeal, Seal};

impl Encode for Seal<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Seal::Digest { d } => {
                out.extend_from_slice(b"{\"d\":");
                d.encode(out);
                out.push(b'}');
            }
            Seal::Root { rd } => {
                out.extend_from_slice(b"{\"rd\":");
                rd.encode(out);
                out.push(b'}');
            }
            Seal::Source { s, d } => {
                out.extend_from_slice(b"{\"s\":");
                JsonWriter::write_str(out, &s.to_string());
                out.extend_from_slice(b",\"d\":");
                d.encode(out);
                out.push(b'}');
            }
            Seal::Event { i, s, d } => {
                out.extend_from_slice(b"{\"i\":");
                i.encode(out);
                out.extend_from_slice(b",\"s\":");
                JsonWriter::write_str(out, &s.to_string());
                out.extend_from_slice(b",\"d\":");
                d.encode(out);
                out.push(b'}');
            }
            Seal::Last { i } => {
                out.extend_from_slice(b"{\"i\":");
                i.encode(out);
                out.push(b'}');
            }
            Seal::Back { bi, d } => {
                out.extend_from_slice(b"{\"bi\":");
                bi.encode(out);
                out.extend_from_slice(b",\"d\":");
                d.encode(out);
                out.push(b'}');
            }
            Seal::Kind { t, d } => {
                out.extend_from_slice(b"{\"t\":");
                t.encode(out);
                out.extend_from_slice(b",\"d\":");
                d.encode(out);
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

// Lift a scanned seal view into the domain `Seal` (was `seal_from_parsed`).
// Each inner qb64/hex field lifts via the `Field` pipeline, keyed by the
// target field type (`Saider`/`Prefixer`/`Verser`/`SequenceNumber`, all
// `Matter<C>` aliases bar `SequenceNumber`). `ParsedSeal` is `Copy`, so it is
// taken by value.
impl<'a> FromWire<ParsedSeal<'a>> for Seal<'a> {
    fn from_wire(field: &'static str, seal: ParsedSeal<'a>) -> Result<Self, DeserializeError> {
        // A seal has no single outer field: each inner primitive is tagged with
        // its own JSON key ("d"/"i"/…) via the nested `Field::new` lifts below,
        // matching the legacy `seal_from_parsed` (which took no outer field).
        let _ = field;
        match seal {
            ParsedSeal::Digest { d } => Ok(Seal::Digest {
                d: Field::new("d", d).decode()?,
            }),
            ParsedSeal::Root { rd } => Ok(Seal::Root {
                rd: Field::new("rd", rd).decode()?,
            }),
            ParsedSeal::Source { s, d } => Ok(Seal::Source {
                s: Field::new("s", s).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            ParsedSeal::Event { i, s, d } => Ok(Seal::Event {
                i: Field::new("i", i).decode()?,
                s: Field::new("s", s).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            ParsedSeal::Last { i } => Ok(Seal::Last {
                i: Field::new("i", i).decode()?,
            }),
            ParsedSeal::Back { bi, d } => Ok(Seal::Back {
                bi: Field::new("bi", bi).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            ParsedSeal::Kind { t, d } => Ok(Seal::Kind {
                t: Field::new("t", t).decode()?,
                d: Field::new("d", d).decode()?,
            }),
            // The scanner (`ParsedSeal::decode`'s opaque path →
            // `OpaqueScan::object_len`) already proved the span is one
            // well-formed compact object, so wrapping it is a verbatim,
            // infallible move — no re-validation (#193 P3).
            ParsedSeal::Opaque { raw } => Ok(Seal::Opaque(OpaqueSeal::new_unchecked(raw))),
        }
    }
}

impl<'a> Decode<'a> for ParsedSeal<'a> {
    /// One seal object: the seven codex shapes parse typed; anything else
    /// falls back to a verbatim opaque capture of the whole object. A codex
    /// parse failure rewinds — the codex attempt and the opaque scan both
    /// start from the object's first byte.
    fn decode(sc: &mut Scanner<'a>) -> Result<Self, DeserializeError> {
        let start = sc.pos;
        // The codex error is deliberately superseded: the opaque scan is the
        // outermost interpretation and produces its own typed error on failure.
        if let Ok(parsed) = Self::codex(sc) {
            return Ok(parsed);
        }
        sc.pos = start;
        Self::opaque(sc)
    }
}

impl<'a> ParsedSeal<'a> {
    /// The seven fixed codex shapes, dispatched on the first key. Field order
    /// per variant is fixed (matches the writer and keripy's namedtuple
    /// serialization order). The `"i"` key is shared by `Last` (closes
    /// immediately) and `Event` (continues with `"s"`/`"d"`) — the chain order
    /// is grammar, not style.
    fn codex(sc: &mut Scanner<'a>) -> Result<Self, DeserializeError> {
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
}

impl<'a> ParsedSeal<'a> {
    /// Capture a non-codex anchor object verbatim.
    fn opaque(sc: &mut Scanner<'a>) -> Result<Self, DeserializeError> {
        let start = sc.pos;
        let rest = sc
            .input
            .get(start..)
            .ok_or(DeserializeError::InvalidEventLayout(
                "anchor span out of bounds",
            ))?;
        let len =
            OpaqueScan::object_len(rest).map_err(|source| DeserializeError::InvalidAnchor {
                offset: start,
                source,
            })?;
        let end = start
            .checked_add(len)
            .ok_or(DeserializeError::InvalidEventLayout("anchor span overflow"))?;
        let bytes = sc
            .input
            .get(start..end)
            .ok_or(DeserializeError::InvalidEventLayout(
                "anchor span out of bounds",
            ))?;
        let raw = str::from_utf8(bytes).map_err(|e| {
            start.checked_add(e.valid_up_to()).map_or(
                DeserializeError::InvalidEventLayout("UTF-8 error offset overflow"),
                |offset| sc.err_at(offset, "UTF-8 anchor object"),
            )
        })?;
        sc.pos = end;
        Ok(ParsedSeal::Opaque { raw })
    }
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
        let d = make_saider().to_qb64();
        let i = make_prefixer().to_qb64();
        let t = make_verser().to_qb64();

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
    fn seal_lift_digest_variant() {
        let d = make_saider().to_qb64();
        let parsed = ParsedSeal::Digest { d: d.as_str() };
        let seal: Seal = Field::new("a", parsed).decode().unwrap();
        let Seal::Digest { d: lifted } = seal else {
            unreachable!("a Digest parsed-seal lifts to Seal::Digest");
        };
        assert_eq!(*lifted.code(), DigestCode::Blake3_256);
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
        let d = make_saider().to_qb64();
        let i = make_prefixer().to_qb64();
        let t = make_verser().to_qb64();
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
                Err(DeserializeError::InvalidAnchor { offset: 0, .. })
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
            DeserializeError::InvalidAnchor {
                offset: 0,
                source: OpaqueScanError::Truncated,
            }
        ));
    }

    #[test]
    fn encode_seal_array_is_compact() {
        let d = make_saider().to_qb64();
        let seals = [
            Seal::Digest { d: make_saider() },
            Seal::Last { i: make_prefixer() },
        ];
        let mut buf = Vec::new();
        seals.encode(&mut buf);
        let i = make_prefixer().to_qb64();
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
