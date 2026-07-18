//! The seal wire grammar — both directions in one place.
//!
//! Each `Seal` variant's write form lives in [`Encode`]; the matching read
//! form joins as `ParsedSeal`'s [`Decode`](crate::codec::Decode) (#193
//! step-2 task 3), keeping the grammar stated once per direction, adjacent.

#[cfg(feature = "alloc")]
use alloc::{string::ToString, vec::Vec};

use crate::codec::{Encode, JsonWriter};
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

#[cfg(test)]
mod tests {
    use super::*;
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
