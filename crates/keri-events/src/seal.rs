#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::Cow, string::String, vec, vec::Vec};
use cesr::core::primitives::{Prefixer, Saider, Verser};

use crate::sequence::SequenceNumber;

/// Anchoring seals that bind events to external data.
pub enum Seal<'a> {
    /// Digest seal — anchors a single hash.
    Digest {
        /// The digest value.
        d: Saider<'a>,
    },
    /// Root seal — anchors a Merkle tree root.
    Root {
        /// The root digest.
        rd: Saider<'a>,
    },
    /// Source seal — references a prior event by sequence number and digest.
    Source {
        /// Sequence number of the source event.
        s: SequenceNumber,
        /// Digest of the source event.
        d: Saider<'a>,
    },
    /// Event seal — fully identifies an event by prefix, sequence number, and digest.
    Event {
        /// Prefix of the identifier.
        i: Prefixer<'a>,
        /// Sequence number of the event.
        s: SequenceNumber,
        /// Digest of the event.
        d: Saider<'a>,
    },
    /// Last-event seal — references the latest event for a given prefix.
    Last {
        /// Prefix of the identifier.
        i: Prefixer<'a>,
    },
    /// Registrar-backer seal — nontransferable backer prefix plus a digest
    /// of the anchored backer metadata (keripy `SealBack`).
    Back {
        /// Backer identifier prefix.
        bi: Prefixer<'a>,
        /// Digest of the anchored backer metadata.
        d: Saider<'a>,
    },
    /// Typed digest seal — a version/type tag plus a SAID (keripy `SealKind`).
    Kind {
        /// Type of the digest.
        t: Verser<'a>,
        /// The digest value.
        d: Saider<'a>,
    },
    /// A non-codex anchor preserved verbatim.
    Opaque(OpaqueSeal<'a>),
}

impl Seal<'_> {
    /// Detach from the source buffer by owning every contained primitive.
    #[must_use]
    pub fn into_static(self) -> Seal<'static> {
        match self {
            Self::Digest { d } => Seal::Digest { d: d.into_static() },
            Self::Root { rd } => Seal::Root {
                rd: rd.into_static(),
            },
            Self::Source { s, d } => Seal::Source {
                s,
                d: d.into_static(),
            },
            Self::Event { i, s, d } => Seal::Event {
                i: i.into_static(),
                s,
                d: d.into_static(),
            },
            Self::Last { i } => Seal::Last { i: i.into_static() },
            Self::Back { bi, d } => Seal::Back {
                bi: bi.into_static(),
                d: d.into_static(),
            },
            Self::Kind { t, d } => Seal::Kind {
                t: t.into_static(),
                d: d.into_static(),
            },
            Self::Opaque(raw) => Seal::Opaque(raw.into_static()),
        }
    }
}

/// A non-codex anchor: an arbitrary compact-JSON object preserved verbatim.
///
/// keripy validates event anchors (`data`) only as being a list — the dicts
/// inside are arbitrary. This type carries such an anchor through cesr
/// unmodified: the JSON writer re-emits the stored text byte-for-byte, so
/// decode → encode round-trips keripy events exactly.
///
/// The payload must be one well-formed *compact* JSON object (no whitespace
/// between tokens — the form keripy's canonical
/// `json.dumps(..., separators=(",", ":"))` emits). This crate stores the
/// payload verbatim and does not itself parse JSON; the invariant is enforced
/// by `keri-codec` on the read path (its `OpaqueScan` boundary check), #193 P3.
#[derive(Debug, Clone)]
pub struct OpaqueSeal<'a>(Cow<'a, str>);

impl<'a> OpaqueSeal<'a> {
    /// Wrap a payload verbatim, WITHOUT validation.
    ///
    /// The caller guarantees `raw` is exactly one well-formed compact JSON
    /// object. `keri-codec` enforces this on the read path via its `OpaqueScan`
    /// boundary check; this crate is pure data and never originates opaque
    /// payloads. Mirrors every other event type here: a dumb constructor,
    /// with validation living in the codec (#193 P3).
    #[must_use]
    pub fn new_unchecked(raw: impl Into<Cow<'a, str>>) -> Self {
        Self(raw.into())
    }

    /// The verbatim JSON object text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Detach from the source buffer by owning the payload.
    #[must_use]
    pub fn into_static(self) -> OpaqueSeal<'static> {
        OpaqueSeal(Cow::Owned(self.0.into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::borrow::Cow;
    use alloc::borrow::ToOwned;
    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::{DigestCode, VerKeyCode, VerserCode};

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

    #[test]
    fn seal_digest() {
        let Seal::Digest { d } = (Seal::Digest { d: make_saider() }) else {
            unreachable!()
        };
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_root() {
        let Seal::Root { rd } = (Seal::Root { rd: make_saider() }) else {
            unreachable!()
        };
        assert_eq!(*rd.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_source() {
        let Seal::Source { s, d } = (Seal::Source {
            s: SequenceNumber::new(0),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(s.value(), 0);
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_event() {
        let Seal::Event { i, s, d } = (Seal::Event {
            i: make_prefixer(),
            s: SequenceNumber::new(1),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*i.code(), VerKeyCode::Ed25519);
        assert_eq!(s.value(), 1);
        assert_eq!(*d.code(), DigestCode::Blake3_256);
    }

    #[test]
    fn seal_last() {
        let Seal::Last { i } = (Seal::Last { i: make_prefixer() }) else {
            unreachable!()
        };
        assert_eq!(*i.code(), VerKeyCode::Ed25519);
    }

    #[test]
    fn seal_is_send_sync_static() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Seal<'static>>();
        assert_send_sync_static::<OpaqueSeal<'static>>();
    }

    /// Compile-time probe: `Seal` must stay covariant in its lifetime — a
    /// longer-lived seal coerces to a shorter one. If a future field makes
    /// it invariant (e.g. a `Cow<'a, [T<'a>]>` — see the rung-6 spec
    /// amendment), this stops compiling.
    #[test]
    fn seal_is_covariant() {
        fn coerce<'short>(s: &'short Seal<'static>) -> &'short Seal<'short> {
            s
        }
        let seal = Seal::Last { i: make_prefixer() };
        let _ = coerce(&seal);
    }

    #[test]
    fn opaque_new_unchecked_stores_verbatim() {
        // OpaqueSeal is pure verbatim data: `new_unchecked` performs no
        // validation (keri-codec's `OpaqueScan` owns compact-JSON validation
        // on the read path, #193 P3). The wrapper's contract is to store and
        // return the bytes unchanged and to detach cleanly to 'static.
        let raw = "{\"a\":\"b\",\"c\":[1,2,3]}";

        let borrowed = OpaqueSeal::new_unchecked(raw);
        assert_eq!(borrowed.as_str(), raw);

        let owned: OpaqueSeal<'static> = OpaqueSeal::new_unchecked(raw.to_owned());
        assert_eq!(owned.as_str(), raw);

        // Detaching preserves the exact bytes.
        assert_eq!(OpaqueSeal::new_unchecked(raw).into_static().as_str(), raw);
    }

    #[test]
    fn seal_back_and_kind_carry_typed_fields() {
        let Seal::Back { bi, d } = (Seal::Back {
            bi: make_prefixer(),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*bi.code(), VerKeyCode::Ed25519);
        assert_eq!(*d.code(), DigestCode::Blake3_256);

        let Seal::Kind { t, d: kind_digest } = (Seal::Kind {
            t: make_verser(),
            d: make_saider(),
        }) else {
            unreachable!()
        };
        assert_eq!(*t.code(), VerserCode::Tag7);
        assert_eq!(*kind_digest.code(), DigestCode::Blake3_256);
    }
}
