use crate::core::primitives::{Prefixer, Saider, Seqner};
#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::vec;

/// Anchoring seals that bind events to external data.
pub enum Seal {
    /// Digest seal — anchors a single hash.
    Digest {
        /// The digest value.
        d: Saider<'static>,
    },
    /// Root seal — anchors a Merkle tree root.
    Root {
        /// The root digest.
        rd: Saider<'static>,
    },
    /// Source seal — references a prior event by sequence number and digest.
    Source {
        /// Sequence number of the source event.
        s: Seqner,
        /// Digest of the source event.
        d: Saider<'static>,
    },
    /// Event seal — fully identifies an event by prefix, sequence number, and digest.
    Event {
        /// Prefix of the identifier.
        i: Prefixer<'static>,
        /// Sequence number of the event.
        s: Seqner,
        /// Digest of the event.
        d: Saider<'static>,
    },
    /// Last-event seal — references the latest event for a given prefix.
    Last {
        /// Prefix of the identifier.
        i: Prefixer<'static>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::{DigestCode, VerKeyCode};
    use alloc::borrow::Cow;

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
            s: Seqner::new(0),
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
            s: Seqner::new(1),
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
        assert_send_sync_static::<Seal>();
    }
}
