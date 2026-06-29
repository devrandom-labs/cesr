#[cfg(feature = "alloc")]
#[allow(unused_imports, reason = "alloc prelude items; subset used per cfg/feature combination")]
use alloc::{string::String, vec, vec::Vec,};
use alloc::borrow::Cow;
use core::fmt;

use crate::core::indexer::Indexer;
use crate::core::indexer::code::IndexedSigCode;

use super::Verfer;

/// An indexed signature primitive.
///
/// Wraps an [`Indexer`] (which holds the code, index, ondex, and raw signature
/// bytes) and optionally carries the [`Verfer`] (verification key) associated
/// with the signer index.
///
/// Construct a `Siger` by first building an [`Indexer`] via
/// [`IndexerBuilder`](crate::core::indexer::IndexerBuilder), then passing it to
/// [`Siger::new`].
pub struct Siger<'a> {
    indexer: Indexer<'a>,
    verfer: Option<Verfer<'a>>,
}

// -- Manual trait implementations (Matter does not derive Clone/Debug/PartialEq/Eq) --

impl fmt::Debug for Siger<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Siger")
            .field("code", &self.indexer.code())
            .field("index", &self.indexer.index())
            .field("ondex", &self.indexer.ondex())
            .field("raw_len", &self.indexer.raw().len())
            .field("has_verfer", &self.verfer.is_some())
            .finish()
    }
}

impl Clone for Siger<'_> {
    fn clone(&self) -> Self {
        let cloned_verfer = self.verfer.as_ref().map(|v| {
            crate::core::matter::matter::Matter::new(
                *v.code(),
                Cow::Owned(v.raw().to_vec()),
                Cow::Owned(String::from(v.soft())),
            )
        });
        Self {
            indexer: self.indexer.clone(),
            verfer: cloned_verfer,
        }
    }
}

impl PartialEq for Siger<'_> {
    fn eq(&self, other: &Self) -> bool {
        if self.indexer != other.indexer {
            return false;
        }
        match (&self.verfer, &other.verfer) {
            (None, None) => true,
            (Some(a), Some(b)) => a.code() == b.code() && a.raw() == b.raw(),
            _ => false,
        }
    }
}

impl Eq for Siger<'_> {}

impl<'a> Siger<'a> {
    /// Creates a new `Siger` from an `Indexer`, with no attached verfer.
    #[must_use]
    pub const fn new(indexer: Indexer<'a>) -> Self {
        Self {
            indexer,
            verfer: None,
        }
    }

    /// Builder method: attaches a [`Verfer`] (verification key) to this siger.
    #[must_use]
    pub fn with_verfer(mut self, verfer: Verfer<'a>) -> Self {
        self.verfer = Some(verfer);
        self
    }

    /// Returns the CESR indexed signature code.
    #[must_use]
    pub const fn code(&self) -> IndexedSigCode {
        self.indexer.code()
    }

    /// Returns the signer's index in the key list.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.indexer.index()
    }

    /// Returns the "other index" (prior-next key list index), if present.
    #[must_use]
    pub const fn ondex(&self) -> Option<u32> {
        self.indexer.ondex()
    }

    /// Returns the raw signature bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.indexer.raw()
    }

    /// Returns a reference to the attached verfer, if any.
    #[must_use]
    pub const fn verfer(&self) -> Option<&Verfer<'a>> {
        self.verfer.as_ref()
    }

    /// Returns the full CESR-encoded size in characters.
    #[must_use]
    pub fn full_size(&self) -> usize {
        self.indexer.full_size()
    }

    /// Encodes this indexed signature into its qualified Base64 (qb64) CESR
    /// wire format.
    #[must_use]
    pub fn to_qb64(&self) -> String {
        self.indexer.to_qb64()
    }

    /// Encodes this indexed signature into its qualified binary (qb2) CESR
    /// wire format.
    #[must_use]
    pub fn to_qb2(&self) -> Vec<u8> {
        self.indexer.to_qb2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::indexer::IndexerBuilder;
    use crate::core::indexer::code::IndexedSigCode;
    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::VerKeyCode;

    /// Helper: build an Ed25519 Indexer with the given index and raw bytes.
    fn ed25519_indexer(index: u32, raw: &[u8]) -> Indexer<'_> {
        IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(index)
            .unwrap()
            .with_raw(raw)
            .unwrap()
    }

    /// Helper: build an Ed25519 Verfer from 32 bytes.
    fn ed25519_verfer(key_bytes: &[u8; 32]) -> Verfer<'_> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::Borrowed(key_bytes.as_slice()))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn siger_delegates_to_indexer() {
        let raw = [0xAB_u8; 64];
        let indexer = ed25519_indexer(3, &raw);
        let siger = Siger::new(indexer);

        assert_eq!(siger.code(), IndexedSigCode::Ed25519);
        assert_eq!(siger.index(), 3);
        assert_eq!(siger.ondex(), Some(3));
        assert_eq!(siger.raw(), &raw);
    }

    #[test]
    fn siger_with_verfer_attached() {
        let sig_bytes = [0u8; 64];
        let key_bytes = [0u8; 32];

        let indexer = ed25519_indexer(0, &sig_bytes);
        let verfer = ed25519_verfer(&key_bytes);

        let siger = Siger::new(indexer).with_verfer(verfer);

        assert!(siger.verfer().is_some());
        let v = siger.verfer().unwrap();
        assert_eq!(*v.code(), VerKeyCode::Ed25519);
        assert_eq!(v.raw(), &key_bytes);
    }

    #[test]
    fn verfer_returns_none_when_absent() {
        let indexer = ed25519_indexer(0, &[0u8; 64]);
        let siger = Siger::new(indexer);
        assert!(siger.verfer().is_none());
    }

    #[test]
    fn to_qb64_delegation_returns_correct_size() {
        let indexer = ed25519_indexer(0, &[0u8; 64]);
        let siger = Siger::new(indexer);
        let qb64 = siger.to_qb64();
        // Ed25519 indexed sig qb64 is always 88 characters.
        assert_eq!(qb64.len(), 88);
    }

    #[test]
    fn full_size_delegation() {
        let indexer = ed25519_indexer(0, &[0u8; 64]);
        let siger = Siger::new(indexer);
        assert_eq!(siger.full_size(), 88);
    }

    #[test]
    fn owned_siger_is_static() {
        let sig_bytes = vec![0xCDu8; 64];
        let key_bytes = [0xEFu8; 32];

        // Pass owned data → Indexer<'static> naturally via Cow
        let indexer: Indexer<'static> = IndexerBuilder::new()
            .with_code(IndexedSigCode::Ed25519)
            .with_index(5)
            .unwrap()
            .with_raw(sig_bytes)
            .unwrap();

        let verfer: Verfer<'static> = MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(key_bytes.to_vec())
            .unwrap()
            .build()
            .unwrap();

        let siger: Siger<'static> = Siger::new(indexer).with_verfer(verfer);

        assert_eq!(siger.code(), IndexedSigCode::Ed25519);
        assert_eq!(siger.index(), 5);
        assert_eq!(siger.raw(), &[0xCD; 64]);
        assert!(siger.verfer().is_some());
        assert_eq!(siger.verfer().unwrap().raw(), &[0xEF; 32]);
    }

    #[test]
    fn to_qb2_delegation() {
        let indexer = ed25519_indexer(0, &[0u8; 64]);
        let siger = Siger::new(indexer);
        let qb2 = siger.to_qb2();
        // qb2 length = qb64 length * 3 / 4 = 88 * 3 / 4 = 66
        assert_eq!(qb2.len(), 66);
    }

    #[test]
    fn clone_preserves_all_fields() {
        let indexer = ed25519_indexer(2, &[0u8; 64]);
        let verfer = ed25519_verfer(&[0u8; 32]);
        let siger = Siger::new(indexer).with_verfer(verfer);
        let cloned = siger.clone();
        assert_eq!(siger, cloned);
    }
}
