//! Shared borrowed-key and exact-wire-signature authentication for the folds.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use cesr::core::primitives::{Siger, Verfer};
use cesr::crypto::verify;
use keri_events::{BasicPrefix, SigningThreshold, VerifyingKey};

use crate::error::Rejection;

/// Wire identity ignores the optional local verifier attached to a `Siger`.
/// Index and ondex are both material: a different signature at the same
/// current index can verify or expose another prior-next commitment.
type WireSignature<'a> = (&'static str, u32, Option<u32>, &'a [u8]);

/// The common one-signature or identical-repeat case stays stack-only; a
/// balanced set is allocated only when a second distinct wire value arrives.
#[derive(Default)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling folds share private deduplication state without exposing a public API"
)]
pub(crate) struct SeenWireSignatures<'a> {
    first: Option<WireSignature<'a>>,
    rest: Option<BTreeSet<WireSignature<'a>>>,
}

impl<'a> SeenWireSignatures<'a> {
    #[allow(
        clippy::redundant_pub_crate,
        reason = "sibling folds need one exact-material deduplication rule without a public API"
    )]
    pub(crate) fn insert(&mut self, sig: &'a Siger<'_>) -> bool {
        let wire = (sig.code().as_str(), sig.index(), sig.ondex(), sig.raw());
        if self.first == Some(wire) {
            return false;
        }
        if self.first.is_none() {
            self.first = Some(wire);
            return true;
        }
        self.rest.get_or_insert_with(BTreeSet::new).insert(wire)
    }
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling folds share this private-module key adapter without exposing a public API"
)]
pub(crate) trait VerifierKey {
    fn as_verfer(&self) -> &Verfer<'_>;
}

impl VerifierKey for VerifyingKey<'_> {
    fn as_verfer(&self) -> &Verfer<'_> {
        self.as_matter()
    }
}

impl VerifierKey for BasicPrefix<'_> {
    fn as_verfer(&self) -> &Verfer<'_> {
        self.as_matter()
    }
}

/// Shared authentication work; associated methods respect the free-function ratchet.
#[allow(
    clippy::redundant_pub_crate,
    reason = "sibling folds share this private-module helper without exposing a public API"
)]
pub(crate) struct Verifier;

impl Verifier {
    /// Shared controller/backer judgment over borrowed role-wrapped key material.
    #[allow(
        clippy::redundant_pub_crate,
        reason = "sibling folds need one borrowed-key verifier without a public API"
    )]
    pub(crate) fn with_keys<'s, K: VerifierKey>(
        keys: &[K],
        threshold: &SigningThreshold,
        bytes: &[u8],
        sigs: &'s [Siger<'s>],
    ) -> Result<Vec<&'s Siger<'s>>, Rejection> {
        let mut seen = SeenWireSignatures::default();
        let mut indices = Vec::new();
        let mut valid = Vec::new();
        for sig in sigs {
            if !seen.insert(sig) {
                continue;
            }
            let Some(key) = usize::try_from(sig.index())
                .ok()
                .and_then(|position| keys.get(position))
            else {
                continue;
            };
            if verify(key.as_verfer(), bytes, sig).is_ok() {
                indices.push(sig.index());
                valid.push(sig);
            }
        }
        indices.sort_unstable();
        indices.dedup();
        let verified = indices.len();
        if threshold.satisfied_by_sorted_unique(&indices) {
            Ok(valid)
        } else {
            Err(Rejection::MissingSignatures { verified })
        }
    }
}
