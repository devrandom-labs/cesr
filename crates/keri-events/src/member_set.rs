//! Static membership laws for witness and backer identifier lists.
//!
//! These checks need no state: builders, typed wire decoders, and validating
//! folds use the same predicates. Cut membership and additions relative to a
//! prior set remain transition rules.

use crate::BasicPrefix;

/// Static membership checks shared by event builders, decoders, and folds.
pub struct MemberSet;

/// A malformed witness or backer identity list.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MemberSetError {
    /// The same qualified identifier occurs twice in one list.
    #[error("{set} contains a duplicate identifier")]
    Duplicate {
        /// The offending list.
        set: &'static str,
    },
    /// Witness identities must directly encode their fixed verifying key.
    #[error("{set} contains a transferable witness identifier")]
    TransferableWitness {
        /// The offending list.
        set: &'static str,
    },
    /// A cut cannot also be introduced as an addition in the same rotation.
    #[error("{cuts} and {additions} overlap")]
    CutAddOverlap {
        /// Name of the cuts list.
        cuts: &'static str,
        /// Name of the additions list.
        additions: &'static str,
    },
}

impl MemberSet {
    /// Require distinct identifiers, preserving their order.
    ///
    /// # Errors
    ///
    /// Returns [`MemberSetError::Duplicate`] for an invalid list.
    pub fn check_members(
        members: &[BasicPrefix<'_>],
        set: &'static str,
    ) -> Result<(), MemberSetError> {
        for (index, member) in members.iter().enumerate() {
            if members[..index].contains(member) {
                return Err(MemberSetError::Duplicate { set });
            }
        }
        Ok(())
    }

    /// Require distinct nontransferable witness identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`MemberSetError::Duplicate`] or
    /// [`MemberSetError::TransferableWitness`].
    pub fn check_witnesses(
        witnesses: &[BasicPrefix<'_>],
        set: &'static str,
    ) -> Result<(), MemberSetError> {
        Self::check_members(witnesses, set)?;
        if witnesses
            .iter()
            .any(|witness| witness.code().is_transferable())
        {
            return Err(MemberSetError::TransferableWitness { set });
        }
        Ok(())
    }

    /// Require individually valid, disjoint cut and addition lists.
    ///
    /// # Errors
    ///
    /// Returns a [`MemberSetError`] when either list contains duplicates or a
    /// member appears in both lists.
    pub fn check_deltas(
        cuts: &[BasicPrefix<'_>],
        additions: &[BasicPrefix<'_>],
        cut_label: &'static str,
        addition_label: &'static str,
    ) -> Result<(), MemberSetError> {
        Self::check_members(cuts, cut_label)?;
        Self::check_members(additions, addition_label)?;
        if cuts.iter().any(|cut| additions.contains(cut)) {
            return Err(MemberSetError::CutAddOverlap {
                cuts: cut_label,
                additions: addition_label,
            });
        }
        Ok(())
    }

    /// Require distinct, disjoint, nontransferable witness deltas.
    ///
    /// # Errors
    ///
    /// Returns a [`MemberSetError`] when the static witness rules fail.
    pub fn check_witness_deltas(
        cuts: &[BasicPrefix<'_>],
        additions: &[BasicPrefix<'_>],
        cut_label: &'static str,
        addition_label: &'static str,
    ) -> Result<(), MemberSetError> {
        Self::check_deltas(cuts, additions, cut_label, addition_label)?;
        Self::check_witnesses(cuts, cut_label)?;
        Self::check_witnesses(additions, addition_label)
    }
}
