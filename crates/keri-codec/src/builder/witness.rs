//! Witness-set validation shared by the establishment-event builders.
//!
//! Port of keripy's witness preconditions in `incept()` (`eventing.py:625-641`)
//! and `rotate()` (`eventing.py:789-831`), keripy `de59bc7d`: duplicate-free
//! witness lists and rotation cut/add set relations against the prior
//! witness set. TOAD bounds are enforced by [`keri_events::toad::Toad`].

#[cfg(all(feature = "alloc", test))]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::SerderError;
use cesr::core::primitives::Prefixer;
use keri_events::toad::Toad;

/// Witness configuration for an inception-family establishment event
/// (`icp`, `dip`): the witness set (`b`) and the optional explicit witness
/// threshold (`bt`, keripy `toad`).
pub(super) struct WitnessConfiguration {
    pub(super) witnesses: Vec<Prefixer<'static>>,
    pub(super) threshold: Option<u32>,
}

impl WitnessConfiguration {
    /// Starts an empty witness configuration (keripy's `incept()` defaults:
    /// no witnesses, `toad` derived).
    pub(super) const fn new() -> Self {
        Self {
            witnesses: Vec::new(),
            threshold: None,
        }
    }

    /// keripy's `incept()` witness prologue: a duplicate-free witness set,
    /// then the threshold resolved against it. Returns the witness set with
    /// its resolved threshold.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::DuplicatePrefixes`] on a duplicate witness or
    /// [`SerderError::Toad`] on an out-of-bounds threshold.
    pub(super) fn validate(self) -> Result<(Vec<Prefixer<'static>>, Toad), SerderError> {
        validate_distinct(&self.witnesses, "witnesses")?;
        let threshold = resolve_witness_threshold(self.threshold, self.witnesses.len())?;
        Ok((self.witnesses, threshold))
    }
}

/// Witness rotation for a rotation-family establishment event (`rot`,
/// `drt`): the prior witness set the removals (`br`) and additions (`ba`)
/// rotate, and the optional explicit witness threshold (`bt`).
pub(super) struct WitnessRotation {
    pub(super) prior: Vec<Prefixer<'static>>,
    pub(super) removals: Vec<Prefixer<'static>>,
    pub(super) additions: Vec<Prefixer<'static>>,
    pub(super) threshold: Option<u32>,
}

impl WitnessRotation {
    /// Starts a witness rotation against the given prior witness set, with
    /// no removals or additions and a derived threshold.
    pub(super) const fn new(prior: Vec<Prefixer<'static>>) -> Self {
        Self {
            prior,
            removals: Vec::new(),
            additions: Vec::new(),
            threshold: None,
        }
    }

    /// keripy's `rotate()` witness prologue: the cut/add set relations
    /// checked against the prior witness set, then the threshold resolved
    /// against the post-rotation witness count.
    ///
    /// # Errors
    ///
    /// Returns [`SerderError::DuplicatePrefixes`],
    /// [`SerderError::CutNotPriorWitness`],
    /// [`SerderError::AddAlreadyWitness`], or [`SerderError::CutAddOverlap`]
    /// on a broken set relation, and [`SerderError::Toad`] on an
    /// out-of-bounds threshold.
    pub(super) fn validate(self) -> Result<RotatedWitnesses, SerderError> {
        let witness_count =
            validate_rotation_witnesses(&self.prior, &self.removals, &self.additions)?;
        let threshold = resolve_witness_threshold(self.threshold, witness_count)?;
        Ok(RotatedWitnesses {
            removals: self.removals,
            additions: self.additions,
            threshold,
        })
    }
}

/// A validated witness rotation: the removals (`br`) and additions (`ba`)
/// the event serializes, and the resolved post-rotation witness threshold
/// (`bt`).
pub(super) struct RotatedWitnesses {
    pub(super) removals: Vec<Prefixer<'static>>,
    pub(super) additions: Vec<Prefixer<'static>>,
    pub(super) threshold: Toad,
}

/// Resolves the witness threshold (KERI `toad`): an explicit value is
/// bounds-checked against the effective witness count, an absent one
/// defaults to keripy's `ample`.
fn resolve_witness_threshold(
    explicit: Option<u32>,
    witness_count: usize,
) -> Result<Toad, SerderError> {
    let threshold = match explicit {
        Some(value) => Toad::exact(value, witness_count)?,
        None => Toad::ample(witness_count)?,
    };
    Ok(threshold)
}

/// Rejects duplicate prefixes, mirroring keripy's
/// `len(oset(x)) != len(x)` checks. `label` names the offending field.
pub(super) fn validate_distinct(
    prefixes: &[Prefixer<'static>],
    label: &'static str,
) -> Result<(), SerderError> {
    prefixes
        .iter()
        .enumerate()
        .all(|(i, prefix)| !contains(&prefixes[..i], prefix))
        .then_some(())
        .ok_or(SerderError::DuplicatePrefixes(label))
}

fn contains(set: &[Prefixer<'static>], prefix: &Prefixer<'static>) -> bool {
    set.iter().any(|member| member == prefix)
}

/// Validates a rotation's witness configuration against the prior witness
/// set — keripy's check order: duplicate-free prior/cuts, `cuts ⊆ prior`,
/// duplicate-free adds, `adds ∩ prior = ∅`, `cuts ∩ adds = ∅` — and returns
/// the post-rotation witness count `|(prior − cuts) ∪ adds|`.
///
/// keripy's final size check (`len(newitset) != len(wits) - len(cuts) +
/// len(adds)`, marked `# redundant?` in its own source) is provably implied
/// by these relations and is not ported: distinct cuts drawn from `prior`
/// remove exactly `len(cuts)` members and distinct adds disjoint from both
/// contribute exactly `len(adds)`.
///
/// The `cuts ∩ adds = ∅` branch is likewise unreachable given the earlier
/// checks — `cuts ⊆ prior` and `adds ∩ prior = ∅` already imply the
/// disjointness — but it is kept for keripy check-order parity (keripy
/// carries the same latent redundancy).
pub(super) fn validate_rotation_witnesses(
    prior: &[Prefixer<'static>],
    cuts: &[Prefixer<'static>],
    adds: &[Prefixer<'static>],
) -> Result<usize, SerderError> {
    validate_distinct(prior, "prior witnesses")?;
    validate_distinct(cuts, "witness removals")?;
    if !cuts.iter().all(|cut| contains(prior, cut)) {
        return Err(SerderError::CutNotPriorWitness);
    }
    validate_distinct(adds, "witness additions")?;
    if adds.iter().any(|add| contains(prior, add)) {
        return Err(SerderError::AddAlreadyWitness);
    }
    if cuts.iter().any(|cut| contains(adds, cut)) {
        return Err(SerderError::CutAddOverlap);
    }
    let kept = prior.iter().filter(|wit| !contains(cuts, wit)).count();
    kept.checked_add(adds.len())
        .ok_or(SerderError::WitnessCountOverflow)
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use cesr::core::matter::builder::MatterBuilder;
    use cesr::core::matter::code::VerKeyCode;

    use super::*;

    fn prefixer(tag: u8) -> Prefixer<'static> {
        MatterBuilder::new()
            .with_code(VerKeyCode::Ed25519)
            .with_raw(Cow::<[u8]>::Owned(vec![tag; 32]))
            .unwrap()
            .build()
            .unwrap()
    }

    #[test]
    fn distinct_accepts_empty_single_and_distinct() {
        assert!(validate_distinct(&[], "wits").is_ok());
        assert!(validate_distinct(&[prefixer(1)], "wits").is_ok());
        assert!(validate_distinct(&[prefixer(1), prefixer(2)], "wits").is_ok());
    }

    #[test]
    fn distinct_rejects_duplicates_with_label() {
        let result = validate_distinct(&[prefixer(1), prefixer(2), prefixer(1)], "prior witnesses");
        assert!(matches!(
            result,
            Err(SerderError::DuplicatePrefixes("prior witnesses"))
        ));
    }

    #[test]
    fn rotation_count_is_prior_minus_cuts_plus_adds() {
        let prior = [prefixer(1), prefixer(2), prefixer(3), prefixer(4)];
        let cuts = [prefixer(1)];
        let adds = [prefixer(5), prefixer(6)];
        assert_eq!(
            validate_rotation_witnesses(&prior, &cuts, &adds).unwrap(),
            5
        );
        assert_eq!(validate_rotation_witnesses(&[], &[], &[]).unwrap(), 0);
        assert_eq!(validate_rotation_witnesses(&prior, &prior, &[]).unwrap(), 0);
    }

    #[test]
    fn rotation_rejects_cut_not_in_prior() {
        let result = validate_rotation_witnesses(&[prefixer(1)], &[prefixer(9)], &[]);
        assert!(matches!(result, Err(SerderError::CutNotPriorWitness)));
    }

    #[test]
    fn rotation_rejects_add_already_prior() {
        let result = validate_rotation_witnesses(&[prefixer(1)], &[], &[prefixer(1)]);
        assert!(matches!(result, Err(SerderError::AddAlreadyWitness)));
    }

    #[test]
    fn rotation_rejects_cut_add_overlap() {
        // No input reaches the cuts ∩ adds branch: an overlapping cut must be
        // a prior witness (else cuts ⊆ prior fires first), which makes the
        // overlapping add a prior member too, so adds ∩ prior always fires
        // first — same terminal Err and keripy check order either way.
        let result = validate_rotation_witnesses(&[prefixer(1)], &[prefixer(1)], &[prefixer(1)]);
        assert!(matches!(result, Err(SerderError::AddAlreadyWitness)));
        let overlap = validate_rotation_witnesses(
            &[prefixer(1), prefixer(2)],
            &[prefixer(1)],
            &[prefixer(1)],
        );
        assert!(matches!(overlap, Err(SerderError::AddAlreadyWitness)));
    }
}
