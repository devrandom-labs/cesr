//! Witness-set validation shared by the establishment-event builders.
//!
//! Port of keripy's witness preconditions in `incept()` (`eventing.py:624-640`)
//! and `rotate()` (`eventing.py:788-831`), keripy `de59bc7d`: duplicate-free
//! witness lists, rotation cut/add set relations against the prior witness
//! set, and TOAD bounds.

#[cfg(feature = "alloc")]
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{borrow::ToOwned, format, string::ToString, vec, vec::Vec};

use crate::core::primitives::Prefixer;
use crate::serder::error::SerderError;

/// Rejects duplicate prefixes, mirroring keripy's
/// `len(oset(x)) != len(x)` checks. `label` names the offending field.
pub(super) fn validate_distinct(
    prefixes: &[Prefixer<'static>],
    label: &str,
) -> Result<(), SerderError> {
    prefixes
        .iter()
        .enumerate()
        .all(|(i, prefix)| !contains(&prefixes[..i], prefix))
        .then_some(())
        .ok_or_else(|| SerderError::Validation(format!("{label} must not contain duplicates")))
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
#[allow(
    dead_code,
    reason = "wired into the rot/drt builders in the immediate follow-up change for #149; remove this allow there"
)]
pub(super) fn validate_rotation_witnesses(
    prior: &[Prefixer<'static>],
    cuts: &[Prefixer<'static>],
    adds: &[Prefixer<'static>],
) -> Result<usize, SerderError> {
    validate_distinct(prior, "prior witnesses")?;
    validate_distinct(cuts, "witness removals")?;
    if !cuts.iter().all(|cut| contains(prior, cut)) {
        return Err(SerderError::Validation(
            "witness removals must all be prior witnesses".to_owned(),
        ));
    }
    validate_distinct(adds, "witness additions")?;
    if adds.iter().any(|add| contains(prior, add)) {
        return Err(SerderError::Validation(
            "witness additions must not already be prior witnesses".to_owned(),
        ));
    }
    if cuts.iter().any(|cut| contains(adds, cut)) {
        return Err(SerderError::Validation(
            "witness removals and additions must be disjoint".to_owned(),
        ));
    }
    let kept = prior.iter().filter(|wit| !contains(cuts, wit)).count();
    kept.checked_add(adds.len()).ok_or_else(|| {
        SerderError::Validation("post-rotation witness count overflows usize".to_owned())
    })
}

/// Bounds-checks a witness threshold (TOAD) against its governing witness
/// count: `1 <= toad <= count` when witnesses exist, exactly `0` when none
/// do (keripy `eventing.py:634-640` incept / `:825-831` rotate).
pub(super) fn validate_toad(toad: u32, witness_count: usize) -> Result<(), SerderError> {
    let out_of_bounds = || {
        SerderError::Validation(format!(
            "witness threshold {toad} out of bounds for {witness_count} witnesses"
        ))
    };
    if witness_count == 0 {
        return (toad == 0).then_some(()).ok_or_else(out_of_bounds);
    }
    usize::try_from(toad)
        .ok()
        .filter(|threshold| (1..=witness_count).contains(threshold))
        .map(|_| ())
        .ok_or_else(out_of_bounds)
}

#[cfg(test)]
#[allow(clippy::panic, reason = "panics are expected in test assertions")]
mod tests {
    use alloc::borrow::Cow;

    use crate::core::matter::builder::MatterBuilder;
    use crate::core::matter::code::VerKeyCode;

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
        let Err(SerderError::Validation(msg)) = result else {
            panic!("duplicate prefixes must be rejected");
        };
        assert_eq!(msg, "prior witnesses must not contain duplicates");
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
        assert_eq!(
            validate_rotation_witnesses(&prior, &prior.clone(), &[]).unwrap(),
            0
        );
    }

    #[test]
    fn rotation_rejects_cut_not_in_prior() {
        let result = validate_rotation_witnesses(&[prefixer(1)], &[prefixer(9)], &[]);
        let Err(SerderError::Validation(msg)) = result else {
            panic!("cut outside the prior set must be rejected");
        };
        assert_eq!(msg, "witness removals must all be prior witnesses");
    }

    #[test]
    fn rotation_rejects_add_already_prior() {
        let result = validate_rotation_witnesses(&[prefixer(1)], &[], &[prefixer(1)]);
        let Err(SerderError::Validation(msg)) = result else {
            panic!("re-adding a prior witness must be rejected");
        };
        assert_eq!(msg, "witness additions must not already be prior witnesses");
    }

    #[test]
    fn rotation_rejects_cut_add_overlap() {
        let result = validate_rotation_witnesses(&[prefixer(1)], &[prefixer(1)], &[prefixer(1)]);
        // add ∩ prior fires first (keripy order); make the overlap-only case:
        let Err(SerderError::Validation(_)) = result else {
            panic!("overlapping cut/add must be rejected");
        };
        let overlap_only = validate_rotation_witnesses(
            &[prefixer(1), prefixer(2)],
            &[prefixer(1)],
            &[prefixer(1)],
        );
        let Err(SerderError::Validation(msg)) = overlap_only else {
            panic!("overlapping cut/add must be rejected");
        };
        assert_eq!(msg, "witness additions must not already be prior witnesses");
    }

    #[test]
    fn toad_boundaries_match_keripy() {
        assert!(validate_toad(0, 0).is_ok());
        assert!(validate_toad(1, 0).is_err());
        assert!(validate_toad(0, 1).is_err());
        assert!(validate_toad(1, 1).is_ok());
        assert!(validate_toad(1, 3).is_ok());
        assert!(validate_toad(3, 3).is_ok());
        assert!(validate_toad(4, 3).is_err());
        assert!(validate_toad(u32::MAX, 3).is_err());
    }
}
