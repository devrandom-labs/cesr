//! Fold-level property tests: they drive the real `validate`/`apply`/`fold`
//! (not just `satisfied_by`) over generated inputs and assert invariants that
//! would fail if the fold's sequencing, threshold arithmetic, or state carry-over
//! regressed. Generators are kept small (bounded key counts and chain lengths) so
//! proptest stays fast.
mod common;

use cesr::core::primitives::{Tholder, Verfer};
use cesr::keri::{Ilk, KeriEvent};
use common::{inception, inception_multi, interaction_after, sig_for, verfer};
use keri::{RejectionReason, SignedEvent, fold, validate};
use proptest::prelude::*;

/// Build a genesis + `n` interactions, all signed by the single genesis key at
/// index 0.
///
/// Each interaction's `prior_event_said` depends on the running state, so the
/// chain is built in order: the accumulated events are re-folded to learn the
/// current state, the next interaction is chained onto it, and only then is it
/// pushed. `state` (which borrows `events`) is dropped before each push, so the
/// growing `Vec` is never aliased.
#[allow(
    clippy::unwrap_used,
    reason = "test helper: a fold failure while building fixtures is a test-setup bug that should abort loudly"
)]
fn build_ixn_chain(n: u128) -> Vec<KeriEvent> {
    let k0 = verfer(1);
    let k1 = verfer(2);
    let mut events = vec![inception(&k0, &k1)];
    for sn in 1..=n {
        let state = fold(None, signed_chain(&events, &k0)).unwrap();
        let ixn = interaction_after(&state, sn);
        events.push(ixn);
    }
    events
}

/// Pair each event with a single index-0 signature by `signer`.
fn signed_chain<'a>(
    events: &'a [KeriEvent],
    signer: &'a Verfer<'static>,
) -> impl Iterator<Item = SignedEvent<'a>> {
    events.iter().map(move |event| SignedEvent {
        event,
        sigs: vec![sig_for(0, signer)],
        wigs: vec![],
    })
}

proptest! {
    /// Folding a genesis then `n` interactions yields a final state at sn `n`, and
    /// every prefix of length `j` folds to sn `j - 1`: the sequence number
    /// advances by exactly one per event and never skips or repeats.
    #[test]
    fn sn_advances_by_one_per_event(n in 0u128..8) {
        let events = build_ixn_chain(n);
        let k0 = verfer(1);

        for j in 1..=events.len() {
            let state = fold(None, signed_chain(&events[..j], &k0)).unwrap();
            let expected = u128::try_from(j - 1).unwrap();
            prop_assert_eq!(state.sn().value(), expected);
        }

        let final_state = fold(None, signed_chain(&events, &k0)).unwrap();
        prop_assert_eq!(final_state.sn().value(), n);
        if n >= 1 {
            prop_assert_eq!(final_state.latest_ilk(), Ilk::Ixn);
        } else {
            prop_assert_eq!(final_state.latest_ilk(), Ilk::Icp);
        }
    }

    /// Interactions never touch establishment state: after folding a genesis and
    /// any number of interactions, the current keys, next-key commitment, and
    /// last-establishment pointer are identical to the genesis event's.
    #[test]
    fn interactions_preserve_establishment_state(n in 0u128..8) {
        let events = build_ixn_chain(n);
        let k0 = verfer(1);

        let genesis = fold(None, signed_chain(&events[..1], &k0)).unwrap();
        let g_keys: Vec<_> = genesis.keys().iter().map(|k| k.raw().to_vec()).collect();
        let g_next: Vec<_> = genesis.next_keys().iter().map(|d| d.raw().to_vec()).collect();
        let g_est_sn = genesis.last_establishment().sn.value();
        let g_est_said = genesis.last_establishment().said.raw().to_vec();

        let final_state = fold(None, signed_chain(&events, &k0)).unwrap();
        let f_keys: Vec<_> = final_state.keys().iter().map(|k| k.raw().to_vec()).collect();
        let f_next: Vec<_> = final_state.next_keys().iter().map(|d| d.raw().to_vec()).collect();

        prop_assert_eq!(f_keys, g_keys);
        prop_assert_eq!(f_next, g_next);
        prop_assert_eq!(final_state.last_establishment().sn.value(), g_est_sn);
        prop_assert_eq!(final_state.last_establishment().said.raw().to_vec(), g_est_said);
    }

    /// An inception with `k` keys and a `Simple(t)` threshold is accepted iff at
    /// least `t` distinct in-range signer indices are supplied, and otherwise
    /// rejected as `MissingSignatures`. Indices `0..m` are distinct and in range,
    /// so the only variable is whether `m >= t`.
    #[test]
    fn inception_threshold_boundary(
        (k, t, m) in (1usize..=5)
            .prop_flat_map(|k| (Just(k), 1u64..=u64::try_from(k).unwrap(), 0usize..=k))
    ) {
        let keys: Vec<_> = (0..k)
            .map(|i| verfer(u8::try_from(i).unwrap() + 1))
            .collect();
        let next = verfer(200);
        let icp = inception_multi(&keys, &next, Tholder::Simple(t));

        let sigs: Vec<_> = (0..m)
            .map(|i| sig_for(u32::try_from(i).unwrap(), &keys[i]))
            .collect();

        let result = validate(None, &icp, &sigs, &[]);
        if u64::try_from(m).unwrap() >= t {
            prop_assert!(result.is_ok(), "m={} t={} should accept", m, t);
        } else {
            let err = result.unwrap_err();
            prop_assert_eq!(err.reason, RejectionReason::MissingSignatures);
        }
    }
}
