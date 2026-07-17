//! Property tests that drive the real `incept`/`ingest` over generated KEL shapes
//! and assert invariants that would fail if the transition's sequencing, state
//! carry-over, or threshold arithmetic regressed. Generators stay small (bounded
//! key counts and chain lengths) and case counts are capped so the suite — which
//! builds real events and real Ed25519 signatures per case — stays fast.
mod common;

use keri_events::SigningThreshold;
use proptest::prelude::*;

use common::{Fallible, Key, genesis, inception_multi, interaction, seed};
use keri::{KeyState, Rejection};

/// Fold a genesis followed by `n` interactions, all signed by the genesis key,
/// and return the final sequence number.
fn fold_interaction_chain(n: u128) -> Fallible<u128> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let mut chain = vec![genesis(&k0, &k1)?];
    for sn in 1..=n {
        let prior = chain.last().ok_or("chain is never empty")?;
        let ixn = interaction(prior, sn)?;
        chain.push(ixn);
    }

    let genesis_event = chain.first().ok_or("chain has a genesis")?;
    let mut state = seed(genesis_event, &k0)?;
    for ev in &chain[1..] {
        let sig = k0.sign(&ev.bytes, 0)?;
        state = state.ingest(&ev.signed(vec![sig]))?;
    }
    Ok(state.sn().value())
}

/// Facts about establishment state before and after folding `n` interactions onto
/// a genesis: the two must agree on everything an interaction leaves untouched.
struct EstablishmentDelta {
    genesis_keys: Vec<Vec<u8>>,
    final_keys: Vec<Vec<u8>>,
    genesis_next: Vec<Vec<u8>>,
    final_next: Vec<Vec<u8>>,
    genesis_est_sn: u128,
    final_est_sn: u128,
    final_sn: u128,
}

fn establishment_delta(n: u128) -> Fallible<EstablishmentDelta> {
    let (k0, k1) = (Key::new()?, Key::new()?);
    let mut chain = vec![genesis(&k0, &k1)?];
    for sn in 1..=n {
        let prior = chain.last().ok_or("chain is never empty")?;
        chain.push(interaction(prior, sn)?);
    }

    let genesis_event = chain.first().ok_or("chain has a genesis")?;
    let start = seed(genesis_event, &k0)?;
    let genesis_keys = start.keys().iter().map(|v| v.raw().to_vec()).collect();
    let genesis_next = start.next_keys().iter().map(|d| d.raw().to_vec()).collect();
    let genesis_est_sn = start.last_establishment().sn.value();

    let mut state = start;
    for ev in &chain[1..] {
        let sig = k0.sign(&ev.bytes, 0)?;
        state = state.ingest(&ev.signed(vec![sig]))?;
    }

    Ok(EstablishmentDelta {
        genesis_keys,
        final_keys: state.keys().iter().map(|v| v.raw().to_vec()).collect(),
        genesis_next,
        final_next: state.next_keys().iter().map(|d| d.raw().to_vec()).collect(),
        genesis_est_sn,
        final_est_sn: state.last_establishment().sn.value(),
        final_sn: state.sn().value(),
    })
}

/// `Ok(())` if a `k`-key genesis with a simple `t`-of-`k` threshold, signed by
/// `signers` distinct keys, is accepted; the caller asserts on the outcome.
fn incept_with_signers(
    k: usize,
    threshold: u64,
    signers: usize,
) -> Fallible<Result<(), Rejection>> {
    let keys: Vec<Key> = (0..k).map(|_| Key::new()).collect::<Fallible<_>>()?;
    let next = Key::new()?;
    let key_refs: Vec<&Key> = keys.iter().collect();

    let icp = inception_multi(&key_refs, &next, SigningThreshold::Simple(threshold))?;
    // `sign_all` signs each provided key at its list position, so the first
    // `signers` keys produce signatures at indices `0..signers`.
    let signing: Vec<&Key> = key_refs.iter().take(signers).copied().collect();
    let sigs = icp.sign_all(&signing)?;

    Ok(KeyState::incept(&icp.signed(sigs)).map(|_| ()))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// Each accepted event advances the sequence number by exactly one, so after a
    /// genesis and `n` interactions the state sits at sn `n`.
    #[test]
    fn sn_advances_by_one_per_event(n in 0u128..8) {
        let final_sn = fold_interaction_chain(n)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(final_sn, n);
    }

    /// Interactions are non-establishment: they move sn forward but never touch the
    /// current keys, the next-key commitment, or the last-establishment pointer.
    #[test]
    fn interactions_preserve_establishment_state(n in 0u128..8) {
        let d = establishment_delta(n).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(d.final_keys, d.genesis_keys);
        prop_assert_eq!(d.final_next, d.genesis_next);
        prop_assert_eq!(d.final_est_sn, d.genesis_est_sn);
        prop_assert_eq!(d.genesis_est_sn, 0);
        prop_assert_eq!(d.final_sn, n);
    }

    /// A simple `t`-of-`k` inception is accepted with exactly `t` signatures and
    /// rejected as under-signed with `t - 1`.
    #[test]
    fn inception_threshold_boundary((k, t) in (1usize..5).prop_flat_map(|k| (Just(k), 1usize..=k))) {
        let threshold = u64::try_from(t).map_err(|e| TestCaseError::fail(e.to_string()))?;

        let at_threshold = incept_with_signers(k, threshold, t)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert!(at_threshold.is_ok(), "t-of-k with t sigs must be accepted");

        let below = incept_with_signers(k, threshold, t - 1)
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert!(matches!(below, Err(Rejection::MissingSignatures)));
    }
}
