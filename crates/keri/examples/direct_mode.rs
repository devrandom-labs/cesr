//! Direct-mode KERI, end to end on the pure sans-io core — no network, no
//! database, no runtime.
//!
//! Two in-memory parties, Alice and Bob, run the full protocol. Alice controls
//! a delegated Agent AID (the "device", provisioned and held by Alice — it only
//! ever receives signatures, which is why revocation locks it out). Parties
//! exchange nothing but framed wire bytes (`Vec<u8>` transcripts) and answer
//! every protocol question with the fold: [`KeyState::incept`] /
//! [`KeyState::ingest`] for validation, [`KeyStateSnapshot`] as the only
//! cross-step state, [`Authority`] for message signing, and
//! [`KeyState::judge_same_sn`] for duplicity.
//!
//! The seven steps prove: (1-2) self-addressing inception and the K1 fold,
//! (3) pre-rotation and the stale-key wedge, (4) K4 delegation over anchored
//! seals, (5) agent message signing, (6) revocation by rotation-to-abandonment
//! — the delegated AID dies by pure verification, (7) K2 escrow dispositions
//! and K3 duplicity judgment. CI compiles this example for
//! `wasm32-unknown-unknown`.
//!
//! Run with:
//! ```text
//! cargo run -p keri-rs --example direct_mode --features wire
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it narrates each protocol step"
)]

use std::error::Error;

use cesr::core::primitives::Number;
use cesr::crypto::salt::{Salt, Tier};
use cesr_stream::group::ControllerIdxSigs;
use keri::{
    AnchoredDelegation, Authority, Custodian, CustodyError, DelegationError, DelegationEvidence,
    Disposition, EvidenceKind, KeyCommitment, KeySpec, KeyState, KeyStateSnapshot, PathConvention,
    Rejection, SaltyCustodian, SaltyParams, SameSnVerdict, Signed,
};
use keri_codec::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, EventMessage, InceptionBuilder,
    InteractionBuilder, RotationBuilder, SerializedEvent,
};
use keri_events::{Identifier, Said, Seal};

/// Fixed root salt for Alice's custodian (deterministic, no OS RNG).
const SALT_ALICE: &[u8; 16] = b"alice-salt-00001";
/// Fixed root salt for Bob's custodian.
const SALT_BOB: &[u8; 16] = b"bob-salt-0000002";
/// Fixed root salt for the delegated Agent's custodian.
const SALT_AGENT: &[u8; 16] = b"agent-salt-00003";

/// Every identifier here is single-signature, transferable, with one
/// pre-rotated next key.
const ONE_OF_ONE: KeySpec = KeySpec {
    count: 1,
    ncount: 1,
    transferable: true,
};

/// The revocation spec: rotate onto the committed key and commit to NOTHING —
/// an empty next-key set abandons the identifier.
const ABANDON: KeySpec = KeySpec {
    count: 1,
    ncount: 0,
    transferable: true,
};

/// A fresh deterministic custodian for one party: fixed salt, the cheapest
/// argon2 tier, keripy path convention. Never `Salt::generate()` — the
/// example stays deterministic and free of OS RNG (wasm has none by default).
fn custodian(salt: &[u8; 16]) -> Result<SaltyCustodian, Box<dyn Error>> {
    Ok(SaltyCustodian::new(
        Salt::from_raw(salt)?,
        Tier::Low,
        PathConvention::Keripy,
    ))
}

/// Sign `event` with `custodian` and frame it as one V1 wire message
/// (keripy `messagize`: body + `-A` controller-indexed-signature group).
fn frame(event: &SerializedEvent, custodian: &SaltyCustodian) -> Result<Vec<u8>, Box<dyn Error>> {
    let sigs = custodian.sign(event.as_bytes(), None)?;
    let group = ControllerIdxSigs::from_indexed_signatures(&sigs)?;
    Ok(event.frame_v1(&group, None)?)
}

/// Parse one framed message off the wire, asserting the frame held exactly
/// one message (the transcript stores one frame per event).
fn parse_one(wire: &[u8]) -> Result<EventMessage<'_>, Box<dyn Error>> {
    let (message, rest) = EventMessage::parse(wire)?;
    assert!(
        rest.is_empty(),
        "each transcript frame carries exactly one message"
    );
    Ok(message)
}

/// Deliver one framed event: parse, bridge wire→fold (`Signed::from` is the
/// `wire`-feature adapter — the only place bytes meet the fold), validate,
/// and return the owned successor snapshot. `None` seeds from a genesis.
fn deliver(
    wire: &[u8],
    snapshot: Option<&KeyStateSnapshot>,
) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let message = parse_one(wire)?;
    let signed = Signed::from(&message);
    let next = match snapshot {
        None => KeyStateSnapshot::from(&KeyState::incept(&signed)?),
        Some(current) => KeyStateSnapshot::from(&current.view().ingest(&signed)?),
    };
    Ok(next)
}

/// The facts about Alice's rotation that later steps need: its SAID (chain
/// links, fork building) and its key commitment (the fork reuses the keys).
struct RotationFacts {
    /// SAID of Alice's rotation event.
    said: Said<'static>,
    /// The keys Alice rotated onto, plus the fresh next-key commitment.
    commitment: KeyCommitment,
}

/// The facts about the delegated Agent that later steps need.
struct AgentFacts {
    /// The Agent's self-addressing prefix.
    id: Identifier<'static>,
    /// SAID of the Agent's delegated inception.
    dip_said: Said<'static>,
    /// Bob's snapshot of the Agent KEL after accepting the dip.
    at_bob: KeyStateSnapshot,
}

/// One direct-mode session: the three custodians, the wire transcripts each
/// side retains, and the key-state snapshots that are the ONLY cross-step
/// state. Alice's transcript is the detour playground in step 7.
struct World {
    /// Alice's custodian (post-step-3: rotated once).
    alice: SaltyCustodian,
    /// The Agent's custodian, provisioned and held by Alice.
    agent: SaltyCustodian,
    /// Alice's KEL as raw framed wire bytes, one frame per event.
    alice_wire: Vec<Vec<u8>>,
    /// The Agent's KEL as raw framed wire bytes.
    agent_wire: Vec<Vec<u8>>,
    /// Alice's self-addressing prefix.
    alice_id: Identifier<'static>,
    /// SAID of Alice's inception (chain link for her rotation).
    alice_icp_said: Said<'static>,
    /// Alice's inception key commitment (key-change assertion in step 3).
    alice_icp_commitment: KeyCommitment,
    /// Bob's snapshot of Alice's KEL.
    alice_at_bob: KeyStateSnapshot,
}

impl World {
    /// Steps 1-2: Alice and Bob incept and exchange genesis events.
    fn incept() -> Result<Self, Box<dyn Error>> {
        println!("== 1. Alice incepts (self-addressing AID) ==");
        let mut alice = custodian(SALT_ALICE)?;
        let alice_icp_commitment = alice.incept(ONE_OF_ONE)?;
        let alice_icp = InceptionBuilder::new()
            .keys(alice_icp_commitment.verkeys.clone())
            .next_keys(alice_icp_commitment.next_digests.clone())
            .build()?;
        let alice_id = alice_icp
            .identifier()
            .ok_or("a transferable inception is self-addressing")?;
        let alice_wire = vec![frame(&alice_icp, &alice)?];

        // Bob receives Alice's genesis over the wire and seeds his fold.
        let alice_at_bob = deliver(&alice_wire[0], None)?;
        {
            let view = alice_at_bob.view();
            assert_eq!(view.prefix(), &alice_id, "prefix is the inception SAID");
            assert_eq!(view.sn(), Number::new(0), "genesis sits at sn 0");
            assert_eq!(
                view.keys(),
                alice_icp_commitment.verkeys.as_slice(),
                "folded keys are the committed verkeys"
            );
            assert!(view.is_transferable(), "one committed next key: rotatable");
            assert!(view.witnesses().is_empty(), "direct mode: zero witnesses");
        }

        println!("== 2. Bob incepts; the exchange is symmetric ==");
        let mut bob = custodian(SALT_BOB)?;
        let bob_icp_commitment = bob.incept(ONE_OF_ONE)?;
        let bob_icp = InceptionBuilder::new()
            .keys(bob_icp_commitment.verkeys.clone())
            .next_keys(bob_icp_commitment.next_digests.clone())
            .build()?;
        let bob_id = bob_icp
            .identifier()
            .ok_or("a transferable inception is self-addressing")?;
        let bob_wire = [frame(&bob_icp, &bob)?];
        let bob_at_alice = deliver(&bob_wire[0], None)?;
        {
            let view = bob_at_alice.view();
            assert_eq!(view.prefix(), &bob_id, "Alice's view mirrors Bob's AID");
            assert_eq!(view.sn(), Number::new(0));
            assert!(view.witnesses().is_empty(), "direct mode: zero witnesses");
        }

        Ok(Self {
            alice,
            agent: custodian(SALT_AGENT)?,
            alice_wire,
            agent_wire: Vec::new(),
            alice_icp_said: alice_icp.said().clone(),
            alice_id,
            alice_icp_commitment,
            alice_at_bob,
        })
    }

    /// Step 3: Alice rotates. Pre-rotation opens her inception commitment;
    /// afterwards her OLD keys are worthless against the new state.
    fn rotate_alice(&mut self) -> Result<RotationFacts, Box<dyn Error>> {
        println!("== 3. Alice rotates (pre-rotation) ==");
        let params_before_rotate = self.alice.params();
        let rot_commitment = self.alice.rotate(ONE_OF_ONE)?;
        let alice_rot = RotationBuilder::new()
            .prefix(self.alice_id.clone())
            .prior_event_said(self.alice_icp_said.clone())
            .keys(rot_commitment.verkeys.clone())
            .prior_witnesses(vec![])
            .next_keys(rot_commitment.next_digests.clone())
            .build()?;
        let rot_said = alice_rot.said().clone();
        self.alice_wire.push(frame(&alice_rot, &self.alice)?);
        self.alice_at_bob = deliver(&self.alice_wire[1], Some(&self.alice_at_bob))?;

        let probe = b"message signed under Alice's keys";
        let fresh_sigs = self.alice.sign(probe, None)?;
        let stale = SaltyCustodian::resume(Salt::from_raw(SALT_ALICE)?, params_before_rotate);
        let stale_sigs = stale.sign(probe, None)?;
        {
            let view = self.alice_at_bob.view();
            assert_eq!(view.sn(), Number::new(1), "rotation advances to sn 1");
            assert_ne!(
                view.keys(),
                self.alice_icp_commitment.verkeys.as_slice(),
                "rotation changes the controlling keys"
            );
            let authority = Authority::new(view.keys(), view.threshold());
            let stale_err = authority
                .verify(probe, &stale_sigs)
                .err()
                .ok_or("pre-rotation keys must no longer verify")?;
            assert!(
                matches!(stale_err, Rejection::MissingSignatures { .. }),
                "the stale-key wedge: old keys verify against nothing"
            );
            assert!(
                authority.verify(probe, &fresh_sigs).is_ok(),
                "current keys verify against the rotated state"
            );
        }
        Ok(RotationFacts {
            said: rot_said,
            commitment: rot_commitment,
        })
    }

    /// Step 4: Alice delegates the Agent. She anchors the dip's event-seal in
    /// her ixn sn 2; Bob folds the ixn FIRST, then validates the dip against
    /// the anchored evidence.
    fn delegate_agent(&mut self, rot: &RotationFacts) -> Result<AgentFacts, Box<dyn Error>> {
        println!("== 4. Alice delegates an Agent (dip + anchored seal) ==");
        let dip_commitment = self.agent.incept(ONE_OF_ONE)?;
        let agent_dip = DelegatedInceptionBuilder::new(self.alice_id.clone())
            .keys(dip_commitment.verkeys.clone())
            .next_keys(dip_commitment.next_digests.clone())
            .build()?;
        let agent_id = agent_dip
            .identifier()
            .ok_or("a transferable delegated inception is self-addressing")?;
        let dip_said = agent_dip.said().clone();
        self.agent_wire.push(frame(&agent_dip, &self.agent)?);

        let dip_seal = Seal::Event {
            i: agent_id.clone(),
            s: Number::new(0),
            d: dip_said.clone(),
        };
        let alice_ixn2 = InteractionBuilder::new()
            .prefix(self.alice_id.clone())
            .prior_event_said(rot.said.clone())
            .sn(2)
            .anchors(vec![dip_seal])
            .build()?;
        self.alice_wire.push(frame(&alice_ixn2, &self.alice)?);
        // Bob folds the anchoring ixn into his Alice KEL FIRST — the evidence
        // must name an event already accepted in the delegator's KEL.
        self.alice_at_bob = deliver(&self.alice_wire[2], Some(&self.alice_at_bob))?;

        let dip_message = parse_one(&self.agent_wire[0])?;
        let anchor_message = parse_one(&self.alice_wire[2])?;
        let dip_signed = Signed::from(&dip_message);

        // Negative first: a dip reaching the plain fold entry parks for
        // delegation evidence (keripy's .pdes/.udes escrows).
        let no_evidence_err = KeyState::incept(&dip_signed)
            .err()
            .ok_or("a dip without evidence must be rejected")?;
        assert!(
            matches!(
                no_evidence_err,
                Rejection::Delegation(DelegationError::EvidenceRequired)
            ),
            "the plain fold refuses delegated events"
        );
        assert_eq!(
            no_evidence_err.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence),
            "it awaits the delegator's authorizing evidence"
        );

        let at_bob = {
            let alice_view = self.alice_at_bob.view();
            let evidence = DelegationEvidence::Anchored(AnchoredDelegation {
                delegator: &alice_view,
                delegating_event: anchor_message.event(),
            });
            let agent_state = KeyState::incept_delegated(&dip_signed, &evidence)?;
            KeyStateSnapshot::from(&agent_state)
        };
        {
            let view = at_bob.view();
            assert_eq!(
                view.delegator(),
                Some(&self.alice_id),
                "the Agent KEL binds Alice as delegator"
            );
            assert_eq!(view.sn(), Number::new(0), "the dip is the Agent genesis");
        }
        Ok(AgentFacts {
            id: agent_id,
            dip_said,
            at_bob,
        })
    }

    /// Step 5: the Agent signs an application message; Bob verifies it
    /// against the folded Agent authority — no shared state but the KEL.
    fn agent_signs(&self, facts: &AgentFacts) -> Result<(), Box<dyn Error>> {
        println!("== 5. the Agent signs; Bob verifies ==");
        let order = b"order:42";
        let order_sigs = self.agent.sign(order, None)?;
        let view = facts.at_bob.view();
        let authority = Authority::new(view.keys(), view.threshold());
        let verified = authority.verify(order, &order_sigs)?;
        assert_eq!(
            verified.sigs().len(),
            1,
            "one valid signature from the Agent's current key"
        );
        Ok(())
    }

    /// Step 6: revocation. The Agent rotates with an EMPTY next-key
    /// commitment (abandonment); Alice anchors the drt seal in ixn sn 3.
    /// After Bob folds it, the delegated AID is dead by pure verification.
    fn revoke_agent(&mut self, facts: &AgentFacts) -> Result<(), Box<dyn Error>> {
        println!("== 6. Alice revokes the delegation (rotate to abandonment) ==");
        let params_before_revoke = self.agent.params();
        let drt_commitment = self.agent.rotate(ABANDON)?;
        let agent_drt = DelegatedRotationBuilder::new()
            .prefix(facts.id.clone())
            .prior_event_said(facts.dip_said.clone())
            .keys(drt_commitment.verkeys.clone())
            .prior_witnesses(vec![])
            .build()?;
        let drt_said = agent_drt.said().clone();
        self.agent_wire.push(frame(&agent_drt, &self.agent)?);

        let drt_seal = Seal::Event {
            i: facts.id.clone(),
            s: Number::new(1),
            d: drt_said.clone(),
        };
        let alice_ixn3 = InteractionBuilder::new()
            .prefix(self.alice_id.clone())
            .prior_event_said(self.alice_wire_said_of_ixn2()?)
            .sn(3)
            .anchors(vec![drt_seal])
            .build()?;
        self.alice_wire.push(frame(&alice_ixn3, &self.alice)?);
        self.alice_at_bob = deliver(&self.alice_wire[3], Some(&self.alice_at_bob))?;

        let drt_message = parse_one(&self.agent_wire[1])?;
        let anchor_message = parse_one(&self.alice_wire[3])?;
        let revoked = {
            let alice_view = self.alice_at_bob.view();
            let evidence = DelegationEvidence::Anchored(AnchoredDelegation {
                delegator: &alice_view,
                delegating_event: anchor_message.event(),
            });
            let drt_signed = Signed::from(&drt_message);
            let prior_view = facts.at_bob.view();
            let next_state = prior_view.ingest_delegated(&drt_signed, &evidence)?;
            KeyStateSnapshot::from(&next_state)
        };

        // (a) the delegation is dead by pure verification.
        {
            let view = revoked.view();
            assert!(
                !view.is_transferable(),
                "empty next-key commitment: the AID is abandoned"
            );
        }
        self.revocation_wedges(facts, &revoked, drt_said, params_before_revoke)
    }

    /// Steps 6b-d: the wedge assertions on the revoked Agent state — the
    /// revoked device is locked out, the AID is inert, and custody agrees.
    fn revocation_wedges(
        &mut self,
        facts: &AgentFacts,
        revoked: &KeyStateSnapshot,
        drt_said: Said<'static>,
        params_before_revoke: SaltyParams,
    ) -> Result<(), Box<dyn Error>> {
        // (b) the revoked device's signature is rejected: keys derived from
        // the PRE-revocation custody params verify against nothing now.
        let stale_device = SaltyCustodian::resume(Salt::from_raw(SALT_AGENT)?, params_before_revoke);
        let stale_order = b"order:43";
        let stale_device_sigs = stale_device.sign(stale_order, None)?;
        {
            let view = revoked.view();
            let authority = Authority::new(view.keys(), view.threshold());
            let stale_err = authority
                .verify(stale_order, &stale_device_sigs)
                .err()
                .ok_or("revoked keys must not verify")?;
            assert!(
                matches!(stale_err, Rejection::MissingSignatures { .. }),
                "the wedge: the revoked device is cryptographically locked out"
            );
        }

        // (c) the AID is inert: even a well-formed, correctly-signed follow-up
        // event is rejected — a closed KEL admits no more key events.
        let inert_ixn = InteractionBuilder::new()
            .prefix(facts.id.clone())
            .prior_event_said(drt_said)
            .sn(2)
            .build()?;
        let inert_wire = frame(&inert_ixn, &self.agent)?;
        let inert_message = parse_one(&inert_wire)?;
        let inert_signed = Signed::from(&inert_message);
        let inert_err = revoked
            .view()
            .ingest(&inert_signed)
            .err()
            .ok_or("an abandoned AID must reject every further event")?;
        assert!(
            matches!(inert_err, Rejection::NonTransferableState),
            "no more key events on an abandoned state"
        );
        assert_eq!(inert_err.disposition(), Disposition::Terminal);

        // (d) custody agrees: the abandoned custodian cannot rotate again.
        let custody_err = self
            .agent
            .rotate(ONE_OF_ONE)
            .err()
            .ok_or("an abandoned custodian must refuse rotation")?;
        assert!(
            matches!(custody_err, CustodyError::NotRotatable),
            "custody mirrors the fold's verdict"
        );
        Ok(())
    }

    /// Step 7: detours — K2 escrow dispositions on out-of-order/stale
    /// delivery, K3 duplicity judgment on a forged fork at an occupied sn.
    fn detours(&self, rot: &RotationFacts) -> Result<(), Box<dyn Error>> {
        println!("== 7a. out-of-order delivery: escrow dispositions (K2) ==");
        let replay_genesis = deliver(&self.alice_wire[0], None)?;
        let gap_message = parse_one(&self.alice_wire[2])?;
        let gap_signed = Signed::from(&gap_message);
        let gap_err = replay_genesis
            .view()
            .ingest(&gap_signed)
            .err()
            .ok_or("skipping sn 1 must be rejected")?;
        assert!(
            matches!(
                gap_err,
                Rejection::OutOfOrder {
                    expected: 1,
                    actual: 2
                }
            ),
            "ixn sn 2 before rot sn 1 is a gap"
        );
        assert_eq!(
            gap_err.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 1 }),
            "a gap awaits the missing prior events (keripy .ooes)"
        );

        let mut replay = deliver(&self.alice_wire[1], Some(&replay_genesis))?;
        replay = deliver(&self.alice_wire[2], Some(&replay))?;
        assert_eq!(
            replay.view().sn(),
            Number::new(2),
            "re-driven in order, the parked event folds"
        );

        let stale_message = parse_one(&self.alice_wire[1])?;
        let stale_signed = Signed::from(&stale_message);
        let stale_err = replay
            .view()
            .ingest(&stale_signed)
            .err()
            .ok_or("re-delivering an occupied sn must be rejected")?;
        assert!(
            matches!(stale_err, Rejection::OutOfOrder { .. }),
            "sn 1 is already occupied"
        );
        assert_eq!(
            stale_err.disposition(),
            Disposition::Contested,
            "a stale sn routes to the same-sn judge, not escrow"
        );

        println!("== 7b. duplicity: judging a forged fork (K3) ==");
        let fork_anchor = Seal::Digest { d: rot.said.clone() };
        let alice_rot_fork = RotationBuilder::new()
            .prefix(self.alice_id.clone())
            .prior_event_said(self.alice_icp_said.clone())
            .keys(rot.commitment.verkeys.clone())
            .prior_witnesses(vec![])
            .next_keys(rot.commitment.next_digests.clone())
            .anchors(vec![fork_anchor])
            .build()?;
        let fork_wire = frame(&alice_rot_fork, &self.alice)?;
        let fork_message = parse_one(&fork_wire)?;
        let recorded_message = parse_one(&self.alice_wire[1])?;
        let view = self.alice_at_bob.view();
        let fork_verdict = view.judge_same_sn(fork_message.event(), recorded_message.event(), &[])?;
        assert!(
            matches!(fork_verdict, SameSnVerdict::Duplicitous { .. }),
            "same sn, same keys, different SAID: duplicity evidence"
        );
        let replay_verdict =
            view.judge_same_sn(recorded_message.event(), recorded_message.event(), &[])?;
        assert_eq!(
            replay_verdict,
            SameSnVerdict::Duplicate,
            "the identical recorded event is an idempotent duplicate"
        );
        Ok(())
    }

    /// The SAID of Alice's ixn sn 2, re-parsed from the transcript — parties
    /// retain raw wire bytes; anything else is re-derived on demand.
    fn alice_wire_said_of_ixn2(&self) -> Result<Said<'static>, Box<dyn Error>> {
        let message = parse_one(&self.alice_wire[2])?;
        Ok(message.event().said().clone().into_static())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut world = World::incept()?;
    let rotation = world.rotate_alice()?;
    let agent = world.delegate_agent(&rotation)?;
    world.agent_signs(&agent)?;
    world.revoke_agent(&agent)?;
    world.detours(&rotation)?;

    println!();
    println!("Direct mode, end to end, on the pure sans-io core:");
    println!("  inception + exchange (K1 fold, self-addressing AIDs),");
    println!("  pre-rotation with the stale-key wedge (K7 custody),");
    println!("  delegation over anchored seals (K4), agent message signing,");
    println!("  revocation by abandonment — the delegated AID dies by verification,");
    println!("  escrow dispositions (K2) and duplicity judgment (K3).");
    println!("No network, no database, no runtime — see \"KERI without a database\"");
    println!("in the README. CI compiles this example for wasm32-unknown-unknown.");
    Ok(())
}
