//! The credential lifecycle — registry, issue, grant, admit, verify, revoke —
//! end to end on the pure sans-io core. No network, no database, no runtime.
//!
//! This is the vLEI-loop counterpart to the `direct_mode` example: what
//! `direct_mode` proves for the KEL (identifier layer), this proves for the
//! credential layer (what identifiers are *for*). Two in-memory parties,
//! Alice (issuer) and Bob (holder), exchange nothing but framed wire bytes
//! and answer every protocol question with the folds: [`KeyState`] for the
//! key-event side, [`RegistryState`] for the registry side. Alice incepts a
//! backerless registry (`vcp`), issues an ACDC v1.1 credential into it
//! (`iss`, anchored in her KEL), grants it to Bob over IPEX (`exn` with the
//! credential, its issuance TEL event, and the anchoring KEL event as
//! SAIDified embeds), Bob admits and independently verifies it, and Alice
//! revokes it (`rev`) — the holder's verification flips to REVOKED by pure
//! recomputation. Every phase asserts, including the rejections: a replayed
//! TEL event routes to the duplicity judge, a premature revocation escrows,
//! a mis-addressed envelope is a sender mismatch, and a tampered attribute
//! fails the credential's own SAID.
//!
//! Run with:
//! ```text
//! cargo run -p keri-rs --example credential_lifecycle --features wire
//! ```

#![allow(
    clippy::print_stdout,
    reason = "runnable example: it narrates each protocol step"
)]

use std::error::Error;

use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{CesrCode, DigestCode, NoncerCode};
use cesr::core::primitives::{Noncer, Number, Siger};
use cesr::crypto::digest;
use cesr::crypto::salt::{Salt, Tier};
use cesr_stream::group::ControllerIdxSigs;
use keri::{
    Authority, CredentialStatus, Custodian, Disposition, EvidenceKind, KeySpec, KeyState,
    KeyStateSnapshot, PathConvention, RegistryRejection, RegistryState, SaltyCustodian, Signed,
    SignedTel, TelEvidence,
};
use keri_codec::{
    CodecError, Deserialize, EventMessage, Exn, ExnMessage, InceptionBuilder, InteractionBuilder,
    IpexMessage, IssueBuilder, Message, RegistryInceptionBuilder, RevokeBuilder, SadCodes,
    Serialize, SerializedEvent, TelMessage,
};
use keri_events::{Acdc, AcdcField, ConfigTrait, Identifier, SadBlock, Said, Seal, TelEvent};

/// Deterministic demo salt for one party: the first 16 bytes of the Blake3
/// digest of the party's label. Not secret — a reproducibility device so the
/// example never touches OS RNG (wasm has none by default).
fn demo_salt(label: &str) -> Result<[u8; 16], Box<dyn Error>> {
    let diger = digest(DigestCode::Blake3_256, label.as_bytes())?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&diger.raw()[..16]);
    Ok(salt)
}

/// Every identifier here is single-signature, transferable, with one
/// pre-rotated next key.
const ONE_OF_ONE: KeySpec = KeySpec {
    count: 1,
    ncount: 1,
    transferable: true,
};

/// Fixed timestamps: determinism mandate — the builders never default to
/// `nowIso8601()`.
const DT_ISSUE: &str = "2026-09-18T12:00:01+00:00";
const DT_REVOKE: &str = "2026-09-18T12:00:02+00:00";
const DT_GRANT: &str = "2026-09-18T12:00:03+00:00";
const DT_ADMIT: &str = "2026-09-18T12:00:04+00:00";

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

/// A fresh deterministic 128-bit registry nonce.
fn registry_nonce(byte: u8) -> Result<Noncer<'static>, Box<dyn Error>> {
    Ok(MatterBuilder::new()
        .with_code(NoncerCode::Salt128)
        .with_raw(std::borrow::Cow::Owned(vec![byte; 16]))?
        .build()?)
}

/// The qb64 rendering of a self-addressing identifier.
fn qb64(id: &Identifier<'_>) -> Result<String, Box<dyn Error>> {
    Ok(id
        .as_saider()
        .ok_or("the example incepts only self-addressing identifiers")?
        .to_qb64())
}

/// Sign `event` with `custodian` and frame it as one V1 wire message
/// (keripy `messagize`: body + `-A` controller-indexed-signature group).
fn frame(event: &SerializedEvent, custodian: &SaltyCustodian) -> Result<Vec<u8>, Box<dyn Error>> {
    let sigs = custodian.sign(event.as_bytes(), None)?;
    let group = ControllerIdxSigs::from_indexed_signatures(&sigs)?;
    Ok(event.frame_v1(&group, None)?)
}

/// Sign an `exn` envelope with `custodian` and frame it as one V1 wire
/// message (keripy `messagize` for exchanges: envelope + `-A` group).
fn frame_exn(envelope: &Exn<'_>, custodian: &SaltyCustodian) -> Result<Vec<u8>, Box<dyn Error>> {
    let serialized = envelope.serialize()?;
    let sigs = custodian.sign(serialized.as_bytes(), None)?;
    let group = ControllerIdxSigs::from_indexed_signatures(&sigs)?;
    Ok(serialized.frame_v1(&group)?)
}

/// Parse one framed key event, asserting the frame held exactly one message.
fn parse_event(wire: &[u8]) -> Result<EventMessage<'_>, Box<dyn Error>> {
    let (message, rest) = EventMessage::parse(wire)?;
    assert!(
        rest.is_empty(),
        "each transcript frame carries exactly one message"
    );
    Ok(message)
}

/// Parse one framed TEL event, asserting the frame held exactly one message.
fn parse_tel(wire: &[u8]) -> Result<TelMessage<'_>, Box<dyn Error>> {
    let (message, rest) = TelMessage::parse(wire)?;
    assert!(
        rest.is_empty(),
        "each registry frame carries exactly one event"
    );
    Ok(message)
}

/// Parse one framed exn envelope, asserting the frame held exactly one
/// message and that it routes as an exchange message.
fn parse_exn(wire: &[u8]) -> Result<ExnMessage<'_>, Box<dyn Error>> {
    let (Message::Exn(message), rest) = Message::parse(wire)? else {
        return Err("expected an exn envelope".into());
    };
    assert!(
        rest.is_empty(),
        "each exchange frame carries exactly one message"
    );
    Ok(*message)
}

/// Deliver one framed key event: parse, bridge wire→fold (`Signed::from` is
/// the `wire`-feature adapter), validate, and return the owned successor
/// snapshot. `None` seeds from a genesis.
fn deliver(
    wire: &[u8],
    snapshot: Option<&KeyStateSnapshot>,
) -> Result<KeyStateSnapshot, Box<dyn Error>> {
    let message = parse_event(wire)?;
    let signed = Signed::from(&message);
    let next = match snapshot {
        None => KeyStateSnapshot::from(&KeyState::incept(&signed)?),
        Some(current) => KeyStateSnapshot::from(&current.view().ingest(&signed)?),
    };
    Ok(next)
}

/// The facts about the registry that later steps need.
struct RegistryFacts {
    /// The registry's identity: the `vcp`'s SAID.
    id: Said<'static>,
}

/// One issued credential: the canonical bytes, the issuer's indexed
/// signatures over them, and the SAID every later phase references.
struct CredentialFacts {
    /// SAID of the credential (its `d`, verified by the typed read path).
    said: Said<'static>,
    /// The credential's canonical JSON bytes.
    wire: Vec<u8>,
    /// The issuer's indexed signatures over [`Self::wire`].
    sigs: Vec<Siger<'static>>,
}

/// The facts about the issued credential that later steps need.
struct IssuanceFacts {
    /// The issued credential.
    credential: CredentialFacts,
    /// The issuance TEL event's canonical body (the grant's `iss` embed —
    /// embeds carry the event message, never the framed attachments).
    iss_body: Vec<u8>,
    /// The issuance TEL event's SAID — the revocation chain's prior link.
    iss_said: Said<'static>,
    /// The anchoring KEL event's canonical body (the grant's `anc` embed —
    /// the provenance Alice hands the holder).
    anchor_body: Vec<u8>,
    /// The anchoring KEL event's SAID.
    anchor_said: Said<'static>,
}

/// The facts about the grant that the admit step chains onto.
struct GrantFacts {
    /// SAID of the grant envelope (the admit's `p`).
    said: Said<'static>,
}

/// One credential-lifecycle session: the two custodians, the wire channels
/// each side retains (KEL, TEL, IPEX — three streams in one transcript), and
/// the key-state snapshots that are the ONLY cross-step state.
struct World {
    /// Alice's custodian — the issuer.
    alice: SaltyCustodian,
    /// Bob's custodian — the holder.
    bob: SaltyCustodian,
    /// Alice's KEL as raw framed wire bytes: her inception, then the
    /// issuance-anchoring interaction.
    alice_wire: Vec<Vec<u8>>,
    /// The registry's TEL as raw framed wire bytes: `vcp`, `iss`, `rev`.
    tel_wire: Vec<Vec<u8>>,
    /// The IPEX channel: the grant, then the admit.
    ipex_wire: Vec<Vec<u8>>,
    /// Alice's self-addressing prefix.
    alice_id: Identifier<'static>,
    /// Bob's self-addressing prefix.
    bob_id: Identifier<'static>,
    /// SAID of Alice's inception (chain link for her anchor ixn).
    alice_icp_said: Said<'static>,
    /// Alice's fold of her own KEL — her TEL-signing evidence.
    alice_at_alice: KeyStateSnapshot,
    /// Bob's snapshot of Alice's KEL — his TEL-verification evidence.
    alice_at_bob: KeyStateSnapshot,
    /// Alice's snapshot of Bob's KEL — her IPEX-verification evidence.
    bob_at_alice: KeyStateSnapshot,
    /// Bob's fold of his own KEL — the mis-addressed-envelope negative.
    bob_at_bob: KeyStateSnapshot,
}

impl World {
    /// Phase 1: Alice and Bob incept and exchange genesis events.
    fn incept() -> Result<Self, Box<dyn Error>> {
        println!("== 1. Alice and Bob incept and exchange identifiers ==");
        let mut alice = custodian(&demo_salt("alice")?)?;
        let alice_commitment = alice.incept(ONE_OF_ONE)?;
        let alice_icp = InceptionBuilder::new()
            .keys(alice_commitment.verkeys.clone())
            .next_keys(alice_commitment.next_digests.clone())
            .build()?;
        let alice_id = alice_icp
            .identifier()
            .ok_or("a transferable inception is self-addressing")?;
        let alice_wire = vec![frame(&alice_icp, &alice)?];
        let alice_at_bob = deliver(&alice_wire[0], None)?;
        let alice_at_alice = deliver(&alice_wire[0], None)?;
        {
            let view = alice_at_bob.view();
            assert_eq!(view.prefix(), &alice_id, "prefix is the inception SAID");
            assert_eq!(view.sn(), Number::new(0), "genesis sits at sn 0");
            assert!(view.is_transferable(), "one committed next key: rotatable");
        }

        let mut bob = custodian(&demo_salt("bob")?)?;
        let bob_commitment = bob.incept(ONE_OF_ONE)?;
        let bob_icp = InceptionBuilder::new()
            .keys(bob_commitment.verkeys.clone())
            .next_keys(bob_commitment.next_digests.clone())
            .build()?;
        let bob_id = bob_icp
            .identifier()
            .ok_or("a transferable inception is self-addressing")?;
        let bob_wire = [frame(&bob_icp, &bob)?];
        let bob_at_alice = deliver(&bob_wire[0], None)?;
        let bob_at_bob = deliver(&bob_wire[0], None)?;
        {
            let view = bob_at_alice.view();
            assert_eq!(view.prefix(), &bob_id, "Alice's view mirrors Bob's AID");
            assert_eq!(view.sn(), Number::new(0));
        }

        Ok(Self {
            alice,
            bob,
            alice_wire,
            tel_wire: Vec::new(),
            ipex_wire: Vec::new(),
            alice_icp_said: alice_icp.said().clone().into_static(),
            alice_id,
            bob_id,
            alice_at_alice,
            alice_at_bob,
            bob_at_alice,
            bob_at_bob,
        })
    }

    /// Phase 2: Alice incepts a backerless credential registry (`vcp`); Bob
    /// folds the same wire event with Alice's key state as evidence.
    fn create_registry(&mut self) -> Result<RegistryFacts, Box<dyn Error>> {
        println!("== 2. Alice incepts a credential registry (vcp) ==");
        let vcp = RegistryInceptionBuilder::new(self.alice_id.clone(), registry_nonce(0x11)?)
            .config(vec![ConfigTrait::NoBackers])
            .build()?;
        let vcp_said = vcp.said().clone().into_static();
        self.tel_wire.push(frame(&vcp, &self.alice)?);
        let vcp_wire = self.tel_wire[0].clone();

        // Alice folds her own registry from her own wire frame.
        let alice_vcp = parse_tel(&vcp_wire)?;
        let alice_view = self.alice_at_alice.view();
        let signed_vcp = SignedTel::from(&alice_vcp);
        let registry = RegistryState::incept(&signed_vcp, &alice_view)?;
        assert_eq!(
            registry.id(),
            &vcp_said,
            "the registry's identity IS the vcp's SAID"
        );
        assert!(
            registry.is_backerless(),
            "the NB trait seeded a backerless registry"
        );
        assert_eq!(
            registry.sn(),
            Number::new(0),
            "the registry is born at sn 0"
        );

        // Bob folds the same event from the wire, with Alice's KEL state as
        // the signing evidence — no shared state but the transcripts.
        let bob_vcp = parse_tel(&vcp_wire)?;
        let bob_view = self.alice_at_bob.view();
        let signed_bob_vcp = SignedTel::from(&bob_vcp);
        let bob_registry = RegistryState::incept(&signed_bob_vcp, &bob_view)?;
        assert_eq!(
            bob_registry.id(),
            &vcp_said,
            "Bob folds the same registry identity"
        );

        // Negative: a vcp whose issuer is not the evidence's own identity is
        // terminal — another issuer's state can never authorize this event.
        let wrong_issuer = self.bob_at_bob.view();
        let wrong_vcp = parse_tel(&vcp_wire)?;
        let signed_wrong = SignedTel::from(&wrong_vcp);
        let rejection = RegistryState::incept(&signed_wrong, &wrong_issuer)
            .err()
            .ok_or("a vcp judged against a non-issuer key state must be rejected")?;
        assert!(
            matches!(rejection, RegistryRejection::MissingIssuer),
            "the evidence class, not the signatures, is rejected first: {rejection:?}"
        );
        assert_eq!(
            rejection.disposition(),
            Disposition::Terminal,
            "a missing issuer is terminal, not escrowed"
        );

        Ok(RegistryFacts { id: vcp_said })
    }

    /// Phase 3: Alice issues the credential — the ACDC v1.1 body SAIDified
    /// inner-out through the generic SAD path, the `iss` TEL event, and a
    /// KEL interaction anchoring the issuance. The fold reads ISSUED.
    fn issue(&mut self, registry: &RegistryFacts) -> Result<IssuanceFacts, Box<dyn Error>> {
        println!("== 3. Alice issues the credential (ACDC + iss, KEL-anchored) ==");
        let credential = self.issue_credential(&self.bob_id, &registry.id)?;

        let iss =
            IssueBuilder::new(credential.said.clone(), registry.id.clone(), DT_ISSUE).build()?;
        let iss_said = iss.said().clone().into_static();
        let iss_body = iss.as_bytes().to_vec();
        self.tel_wire.push(frame(&iss, &self.alice)?);

        // Alice anchors the issuance in her KEL: the interaction's event
        // seal names the registry, the TEL sequence number, and the iss SAID.
        let anchor = InteractionBuilder::new()
            .prefix(self.alice_id.clone())
            .prior_event_said(self.alice_icp_said.clone())
            .sn(1)
            .anchors(vec![Seal::Event {
                i: Identifier::SelfAddressing(registry.id.clone()),
                s: Number::new(0),
                d: iss_said.clone(),
            }])
            .build()?;
        let anchor_said = anchor.said().clone().into_static();
        let anchor_body = anchor.as_bytes().to_vec();
        let anchor_wire_index = self.alice_wire.len();
        self.alice_wire.push(frame(&anchor, &self.alice)?);

        // Both parties fold the anchor into their views of Alice's KEL.
        self.alice_at_alice = deliver(
            &self.alice_wire[anchor_wire_index],
            Some(&self.alice_at_alice),
        )?;
        self.alice_at_bob = deliver(
            &self.alice_wire[anchor_wire_index],
            Some(&self.alice_at_bob),
        )?;

        // The TEL fold on Alice's side: the vcp seeds, the iss lands.
        let vcp_message = parse_tel(&self.tel_wire[0])?;
        let iss_message = parse_tel(&self.tel_wire[1])?;
        let issuer_view = self.alice_at_alice.view();
        let evidence = TelEvidence::Issuer {
            state: &issuer_view,
            anchor: None,
        };
        let signed_vcp = SignedTel::from(&vcp_message);
        let registry_state = RegistryState::incept(&signed_vcp, &issuer_view)?;
        let signed_iss = SignedTel::from(&iss_message);
        let issued_state = registry_state.ingest(&signed_iss, &evidence)?;
        assert_eq!(
            issued_state.vcstate(&credential.said),
            CredentialStatus::Issued,
            "the issuance lands: the credential reads ISSUED"
        );

        // Negative: replaying the iss cannot re-land — the chain head sits at
        // sn 0, so a second sn-0 event is a contested (occupied) sequence
        // number, not a gap awaiting prior events.
        let replay_err = issued_state
            .ingest(&signed_iss, &evidence)
            .err()
            .ok_or("a replayed issuance must be rejected")?;
        assert!(
            matches!(
                replay_err,
                RegistryRejection::OutOfOrder {
                    expected: 1,
                    actual: 0
                }
            ),
            "the replay is an occupied-sn rejection: {replay_err:?}"
        );
        assert_eq!(
            replay_err.disposition(),
            Disposition::Contested,
            "an occupied sn routes to the duplicity judge, not escrow"
        );

        Ok(IssuanceFacts {
            credential,
            iss_body,
            iss_said,
            anchor_body,
            anchor_said,
        })
    }

    /// Build, `SAIDify`, sign, and typed-parse one ACDC v1.1 credential: the
    /// attribute and edge blocks digest first (their own
    /// `d`, under the generic SAD path), then the enclosing body — one
    /// canonical serialization per object, values backfilled in place.
    fn issue_credential(
        &self,
        holder: &Identifier<'_>,
        registry: &Said<'_>,
    ) -> Result<CredentialFacts, Box<dyn Error>> {
        let said_code = DigestCode::Blake3_256;
        let config = SadCodes::from_pairs(&[("d", said_code)])?;
        let placeholder = said_code.placeholder()?;
        let holder_qb64 = qb64(holder)?;
        let issuer_qb64 = qb64(&self.alice_id)?;

        // Deterministic inputs (no OS RNG): a fixed schema digest and a
        // fixed 128-bit salt for the privacy-preservation field `u`.
        let schema = Said::from_matter(digest(said_code, b"schema:driver-license.devrandom.co")?);
        let salt = MatterBuilder::new()
            .with_code(NoncerCode::Salt128)
            .with_raw(std::borrow::Cow::Owned(vec![0x51; 16]))?
            .build()?;

        // Inner first: the attribute block, then the edge block (whose node
        // chains the credential to the holder's own KEL). Every interpolated
        // value is a qb64 primitive or a fixed string — compact rendering is
        // canonical (no quotes, backslashes, or control bytes in play).
        let mut attributes = format!(
            "{{\"d\":\"{placeholder}\",\"i\":\"{holder_qb64}\",\"authorization\":\"drive any vehicle\"}}"
        )
        .into_bytes();
        config.saidify(&mut attributes)?;
        let mut edges =
            format!("{{\"d\":\"{placeholder}\",\"driver\":{{\"n\":\"{holder_qb64}\"}}}}")
                .into_bytes();
        config.saidify(&mut edges)?;

        // The body in ACDC's canonical field order: v,d,u,i,ri,s,a,e. The
        // version string carries a zero size; `saidify` backpatches it to
        // the final render length before digesting.
        let mut body = format!(
            "{{\"v\":\"ACDC10JSON000000_\",\"d\":\"{placeholder}\",\"u\":\"{}\",\"i\":\"{issuer_qb64}\",\"ri\":\"{}\",\"s\":\"{}\",\"a\":{},\"e\":{}}}",
            salt.to_qb64(),
            registry.to_qb64(),
            schema.to_qb64(),
            core::str::from_utf8(&attributes)?,
            core::str::from_utf8(&edges)?,
        )
        .into_bytes();
        config.saidify(&mut body)?;

        // The typed read path verifies every digest — the outer SAID, the
        // attribute block's, the edge block's — before the credential lifts.
        let acdc = Acdc::deserialize(&body)?;
        let registry_field = acdc
            .registry()
            .ok_or("the credential names its governing registry")?;
        assert!(
            matches!(registry_field, AcdcField::Said(_)),
            "ri is a registry reference, not an embedded block"
        );
        let attributes_field = acdc
            .attributes()
            .ok_or("the credential carries its attributes inline")?;
        assert!(
            matches!(attributes_field, AcdcField::Block(_)),
            "attributes are carried as a block"
        );
        let edges_field = acdc
            .edges()
            .ok_or("the credential carries its edges inline")?;
        assert!(
            matches!(edges_field, AcdcField::Block(_)),
            "edges are carried as a block"
        );

        let said = acdc.said().clone().into_static();
        let sigs = self.alice.sign(&body, None)?;
        assert_eq!(sigs.len(), 1, "single-signature issuer");
        Ok(CredentialFacts {
            said,
            wire: body,
            sigs,
        })
    }

    /// Phase 4: Alice grants the credential to Bob over IPEX — the `exn`
    /// envelope embeds the credential, its issuance TEL event, and the
    /// anchoring KEL event as SAIDified embeds. Bob verifies the envelope
    /// against Alice's key state and reads the typed route.
    fn grant(&mut self, issuance: &IssuanceFacts) -> Result<GrantFacts, Box<dyn Error>> {
        println!("== 4. Alice grants the credential over IPEX (exn) ==");
        let acdc_block = SadBlock::deserialize(&issuance.credential.wire)?;
        let iss_block = SadBlock::deserialize(&issuance.iss_body)?;
        let anc_block = SadBlock::deserialize(&issuance.anchor_body)?;
        let grant = Exn::ipex_grant(
            &self.alice_id,
            DT_GRANT,
            "license for the holder",
            &self.bob_id,
            &acdc_block,
            Some(&iss_block),
            Some(&anc_block),
            None,
        )?;
        self.ipex_wire.push(frame_exn(&grant, &self.alice)?);
        let grant_wire = self.ipex_wire[0].clone();
        let anchor_said_qb64 = issuance.anchor_said.to_qb64();

        // Bob receives the grant and verifies the envelope against Alice's
        // folded KEL authority — no shared state but the transcripts.
        let message = parse_exn(&grant_wire)?;
        let alice_view = self.alice_at_bob.view();
        let verified = alice_view.verify_exn(&message)?;
        assert_eq!(
            verified.sigs().len(),
            1,
            "one valid signature from Alice's current key"
        );
        let IpexMessage::Grant(parsed) = IpexMessage::parse(message.exn())? else {
            return Err("expected an /ipex/grant route".into());
        };
        assert_eq!(parsed.message(), "license for the holder");
        assert_eq!(
            parsed.recipient(),
            &self.bob_id,
            "the grant names Bob as the recipient"
        );
        assert_eq!(
            parsed.acdc().said(),
            &issuance.credential.said,
            "the embedded credential is the issued one"
        );
        assert_eq!(
            parsed.iss().map(TelEvent::said),
            Some(&issuance.iss_said),
            "the embedded issuance event is the registry's iss"
        );
        assert!(
            parsed
                .anc()
                .is_some_and(|anc| anc.payload().contains(anchor_said_qb64.as_str())),
            "the anchor embed carries the anchoring KEL event"
        );
        assert_eq!(
            parsed.prior(),
            None,
            "this grant opens the exchange conversation"
        );

        // Negative: the envelope judged against Bob's OWN key state is a
        // sender mismatch — the declared issuer is Alice.
        let wrong_state = self.bob_at_bob.view();
        let mismatch = wrong_state
            .verify_exn(&message)
            .err()
            .ok_or("an envelope judged against the wrong key state must fail")?;
        assert!(
            matches!(mismatch, keri::ExchangeError::SenderMismatch),
            "the declared sender gates verification: {mismatch:?}"
        );

        Ok(GrantFacts {
            said: message.exn().said().clone().into_static(),
        })
    }

    /// Phase 5: Bob admits the grant — the admit's `p` chains the
    /// conversation to the grant's SAID, which Alice verifies.
    fn admit(&mut self, grant: &GrantFacts) -> Result<(), Box<dyn Error>> {
        println!("== 5. Bob admits the grant; the conversation chains ==");
        let admit = Exn::ipex_admit(
            &self.bob_id,
            DT_ADMIT,
            "credential accepted",
            Some(&grant.said),
        )?;
        self.ipex_wire.push(frame_exn(&admit, &self.bob)?);
        let admit_wire = self.ipex_wire[1].clone();

        let message = parse_exn(&admit_wire)?;
        let bob_view = self.bob_at_alice.view();
        bob_view.verify_exn(&message)?;
        let IpexMessage::Admit(parsed) = IpexMessage::parse(message.exn())? else {
            return Err("expected an /ipex/admit route".into());
        };
        assert_eq!(
            parsed.prior(),
            Some(&grant.said),
            "the admit chains to the grant's SAID"
        );
        Ok(())
    }

    /// Phase 6: Bob verifies the credential independently — he re-folds the
    /// registry from the wire (vcp + iss, Alice's KEL state as evidence) and
    /// checks the credential's signatures against the same authority.
    fn verify(
        &self,
        registry: &RegistryFacts,
        issuance: &IssuanceFacts,
    ) -> Result<(), Box<dyn Error>> {
        println!("== 6. Bob verifies the credential against the registry ==");
        let issuer_view = self.alice_at_bob.view();
        self.with_iss_state(&self.alice_at_bob, |registry_state, _evidence| {
            assert_eq!(
                registry_state.id(),
                &registry.id,
                "Bob folds the same registry identity"
            );
            assert_eq!(
                registry_state.vcstate(&issuance.credential.said),
                CredentialStatus::Issued,
                "the holder's fold reads ISSUED with no help from the issuer"
            );

            // Negative: a credential never issued here reads Unknown.
            let stranger =
                Said::from_matter(digest(DigestCode::Blake3_256, b"stranger credential")?);
            assert_eq!(
                registry_state.vcstate(&stranger),
                CredentialStatus::Unknown,
                "no chain exists for a credential the registry never issued"
            );
            Ok(())
        })?;

        let authority = Authority::new(issuer_view.keys(), issuer_view.threshold());
        let verified = authority.verify(&issuance.credential.wire, &issuance.credential.sigs)?;
        assert_eq!(
            verified.sigs().len(),
            1,
            "the credential's signatures verify against Alice's KEL authority"
        );

        // Negative: one flipped attribute byte fails the credential's own
        // SAID check — the tamper cannot masquerade as the issued body.
        let mut tampered = issuance.credential.wire.clone();
        let pos = tampered
            .windows(15)
            .position(|w| w == b"\"authorization\"")
            .ok_or("fixture shape: the attribute label must be present")?;
        tampered[pos + 1] = b'A';
        let Err(said_err) = Acdc::deserialize(&tampered) else {
            unreachable!("a tampered credential must not deserialize");
        };
        assert!(
            matches!(said_err, CodecError::Said(_)),
            "the tampered body fails its own SAID: {said_err:?}"
        );
        Ok(())
    }

    /// Phase 7: Alice revokes the credential — the `rev` chains to the iss;
    /// both parties' folds flip the status to REVOKED, a premature revocation
    /// escrows, and a replayed rev routes to the duplicity judge.
    fn revoke(
        &mut self,
        registry: &RegistryFacts,
        issuance: &IssuanceFacts,
    ) -> Result<(), Box<dyn Error>> {
        println!("== 7. Alice revokes the credential (rev chains to the iss) ==");
        let rev = RevokeBuilder::new(
            issuance.credential.said.clone(),
            registry.id.clone(),
            issuance.iss_said.clone(),
            DT_REVOKE,
        )
        .build()?;
        self.tel_wire.push(frame(&rev, &self.alice)?);

        // Both parties fold the registry from the wire — the issuer with her
        // own KEL state, the holder with his fold of it. The holder learns of
        // the revocation by pure verification.
        self.assert_revocation(&self.alice_at_alice, &issuance.credential.said, "issuer")?;
        self.assert_revocation(&self.alice_at_bob, &issuance.credential.said, "holder")?;

        // Negative: a rev arriving on an EMPTY chain is a sequence gap — it
        // escrows awaiting the prior events (keripy's .ooes), it does not
        // drop, and its disposition says so.
        self.assert_premature_rev_escrow(&self.alice_at_bob)?;
        Ok(())
    }

    /// Fold the registry from the wire through the rev against `issuer`'s
    /// key state and assert REVOKED plus the replay negative. One scope,
    /// deliberately: the fold's borrows (messages, evidence view) live
    /// exactly as long as the state, like the crate's own fold tests.
    fn assert_revocation(
        &self,
        issuer: &KeyStateSnapshot,
        credential: &Said<'_>,
        party: &str,
    ) -> Result<(), Box<dyn Error>> {
        let vcp_message = parse_tel(&self.tel_wire[0])?;
        let iss_message = parse_tel(&self.tel_wire[1])?;
        let rev_message = parse_tel(&self.tel_wire[2])?;
        let view = issuer.view();
        let evidence = TelEvidence::Issuer {
            state: &view,
            anchor: None,
        };
        let signed_vcp = SignedTel::from(&vcp_message);
        let state = RegistryState::incept(&signed_vcp, &view)?;
        let signed_iss = SignedTel::from(&iss_message);
        let issued_state = state.ingest(&signed_iss, &evidence)?;
        let signed_rev = SignedTel::from(&rev_message);
        let revoked_state = issued_state.ingest(&signed_rev, &evidence)?;
        assert_eq!(
            revoked_state.vcstate(credential),
            CredentialStatus::Revoked,
            "{party}'s fold reads REVOKED"
        );

        // Negative: replaying the rev is an occupied sn (expected 2, got 1)
        // — contested, the duplicity path.
        let replay_err = revoked_state
            .ingest(&signed_rev, &evidence)
            .err()
            .ok_or("a replayed revocation must be rejected")?;
        assert!(
            matches!(
                replay_err,
                RegistryRejection::OutOfOrder {
                    expected: 2,
                    actual: 1
                }
            ),
            "the replay is an occupied-sn rejection: {replay_err:?}"
        );
        assert_eq!(
            replay_err.disposition(),
            Disposition::Contested,
            "an occupied sn routes to the duplicity judge, not escrow"
        );
        Ok(())
    }

    /// Fold ONLY the registry's seed (the vcp) and assert that a premature
    /// revocation — a rev on an empty chain — escrows as a sequence gap.
    fn assert_premature_rev_escrow(&self, issuer: &KeyStateSnapshot) -> Result<(), Box<dyn Error>> {
        let vcp_message = parse_tel(&self.tel_wire[0])?;
        let rev_message = parse_tel(&self.tel_wire[2])?;
        let view = issuer.view();
        let evidence = TelEvidence::Issuer {
            state: &view,
            anchor: None,
        };
        let signed_vcp = SignedTel::from(&vcp_message);
        let state = RegistryState::incept(&signed_vcp, &view)?;
        let signed_rev = SignedTel::from(&rev_message);
        let gap_err = state
            .ingest(&signed_rev, &evidence)
            .err()
            .ok_or("a premature revocation must be rejected")?;
        assert!(
            matches!(
                gap_err,
                RegistryRejection::OutOfOrder {
                    expected: 0,
                    actual: 1
                }
            ),
            "the premature rev is a gap: {gap_err:?}"
        );
        assert_eq!(
            gap_err.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 0 }),
            "a gap awaits the missing prior events in escrow"
        );
        Ok(())
    }

    /// Fold the registry from the wire through the iss, against `issuer`'s
    /// key state as evidence, and run `with` on the live state — the fold's
    /// borrows never escape this helper. Read-only closures only: further
    /// ingests need their own single-scope helper (see
    /// [`World::assert_revocation`]).
    fn with_iss_state<R>(
        &self,
        issuer: &KeyStateSnapshot,
        with: impl FnOnce(RegistryState<'_>, TelEvidence<'_>) -> Result<R, Box<dyn Error>>,
    ) -> Result<R, Box<dyn Error>> {
        let vcp_message = parse_tel(&self.tel_wire[0])?;
        let iss_message = parse_tel(&self.tel_wire[1])?;
        let view = issuer.view();
        let evidence = TelEvidence::Issuer {
            state: &view,
            anchor: None,
        };
        let signed_vcp = SignedTel::from(&vcp_message);
        let state = RegistryState::incept(&signed_vcp, &view)?;
        let signed_iss = SignedTel::from(&iss_message);
        let folded = state.ingest(&signed_iss, &evidence)?;
        with(folded, evidence)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut world = World::incept()?;
    let registry = world.create_registry()?;
    let issuance = world.issue(&registry)?;
    let grant = world.grant(&issuance)?;
    world.admit(&grant)?;
    world.verify(&registry, &issuance)?;
    world.revoke(&registry, &issuance)?;

    println!();
    println!("The vLEI loop, end to end, on the pure sans-io core:");
    println!("  identifiers exchanged (K1), a registry incepted (TEL vcp),");
    println!("  a credential issued (ACDC v1.1 + TEL iss) and anchored in the issuer's KEL,");
    println!("  granted and admitted over IPEX (exn), verified by the holder");
    println!("  against the registry fold, then revoked (TEL rev) — every phase asserted.");
    println!("No network, no database, no runtime — the \"vLEI loop without a database\"");
    println!(
        "counterpart to the direct_mode example. CI compiles this example for wasm32-unknown-unknown."
    );
    Ok(())
}
