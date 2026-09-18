//! Validation verdict types for the key-state fold.
use keri_events::SigningThresholdError;
use keri_events::ToadError;

/// Why an event was not accepted by the fold.
///
/// The fold's single verdict type. Variants that wrap a cesr or keri sub-error
/// carry it directly, so the precise cause survives (`?` lifts each source in via
/// [`From`]). [`disposition`](Self::disposition) classifies every variant as
/// [`Terminal`](Disposition::Terminal), [`Contested`](Disposition::Contested),
/// or [`Awaiting`](Disposition::Awaiting) specific evidence — the K2 escrow
/// verdict.
/// `#[non_exhaustive]` keeps additions non-breaking for external matchers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// Sequence number is not the expected next sn.
    ///
    /// Disposition: gap (`actual > expected`) is
    /// [`Awaiting(PriorEvents)`](EvidenceKind::PriorEvents) — keripy's
    /// out-of-order escrow (`.ooes`, `OutOfOrderError`); re-drive when the
    /// missing prior events arrive. Stale (`actual <= expected`) is
    /// [`Contested`](Disposition::Contested): the sn is already occupied, and
    /// keripy routes the event to the duplicity / superseding-recovery path —
    /// fetch the recorded event and consult
    /// [`KeyState::judge_same_sn`](crate::KeyState::judge_same_sn).
    #[error("out of order: expected sn {expected}, got {actual}")]
    OutOfOrder {
        /// The sn the fold expected next.
        expected: u128,
        /// The sn the event actually carried.
        actual: u128,
    },

    /// Prior-event digest does not match the current state's latest SAID.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal). Fires at the
    /// in-order sn, where keripy raises a bare `ValidationError` (drop).
    /// keripy's likely-duplicitous escrow (`.ldes`) concerns a *different*
    /// situation — a second event at an already-accepted sn — which is K3's
    /// duplicity verdict, not this rejection.
    #[error("prior-event digest does not match current state")]
    PriorDigestMismatch,

    /// The verified signatures do not satisfy the signing threshold.
    ///
    /// `verified` is the number of *distinct valid signature indices* after
    /// keripy `verifySigs`-parity filtering
    /// ([`Authority::verify`](crate::Authority::verify) skips a signature that
    /// fails verification or whose index addresses no key — never an error).
    /// `verified == 0` means *no verifiable controller signature*: the attached
    /// set was empty, all forged, or all out-of-range.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) when `verified == 0`
    /// (KERI spec: a message without at least one verifiable controller
    /// signature MUST be dropped, not escrowed — `DDoS` guard);
    /// [`Awaiting(Signatures)`](EvidenceKind::Signatures) when `verified >= 1`
    /// (spec SHOULD-escrow; keripy `.pses` via `escrowPSEvent` +
    /// `MissingSignatureError`). Re-drive trigger: more controller signatures
    /// for the same event version arrive.
    #[error("signing threshold not satisfied: {verified} verified signature(s)")]
    MissingSignatures {
        /// How many distinct valid signature indices the filtered set holds.
        verified: usize,
    },

    /// The event's signing threshold is not well-formed for its key set.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy raises a
    /// bare `ValidationError` (drop) for an invalid sith.
    #[error(transparent)]
    MalformedThreshold(#[from] SigningThresholdError),

    /// The verified signatures do not expose enough prior next keys to
    /// satisfy the prior next threshold.
    ///
    /// A signature exposes a prior next key when its `ondex` selects a
    /// committed digest and the revealed current key at its `index` hashes
    /// to that digest under the committed digest's own code. Signatures with
    /// no `ondex`, an out-of-range `ondex`, or a digest mismatch are
    /// skipped and contribute nothing.
    ///
    /// Disposition:
    /// [`Awaiting(Signatures)`](EvidenceKind::Signatures) — keripy's
    /// partially-signed escrow (`.pses` via `escrowPSEvent` +
    /// `MissingSignatureError`, `src/keri/core/eventing.py:2877-2885`).
    /// Divergence D2 from the K2 design doc is closed by #132; more
    /// controller signatures for the same event version are the re-drive
    /// trigger.
    #[error("prior next threshold not satisfied: {exposed} exposed prior-next key(s)")]
    PriorNextThresholdUnsatisfied {
        /// Distinct prior-next indices exposed by verified signatures.
        exposed: usize,
    },

    /// A rotation's witness cut/add deltas are inconsistent.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy's backer
    /// derivation raises a bare `ValidationError` (drop) for every cut/add
    /// algebra violation.
    #[error(transparent)]
    WitnessSet(#[from] WitnessSetError),

    /// The witness threshold (`TOAD`) is out of bounds for the witness set.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops
    /// out-of-bounds toads with a bare `ValidationError`.
    #[error("witness threshold {toad} exceeds {count} witnesses")]
    WitnessThresholdExceeded {
        /// The declared threshold of accountable duplicity.
        toad: u32,
        /// The number of witnesses available.
        count: usize,
    },

    /// Fewer distinct witnesses than the `TOAD` requires have a valid receipt
    /// over the event.
    ///
    /// Disposition:
    /// [`Awaiting(WitnessReceipts)`](EvidenceKind::WitnessReceipts) —
    /// keripy's partially-witnessed escrow (`.pwes`, `escrowPWEvent` +
    /// `MissingWitnessSignatureError`). Re-drive when further witness
    /// receipts arrive.
    #[error("witness receipts below threshold: {valid} valid of {required} required")]
    InsufficientWitnessReceipts {
        /// Distinct witnesses whose receipt verified.
        valid: usize,
        /// The governing threshold of accountable duplicity (TOAD).
        required: u32,
    },

    /// The inception violates the transferability / next-key agreement rule:
    /// a non-transferable prefix must not commit to next keys.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — inception content
    /// is self-contradictory; keripy drops it with a bare `ValidationError`
    /// (eventing.py:2374-2378). The former self-addressing-without-next-keys
    /// rejection was removed by #250: the spec requires such an inception to
    /// be accepted and deemed non-transferable (see
    /// [`NonTransferableState`](Self::NonTransferableState)).
    #[error(transparent)]
    Transferability(#[from] TransferabilityError),

    /// A delegation rule was violated (K4). See [`DelegationError`] for the
    /// specific rule and its keripy/escrow anchor.
    ///
    /// Disposition: per sub-variant — see [`DelegationError`].
    #[error(transparent)]
    Delegation(#[from] DelegationError),

    /// Any event on a non-transferable or abandoned key state: the state
    /// commits to no next keys (empty-`n` inception, or abandonment via an
    /// empty-`n` rotation), so its KEL admits no more key events (spec MUST).
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops with a
    /// bare `ValidationError` ("Unexpected event … is nontransferable or
    /// abandoned state", eventing.py:2477). No evidence can re-open a closed
    /// KEL, so there is no re-drive trigger.
    #[error("no more key events: key state is non-transferable or abandoned")]
    NonTransferableState,

    /// The event violates a structural rule (shape, arity, message type
    /// placement, ranges).
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — the KERI spec
    /// requires config-trait violations to be invalidated ("MUST … drop"),
    /// and the remaining shape/arity/range violations are functions of the
    /// event's own content. The one exception is
    /// [`DuplicateInception`](StructuralError::DuplicateInception):
    /// [`Contested`](Disposition::Contested) — keripy routes a second
    /// inception to the duplicate/duplicitous branch, so the host must fetch
    /// the recorded genesis and consult
    /// [`KeyState::judge_same_sn`](crate::KeyState::judge_same_sn).
    #[error(transparent)]
    Structural(#[from] StructuralError),
}

/// What a host should do with a rejected event.
///
/// Escrow as a pure classification: `keri-rs` owes only the verdict on the
/// fold's [`Rejection`] — parking, retry scheduling, timeouts, and storage
/// are entirely the host's (an event-sourced host records "awaiting X" as its
/// own state and re-drives the event when X arrives). Both enums here are
/// deliberately exhaustive: a new evidence kind (K4 delegation, K5 receipt
/// evidence) must be a compile error in hosts, not a silently-parked event
/// that never re-drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Never acceptable — drop or report.
    Terminal,
    /// The sn is already occupied: fetch the recorded event at that sn (plus
    /// delegating-event pairs for a delegated contest) and consult
    /// [`KeyState::judge_same_sn`](crate::KeyState::judge_same_sn) — the
    /// event may be a duplicate, duplicitous, or a superseding recovery.
    Contested,
    /// Acceptable the moment this evidence arrives — park and re-drive.
    Awaiting(EvidenceKind),
}

/// The specific evidence whose arrival makes a parked event acceptable.
///
/// Each variant names the keripy escrow whose *outcome* it reproduces
/// (semantics, not tables — see the K2 design doc for line-anchored
/// evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// The KEL events between the accepted head and `expected_sn`.
    /// keripy `.ooes` (out-of-order escrow). Re-drive when the prior
    /// event(s) arrive and fold in order.
    PriorEvents {
        /// The sequence number the fold expected next.
        expected_sn: u128,
    },
    /// More controller signatures for the same event version.
    /// keripy `.pses` (partially-signed escrow). Re-drive when new
    /// signatures arrive, attached to the event or to a receipt of it.
    Signatures,
    /// More witness receipts over the event. keripy `.pwes` (partially
    /// witnessed escrow). Re-drive when further receipts arrive.
    WitnessReceipts {
        /// Distinct witnesses whose receipt verified.
        valid: usize,
        /// The governing threshold of accountable duplicity (`TOAD`).
        required: u32,
    },
    /// The delegator's authorizing evidence for a delegated event.
    /// keripy `.pdes`/`.udes` (partially/unverified delegated escrow).
    /// Re-drive through [`KeyState::incept_delegated`](crate::KeyState::incept_delegated)/[`KeyState::ingest_delegated`](crate::KeyState::ingest_delegated)
    /// with the delegator's evidence.
    DelegationEvidence,
    /// The transferable receiptor's establishment event at the coordinate
    /// the endorsement names. keripy's unverified transferable-receipt
    /// escrow (`escrowTReceipts` + `UnverifiedTransferableReceiptError`,
    /// eventing.py:4604-4610). Re-drive
    /// [`ReceiptedEvent::endorsed_by`](crate::ReceiptedEvent::endorsed_by)
    /// with the evidence once the host's stream/query produces it.
    ReceiptorEstablishment,
    /// The registry-management TEL event (the `vcp` or latest `vrt`) at the
    /// coordinate a backer event's `ra` anchor names. keripy's
    /// `getBackerState` raises "have to escrow this somewhere" when the
    /// anchored event is not recorded (`vdr/eventing.py:1255-1266`). Re-drive
    /// the backer event once the anchored management event has folded in.
    TelAnchor {
        /// The management-chain sequence number the anchor names.
        sn: u128,
    },
}

impl Rejection {
    /// Classify this rejection: [`Terminal`](Disposition::Terminal),
    /// [`Contested`](Disposition::Contested), or
    /// [`Awaiting`](Disposition::Awaiting) specific evidence.
    ///
    /// Total over every variant with no wildcard arm, so a new [`Rejection`]
    /// variant forces a decision here at compile time. The rule: **awaiting**
    /// iff more host-supplied evidence (prior events, signatures, receipts,
    /// delegator approval) can change the verdict on re-drive; **contested**
    /// iff the sn is already occupied and the same-sn judge decides;
    /// **terminal** iff the verdict is a function of the event's own content
    /// plus accepted state alone, so re-driving the same event can never
    /// succeed.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            // A second inception contests the recorded genesis: keripy routes
            // it to the duplicate/duplicitous branch, so the same-sn judge
            // decides — carved out ahead of the blanket Structural coverage.
            Self::Structural(StructuralError::DuplicateInception) => Disposition::Contested,
            Self::PriorDigestMismatch
            | Self::MalformedThreshold(_)
            | Self::WitnessSet(_)
            | Self::WitnessThresholdExceeded { .. }
            | Self::Transferability(_)
            | Self::NonTransferableState
            | Self::Structural(_)
            | Self::MissingSignatures { verified: 0 } => Disposition::Terminal,
            Self::PriorNextThresholdUnsatisfied { .. } => {
                Disposition::Awaiting(EvidenceKind::Signatures)
            }
            Self::OutOfOrder { expected, actual } => {
                if *actual > *expected {
                    Disposition::Awaiting(EvidenceKind::PriorEvents {
                        expected_sn: *expected,
                    })
                } else {
                    // Stale: the "missing prior" already exists, so no
                    // evidence arrival can cure it. keripy routes sn <= sno
                    // to the duplicity / superseding-recovery path — the
                    // same-sn judge decides.
                    Disposition::Contested
                }
            }
            Self::MissingSignatures { .. } => Disposition::Awaiting(EvidenceKind::Signatures),
            Self::Delegation(
                DelegationError::EvidenceRequired
                | DelegationError::SealNotFound
                | DelegationError::DelegatorMismatch,
            ) => Disposition::Awaiting(EvidenceKind::DelegationEvidence),
            Self::Delegation(DelegationError::Denied | DelegationError::DelegatorUnknown) => {
                Disposition::Terminal
            }
            Self::InsufficientWitnessReceipts { valid, required } => {
                Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                    valid: *valid,
                    required: *required,
                })
            }
        }
    }
}

/// Why a TEL event was not accepted by the registry-state fold.
///
/// The registry fold's single verdict type, mapped to keripy's `Tevery`
/// dispositions (`vdr/eventing.py`, pin `de59bc7d`). Variants that wrap a
/// shared sub-error carry it directly, so the precise cause survives (`?`
/// lifts each source in via [`From`]). [`disposition`](Self::disposition)
/// classifies every variant as [`Terminal`](Disposition::Terminal),
/// [`Contested`](Disposition::Contested), or [`Awaiting`](Disposition::Awaiting)
/// specific evidence — the escrow verdict.
///
/// `#[non_exhaustive]` keeps additions non-breaking for external matchers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryRejection {
    /// A `vcp` arrived for a registry this fold already governs.
    ///
    /// keripy routes a first-seen `vcp` whose registry is already known to the
    /// likely-duplicitous branch (`LikelyDuplicitousError`,
    /// `vdr/eventing.py:1888-1906`) — the host fetches the recorded event and
    /// judges by SAID.
    ///
    /// Disposition: [`Contested`](Disposition::Contested).
    #[error("duplicate registry inception")]
    DuplicateInception,

    /// The event names a registry this fold does not govern: a `vrt`'s `i`, an
    /// `iss`/`rev`'s `ri`, a `bis`'s `ii`, or a `brv`'s `ra.i` that is not this
    /// registry's id.
    ///
    /// keripy: `MissingRegistryError` — the `registryKey` dispatch never finds
    /// a `Tever` for the named registry.
    /// Disposition: [`Terminal`](Disposition::Terminal) — another registry's
    /// fold governs it.
    #[error("event names an unknown registry")]
    MissingRegistry,

    /// The signing evidence does not resolve as the event's authority: the
    /// supplied key state is not the registry's issuer's, backer evidence
    /// arrived for an issuer-signed event (or the reverse), or the endorser is
    /// not a current backer.
    ///
    /// keripy: `MissingIssuerError` — the signing identity is missing from the
    /// verifier's authority tables (and a non-backer's signature can never
    /// verify, since keripy derives the verification keys from the recorded
    /// backer list).
    /// Disposition: [`Terminal`](Disposition::Terminal).
    #[error("event's signing authority does not resolve for this registry")]
    MissingIssuer,

    /// A `vrt` arrived without anchor evidence, or the supplied anchoring KEL
    /// event carries no event seal naming the rotation's `(i, s, d)`.
    ///
    /// keripy: `MissingAnchorError` (`verifyAnchor`, `vdr/eventing.py:1410-1437`).
    /// Disposition: [`Terminal`](Disposition::Terminal) per the registry fold
    /// table.
    #[error("rotation's anchoring event seal did not verify")]
    MissingAnchor,

    /// Sequence number is not the expected next sn on the registry chain
    /// (`vrt`) or the credential chain (`iss`/`rev`/`bis`/`brv`).
    ///
    /// Disposition: gap (`actual > expected`) is
    /// [`Awaiting(PriorEvents)`](EvidenceKind::PriorEvents) — keripy's
    /// out-of-order escrow (`.ooes`); stale (`actual <= expected`) is
    /// [`Contested`](Disposition::Contested) — keripy routes the occupied sn
    /// to the duplicity path and the host judges by SAID.
    #[error("out of order: expected sn {expected}, got {actual}")]
    OutOfOrder {
        /// The sn the fold expected next.
        expected: u128,
        /// The sn the event actually carried.
        actual: u128,
    },

    /// A chain event's prior-event digest does not match the recorded head at
    /// the in-order sn (a `vrt`'s `p`, or a `rev`/`brv`'s `p`).
    ///
    /// keripy raises a bare `ValidationError` (drop) at this point
    /// (`vdr/eventing.py:996-1000,1137-1145`).
    /// Disposition: [`Terminal`](Disposition::Terminal).
    #[error("prior-event digest does not match the recorded chain head")]
    PriorDigestMismatch,

    /// A backer event's `ra` anchor does not name this registry's current
    /// management head — the anchored `vcp`/`vrt` is not recorded yet (or a
    /// later rotation superseded it).
    ///
    /// keripy: `getBackerState`'s "have to escrow this somewhere"
    /// (`vdr/eventing.py:1255-1266`).
    /// Disposition: [`Awaiting(TelAnchor)`](EvidenceKind::TelAnchor) — re-drive
    /// when the anchored management event governs the head.
    #[error("backer anchor does not resolve against management head at sn {sn}")]
    UnresolvedAnchor {
        /// The management-chain sn the anchor names.
        sn: u128,
    },

    /// A rotation's backer cut/add deltas are inconsistent.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy's `rotate`
    /// set relations raise a bare `ValidationError` (drop).
    #[error(transparent)]
    BackerSet(#[from] WitnessSetError),

    /// The backer threshold is out of bounds for the (resolved) backer set.
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal) — keripy drops for the
    /// toad-law violation.
    #[error(transparent)]
    BackerThreshold(#[from] ToadError),

    /// Signature verification failed through the shared
    /// [`Authority::verify`](crate::Authority::verify) path — in practice
    /// always [`Rejection::MissingSignatures`], whose own disposition applies
    /// (zero verifiable signatures are terminal, one-or-more await more).
    #[error(transparent)]
    Signatures(#[from] Rejection),

    /// A structural agreement rule failed. See [`RegistryStructuralError`].
    ///
    /// Disposition: [`Terminal`](Disposition::Terminal).
    #[error(transparent)]
    Structural(#[from] RegistryStructuralError),
}

impl RegistryRejection {
    /// Classify this rejection: [`Terminal`](Disposition::Terminal),
    /// [`Contested`](Disposition::Contested), or
    /// [`Awaiting`](Disposition::Awaiting) specific evidence.
    ///
    /// Total over every variant with no wildcard arm, so a new
    /// [`RegistryRejection`] variant forces a decision here at compile time.
    /// The rule mirrors [`Rejection::disposition`]: **awaiting** iff more
    /// host-supplied evidence (management events, prior chain events,
    /// signatures) can change the verdict on re-drive; **contested** iff the
    /// sn is already occupied and a same-sn judge decides; **terminal** iff
    /// the verdict is a function of the event's own content plus accepted
    /// state alone.
    #[must_use]
    pub const fn disposition(&self) -> Disposition {
        match self {
            Self::DuplicateInception => Disposition::Contested,
            Self::MissingRegistry
            | Self::MissingIssuer
            | Self::MissingAnchor
            | Self::PriorDigestMismatch
            | Self::BackerSet(_)
            | Self::BackerThreshold(_)
            | Self::Structural(_) => Disposition::Terminal,
            Self::OutOfOrder { expected, actual } => {
                if *actual > *expected {
                    Disposition::Awaiting(EvidenceKind::PriorEvents {
                        expected_sn: *expected,
                    })
                } else {
                    Disposition::Contested
                }
            }
            Self::UnresolvedAnchor { sn } => {
                Disposition::Awaiting(EvidenceKind::TelAnchor { sn: *sn })
            }
            Self::Signatures(inner) => inner.disposition(),
        }
    }
}

/// Structural agreement rules the registry fold enforces beyond per-event
/// guard order — each a mismatch between the event's kind and the registry's
/// recorded configuration.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryStructuralError {
    /// [`RegistryState::incept`](crate::RegistryState::incept) was called with
    /// a non-`vcp` event.
    #[error("registry inception called with a non-vcp event")]
    NotRegistryInception,

    /// The `NoBackers` configuration trait is set but the inception seeds a
    /// non-empty backer set. keripy's `incept` factory raises this at
    /// `vdr/eventing.py:89`; the TEL parser does not enforce the agreement, so
    /// the fold rejects it for parsed events.
    #[error("the NoBackers trait is set but the inception seeds backers")]
    NoBackersWithBackers,

    /// A simple `iss`/`rev` against a backer-based registry (keripy `issue`/
    /// `revoke`: "invalid simple issue evt against backer based registry",
    /// `vdr/eventing.py:1065,1146`).
    #[error("a backer-based registry does not accept simple issue/revoke events")]
    SimpleEventOnBackerRegistry,

    /// A `bis`/`brv` against a backerless registry (keripy `backerIssue`/
    /// `backerRevoke`: "invalid backer issue evt against backerless registry",
    /// `vdr/eventing.py:1086,1160`).
    #[error("a backerless registry does not accept backer issue/revoke events")]
    BackedEventOnBackerlessRegistry,

    /// A `vrt` against a backerless registry (keripy `rotate`: "invalid
    /// rotation evt against backerless registry", `vdr/eventing.py:910`).
    #[error("a backerless registry does not accept rotations")]
    RotationOnBackerlessRegistry,

    /// The registry chain's expected next sequence number overflows `u128`.
    #[error("registry chain sequence number overflows")]
    SequenceNumberOverflow,
}

/// Exn ingest verification failures: the two distinct verdict domains of
/// verifying a signed exchange envelope against the sender's key state.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// The envelope's declared sender is not the verifying key state's
    /// identifier — the evidence cannot authorize this envelope.
    #[error("exchange sender does not match the verifying key state's prefix")]
    SenderMismatch,

    /// Signature verification failure through the shared
    /// [`Authority::verify`](crate::Authority::verify) path.
    #[error(transparent)]
    Signatures(#[from] Rejection),
}

/// Witness cut/add algebra failures during a rotation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WitnessSetError {
    /// A witness removal names a prefix that is not a current witness.
    #[error("witness removal names a prefix that is not a current witness")]
    RemovalNotCurrent,
    /// A prefix appears in both the witness cut and add sets.
    #[error("a prefix appears in both the witness cut and add sets")]
    CutAddOverlap,
    /// A witness addition names a prefix already in the set.
    #[error("witness addition names a prefix already in the set")]
    AdditionAlreadyPresent,
}

/// Delegation-rule violations for delegated establishment events (K4).
///
/// Spec anchors (kswg-keri-specification, §Cooperative Delegation and
/// §Configuration Traits): a validator MUST be given or find the delegating
/// seal in the delegator's KEL, and MUST drop delegated events whose
/// delegator carries the do-not-delegate trait.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DelegationError {
    /// A dip/drt reached a plain fold entry
    /// ([`KeyState::incept`](crate::KeyState::incept)/[`KeyState::ingest`](crate::KeyState::ingest))
    /// without evidence — keripy's delegated escrows (`.pdes`/`.udes`).
    /// Park and re-drive through the delegated entry once the host has
    /// evidence.
    #[error("delegated event requires delegation evidence")]
    EvidenceRequired,
    /// The supplied delegating event carries no event-seal matching the
    /// delegated event's `(i, s, d)` (keripy nullifies the couple and
    /// escrows — eventing.py:3389-3400; better evidence cures).
    #[error("delegating event carries no seal of the delegated event")]
    SealNotFound,
    /// The supplied delegator state does not match the event's declared
    /// delegator (dip `di` / drt state) or the delegating event's prefix —
    /// evidence for the wrong identifier; correct evidence cures.
    #[error("delegation evidence names a different delegator")]
    DelegatorMismatch,
    /// A delegated rotation on a state that carries no delegator: the
    /// identifier was not incepted as delegated, so no evidence can make a
    /// drt valid.
    #[error("delegated rotation on a non-delegated identifier")]
    DelegatorUnknown,
    /// The delegator carries the do-not-delegate config trait (spec MUST
    /// drop; keripy `doNotDelegate` — eventing.py:3293-3299).
    #[error("delegator does not allow delegation")]
    Denied,
}

/// Transferability / next-key commitment rule violations at inception.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransferabilityError {
    /// A non-transferable prefix must not commit to next keys.
    #[error("a non-transferable prefix must not commit to next keys")]
    NonTransferableCommitsNextKeys,
}

/// Structural rule violations — event shape, arity, and range guards.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StructuralError {
    /// `incept` was called on a non-inception event.
    #[error("incept called on a non-inception event")]
    NotInception,
    /// `incept_delegated` was called on a non-delegated-inception event.
    #[error("incept_delegated called on a non-delegated-inception event")]
    NotDelegatedInception,
    /// `ingest_delegated` was called on a non-delegated-rotation event.
    #[error("ingest_delegated called on a non-delegated-rotation event")]
    NotDelegatedRotation,
    /// A genesis event carried a non-zero sequence number.
    #[error("genesis event has non-zero sequence number {sn}")]
    NonZeroGenesisSn {
        /// The offending sequence number.
        sn: u128,
    },
    /// A second inception event cannot advance an existing state.
    #[error("a second inception event cannot advance state")]
    DuplicateInception,
    /// An interaction event under the establishment-only config trait.
    #[error("an interaction is not allowed under the establishment-only config")]
    InteractionOnEstablishmentOnly,
    /// `prior_sn + 1` overflowed `u128`.
    #[error("sequence number overflowed")]
    SequenceNumberOverflow,
    /// A witness count exceeded the addressable range (defensive guard).
    #[error("witness count exceeds addressable range")]
    WitnessCountOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_carries_sn_context() {
        let r = Rejection::OutOfOrder {
            expected: 1,
            actual: 4,
        };
        assert!(matches!(
            r,
            Rejection::OutOfOrder {
                expected: 1,
                actual: 4
            }
        ));
    }

    #[test]
    fn threshold_error_maps_to_malformed_threshold() {
        let r = Rejection::from(SigningThresholdError::BelowMinimum);
        assert!(matches!(
            r,
            Rejection::MalformedThreshold(SigningThresholdError::BelowMinimum)
        ));
    }

    #[test]
    fn witness_set_error_maps_to_witness_set() {
        let r = Rejection::from(WitnessSetError::RemovalNotCurrent);
        assert!(matches!(
            r,
            Rejection::WitnessSet(WitnessSetError::RemovalNotCurrent)
        ));
    }

    #[test]
    fn transferability_error_maps_to_transferability() {
        let r = Rejection::from(TransferabilityError::NonTransferableCommitsNextKeys);
        assert!(matches!(
            r,
            Rejection::Transferability(TransferabilityError::NonTransferableCommitsNextKeys)
        ));
    }

    #[test]
    fn non_transferable_state_is_terminal() {
        assert_eq!(
            Rejection::NonTransferableState.disposition(),
            Disposition::Terminal
        );
    }

    #[test]
    fn structural_error_maps_to_structural() {
        let r = Rejection::from(StructuralError::DuplicateInception);
        assert!(matches!(
            r,
            Rejection::Structural(StructuralError::DuplicateInception)
        ));
    }

    #[test]
    fn out_of_order_gap_awaits_prior_events() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 7,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 3 })
        );
    }

    #[test]
    fn out_of_order_stale_is_contested() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 2,
        };
        assert_eq!(r.disposition(), Disposition::Contested);
    }

    #[test]
    fn out_of_order_stale_at_u128_boundary_is_contested() {
        let r = Rejection::OutOfOrder {
            expected: u128::MAX,
            actual: 0,
        };
        assert_eq!(r.disposition(), Disposition::Contested);
    }

    #[test]
    fn duplicate_inception_is_contested() {
        let r = Rejection::from(StructuralError::DuplicateInception);
        assert_eq!(r.disposition(), Disposition::Contested);
    }

    #[test]
    fn out_of_order_minimal_gap_awaits_prior_events() {
        let r = Rejection::OutOfOrder {
            expected: 3,
            actual: 4,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 3 })
        );
    }

    #[test]
    fn zero_verified_signatures_is_terminal() {
        let r = Rejection::MissingSignatures { verified: 0 };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn one_verified_signature_below_threshold_awaits_signatures() {
        let r = Rejection::MissingSignatures { verified: 1 };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::Signatures)
        );
    }

    #[test]
    fn insufficient_witness_receipts_awaits_receipts() {
        let r = Rejection::InsufficientWitnessReceipts {
            valid: 1,
            required: 3,
        };
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::WitnessReceipts {
                valid: 1,
                required: 3
            })
        );
    }

    #[test]
    fn delegation_evidence_required_awaits_delegation_evidence() {
        let r = Rejection::from(DelegationError::EvidenceRequired);
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn delegation_seal_not_found_awaits_delegation_evidence() {
        let r = Rejection::from(DelegationError::SealNotFound);
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn delegation_delegator_mismatch_awaits_delegation_evidence() {
        let r = Rejection::from(DelegationError::DelegatorMismatch);
        assert_eq!(
            r.disposition(),
            Disposition::Awaiting(EvidenceKind::DelegationEvidence)
        );
    }

    #[test]
    fn delegation_denied_is_terminal() {
        let r = Rejection::from(DelegationError::Denied);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn delegator_unknown_is_terminal() {
        let r = Rejection::from(DelegationError::DelegatorUnknown);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn delegation_error_maps_to_delegation() {
        let r = Rejection::from(DelegationError::EvidenceRequired);
        assert!(matches!(
            r,
            Rejection::Delegation(DelegationError::EvidenceRequired)
        ));
    }

    #[test]
    fn not_delegated_entry_structural_errors_are_terminal() {
        assert_eq!(
            Rejection::from(StructuralError::NotDelegatedInception).disposition(),
            Disposition::Terminal
        );
        assert_eq!(
            Rejection::from(StructuralError::NotDelegatedRotation).disposition(),
            Disposition::Terminal
        );
    }

    #[test]
    fn prior_digest_mismatch_is_terminal() {
        assert_eq!(
            Rejection::PriorDigestMismatch.disposition(),
            Disposition::Terminal
        );
    }

    #[test]
    fn malformed_threshold_is_terminal() {
        let r = Rejection::from(SigningThresholdError::BelowMinimum);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn prior_next_threshold_unsatisfied_awaits_signatures() {
        assert_eq!(
            Rejection::PriorNextThresholdUnsatisfied { exposed: 0 }.disposition(),
            Disposition::Awaiting(EvidenceKind::Signatures)
        );
    }

    #[test]
    fn witness_set_error_is_terminal() {
        let r = Rejection::from(WitnessSetError::RemovalNotCurrent);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn witness_threshold_exceeded_is_terminal() {
        let r = Rejection::WitnessThresholdExceeded { toad: 3, count: 2 };
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn transferability_error_is_terminal() {
        let r = Rejection::from(TransferabilityError::NonTransferableCommitsNextKeys);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }

    #[test]
    fn structural_error_is_terminal() {
        let r = Rejection::from(StructuralError::InteractionOnEstablishmentOnly);
        assert_eq!(r.disposition(), Disposition::Terminal);
    }
}
