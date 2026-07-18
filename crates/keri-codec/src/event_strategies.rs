//! Shared proptest strategies over the builder-reachable KERI event space.
//!
//! Single source of truth for the structural-oracle (write path) and
//! strict-vs-reference (read path) differential property tests.

#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{
    borrow::Cow, borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec,
};
use cesr::core::matter::builder::MatterBuilder;
use cesr::core::matter::code::{DigestCode, VerKeyCode, VerserCode};
use cesr::core::primitives::{Prefixer, Saider, Verser};
use keri_events::threshold_form::ThresholdForm;
use keri_events::toad::Toad;
use keri_events::{
    ConfigTrait, Identifier, InceptionEvent, InteractionEvent, OpaqueSeal, RotationEvent, Seal,
    SequenceNumber, SigningThreshold, WeightedThreshold,
};
use proptest::prelude::*;

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn prefixer(raw: [u8; 32]) -> Prefixer<'static> {
    MatterBuilder::new()
        .with_code(VerKeyCode::Ed25519)
        .with_raw(Cow::<[u8]>::Owned(raw.to_vec()))
        .unwrap()
        .build()
        .unwrap()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn saider(raw: [u8; 32]) -> Saider<'static> {
    MatterBuilder::new()
        .with_code(DigestCode::Blake3_256)
        .with_raw(Cow::<[u8]>::Owned(raw.to_vec()))
        .unwrap()
        .build()
        .unwrap()
}

const VERSER_POOL: &[&str] = &["YKERIBAA", "YKERICAA", "YACDCBAA"];

/// Compact-JSON opaque anchor payloads. Constraints, both load-bearing:
/// no exact codex key set (those parse typed or error, never opaque), and
/// normalization-stable spelling (integers in i64 range, minimal string
/// escaping, no floats or `\uXXXX`) so the tolerant oracle's
/// Value-round-tripped opaque matches the strict path's verbatim span in
/// the strict-vs-oracle differential properties.
const OPAQUE_POOL: &[&str] = &[
    "{}",
    "{\"x\":1}",
    "{\"d\":\"EJPymiKPV7UD9EmynqY9j8c-mBRcH0vQ-7jD3nqa-z9-\",\"extra\":true}",
    "{\"i\":\"not-qb64\",\"note\":\"arbitrary\"}",
    "{\"nested\":{\"deep\":[1,-25000000000,{\"q\":\"say \\\"hi\\\"\"}]},\"n\":null}",
];

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn verser(pick: u8) -> Verser<'static> {
    let qb64 = VERSER_POOL[usize::from(pick) % VERSER_POOL.len()];
    MatterBuilder::new()
        .from_qualified_base64(qb64.as_bytes())
        .unwrap()
        .narrow::<VerserCode>()
        .unwrap()
        .into_static()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn opaque(pick: u8) -> OpaqueSeal<'static> {
    let raw = OPAQUE_POOL[usize::from(pick) % OPAQUE_POOL.len()];
    OpaqueSeal::new_unchecked(raw)
}

/// A plain-data spec that both generates itself (proptest) and builds its
/// corresponding domain event. One entry point per spec: `Spec::strategy()`
/// to generate, `spec.build()` to realize.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) trait EventSpec: Sized {
    /// The domain value this spec builds.
    type Event;
    /// A proptest strategy generating values of this spec.
    fn strategy() -> impl Strategy<Value = Self>;
    /// Realize the domain value from this spec.
    fn build(self) -> Self::Event;
}

// Strategies emit plain-data specs (all `Debug`) and the test bodies
// build domain events from them — the event types deliberately do not
// implement `Debug`.

/// (basic?, raw) -> Identifier
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) type IdSpec = (bool, [u8; 32]);
/// (variant selector 0..8, raw a, raw b, sn) -> Seal.
///
/// Selector: 0 Digest, 1 Root, 2 Source, 3 Event, 4 Last, 5 Back, 6 Kind,
/// 7 Opaque. `a`/`b` feed [`saider`]/[`prefixer`] for the typed variants and
/// double as pool-index bytes (`a[0]`) for [`verser`]/[`opaque`]'s bounded
/// pools.
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) type SealSpec = (u8, [u8; 32], [u8; 32], u128);
/// (simple?, simple value, weighted clauses) -> Tholder
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) type TholderSpec = (bool, u64, Vec<Vec<(u64, u64)>>);
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) type IcpSpec = (
    IdSpec,
    u128,
    [u8; 32],
    Vec<[u8; 32]>,
    TholderSpec,
    Vec<[u8; 32]>,
    TholderSpec,
    Vec<[u8; 32]>,
    u32,
    Vec<bool>,
    Vec<SealSpec>,
);
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) type RotSpec = (
    IdSpec,
    u128,
    [u8; 32],
    [u8; 32],
    Vec<[u8; 32]>,
    TholderSpec,
    Vec<[u8; 32]>,
    TholderSpec,
    Vec<[u8; 32]>,
    u32,
    Vec<SealSpec>,
);
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) type IxnSpec = (IdSpec, u128, [u8; 32], [u8; 32], Vec<SealSpec>);

impl EventSpec for IdSpec {
    type Event = Identifier<'static>;

    fn strategy() -> impl Strategy<Value = Self> {
        any::<Self>()
    }

    fn build(self) -> Self::Event {
        let (basic, raw) = self;
        if basic {
            Identifier::Basic(prefixer(raw))
        } else {
            Identifier::SelfAddressing(saider(raw))
        }
    }
}

impl EventSpec for SealSpec {
    type Event = Seal<'static>;

    fn strategy() -> impl Strategy<Value = Self> {
        (0_u8..8, any::<[u8; 32]>(), any::<[u8; 32]>(), sn_strategy())
    }

    fn build(self) -> Self::Event {
        let (variant, a, b, sn) = self;
        match variant {
            0 => Seal::Digest { d: saider(a) },
            1 => Seal::Root { rd: saider(a) },
            2 => Seal::Source {
                s: SequenceNumber::new(sn),
                d: saider(a),
            },
            3 => Seal::Event {
                i: prefixer(b),
                s: SequenceNumber::new(sn),
                d: saider(a),
            },
            5 => Seal::Back {
                bi: prefixer(b),
                d: saider(a),
            },
            6 => Seal::Kind {
                t: verser(a[0]),
                d: saider(a),
            },
            7 => Seal::Opaque(opaque(a[0])),
            _ => Seal::Last { i: prefixer(a) },
        }
    }
}

impl EventSpec for TholderSpec {
    type Event = SigningThreshold;

    fn strategy() -> impl Strategy<Value = Self> {
        (
            any::<bool>(),
            prop_oneof![Just(0_u64), Just(1_u64), Just(u64::MAX), any::<u64>()],
            proptest::collection::vec(
                proptest::collection::vec((0_u64..=3, 0_u64..=3), 0..4),
                0..4,
            ),
        )
    }

    fn build(self) -> Self::Event {
        let (simple, value, clauses) = self;
        if simple {
            SigningThreshold::Simple(value)
        } else {
            SigningThreshold::Weighted(
                WeightedThreshold::from_nested(clauses)
                    .expect("strategy clauses stay well within the u32 weight bound"),
            )
        }
    }
}

impl EventSpec for IcpSpec {
    type Event = InceptionEvent<'static>;

    fn strategy() -> impl Strategy<Value = Self> {
        (
            any::<IdSpec>(),
            sn_strategy(),
            any::<[u8; 32]>(),
            proptest::collection::vec(any::<[u8; 32]>(), 0..3),
            TholderSpec::strategy(),
            proptest::collection::vec(any::<[u8; 32]>(), 0..3),
            TholderSpec::strategy(),
            proptest::collection::vec(any::<[u8; 32]>(), 0..3),
            bt_strategy(),
            proptest::collection::vec(any::<bool>(), 0..3),
            proptest::collection::vec(SealSpec::strategy(), 0..3),
        )
    }

    fn build(self) -> Self::Event {
        let (prefix, sn, said, keys, kt, next, nt, wits, bt, config, anchors) = self;
        InceptionEvent::new(
            prefix.build(),
            SequenceNumber::new(sn),
            saider(said),
            keys.into_iter().map(prefixer).collect(),
            kt.build(),
            next.into_iter().map(saider).collect(),
            nt.build(),
            wits.into_iter().map(prefixer).collect(),
            Toad::from_wire(bt),
            config
                .iter()
                .map(|p| {
                    if *p {
                        ConfigTrait::EstOnly
                    } else {
                        ConfigTrait::DoNotDelegate
                    }
                })
                .collect(),
            anchors.into_iter().map(SealSpec::build).collect(),
            ThresholdForm::HexString,
        )
    }
}

impl EventSpec for RotSpec {
    type Event = RotationEvent<'static>;

    fn strategy() -> impl Strategy<Value = Self> {
        (
            any::<IdSpec>(),
            sn_strategy(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            proptest::collection::vec(any::<[u8; 32]>(), 0..3),
            TholderSpec::strategy(),
            proptest::collection::vec(any::<[u8; 32]>(), 0..3),
            TholderSpec::strategy(),
            proptest::collection::vec(any::<[u8; 32]>(), 0..3),
            bt_strategy(),
            proptest::collection::vec(SealSpec::strategy(), 0..3),
        )
    }

    fn build(self) -> Self::Event {
        let (prefix, sn, said, prior, keys, kt, next, nt, wits, bt, anchors) = self;
        RotationEvent::new(
            prefix.build(),
            SequenceNumber::new(sn),
            saider(said),
            saider(prior),
            keys.into_iter().map(prefixer).collect(),
            kt.build(),
            next.into_iter().map(saider).collect(),
            nt.build(),
            wits.clone().into_iter().map(prefixer).collect(),
            wits.into_iter().map(prefixer).collect(),
            Toad::from_wire(bt),
            anchors.into_iter().map(SealSpec::build).collect(),
            ThresholdForm::HexString,
        )
    }
}

impl EventSpec for IxnSpec {
    type Event = InteractionEvent<'static>;

    fn strategy() -> impl Strategy<Value = Self> {
        (
            any::<IdSpec>(),
            sn_strategy(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            proptest::collection::vec(SealSpec::strategy(), 0..4),
        )
    }

    fn build(self) -> Self::Event {
        let (prefix, sn, said, prior, anchors) = self;
        InteractionEvent::new(
            prefix.build(),
            SequenceNumber::new(sn),
            saider(said),
            saider(prior),
            anchors.into_iter().map(SealSpec::build).collect(),
        )
    }
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn sn_strategy() -> impl Strategy<Value = u128> {
    prop_oneof![Just(0_u128), Just(1_u128), Just(u128::MAX), any::<u128>()]
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn bt_strategy() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0_u32), Just(1_u32), Just(u32::MAX), any::<u32>()]
}
