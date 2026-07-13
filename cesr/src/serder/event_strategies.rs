//! Shared proptest strategies over the builder-reachable KERI event space.
//!
//! Single source of truth for cross-backend (write path) and
//! strict-vs-reference (read path) differential property tests.

use crate::core::matter::builder::MatterBuilder;
use crate::core::matter::code::{DigestCode, VerKeyCode, VerserCode};
use crate::core::primitives::{Prefixer, Saider, Seqner, Tholder, Verser};
use crate::keri::toad::Toad;
use crate::keri::{
    ConfigTrait, Identifier, InceptionEvent, InteractionEvent, OpaqueSeal, RotationEvent, Seal,
};
#[allow(
    unused_imports,
    reason = "alloc prelude items; subset used per cfg/feature combination"
)]
use alloc::{
    borrow::Cow, borrow::ToOwned, format, string::String, string::ToString, vec, vec::Vec,
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
pub(crate) fn opaque(pick: u8) -> OpaqueSeal {
    let raw = OPAQUE_POOL[usize::from(pick) % OPAQUE_POOL.len()];
    OpaqueSeal::new(raw.to_owned()).unwrap()
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

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn build_identifier((basic, raw): IdSpec) -> Identifier<'static> {
    if basic {
        Identifier::Basic(prefixer(raw))
    } else {
        Identifier::SelfAddressing(saider(raw))
    }
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn build_seal((variant, a, b, sn): SealSpec) -> Seal {
    match variant {
        0 => Seal::Digest { d: saider(a) },
        1 => Seal::Root { rd: saider(a) },
        2 => Seal::Source {
            s: Seqner::new(sn),
            d: saider(a),
        },
        3 => Seal::Event {
            i: prefixer(b),
            s: Seqner::new(sn),
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

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn build_tholder((simple, value, clauses): TholderSpec) -> Tholder {
    if simple {
        Tholder::Simple(value)
    } else {
        Tholder::Weighted(clauses)
    }
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn build_config(picks: &[bool]) -> Vec<ConfigTrait> {
    picks
        .iter()
        .map(|p| {
            if *p {
                ConfigTrait::EstOnly
            } else {
                ConfigTrait::DoNotDelegate
            }
        })
        .collect()
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn build_icp(spec: IcpSpec) -> InceptionEvent {
    let (prefix, sn, said, keys, kt, next, nt, wits, bt, config, anchors) = spec;
    InceptionEvent::new(
        build_identifier(prefix),
        Seqner::new(sn),
        saider(said),
        keys.into_iter().map(prefixer).collect(),
        build_tholder(kt),
        next.into_iter().map(saider).collect(),
        build_tholder(nt),
        wits.into_iter().map(prefixer).collect(),
        Toad::from_wire(bt),
        build_config(&config),
        anchors.into_iter().map(build_seal).collect(),
    )
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn build_rot(spec: RotSpec) -> RotationEvent {
    let (prefix, sn, said, prior, keys, kt, next, nt, wits, bt, anchors) = spec;
    RotationEvent::new(
        build_identifier(prefix),
        Seqner::new(sn),
        saider(said),
        saider(prior),
        keys.into_iter().map(prefixer).collect(),
        build_tholder(kt),
        next.into_iter().map(saider).collect(),
        build_tholder(nt),
        wits.clone().into_iter().map(prefixer).collect(),
        wits.into_iter().map(prefixer).collect(),
        Toad::from_wire(bt),
        anchors.into_iter().map(build_seal).collect(),
    )
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn build_ixn(spec: IxnSpec) -> InteractionEvent {
    let (prefix, sn, said, prior, anchors) = spec;
    InteractionEvent::new(
        build_identifier(prefix),
        Seqner::new(sn),
        saider(said),
        saider(prior),
        anchors.into_iter().map(build_seal).collect(),
    )
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

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn tholder_strategy() -> impl Strategy<Value = TholderSpec> {
    (
        any::<bool>(),
        prop_oneof![Just(0_u64), Just(1_u64), Just(u64::MAX), any::<u64>()],
        proptest::collection::vec(
            proptest::collection::vec((0_u64..=3, 0_u64..=3), 0..4),
            0..4,
        ),
    )
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn seal_strategy() -> impl Strategy<Value = SealSpec> {
    (0_u8..8, any::<[u8; 32]>(), any::<[u8; 32]>(), sn_strategy())
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn icp_strategy() -> impl Strategy<Value = IcpSpec> {
    (
        any::<IdSpec>(),
        sn_strategy(),
        any::<[u8; 32]>(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..3),
        tholder_strategy(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..3),
        tholder_strategy(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..3),
        bt_strategy(),
        proptest::collection::vec(any::<bool>(), 0..3),
        proptest::collection::vec(seal_strategy(), 0..3),
    )
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn rot_strategy() -> impl Strategy<Value = RotSpec> {
    (
        any::<IdSpec>(),
        sn_strategy(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..3),
        tholder_strategy(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..3),
        tholder_strategy(),
        proptest::collection::vec(any::<[u8; 32]>(), 0..3),
        bt_strategy(),
        proptest::collection::vec(seal_strategy(), 0..3),
    )
}

#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is intentional — the enclosing module is crate-internal and `unreachable_pub` denies plain `pub`"
)]
pub(crate) fn ixn_strategy() -> impl Strategy<Value = IxnSpec> {
    (
        any::<IdSpec>(),
        sn_strategy(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        proptest::collection::vec(seal_strategy(), 0..4),
    )
}
