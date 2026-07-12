# keripy Parity — Divergence Ledger

Deliberate, documented divergences between cesr and the pinned keripy
(`scripts/KERIPY_PIN`). Every `divergence`-marked corpus row under
`cesr/tests/corpus/keripy/parity/` and every skipped-row class in
`cesr/src/keripy_parity/` maps to an entry here. **Documented divergence ≠
discovered divergence** — anything the sweeps surface that is not listed
here is a bug.

Temporarily-open gaps are NOT listed here — they live in Rust-side tracked
tables (`TRACKED_SEALS` → #150) beside `#[ignore]`d bug-probes that fail
while the gap exists. #149 (witness semantics) is closed: its
`TRACKED`/`INEXPRESSIBLE` tables are emptied, its probe deleted, and its
rows now assert live in the validation sweep. Per the porting doctrine, a
fix that makes an invalid state unrepresentable at the type level satisfies
the gate — stronger than keripy's runtime `ValueError`.

## Ilks: non-KEL-core message types

cesr implements the 9 KEL-core ilks (`icp` `rot` `ixn` `dip` `drt` `rct`
`qry` `rpy` `exn`). keripy's `Ilks` at the pin carries 21 more — TEL
registry, ACDC, and exchange/disclosure message types: `xip` `pro` `bar`
`vcp` `vrt` `iss` `rev` `bis` `brv` `rip` `bup` `upd` `acm` `act` `acg`
`ace` `sch` `att` `agg` `edg` `rul`. All 21 are carried in `codex.jsonl`
as `divergence`-marked rows. Out of scope for a KEL-core primitives crate.

## Tholder.satisfy: duplicate signer indices (fail-closed dedup)

keripy counts duplicate index entries toward numeric thresholds:
`Tholder(sith=2).satisfy([0, 0]) == True` at the pin. cesr's
`Tholder::satisfy` deduplicates the index list before counting
(`cesr/src/core/primitives/tholder.rs`) — a threshold counts **distinct**
verified signers, so the same row is `false` in cesr. Deliberate
fail-closed security choice, adjudicated to keep cesr's behavior. The
corpus carries the keripy verdict as a marked row
(`formulas.jsonl`: `tholder_satisfy`, `sith=2`, `indices=[0,0]`), and the
anti-rot guard
(`formulas.rs::satisfy_divergences_are_marked_not_dropped`) fails if cesr
ever silently starts agreeing — the marker can only be removed
deliberately.

## Strong-majority ample

keripy `ample(n, weak=False)` maximizes `m`; cesr implements only the weak
form (`ample(n)`, `cesr/src/serder/ample.rs`) and no cesr call site
consumes the strong form — cesr's witness-threshold default is the weak
form, matching keripy's own factory defaults (`ample(n, f=None,
weak=True)`). The 257 `weak=false` rows (n = 0..=256) are carried in
`formulas.jsonl` and counted-and-skipped by
`formulas.rs::ample_matches_keripy_table`; the 257 weak rows are asserted
exactly.

## PreDex: Ed448_Sig (1AAE) self-signing prefix derivation

keripy's `PreDex` includes `1AAE` (`Ed448_Sig`, self-signing Ed448
derivation). In cesr `1AAE` exists only as a signature code
(`SignatureCode::Ed448Sig` / `MatterCode::Ed448Sig`), and `Identifier`
models `Basic | SelfAddressing` derivations only — there is no
self-signing identifier derivation. Ed448 crypto is deferred under the
RustCrypto stable-generation policy (no stable-generation Ed448 crate).
The other 17 `PreDex` codes — the Ed25519/Ed448/ECDSA verkey codes
(including non-transferable variants) and all 9 digest codes — parse and
roundtrip in the `pre` sweep (`codex.rs::codex_tables_match_keripy`).

## Type-system-enforced factory rejections

keripy validates at runtime that `cnfg` and `data` are lists
(`ValueError` otherwise); cesr's builders take `Vec<ConfigTrait>` (config
traits) and `Vec<Seal>` (anchors), so the malformed inputs are
unrepresentable — the invalid state cannot be constructed. The 3 corpus
rows (`validation.jsonl`: `incept/cnfg_not_list`, `incept/data_not_list`,
`interact/data_not_list`) carry `rust_static` markers;
`validation.rs::builder_validation_matches_keripy` counts and skips them,
and `tracked_tables_match_corpus` forbids them from ever appearing in the
runtime-tracked tables.

## intive write emission

keripy `intive=True` is a write-emission option: `kt`/`nt`/`bt` (sith,
nsith, toad) are serialized as JSON integers instead of hex strings
(`eventing.py`; keripy itself notes it is "not standard KERI" and slated
for removal). None of the three parity families exercises emission — that
is #145's event-tier byte-identity scope. Read-path intive handling
already landed with the #142 strict canonical parser
(`cesr/src/serder/deserialize/canonical.rs`: `ParsedTholder::Number` /
`ParsedCount::Number` accept the integer form; behavior-pinned by
`deserialize.rs::intive_integer_{kt,bt}_is_accepted`).

## Arbitrary anchor dicts

keripy accepts fully arbitrary dicts as anchors (`data` is validated only
as being a list); cesr's strict reader (`parse_seal_array`) parses only
the seal codex shapes. Whether cesr should accept arbitrary anchor maps
or stay strict is a policy decision tracked in #150; this entry records
the outcome once decided.
