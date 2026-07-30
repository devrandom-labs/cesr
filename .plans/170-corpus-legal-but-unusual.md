# #170 — extend event-tier corpus with legal-but-unusual shapes

## Context

Issue #170 (follow-up to #145): the event-wire corpus `crates/keri-codec/tests/corpus/keripy/parity/events.jsonl` (26 vectors) misses several **legal-but-unusual** shapes keripy can emit. Add three families — reserve/partial rotation, asymmetric thresholds, scale boundaries — plus a small second-salt sweep, all keripy-generated at the existing pin (`de59bc7d`, v2.0.0.dev5-1030).

Probed facts (verified against keripy AT THE PIN, 2026-07-30 — do not re-derive):

- `Salter(raw=salt).signers(count=N)` is **prefix-stable**: growing the bank 6→24 (and witness bank 3→8) leaves signers 0..6 / 0..3 byte-identical. Existing vectors MUST NOT change.
- **Churn trap:** existing witnessed rows use the whole witness bank as `wits`. After growing the bank to 8, existing rows must keep using only the FIRST 3 witnesses. New scale rows use all 8.
- keripy accepts: zero-weight members (`"0"` inside a clause whose sum ≥ 1), weighted `kt` with simple `nt` and vice versa, differing clause counts between `kt`/`nt`, 12-key events, 8-witness events, 4-clause nesting, rotations revealing fewer keys than previously committed, rot with non-empty `cuts` AND `adds`.
- keripy REJECTS an all-zero clause (`ValueError: all top level clause weight sums must be >= 1`) — not a corpus row.
- keripy emits zero weight as string `"0"`; cesr's `parse_weight` reads it as `(0,1)` and `weight_to_string` re-renders `"0"` — round-trips today, no codec change expected.
- Fold-corpus growth (`--kels-out` extension) is gated on #90/#91 (both still open) — OUT OF SCOPE.

Invariants:

- All 26 existing corpus rows stay byte-identical after regeneration (guarded: `git diff` on `events.jsonl` must show only ADDED lines).
- Every new row: `"reserialize":"identical"`, `"derivation":"self_addressing"`, `"kind":"event"`.
- New row count: 26 + 17 = **43**.
- Corpus regeneration is done by the controller (Claude) with the pinned local keripy env — NOT part of this execution. Do not run the generator; do not run cargo tests (sandbox hangs them). Verification here is compile-only.

## Steps

### Step 1 — generator matrix extension `scripts/keripy_events_gen.py` [PARALLEL OK]

Files: `scripts/keripy_events_gen.py` only.

1a. Grow the banks (line ~60): `signers` count 6→24, `wsigners` count 3→8. Keep existing `wits` meaning the FIRST THREE witnesses so the 12 existing rows that reference `wits` stay byte-identical, and add the full bank:

```python
wits = [w.verfer.qb64 for w in wsigners[:3]]
wits8 = [w.verfer.qb64 for w in wsigners]
```

1b. After the existing `drt` block (line ~165), append three new sections, in this order, using the existing `add(case, ilk, derivation, serder)` helper (all `derivation="self_addressing"`):

```python
# --- #170: reserve / partial rotation (pairs with #132 ondex exposure) ----
add("rot_partial_reveal", "rot", "self_addressing",
    rotate(pre=pre, keys=keys(3, 5), dig=dig, sn=1, isith="2",
           ndigs=ndigs(6, 9), **J))
add("rot_partial_weighted", "rot", "self_addressing",
    rotate(pre=pre, keys=keys(3, 5), dig=dig, sn=1, isith=["1/2", "1/2"],
           ndigs=ndigs(6, 9), **J))
add("drt_partial_reveal", "drt", "self_addressing",
    rotate(pre=pre, keys=keys(3, 5), dig=dig, sn=1, ilk=Ilks.drt, isith="2",
           ndigs=ndigs(6, 9), **J))

# --- #170: asymmetric threshold structures ------------------------------
add("icp_weighted_kt_simple_nt", "icp", "self_addressing",
    incept(keys=keys(0, 3), isith=["1/2", "1/2", "1"], ndigs=ndigs(3, 6),
           nsith="2", **J))
add("icp_simple_kt_weighted_nt", "icp", "self_addressing",
    incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
           nsith=["1/2", "1/2", "1"], **J))
add("icp_clause_count_asym", "icp", "self_addressing",
    incept(keys=keys(0, 4), isith=[["1/2", "1/2"], ["1", "1"]],
           ndigs=ndigs(4, 10),
           nsith=[["1/2", "1/2"], ["1"], ["1", "1/2", "1/2"]], **J))
add("icp_zero_weight", "icp", "self_addressing",
    incept(keys=keys(0, 3), isith=["1/2", "1/2", "0"], ndigs=ndigs(3, 6),
           nsith=["1/2", "1/2", "0"], **J))
add("icp_multiclause_zero_member", "icp", "self_addressing",
    incept(keys=keys(0, 4), isith=[["1/2", "1/2", "0"], ["1"]],
           ndigs=ndigs(4, 8),
           nsith=[["1/2", "1/2", "0"], ["1"]], **J))
add("rot_weighted_kt_simple_nt", "rot", "self_addressing",
    rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1,
           isith=["1/2", "1/2", "1"], ndigs=ndigs(0, 3), nsith="2", **J))

# --- #170: scale boundaries ---------------------------------------------
add("icp_12_keys", "icp", "self_addressing",
    incept(keys=keys(0, 12), isith="8", ndigs=ndigs(12, 24), nsith="8", **J))
add("icp_8_witnesses", "icp", "self_addressing",
    incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits8,
           toad=6, **J))
add("icp_4_clauses", "icp", "self_addressing",
    incept(keys=keys(0, 8),
           isith=[["1/2", "1/2"], ["1"], ["1/2", "1/2", "1/2"], ["1", "1"]],
           ndigs=ndigs(8, 16),
           nsith=[["1/2", "1/2"], ["1"], ["1/2", "1/2", "1/2"], ["1", "1"]],
           **J))
add("rot_12_keys", "rot", "self_addressing",
    rotate(pre=pre, keys=keys(3, 15), dig=dig, sn=1, isith="8",
           ndigs=ndigs(0, 3), **J))
add("rot_witness_mixed_cuts_adds", "rot", "self_addressing",
    rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
           ndigs=ndigs(0, 3), wits=wits8[0:4], cuts=wits8[0:2],
           adds=wits8[4:7], toad=3, **J))

# --- #170: second-salt sweep (fixture-coupling hardening) ----------------
add("icp_multisig_simple_salt2", "icp", "self_addressing", base2)
add("rot_weighted_salt2", "rot", "self_addressing",
    rotate(pre=base2.pre, keys=keys2(3, 6), dig=base2.said, sn=1,
           isith=["1/2", "1/2", "1"], ndigs=ndigs2(0, 3), **J))
add("icp_witnessed_salt2", "icp", "self_addressing",
    incept(keys=keys2(0, 3), isith="2", ndigs=ndigs2(3, 6), wits=wits2,
           toad=2, **J))
```

1c. The salt2 bank + helpers + `base2` go right after the existing `base`/`delg` setup (line ~81), before the `rows` list:

```python
salt2 = b"0123456789abcdef"
signers2 = Salter(raw=salt2).signers(count=6, transferable=True, temp=True)
wsigners2 = Salter(raw=salt2).signers(count=3, transferable=False, temp=True)

def keys2(a, b):
    return [s.verfer.qb64 for s in signers2[a:b]]

def ndigs2(a, b):
    return [Diger(ser=s.verfer.qb64b).qb64 for s in signers2[a:b]]

wits2 = [w.verfer.qb64 for w in wsigners2]

base2 = incept(keys=keys2(0, 3), isith="2", ndigs=ndigs2(3, 6), nsith="2", **J)
```

1d. Update the module docstring: mention the #170 families (reserve/partial rotation, asymmetric thresholds incl. zero-weight members, scale boundaries 12 keys / 8 witnesses / 4 clauses, second-salt sweep) and that the second salt hardens against fixture coupling.

Expected outcome: generator emits 43 rows; first 26 byte-identical to today (banks prefix-stable, `wits` still first-3).

Verification: `python3 -m py_compile scripts/keripy_events_gen.py` (syntax only — do NOT run the generator, keripy is not importable here).

### Step 2 — Rust-side count guard + docs `crates/keri-codec/src/keripy_parity/events.rs` [PARALLEL OK]

Files: `crates/keri-codec/src/keripy_parity/events.rs` only.

2a. `event_corpus_reserializes_byte_identically`: change `assert_eq!(asserted, 26, ...)` to `assert_eq!(asserted, 43, ...)` (keep the message).

2b. Module doc header: extend the first paragraph's shape list with the #170 families — reserve/partial rotations (keys a strict subset of the prior commitment), asymmetric `kt`/`nt` structures (weighted-vs-simple both directions, differing clause counts, zero-weight members), scale rows (12 keys, 8 witnesses, 4-clause nesting), and a second-salt sweep. One or two sentences; keep existing content.

Verification: `cargo check -p keri-codec` (tests run later in the unsandboxed gate — do not run them).

### Step 3 — ledger note `docs/keripy-parity/ledger.md` [PARALLEL OK]

Files: `docs/keripy-parity/ledger.md` only.

Under `## Event-tier wire parity (#145)`, extend the intro paragraph (line ~139-143) with one sentence: the #170 extension adds reserve/partial rotation, asymmetric-threshold (incl. zero-weight member), scale-boundary (12 keys / 8 witnesses / 4 clauses), and second-salt rows — 43 vectors total. Note keripy rejects an all-zero clause (sum < 1), so that shape is deliberately absent.

Verification: none (prose).

## Verification (controller-driven, after execution)

1. Claude regenerates the corpus with the pinned env (worktree at `de59bc7d`):

```bash
DYLD_LIBRARY_PATH="$(nix build --no-link --print-out-paths nixpkgs#libsodium)/lib" \
PYTHONPATH=~/Code/keripy/.venv/lib/python3.14/site-packages \
/nix/store/llk2h8rxqzv7zh53bi413ffibjrxskxw-python3-3.14.6/bin/python3 \
  scripts/keripy_events_gen.py --keripy <keripy-pin-worktree> \
  --out crates/keri-codec/tests/corpus/keripy/parity
```

2. `git diff crates/keri-codec/tests/corpus/keripy/parity/events.jsonl` — added lines only, exactly 17.
3. `nix flake check` via commit/push hook.

## Out of scope

- `--kels-out` fold-vector growth (gated on #90/#91).
- Any change to codec/threshold parsing, `keri-events`, or other corpus families.
- CBOR/MGPK/v2 kinds, semantic verdicts (#95).
- Running the generator or any cargo test from the execution sandbox.
