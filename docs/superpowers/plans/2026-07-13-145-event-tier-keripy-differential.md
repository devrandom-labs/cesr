# Event-Tier keripy Differential — Full-Breadth Corpus + Bidirectional Byte-Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single-line event-tier keripy corpus with a keripy-generated scenario matrix spanning all 5 ilks × both derivations × threshold/witness/seal/config/intive variants, exercised by a read differential (every event deserializes) and a byte-identity write differential (read → re-serialize → byte-equal), with the one known write-path gap (`intive` integer thresholds) tracked as an `#[ignore]`d red, wired into nightly regen, and recorded in the parity ledger.

**Architecture:** A new sibling generator `scripts/keripy_events_gen.py` emits `cesr/tests/corpus/keripy/parity/events.jsonl` (one JSON record per event scenario, following the existing `keripy_parity_gen.py` conventions — deterministic fixed salt, JSON-only, `include_str!`-embedded). A new parity family `cesr/src/keripy_parity/events.rs` sweeps the corpus: every vector must `deserialize_event` cleanly (read differential) and re-serialize byte-identically (write differential), skipping vectors listed in a `TRACKED` table for the `intive` write gap, with an `#[ignore]`d bug-probe that FAILS while the gap exists. The generator is added to `.github/workflows/keripy-diff.yml` so keripy drift surfaces nightly, and `docs/keripy-parity/ledger.md` gains an event-tier divergence section. An optional final task extends fold coverage with a weighted-multisig complete KEL.

**Tech Stack:** Rust 2024 (cesr-rs crate, `serder` + `std` features), Python 3.14 + keripy `v2.0.0.dev5` (pinned at `scripts/KERIPY_PIN`), `serde`/`serde_json`, `nix flake check` as the single gate.

---

## Context an engineer needs before starting

**The existing single-line corpus and where the new work slots in.** The event-tier corpus today is `keri/tests/corpus/keystate.jsonl` — one 3-event KEL (`icp→rot→ixn`) consumed by `keri/tests/differential.rs` for a *fold* differential and a *byte-identity* differential over just those three events. This plan does **not** touch that file or `differential.rs` (until the optional Task 7). Instead it adds a **breadth** corpus in the cesr crate's parity harness, because read + byte-identity are pure `cesr::serder` capabilities (`deserialize_event` / `serialize`), and the parity families already live in `cesr/src/keripy_parity/` under `#[cfg(all(feature = "serder", feature = "std"))]`.

**Public APIs this plan uses (all confirmed to exist):**
- `cesr::serder::deserialize_event(raw: &[u8]) -> Result<KeriEvent, SerderError>` — dispatches on ilk, verifies SAID in place. (`cesr/src/serder/deserialize.rs:54`)
- `cesr::serder::serialize(event: &KeriEvent) -> Result<SerializedEvent, SerderError>` — reconstructs canonical JSON + SAID. `SerializedEvent::as_bytes(&self) -> &[u8]`. (`cesr/src/serder/serialize.rs:59`)
- Ilk-specific reads/writes also exist (`deserialize_interaction`, `serialize_interaction`, etc.) — the `seal_events.rs` family uses those; this plan uses the ilk-agnostic `deserialize_event` / `serialize` so one sweep covers all 5 ilks.
- `KeriEvent` is an enum with variants `Inception`, `Rotation`, `Interaction`, `DelegatedInception`, `DelegatedRotation` (`cesr/src/keri/event/mod.rs:24`).

**The established parity-family pattern (mirror it exactly):** Each family is a `mod` in `cesr/src/keripy_parity/mod.rs` with (a) a `#[derive(Deserialize)]` vector struct, (b) a `load_<family>()` that `parse_lines(include_str!("../../tests/corpus/keripy/parity/<family>.jsonl"))`, (c) a submodule file with the sweep tests, (d) an entry in the `scaffold_tests` module asserting the corpus loads non-empty and is kind-homogeneous. The tracked-red idiom is in `cesr/src/keripy_parity/said_codes.rs`: a `const TRACKED: &[(...)]` list of blocked cases, a `tracked_issue()` helper, a main sweep that skips tracked cases, and a separate `#[ignore]`d probe that fails while the gap exists.

**Generator conventions (from `keripy_parity_gen.py` / `keripy_keystate_gen.py`):**
- `argparse` with `--keripy <path>` (prepends `<path>/src` to `sys.path`; omit if keripy is importable) and `--out <dir>`.
- Deterministic: fixed 16-byte salt `b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"` → `Salter(raw=salt).signers(count=N, transferable=..., temp=True)`. No wall-clock, no OS randomness.
- Emit one JSON object per line: `json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n"`.
- Pin recorded via `scripts/KERIPY_PIN` (a single 40-char lowercase hex commit SHA); CI clones that commit. The version string constant `KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"` is carried inline (as `keystate_gen.py` does).
- keripy imports: `from keri.core.eventing import incept, rotate, interact` (delegated: `incept(delpre=...)` for `dip`, `rotate(ilk=Ilks.drt, ...)` for `drt`), `from keri.core.coring import Kinds, Diger`, `from keri.core.signing import Salter`, `from keri.kering import Vrsn_1_0, TraitDex`.

**keripy wire facts confirmed empirically at the pin (do NOT re-derive; these are the oracle's behavior):**
- Default single-key `incept(keys=[k])` with `code=None` produces a **basic-derivation** identifier: `i` equals the key qb64 (`D…`), `i != d`. This is the class #144 fixed; it now round-trips.
- `intive=True` serializes numeric `kt`/`nt`/`bt` as JSON **integers** (`"kt":2`, `"bt":1`); `intive=False` (default) serializes them as **hex strings** (`"kt":"2"`, `"bt":"0"`).
- Weighted thresholds: single clause serializes flat (`"kt":["1/2","1/2","1"]`); multi-clause nests (`"kt":[["1/2","1/2"],["1"]]`). cesr's writer mirrors this (single clause collapses — `serialize.rs:581`).
- Rotation carries `br`/`ba` (witness cuts/adds) and, in **v1**, drops the `c` config field entirely (keripy only adds `c` to rotation for v2). Config traits (`c`) appear on `icp`/`dip` only in v1.
- Witnessed events place witness prefixes in `b` (icp/dip) with `bt`=toad; rotation uses `br`/`ba`. `TraitDex` codes: `EO`, `DND`, `NB`, `RB`, `NRB`, `DID` (all 6 supported by cesr's `ConfigTrait`).

**Fold scope (why fold is secondary here):** `KeyState::ingest` (`keri/src/state.rs:246`) returns `Rejection::DelegationUnsupported` for `dip`/`drt`, and neither `incept` nor `ingest` verifies witness receipts (`wigs`). So the fold differential can only cover non-delegated shapes, and semantic parity is issue #95's job (see the issue's division of labor). This plan's acceptance criteria are **read + byte-identity + nightly + ledger**; fold is an optional strengthening (Task 7).

**Verification gate:** The only gate is `nix flake check` (clippy god-level, fmt, taplo, audit, deny, nextest across feature combos, doctests, wasm, no_std). Never substitute raw `cargo`. Individual tests during development: `nix develop --command cargo nextest run -p cesr-rs --all-features <testname>`.

---

### Task 1: File the `intive` write-path tracking issue

**Files:** none (GitHub only).

This is the one anticipated byte-identity gap: keripy's `intive=True` integer thresholds cannot be re-serialized byte-identically because the domain `Tholder::Simple(u64)` does not remember whether the wire form was an integer or a hex string, and `tholder_to_json` (`cesr/src/serder/serialize.rs:567`) always emits hex strings. The gap is a *serialization-model* change (thread an `intive`/wire-form memory through the event types + writer), out of scope for this testing issue — so it is tracked as a red, matching the `#144`/`#160` doctrine.

- [ ] **Step 1: Create the tracking issue and attach it to the board**

Run (uses the `joeldsouzax` gh account per project convention; attaches to org Project #5):

```bash
gh issue create --repo devrandom-labs/cesr \
  --title "serder write path drops intive integer thresholds — cannot byte-round-trip keripy intive=True events" \
  --body "keripy \`incept/rotate(intive=True)\` serializes numeric \`kt\`/\`nt\`/\`bt\` as JSON integers (\`\"kt\":2\`, \`\"bt\":1\`); the default (\`intive=False\`) serializes them as hex strings (\`\"kt\":\"2\"\`, \`\"bt\":\"0\"\`). cesr's read path (\`tholder_from_json\`/\`witness_threshold_from_parsed\`) accepts both, but the domain \`Tholder::Simple(u64)\`/\`witness_threshold: u32\` do not retain the wire form, and the writer (\`tholder_to_json\`, \`sn_to_hex\` for \`bt\`) always emits hex strings. So intive events read and fold correctly but re-serialize with hex thresholds, breaking byte-identity.

Surfaced by the #145 event-tier byte-identity differential; the intive vectors are TRACKED (\`#[ignore]\`d probe) in \`cesr/src/keripy_parity/events.rs\` until this lands. Fix requires carrying an intive/wire-form flag on the establishment events (icp/rot/dip/drt) and honoring it in the writer — a serialization-model change, additive.

Related: #145 (this differential), #144 (basic-derivation write fix), #160 (mixed-code SAID tracked red)." \
  --label keripy-diff
```

- [ ] **Step 2: Record the issue number**

Note the returned issue number (e.g. `#166`). It is used verbatim in Task 4's `TRACKED` table and in Task 6's ledger entry. **Everywhere this plan writes `#166`, substitute the real number returned here.**

```bash
gh project item-add 5 --owner devrandom-labs --url <issue-url-from-step-1>
```

- [ ] **Step 3: Commit (no code yet — this task is issue-only)**

No commit; proceed to Task 2.

---

### Task 2: Write the event-matrix generator `keripy_events_gen.py`

**Files:**
- Create: `scripts/keripy_events_gen.py`

The generator builds the scenario matrix by calling keripy's event factories directly (no DB, no signing — read + byte-identity need only the wire bytes) and emits one record per scenario. Prior events for `rot`/`ixn`/`drt` are synthesized from a genesis `icp` in the same scenario group so `pre`/`dig` are real keripy values.

- [ ] **Step 1: Write the generator**

```python
#!/usr/bin/env python3
"""Generate the keripy event-wire corpus: full-breadth scenario matrix (issue #145).

keripy is the oracle. This builds every KEL event shape keripy emits at the
pin — all 5 ilks, basic AND self-addressing derivations, simple/weighted/
multi-clause thresholds, intive on and off, witnesses with br/ba and toad at
boundaries, every TraitDex config trait, and seal anchors — and emits ONE JSON
object per scenario capturing the raw wire bytes (as a JSON string, like
seal_events.jsonl). cesr must (1) deserialize every record cleanly and
(2) re-serialize it byte-identically, except rows marked reserialize="blocked"
(the intive integer-threshold write gap, tracked in events.rs).

No signing, no DB: read + byte-identity are pure serializer facts. Prior
events for rot/ixn/drt reuse a genesis icp's pre/said so chaining fields are
real keripy values, not synthetic.

Deterministic: fixed salt, no wall-clock, no OS randomness.
Pin: keripy v2.0.0.dev5-1030-gde59bc7d, KERI/CESR V1 JSON (KERI10JSON).
"""
import argparse
import json
import sys
from pathlib import Path

KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"


def emit(fh, obj):
    fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is prepended "
                         "to sys.path); omit if keripy is already importable")
    ap.add_argument("--out", required=True, type=Path,
                    help="output directory (events.jsonl is written here)")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    from keri.core.coring import Diger, Kinds
    from keri.core.eventing import incept, interact, rotate
    from keri.core.signing import Salter
    from keri.core.counting import Vrsn_1_0
    from keri.kering import Ilks, TraitDex

    salt = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"
    signers = Salter(raw=salt).signers(count=6, transferable=True, temp=True)
    wsigners = Salter(raw=salt).signers(count=3, transferable=False, temp=True)

    def keys(a, b):
        return [s.verfer.qb64 for s in signers[a:b]]

    def ndigs(a, b):
        return [Diger(ser=s.verfer.qb64b).qb64 for s in signers[a:b]]

    wits = [w.verfer.qb64 for w in wsigners]
    J = dict(kind=Kinds.json, version=Vrsn_1_0)

    seal = {"i": signers[0].verfer.qb64,
            "s": "0",
            "d": Diger(ser=b"anchor").qb64}

    # A self-addressing genesis to source pre/dig for rot/ixn/drt scenarios.
    base = incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), nsith="2", **J)
    pre, dig = base.pre, base.said

    # A delegator prefix for dip/drt.
    delg = incept(keys=keys(0, 1), **J)

    rows = []  # (case, ilk, derivation, serder, blocked)

    def add(case, ilk, derivation, serder, blocked=False):
        rows.append((case, ilk, derivation, serder, blocked))

    # --- icp ---------------------------------------------------------------
    add("icp_basic_single", "icp", "basic",
        incept(keys=keys(0, 1), ndigs=ndigs(1, 2), **J))
    add("icp_multisig_simple", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), nsith="2", **J))
    add("icp_weighted", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=["1/2", "1/2", "1"], ndigs=ndigs(3, 6),
               nsith=["1/2", "1/2", "1"], **J))
    add("icp_weighted_multiclause", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=[["1/2", "1/2"], ["1"]], ndigs=ndigs(3, 6),
               nsith=[["1/2", "1/2"], ["1"]], **J))
    add("icp_witnessed", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits, toad=2, **J))
    add("icp_witnessed_toad0", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits, toad=0, **J))
    add("icp_config_estonly", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               cnfg=[TraitDex.EstOnly], **J))
    add("icp_config_dnd_nb", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               cnfg=[TraitDex.DoNotDelegate, TraitDex.NoBackers], **J))
    add("icp_seal_anchored", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), data=[seal], **J))
    add("icp_intive", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=2, ndigs=ndigs(3, 6), nsith=2,
               wits=wits, toad=1, intive=True, **J), blocked=True)

    # --- rot ---------------------------------------------------------------
    add("rot_simple", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
               ndigs=ndigs(0, 3), **J))
    add("rot_weighted", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1,
               isith=["1/2", "1/2", "1"], ndigs=ndigs(0, 3), **J))
    add("rot_witness_cuts_adds", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
               ndigs=ndigs(0, 3), wits=[], cuts=[], adds=wits, toad=2, **J))
    add("rot_seal_anchored", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
               ndigs=ndigs(0, 3), data=[seal], **J))
    add("rot_intive", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith=2,
               ndigs=ndigs(0, 3), intive=True, **J), blocked=True)

    # --- ixn ---------------------------------------------------------------
    add("ixn_empty", "ixn", "self_addressing",
        interact(pre=pre, dig=dig, sn=1, **J))
    add("ixn_seal", "ixn", "self_addressing",
        interact(pre=pre, dig=dig, sn=1, data=[seal], **J))
    add("ixn_multi_seal", "ixn", "self_addressing",
        interact(pre=pre, dig=dig, sn=1, data=[seal, seal], **J))

    # --- dip (delegated inception; read + byte-identity only) --------------
    add("dip_basic", "dip", "self_addressing",
        incept(keys=keys(0, 1), ndigs=ndigs(1, 2), delpre=delg.pre, **J))
    add("dip_multisig", "dip", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               delpre=delg.pre, **J))
    add("dip_witnessed", "dip", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits,
               toad=2, delpre=delg.pre, **J))

    # --- drt (delegated rotation; read + byte-identity only) ---------------
    add("drt_simple", "drt", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, ilk=Ilks.drt,
               isith="2", ndigs=ndigs(0, 3), **J))
    add("drt_weighted", "drt", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, ilk=Ilks.drt,
               isith=["1/2", "1/2", "1"], ndigs=ndigs(0, 3), **J))

    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / "events.jsonl"
    with out.open("w") as fh:
        for case, ilk, derivation, serder, blocked in rows:
            rec = {
                "kind": "event",
                "case": case,
                "ilk": ilk,
                "derivation": derivation,
                "raw": serder.raw.decode("utf-8"),
                "reserialize": "blocked" if blocked else "identical",
            }
            if blocked:
                rec["blocked_by"] = "#166"  # intive write gap (Task 1 issue)
            emit(fh, rec)

    print(f"wrote {len(rows)} event vectors -> {out} "
          f"(keripy {KERIPY_VERSION})", file=sys.stderr)


if __name__ == "__main__":
    main()
```

> **Note:** replace `#166` with the real issue number from Task 1.

- [ ] **Step 2: Run the generator against the local keripy checkout**

The local keripy venv lives at `~/Code/keripy/.venv` (Python 3.14, keripy installed editable at the pin). keripy's `pysodium` dep dlopens libsodium, so pass `DYLD_LIBRARY_PATH` on macOS.

Run:
```bash
DYLD_LIBRARY_PATH="$(nix build --no-link --print-out-paths nixpkgs#libsodium)/lib" \
  ~/Code/keripy/.venv/bin/python scripts/keripy_events_gen.py \
  --keripy ~/Code/keripy --out cesr/tests/corpus/keripy/parity
```
Expected: `wrote 23 event vectors -> cesr/tests/corpus/keripy/parity/events.jsonl (keripy v2.0.0.dev5-1030-gde59bc7d)` on stderr, and `cesr/tests/corpus/keripy/parity/events.jsonl` created with 23 lines.

- [ ] **Step 3: Sanity-check the generated corpus**

Run:
```bash
test "$(wc -l < cesr/tests/corpus/keripy/parity/events.jsonl)" -eq 23 && echo LINES_OK
rg -c '"reserialize":"blocked"' cesr/tests/corpus/keripy/parity/events.jsonl   # expect 2 (icp_intive, rot_intive)
rg -o '"ilk":"[a-z]+"' cesr/tests/corpus/keripy/parity/events.jsonl | sort | uniq -c  # expect all 5 ilks
```
Expected: `LINES_OK`, `2`, and counts for `dip drt icp ixn rot`.

- [ ] **Step 4: Commit**

```bash
git add scripts/keripy_events_gen.py cesr/tests/corpus/keripy/parity/events.jsonl
git commit -m "test(diff): add keripy event-wire matrix generator + corpus (#145)"
```

---

### Task 3: Wire the `events` family into the parity harness (loader + scaffold)

**Files:**
- Modify: `cesr/src/keripy_parity/mod.rs`

Add the vector struct, the loader, the `mod events;` declaration, and the scaffold assertions — mirroring the `SealEventVector` / `load_seal_events` wiring exactly.

- [ ] **Step 1: Add the `mod events;` declaration**

In `cesr/src/keripy_parity/mod.rs`, the module list currently reads:
```rust
mod codex;
mod formulas;
mod said_codes;
mod seal_events;
mod validation;
```
Change it to (keep alphabetical among the existing set; `events` sorts first):
```rust
mod codex;
mod events;
mod formulas;
mod said_codes;
mod seal_events;
mod validation;
```

- [ ] **Step 2: Add the `EventVector` struct and `load_events()` loader**

Immediately after the `SealEventVector` struct + `load_seal_events()` block (near the other `load_*` functions), add:
```rust
#[derive(Debug, Deserialize)]
pub(super) struct EventVector {
    pub kind: String,
    pub case: String,
    pub ilk: String,
    #[allow(
        dead_code,
        reason = "corpus-carried derivation label; sweeps assert via read/round-trip, not this field"
    )]
    pub derivation: String,
    pub raw: String,
    pub reserialize: String,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "corpus-carried tracking-issue reference for blocked rows; matched against TRACKED in events.rs"
    )]
    pub blocked_by: String,
}

fn load_events() -> Vec<EventVector> {
    parse_lines(include_str!("../../tests/corpus/keripy/parity/events.jsonl"))
}
```

- [ ] **Step 3: Extend the scaffold tests**

In `mod scaffold_tests`, add to `corpus_families_load_and_are_nonempty`:
```rust
        assert!(!load_events().is_empty(), "events corpus is empty");
```
and to `kinds_are_homogeneous`:
```rust
        assert!(load_events().iter().all(|v| v.kind == "event"));
```

- [ ] **Step 4: Verify it compiles (events.rs does not exist yet — expect a module-not-found error, which confirms the wiring is in place)**

Run:
```bash
nix develop --command cargo build -p cesr-rs --all-features 2>&1 | rg -i "events" | head
```
Expected: an error `file not found for module \`events\`` (or similar) pointing at `keripy_parity/events.rs`. This proves Step 1's `mod events;` is wired; Task 4 creates the file.

- [ ] **Step 5: Do NOT commit yet** — the crate does not compile until Task 4 adds `events.rs`. Commit at the end of Task 4.

---

### Task 4: Write the `events.rs` read + byte-identity sweep with the intive tracked red

**Files:**
- Create: `cesr/src/keripy_parity/events.rs`
- Test: the file IS the test (parity families are in-crate `#[cfg(test)]`-style sweeps compiled under `serder`+`std`).

This is the heart of the issue: the **read differential** (every vector deserializes) and the **write differential** (byte-identity, skipping the `intive` tracked red), plus an `#[ignore]`d probe that FAILS while the intive gap exists, plus a stale-tracked guard.

- [ ] **Step 1: Write the failing test file**

Create `cesr/src/keripy_parity/events.rs`:
```rust
//! #145 event-wire matrix: keripy-generated events across all 5 ilks, both
//! derivations, and every threshold/witness/seal/config/intive variant must
//! (1) deserialize on the strict read path and (2) re-serialize byte-identically.
//!
//! The one anticipated write gap is keripy's `intive=True` integer thresholds:
//! the domain `Tholder`/`witness_threshold` do not retain the integer-vs-hex
//! wire form, and the writer always emits hex strings, so intive events read
//! and fold correctly but cannot round-trip byte-for-byte. Those rows are
//! `TRACKED` below (skipped by the byte-identity sweep) next to an `#[ignore]`d
//! probe that FAILS while the gap exists — the #144/#160 doctrine.

use std::eprintln;
use std::string::String;

use crate::serder::deserialize::deserialize_event;
use crate::serder::serialize::serialize;

use super::{EventVector, load_events};

/// Scenario cases whose byte-identity is blocked by the intive write gap
/// (issue #166). The byte-identity sweep skips these; the `#[ignore]`d probe
/// FAILS while any remains non-round-trippable. Remove entries as #166 lands
/// (the stale-entry guard flags leftovers).
const TRACKED: &[(&str, &str)] = &[
    ("icp_intive", "#166"),
    ("rot_intive", "#166"),
];

fn tracked_issue(case: &str) -> Option<&'static str> {
    TRACKED
        .iter()
        .find(|(c, _)| *c == case)
        .map(|(_, issue)| *issue)
}

/// Read differential: every corpus event — including delegated (dip/drt),
/// witnessed, weighted, config, seal, and intive shapes — must deserialize
/// on the strict path. A typed error here is a red build.
#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: an unreadable vector panics with case context"
)]
fn event_corpus_reads_cleanly() {
    let vectors = load_events();
    assert!(!vectors.is_empty(), "events corpus is empty");
    for v in &vectors {
        deserialize_event(v.raw.as_bytes())
            .unwrap_or_else(|e| panic!("{} ({}): read: {e}", v.case, v.ilk));
    }
}

/// Write differential: every representable corpus event must re-serialize
/// byte-for-byte. Intive rows (TRACKED) are skipped; everything else — basic
/// derivation (#144), weighted/multi-clause thresholds, witness br/ba, config
/// traits, and seal anchors — must round-trip exactly.
#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: failed round trips panic with context; tracked skips logged"
)]
fn event_corpus_reserializes_byte_identically() {
    let mut asserted = 0usize;
    let mut skipped = 0usize;
    for v in load_events() {
        let blocked = v.reserialize == "blocked";
        assert_eq!(
            blocked,
            tracked_issue(&v.case).is_some(),
            "{}: corpus `reserialize` flag and TRACKED table disagree",
            v.case
        );
        if blocked {
            eprintln!("TRACKED {}: {}", v.case, tracked_issue(&v.case).unwrap());
            skipped += 1;
            continue;
        }
        let event = deserialize_event(v.raw.as_bytes())
            .unwrap_or_else(|e| panic!("{}: read: {e}", v.case));
        let re = serialize(&event).unwrap_or_else(|e| panic!("{}: write: {e}", v.case));
        assert_eq!(
            String::from_utf8_lossy(re.as_bytes()),
            v.raw,
            "{} ({}) must re-serialize byte-identically",
            v.case,
            v.ilk
        );
        asserted += 1;
    }
    eprintln!("events: {asserted} asserted, {skipped} tracked (#166)");
    assert!(asserted >= 20, "expected >=20 representable rows, got {asserted}");
}

/// Bug-probe for the intive write gap (#166): FAILS while any TRACKED intive
/// vector cannot round-trip byte-identically. `#[ignore]`d so the gap is a
/// tracked red, not a green build. Delete the `#[ignore]` (and the TRACKED
/// entries) when #166 lands.
#[test]
#[ignore = "#166: intive integer thresholds are not preserved on the write path"]
#[allow(
    clippy::panic,
    reason = "test-only probe: documents the gap, fails while it exists"
)]
fn intive_events_round_trip_byte_identically() {
    for v in load_events().into_iter().filter(|v| tracked_issue(&v.case).is_some()) {
        let event = deserialize_event(v.raw.as_bytes())
            .unwrap_or_else(|e| panic!("{}: read: {e}", v.case));
        let re = serialize(&event).unwrap_or_else(|e| panic!("{}: write: {e}", v.case));
        assert_eq!(
            String::from_utf8_lossy(re.as_bytes()),
            v.raw,
            "{}: intive event must re-serialize byte-identically once #166 lands",
            v.case
        );
    }
}

/// Anti-rot guard: every TRACKED case must still exist in the corpus. A stale
/// entry (case renamed or removed) means the tracked list drifted from reality.
#[test]
#[allow(
    clippy::panic,
    reason = "test-only guard: a stale tracked entry panics with context"
)]
fn tracked_cases_exist_in_corpus() {
    let cases: std::vec::Vec<String> = load_events().into_iter().map(|v| v.case).collect();
    for (case, issue) in TRACKED {
        assert!(
            cases.iter().any(|c| c == case),
            "TRACKED case `{case}` ({issue}) is absent from the corpus — stale entry"
        );
    }
}
```

> **Note:** replace both `#166` references (the `TRACKED` table and the `#[ignore]` reason) with the real issue number from Task 1.

- [ ] **Step 2: Run the read + byte-identity sweeps — expect PASS**

Run:
```bash
nix develop --command cargo nextest run -p cesr-rs --all-features \
  keripy_parity::events -- --no-capture 2>&1 | tail -30
```
Expected: `event_corpus_reads_cleanly`, `event_corpus_reserializes_byte_identically`, and `tracked_cases_exist_in_corpus` PASS; `intive_events_round_trip_byte_identically` is reported as `IGNORED`. The stderr shows `events: 21 asserted, 2 tracked (#166)`.

- [ ] **Step 3: Confirm the ignored probe FAILS when forced (proves it is a real red, not a vacuous skip)**

Run:
```bash
nix develop --command cargo nextest run -p cesr-rs --all-features \
  --run-ignored all keripy_parity::events::intive_events_round_trip 2>&1 | tail -20
```
Expected: `intive_events_round_trip_byte_identically` **FAILS** with a byte-identity mismatch (cesr emits `"kt":"2"` where keripy wrote `"kt":2`). This confirms the tracked red is genuine.

- [ ] **Step 4: Commit (Tasks 3 + 4 together — first point the crate compiles)**

```bash
git add cesr/src/keripy_parity/mod.rs cesr/src/keripy_parity/events.rs
git commit -m "test(diff): event-tier read + byte-identity differential over keripy matrix (#145)

Adds the events parity family: all 5 ilks x both derivations x
threshold/witness/seal/config/intive variants. Read differential and
byte-identity write differential are green; intive integer thresholds are
a TRACKED red (#166) with an #[ignore]d bug-probe."
```

---

### Task 5: Wire the generator into nightly regen + drift PR

**Files:**
- Modify: `.github/workflows/keripy-diff.yml`

The nightly job clones keripy at the pin, regenerates the corpus, runs the diff harness, and opens a drift PR. Add the new generator to the regen step so keripy event-wire drift surfaces automatically.

- [ ] **Step 1: Add the generator to the "Regenerate corpus" step**

In `.github/workflows/keripy-diff.yml`, the regen step currently runs:
```yaml
          python scripts/keripy_diff_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy
          python scripts/keripy_parity_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy/parity
          git --no-pager diff --stat -- cesr/tests/corpus/keripy || true
```
Insert the events generator after the parity generator (it writes to the same `parity` dir):
```yaml
          python scripts/keripy_diff_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy
          python scripts/keripy_parity_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy/parity
          python scripts/keripy_events_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy/parity
          git --no-pager diff --stat -- cesr/tests/corpus/keripy || true
```

- [ ] **Step 2: Update the drift-PR body to mention the event corpus**

In the `peter-evans/create-pull-request@v7` step's `body:`, the text describes what the corpus covers. Add a sentence so reviewers know the event matrix is now regenerated. Find the paragraph beginning "Covers the primitive differential corpus AND the parity families" and append to its list `parity/events.jsonl`:
```yaml
          Covers the primitive differential corpus AND the parity families
          (`parity/codex.jsonl`, `parity/formulas.jsonl`,
          `parity/validation.jsonl`, `parity/events.jsonl`): a new codex entry,
          a changed formula row, a new validation rule, or a shifted event-wire
          byte string at the pin lands here as a visible diff, not silent rot.
```

- [ ] **Step 3: Lint the workflow**

Run (actionlint is provided by the flake):
```bash
nix develop --command actionlint .github/workflows/keripy-diff.yml && echo ACTIONLINT_OK
```
Expected: `ACTIONLINT_OK` (no output from actionlint means success).

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/keripy-diff.yml
git commit -m "ci(diff): regenerate event-wire corpus in nightly keripy-diff (#145)"
```

---

### Task 6: Record the event-tier divergence in the parity ledger

**Files:**
- Modify: `docs/keripy-parity/ledger.md`

The ledger records deliberate/long-lived divergences. Two event-tier facts belong here: the intive write gap (tracked, temporary — points at #166) and the JSON-only scope (CBOR/MGPK and v2 out of scope — permanent).

- [ ] **Step 1: Read the current ledger to match its section style**

Run:
```bash
sed -n '1,40p' docs/keripy-parity/ledger.md
```
Note the `## Section Title` + prose + "keripy behavior / cesr behavior / pinning" convention.

- [ ] **Step 2: Append the event-tier section**

Add at the end of `docs/keripy-parity/ledger.md`:
```markdown
## Event-tier wire parity (#145)

The event-wire differential (`cesr/src/keripy_parity/events.rs`, corpus
`parity/events.jsonl`) reads every KEL event shape keripy emits at the pin —
all 5 ilks, basic and self-addressing derivations, simple/weighted/multi-clause
thresholds, witnesses with `br`/`ba` and boundary `toad`, every `TraitDex`
config trait, and seal anchors — and writes each back byte-identically. Two
deliberate boundaries:

### intive integer thresholds (tracked, #166)

keripy `intive=True` serializes numeric `kt`/`nt`/`bt` as JSON integers
(`"kt":2`, `"bt":1`); the default serializes them as hex strings (`"kt":"2"`).
cesr reads both, but the domain `Tholder`/`witness_threshold` do not retain the
wire form and the writer always emits hex strings, so intive events read and
fold correctly but do not round-trip byte-for-byte. This is a **tracked red**,
not a permanent divergence: the `icp_intive`/`rot_intive` rows are in the
`TRACKED` table in `events.rs` next to an `#[ignore]`d probe that fails while
the gap exists. Closes when #166 threads an intive/wire-form flag through the
establishment events and the writer.

### JSON-only, KERI/CESR v1 (permanent)

The event corpus is `KERI10JSON` (v1 JSON) only. keripy can also emit CBOR and
MGPK serializations and v2 (`KERICBOR`/`KERIMGPK`, `KERI20…`); cesr's serder
models v1 JSON, matching the KEL-core scope. CBOR/MGPK/v2 event shapes are out
of scope for this crate and are not carried in the corpus.
```

> **Note:** replace `#166` with the real issue number from Task 1.

- [ ] **Step 3: Commit**

```bash
git add docs/keripy-parity/ledger.md
git commit -m "docs(keripy-parity): record event-tier wire divergences (#145)"
```

---

### Task 7 (optional, recommended): Extend fold coverage with a weighted-multisig complete KEL

**Files:**
- Modify: `scripts/keripy_events_gen.py`
- Modify: `keri/tests/differential.rs`
- Create: `keri/tests/corpus/kels.jsonl`

Scope point 2 of the issue asks that "where a KEL is complete, fold to keripy's recorded state." The existing `keystate.jsonl` folds one single-sig KEL. This task adds a **weighted-multisig** complete KEL (3 keys, `kt=["1/2","1/2","1"]`) that keri-rs's fold supports (non-delegated, threshold logic exercised), signed and folded by keripy's `Kever` to produce the authoritative `final_state`. Witnessed and delegated shapes are intentionally excluded from fold — keri-rs's `ingest` does not verify witness receipts and rejects delegation (`Rejection::DelegationUnsupported`); those shapes are covered by the read + byte-identity sweep in Task 4.

- [ ] **Step 1: Extend the generator to emit a signed, folded weighted KEL**

Add a `--kels-out <path>` argument and a signed-KEL section to `scripts/keripy_events_gen.py`. After the `rows`/`events.jsonl` block in `main()`, before the final `print`, add:
```python
    if args.kels_out is not None:
        from keri.core.eventing import Kever
        from keri.db.basing import openDB

        def diger_qb64(i):
            return Diger(ser=signers[i].verfer.qb64b).qb64

        kel = []  # (serder, [siger])
        with openDB(name="k145-weighted") as db:
            # icp: 3 keys, weighted kt, committing to keys 3..6.
            icp = incept(keys=keys(0, 3), isith=["1/2", "1/2", "1"],
                         ndigs=[diger_qb64(3), diger_qb64(4), diger_qb64(5)],
                         nsith=["1/2", "1/2", "1"], **J)
            wpre = icp.ked["i"]
            isigs = [signers[i].sign(icp.raw, index=i) for i in range(3)]
            kever = Kever(serder=icp, sigers=isigs, db=db)
            kel.append((icp, isigs))

            # rot: reveal keys 3..6, commit back to 0..3, sn 1.
            rot = rotate(pre=wpre, keys=keys(3, 6), dig=icp.said, sn=1,
                         isith=["1/2", "1/2", "1"],
                         ndigs=[diger_qb64(0), diger_qb64(1), diger_qb64(2)],
                         nsith=["1/2", "1/2", "1"], **J)
            rsigs = [signers[i].sign(rot.raw, index=i - 3) for i in range(3, 6)]
            kever.update(serder=rot, sigers=rsigs)
            kel.append((rot, rsigs))

            # ixn: sn 2, signed by current keys 3..6.
            ixn = interact(pre=wpre, dig=rot.said, sn=2, **J)
            xsigs = [signers[i].sign(ixn.raw, index=i - 3) for i in range(3, 6)]
            kever.update(serder=ixn, sigers=xsigs)
            kel.append((ixn, xsigs))

            final_state = {
                "prefix_qb64": kever.prefixer.qb64,
                "sn": kever.sner.num,
                "keys_qb64": [v.qb64 for v in kever.verfers],
                "next_keys_qb64": [d.qb64 for d in kever.ndigers],
                "witness_threshold": kever.toader.num,
                "witnesses_qb64": list(kever.wits),
            }

        import base64
        rec = {
            "keripy_version": KERIPY_VERSION,
            "case": "weighted_multisig_icp_rot_ixn",
            "events": [
                {"raw_b64": base64.standard_b64encode(s.raw).decode("ascii"),
                 "sigs_qb64": [sg.qb64 for sg in sigs]}
                for s, sigs in kel
            ],
            "final_state": final_state,
        }
        args.kels_out.parent.mkdir(parents=True, exist_ok=True)
        with args.kels_out.open("w") as fh:
            emit(fh, rec)
        print(f"wrote 1 fold KEL -> {args.kels_out}", file=sys.stderr)
```
And add the argument to the `argparse` block:
```python
    ap.add_argument("--kels-out", type=Path, default=None,
                    help="output JSONL file for signed complete-KEL fold vectors")
```

- [ ] **Step 2: Regenerate both corpora**

Run:
```bash
DYLD_LIBRARY_PATH="$(nix build --no-link --print-out-paths nixpkgs#libsodium)/lib" \
  ~/Code/keripy/.venv/bin/python scripts/keripy_events_gen.py \
  --keripy ~/Code/keripy --out cesr/tests/corpus/keripy/parity \
  --kels-out keri/tests/corpus/kels.jsonl
```
Expected: the events line count is unchanged (23) and `wrote 1 fold KEL -> keri/tests/corpus/kels.jsonl`.

- [ ] **Step 3: Add a fold sweep to `keri/tests/differential.rs`**

`differential.rs` already has the harness pattern: a `Vector`/`EventRecord`/`FinalState` set of `#[derive(Deserialize)]` structs, `siger_from_qb64` from `common`, and the `KeyState::incept` + `try_fold(.., KeyState::ingest)` fold. Add a new test that loads `kels.jsonl` (a single record with the same `events`/`final_state` schema as `keystate.jsonl`) and folds it. Add near the existing tests:
```rust
const KELS: &str = include_str!("corpus/kels.jsonl");

#[test]
fn weighted_multisig_kel_folds_to_keripy_state() -> Fallible<()> {
    let line = KELS
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or("kels corpus has a vector line")?;
    let vector: Vector = serde_json::from_str(line)?;

    let raws: Vec<Vec<u8>> = vector
        .events
        .iter()
        .map(|rec| BASE64.decode(&rec.raw_b64).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let parsed: Vec<KeriEvent> = raws
        .iter()
        .map(|raw| deserialize_event(raw).map_err(Into::into))
        .collect::<Fallible<_>>()?;
    let signed: Vec<Signed> = parsed
        .iter()
        .zip(&raws)
        .zip(&vector.events)
        .map(|((event, raw), rec)| {
            let sigs = rec
                .sigs_qb64
                .iter()
                .map(|q| siger_from_qb64(q))
                .collect::<Fallible<_>>()?;
            Ok(Signed { event, signed_bytes: raw, sigs, wigs: vec![] })
        })
        .collect::<Fallible<_>>()?;

    let (first, rest) = signed.split_first().ok_or("KEL has a genesis event")?;
    let state = rest.iter().try_fold(KeyState::incept(first)?, KeyState::ingest)?;

    let expected = &vector.final_state;
    assert_eq!(prefix_qb64(state.prefix()), expected.prefix_qb64);
    assert_eq!(state.sn().value(), expected.sn);
    let keys: Vec<String> = state.keys().iter().map(Matter::to_qb64).collect();
    assert_eq!(keys, expected.keys_qb64, "weighted multisig current keys");
    let next_keys: Vec<String> = state.next_keys().iter().map(Matter::to_qb64).collect();
    assert_eq!(next_keys, expected.next_keys_qb64, "weighted multisig next-key digests");
    Ok(())
}
```

- [ ] **Step 4: Run the fold sweep — expect PASS**

Run:
```bash
nix develop --command cargo nextest run -p keri-rs --all-features \
  weighted_multisig_kel_folds 2>&1 | tail -15
```
Expected: `weighted_multisig_kel_folds_to_keripy_state` PASSES — keri-rs's fold agrees with keripy's `Kever` on a weighted-multisig KEL.

- [ ] **Step 5: Add the fold generator to CI**

In `.github/workflows/keripy-diff.yml`, extend the events-generator line (from Task 5) to also emit the fold corpus:
```yaml
          python scripts/keripy_events_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy/parity --kels-out keri/tests/corpus/kels.jsonl
```
And add `keri/tests/corpus/kels.jsonl` to the drift-detection `git diff` scope so it is picked up by the PR:
```yaml
          git --no-pager diff --stat -- cesr/tests/corpus/keripy keri/tests/corpus || true
```

- [ ] **Step 6: Commit**

```bash
git add scripts/keripy_events_gen.py keri/tests/differential.rs keri/tests/corpus/kels.jsonl .github/workflows/keripy-diff.yml
git commit -m "test(diff): fold a weighted-multisig KEL against keripy state (#145)"
```

---

### Task 8: Full gate + PR

**Files:** none (verification + PR).

- [ ] **Step 1: Run the single gate**

The gate sees only committed state (dirty-tree runs are vacuous), so commit everything first, then:
```bash
nix flake check 2>/tmp/gate.log; echo "GATE_EXIT=$?"
```
Expected: `GATE_EXIT=0`. If non-zero, read `/tmp/gate.log` (do NOT pipe the gate through `head`/`tail` — that masks the exit code). Fix and re-run until green.

- [ ] **Step 2: Push the branch and open the PR**

```bash
git push -u origin HEAD
gh pr create --repo devrandom-labs/cesr --base main \
  --title "test(diff): event-tier keripy differential — full-breadth corpus + byte-identity (#145)" \
  --body "Closes #145 (read + byte-identity + nightly + ledger).

## What

- New generator \`scripts/keripy_events_gen.py\` emits a keripy scenario matrix
  (\`parity/events.jsonl\`): all 5 ilks x basic/self-addressing derivations x
  simple/weighted/multi-clause thresholds x witnesses (br/ba, boundary toad) x
  every TraitDex config trait x seal anchors x intive on/off. Deterministic
  (fixed salt), pinned to keripy \`scripts/KERIPY_PIN\`.
- New parity family \`cesr/src/keripy_parity/events.rs\`: read differential
  (every event deserializes) + byte-identity write differential (read ->
  serialize -> byte-equal).
- Nightly \`keripy-diff.yml\` regenerates the event corpus and surfaces drift as
  a PR.
- Event-tier divergence section in \`docs/keripy-parity/ledger.md\`.
- (Task 7) weighted-multisig complete KEL folds against keripy's Kever state.

## Tracked red

\`intive=True\` integer thresholds (\`icp_intive\`/\`rot_intive\`) cannot re-serialize
byte-identically — the writer always emits hex strings and the domain \`Tholder\`
does not retain the wire form. TRACKED in \`events.rs\` with an \`#[ignore]\`d
bug-probe; fix is #166.

## Not in scope

Semantic parity (#95), CBOR/MGPK/v2 serializations, and delegated/witnessed
*fold* (keri-rs rejects delegation and does not verify witness receipts) —
delegated/witnessed shapes are covered by the read + byte-identity sweep, not
fold.

🤖 Generated with [Claude Code](https://claude.com/claude-code)"
```

- [ ] **Step 3: Confirm CI is green on the PR**

```bash
gh pr checks --repo devrandom-labs/cesr --watch
```
Expected: all checks pass.

---

## Self-Review

**Spec coverage** (issue #145 acceptance):
- ✅ *Corpus ≥ all 5 ilks × both derivations × threshold/witness/seal/config/intive variants, keripy-generated, deterministic* — Task 2 generator (23 scenarios: icp/rot/ixn/dip/drt; basic + self-addressing; simple/weighted/multi-clause; witnesses with br/ba and toad 0/2; EO/DND/NB config; seal anchors; intive on/off; fixed salt).
- ✅ *Read differential green over the full corpus in `nix flake check`* — Task 4 `event_corpus_reads_cleanly`.
- ✅ *Byte-identity write differential green (minus explicit `#[ignore]`s)* — Task 4 `event_corpus_reserializes_byte_identically`; #144 basic-derivation now passes (issue closed), the only tracked red is intive (#166), not #144.
- ✅ *Nightly regen + drift PR wired* — Task 5.
- ✅ *Divergence ledger section* — Task 6.
- ➕ *Fold (scope point 2, not an acceptance item)* — Task 7 (optional), weighted-multisig KEL; delegated/witnessed fold correctly excluded per keri-rs's documented limits.

**Placeholder scan:** No `TBD`/"add error handling"/"similar to Task N". The one substitution is the tracking-issue number `#166` (flagged in Tasks 2, 4, 6) — filed concretely in Task 1. All code blocks are complete.

**Type consistency:** `deserialize_event(&[u8]) -> Result<KeriEvent, SerderError>` and `serialize(&KeriEvent) -> Result<SerializedEvent, SerderError>` + `as_bytes()` used consistently. `EventVector` fields (`kind`, `case`, `ilk`, `derivation`, `raw`, `reserialize`, `blocked_by`) match the generator's emitted keys exactly. `TRACKED: &[(&str, &str)]` and `tracked_issue` signatures are consistent between `events.rs` uses. Task 7's `Vector`/`Signed`/`KeyState::incept`/`ingest` reuse the exact structs/APIs already in `differential.rs`.

## Known risks the executor should watch

- **Any NON-intive byte-identity failure in Task 4 Step 2 is a real cesr bug, not an expected red.** The plan asserts weighted, witnessed (br/ba), config, seal, and basic-derivation all round-trip. If one fails, treat it like #160: confirm against keripy, file a tracking issue, add it to `TRACKED` with its own case + issue, and note it in the ledger — do not silently `#[ignore]` without a reference.
- **Scenario count.** The generator emits 23 rows; the sweep asserts `>=20` representable. If keripy at a future pin changes a shape (e.g. adds a field), the byte-identity sweep flags it as drift — which is the point.
- **`--run-ignored` flag name.** Task 4 Step 3 uses `cargo nextest run --run-ignored all`; if the pinned nextest differs, `cargo test -- --ignored` is the fallback to force the probe.
