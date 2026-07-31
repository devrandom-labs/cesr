# #95 K9 — Semantic differential corpus vs keripy: same events → same verdicts, same key state

## Context

- **Why.** The differential harness proves byte-level parity (matter/counter/indexer/stream/events)
  and per-facet verdict parity (K3 duplicity `keripy_duplicity.rs`, K4 delegation
  `keripy_delegation.rs`, K5 receipts `keripy_receipts.rs`, K1 final-state
  `differential.rs` + `kels.jsonl`). What is missing is **semantic parity of the
  fold as a process**: given the same event sequence in the same *delivery
  order*, cesr and keripy reach the same **per-event verdict** — accepted /
  escrowed(reason) / rejected — and the same resulting key state. K2's escrow
  taxonomy has NO keripy differential today; that is the biggest gap this card
  closes.
- **Oracle mechanism.** keripy side: `keri.core.eventing.Kevery.processEvent`
  on a bare validator-role Kevery (pattern: `scripts/keripy_delegation_gen.py:154-236`).
  The verdict is the raised exception class (or acceptance):
  - accepted — no exception, kever created/updated
  - escrowed — `OutOfOrderError` (`.ooes`), `MissingSignatureError` (`.pses`),
    `MissingWitnessSignatureError` (`.pwes`), `MissingDelegationError` (`.pdes`/`.udes`)
  - rejected — bare `ValidationError` (drop)
  cesr side: `keri::KeyState::incept` / `ingest`
  (`crates/keri/src/state.rs:207,348`) returning `Rejection`
  (`crates/keri/src/error.rs:15`), classified by `Rejection::disposition()`
  (`crates/keri/src/error.rs:253`): `Awaiting(EvidenceKind)` ↔ escrow,
  `Terminal` ↔ drop, `Contested` ↔ duplicity branch.
- **The mapping is already documented per-variant** in the `Rejection` doc
  comments (`crates/keri/src/error.rs:15-175`) — each variant names its keripy
  escrow/exception anchor. The harness turns that prose into an executable
  assertion table.
- **Invariants that must hold:**
  - keripy is the SEMANTIC oracle, never the architecture template. The corpus
    is keripy-GENERATED (events are keripy `serder.raw`, signed by keripy-side
    deterministic signers); cesr verifies keripy's own signatures inside the
    fold — never synthesize expected values from cesr itself (circular).
  - Deterministic generator: fixed salt, no wall-clock, no OS randomness
    (pattern: `scripts/keripy_duplicity_gen.py` SALT constant).
  - Corpus embedded via `include_str!` (nix sandbox has no network/paths).
  - Test file and test names MUST contain `keripy` (nightly CI filter
    `cargo test --all-features keripy` matches test NAMES —
    `.github/workflows/keripy-diff.yml:75`).
  - Parsing untrusted corpus lines in the test may use `expect` freely
    (test code), but any production-path change is OUT OF SCOPE — this card
    owns the harness + corpus, NOT fixes. If a scenario exposes a genuine
    cesr↔keripy divergence, do NOT change `crates/keri/src` — record the
    divergence in the docs ledger (step 5), mark the vector
    `"divergent": "<ledger-id>"`, have the consumer assert the DOCUMENTED
    cesr behavior instead, and report the finding in your final output.
  - No new dependencies. No changes to `[lints]`, `clippy.toml`,
    `free-fn-budget.toml`.
  - Import style (top-of-file `use`, no inline) applies to `src/`; test files
    still keep imports at the top by convention.

## Vector schema (JSONL, one scenario per line)

```json
{
  "scenario": "escrow_out_of_order_gap",
  "family": "escrow",
  "events": [
    {"raw": "<b64 of serder.raw>", "sigs": [{"index": 0, "ondex": 0, "raw": "<b64 sig>"}]}
  ],
  "delivery": [0, 2, 1],
  "expected": [
    {"event": 0, "verdict": "accepted"},
    {"event": 2, "verdict": "escrowed", "keripy_error": "OutOfOrderError", "evidence": "prior_events"},
    {"event": 1, "verdict": "accepted"},
    {"event": 2, "verdict": "accepted", "redrive": true}
  ],
  "final_state": {"prefix": "...", "sn": 2, "keys": ["..."], "ndigs": ["..."],
                   "wits": ["..."], "toad": 0, "said": "..."},
  "keripy_version": "v2.0.0.dev5-1030-gde59bc7d",
  "note": "<one-line intent>"
}
```

- `delivery` indexes into `events`; an index MAY appear twice (re-drive after
  evidence arrives). `expected` is parallel to `delivery` (one entry per
  delivery step, in order).
- `verdict` ∈ `accepted | escrowed | rejected | contested`.
- `evidence` (present iff `escrowed`) ∈
  `prior_events | signatures | witness_receipts | delegation` — the cesr
  `EvidenceKind` the consumer must match (`crates/keri/src/error.rs:205`).
- `contested` = keripy routes to duplicate/duplicitous branch (stale sn /
  second inception); cesr disposition `Contested`.
- `final_state` is keripy's `Kever` state after all deliveries AND escrow
  re-processing — the fields mirror `scripts/keripy_keystate_gen.py`'s
  `final_state` object. Omitted (null) for scenarios whose KEL never accepts
  an inception.

## Steps

### 1. Generator `scripts/keripy_semantics_gen.py` — SEQUENTIAL (everything depends on it)

New script, modeled on `scripts/keripy_duplicity_gen.py` (arg parsing, SALT,
`b64`, `--keripy`/`--out`, deterministic signers) and
`scripts/keripy_delegation_gen.py:77-101` (`outcome()` exception-classifier
driving `Kevery(db=db).processEvent`). Requirements:

- One `Kevery` (fresh LMDB via `keri.db.basing.openDB` context, as the
  existing gens do) per scenario.
- A `deliver(kvy, serder, sigers)` helper returning the verdict tuple
  `("accepted") | ("escrowed", ExcClassName) | ("rejected", ExcClassName) |
  ("contested", ExcClassName)`; classification:
  - `OutOfOrderError`, `MissingSignatureError`,
    `MissingWitnessSignatureError`, `MissingDelegationError` → escrowed
    (record class name verbatim)
  - `LikelyDuplicitousError` → contested
  - any other `ValidationError` → rejected (record class name verbatim)
  - any non-`ValidationError` exception → `error:<class>` — and per the
    duplicity-gen rule, a checked-in corpus must contain NO `error:*`
    verdict; fix the scenario instead.
  - Re-drives: after delivering the missing evidence, call the matching
    escrow processor (`kvy.processEscrowOutOfOrders()` /
    `kvy.processEscrowPartialSigs()` / … — verify exact method names against
    the pin checkout source, `src/keri/core/eventing.py`) and derive the
    re-drive verdict from whether the kever advanced (`kvy.kevers[pre].sn`).
- **Scenario list** (each is one JSONL line; family in parens):
  1. (happy) `happy_single_sig_ladder` — icp → ixn → rot → ixn → rot,
     single-sig, in-order. Every verdict `accepted`.
  2. (happy) `happy_multisig_weighted` — 3-key weighted threshold
     `["1/2","1/2","1/2"]` icp → ixn → rot, in-order, all sigs attached.
  3. (happy) `happy_partial_rotation` — 5-key set, rotation revealing a
     subset per keripy partial-rotation semantics (reuse the #170
     partial-rotation construction from `scripts/keripy_events_gen.py`).
  4. (escrow) `escrow_out_of_order_gap` — deliver icp, then the sn-2 event
     before sn-1: `OutOfOrderError` → deliver sn-1 → re-drive → accepted;
     final state complete.
  5. (escrow) `escrow_partial_signatures` — 3-key `sith=2` icp delivered
     with 1 of 3 sigs: `MissingSignatureError` → redeliver with all sigs →
     accepted.
  6. (escrow) `escrow_partial_witness` — icp with 2 witnesses, `toad=2`,
     no witness receipts delivered: `MissingWitnessSignatureError`. No
     re-drive (final_state null) — receipt-evidence re-drive is K5's
     per-facet suite.
  7. (escrow) `escrow_missing_delegation` — dip without delegator anchor
     seal available: `MissingDelegationError` (pattern:
     `keripy_delegation_gen.py` awaiting case). No re-drive here (K4 suite
     owns the cure path).
  8. (reject) `reject_unverifiable_sigs` — icp whose only attached sig is
     forged (sign different bytes): keripy bare `ValidationError` drop;
     cesr `MissingSignatures{verified: 0}` → Terminal.
  9. (reject) `reject_stale_sn` — accepted icp+ixn, then a NEW distinct
     event at sn 1 (different digest): keripy duplicitous branch →
     contested; cesr `OutOfOrder{actual <= expected}` → Contested.
  10. (reject) `reject_nontransferable_state` — non-transferable icp
      (empty `n`), then any ixn: keripy "nontransferable or abandoned"
      `ValidationError`; cesr `NonTransferableState` → Terminal.
- Emit families to separate files: `--out-dir` writing
  `happy.jsonl` and `escrow.jsonl` (reject/contested scenarios live in
  `escrow.jsonl` — they are the same delivery-verdict harness; family field
  distinguishes).
- Docstring documents pin, env, and the exact regeneration command (step 2's
  command verbatim).

### 2. Generate the corpus — SEQUENTIAL (depends on 1)

Run (keripy pin worktree already prepared at the path below):

```bash
DYLD_LIBRARY_PATH=/nix/store/4cip8y1ab6xcpr0vynm242h202m6a874-libsodium-1.0.22-unstable-2026-04-16/lib \
PYTHONPATH=/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages \
/Users/joel/.local/bin/python3.14 scripts/keripy_semantics_gen.py \
  --keripy /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/7bc70638-c9f8-4ceb-a375-0f85c47c2748/scratchpad/keripy-pin \
  --out-dir crates/keri-codec/tests/corpus/semantics
```

Expected outcome: `crates/keri-codec/tests/corpus/semantics/{happy,escrow}.jsonl`,
10 scenarios total, zero `error:*` verdicts. Inspect each line's `expected`
against the scenario intents above before proceeding; a wrong verdict at this
stage is a generator bug, not a corpus fact.

### 3. Consumer `crates/keri-codec/tests/keripy_semantics.rs` — SEQUENTIAL (depends on 2)

Modeled on `crates/keri-codec/tests/keripy_duplicity.rs` (corpus
`include_str!`, serde-less hand-rolled or `serde_json`-based line parsing —
match whatever `keripy_duplicity.rs` does today) and `differential.rs`
(final-state assertions). Requirements:

- `const HAPPY: &str = include_str!("corpus/semantics/happy.jsonl");`
  `const ESCROW: &str = include_str!("corpus/semantics/escrow.jsonl");`
- Drive: parse each event's `raw` through `keri_codec::EventMessage` (same
  entry the existing suites use), build `Signed` via the `wire` adapter
  (`crates/keri/src/wire.rs`) exactly as `keripy_duplicity.rs` does, fold in
  `delivery` order through `KeyState::incept` / `ingest`
  (delegated events through `incept_delegated` only if scenario 7 needs a
  cure path — it does not; the escrow verdict comes from plain
  `incept`/`ingest` returning `Rejection::Delegation` → `Awaiting(DelegationEvidence)`;
  verify against the K4 suite's classify pattern
  `crates/keri-codec/tests/keripy_delegation.rs:92-100`).
- Verdict mapping asserted per delivery step (exact `assert_eq!` on a small
  local `Verdict` enum, not `contains`):
  - `Ok(state)` ↔ `accepted`
  - `Err(r)` with `r.disposition()` = `Awaiting(k)` ↔ `escrowed` + evidence
    kind name matches the vector's `evidence` field
  - `Terminal` ↔ `rejected`; `Contested` ↔ `contested`
- Re-drive steps (`redrive: true`): re-ingest the SAME event against the
  state after the evidence arrived; assert accepted.
- Final state: assert prefix / sn / keys / ndigs / wits / toad / latest SAID
  against `final_state`, same field-by-field style as
  `differential.rs:184-230`.
- Witness scenario 6: plain fold. If `ingest`'s witness handling does not
  surface `InsufficientWitnessReceipts` without host-supplied receipt
  evidence, mirror however the K5 suite (`keripy_receipts.rs`) reaches the
  witnessed verdict; if the shapes genuinely do not meet (fold API takes no
  receipt evidence), assert the cesr-reachable verdict and record the
  delta as a ledger entry (see Context invariant) — do NOT force it.
- Test functions: `keripy_semantics_happy_verdicts_and_state`,
  `keripy_semantics_escrow_verdicts`, plus one test asserting every corpus
  line was consumed (count guard, so a truncated corpus fails loudly).
- Doc comment at the top: oracle mechanism, regeneration command, pin.

### 4. Docs `docs/keripy-parity/semantics.md` + ledger link — PARALLEL OK with step 5 (disjoint files)

New file with:
- What semantic parity means here (verdict stream + final state), the oracle
  mechanism (Kevery exception classes), the schema, and the regeneration
  command.
- **Verdict-mapping table**: every `Rejection` variant → disposition →
  keripy exception/escrow (transcribe from `crates/keri/src/error.rs`
  doc comments — this is the executable-ledger index).
- **Coverage honesty table**: families and where they live —
  happy + escrow (this corpus); duplicity (`keripy_duplicity.rs`,
  including the keripy-pin defects already recorded in `ledger.md` — B2/B3/C
  cascade untestable at pin); delegation (`keripy_delegation.rs`); receipts
  (`keripy_receipts.rs`); custody derivation (`keripy_salt.rs`,
  `keripy_custody.rs`).
- **Semantic divergence ledger** section: seed with the known carve-outs —
  Tholder.satisfy dedup divergence (from `ledger.md`), plus anything step 2/3
  surfaces. Each entry: id, scenario, keripy behavior, cesr behavior, why
  intentional.

### 5. Ledger cross-link — PARALLEL OK with step 4? NO — same-file risk is zero but keep SEQUENTIAL after 4 for content coherence: add one line to `docs/keripy-parity/ledger.md` pointing at `semantics.md` for the semantics section.

## Verification

Sandbox rule: NO `cargo test` / `cargo nextest` in your session — test
binaries hang in this sandbox. Run ONLY:

```bash
cargo check -p keri-codec --all-features
cargo clippy -p keri-codec --all-features --all-targets
```

Both must be clean. The full test run happens in the commit hook's
`nix flake check` (unsandboxed), driven by the controller afterwards.
Also verify: `python3 -m json.tool` accepts every generated JSONL line
(loop over lines), and zero occurrences of `error:` in the corpus files.

## Out of scope

- ANY change under `crates/keri/src`, `crates/cesr*/src`, `crates/keri-events/src`,
  `crates/keri-codec/src` — harness + corpus + docs only.
- The existing per-facet suites and their corpora — do not touch.
- `flake.nix`, CI workflows (the name-filter picks the new tests up), lints,
  budgets, `Cargo.toml` beyond nothing (no new deps).
- keripy checkout management (worktree already prepared).
- Fixing any divergence the harness discovers — record + report only.
