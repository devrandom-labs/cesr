# 94 — K8: direct-mode KERI end-to-end proof example

## Context

Issue #94 (K8, integration card): `examples/direct_mode.rs` — two in-memory parties run
the full KERI protocol on the pure sans-io core. No network, no db, no runtime. This
example IS the "cesr has everything except db/runtime/config" claim, and must compile
for `wasm32-unknown-unknown` in CI.

**Corrections to stale issue nouns** (decided with Joel):
- `MemKel` does not exist. State handling = `KeyState<'e>` fold (`incept`/`ingest`) +
  owned `KeyStateSnapshot` for cross-step storage. No container type.
- `SaltyKeeper` is `SaltyCustodian` (K7, `crates/keri/src/custody.rs`).

**Decisions:**
- Example home: `crates/keri/examples/direct_mode.rs`, `[[example]]` with
  `required-features = ["wire"]`, `keri-codec` as dev-dependency.
- wasm CI: extend the existing `cesr-wasm` flake check with one example-build line.
- README: rewrite — fix stale "two-crate workspace" text to the five-crate reality,
  add a "KERI without a database" section around this example.
- Revocation (step 6): drt to abandonment — `rotate` with `ncount: 0` → empty next
  keys → `Transferability::NonTransferable`. Wedge asserts below.

**Probed facts (hold at HEAD of `feat/94-k8-direct-mode`):**
- `SaltyCustodian::rotate` accepts `spec.ncount == 0`; afterwards further `rotate`
  fails `CustodyError::NotRotatable` (`crates/keri/src/custody.rs:277-305`).
- `RotationBuilder::next_keys` is optional, defaults to empty (`crates/keri-codec/src/builder/rot.rs:266`).
- Fold: `decide_transferability` (`crates/keri/src/state.rs:749`) — transferable iff
  prefix code transferable AND next-keys non-empty. Non-transferable state rejects any
  further event with `Rejection::NonTransferableState` (`crates/keri/src/state.rs:349`).
- `SaltyCustodian::params()` / `resume(salt, params)` (`custody.rs:373,390`)
  reconstruct a pre-rotation custodian — used to produce the revoked agent's stale
  signature.
- `assert!`/`assert_eq!` in examples pass the workspace clippy wall (precedent:
  `crates/keri-codec/examples/incept_aid.rs:54-67`). `clippy::print_stdout` is denied —
  file-level `#![allow(clippy::print_stdout, reason = "...")]` like
  `crates/keri-codec/examples/kel_chain.rs`.
- The `wire` feature of keri-rs provides `impl From<&EventMessage> for Signed`
  (`crates/keri/src/wire.rs:17`) — the only honest wire→fold bridge; the example MUST
  route every ingested event through `EventMessage::parse` + this adapter (that is the
  end-to-end claim).

**Key API anchors:**
- `KeyState::incept(&Signed)` — `crates/keri/src/state.rs:207`
- `KeyState::ingest(self, &Signed)` — `state.rs:348`
- `KeyState::incept_delegated(&Signed, &DelegationEvidence)` — `state.rs:257`
- `KeyState::ingest_delegated(self, &Signed, &DelegationEvidence)` — `state.rs:287`
- `KeyStateSnapshot::view()` / `From<&KeyState>` — `state.rs:509`, `state.rs:640`
- `Authority::new(keys, threshold)` / `verify(bytes, sigs) -> Result<Verified, Rejection>` —
  `crates/keri/src/authority.rs:32,69`
- `Rejection::disposition() -> Disposition` — `crates/keri/src/error.rs:253`
- `KeyState::judge_same_sn(incoming, recorded, delegation_chain) -> Result<SameSnVerdict, EvidenceError>` —
  `crates/keri/src/duplicity.rs:104`
- `DelegationEvidence::Anchored(AnchoredDelegation { delegator, delegating_event })` —
  `crates/keri/src/delegation.rs:25-47`
- Builders: `InceptionBuilder` (`keri-codec/src/builder/icp.rs:122`),
  `DelegatedInceptionBuilder::new(delegator)` (`icp.rs:140`),
  `RotationBuilder` (`rot.rs:161`, `.prior_witnesses` required),
  `DelegatedRotationBuilder` (`rot.rs:157`), `InteractionBuilder` (`ixn.rs:68`).
- `SerializedEvent::frame_v1(&ControllerIdxSigs, Option<&WitnessIdxSigs>)` —
  `keri-codec/src/serialize.rs:503`. Find the real constructor for
  `ControllerIdxSigs` from `Vec<Siger<'static>>` (it exists in cesr-stream/keri-codec —
  read the type, do not invent).
- `EventMessage::parse(&[u8])` — `keri-codec/src/message.rs:106`.
- Custody: `Custodian` trait (`custody.rs:55-83`), `KeySpec`, `KeyCommitment`,
  `SaltyCustodian::new(salt, tier, convention)` (`custody.rs:170`).
  Salt from fixed bytes: `Salt::from_raw` (see `custody.rs` tests ~line 425).
  Use the cheapest argon2 `Tier` variant (read `cesr::crypto` for its name) — the
  example must run fast and MUST NOT call `Salt::generate()` (keeps it deterministic
  and free of OS RNG on wasm).

**Lifetime pattern (invariant for the whole example):** per delivered message —
parse into a scope-local `EventMessage`, `let state = snapshot.view()`,
`state.ingest(&signed)?` (or `incept*`), then `snapshot = KeyStateSnapshot::from(&new_state)`,
drop the message. Cross-step state lives ONLY in `KeyStateSnapshot`s. Exception:
step 7b needs the recorded rot event alive — keep Alice's framed wire bytes
(`Vec<Vec<u8>>` per party, i.e. the "transcript" each side keeps) and re-parse when a
detour needs an old event. That doubles as the direct-mode story: parties exchange and
retain raw wire bytes, nothing else.

**Invariants that must hold:**
- Every protocol verdict in the script is asserted (`assert!`/`assert_eq!`/`matches!`),
  not just printed. Failure of any assert = example exits non-zero.
- `main() -> Result<(), Box<dyn Error>>` like existing examples; `?` for fallible
  setup, asserts for protocol verdicts.
- No new API in any `src/` — if something is missing, STOP and report blocked (that is
  a scope bug in K1–K7 per the issue; do not hack around it).
- Deterministic: fixed salts, no clocks, no RNG.
- Narrated: module `//!` doc explaining the scenario + "Run with:" block
  (`cargo run -p keri-rs --example direct_mode --features wire`), numbered
  step banners via `println!` matching the 7 script steps.

## Steps

### Step 1 — manifest wiring (SEQUENTIAL — first)
File: `crates/keri/Cargo.toml`
- Add dev-dependency: `keri-codec = { path = "../keri-codec", features = ["std"] }`
  (workspace-dep style consistent with how other members reference it — mirror the
  existing optional `keri-codec` dependency entry's source form).
- Add:
  ```toml
  [[example]]
  name = "direct_mode"
  required-features = ["wire"]
  ```
Expected outcome: `cargo check -p keri-rs --example direct_mode --features wire` fails
only because the example file doesn't exist yet.

### Step 2 — the example (SEQUENTIAL — depends on step 1)
File: `crates/keri/examples/direct_mode.rs` (new)

Cast: Alice (custodian A), Bob (custodian B), Agent (custodian G — provisioned and
held by Alice; the "device" only ever receives signatures, which is why revocation
locks it out). Three fixed distinct salts via `Salt::from_raw`. All `KeySpec`s:
`count: 1, ncount: 1, transferable: true` unless stated.

Each party keeps: its custodian, a `KeyStateSnapshot` per KEL it tracks, and the raw
wire transcript (`Vec<Vec<u8>>`) per KEL. Helper functions inside the example are fine
(e.g. `fn deliver(wire: &[u8], snapshot: Option<KeyStateSnapshot>) -> Result<KeyStateSnapshot, ...>`)
— keep them small; this file is documentation.

Script (each step: build → sign via custodian → `frame_v1` → deliver as wire bytes →
`EventMessage::parse` → `Signed::from` → fold → assert):

1. **Alice incepts.** `A.incept(spec)` → `InceptionBuilder::new().keys(..).next_keys(..).build()?`
   → `A.sign(event.as_bytes(), None)?` → frame → Bob ingests via `KeyState::incept`.
   Assert: self-addressing prefix (`icp.identifier()` is `Some` and equals state
   prefix), `sn == 0`, state keys == committed verkeys, `is_transferable()`.
2. **Bob incepts; exchange.** Symmetric: Bob's icp delivered to Alice. Assert Alice's
   view of Bob mirrors (prefix, sn 0). Banner notes: direct mode, zero witnesses,
   `witnesses().is_empty()`.
3. **Alice rotates.** `A.rotate(spec)` → `RotationBuilder::new().prefix(..).sn(1)
   .prior_event_said(..).keys(..).next_keys(..).prior_witnesses(vec![]).build()?` →
   sign → deliver. Assert: new state `sn == 1`, keys changed (old != new).
   Stale-key wedge preview: sign arbitrary message bytes with the PRE-rotation
   custodian (`SaltyCustodian::resume(salt_a, params_captured_before_rotate)`), verify
   against `Authority::new(state.keys(), state.threshold())` → assert
   `matches!(err, Rejection::MissingSignatures { .. })`; same message signed with
   current custodian → `verify(..).is_ok()`.
4. **Alice delegates Agent.** `G.incept(spec)` →
   `DelegatedInceptionBuilder::new(alice_id).keys(..).next_keys(..).build()?` → dip
   signed by G. Alice anchors the dip seal in an ixn (sn 2, `.anchors(..)` — read the
   builder for the seal type; the seal binds the dip's said/prefix/sn) → Bob ingests
   the ixn into his Alice snapshot FIRST. Then Bob validates the dip:
   `DelegationEvidence::Anchored(AnchoredDelegation { delegator: &alice_view, delegating_event: &ixn_event })`
   → `KeyState::incept_delegated(&signed_dip, &evidence)`.
   Assert: agent state `delegator() == Some(alice_prefix)`, sn 0.
   Also assert the negative: `KeyState::incept(&signed_dip)` (no evidence) fails with
   the delegation-evidence-required rejection (`matches!` on the variant).
5. **Agent signs; Bob verifies.** Message bytes (e.g. b"order:42") signed via
   `G.sign` → `Authority::new(agent_state.keys(), agent_state.threshold()).verify(..)`
   → assert `Ok`, and `Verified::sigs()` count == 1.
6. **Alice revokes the delegation (the wedge).** Capture `params_g = G.params()`.
   `G.rotate(KeySpec { count: 1, ncount: 0, transferable: true })` →
   `DelegatedRotationBuilder::new().prefix(agent_id).sn(1).prior_event_said(..)
   .keys(revealed).prior_witnesses(vec![]).build()?` (NO `.next_keys` — empty
   commitment = abandonment) → signed by G → Alice anchors its seal in ixn sn 3 →
   Bob ingests ixn, then `ingest_delegated(&signed_drt, &evidence)`.
   Assert, in order:
   a. new agent state `!is_transferable()` (delegation dead by pure verification);
   b. the revoked device's signature is rejected: sign a new message with
      `SaltyCustodian::resume(salt_g, params_g)` (pre-revocation keys) → verify
      against post-drt authority → `matches!(err, Rejection::MissingSignatures { .. })`;
   c. the AID is inert: build any further agent event (ixn sn 2 signed with current
      G keys), attempt `ingest` → `matches!(err, Rejection::NonTransferableState)`;
   d. custodian agrees: `G.rotate(..)` → `matches!(err, CustodyError::NotRotatable)`.
7. **Detours.**
   a. *Out-of-order (K2):* fresh replay of Alice's transcript on a new snapshot —
      incept from wire[0], then deliver wire[2] (ixn sn 2) before wire[1] (rot sn 1):
      assert `matches!(err, Rejection::OutOfOrder { .. })` and
      `err.disposition() == Disposition::Awaiting(EvidenceKind::PriorEvents { expected_sn: 1 })`
      (exact equality if the types impl PartialEq; otherwise `matches!`). Then deliver
      wire[1], wire[2] in order → success, final sn == 2. Also the stale side:
      re-deliver wire[1] → `OutOfOrder` with
      `disposition() == Disposition::Contested`.
   b. *Duplicity (K3):* forge a fork — build a second rotation at sn 1 with the SAME
      revealed keys/digests as the real rot but different content (e.g. an extra
      anchor seal), signed with Alice's current custodian. Re-parse recorded wire[1].
      `alice_view.judge_same_sn(&fork_event, &recorded_event, &[])` → assert
      `matches!(verdict, SameSnVerdict::Duplicitous { .. })`. Replay the identical
      recorded event → `SameSnVerdict::Duplicate`.

End banner: recap of what was proven, pointing at the README section.

Expected outcome: `cargo check -p keri-rs --example direct_mode --features wire`
clean; clippy clean.

### Step 3 — wasm CI line (PARALLEL OK with 4/5/6 after step 2; file disjoint)
File: `flake.nix` — in the `cesr-wasm` check's `buildPhaseCargoCommand`, after the
existing `keri-rs` line, add:
```
cargo build -p keri-rs --example direct_mode --features wire --target wasm32-unknown-unknown
```
(Default features stay on for this line — std compiles on wasm32-unknown-unknown; the
lib lines keep proving no_std separately.)
Expected outcome: `nix flake check` (run by Claude, not you) compiles the example for
wasm32.

### Step 4 — README (PARALLEL OK; file disjoint)
File: `README.md` — rewrite:
- Fix stale "two-crate workspace" → five crates; compact table (crate / import / one-line
  contents) matching the Crates table in CLAUDE.md (do not copy CLAUDE.md prose
  wholesale — README is for consumers).
- New section **"KERI without a database"**: the 7-step script narrative, what each
  step proves (K1 fold, K2 dispositions, K3 duplicity, K4 delegation, K7 custody),
  the run command, and the note that CI compiles this example for
  wasm32-unknown-unknown. Link `crates/keri/examples/direct_mode.rs` as the flagship
  example.
- Keep gate + license lines.

### Step 5 — kel_chain header fix (PARALLEL OK; file disjoint; sonic-suitable)
File: `crates/keri-codec/examples/kel_chain.rs` — the doc-header run line mentions
`--features serder`, which does not exist. Fix to
`cargo run -p keri-codec --example kel_chain`. Touch nothing else in the file.

### Step 6 — CHANGELOG (PARALLEL OK; file disjoint)
File: `crates/keri/CHANGELOG.md` — under `## [Unreleased]`, `### Added`:
one entry: flagship `direct_mode` example — direct-mode end-to-end (icp/rot/dip/
sign/revoke/escrow/duplicity) on the pure core, wasm32-compiled in CI (#94).

## Verification (sandbox rules: NO cargo test / nextest / cargo run — they hang here; tests run in Claude-driven `nix flake check`)

Per-step:
- Step 1+2: `cargo check -p keri-rs --example direct_mode --features wire`
- Step 2: `cargo clippy -p keri-rs --example direct_mode --features wire`
- Step 3: wasm cross-check IF the toolchain target is present:
  `cargo check -p keri-rs --example direct_mode --features wire --target wasm32-unknown-unknown`
  (if the target is missing in your shell, say so in the final report — Claude verifies
  via the flake check.)
- Steps 4/5/6 are docs — no build check beyond step 5's crate still passing
  `cargo check -p keri-codec --examples`.

Final report must QUOTE the tail of each check command's output (not just claim green).

## Out of scope
- NO changes to any `src/` in any crate. If the example cannot be written against the
  existing public API, report `<<<KIMI-DONE: blocked>>>` with the exact missing
  capability — that's a K1–K7 scope bug to file, not something to patch here.
- No receipts (K5) in the script — direct mode has no witnesses.
- No lint-level changes anywhere; only the file-level
  `#![allow(clippy::print_stdout, reason = "...")]` inside the new example (and it must
  carry a reason).
- Don't touch `free-fn-budget.toml`, `_typos.toml`, version grammar, or any test file.
- No commits — Claude commits.
