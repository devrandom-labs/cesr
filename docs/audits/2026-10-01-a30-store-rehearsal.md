# A30 synthetic Selo store migration rehearsal (partial)

Status: selected disposable Fjall stores replayed successfully under corrected
local CESR source. No production store, published CESR release, quarantine
operator flow or full Selo migration gate was exercised.

## Inputs and boundary

- Selo source: signed draft PR #35 head `a2aa6b0`, including the direct
  recovery projection from PR #34. The old seed used its committed published
  dependency graph (`keri-rs` 0.0.15, `keri-codec` 0.9.0 and siblings).
- Corrected replay source: CESR draft PR #300 at `b54f74a7`, inserted through
  temporary `[patch.crates-io]` entries for all five local crates in an
  isolated detached `/tmp/selo-a30-migration` worktree. The temporary Selo
  copy supplied explicit `MessageLimits`/`JsonLimits` at nine library call
  sites; this patch was not committed as a product dependency migration.
- The store root was a fresh `/tmp/selo-a30-store-*` directory. The valid
  store contained five accepted signed frames: witnessed inception, two
  interactions, a sequence-1 witnessed recovery rotation and a new-branch
  sequence-2 interaction. The invalid store contained the pinned correctly
  signed, SAID-valid basic inception whose prefix belongs to another key.
- A follow-up replay used Selo draft PR #37 at `d2b6b3d`, also patched only
  in a disposable checkout to the same local CESR source. Its new read-only
  `audit_kel` path shares validation with `load_kel`.

## Executed sequence and observations

1. With published Selo dependencies, `nix develop --command cargo test -p
   selo-kel --test a30_store_rehearsal -- --exact selected_store_rehearsal
   --nocapture` in seed mode passed. `accept_candidate` committed all five
   valid recovery facts and also committed the wrong-controller inception in
   the separate invalid store. The two Fjall directories were closed.
2. After patching the isolated checkout to the corrected CESR worktree and
   supplying explicit bounds (one mebibyte body/attachment, 128 groups,
   1,024 elements/signatures/nested groups, nesting depth 16, JSON 4,096
   fields/depth 64), the same targeted test compiled and passed in verify
   mode. `load_kel` rebuilt the valid head at protocol sequence 2; its
   accepted stream still had all five original facts, including the displaced
   sequence-2 interaction at its original append position.
3. `load_kel` on the invalid store failed with
   `Decision(Wire(Body(Deserialize(InceptionIdentity(BasicKeyMismatch)))))`.
   The old invalid accepted fact remained byte-identical in its store; replay
   did not mutate or silently bless it. The verification test matched this
   exact error and the original one-row payload.
4. On the PR #37 follow-up, `audit_kel` returned the original wrong-key
   accepted envelope at storage version 1, no preceding accepted coordinate,
   and that exact `BasicKeyMismatch` reason. `load_kel` still rejected it.
   The valid five-fact store still rebuilt the sequence-2 head. The targeted
   verify test passed again under corrected local CESR without modifying
   either source directory.

The first corrected-API compile identified nine Selo library calls needing
explicit limits; this is the same API family as the earlier A21 local patch
probe, expanded for the new recovery and proposal code. The test used a
temporary harness in the isolated worktree and did not exercise the full
  Selo test suite under the corrected dependency graph. PR #37's committed
  Fjall test separately proves that a repeated accepted fact returns its
  exact row and preceding coordinate after restart under the published graph.

## Remaining migration gate

- Publish the coordinated corrected CESR crates, adopt those **published**
  versions in Selo, and run the wrong-controller regression unignored with
  full Selo checks. A local path patch is only compatibility evidence.
- Define and execute a quarantine/export and operator recovery procedure for
  rejected historical accepted facts. This rehearsal confirmed fail-closed
  replay but did not provide an operator workflow.
- Rehearse a disposable copy of a real production-like store with old
  schema versions, pending requests, command markers, outbox/device receipts
  and checkpoint variants. Compare immutable facts and effect identities
  before/after; run rollback without redelivery.
