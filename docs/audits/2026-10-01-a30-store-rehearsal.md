# A30 synthetic Selo store migration rehearsal (partial)

Status: selected disposable Fjall stores replayed successfully under corrected
local CESR source; the isolated patched Selo gate passed. No production store,
published CESR release or quarantine/repair operator flow was exercised.

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
- The later PR #37 audit CLI source from `9e9f0e2` was copied into that same
  isolated patched checkout for an operator-command probe. Its Fjall adapter
  dependency moved from dev-only to normal dependencies there. No product
  branch or production store was altered by this probe.

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
5. `nix develop -c cargo run -p selo-kel --bin selo_kel_audit --
   /tmp/selo-a30-store-S3hvzr/invalid
   DEPIjjhH8mxoUqbrIeKv0mWS1Nj-K8Z0ikpuehf6t7Kf
   /tmp/selo-a30-cli-evidence-20261001` exited 0 and exported the rejected
   accepted row at storage version 1. `cmp` found its 345-byte `payload.bin`
   byte-identical to `invalid-basic-key.cesr`. The manifest records schema 1,
   no prior accepted coordinate and payload BLAKE3
   `23e041bc8b368ec827c30e68b7a5309b13bfd0a49ea074b695eee5a4c3aa145c`;
   `reason.txt` says the basic inception prefix does not equal its controlling
   key. The targeted corrected-source `verify` test still passed after CLI
   opening, confirming the invalid accepted row stayed unchanged and the
   valid sequence-2 head remained replayable.
6. Running the same CLI on the valid disposable store printed `accepted` and
   created no output directory. The committed PR #37 CLI test separately
   covers output overwrite and unknown-AID refusal under published crates.
7. For a full local compatibility probe, all five corrected CESR crate sources
   were copied under `vendor/cesr` in the disposable checkout and referenced
   by relative `[patch.crates-io]` paths so Nix could read them. The checkout's
   nine library parse calls already had explicit selected-profile limits; an
   integration-test wrapper supplied the same limits to its old one-argument
   parser calls. The external-store test was marked ignored in the ordinary
   gate because it requires a disposable store path, then executed explicitly
   with `MIGRATION_MODE=verify`. `nix flake check -L --option max-jobs 1`
   passed all six compatible Selo checks on aarch64-darwin. The published-graph
   wrong-controller regression remained ignored in that ordinary test lane;
   `cargo test -p selo-kel --test service
   basic_prefix_cannot_be_controlled_by_an_unrelated_signed_key -- --ignored
   --exact` then executed and passed against the corrected local graph.

The first corrected-API compile identified nine Selo library calls and the
integration-test parser calls needing explicit limits; this is the same API
family as the earlier A21 local patch probe, expanded for recovery and
proposal code. The full local gate applies to the older PR #37 audit-API
checkout plus the copied CLI and temporary test adapter, not the latest
stacked proposal-work consumer or published dependency graph. PR #37's
committed Fjall test separately proves that a repeated accepted fact returns
its exact row and preceding coordinate after restart under published crates.

## Remaining migration gate

- Publish the coordinated corrected CESR crates, adopt those **published**
  versions in current Selo, and run the wrong-controller regression unignored
  in its ordinary full gate. The passed temporary patched-source gate is only
  compatibility evidence for the older isolated checkout.
- Review and execute a quarantine/recovery procedure for rejected historical
  accepted facts. This rehearsal now confirms exact rejected-row export from
  a disposable invalid store under corrected local CESR, but the command does
  not quarantine or repair the source and no production operator run occurred.
- Rehearse a disposable copy of a real production-like store with old
  schema versions, pending requests, command markers, outbox/device receipts
  and checkpoint variants. Compare immutable facts and effect identities
  before/after; run rollback without redelivery.
