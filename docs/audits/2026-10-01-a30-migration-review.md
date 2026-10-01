# A30 compatibility and migration review (draft)

Status: policy and one synthetic replay recorded; production-like migration
rehearsal and independent review remain open.
Scope: the selected KERI V1 JSON/text profile and Selo's A21–A23 draft
application branches. This is not a production-readiness decision.

## Version boundaries

| Boundary | Current evidence | Migration rule |
| --- | --- | --- |
| CESR public crates | Five interdependent crates have unpublished breaking APIs; the current released Selo graph uses `keri-rs` 0.0.15, `keri-codec` 0.9.0 and `keri-events` 0.5.0. | Publish coordinated versions in dependency order (`cesr-rs`, then `cesr-stream` and `keri-events`, then `keri-codec`, then `keri-rs`). Update Selo to published versions and adapt explicit `MessageLimits`/`JsonLimits`. No committed path patch. |
| Signed KERI/ACDC/EXN wire | The event SAID and signatures bind the original serialized bytes. The first profile accepts V1 JSON/text; unsupported versions/formats are typed outcomes. | Keep the exact original frame in candidate evidence. Never rewrite a signed body to make it parse under a new version. Route a later wire version to its own codec only when specified and tested. |
| Accepted KEL facts | Selo's draft `selo.kel.accepted` envelope uses schema version 1. Draft PR #34 replays a recovery rotation by rebuilding an in-memory canonical sequence while retaining superseded accepted facts in append order. The published dependency still accepts the pinned wrong-controller-key basic inception. | Before enabling untrusted ingress, adopt corrected published CESR, unignore that regression and replay every existing accepted KEL under the corrected decision. Quarantine any log that fails authentication or continuity; do not silently retain it as trusted state or mutate historical facts in place. A concrete quarantine/export and operator recovery procedure must pass a restart rehearsal. |
| Commands and effects | A21 stores immutable candidate/request observations, an accepted command marker and an outgoing intent; A22 stores pending/resolution facts and schema-1 content-addressed `selo.proposal.work` batches; A23 stores a typed promotion intent and receipt. The proposal decoder verifies key, schema and bounded source coordinates before use. Draft Selo PR #37 now requires an exact marker and complete accepted-KEL replay before `deliver_intent` invokes the sink; a corrected-local-CESR probe refuses the old wrong-controller store. | Preserve command IDs, original candidate bytes, committed marker identity, exact proposal work facts and intent digests across deployment. A duplicate command must reconcile to its existing committed fact; it must not produce a new intent. An unknown persisted schema fails closed with a typed outcome until a versioned decoder and migration test exist. After restart, replay committed outbox/pending/work facts; only committed facts can authorize device promotion or external delivery. Measure full-replay cost and establish a coherent startup/cursor gate for concurrent ingress before relying on per-call replay at scale. |
| Projection snapshots/checkpoints | Selo's KEL loader still replays the log. Draft PR #33 checkpoints the active missing-prior index with its `$all` cursor; PR #36 checkpoints the proposal source index with an acknowledged cursor after queuing exact work, and independently checkpoints the processed work-consumer cursor. These use Mnesis `SnapshotStore<Vec<u8>, AllPosition>` and Fjall's `projection` feature; absent/stale schema replays, corrupt same-schema data fails closed. Witness-position indexing remains open. | Treat every KEL/escrow snapshot as disposable derived state. Persist state plus `$all` position atomically, version the payload, and rebuild from immutable facts on schema mismatch. Never advance a checkpoint past an unprocessed committed fact or an unqueued proposal wake. Measure full-replay cost before requiring that fallback on constrained hosts. |

## Rollout and rollback gate

1. Pin the exact CESR release set and record lockfiles for each consumer.
   Package/compile checks alone do not establish behavioral compatibility;
   the wrong-key regression must execute unignored against published crates.
2. In a disposable copy of an existing Selo Fjall store, replay accepted KEL
   facts under the corrected decision and compare AID, protocol sequence,
   SAID and command marker with the stored history. Exercise incompatible
   envelope schema and a deliberately invalid accepted fact; both must stop
   promotion and delivery. Keep the source store untouched.
3. Stop new ingress during the cutover, retain a read-only copy of the old
   store, and restart pending/outbox workers from committed evidence. Observe
   unresolved, contested and quarantined counts before reopening ingress.
   Existing command IDs are retried, never reassigned.
4. Rollback may restore the old binary only against its original untouched
   store copy. Newer accepted facts or schemas cannot be assumed readable by
   older code. A rollback plan must avoid re-delivering external effects by
   preserving device/sink idempotency records and receipts.

## Open verification

- A [synthetic Fjall replay](2026-10-01-a30-store-rehearsal.md) passed for a
  valid recovered five-fact KEL and a published-dependency wrong-key accepted
  fact: corrected local CESR rebuilt the former and rejected the latter with
  `BasicKeyMismatch` while preserving both stores' immutable bytes. It used
  temporary local crate patches and is not a published-version or production
  operator migration gate. An older PR #37 checkout with the five corrected
  crates vendored locally then passed all six compatible Selo Nix checks after
  its test parser calls were adapted to explicit selected-profile limits.
  The ignored published-graph wrong-controller regression was run explicitly
  against that corrected local graph and passed. A second isolated checkout
  at current stacked PR #37 head `b3bc5e4` passed all six Nix checks with the
  five corrected local crates and explicit parse limits. Its wrong-key test
  passed when invoked explicitly, and its selected valid/invalid Fjall replay
  passed in verify mode. The published versions still need their own ordinary
  gate, with the regression unignored.
- Selo draft PR #37 adds a read-only `audit_kel` result with the exact first
  rejected envelope and prior verified coordinate, sharing the ordinary
  `load_kel` validation loop. Its `selo_kel_audit` command exports the first
  rejected row's exact field bytes, replay coordinates and payload digest
  from a stopped disposable Fjall copy; the [operator guide](https://github.com/devrandom-labs/selo/blob/feat/30-kel-audit/docs/kel-replay-audit.md)
  records the capture boundary. A Fjall restart test proves export for a
  repeated accepted fact. The synthetic corrected-CESR follow-up now runs
  this CLI on both old-dependency disposable stores: it exports the exact
  wrong-key accepted row and reports the valid recovered store as accepted.
  No production-like corrected-CESR store has been exercised.
- PR #37 head `706823f` additionally checks a command marker and the exact
  accepted wire during KEL replay before effect delivery. Five Fjall effect
  tests and its full six-check Selo gate passed on the committed published
  graph; a separate disposable checkout with corrected local CESR passed its
  full six-check gate and explicitly refused delivery from the old
  wrong-controller store. This is a refusal boundary, not quarantine or a
  production migration. It scans the complete accepted history on each
  delivery and can race concurrent ingress; the rollout procedure still
  requires stopped writers and a bounded host gate.

- The coordinated CESR release, Selo published-dependency adoption and the
  wrong-key test executing unignored in the ordinary current-stack gate are
  outstanding.
- No production Selo store migration rehearsal or quarantine/recovery workflow
  has run. The prior/proposal checkpoints and queued work facts are drafts;
  their wider format, witness-position index, terminal-resolution policy and
  perpetual host subscription remain A22 work. A bounded work consumer is
  implemented in Selo draft PR #36 but has no deployed scheduler.
- The Bombay host and actual SDK/device custody destination remain unresolved;
  this document does not claim their compatibility.
- The [independent review brief](2026-10-01-a30-independent-review-brief.md)
  is prepared; no independent reviewer has performed the authentication,
  recovery, credential or custody review yet. The full A30
  performance/fuzz/target gate remains required before foundation release
  acceptance.
