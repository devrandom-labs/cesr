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
| Commands and effects | A21 stores immutable candidate/request observations, an accepted command marker and an outgoing intent; A22 stores pending/resolution facts; A23 stores a typed promotion intent and receipt. Schema version 1 is checked on read. | Preserve command IDs, original candidate bytes, committed marker identity and intent digests across deployment. A duplicate command must reconcile to its existing committed fact; it must not produce a new intent. An unknown persisted schema fails closed with a typed outcome until a versioned decoder and migration test exist. After restart, replay committed outbox/pending facts; only committed facts can authorize device promotion or external delivery. |
| Projection snapshots/checkpoints | Selo's KEL loader still replays the log. Draft escrow PR #33 now checkpoints the active missing-prior index with its `$all` cursor through Mnesis `SnapshotStore<Vec<u8>, AllPosition>` and Fjall's `projection` feature; absent/stale schema replays, corrupt same-schema data fails closed. Proposal and witness indexes remain replay-only. | Treat every KEL/escrow snapshot as disposable derived state. Persist state plus `$all` position atomically, version the payload, and rebuild from immutable facts on schema mismatch. Never advance a checkpoint past an unprocessed committed fact. Measure full-replay cost before requiring that fallback on constrained hosts. |

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
  temporary local crate patches and is not a published-version or operator
  migration gate.
- Selo draft PR #37 adds a read-only `audit_kel` result with the exact first
  rejected envelope and prior verified coordinate, sharing the ordinary
  `load_kel` validation loop. A Fjall restart test proves this for a repeated
  accepted fact; the synthetic corrected-CESR follow-up returns the same
  evidence for the historical wrong-key fact. No quarantine store, export
  command or operator recovery workflow exists yet.

- The coordinated CESR release, Selo published-dependency adoption and
  unignored wrong-key test are outstanding.
- No production Selo store migration rehearsal or quarantine/export workflow
  has run. The first prior-index checkpoint is a draft and its wider format,
  proposal/witness checkpoints and host-owned escrow lifecycle remain A22 work.
- The Bombay host and actual SDK/device custody destination remain unresolved;
  this document does not claim their compatibility.
- The [independent review brief](2026-10-01-a30-independent-review-brief.md)
  is prepared; no independent reviewer has performed the authentication,
  recovery, credential or custody review yet. The full A30
  performance/fuzz/target gate remains required before foundation release
  acceptance.
