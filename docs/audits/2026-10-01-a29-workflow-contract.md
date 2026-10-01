# A29 multisig, witnessing and recovery contract (in progress)

The first release profile is KERI V1 JSON/text with Selo-owned workflow state.
CESR decides authentication, thresholds, commitment opening, witness sets,
delegation and recovery transitions from supplied evidence. Selo owns proposal
coordination, signed attachment retention, evidence collection, deadlines,
dissemination and restart. A successful threshold calculation alone never
means that a multi-party proposal was agreed or delivered.

| Role | Authority and durable evidence | Required host action |
| --- | --- | --- |
| Controller signer | A key at a current event's `k` index; for a rotation, its `ondex` also names a committed prior `n` position. | Agree on the exact signed body bytes and proposal SAID before signing. Retain each distinct indexed signature bound to that body and signer coordinate. Merge valid signatures only for the same body; a conflicting body at the same AID/sequence is competing evidence, not another share. |
| Witness | A key in the event's governing historical witness set. | Retain each verified indexed receipt for the exact event. Count distinct witness positions toward historical `bt`; late receipts re-drive only the matching candidate. A missing receipt cannot be replaced by a controller signature. |
| Delegator/validator | Accepted historical KEL and source seal authorizing a delegated event or validator role. | Await the exact delegator/seal coordinate; re-drive after that accepted evidence changes. A controller or witness threshold cannot stand in for delegation authority. |
| Recovery participant | Pre-committed next keys and the prior-next threshold. | For rotation, preserve current index and prior-next `ondex` separately, including sparse/reordered positions. Check the full accepted KEL head and competing proposals before promoting a new key generation. Keep the old generation until the accepted command marker and device acknowledgement protocol allow promotion. |

## First executable decision slice

`keri::Authority::verify` filters invalid/out-of-range signatures and counts
distinct verified current indices. `keri::Commitment::verify_opening` then
uses the same valid subset and each signature's distinct `ondex` to check the
prior-next commitment. The new core regression constructs two current
controllers at indices 0 and 1 exposing prior-next positions 3 and 1.
Both signatures over the exact body open a threshold-2 commitment; changing
one valid signature's `ondex` to an uncommitted position leaves current
authentication valid but rejects commitment opening. This exercises the
sparse-index rule independently of any Selo coordination claim.

## Host transcript gate still required

1. Generate pinned reference multi-controller inception, partial shares,
   rotation with noncontiguous `ondex`, witness receipt and conflicting
   same-sequence proposal. Record exact body, SAID, group and signer bytes.
2. Park one-share and delayed-witness candidates under exact evidence keys.
   Persist each distinct share/receipt; reject cross-body and cross-AID
   substitution; replay after Fjall restart without duplicating acceptance or
   delivery. Check participant/key-set changes only at an authenticated
   establishment transition.
3. Exercise abandoned proposal, competing recovery rotation, lost response,
   delegation-chain arrival and stale evidence after supersession. Require
   the direct and actor host to reach the same committed outcome.
4. Run the pinned oracle, all supported feature/target checks, Selo fault gate
   and full CESR Nix gate. A29 remains open until these are executed.

Selo A22's escrow branch indexes missing-prior KEL events and offers an
explicit, bounded `assemble_controller_shares` path over separately observed
raw command candidates. Its candidate/request identity binds each exact
initial wire frame and intent; a distinct aggregate command submits the
deterministic merged frame. Stacked witness draft PR #33 extends that manual
assembly to delayed indexed receipts with `assemble_event_evidence`; pinned
restart tests cover TOAD 1, sparse two-of-three TOAD 2, duplicate receipt
rejection and an unrelated-key receipt. A pinned post-restart rotation cuts
one witness and adds another: the cut witness's signature cannot satisfy the
rotation's resolved set, while the added witness's signature does. The pure
KERI decision still checks the governing witness set/TOAD. Selo does
not yet automatically park/index/wake a proposal on partial-signature or
receipt arrival, establish multi-party agreement, host witness KELs or
implement KAACE. Those are the next host implementation boundaries, not
implied capabilities of the sparse-ondex core test.
