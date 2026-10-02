# A30 independent security review brief (prepared, not reviewed)

## Review target

- CESR draft PR #300, branch `feat/foundation-correctness-profile`; review the
  final head, not the historical audit baseline. The selected profile is KERI
  V1 JSON with text CESR attachments; the [capability matrix](../capability-matrix.md)
  names the deliberate exclusions and still-open product workflows.
- Selo draft PR #41 at signed head `2660856` combines the A21–A23/A29/A30
  slices from PRs #31–#40 on one branch. Review this merged tree, including
  the custody/effect guard conflict resolution and the corrupt accepted-KEL
  device-promotion regression; the individual draft PRs alone do not exercise
  those combinations. The test-only durable Fjall device from PR #39 holds
  no keys, and PR #40's witness positions are untrusted wake hints.
  The published Selo graph still uses `keri-rs` 0.0.15,
  so its known wrong-controller-key ingress regression remains ignored until
  corrected CESR crates are published and adopted.
- The [migration review](2026-10-01-a30-migration-review.md),
  [synthetic store rehearsal](2026-10-01-a30-store-rehearsal.md) and
  [performance review](2026-10-01-a30-performance-review.md) are draft
  evidence, not release acceptance.

## Boundaries to examine independently

| Boundary | Primary code and evidence | Question for reviewer |
| --- | --- | --- |
| Event identity and authority | `crates/keri-codec/src/deserialize.rs`, `message.rs`; `crates/keri/src/state.rs`, `authority.rs`; `crates/keri-codec/tests/transitions.rs`, `keripy_semantics.rs` | Can any public typed/wire or caller-asserted path create an accepted state with an AID, key, threshold, body, signature or prior-next `ondex` that is not bound to the same event? Are malformed but SAID-valid signed inputs rejected before state creation? |
| Recovery, delegation and duplicity | `crates/keri/src/duplicity.rs`, `state.rs`, `registry.rs`; `crates/keri-codec/tests/duplicity.rs`, `delegation.rs`, `keripy_duplicity.rs`; Selo `lib.rs`, `load.rs`, `transaction.rs`, `escrow.rs`, `shares.rs`, `tests/recovery.rs`, `tests/multisig_rekey.rs`, `tests/audit.rs` in PRs #34–#37 | Can a competing/recovery/delegated event erase raw fork evidence, advance from wrong historical coordinates, or re-drive without accepted delegator/witness evidence? Are missing facts distinguished from terminal inconsistency after restart? Does audit preserve exact rejected bytes and the verified preceding coordinate? |
| Credential and exchange trust | `crates/keri/src/credential.rs`, `credential_wire.rs`, `ipex.rs`, `registry.rs`; `crates/keri-codec/tests/a27_credential.rs`, `a28_ipex.rs`, `registry_fold.rs` | Are schema, issuer KEL, registry/TEL status, chain, grant attachment and conversation identities bound to the same credential and accepted historical facts? Can a revoked or unrelated object with a correct SAID pass? |
| Custody and effect boundary | Combined Selo PR #41 `crates/selo-kel/src/controller.rs`, `service.rs`, `transaction.rs`, `load.rs`, `delivery.rs`; `tests/controller.rs`, `tests/effects.rs`, `tests/faults.rs`; `docs/custody-contract.md` | Can rejected/ambiguous acceptance, an orphan/mismatched command marker, a newly invalid accepted fact, or lost device/sink acknowledgement advance the key generation or duplicate an external effect? Is full replay before each sink call tolerable on the target device, and what coherently gates concurrent ingress? Which promises still require a real SDK/device, encrypted backup and remote signer permission implementation? |
| Direct and actor host composition (pending) | Selo `accept_candidate`; Mnesis committed log and atomic append; Bombay Entity runtime; mnesis-bombay ADR 0001 and card #5 | Does the eventual Bombay host invoke the same Selo application service as direct execution, preserve command identity and durable outcomes, and keep actor activation disposable? Are external effects sourced only from committed Mnesis facts? The current combined Selo branch does not establish this host gate. |

## Reproduction and evidence standard

1. On CESR PR #300, run the pinned Python 3.14 Keripy workflow in
   `.github/workflows/keripy-diff.yml`, the focused public regression binaries
   above, and `nix flake check -L --option max-jobs 1`. Record actual platform,
   executed counts and skipped/compile-only checks. Check CI on the exact
   reviewed head; earlier CESR heads passed local and compatible CI Nix gates,
   while CodSpeed flagged a regression with a cross-environment warning.
2. On combined Selo PR #41, run its staged `nix flake check -L --option
   max-jobs 1` and inspect the one ignored published-CESR wrong-key regression.
   Re-run it unignored only after consuming corrected **published** CESR
   versions. Distinguish Fjall restart/fault tests from simulated in-memory
   device acknowledgement. The Bombay actor host is still A21 work.
3. For each finding, provide the exact public entry point, accepted or
   rejected fixture, expected disposition and changed durable facts. Separate
   reference parity from normative policy where Keripy behavior and selected
   specification differ. Record residual risks that need an owner decision.

This brief is ready to hand to an independent reviewer. No independent review
or production-like store migration rehearsal has happened yet; A30 remains open.
