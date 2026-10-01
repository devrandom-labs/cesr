# A30 independent security review brief (prepared, not reviewed)

## Review target

- CESR draft PR #300, branch `feat/foundation-correctness-profile`; review the
  final head, not the historical audit baseline. The selected profile is KERI
  V1 JSON with text CESR attachments; the [capability matrix](../capability-matrix.md)
  names the deliberate exclusions and still-open product workflows.
- Selo draft PRs #30 (direct accepted KEL), #31 (prior escrow and retained
  shares), #32 (custody, stacked on #31), #33 (witness/proposal workflow,
  also stacked on #31), #34 (direct recovery, stacked on #33) and #35
  (sparse multisig rekey, stacked on #34). #32 and #33–#35 are sibling
  branch lines; neither contains the other's last changes.
  The published Selo graph still uses `keri-rs` 0.0.15,
  so its known wrong-controller-key ingress regression remains ignored until
  corrected CESR crates are published and adopted.
- The [migration review](2026-10-01-a30-migration-review.md) and
  [performance review](2026-10-01-a30-performance-review.md) are draft
  evidence, not release acceptance.

## Boundaries to examine independently

| Boundary | Primary code and evidence | Question for reviewer |
| --- | --- | --- |
| Event identity and authority | `crates/keri-codec/src/deserialize.rs`, `message.rs`; `crates/keri/src/state.rs`, `authority.rs`; `crates/keri-codec/tests/transitions.rs`, `keripy_semantics.rs` | Can any public typed/wire or caller-asserted path create an accepted state with an AID, key, threshold, body, signature or prior-next `ondex` that is not bound to the same event? Are malformed but SAID-valid signed inputs rejected before state creation? |
| Recovery, delegation and duplicity | `crates/keri/src/duplicity.rs`, `state.rs`, `registry.rs`; `crates/keri-codec/tests/duplicity.rs`, `delegation.rs`, `keripy_duplicity.rs`; Selo `lib.rs`, `load.rs`, `transaction.rs`, `escrow.rs`, `shares.rs`, `tests/recovery.rs` in PR #34 | Can a competing/recovery/delegated event erase raw fork evidence, advance from wrong historical coordinates, or re-drive without accepted delegator/witness evidence? Are missing facts distinguished from terminal inconsistency after restart? |
| Credential and exchange trust | `crates/keri/src/credential.rs`, `credential_wire.rs`, `ipex.rs`, `registry.rs`; `crates/keri-codec/tests/a27_credential.rs`, `a28_ipex.rs`, `registry_fold.rs` | Are schema, issuer KEL, registry/TEL status, chain, grant attachment and conversation identities bound to the same credential and accepted historical facts? Can a revoked or unrelated object with a correct SAID pass? |
| Custody and effect boundary | Selo PR #32 `crates/selo-kel/src/controller.rs`, `service.rs`, `transaction.rs`, `delivery.rs`; `tests/controller.rs`, `tests/faults.rs`; `docs/custody-contract.md` | Can rejected/ambiguous acceptance or lost device/sink acknowledgement advance the key generation or duplicate an external effect? Which promises still require a real SDK/device, encrypted backup and remote signer permission implementation? |

## Reproduction and evidence standard

1. On CESR PR #300, run the pinned Python 3.14 Keripy workflow in
   `.github/workflows/keripy-diff.yml`, the focused public regression binaries
   above, and `nix flake check -L --option max-jobs 1`. Record actual platform,
   executed counts and skipped/compile-only checks. The current draft full gate
   and compatible CI Nix jobs passed; the CodSpeed comparison has one flagged
   regression and a cross-environment warning.
2. On each Selo draft branch, run its staged `nix flake check -L --option
   max-jobs 1` and inspect the one ignored published-CESR wrong-key regression.
   Re-run it unignored only after consuming corrected **published** CESR
   versions. Distinguish Fjall restart/fault tests from simulated in-memory
   device acknowledgement. The Bombay actor host is still A21 work.
3. For each finding, provide the exact public entry point, accepted or
   rejected fixture, expected disposition and changed durable facts. Separate
   reference parity from normative policy where Keripy behavior and selected
   specification differ. Record residual risks that need an owner decision.

This brief is ready to hand to an independent reviewer. No independent review
or production-store migration rehearsal has happened yet; A30 remains open.
