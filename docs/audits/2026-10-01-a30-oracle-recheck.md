# A30 pinned Keripy oracle recheck

Status: local pinned-oracle and Rust regressions passed on CESR PR #300.
Verify-only Linux dispatches also passed at the exact PR #301 and PR #300
heads. This checks the selected V1 profile, not every protocol variant or
production host.

The latest `main` [keripy-diff run](https://github.com/devrandom-labs/cesr/actions/runs/36852902616)
at `de08a972` failed during TEL corpus generation with
`ModuleNotFoundError: No module named 'nacl'`. It never reached the imported
oracle or Rust harness. Keripy installs `pysodium`, while the repository's
TEL, ACDC and IPEX generators import `nacl.signing` from PyNaCl. The CESR
workflow now installs the previously audited `PyNaCl==1.6.2` alongside
Keripy and smoke-imports `SigningKey` and `blake3` before generating vectors.
`nix develop --command actionlint .github/workflows/keripy-diff.yml` passed.
The same one-step dependency repair is separately available in CESR
[draft PR #301](https://github.com/devrandom-labs/cesr/pull/301) against
`main`, whose scheduled nightly otherwise remains blocked while the larger
foundation PR #300 is under review. PR #301's pinned TEL generator reproduced
its three committed corpus files byte for byte and its full local Nix gate
passed. Its [verify-only Linux dispatch](https://github.com/devrandom-labs/cesr/actions/runs/36903629795)
at `41cea42e` passed checkout, pinned Keripy install, corpus regeneration and
the differential harness. The harness log reports 65 selected tests passed
with none failed across the workspace; many other test binaries selected
zero cases under its `keripy` name filter. The App token and corpus-drift PR
steps were skipped as intended. PR #301 is still draft and unmerged, and
the scheduled `main` nightly has not run with this fix.

## Local reproduction

- Pinned Keripy checkout: `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`,
  verified with `git rev-parse HEAD` against `scripts/KERIPY_PIN`.
  Python 3.14.6 on aarch64-darwin imported `keri` from that checkout in
  editable mode, with libsodium 1.0.20 and PyNaCl 1.6.2. Other Python
  packages were resolved by `uv` for this local recheck; this is not the
  workflow's Linux `pip` environment.
- `keripy_tel_gen.py`, `keripy_acdc_gen.py` and `keripy_ipex_gen.py` ran
  with PyNaCl and blake3. The TEL generator wrote 7 happy, 7 signed and 10
  hardening rows; ACDC wrote 4, 4 and 11; IPEX wrote 7, 7 and 8.
  `cmp` confirmed all nine generated JSONL files are byte-identical to
  their committed corpus files. Generation reproduces shapes; it does not
  independently establish Keripy parity.
- The imported `keripy_tel_oracle.py`, `keripy_acdc_oracle.py` and
  `keripy_ipex_oracle.py` all exited 0. TEL checked seven happy factory,
  reader and signature rows plus a wrong-registry-anchor case; ACDC checked
  four happy and five rejected cases; IPEX checked seven factory/embedded
  rows and reported seven accepted and two rejected protocoling verdicts.
  `keripy_credential_oracle.py` checked four named credential cases and
  `keripy_ipex_flow_oracle.py` checked thirteen named flow cases, both exiting
  0. The historical A07 and A09 imported scripts exited 0 with 14 and 15
  structured outcome rows respectively. A07 needed the pinned checkout root
  on `PYTHONPATH`, as specified by the workflow; its first local invocation
  without that path failed at `from tests.vdr import buildHab` before the
  oracle ran.
- On the same CESR source tree, `cargo test -p keri-codec --all-features`
  with the eleven explicit `--test` selectors from the workflow exited 0:
  **36/36 tests passed**, none ignored. The selectors covered TEL, ACDC,
  IPEX, receipts, JSON payloads, custody, duplicity, delegation, semantics,
  credential verification and the IPEX decision path. The generated files
  were byte-identical to the test corpus, so these tests used those exact
  checked-in vectors. This is a local test run, not proof that GitHub's
  updated nightly workflow will pass.

The broader [PR #300 Linux dispatch](https://github.com/devrandom-labs/cesr/actions/runs/36904116680)
at `663bf9da` completed successfully. Its pinned Keripy checkout, PyNaCl
install, corpus regeneration and imported TEL, ACDC, IPEX, credential,
IPEX-flow, A07 and A09 oracle commands all exited 0. The `keripy` name-filter
phase passed; as noted above, it selects zero cases in many binaries. The
eleven subsequent explicit `keri-codec` binary checks each matched the
expected test count and passed **36/36 tests**, with no ignored or failed
cases. The App token and corpus-drift PR steps were skipped in verify-only
mode. Both Linux dispatches verified PR heads, not the scheduled `main`
workflow; that gate requires the backport to be merged and a subsequent
nightly to execute. A30 remains open for the published release/consumer
gate, target-device performance policy, independent security review and
product migration.
