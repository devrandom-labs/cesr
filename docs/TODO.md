# CESR/KERI foundation work queue

Updated: 2026-09-30. Baseline: `de08a972b390ea640519d4dcb7343d5dc4a864b9`.
Purpose: make the full protocol foundation correct, idiomatic, efficient and
understandable before composing Selo with Bombay, Mnesis and mnesis-bombay.

Evidence and design rationale: [foundation audit](audits/2026-09-29-foundation.md).
Reproductions: [audit probes](audits/2026-09-29-probes.rs).
Earlier strategy and `docs/superpowers` plans are historical context; reconcile
them against current code. This queue does not silently supersede an existing
issue/ADR's contract. Record any conflict before implementation.

## Start a new session

Use this prompt:

> Read `docs/TODO.md` and `docs/audits/2026-09-29-foundation.md`. Check the current
> commit and worktree. Continue the first unblocked foundation task; default to
> A01 if none has been started. Verify the finding against current code, add a
> regression that fails on the defect, implement the focused fix, run the
> required gate, and update this queue with the result and remaining work. Keep
> the pure protocol boundary and explain intentional API changes. Do not combine
> unrelated cleanup with a correctness fix.

Session procedure:

1. Read applicable repository instructions, current changes, this queue, and the
   selected task's source. Preserve other work. Check whether a later commit
   already fixed the finding before reproducing it.
2. Select one task (or one explicitly recorded subtask) and mark it in progress.
   Do not start every task or redesign all five crates at once.
3. For a confirmed defect, convert the observation into a normal regression test
   asserting the **desired** behavior. Audit probes deliberately assert bad
   current behavior and are not regression tests to retain unchanged.
4. Keep the source of protocol truth, invariant owner, and trust boundary explicit.
   Reference implementations can have defects; document intentional divergence
   with a spec reason and executable evidence.
5. Run focused checks while developing, then `nix flake check` before declaring
   implementation complete or committing. Record platform, feature profile,
   commands and actual outcomes. Do not claim skipped/cached checks were rerun.
6. Update the task, change log if the public API changed, and the session log.
   Record exact remaining acceptance criteria and the next starting point.
7. Keep concrete security findings local unless the owner authorizes external
   publication; follow `SECURITY.md`. This audit created no external issues.

Status convention: `[ ]` open; `[-]` in progress; `[x]` accepted/verified.
No implementation task below was completed during the audit. An audit conclusion
or a test demonstrating a defect is not a fix.

## Work order and dependencies

- First: **A01, A02, A03, A04** (authentication and state integrity).
- **A05** (quadratic copying) is independently actionable and urgent for exposed
  input. It can be done between correctness tasks without a domain redesign.
- Then **A06–A09** (input provenance, TEL semantics, IPEX, payload grammar).
- **A10–A15** repair ownership, performance and stream contracts. A12 follows
  the TEL evidence decision in A07; A14 follows A05.
- **A16–A18** establish reliable protocol evidence, feature gates and documentation.
  Start A16 alongside protocol fixes when generating the needed oracle vectors.
- **A19–A23** settle consolidation and product composition after the boundary fixes.
- **A24–A30** are the remaining protocol capability decisions/implementation tracks.
  A24 records supported versions/profiles; each later track must cite that choice.
  Being listed does not mean every optional format or product integration belongs
  in a first release. Any exclusion must be explicit in the capability matrix.

## Acceptance and functionality

### [x] A01 — Bind inception identity to its controlling authority

Priority: critical. Audit F01. Owner: `keri-codec/src/deserialize.rs`,
`keri/src/state.rs`; structural laws may belong in `keri-events`.

- Reproduce `audit_basic_identifier_accepts_an_unrelated_controlling_key`.
- Reject basic prefixes with unrelated keys, wrong key cardinality or invalid
  threshold. Check exact prefix/code rules against the selected specification.
- Inventory nontransferable-prefix restrictions and digestive-prefix requirements
  for `dip`/`drt`; decide their owning validation boundary.
- Verify both standalone typed decode and decode → signed fold. Constructors
  must not provide an ordinary route around the selected checked contract.
- Replace invalid positive fixtures where necessary; do not weaken the validator
  to retain a convenient fixture (some use unrelated basic prefixes and keys).

Done when: the attack is rejected as a specific typed error before state is
created; valid basic and self-addressing identifiers still interoperate; targeted
oracle vectors and the full gate pass.

### [x] A02 — Enforce delegated event kinds during advancement and recovery

Priority: high. Audit F02. Owner: `keri/src/state.rs`, `duplicity.rs`.

- Reject plain `rot` on delegated state. Retain valid delegated `ixn` behavior.
- Reject `drt` on nondelegated state consistently; validate early routing and
  disposition semantics.
- Test genuine anchored dip → ordinary rot rejection and dip → anchored drt
  acceptance, plus recovery routes. The observation uses `HostAccepted` only to
  establish its initial dip; include the full anchored path in regression tests.

Done when: event-kind changes cannot skip delegation authorization, with reference
comparison and typed errors. Depend on A01 only where shared construction changes.

### [x] A03 — Enforce actual witness/backer set invariants on untrusted input

Priority: high. Audit F03. Owners: event validation, `authority.rs`, `registry.rs`.

- Reject duplicate witness identities before indexed signatures are counted.
- Review nontransferable witness/backer eligibility, prohibited identity overlap,
  duplicate cuts/adds, cut/add overlap, and TOAD's zero/nonzero domain law.
- Apply the same invariant owner to builder and wire paths; keep state-dependent
  membership checks in the transition.
- Add the duplicate-witness wire attack, malformed rotations and analogous TEL
  cases. Preserve valid witness ordering because signature indices depend on it.

Done when: one witness cannot satisfy two distinct-witness positions; hostile
wire inputs cannot bypass builder-only checks; valid permutations and rotations
retain correct indexed receipt semantics.

Recorded A03 subtasks (execute in order; all are required):

1. **A03.1 static KEL membership:** reject duplicate or ineligible witness
   identities on `icp`/`dip` and duplicate/ineligible `br`/`ba` on `rot`/`drt`
   from direct events and wire, sharing a domain-level invariant with builders.
2. **A03.2 state-dependent KEL membership:** enforce cut membership, additions
   absent from the prior set, cut/add disjointness, resolved ordering and the
   TOAD domain law through the validating fold; test valid permutations and
   indexed receipt behavior.
3. **A03.3 TEL backers:** apply the same static membership and eligibility
   rules to `vcp`/`vrt` builder, decoder and registry fold, and verify cut/add
   membership and TOAD against the resolved backer set.
4. **A03.4 comparison and gate:** execute pinned reference checks for the
   relevant cases, focused tests, all features/target checks and `nix flake
   check`; record exact outcomes and migration guidance before marking A03.

### [x] A04 — Bind transitions and contests to complete event coordinates

Priority: high. Audit F04. Owners: `state.rs`, `duplicity.rs`, evidence consumers.

- Require event prefix == state prefix before interaction/rotation advancement.
- Review prefix, sequence, digest, event kind and historical establishment bindings
  on contests, receipts, delegation and TEL anchors.
- Distinguish a structural contest classification from authenticated duplicity
  evidence. An unauthenticated candidate must not become durable proof of a fork.
- Test mismatched AIDs with real signatures and internally consistent SAIDs.

Done when: wrong-identifier events are rejected on every applicable public path;
the existing valid same-sn/recovery cases remain valid.

Recorded A04 subtasks (execute in order; all are required):

1. **A04.1 transition prefix:** reproduce F04 with a signed, SAID-valid
   wrong-AID interaction, cover rotations and delegated rotation, and bind
   prefix to the state before advancement on each validating fold path.
2. **A04.2 evidence coordinates:** verify incoming/recorded same-sn prefix,
   sequence and SAID bindings, delegation-chain seals, receipts and TEL
   management anchors against existing issue/ADR contracts; reject mismatched
   host-supplied coordinates with typed errors.
3. **A04.3 duplicity boundary:** keep structural same-sn classification
   distinct from verified fork evidence, with an executable regression showing
   an unsigned candidate cannot become durable authenticated proof; preserve
   valid recovery semantics.
4. **A04.4 oracle and gate:** compare with pinned keripy, run focused/public
   wire tests and all required feature/target checks plus `nix flake check`;
   record migration guidance and exact outcomes before marking A04.

### [x] A05 — Remove quadratic group/message suffix copying

Priority: high. Audit P01. Owners: `cesr-stream/group`, `keri-codec/message`, async codec.

- Preserve shared input ownership across repeated group parsing, or copy only the
  consumed frame. Include following messages when analyzing copied suffixes.
- Repair key-event, receipt, TEL and EXN consumers through the common owner.
- Cover framed and bare groups, concatenated messages, truncated groups, errors,
  and retained group buffers. Preserve exact remainders and signed body bytes.
- Add byte-allocation scaling tests at `EventMessage::parse` / `Message::parse`,
  not only at `Groups::over`. Do not enforce a magic wall-clock threshold.
- Audit the async element-group path's per-message tail copy separately.

Baseline: 94,507 input bytes / 1,024 bare groups → 49,120,238 requested allocation
bytes. 101,120 input bytes / 256 framed messages → 13,531,776 requested bytes.
Done when: cumulative copied/allocated bytes scale linearly with equivalent input
and output; allocation/retained-memory evidence and correctness tests pass.

Recorded A05 subtasks (execute in order; all are required):

1. **A05.1 measurement and ownership audit:** reproduce P01 through the
   public key-event and generic message parsers in release mode; inspect
   `CesrGroup`, `Groups`, retained buffers and the async group path.
2. **A05.2 common parsing fix:** preserve ownership or limit copies at the
   shared group parser, then route key-event, receipt, TEL and EXN attachment
   consumers through it without changing remainder or signed-body semantics.
3. **A05.3 adversarial and scaling evidence:** assert linear requested-byte
   allocation growth across bare/framed, concatenated/truncated/error cases,
   retained buffers and async tails; compare to the recorded baseline.
4. **A05.4 gate:** run focused/full tests, required features and targets,
   `nix flake check`, and record measured commands, outcomes and limitations.

### [x] A06 — Make event/body provenance and trusted evidence explicit

Priority: high API risk. Audit F05. Owners: `Signed`, `SignedTel`, wire adapters.

- Choose a codec-neutral ordinary input contract that preserves the association
  between the parsed event and its exact signed bytes.
- Make caller-asserted construction and accepted-event rehydration explicit.
  Avoid pretending a public wrapper proves membership in a remote or durable KEL.
- Review public `Verified` reuse against a different authority/message. Couple
  proof creation/use or narrow the public surface where appropriate.
- Correct the false claim that mismatched bytes necessarily fail verification.
- Coordinate with A10 to borrow signature slices and avoid extra wrappers/copies.

Done when: the recommended wire path cannot accidentally pair unrelated values;
trust assumptions are testable/documented; misuse is rejected or confined to an
explicitly trusted path; no new runtime dependency enters default `keri`.

Recorded A06 subtasks (execute in order; all are required):

1. **A06.1 trust-boundary inventory and red regression:** verify F05 in the
   current fold, identify every `Signed`/`SignedTel` construction and every
   public `Verified` consumer; reconcile K1/#128 and wire-adapter contracts.
2. **A06.2 input contract:** close ordinary event/body pairs at the message
   adapter, provide an explicitly named caller-asserted codec-neutral path for
   hosts with other parsers or accepted-event rehydration, and preserve exact
   signed bytes without a default codec dependency.
3. **A06.3 proof scoping:** prevent a `Verified` result from being used as
   authentication for another event/authority at the public commitment API;
   add misuse/valid-path tests and migration guidance.
4. **A06.4 gate:** focused tests, default/no_std/WASM/wire builds, full Nix
   gate and exact evidence; coordinate signature borrowing with A10 without
   dropping A06's provenance criteria.

### [x] A07 — Correct TEL authentication, historical evidence and escrow

Priority: high protocol gap. Audit F06. Owners: `registry.rs`, TEL messages/errors.

- Execute the pinned reference's Tevery/Tever, not just its event factories.
- Model issuer KEL anchoring for registry/credential events, including the exact
  accepted anchor coordinate and attachment layouts.
- Distinguish missing anchor/issuer/registry evidence from inconsistent evidence;
  missing facts that can arrive later must yield the appropriate awaiting result.
- Supply historical registry/backer state as evidence instead of rejecting every
  event whose governing management head is no longer current.
- Cover first-seen acceptance, out-of-order evidence, delayed anchors, delayed
  backer receipts, issuance/revocation and re-drive after key/backer rotation.
- Replace blueprint-based divergence with spec-grounded decisions and corpus
  evidence. Split this task into named subtasks before implementation if needed.

Done when: an executable TEL semantic matrix agrees with the chosen reference/spec
profile, with justified divergences, and genuine framed TEL traffic reaches it.

Recorded A07 subtasks (execute in order; all are required):

1. **A07.1 reference contract and red matrix (done):** inspect the pinned Tevery/Tever
   code and official TEL specification, execute the reference over real vcp,
   vrt, iss, rev, bis and brv traffic, and record accepted, escrowed and
   terminal outcomes with exact anchor coordinates and attachment layouts.
   Preserve the sibling checkout's existing work.
2. **A07.2 issuer anchoring and evidence taxonomy (done):** add failing framed-wire
   regressions for issuer KEL anchoring at every TEL ilk, then model accepted
   anchor coordinates and separate missing issuer/anchor/registry evidence
   from supplied inconsistent evidence with correct disposition and re-drive.
3. **A07.3 historical backers (done):** supply the anchored management event's
   historical registry/backer state through host evidence; validate its
   registry coordinate, management sn/SAID, backer set and threshold before
   admitting bis/brv after later registry rotation.
4. **A07.4 end-to-end matrix (done):** cover first-seen, out-of-order and delayed
   evidence, delayed backer receipts, issuance/revocation, issuer key and
   registry backer rotations, plus genuine `Message::parse` framed TEL
   traffic. Document every intentional spec/reference divergence with an
   executable case.
5. **A07.5 gate and migration (done):** run focused oracle, feature/target and full
   Nix checks; update TEL API migration guidance and record actual outcomes.

### [x] A08 — Repair every public IPEX construction path

Priority: high functionality. Audit F07. Owner: `keri-codec/src/ipex.rs`.

- Stop decoding hash-placeholder `#` characters as a qualified digest.
- Define construction-before-SAID versus serialized/verified values deliberately.
- Test apply, offer, agree, grant, admit and spurn from their actual public
  constructors through serialization, deserialization and `IpexMessage::parse`.
- Include real embedded ACDC/issuance/anchor bodies and empty/optional fields
  according to the selected protocol profile.

Done when: the public builders work; tests are not limited to deserializing a
hand-generated happy corpus. Text escaping correctness additionally requires A09.

### [x] A09 — Correct generic JSON payload grammar without changing signed bytes

Priority: interoperability. Audit F08. Owners: scanner, SAD, ACDC, EXN, IPEX.

- Separate fixed CESR tokens from arbitrary JSON strings/numbers.
- Define supported canonical forms using spec and live oracle cases. Cover quotes,
  backslashes, escaped controls, UTF-8/surrogates, negative numbers, decimal and
  exponent forms, duplicate keys, object order and nesting limits.
- Preserve original accepted bytes for SAID/signature verification; do not
  normalize data before checking what was signed.
- Reconcile the strict scanner, opaque scanner and SAD scanner; retain deliberate
  grammar differences as policy at the appropriate level.

Done when: ordinary human messages and credential attributes round-trip and
interop; malformed inputs fail as typed errors; valid signed bytes stay exact.

Recorded A09 subtasks (execute in order; all are required):

1. **A09.1 reference and profile contract (done):** pin the V1 JSON canonical form
   against the KERI/SAID drafts, RFC 8259, pinned keripy's serializer/parser,
   and actual IPEX/ACDC wire examples. Inventory strict, SAD and opaque
   scanner differences. Record the A24 versioned capability matrix before
   choosing or implementing any profile-dependent acceptance rule.
2. **A09.2 red public-path matrix (done):** add failing tests for escaped human text,
   UTF-8 and surrogate pairs, numeric forms, duplicate keys, object order,
   nesting limits, exact SAID/signature bytes and malformed typed errors.
3. **A09.3 scanner and typed-lift repair (done):** separate fixed CESR token strings
   from generic JSON, preserve original wire slices for hashes/signatures,
   decode human text deliberately, and reconcile the strict/SAD/opaque walks.
4. **A09.4 oracle and gate (done):** run pinned oracle comparisons, adversarial,
   feature/no_std/WASM and full Nix checks, record API migration and outcomes.

## Ownership, performance and simplification

### [x] A10 — Remove authentication-boundary copies and duplicate work

Audit P02/P03. Owners: wire adapters, crypto verification, authority, threshold.

- Borrow signature slices for transient validation; measure owned alternatives
  only where asynchronous retention actually requires them.
- Resolve keys by reference instead of cloning each `Matter` to unwrap a role.
- Deduplicate exact signature material before crypto while preserving invalid-
  first/valid-later and meaningful ondex cases.
- Reuse the verified index set through threshold and commitment checks.
- Measure controller/witness/receipt/backer paths and no_std compatibility.

Done when: allocation and crypto-work regressions guard the public paths, current
valid/invalid signature semantics are preserved, and the before/after report
includes counts plus statistically useful release benchmarks.

Recorded A10 subtasks (execute in order; all are required):

1. **A10.1 baseline and contracts:** inventory public controller/witness/receipt/backer authentication routes, borrowed versus retained signature ownership, key-resolution and duplicate-signature semantics. Capture allocation counts and release timing distributions before the change, including the P02/P03 probes.
2. **A10.2 red public-path regressions:** assert preserved invalid-first/valid-later and ondex behavior, duplicate crypto-work bounds, transient borrowing and host-retention needs at public boundaries before changing implementation.
3. **A10.3 focused implementation:** borrow transient signature/key views, deduplicate exact signature material before crypto without losing valid alternatives, and reuse verified indices for threshold/commitment decisions across the affected paths.
4. **A10.4 evidence and gate:** measure before/after allocation and statistically useful release benchmarks for 1/16/64/256 signatures and controller/witness/receipt/backer paths; run focused, feature/no_std/WASM and full Nix checks; record API migration and platform limits.

### [x] A11 — Preserve state ownership on rejected transitions

Audit P04. Owners: `KeyState::ingest`, delegated ingestion, `RegistryState::ingest`.

- Choose recoverable consumption, borrowed decision/update, or validate-before-
  mutate based on caller needs; prototype the real retry loop before committing.
- Test failed delivery followed by added evidence using the actual retained state,
  without cloning solely to hide consumption.
- Account for cheap `KeyStateSnapshot::view()` and avoid needless ownership APIs.
- Correct registry claims about the old state being returned/retained.

Done when: retry ownership is explicit and usable; rejection cannot leave a
partially advanced state; success/retry allocation behavior is recorded.

Recorded A11 subtasks (execute in order; all are required):

1. **A11.1 contracts and retry prototype:** verify consuming failure behavior in current KEL, delegated and TEL APIs; compare a host retry loop over `KeyStateSnapshot::view()` with a retained registry state and choose the API that avoids cloning on rejection or success.
2. **A11.2 red public-path regressions:** write and execute actual failed-delivery → added-evidence → successful-redrive loops for KEL, delegated rotation and TEL, using the same retained state without cloning; prove exact state preservation and no partial advancement on terminal and retryable failures.
3. **A11.3 focused implementation:** provide validated, in-place ingestion for retained state while keeping the current consuming convenience API; perform all fallible checks before mutation, including credential-chain lookup, and correct misleading docs. Preserve snapshot's cheap borrowed view.
4. **A11.4 evidence and gate:** measure host retry and success allocations versus clone-based calls (include snapshot conversion), run focused, feature/target and full Nix checks, record public API migration and platform limits; mark `[x]` only when all criteria pass.

### [x] A12 — Separate registry management from unbounded credential state

Depends on A07's evidence model. Audit P04. Owner: `keri/src/registry.rs`.

- Prototype a credential status transition over caller-supplied previous credential
  state and governing registry evidence, with lookup/persistence outside the core.
- Compare against a justified bounded aggregate; do not automatically replace
  `Vec` with a map and retain the same unbounded ownership problem.
- Provide an owned persistence boundary and historical evidence inputs.
- Benchmark distinct issuance and random status lookups at increasing cardinality;
  include memory retention, replay and rejected-delivery costs.

Done when: per-credential work does not scan all unrelated credentials, no lifetime
requires retaining the full input history, and issuer/registry bindings remain valid.

Recorded A12 subtasks (execute in order; all are required):

1. **A12.1 contract and baseline:** inventory the current TEL state/evidence APIs and existing issue/ADR contracts; measure distinct issuance, random status lookup, retained memory, replay and rejected-delivery cost over increasing credential counts. Record the selected per-credential boundary and API migration before editing the fold.
2. **A12.2 red public-path regressions:** write executable issue/revoke/backed and adversarial binding cases over caller-supplied previous credential state plus registry management and historical evidence; include owned persistence/reload and retry without unrelated credential history. Prove the intended new contract fails before implementation.
3. **A12.3 focused split:** keep only bounded, owned registry management in its state, make credential transitions operate only on the caller-supplied owned credential head after all validation, and migrate public wire, host and tests without weakening disposition or provenance checks. Remove the unbounded aggregate API and redundant historical-evidence wrapper rather than retaining compatibility facades; no compatibility requirement has been set.
4. **A12.4 scaling, oracle and gate:** repeat issuance/lookup/replay/rejection measurements at the same cardinalities, check source-byte retention, compare TEL semantics to the pinned reference, run focused/all-feature/no_std/WASM and full `nix flake check`; document migration, actual outcomes and remaining platform limits before marking A12 `[x]`.

### [x] A13 — Reuse encoding buffers and measure owned representations

Audit P02. Owners: `Matter`, `Indexer`, JSON writer, serialization.

- Add append/encode-into support at the substrate where useful; remove per-field
  qb64 strings and padded scratch copies when a correct direct write is simpler.
- Preserve partial-block/padding/canonicality rules with boundary and oracle tests.
- Measure end-to-end serialization and primitive paths; benchmark stack/fixed-size
  crypto material before replacing flexible `Cow` types.
- Prefer ceilings or scaling laws over equality tests that reject improvements.

Done when: measurable reductions are preserved by allocation tests and benchmarks;
no unsafe shortcut or semantic duplication is introduced.

A13 execution subtasks (one at a time):
1. **A13.1 contract and baseline:** verify current CESR right-aligned, zero-lead-byte and zero-pad-bit rules against the published table and pinned keripy; inventory all production qb64 write paths, profile primitive and representative JSON allocations/time in release, and separately measure fixed-size owned key storage before changing `Cow`.
2. **A13.2 red regressions:** add allocation-ceiling and byte-exact tests for zero/one/two lead bytes, all indexer header classes, variable lengths and writer reuse. Demonstrate failure before the rewrite; retain semantic corpus/oracle expectations, not the old allocation count.
3. **A13.3 focused encoding:** write qb64 directly into caller-owned buffers at the CESR substrate, reuse that path for owned convenience results and JSON field writes, eliminate redundant scratch and per-field strings, and avoid a second encoder or pass-through wrapper layer.
4. **A13.4 measurement and gate:** repeat release primitive and end-to-end measurements, run keripy comparison and target/feature checks, run fresh full `nix flake check`, update changelog/API guidance and actual evidence, then mark A13 complete only if all criteria hold.

### [x] A14 — Define bounded incremental framing and work limits

Depends on A05 for shared buffer ownership. Owner: `cesr-stream`, message adapter.

- Specify partial-input, end-of-input, malformed-frame and consumed-remainder
  behavior, including body-complete/attachments-incomplete and bare attachments.
- Correct short JSON headers being classified as missing/malformed version before
  sufficient bytes arrive; ensure successful parsing always makes progress.
- Define limits for message bytes, attachment bytes/counts, signatures, fields and
  nesting. Supply policy explicitly; remain independent of clocks/network I/O.
- Prevent whole-prefix reparse/copy for every arriving fragment where it produces
  quadratic work; test byte-by-byte delivery, coalescing and hostile lengths.

Done when: a deterministic sans-I/O decoder contract composes with an async host,
has bounded memory/work, and returns the same messages for every chunking.

A14 execution subtasks (one at a time):
1. **A14.1 framing contract and baseline:** inventory `CesrMessage`, `Message::parse`, `CesrCodec`, `Groups` and JSON/attachment scanners against the CESR cold-start/version-first rule and issue #193/#208 contracts; measure byte-by-byte versus coalesced work, memory and exact outcomes. Specify EOF, bare attachment, body/attachment ambiguity, progress and explicit caller work limits before changing public behavior.
2. **A14.2 red public regressions:** reproduce short valid JSON version prefixes reported as malformed, truncated body/attachment, partial element groups, malformed heads, hostile declared lengths/counts, field/nesting/signature budgets, and exact consumed remainder across all supported chunkings. Assert desired typed incomplete/malformed/limit outcomes and linear work before implementation.
3. **A14.3 bounded state machine:** implement a sans-I/O incremental decoder whose framing state survives fragments and whose limits are supplied explicitly; reuse the existing typed CESR/body parsers and exact signed bytes, eliminate repeated whole-prefix scans, and have the async host adapter delegate to it without a parallel grammar.
4. **A14.4 evidence and gate:** execute chunking equivalence, hostile-length scaling, pinned oracle and integration tests, all-feature/no_std/WASM checks and fresh full `nix flake check`; document API/migration and remaining profile-dependent work before accepting A14.

### [x] A15 — Establish integrated performance and memory baselines

Owners: benchmarks/allocation tests. Can begin before A05; refresh after fixes.

- Measure parse → bind → verify → transition → owned accepted state, happy and
  rejected paths, receipt accumulation, recovery, and large credentials.
- Vary input bytes, group count, key/witness/signature count, duplicate signatures,
  credential count, chunk size and batch size.
- Record release configuration, hardware, distributions, throughput, allocations,
  allocated bytes and retained memory. Keep crypto/security settings equivalent.
- Measure `SaltyCustodian` Argon2 derivation/signing separately; choose any key
  cache only with an explicit secret-lifetime policy.

Done when: future optimization decisions have reproducible representative data.
No cross-stack speed claim without equivalent workload/trust/durability boundaries.

A15 execution subtasks (one at a time; all required):
1. **A15.1 workload and measurement contract (done):** inventory the public parse → bind → verify → transition → owned-state route, receipt/recovery/TEL/credential routes and current microbenches; pin representative signed fixtures and adversarial variants. Specify release toolchain/features, hardware, sampling/warm-up, throughput, allocation/requested-byte and retained-memory methodology, and equal crypto/security settings. Record a reproducible harness command before measuring.
2. **A15.2 integrated KEL/receipt/recovery matrix (done):** execute happy and rejected signed folds, receipt accumulation and recovery across input bytes, group count, keys, witnesses, signatures, duplicate signatures, chunk size and batch size; report distributions, throughput, allocations/requested bytes and retained memory rather than one timing observation.
3. **A15.3 credential/lifecycle matrix (done):** execute large credential and credential-count workloads with TEL/ACDC parsing/verification paths, including accepted and rejected cases; report the same measurement dimensions and ownership profile.
4. **A15.4 custody isolation (done):** measure `SaltyCustodian` Argon2 derivation and signing separately with equivalent tier/security settings. Do not add a key cache without an explicit secret-lifetime policy.
5. **A15.5 evidence and gate (done):** archive representative raw results and environment, document variance/limitations and any optimization decisions, run focused feature/target checks and fresh `nix flake check`, then accept A15 only if each axis and path above has reproducible evidence.

## Protocol evidence and maintainability

### [x] A16 — Replace shape-only parity and fix nightly test selection

Owners: `scripts/keripy_*`, corpora, `.github/workflows/keripy-diff.yml`.

- Generate TEL/ACDC/IPEX behavior using imported pinned keripy with Python 3.14.
  Keep generated provenance and reproducible environment details.
- Run explicit test binaries or assert expected selection counts; filename
  `keripy_tel.rs` does not make every test match the `keripy` name filter.
- Add the newly found acceptance defects to a negative semantic corpus, including
  malformed-but-SAID-valid and correctly signed adversarial events.
- Distinguish code-table, factory-byte, parser and state-machine parity in reports.
- Document oracle defects and spec-based divergences; never patch expectations
  simply to make local behavior pass.

Done when: CI proves which families ran and which are independent oracle evidence;
missing corpus rows/test selection cannot silently pass.

A16 execution subtasks (one at a time; all required):
1. **A16.1 selection and provenance baseline (done):** inspect pin, Python 3.14 environment, current shape generators/corpus claims, relevant issue/ADR and differential workflow; demonstrate which named tests currently run, then make CI execute complete explicit parity test binaries with nonempty/count assertions. Preserve existing corpus bytes until an imported reference comparison establishes replacements.
2. **A16.2 imported TEL factory/semantic oracle (done):** generate or byte-check every supported TEL happy/signed shape through actual pinned keripy factories/reader, run real Tevery anchor/backer/chain verdicts, archive pin/dependencies/commands and classify reference limitations.
3. **A16.3 imported ACDC oracle (done):** generate or byte-check compact/expanded/nested ACDC and signed behavior through pinned `credential`/`SerderACDC`, extending coverage without silently excluding optional aggregate forms; keep unsupported profile decisions in A24.
4. **A16.4 imported IPEX oracle (done):** run all route and embed bodies through pinned exchange/specialExchange/protocoling behavior, verify signatures and typed route outcomes, and make the nightly generation use the imported oracle rather than only deterministic shape reproduction.
5. **A16.5 negative semantic corpus and gate (done):** add malformed-but-SAID-valid and correctly signed adversarial acceptance cases with typed Rust expectations and independent reference outcomes; distinguish code-table, factory-byte, parser and state-machine parity in the ledger/report. Run explicit selected suites, Python 3.14 imported oracle and final `nix flake check`, then mark A16 only when every criterion is met.

### [x] A17 — Verify the supported feature/build matrix honestly

Owners: Cargo manifests and Nix checks.

- Enumerate supported standalone feature profiles per crate and compile/test them
  separately where required; all-features is not all feature combinations.
- Include default protocol core without wire, alloc-only, supported WASM/no_std
  targets, and optional async/wire paths. Record compile-only versus tested.
- Check accidental feature unification (`internals`, `test-utils`, `std`, crypto)
  and downstream examples in small independent consumer crates.
- Measure dependency/WASM size before deciding to split custody/Argon2/algorithms
  into finer optional features; no speculative crate explosion.

Done when: manifests, documented guarantees and CI matrix agree.

A17 execution subtasks (one at a time; all required):
1. **A17.1 standalone profile baseline (done):** inventory manifest promises and current Nix builds, reproduce the plain no-default failures, and test each supported crate/profile in isolated consumer manifests so dev-dependency/workspace feature unification cannot mask defects.
2. **A17.2 feature and target gate (done):** encode the supported standalone/default/alloc-only, core-without-wire, async/wire, and WASM/no_std matrix in CI/Nix; make profile exclusions explicit and fix confirmed defects rather than relabeling broken supported paths.
3. **A17.3 size and documentation (done):** measure dependency and WASM-size effects of custody/Argon2/algorithms before a feature split decision; reconcile manifests, CLAUDE/README, capability matrix and check descriptions, run the full gate, and record executed versus compile-only evidence.

### [x] A18 — Correct live documentation and isolate historical claims

Owners: README, crate docs, CLAUDE.md, strategy, parity reports, examples.

- Correct provenance, failure ownership, allocation, binary/format support and
  capability-completeness claims found in the audit.
- Replace stale module names and misleading example snippets with compiling ones.
- Mark old design plans/audits historical or link to their verified replacement.
- Review abandonment vs rotation prohibition vs application authorization; do not
  describe loss of next-key commitment as an automatic cryptographic revocation of
  every possible application signature without an explicit acceptance policy.

Done when: one capability matrix and one current work queue are discoverable,
and public claims are supported by named executable evidence.

A18 execution subtasks (A17's external Nix-store gate is pending; resume it first
when available):
1. **A18.1 claim inventory (done):** map live README/crate docs/CLAUDE/examples to current public paths and A01–A17 evidence; identify misleading provenance, failure, allocation, format and capability statements without editing historical audit evidence.
2. **A18.2 focused corrections (done):** update live docs and example sources, link the authoritative work queue and capability matrix, and distinguish abandonment, rotation rules and host application authorization. A18.3 must still prove the example commands compile.
3. **A18.3 executable verification (done):** run example/doc tests, source-linked evidence checks and `nix flake check` on final docs; keep unsupported claims explicit and mark complete only when every acceptance clause is met.

### [x] A19 — Consolidate invariant owners and accepted-state computation

Depends on A01–A04/A07 decisions. Audit P05.

- Inventory where each law lives: primitive syntax, event structure, signed-body
  binding, chain rule, historical evidence, or host/application policy.
- Share witness/backer ordered-set calculation where the laws match.
- Share accepted update computation between validating state and trusted snapshot
  replay where doing so reduces drift without rerunning cryptography.
- Preserve exhaustive enums and typed errors. Keep trusted replay's storage
  integrity contract explicit and property-test equivalence on accepted histories.

Done when: duplication removed corresponds to a shared responsibility; cognitive
load and public surface actually shrink; trust boundaries remain visible.

A19 execution subtasks (one at a time; all required):
1. **A19.1 owner inventory (done):** map primitive, event, signed-body, chain, historical and host-policy laws to current public paths; reconcile P05, the K6/#92 and witness/#149 contracts with the KERI specification. Identify which repeated calculations truly share a law and which differ by trust/error contract. [Inventory](audits/2026-09-30-a19-owners.md).
2. **A19.2 ordered membership (done):** add focused witness/backer and accepted-history checks, then share the ordered cut/add computation without adding a public wrapper or moving cryptography into trusted replay; preserve typed rejections and builder guard order.
3. **A19.3 accepted updates (done):** evaluate the validating and trusted state assignments; remove duplicated accepted-update logic where a private common calculation demonstrably reduces drift, and property-test full-state equivalence across accepted plain/delegated histories. The ordered member update is the common computation; the borrowed validating assignments and owned trusted assignments remain distinct by contract.
4. **A19.4 verification (done):** run focused regressions, target/feature checks and `nix flake check`; measure source/API change and document residual distinct responsibilities before marking A19 complete.

### [x] A20 — Review public API and vocabulary placement

After urgent fixes. Owners: all crate roots; EXN/IPEX/event construction.

- Evaluate moving EXN/IPEX domain values into `keri-events`, keeping codecs and
  protocol decisions in their respective owners.
- Replace misleading `internals` feature constructor contracts with an explicit
  checked/unchecked design; features are not access-control capabilities.
- Review overly coupled lifetimes and ergonomic standard traits (`Debug`, useful
  equality/conversions) on public values, including `KeriEvent`.
- Remove construction-stage placeholders masquerading as validated protocol data.
- Keep useful sealed group/builders/newtypes. Reassess the free-function ratchet
  as a documented policy proposal; do not change protected lint/config policy
  without the required owner authorization.

Done when: a small consumer example shows a clearer import/ownership/error path;
breaking changes have deliberate migration notes.

A20 execution subtasks (one at a time; all required):
1. **A20.1 ownership and contract inventory (done):** compare current public imports, EXN/IPEX wire/data boundaries, constructors, lifetimes, traits and placeholder states against the current issue/ADR and pinned protocol profile. Record a concrete minimal design, including any vocabulary that should stay in the codec. [Inventory and design](audits/2026-10-01-a20-api.md).
2. **A20.2 explicit construction contract (done):** remove the misleading `internals` feature and distinguish unchecked constituent-field construction from checked wire/builder paths, with regressions and migration guidance.
3. **A20.3 consumer ergonomics (done):** add only useful standard traits/conversions and eliminate validated-looking construction placeholders where a clear state model exists; prove with a small standalone consumer and signed-wire tests. The builder's placeholder remains private serialization scratch and is never returned as a validated event.
4. **A20.4 verification and policy proposal (done):** run focused native/no_std/WASM checks and `nix flake check`, update the capability matrix and changelogs, and record a ratchet-policy recommendation without editing protected lint/config policy.

## Product composition and remaining capabilities

### [-] A21 — Prove Selo's durable acceptance transaction

Depends on correctness and ownership fixes. Owner: Selo integration, not CESR core.

- Reconcile current sibling versions/instructions: Bombay, Mnesis (currently
  checked out as sibling `nexus`), and `mnesis-bombay` ADR 0001.
- Prototype receive → decode → gather accepted evidence → pure decision → atomic
  optimistic append → durable outgoing intent → effect delivery.
- Keep protocol sequence/SAID distinct from storage revision and command ID.
- Test duplicate delivery, conflict/retry, ambiguous append result, crash after
  commit before send, rehydration and evidence-version changes.
- Preserve competing events while selecting a canonical KEL history; recovery must
  not erase the facts needed to establish duplicity.

Done when: direct and Bombay-hosted execution share the durable path and identical
protocol outcomes; notifications alone are never treated as durable delivery.

A21 execution subtasks (all required):

1. **A21.1 inventory and first red aggregate slice (done):** reconciled exact checked-out/published CESR, Selo, Mnesis, Bombay and mnesis-bombay contracts; the [host inventory](audits/2026-10-01-a21-host-inventory.md) records the transaction ownership gap. On Selo card #20's branch, a real signed KEL test initially accepted a repeated protocol event at a new store version; the trusted rehydration fold now checks KERI coordinate continuity. Selo's indexed full Nix gate passed.
2. **A21.2 durable acceptance transaction (storage mechanics verified; dependency gate open):** retained raw competing evidence, revalidated the accepted KEL, and atomically CAS-appended accepted facts, command identity and outgoing intents. Protocol `s`, SAID, command ID and Mnesis version remain distinct. Tested duplicate commands, competing signed SAIDs, conflicts, Fjall restart, ambiguous pre/post-commit failures and incompatible persisted schemas. A signed wrong-key basic inception from pinned keripy is still **accepted** through published `keri-rs` 0.0.15; an isolated Selo copy with corrected local CESR crates and explicit A14 limits rejects it. Selo must consume a corrected **published** CESR version and run that regression unignored before this subtask is accepted. Its latest published-dependency Nix gate passes with this one test explicitly ignored. [Evidence](audits/2026-10-01-a21-host-inventory.md).
3. **A21.3 direct and Bombay hosts:** execute the same application service from both entry paths, reconcile confirmed conflicts and ambiguous append results, and deliver external effects only from committed intents with a named receipt boundary.
4. **A21.4 fault and restart gate:** duplicate delivery, conflict, ambiguous result, crash-after-commit, rehydration, evidence-version changes, duplicity preservation and the full Selo/Bombay/Mnesis gates must pass before A21 is accepted.

### [-] A22 — Implement durable escrow/evidence workflows outside the core

Depends on corrected dispositions (A07/A11). Owner: Selo/Mnesis/Bombay adapters.

- Define typed evidence requests and dedup keys; accumulate partial signatures and
  receipts; re-drive only affected events when evidence arrives.
- Add bounded queues/storage quotas, cancellation, logical deadlines and explicit
  retry policy. Keep timers, lookups and network calls out of pure validation.
- Test restart, repeated evidence, stale evidence, missing prerequisites and
  permanent rejection; distinguish supersession/recovery from normal retry.

Done when: every awaiting disposition has an owner and tested progress/termination
conditions; no network scheduling policy is hidden in the protocol fold.

A22 execution subtasks (all required):

1. **A22.1 evidence contract and first red KEL slice (done):** map every corrected-core `EvidenceKind` to an owner, exact dependency coordinate and re-drive trigger. Selo card #21's `docs/escrow-contract.md` records the mapping and laws. A real signed out-of-order interaction failed the initial compile for absent escrow APIs, then passed a Fjall restart/re-drive test. A separate red command-collision regression proved an initially rejected command ID could change its outgoing intent; atomic candidate/request observation now binds the exact intent. The current published `keri-rs` has only the KEL subset, so the coordinated CESR release remains a dependency.
2. **A22.2 durable indexed KEL escrow (prior-event slice in review; rest open):** the per-command pending fact, bounded `$all` request replay after a crash before parking, saved-intent re-drive and lost-resolution-reply reconciliation execute. A bounded `PriorWakeIndex` rebuilds from committed facts and selects only the exact AID/missing sequence; independent signed second-AID and later-sequence fixtures exercise filtering and resolution. A cursor-driven `PriorLogWorker` now polls committed `$all` batches, wakes exact prior dependencies, replays after Fjall restart and retries a transient re-drive read without skipping its row. Add a host-owned perpetual subscription/checkpoint, per-AID and per-tenant quotas, partial signatures, witness receipts and delegation.
3. **A22.3 TEL, credential, IPEX and discovery evidence:** re-drive only candidates whose exact accepted dependency changed, preserve typed terminal and contested outcomes, and avoid pure-core I/O.
4. **A22.4 restart and fault gate:** repeated/stale evidence, missing prerequisites, deadlines, cancellation, quotas, ambiguity, supersession and full Selo/Mnesis/Bombay gates pass before A22 is accepted.

### [-] A23 — Define custody and client/agent trust boundaries

Owner: Selo custody application/adapters, shared primitives as appropriate.

- Specify where secrets live, remote signing permissions, key derivation policy,
  encrypted backup/recovery and algorithm support.
- Make prepare/sign/commit of rotations crash-safe; a rejected/ambiguous durable
  append must not strand the custodian at the wrong key generation.
- Test retries, restart, abandonment, unauthorized signing and hardware/remote
  signer behavior. Avoid putting device or network I/O in the deterministic core.

Done when: documented threat/ownership decisions have executable rotation/recovery
scenarios and an explicit client/agent protocol profile.

A23 execution subtasks (all required):

1. **A23.1 direct controller and custody seam (first slice implemented):** Selo card #24's `docs/custody-contract.md` assigns device/SDK ownership of secrets, approval and encrypted backups. Its typed preparation request loads the accepted KEL head and requires exact AID, prior SAID and next sequence; a pinned keripy signed rotation is submitted through A21's atomic fact/marker/intent transaction. The committed outbox gates device promotion, with a durable receipt after acknowledgement. Focused tests cover unauthorized preparation, stale frames, abandonment without storage effects, rejected rotation, restart and idempotent promotion. The staged Selo `nix flake check -L` passed all six compatible checks, with the known published-CESR security regression still ignored. The checked-out Selo depends on published `keri-rs` 0.0.15, so this is not an untrusted production authentication pass.
2. **A23.2 real local/hardware/remote custody and recovery (open):** enforce local approval and key-generation persistence in an SDK/backend, implement and test encrypted backup/recovery ownership, remote signer denial and operation-scoped permissions, and prove ambiguous accept/device acknowledgement recovery.
3. **A23.3 complete protocol/fault gate (open):** run actual client/agent transcripts through the chosen profile, retry/restart/abandonment/recovery scenarios and full Selo/CESR integration gates after the corrected CESR crates are published and adopted.

### [x] A24 — Pin the protocol and interoperability profiles

Owner: protocol capability matrix and version policy.

- Pin CESR/KERI/ACDC spec revisions and the reference implementation revision.
- Distinguish V1/V2 counters, version strings, native bodies, JSON/CBOR/MessagePack,
  text/binary attachments, algorithms and application exchange routes.
- Inventory every required clause/feature as implemented, partial, missing or
  intentionally excluded, with evidence and owner. Include GramHead and remaining
  code-table omissions without equating their count with semantic completeness.
- State which Signify/KERIA interoperability is a goal versus Selo-only protocol.

Done when: unsupported inputs have deliberate typed behavior, and “complete” has
a finite, versioned and testable definition. Do this before choosing release scope.

A24 execution subtasks (one at a time; all required):

1. **A24.1 pinned source and current-path inventory (done):** compare the exact CESR/KERI/ACDC revisions and keripy pin to the current capability matrix, correct stale audit assumptions, and map each public version/encoding/algorithm/route boundary to its current behavior.
2. **A24.2 release profile decision (done):** record required and excluded cells, including Signify/KERIA versus Selo-only exchange, with an explicit rationale for every exclusion. The first foundation release selects V1 JSON/text and a Selo-specific client/agent route; later profiles remain possible.
3. **A24.3 typed unsupported behavior and evidence (done):** add regressions for unsupported combinations, close any accidental acceptance path, and link independent fixtures for every advertised supported cell. The A24 report distinguishes local primitive tests from independent message fixtures.
4. **A24.4 final matrix and gate (done):** reconcile the parity ledger and live docs, run focused and full feature/target checks including `nix flake check`, and record exact outcomes before marking A24 accepted.

### [x] A25 — Complete binary/native/versioned wire paths for the selected profile

Depends on A14/A24. Owner: CESR substrate, stream and codecs.

- Add actual qb2 group/message parsing or an explicit documented conversion
  boundary; recognizing a binary cold start is insufficient.
- Implement native CESR-v2 bodies and additional serializers only if included in
  A24; otherwise expose exact unsupported-profile errors.
- Test text/binary equivalence, mixed boundaries, version changes, truncation,
  alignment, exact remainders and supported attachment families.

Done when: every advertised wire combination has public end-to-end fixtures and
independent reference comparisons.

A25 execution subtasks (one at a time; all required):

1. **A25.1 wire-boundary inventory (done):** reconcile the A24 V1 JSON/text selection with public framing, primitive qb2 conversion, ACDC body-only reads, and the exact attachment families used by signed fixtures.
2. **A25.2 conversion boundary and regression (done):** document how a caller-delimited qb2 attachment blob converts to qb64 before typed V1 parsing, with a pinned signed fixture, truncation/alignment, mixed-domain rejection and exact remainders. No binary message parser is advertised.
3. **A25.3 final gate (done):** run focused tests, required feature/target builds and `nix flake check`; update the capability matrix and record exact outcomes.

### [x] A26 — Add query/reply, discovery and key-state exchange foundations

Depends on A24. Owners: event/codec/protocol layers; networking in Selo.

- Model `qry`/`rpy`, key-state notices, endpoint-role/location replies, relevant
  reply acceptance/replay rules and historical signature authority.
- Define OOBI resolution's evidence requirements; fetching/caching/routing remain
  host work. Keep message representation separate from application routing.
- Test stale/replayed replies, wrong signer/route, absent evidence and updates.

Done when: the protocol foundation can validate the selected discovery/state
exchange workflows without embedding a transport or database.

A26 execution subtasks (one at a time; all required):

1. **A26.1 pinned V1 contract and red corpus (done):** reconcile issue #82's deliberate `qry`/`rpy` exclusion with A24's selected release requirement, execute pinned keripy V1 `query`/`reply`/key-state factories, and record exact field domains, routes and attachments. The current KERI spec prose omits top-level V1 `i`, while its V2 examples include it; pinned keripy confirms that version split.
2. **A26.2 typed body and attachment paths (done):** added V1 `qry`/`rpy` vocabulary, canonical byte/SAID readers and writers, typed framed dispatch, and independent fixtures without admitting V2 fields through the V1 path. Seven pinned fixtures round-trip byte-exactly and preserve `-F` signer coordinates, `-C` nontransferable signer couples and unsigned OOBI status.
3. **A26.3 pure acceptance decisions (done):** selected `/logs`, endpoint-role/location, key-state notice and OOBI reply paths have signer/route bindings, historical threshold authentication, KSN fields backed by the accepted key-state snapshot, RFC-3339-aware replay rules and typed awaiting/terminal outcomes.
4. **A26.4 gate and host boundary (done):** stale/replayed/wrong-signer/absent-evidence/update cases pass; fetch/cache/routing remain outside the core; the indexed full Nix gate passed; the capability matrix and [host integration contract](discovery-integration.md) record the boundary.

### [x] A27 — Complete credential verification beyond SAID checking

Depends on A07/A09/A24. Owner: pure credential protocol plus host evidence retrieval.

- Verify schema, issuer binding, registry status, historical authority and required
  ACDC chains/rules. Define cycle, depth, resource and missing-evidence semantics.
- Specify disclosure/path-signature/privacy features in the chosen profile.
- Test genuine issuer/holder/verifier flows and failures that still have valid
  SAIDs, including revoked credentials and unrelated registry/issuer evidence.

Done when: a credential verification result has a defined trust meaning beyond
well-formed serialization and content hashing.

A27 execution subtasks (all required):

1. **A27.1 contract and red corpus (done):** pinned `Schemer`, `SerderACDC`, KEL/TEL factories and `Verifier.verifyChain` at `de59bc7d`; four base cases plus I2I/NI2I/DI2I, rules and disclosure bodies retain valid SAIDs. The public test initially failed for missing `VerifiedSchema`.
2. **A27.2 issuer, schema and status judgment (done):** exact schema `$id` SAID and local bounded Draft 7 validation compose with accepted issuer KEL, registry and credential TEL heads; revoked status is invalid for the current-validity result.
3. **A27.3 chains, rules and bounds (done):** bounded transitive I2I/NI2I verification, claim/cycle/depth/node/byte checks and typed awaiting/terminal outcomes; DI2I, nonempty rules, referenced/aggregate attributes, path signatures and selective disclosure are excluded explicitly in the [A27 report](audits/2026-10-01-a27-credential.md).
4. **A27.4 flow/gate (done):** genuine issuer/holder KEL and registry/credential TEL transcript, wrong issuer/registry/issuee/schema, missing evidence and revocation tests pass; the [host contract](credential-integration.md) and capability matrix are updated. The indexed full Nix gate passed with 2,587/2,587 release tests; see the [A27 report](audits/2026-10-01-a27-credential.md).

### [x] A28 — Implement IPEX and EXN protocol decisions

Depends on A08/A09/A24 and credential evidence as needed.

- Define route sequence, prior-message link, sender/recipient authority,
  duplicates/replays, spurn and partial evidence; support only documented paths.
- Validate embedded credential/issuance/anchor relationships and required pathed
  attachments, rather than verifying independent hashes and assuming linkage.
- Keep conversation state deterministic; transport, storage and notifications are
  host responsibilities. Test two-party transcripts and adversarial substitutions.

Done when: actual issuer/holder exchanges interoperate and cannot cross-bind an
unrelated credential, participant or conversation.

A28 execution subtasks (all required):

1. **A28.1 contract and red transcript (done):** pinned reference route/prior and `-L` pathed attachment behavior, built genuine signed two-party apply/offer/agree/grant/admit/spurn and seven signed adversarial frames, and observed the initial public parser reject the `PathedMaterialCouples` group.
2. **A28.2 conversation judgment (done):** authenticated historical EXN sender state, applicant/issuer alternation, exact prior SAID, replay/competing response and spurn/terminal rules have typed awaiting/terminal outcomes and unchanged heads on rejection.
3. **A28.3 grant evidence (done):** offer and grant bind the exact embedded ACDC and `e.acdc` pathed indexed issuer signature; grant requires accepted schema/registry/TEL/KEL and exact embedded issuance plus issuer KEL anchor. Direct offer/grant starts and other pathed attachment forms are [excluded explicitly](ipex-integration.md).
4. **A28.4 flow/gate (done):** the pinned issuer/holder flow, adversarial substitutions and missing evidence pass the public path; the [host contract](ipex-integration.md), [A28 report](audits/2026-10-01-a28-ipex.md), capability matrix and nightly oracle are updated. The indexed full Nix gate passed with 2,589/2,589 release tests.

### [ ] A29 — Complete multisig, witness and recovery workflows

Depends on A01–A04/A22/A24. Owner: pure protocol decisions plus Selo workflows.

- Distinguish threshold mathematics already implemented from coordination,
  agreement on exact body bytes, partial signature merging and dissemination.
- Specify controller/witness/validator roles and receipt collection policy.
- Test noncontiguous ondex, participant changes, delayed receipts, conflicting
  proposals, recovery and delegation-chain evidence after restart.

Done when: real multi-party transcripts demonstrate liveness and rejection laws;
existing small threshold tests alone do not close this task.

### [ ] A30 — Run the foundation release review

Depends on all capabilities declared required in A24, and A15–A18/A21–A23.

- Re-run the defect regressions, semantic oracle matrix, fuzz campaigns, supported
  feature/target builds and representative performance workloads.
- Record residual risks and deliberate exclusions. Arrange independent security
  review of authentication, recovery, credential and custody boundaries.
- Establish compatibility/migration policy for accepted event storage, snapshot
  formats, public crate APIs and wire versions.

Done when: the selected foundation has traceable evidence and bounded operational
behavior. The decision to call Selo production-ready belongs to the product owner.

## Session log

### 2026-10-01 — A30 stream ownership/performance preflight (aarch64-darwin)

- CESR PR #300's CodSpeed simulation reported six regressions and warned that compared runs used different runtime environments. A same-host `nix develop -c cargo bench -p cesr-stream --bench stream -- stream_parse_scaling` comparison used the same Rust/toolchain, `CARGO_TARGET_DIR` and four 100-sample Criterion cases at pre-change `de08a972`, the feature head `e31559a7`, and a focused local V1 parser optimization. Median times for 1/16/64/256 two-signature groups were **74.275 ns / 703.03 ns / 2.4901 µs / 9.9872 µs** at the pre-change commit, **102.91 ns / 1.5477 µs / 6.0189 µs / 24.295 µs** at the feature head, and **60.725 ns / 823.00 ns / 3.0035 µs / 12.711 µs** after avoiding the second element scan for framed V1 controller/witness groups. The focused group and allocation tests, including the retained-first-group-under-1-KiB test, pass after the change. The pre-change iterator kept one shared allocation for the whole stream; the current iterator copies one completed frame so a retained group cannot retain following frames. The remaining 256-group cost is about 27% above that pre-change path on this host, with bounded ownership preserved. A four-group/768-byte chunk experiment measured 12.300 µs at 256 but was slower at 1/16/64 groups and was removed. The staged `nix flake check -L --option max-jobs 1` then passed: Nextest 2,589/2,589 with 24 skipped, plus all compatible WASM/no-std, Clippy, fmt, docs/doctests, examples, deny and fuzz replay checks. This is a preflight observation, not A30 acceptance; CI/CodSpeed recheck and broader representative workloads remain.

### 2026-10-01 — A22 escrow and A23 custody slices in review (aarch64-darwin)

- Selo's A22 card #21 direct KEL prior-event escrow slice is stacked as draft PR #31 on #30. Commit `0f61347` added a bounded cursor-driven committed-log poller that wakes exact prior dependencies and replays after restart; live polling and transient read retry tests pass. The staged full `nix flake check -L` after this addition passed all six compatible checks; the known published-CESR wrong-controller-key regression remains ignored. Host-owned perpetual subscription/checkpoint, remaining evidence families, per-tenant quotas and the wider fault/restart matrix remain open.
- Selo's A23 card #24 first controller/custody slice is draft PR #32, now stacked on A22 PR #31 after resolving the shared README edit. Its signed commit head is `f8d3824`. `prepare_rotation` passes an exact accepted-head request to an approving device, and `submit_rotation` atomically commits a signed keripy rotation with a promotion intent. `promote_rotation` checks the accepted command claim before receipt reuse or device invocation; a forged-outbox-plus-receipt regression failed first and now passes. A new fault test covers pre-commit ambiguity with no promotion and a committed rotation whose append reply is lost and reconciled before promotion. Focused controller/fault tests, strict Clippy, pinned keripy fixture regeneration, combined A22/A23 `selo-kel` tests and the full integrated Selo Nix gate passed after this addition. The device/SDK still needs real key custody, recovery and ambiguous-device-acknowledgement proof. A21–A23 and A29–A30 remain open; CESR draft PR #300 is not merged or published.
- CESR draft PR #300's two Nix jobs and deep fuzz checks passed. Its CodSpeed check reports six benchmark regressions while warning that compared runs used different runtime environments. Investigate that measurement under A30 before treating the performance gate as resolved.

### 2026-10-01 — A21 published CESR authentication gate found (commit de08a972, aarch64-darwin)

- A follow-up package verification proved this is a coordinated five-crate release, not an isolated `keri-rs` bump: `cargo package --allow-dirty` for `keri-rs` failed against published `keri-events` 0.5.0, and `keri-codec` failed against published `cesr-stream` 0.6.0/`keri-events` 0.5.0. The workspace and isolated all-local Selo copy pass with matching source revisions. The dependency order and exact gate are recorded in the [A21 host inventory](audits/2026-10-01-a21-host-inventory.md); no crates were published.
- A pinned keripy factory generated a 345-byte SAID-valid, correctly signed basic inception whose prefix belongs to another key; keripy rejected `Mismatch prefix`. The new Selo regression against published `keri-rs` 0.0.15 **failed** with `Ok(Committed(InMemoryAllPos(4)))`. The Selo `nix flake check -L > /tmp/selo-a21-auth-blocked-flake.log 2>&1` exited 0 with **one explicitly ignored security regression**; it is not an authentication pass. An isolated Selo copy patched to the corrected CESR worktree and adapted to A14's explicit message/JSON limits passed that exact ignored test when invoked with `--ignored`. [Evidence and remaining release dependency](audits/2026-10-01-a21-host-inventory.md). A21 and the whole TODO remain open.

### 2026-10-01 — A21 durable Selo acceptance and effect receipt slice (commit de08a972, aarch64-darwin)

- Upgraded Selo's new `selo-kel` branch from Mnesis 0.2.2 to the current host's published Mnesis 0.3.1 family. The direct `accept_candidate` service now retains raw candidates, revalidates the accepted KEL, decides against its current root, and atomically appends the accepted event, command marker and outgoing intent. Conflict reload, command collision and ambiguous append reconciliation have typed outcomes; injected pre/post-commit and reconciliation read faults pass. The prior error loss on failed reconciliation was fixed. Foreign marker schema and accepted-fact schema regressions failed first, then passed with explicit event type/schema checks. `deliver_intent` reads the committed outbox, calls an idempotent sink with the command ID, and records a named receipt after acknowledgement; Fjall restart, sink reply loss and receipt append reply loss pass. A forced competing head and cancellation immediately after commit also pass without losing raw evidence or duplicating an accepted fact. The indexed Selo `nix flake check -L > /tmp/selo-a21-cancellation-flake.log 2>&1` exited 0 **before** the new basic-prefix probe. That pinned signed probe then failed as expected: published `keri-rs` 0.0.15 committed a wrong-controller basic inception. The Selo regression is ignored with an explicit release dependency, not accepted as a passing authentication gate. [Host inventory and remaining work](audits/2026-10-01-a21-host-inventory.md). A21.2 transaction mechanics are verified, but its dependency gate and A21.3–4, A22–A23, A29–A30 remain open.

### 2026-10-01 — A21 product acceptance work started after A28 (commit de08a972, aarch64-darwin)

- Reconciled Selo `c7f394b`, Mnesis/nexus `5d80969`, Bombay `a7a66e3` and mnesis-bombay `9d567f6` against the accepted ADR and open project cards. Selo at baseline is naming-only. On its card #20 branch `feat/20-kel-aggregate`, a new `selo-kel` crate accepts signed pinned issuer inception/interaction frames through the released KERI core and Mnesis aggregate, binds candidate AID to stream ID, and separates KERI `s` from Mnesis `Version`. A red replay test showed a repeated KERI event could advance at a fresh storage revision; the trusted fold now detects this and enters `Corrupt`. The Selo `nix flake check -L` exited 0 (build, tests, formatting, Clippy, docs, doctests). The [A21 inventory](audits/2026-10-01-a21-host-inventory.md) records the remaining atomic append, competing evidence, command/outbox, direct/Bombay host and restart proof. A21 remains in progress; A22–A23 and A29–A30 remain open.

### 2026-10-01 — A28 accepted; A21–A23 and A29–A30 still open (commit de08a972, aarch64-darwin)

- `scripts/keripy_ipex_flow_oracle.py` reproduced 13 pinned real signed issuer/holder frames. The public test first failed on the real `-L` path group; bounded `PathedAttachment` routing and `IpexConversation` then accepted the full apply→offer→agree→grant→admit transcript, an offer→spurn branch, and rejected wrong sender/prior/credential/recipient/anchor, missing/wrong proof, replay and incomplete host evidence without mutating accepted state. The `e.acdc` signature, accepted TEL head and KEL anchor bind the same credential. The selected profile requires apply-root, one indexed `e.acdc` proof path and host-atomic replay/head storage; see the [A28 report](audits/2026-10-01-a28-ipex.md) and [integration contract](ipex-integration.md).
- The indexed `nix flake check -L --option max-jobs 1 > /tmp/cesr-a28-final-flake.log 2>&1` exited 0. Nextest passed **2,589/2,589**, 24 skipped. All supported host/WASM feature profiles, no-std, Clippy, formatting, docs/doctests, examples, fuzz replay, audit, deny, typo, API ratchet, version-owner and KERI boundary checks passed. Incompatible aarch64-linux, x86_64-darwin and x86_64-linux were omitted. The pinned Python oracle and staged/unstaged `git diff --check` also passed. A21–A23 and A29–A30 remain open.

### 2026-10-01 — A27 accepted; A28 IPEX protocol decisions next (commit de08a972, aarch64-darwin)

- [A27 evidence](audits/2026-10-01-a27-credential.md) pins schema, ACDC, TEL and chain reference behavior and records the current-validity trust meaning. Exact-body Draft 7 schema validation, issuer/registry/TEL binding, bounded I2I/NI2I chains, typed missing/terminal outcomes and explicit disclosure/rule/DI2I exclusions pass the genuine issuer/holder/verifier and adversarial corpus tests. The optional `credential-verification` feature preserves the codec-free default core; the [host contract](credential-integration.md) states accepted-state provenance and retrieval duties.
- `nix flake check -L --option max-jobs 1 > /tmp/cesr-a27-final-flake.log 2>&1` exited 0 after all new files were indexed. Release Nextest ran **2,587/2,587 passed**, 24 skipped; 19 isolated host and WASM profiles, no-std, Clippy, docs/doctests, formatting, examples, fuzz replay, audit, deny, typos, API ratchet, version-owner and boundary checks passed. Incompatible aarch64-linux, x86_64-darwin and x86_64-linux were omitted. Both staged and unstaged `git diff --check` passed. A21–A23 and A28–A30 remain open.

### 2026-10-01 — A26 accepted; A27 credential verification next (commit de08a972, aarch64-darwin)

- The [A26 report](audits/2026-10-01-a26-discovery.md) records seven exact pinned keripy V1 query/reply cases, strict typed bodies, `-F` and `-C` signer forms, authenticated `/logs` and reply judgments, key-state projection checks, replay/missing-evidence outcomes, and unsigned OOBI hints. The original red public test failed on `UnknownMessageType("qry")`; the final focused suite passed 4/4, the KSN comparison unit passed, the pinned Python oracle reproduced all seven rows, and touched-crate all-target Clippy passed with `-D warnings`.
- `nix flake check -L --option max-jobs 1 > /tmp/cesr-a26-final-flake.log 2>&1` exited 0 with every new source, fixture and test indexed into the Nix fileset. Release Nextest ran **2,583/2,583 passed**, 24 skipped. The compatible no-std, WASM, Clippy, formatting, docs/doctest, examples, fuzz replay, audit, deny, typo, API ratchet and version-owner checks passed. Incompatible aarch64-linux, x86_64-darwin and x86_64-linux were omitted. `git diff --check` and `git diff --cached --check` passed. No A21–A23 or A27–A30 completion is implied.

### 2026-10-01 — A26 pinned discovery corpus and red public path (commit de08a972, aarch64-darwin)

- [The A26 contract report](audits/2026-10-01-a26-discovery.md) records the issue #82 scope revision, V1/V2 `i` field split and pinned OOBI/BADA trust rules. `scripts/keripy_discovery_oracle.py` executed against exact keripy `de59bc7d` under Python 3.14.6 and produced/verified six V1 query/reply cases, including signed `-F` historical establishment attachments, an inception-derived key-state notice and an unsigned OOBI hint. The independent body/SAID/attachment rows are checked in under `corpus/discovery/v1.jsonl`.
- The new public `a26_discovery` test verifies each body SAID and then fails before implementation with `UnknownMessageType("qry")`, proving the selected V1 route is absent. A26.2 is next: add typed vocabulary, canonical read/write and framed paths, then tighten the test to assert variants. A26.3 and A26.4 still own authenticated reply decisions, missing evidence, replay, updates and the full gate.

### 2026-10-01 — A25 accepted; A26 query/reply profile next (commit de08a972, aarch64-darwin)

- `nix flake check -L --option max-jobs 1 > /tmp/cesr-a25-final-flake.log 2>&1` exited 0 with `a25_wire.rs` indexed into the Nix fileset. Release Nextest executed **2,577/2,577 passed**, 24 skipped, including both A25 tests. All 18 isolated host and 18 WASM consumer profiles compiled; WASM tests were not executed. Examples and fuzz replay executed, and compatible Clippy, formatting, docs/doctest, deny, ratchet and other checks passed. Incompatible aarch64-linux, x86_64-darwin and x86_64-linux were omitted. Focused `a25_wire` passed 2/2, all-target/all-feature `keri-codec`/`cesr-stream` Clippy, `cargo fmt --all --check`, staged/unstaged `git diff --check` passed before the gate. [The A25 report](audits/2026-10-01-a25-wire.md) defines the exact supported conversion boundary and its limits; no binary message transport is claimed.
- **Next: A26.** The pinned KERI text lists V1 `qry`/`rpy` field orders without top-level `i` but shows V2 examples with `i`. Pinned keripy `eventing.query`/`reply` and `SerderKERI.Fields` confirm that V1 omits `i` and V2 adds it. Reconcile the prior issue #82 exclusion with A24's selected V1 query/reply requirement, then add an independent V1 reference corpus and typed message/decision paths.

### 2026-10-01 — A25 conversion boundary and public signed fixture; gate next (commit de08a972, aarch64-darwin)

- [A25's wire inventory](audits/2026-10-01-a25-wire.md) distinguishes required V1 JSON/text message routes, `Acdc::deserialize`'s body-only contract, and the later binary/native/V2 routes. `cesr-stream::qb2` now documents exact externally delimited group conversion and the caller's byte-bound responsibility. The new `a25_wire` integration suite uses pinned keripy signed inception bytes: qb64→qb2→qb64 preserves the complete `-V` envelope; the recomposed public `EventMessage::parse` returns the same event/body/signature sets and leaves a second signed frame as the exact remainder. A one-byte short binary span returns `Misaligned`, a full-triple-short group returns `Truncated`, and raw mixed JSON/qb2 returns typed `UnsupportedColdStart`. Focused `cargo test -p keri-codec --test a25_wire` passed 2/2 in the Nix dev shell. A25.3 full gate remains.

### 2026-10-01 — A24 accepted; A25 selected wire boundary next (commit de08a972, aarch64-darwin)

- After adding the four-test `a24_profile.rs` file to Git's index so Nix's fileset included it, `nix flake check -L --option max-jobs 1 > /tmp/cesr-a24-indexed-flake.log 2>&1` exited 0. Release Nextest executed **2,575/2,575 passed**, 24 skipped, including all four A24 profile tests. The 18 isolated host and 18 `wasm32-unknown-unknown` consumer profiles compiled; WASM tests did not execute. Examples and fuzz replay executed; compatible Clippy, fmt, docs/doctest, deny, ratchet and other checks passed. Nix omitted incompatible aarch64-linux, x86_64-darwin and x86_64-linux. `cargo fmt --all --check`, focused all-target/all-feature Clippy and both staged/unstaged `git diff --check` exited 0 before the gate. The earlier Nix run also passed but omitted the untracked test file and is not used as final evidence.
- [A24's report](audits/2026-10-01-a24-profile.md), [capability matrix](capability-matrix.md) and [parity ledger](keripy-parity/ledger.md) fix the first release profile at V1 JSON/text with typed unsupported-format/version behavior, and map required but incomplete product/protocol workflows to A21–A29. **Next: A25.** Prove the documented qb2-to-qb64 conversion boundary for exact caller-delimited attachment blobs using a pinned signed message, plus mixed-domain rejection, truncation, alignment and remainders. Binary message transport remains outside the selected release profile.

### 2026-10-01 — A24 V2/non-JSON typed boundaries and clause ledger; full gate next (commit de08a972, aarch64-darwin)

- A valid CESR V2 JSON version head now returns `UnsupportedVersion(V2)` through `MessageFramer`/`EventMessage::parse` and `UnsupportedCesrVersion(V2)` through direct typed body reads; the incremental framer waits until the full 19-byte head arrives. The public A24 regression failed before the stream correction because the old path surfaced a V1 grammar error. Correctly sized V1 CBOR/MGPK maps still frame in `cesr-stream`, while typed message parsing returns `UnsupportedColdStart` and direct KEL/receipt/TEL/ACDC/EXN reads return `UnsupportedSerializationKind`. Binary cold starts receive deliberate typed unsupported results. Four A24 tests passed; 349 `cesr-stream` unit tests passed before the final direct-reader additions, which do not edit that crate. Focused all-feature Clippy first found shadowed variable names and is being rerun after correction.
- [The A24 clause ledger](audits/2026-10-01-a24-profile.md) maps each required V1 family to exact pinned source sections, public paths, evidence, status and A21–A29 owner. The [capability matrix](capability-matrix.md) and [parity ledger](keripy-parity/ledger.md) now distinguish the selected first-release scope from old corpus-only decisions. A24.4 still needs the full final gate; the wider required workflows and A21–A23 Selo destination remain open.

### 2026-10-01 — A24 profile audit and typed version boundary underway (commit de08a972, aarch64-darwin)

- The exact pinned CESR/KERI/ACDC sources and keripy revision were rechecked in [the A24 inventory](audits/2026-10-01-a24-profile.md). The historical GramHead code-entry and binary cold-start fallthrough claims were stale; the live capability matrix now distinguishes existing code labels from missing application semantics. Pinned keripy's V1/V2 counter string sets match Rust's 22/22 and 59/59 labels; that comparison is not an end-to-end support claim.
- A SAID-valid `KERI11` inception regression failed before the fix because typed `InceptionEvent::deserialize` accepted the unimplemented minor version. The strict KEL, ACDC and EXN readers now return typed `UnsupportedProtocolVersion` for syntactically valid unimplemented versions. The test recomputes and verifies SAIDs, covers all three typed readers and `EventMessage::parse`, and passes 2/2 after the fix. Nearby imported ACDC/IPEX/KERI/TEL Nextest suites passed 22/22; focused all-target/all-feature Clippy, formatting and `git diff --check` exited 0. A24's full Nix gate has not run.
- The Ed448 and Ed448N exact-error regressions failed on the original `CodeMismatch` result with the `crypto` feature enabled. `crypto::verify` now returns `UnsupportedAlgorithm { verkey }` for those recognized but unimplemented algorithms; targeted tests passed 2/2 and all-target/all-feature `cesr-rs` Clippy exited 0. The `cesr-rs` changelog records the public error migration.
- The first release profile now selects V1 JSON/text, Ed25519/BLAKE3-256 interoperability and Selo-specific client/agent exchange, with V2/native/binary message transport, CBOR/MGPK, Ed448, selective disclosure and Signify/KERIA as explicit later-profile work. The complete route/table-to-operation inventory, unsupported-combination matrix and A24 final gate remain. A21–A23 still require a Selo application destination; that clarification is pending and no sibling production worktree was changed.

### 2026-10-01 — A20 accepted; A21 product integration inventory next (commit de08a972, aarch64-darwin)

- Removed the `keri-events/internals` feature, named all thirteen constituent-field constructors `new_unchecked`, and derived `Clone`, `Debug`, `PartialEq`, and `Eq` for KEL values. The V1 EXN/IPEX data and codec stay together in `keri-codec`; the owned conversion on `KeriEvent` remains explicit. The builder's dummy SAID is private serialization scratch; `SerializedEvent` returns computed bytes and SAID. The standalone `incept_aid` consumer compiles and executes a checked build, typed read, owned value comparison, byte-exact round trip, and typed tamper rejection. Migration notes are in the affected crate changelogs; [the A20 inventory](audits/2026-10-01-a20-api.md) records the placement and ratchet-policy reasoning.
- Focused native evidence: `nix develop --command bash -c 'cargo test -p keri-events --test public_api && cargo test -p keri-codec --test inception_identity && cargo run -p keri-codec --example incept_aid && cargo fmt --all --check'` exited 0 (1/1 public-contract and 4/4 signed-inception tests, example assertions executed). `git diff --check` exited 0. `nix flake check -L --option max-jobs 1` exited 0 on the A20 source: release Nextest executed 2,571/2,571 passed with 24 skipped; all 18 isolated host and 18 WASM consumer profiles compiled, with no WASM runtime execution claim. Fuzz replay, examples, Clippy, documentation, format, audit/deny, and ratchet checks passed. Nix omitted incompatible aarch64-linux, x86_64-darwin, and x86_64-linux systems. The final queue-only status edit follows that gate; no production source changed after it.
- **Next: A21.** Reconcile the checked-out sibling revisions and accepted `mnesis-bombay` ADR, then identify the Selo application checkout before editing its durable acceptance path. No Selo checkout exists under the current sibling directory; its destination has been requested. Preserve unrelated work in Bombay, Mnesis and mnesis-bombay.

### 2026-10-01 — A19 accepted; A20 public API review next (commit de08a972, aarch64-darwin)

- **Exact next step: A20.1 public vocabulary and constructor inventory.** Reconcile A20 with current issue/ADR contracts and the versioned capability matrix. Trace EXN/IPEX domain types, checked/unchecked event constructors, public lifetimes/traits and construction placeholders through actual consumer imports and signed wire paths. Decide the smallest real ownership simplification, add any regression that would have failed before a confirmed defect, and keep the protected ratchet/config policy unchanged without owner approval. Continue A20 subtasks and the full gate before marking it complete.
- Final `nix flake check -L --option max-jobs 1 > /tmp/cesr-a19-final-flake.log 2>&1` **exited 0** on the A19 source and documentation. Release Nextest **executed** 2,570/2,570 passed (24 skipped); fuzz replay and all eight public examples **executed** in their Nix checks. Both isolated feature gates **compiled only** 19/19 host aarch64-darwin and 19/19 wasm32-unknown-unknown consumer profiles; no WASM runtime execution is claimed. Compatible checks for Clippy, docs/doctests, formatting, typos, deny/audit, KERI boundary, version owner, function ratchet, YAML/TOML/Nix/shell/action checks passed, with the log labeling previously built outputs. Nix omitted incompatible aarch64-linux, x86_64-darwin and x86_64-linux systems.
- A19's acceptance audit is in [the owner report](audits/2026-09-30-a19-owners.md): three duplicate materialization loops now use one crate-private `KeyState::updated_members` calculation, the trusted-only `trusted_witnesses` wrapper and unreachable `WitnessSetError::CutAddOverlap` variant were removed, and no new external API was added. Distinct KEL/TEL validation and trusted replay contracts remain visible. Focused Linux tests executed 12 snapshot, 47 registry, 58 transition, 17 delegation and 73 `keri-rs` lib tests; generated accepted witness/delegated histories compare complete validating and trusted snapshots. Linux native and WASM feature profiles compiled 19/19 each, and focused Clippy exited 0. No before/after runtime speed claim is made because the archived A15 baseline lacks the changed witness/backer rotation workload. A19 is complete; A20 remains open.

### 2026-10-01 — A19.2/A19.3 focused evidence passes; full Nix gate next (commit de08a972, aarch64-darwin host + aarch64-linux VM)

- **Exact next step: A19.4 final gate.** Run `cargo fmt --all --check`, `git diff --check` and `nix flake check -L --option max-jobs 1` on the current final source/docs. Inspect all compatible checks and identify cached versus executed. The A15 archived release rows do not exercise witnessed KEL or TEL backer rotation, so do not claim a before/after performance ratio from them. If the gate passes and the acceptance audit is complete, mark A19 `[x]` and continue A20 automatically; otherwise fix the failure and keep A19 open.
- The shared ordered cut/add calculation now lives as crate-private `KeyState::updated_members` in the existing public state module; a separate `ordered_set` module was removed after Clippy found a visibility conflict. KEL validation and TEL management still perform their distinct static/transition checks, while trusted replay remains total and crypto-free. The redundant `trusted_witnesses` wrapper and unreachable overlap branches/public error variant were removed. The first full `nix flake check -L --option max-jobs 1 > /tmp/cesr-a19-flake.log 2>&1` **exited 1** solely because the protected free-function ratchet counted the crate-visible helper. Moving it onto `KeyState` fixed that finding without changing the ratchet budget: `nix build .#checks.aarch64-darwin.cesr-fn-ratchet --no-link -L --option max-jobs 1 > /tmp/cesr-a19-ratchet.log 2>&1` **exited 0**. The focused 134 KEL/TEL/delegation/snapshot integration tests re-executed and passed after this move; focused Clippy exited 0. [Owner analysis](audits/2026-09-30-a19-owners.md) explains why a generic accepted-state carrier would duplicate borrowed-versus-owned field assignments rather than reduce them.
- On an aarch64-linux Ubuntu 24.04 local VM, using Rust/Cargo 1.95.0 with `RUSTUP_HOME=/tmp/cesr-a19-rustup`, `CARGO_HOME=/tmp/cesr-a19-cargo` and `CARGO_TARGET_DIR=/tmp/cesr-a19-target`, the **executed** focused suites passed: `cargo test --locked -p keri-codec --test snapshot` 12/12 (including 24 generated witness-cut/add cases), `--test registry_fold` 47/47, `--test transitions` 58/58, `--test delegation` 17/17 (including 24 generated delegated histories), and `cargo test --locked -p keri-rs --lib` 73/73. `cargo clippy --locked -p keri-rs -p keri-codec --all-targets -- -D warnings` exited 0 after fixing the visibility and test-lint findings; the pre-existing invalid `clippy.toml` disallowed-method-path warning remained non-fatal and the protected lint policy was not changed. `cargo fmt --all --check` passed after source formatting, before the last delegation test edit; rerun it on the final tree.
- The isolated feature script **compiled only** 19/19 native aarch64-linux and 19/19 wasm32-unknown-unknown consumer profiles. The first offline matrix attempt failed only because the fresh VM cache lacked registry packages; `cargo fetch --locked` populated them, and both later matrix invocations exited 0. No WASM binary was executed. The final macOS Nix gate remains required; earlier macOS loader stalls are resolved (`cargo --version` and `nix --version` now exit 0).

### 2026-10-01 — A19.1 owner map complete; A19.2 shared ordered update unverified (commit de08a972, aarch64-darwin)

- At this point A19.2 was still unverified: the first private `ordered_set` module version had not compiled. A later session entry records its replacement by the crate-private function in `state.rs` and the executed evidence. `WitnessSetError::CutAddOverlap` was unreachable and removed; the public overlap error remains `Membership(MemberSetError::CutAddOverlap { .. })`, with a migration note in the changelog.
- [A19 invariant-owner inventory](audits/2026-09-30-a19-owners.md) reconciles the KERI draft, P05 audit, witness issue #149, and approved K6/#92 trusted replay contract. It leaves builder count arithmetic separate because the builder does not need a materialized set, and keeps host accepted-record integrity outside trusted replay.
- Toolchain observation: the current environment reports `IN_NIX_SHELL=impure`; `nix develop --command /bin/sh -c 'command -v git; command -v cargo; cargo --version'` and direct Nix-store `git --version`/`rustc --version` were attempted but stalled before output. `/usr/bin/sample` showed `git` in `_dyld_start` and `nix develop` waiting while `libgit2` loaded the Nix `libiconv_std` module; `syspolicyd` was consuming high CPU. Those commands did not pass. System `/bin` and `/usr/bin` utilities could read sources. Do not infer a source failure from the loader stall or mark A19 complete. Retry the pinned toolchain when the loader responds; do not restart the build solely from a poll timeout.

### 2026-09-30 — A17 and A18 accepted; A19 invariant owners next (commit de08a972, aarch64-darwin)

- **Exact next step: A19.1 invariant-owner inventory.** Read the A19/P05 audit, current KEL/TEL/witness/backer validation and trusted replay paths, relevant issue/ADR contracts and KERI specification. Identify duplicated accepted-state and ordered-set laws before editing. Preserve the signed-body, cryptographic and storage-integrity boundaries; add red equivalence regressions before a focused consolidation. Continue with A19 subtasks until every acceptance clause has evidence.
- Final `nix flake check -L --option max-jobs 1 > /tmp/cesr-a17-a18-final-flake.log 2>&1` **exited 0** on the final source and documentation. Nix **executed** release Nextest 2,567/2,567 passed (24 skipped), fuzz replay, and the isolated no_std and WASM checks. The matrix checks **compiled only** 19/19 independent consumer profiles each for native aarch64-darwin and wasm32-unknown-unknown; they did not execute WASM binaries. Clippy, docs/doctests, formatting, typos, deny, ratchets and other compatible flake checks passed, with previously built outputs cached where the Nix log did not rebuild them. Nix explicitly omitted incompatible aarch64-linux, x86_64-darwin and x86_64-linux systems; this is a single-platform acceptance, not a claim of execution on those targets. `cargo fmt --all --check`, `nixfmt --check flake.nix` and `git diff --check` separately passed before this gate.
- The separately built `cesr-examples` Nix check (`nix build .#checks.aarch64-darwin.cesr-examples -L --no-link --option max-jobs 1 > /tmp/cesr-a18-examples-nix.log 2>&1`) **executed all eight** public examples and exited 0. Its final flake-check output was cached, so the examples were not re-executed in that invocation. [A17 matrix/size measurements](audits/2026-09-30-a17-matrix.md), the [current capability matrix](capability-matrix.md), and [A18 claim inventory](audits/2026-09-30-a18-claims.md) name the supported profiles, public limitations and source-linked claims. A17/A18 acceptance is complete; A19 remains open.

### 2026-09-30 — A18.3 eight hermetic examples execute; final combined gate next (commit de08a972, aarch64-darwin)

- **Exact next step:** run `cargo fmt --all --check`, `nixfmt --check flake.nix`, `git diff --check` and a final `nix flake check -L --option max-jobs 1` on the current tree including the new `cesr-examples` check and 19-profile count guard. Inspect every result and distinguish cached, compile-only and executed. If all pass, mark A17 and A18 `[x]`, then begin A19's invariant-owner inventory; otherwise keep the failing task incomplete and fix the defect.
- `nix build .#checks.aarch64-darwin.cesr-examples -L --no-link --option max-jobs 1 > /tmp/cesr-a18-examples-nix.log 2>&1` **exited 0** in the vendored Nix environment. It executed eight public examples with their assertions: CESR primitive round-trip and Ed25519 sign/verify, CESR stream group parse, four KERI codec construction/round-trip examples, and the direct-mode KERI signed fold/delegation/abandonment example. All eight printed their expected success paths. The new flake check uses a minimal output directory instead of archiving its generated target; the prior local debug compiler stall is not counted as a passing attempt. `nixfmt` initially found the new check's `installPhase` string style; `nixfmt flake.nix` corrected it. The full gate must still run on this final configuration.
- The preceding `nix flake check -L --option max-jobs 1 > /tmp/cesr-a17-a18-flake.log 2>&1` **exited 0** before the new example check and latest prose/count-guard changes: release Nextest executed 2,567/2,567 passed with 24 skipped; isolated host and WASM 19-profile checks each compiled all rows; Clippy, doctests, docs, fuzz replay, typos and other reported checks passed or were previously built as the log labels show. It is code verification evidence, not a claim that the final tree has already passed.

### 2026-09-30 — A18.2 live claims corrected; A17 final gate priority (commit de08a972, aarch64-darwin)

- **Exact next step: finish A17.3 before A18.3.** The first 19-profile Nix run exited 1 only because its isolated default `keri-rs` consumer detected the codec/internals leak; release Nextest still executed 2,567/2,567 with 24 skipped. `keri-rs` no longer has the redundant codec dev-dependency or the `std` → optional-codec feature edge. `python3 scripts/check_feature_matrix.py` and the same `--target wasm32-unknown-unknown` invocation now **pass 19/19 compile-only profiles each**. `cargo test -p keri-rs --lib` and `cargo test -p keri-rs --no-default-features --features wire --lib` passed 73/73 each. Rerun full `nix flake check` on the corrected manifests and documentation; mark A17 `[x]` only after actual pass, then finish A18.3 example/doc verification and gate.
- A18.2 corrected the root README's “full protocol” and automatic revocation claims: the example proves a selected KEL flow, current-state verification rejects stale keys, an empty next-key commitment closes later rotation, and host application policy decides historical signature authorization. The `direct_mode` example's narration, function names and assertion messages now match its actual current-authority check without changing protocol behavior. `keri-rs` docs no longer claim the fold only allocates a witness set; the [A15 baseline](audits/2026-09-30-a15-baseline.md) is the named allocation evidence. `cesr-stream/examples/parse_stream.rs` now names its owning crate and describes owned consumed-group copying accurately. The obsolete `concurrent_parse` example (288 lines) was removed because both public parser arms now copy only consumed frames; `cesr-stream/tests/allocation.rs` guards the current linear-byte rule. Changelog migration notes the example removal. Root and crate READMEs link the current queue and capability matrix; the strategy says historical and the parity ledger distinguishes code-table coverage from protocol completeness. [Claim inventory](audits/2026-09-30-a18-claims.md).
- The corrected `cargo run -p cesr-stream --example parse_stream` command was attempted twice but did **not** execute: local debug `rustc` stalled while loading a proc-macro dynamic library after Nix store cleanup, even with incremental compilation disabled. Those processes were stopped; no runtime pass is claimed. A18.3 still requires executable example/compile evidence and a full gate on the final docs. The Nix all-target Clippy/check can supply compile evidence independently of this local debug-run issue.

### 2026-09-30 — A18.1 live-claim inventory complete while A17 gate waits (commit de08a972, aarch64-darwin)

- **Exact next step: A18.2, unless Nix becomes available first; then finish A17.3 gate.** The [claim inventory](audits/2026-09-30-a18-claims.md) maps the root README, `keri-rs` and `cesr-stream` crate docs/examples, the obsolete concurrent-parse harness, generated code-table report and historical strategy to current A01–A17 evidence. Correct live prose and example commands without changing recorded historical audit results. A18 stays `[-]`; A17 stays `[-]` until its final 19-profile/full-Nix verification.

### 2026-09-30 — A17.3 size and documentation in progress; full gate pending (commit de08a972, aarch64-darwin)

- **Exact next step: A17.3 gate.** The current `nix flake check -L --option max-jobs 1 > /tmp/cesr-a17-flake.log 2>&1` is pending behind a concurrent system `nix store gc` (no check result yet). The final matrix script now adds each crate's literal default profile, so run/confirm **19/19 host and WASM isolated consumers**; earlier 14/14 passes do not cover those five rows. Wait for actual outcomes, fix any findings, rerun the full gate on the final files, and mark A17 `[x]` only afterward. Confirm `cargo fmt --all --check`, `nixfmt --check flake.nix` and `git diff --check`; then begin A18.
- `python3 scripts/measure_feature_size.py` **executed** three linked `wasm32-unknown-unknown` release `cdylib` probes under identical opt-level 3/LTO/one-codegen-unit/stripped/abort settings and two graph-only KERI profiles. CESR core resolved 57 packages and linked 16,264 bytes; Ed25519 sign/verify resolved 82 packages, including Argon2, and linked 451,937 bytes; salty Argon2id derive+sign/verify resolved the same 82 and linked 496,379 bytes. Independent KERI core/no-wire resolved 84 packages (no codec); KERI wire resolved 87. The [method and limits](audits/2026-09-30-a17-matrix.md) distinguish linked size from resolved dependency count. No size result claims actual WASM execution or production application performance. The observed 44,442-byte linked salty increment and dead-code elimination for an Ed-only consumer do not justify multiplying feature gates in A17; A26 can revisit an algorithm/custody split with a selected profile and downstream size budget.
- Updated `CLAUDE.md`, root/crate READMEs, `cesr-rs` module/package docs, the capability matrix and affected changelogs to state feature implications and the actual all-feature/isolated/WASM check boundaries. The stale `cesr` README examples and old `stream`/`keri` feature table were replaced with current crate paths. The initial attempt to build a workspace example for WASM failed in its unrelated dev-dependency `getrandom` backend; the isolated downstream `cdylib` probe avoids that feature unification and is the reported measurement. That failed example command is not acceptance evidence.

### 2026-09-30 — A17.2 isolated host/WASM gate passes; A17.3 size and claims next (commit de08a972, aarch64-darwin)

- **Exact next step: A17.3.** Measure a reproducible WASM artifact and independent dependency graphs for core, crypto and KERI custody/wire profiles before deciding whether to split Argon2 or algorithms. Correct CLAUDE, README, crate README and capability-matrix claims about supported features and checks. Run format/policy and full `nix flake check` after those changes; A17 stays `[-]` until then.
- `scripts/check_feature_matrix.py` now compiles 14 independent downstream manifests and inspects Cargo's resolved graph for leaked `std`, `test-utils`, `crypto`, `internals` or wire codec features in profiles where they do not belong. `python3 scripts/check_feature_matrix.py` **passed 14/14 host profiles**, and `nix develop --command python3 scripts/check_feature_matrix.py --target wasm32-unknown-unknown` **passed 14/14 WASM profiles**, all compile-only. `flake.nix` includes the script in its filtered source and runs the host matrix from `cesr-nostd` and the WASM matrix from `cesr-wasm`; `nix build .#checks.aarch64-darwin.cesr-nostd -L --option max-jobs 1` and the analogous `cesr-wasm` command each **exited 0**, with all 14 rows visible in their build logs. The pre-existing standalone no_std builds and WASM direct-mode example also compiled. No WASM binary was executed.
- Focused runtime checks **executed**: `cargo test -p cesr-rs --no-default-features --features b64 --lib b64::` passed 175/175; `cargo test -p cesr-stream --no-default-features --features async --lib codec::` passed 28/28 with one ignored and 351 filtered out; `cargo test -p keri-rs --no-default-features --lib` and `cargo test -p keri-rs --no-default-features --features wire --lib` each passed 73/73. The standalone consumer checks, not these workspace test invocations, establish feature isolation; workspace tests can unify dev-dependency features. `nixfmt --check flake.nix` and `git diff --check` passed at this point. The final full gate is still outstanding.

### 2026-09-30 — A17.1 isolated consumer matrix complete; A17.2 gate next (commit de08a972, aarch64-darwin)

- **Exact next step: A17.2.** Wire `scripts/check_feature_matrix.py` into the Nix gate and run its host and supported WASM profiles as independent consumer manifests; add meaningful runtime checks where a feature changes behavior. Confirm the default/core-without-wire dependency graph, `internals`/`test-utils` and `std` feature isolation. Keep A17 `[-]`; A17.3 still requires size measurements, docs and full gate.
- `python3 scripts/check_feature_matrix.py` creates one temporary downstream crate per declared profile and invokes `cargo check --offline` separately. Its first run **failed 4/14 profiles**: `cesr-rs` `b64`, `core`, `crypto` failed because `b64` did not enable `alloc` for `String`/`Vec`; `cesr-stream` `async` failed on Tokio's `std::io::Error` bound without `std`. A direct `cargo check -p keri-events --no-default-features --lib` failed because that non-alloc profile reaches `cesr-rs` core; the manifest-supported `keri-events` alloc-only profile passed. The previous workspace all-feature gate could not reveal these standalone defects. [Baseline and decision](audits/2026-09-30-a17-matrix.md).
- Manifest fixes make `cesr-rs/b64` imply `alloc`, keep `base64` owned by `core`, compile the `ZeroLead` helper only when `core` is present, and make `cesr-stream/async` imply `std`; no compatibility surface was added. The same isolated command then **passed 14/14 compile-only host profiles** including no-feature cesr substrate, b64/core/crypto, alloc-only stream/events/codec, async stream, no-wire core and wire-enabled `keri-rs`. The script itself is durable; the audit report records the red-to-green evidence. No claim that each profile's tests ran yet.

### 2026-09-30 — A16 accepted; A17 feature matrix next (commit de08a972, aarch64-darwin)

- **Exact next step: A17.** Inventory the five manifests and Nix feature/target checks, then run each declared standalone feature profile in an independent consumer context. Reproduce the previously observed plain `keri-events --no-default-features` failure and decide from the manifest contract whether it is an unsupported profile or a defect. Measure dependency/WASM sizes before any split decision; update the CI matrix, docs and changelogs as needed. A17–A30 remain open.
- A16.5 retained the malformed-but-SAID-valid ACDC negative corpus and IPEX state rejects from A16.3/A16.4. It added `tests/corpus/tel/semantic.jsonl` with the former backed-revocation body, whose wrong registry anchor remains SAID-valid and correctly signed. The imported TEL oracle proves its bytes, `SerderKERI` reader and signature match but its registry coordinate violates the pinned factory/PTEL rule; the separate imported `Tevery` run returns `ValidationError`. Rust `keripy_tel` now drives the exact adversarial row through public typed decode, serialize, frame, parse and signature verification (5/5 tests passed); `registry_fold` asserts the typed `InconsistentManagement` rejection and unchanged issued state (46/46 passed). The parity ledger separates primitive code-table, factory-byte, parser and state-machine claims. Full host IPEX conversation authorization is explicitly deferred to A28.
- The exact workflow harness extracted from `.github/workflows/keripy-diff.yml` selected and executed all nine explicit binaries: TEL 5, ACDC 5, IPEX 7, receipts 2, JSON payload 6, custody 1, duplicity 1, delegation 1, semantics 3 (31 tests total), all passed; [selected-suite output](audits/2026-09-30-a16-workflow-final.txt). The broad `cargo test --all-features keripy -- --nocapture` also ran, but its name filter is not treated as coverage for those binaries. All TEL/ACDC/IPEX imported Python 3.14 oracles and the pinned A07/A09 comparisons executed earlier in A16.2–A16.4, with case counts and environment recorded below. The nightly now regenerates the corpus, asserts the keripy Git HEAD, executes those oracles and checks nonempty exact Rust suite counts. `actionlint` passed; the workflow PR description now reflects all three families.
- `nix flake check -L --option max-jobs 1 > /tmp/cesr-a16-flake.log 2>&1` first failed only `cesr-typos`: opaque CESR SAIDs in newly archived oracle output looked like English misspellings. The five audit transcripts were reduced to provenance, case names and outcomes; exact bytes remain in the checked-in corpora and reproducible oracle scripts. No spell-check policy was changed. Targeted `nix develop --command typos --config _typos.toml` on the five files passed. `nix flake check -L --option max-jobs 1 > /tmp/cesr-a16-flake-final.log 2>&1` then **exited 0**: the earlier attempt executed Nextest 2,567/2,567 passed, 24 intentionally skipped, plus fuzz replay; the final attempt reused those derivations as **previously built**. Final-run WASM compiled all five crates (**compile-only**); no_std, Clippy, docs/doctests, deny, audit, formatting, ratchets, fuzz replay and Nextest were **previously built** from the same code; typos, YAML and version-owner rebuilt and passed. The check omitted aarch64-linux, x86_64-darwin and x86_64-linux. `git diff --check` passed. A later workflow PR-description-only edit is covered by a subsequent YAML/actionlint check.

### 2026-09-30 — A16.4 IPEX imported oracle accepted; A16.5 final corpus/gate next (commit de08a972, aarch64-darwin)

- **Exact next step: A16.5.** Review all newly found acceptance defects and reference verdicts for complete negative semantic corpus coverage, including malformed-but-SAID-valid and correctly signed adversarial events; add any missing direct Rust public-path assertions with typed outcomes. Verify the nightly's generated TEL/ACDC/IPEX files and imported Python 3.14 oracles, run the exact YAML harness selection step with updated test count (ACDC and TEL now 5 each, 31 explicit total), inspect no_std/WASM/fuzz/CI result distinctions and run a fresh `nix flake check`. Update ledger/capability matrix/changelogs and mark A16 `[x]` only when all acceptance criteria are met. A17–A30 remain open.
- A16.4 `scripts/keripy_ipex_oracle.py` asserts the pinned imported module path, exact seven-case/nonempty selection, all seven raw bodies against actual pinned `exchange` or `specialExchange` **and** the six `vc.protocoling.ipex*Exn` factories (with only deterministic time and host endorsement supplied), `SerderKERI` raw reader, embeds-map SAID, embedded ACDC/TEL/KEL readers, and exact indexed Ed25519 signatures/verification keys. It executes actual `IpexHandler.verify` with a supplied host lookup: seven corpus routes accepted; a SAID-valid agree-after-apply and an admit without prior rejected. [Nine-verdict outcome transcript](audits/2026-09-30-a16-ipex-oracle.txt) records the seven byte/signature matches and verdict aggregate. The host lookup stand-in means this is route-state evidence only, **not** authenticated conversation persistence/authorization, which remains A28.
- `PYTHONPATH=/tmp/cesr-a07-pydeps:/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages /Users/joel/.local/bin/python3.14 scripts/keripy_ipex_gen.py --out-dir crates/keri-codec/tests/corpus/ipex` regenerated 7 happy + 7 signed + 8 hardening rows, with no new vector delta beyond the existing A08 changes; its printed total was corrected from 15 to 22. The pinned oracle command uses `KERIPY_CHECKOUT=/tmp/cesr-a07-keripy-pin`, the A16.2 documented `DYLD_LIBRARY_PATH`/`PYTHONPATH`, and `/Users/joel/.local/bin/python3.14 scripts/keripy_ipex_oracle.py`; it **executed and passed after regeneration**. The nightly now runs generator plus imported oracle, so shape generation alone cannot certify parity. `cargo test -p keri-codec --all-features --test keripy_ipex --test keripy_json_payload` executed 7/7 and 6/6; `cargo test -p keri-codec --no-default-features --test keripy_ipex` executed 7/7; `nix develop --command actionlint .github/workflows/keripy-diff.yml`, `cargo fmt --all --check` and `git diff --check` passed. No production code or public API changed during A16.4. The ledger/matrix distinguish factory bytes, embedded readers, typed Rust route lift and reference handler verdicts from A28's conversation state. Full `nix flake check` awaits A16.5.

### 2026-09-30 — A16.3 ACDC v1 oracle and boundary accepted; A16.4 IPEX next (commit de08a972, aarch64-darwin)

- **Exact next step: A16.4.** Inspect all seven IPEX happy/signed routes and embedded bodies, pinned `exchange`/`specialExchange` and `vc.protocoling`, and the A08 byte oracle. Extend the imported oracle to typed route/cryptographic/negative behavior and make nightly use it. Preserve A24's broader profile decisions; A16.5 still owns cross-family negative corpus, full CI selection proof and fresh `nix flake check`. A16 remains `[-]`.
- A16.3 found the historical shape generator and PR #295's older “compact” claim did not match the pinned v1 reader: the old `compact_minimal` omitted required issuer `i`, and old `compact_issuance` carried top-level `p`. Direct Python 3.14 `SerderACDC(raw=...)` rejected them with `MissingFieldError` and `ExtraFieldError`; the initial new imported oracle failed red on the first. The pinned v1 `FieldDom` is `v,d,u?,i,ri?,s,a?/A?,e?,r?`, with `a`/`A` alternates. Neither `p` nor `E`/`R` is a v1 field. The current ACDC specification has broader/versioned forms, so this **v1 correction does not decide A24's V2 or aggregate capability profile**. PR #295's aggregate exclusion was historical, not used as an owner decision.
- Corrected the generator's accepted forms, added a scalar `A` reference at the **factory-byte/type level only**, and moved the two former “happy” shapes into the SAID-valid negatives. Added three further SAID-valid negative shapes (`a`+`A`, top-level `E`, top-level `R`). The corpus is now 4 happy + 4 signed + 11 hardening rows; generator total reports 19 correctly. The imported `scripts/keripy_acdc_oracle.py` asserts the actual pinned source path, checks all four bodies through `SerderACDC` raw reader and maker, verifies four exact indexed signatures and nested block SAIDs through `Saider`, and checks five specific pinned reader rejection causes over SAID-valid bytes. [Outcome transcript](audits/2026-09-30-a16-acdc-oracle.txt): 4 matches + 5 rejections, pin `de59bc7d`. The separate pinned `credential` oracle `docs/audits/2026-09-29-a09-oracle.py` **re-executed and passed** six EXN and two ACDC escaped/numeric payload comparisons, plus its documented negative/reference-divergence probes ([outcome transcript](audits/2026-09-30-a16-a09-recheck.txt)). Nightly now regenerates ACDC and runs both imported oracles. The A16.2 [environment record](audits/2026-09-30-a16-environment.txt) applies (Python 3.14.6, macOS arm64, dependency versions/libsodium); CI verifies the clone's exact Git HEAD.
- The public Rust ACDC v1 model/parser/writer now requires issuer `i`, drops unsupported `p`/`E`/`R` members instead of retaining compatibility wrappers, and rejects simultaneous `a`/`A` on both reads and typed writes (`BuilderError::AcdcAlternateAttributes`). `Acdc::issuer()` now returns `&Identifier`; migration is in the keri-events and keri-codec changelogs. The Rust hardening suite failed red on old accepted `missing_issuer` ([log](audits/2026-09-30-a16-acdc-rust-red.txt)), then on `both_attribute_forms` after the first fix ([log](audits/2026-09-30-a16-acdc-alternate-red.txt)); desired tests remain. `cargo test -p keri-codec --all-features --test keripy_acdc` executed 5/5 passed, including a typed-writer adversary. `cargo test -p keri-events -p keri-codec --all-features` executed 747 passing tests across 32 result groups with 24 intentionally ignored probes/benchmarks; the later split-out signed TEL wrong-`ra` case executed 1/1. `cargo test -p keri-codec --no-default-features --test keripy_acdc` executed 5/5. `cargo check -p keri-codec --no-default-features --features alloc` and `cargo check -p keri-events --no-default-features --features alloc` passed **compile-only**. A plain `cargo check -p keri-events --no-default-features` failed in the existing `cesr-rs` no-alloc configuration with 111 errors; this is **not** a claimed supported target and A17 will investigate the feature matrix. Clippy on both affected crates/all targets/all features with `-D warnings` initially exposed the TEL test length and a similar local name; after splitting/renaming, the same command passed. `cargo fmt --all --check`, `git diff --check`, and `nix develop --command actionlint .github/workflows/keripy-diff.yml` passed. The versioned capability matrix and parity ledger distinguish ACDC v1 byte/parser evidence from unresolved aggregate commitment, schema/issuer authority, registry status and selective disclosure; A24/A27 remain open. The A16 full Nix gate has not yet run.

### 2026-09-30 — A16.2 TEL factory and Tevery oracle accepted; A16.3 ACDC next (commit de08a972, aarch64-darwin)

- **Exact next step: A16.3.** Inspect the three ACDC happy/signed shapes, their current nested/aggregate claims, `vc.proving.credential` and `SerderACDC` in the pinned Python 3.14 source. Build an imported oracle for compact, expanded and nested ACDC and signed behavior; establish actual supported versus still unverified aggregate evidence without adopting PR #295's historical exclusion as a profile decision. Preserve and log any reference defect/divergence. A16 remains `[-]`; its A16.4/A16.5 and final Nix gate remain mandatory.
- A16.2 red proof: `KERIPY_CHECKOUT=/tmp/cesr-a07-keripy-pin ... /Users/joel/.local/bin/python3.14 scripts/keripy_tel_oracle.py` **failed before correction** at the backed revocation registry coordinate assertion. The old `brv_backed` happy row was SAID-valid and correctly signed but set `ra.d` to the credential `bis` SAID rather than the `(registry, sn=0)` management `vcp` SAID. The [PTEL registry anchor rule](https://trustoverip.github.io/tswg-ptel-specification/draft-pfeairheller-ptel.html) and pinned `backerRevoke(regd=...)` factory identify `ra` as a management TEL reference. Corrected the single generator input, regenerated 7 happy + 7 signed + 10 hardening TEL rows (only the `brv_backed` happy/signed lines changed), and fixed the generator's printed total from 17 to 24. The signed bytes and SAID were regenerated, not patched to a desired digest.
- `scripts/keripy_tel_oracle.py` now imports pinned `incept`, `rotate`, `issue`, `revoke`, `backerIssue`, `backerRevoke`, `SerderKERI` and `Signer`, checks **all seven** happy bodies byte-identical, checks the raw reader and exact indexed signature/verification key for each signed twin, asserts complete/nonempty case selection, and checks backed `ra`/prior coordinates. Its `KERIPY_CHECKOUT` module-path assertion prevents an unrelated installed `keri` from masquerading as the pinned reference; nightly CI also asserts the cloned Git HEAD equals `scripts/KERIPY_PIN`. The exact local command with `KERIPY_CHECKOUT=/tmp/cesr-a07-keripy-pin`, `DYLD_LIBRARY_PATH=/nix/store/gd9s5r9njddmad7mf5rqs86xscbq7c2n-libsodium-1.0.20/lib`, `PYTHONPATH=/tmp/cesr-a07-pydeps:/tmp/cesr-a07-keripy-pin/src:/tmp/cesr-a07-keripy-pin:/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages`, and `/Users/joel/.local/bin/python3.14 scripts/keripy_tel_oracle.py` **executed 7/7 matching rows** ([outcome transcript](audits/2026-09-30-a16-tel-factory.txt)); [environment](audits/2026-09-30-a16-environment.txt) records Python 3.14.6, macOS arm64, imported source, pin, libsodium and package versions. Local source archive lacks `.git`, so the CI HEAD assertion is the Git provenance check; the module path and `scripts/KERIPY_PIN` match locally.
- The same environment executing `docs/audits/2026-09-29-a07-oracle.py` **passed 14 actual `Tevery` outcome rows** ([outcome transcript](audits/2026-09-30-a16-tel-tevery.txt)): all six ilks accepted in valid chains, framed KEL anchor/backer receipts, delayed anchor/sequence re-drive, missing backer receipts, wrong flavor terminal rejection, and the old `brv` shape with a real KEL source plus correct backer signature rejected as `ValidationError`. The Rust public fold now asserts `RegistryRejection::InconsistentManagement` for that correctly signed wrong-`ra` event while preserving the issued state; the focused `registry_fold` case executed 1/1 passed. The focused all-feature TEL/registry binaries executed 4/4 and 45/45 before that assertion; the dedicated signed wrong-`ra` case was split out to satisfy the protected Clippy test-length policy and executed 1/1 passed. `cargo fmt --all --check`, `git diff --check`, and `nix develop --command actionlint .github/workflows/keripy-diff.yml` passed. Nightly now invokes both imported TEL oracles. The local ten hardening bodies are still **Rust parser negatives, not keripy parser verdicts**; the ledger now separates factory bytes, reader, Rust parser and state-machine evidence. Full `nix flake check` awaits A16.5.

### 2026-09-30 — A16.1 selection gate accepted; A16.2 TEL oracle next (commit de08a972, aarch64-darwin)

- **Exact next step: A16.2.** Compare all seven TEL happy/signed bodies to actual pinned `keri.vdr.eventing` factories and reader under Python 3.14, then exercise real `Tevery` anchor/backer/chain outcomes. Keep the shape corpus labeled partial until every claimed row has independent oracle evidence; preserve bytes if comparison exposes a reference limitation rather than changing expectations to pass. A16 remains `[-]` and A17–A30 remain open.
- A16.1 finding: `nix develop --command cargo test --all-features keripy -- --nocapture` **executed** but Cargo filters test names, not binary filenames. It selected only 9 of the 29 tests in the nine `keri-codec` parity binaries: TEL/ACDC/IPEX each ran only `pinned_keripy_commit_is_current` (1/4, 1/4, 1/7); receipts and JSON payload ran 0/2 and 0/6. The remaining four binaries contributed 1/1, 1/1, 1/1 and 3/3. This leaves 20 tests unexecuted in the prior nightly path. The actual imported keripy source is `/tmp/cesr-a07-keripy-pin/src/keri` with `scripts/KERIPY_PIN` = `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`; local Python is 3.14.6, with pinned `vdr.eventing`, `vc.proving`, and `peer.exchanging` importable. The local source archive has no `.git` metadata, so the pin comes from `scripts/KERIPY_PIN` and the previously fetched archive; CI clones/checkout verifies the Git SHA. Existing TEL/ACDC/IPEX generators still say **shape reproduction**, and the existing A08/A09 imported comparisons cover only their documented subsets. PR #295's older aggregate exclusion is historical and does not override A24's profile decision.
- Updated `.github/workflows/keripy-diff.yml` to keep the broad primitive/name filter and explicitly select and execute all nine parity binaries with exact, nonzero test-count assertions. The **actual YAML run block** was extracted and executed locally through `nix develop`; it exited 0 with 29/29 explicit parity tests passed and the broad filter also passed. [Archived output](audits/2026-09-30-a16-workflow-step.txt) records every selected count and result (terminal trailing spaces normalized). `nix develop --command actionlint .github/workflows/keripy-diff.yml` exited 0; workflow YAML parsed and `git diff --check` passed. The first inline `bash -c` version failed actionlint's SC2016 and was replaced with a tested quoted heredoc. No corpus bytes or production code changed in A16.1. The full `nix flake check` is reserved for A16's final gate after imported oracle and corpus work.

### 2026-09-30 — A15 accepted; A16 next (commit de08a972, aarch64-darwin)

- **Exact next step: A16.** Inspect the pinned keripy environment, TEL/ACDC/IPEX generator scripts and corpora, `.github/workflows/keripy-diff.yml`, relevant issue/ADR contracts, and current independent oracle evidence. Verify current nightly test selection counts before editing. Build a reproducible Python 3.14 imported-keripy oracle path, preserve provenance and negative semantic cases, then run explicit selected binaries and the full gate before marking A16. If Python/keripy or an owner decision blocks part of A16, record the concrete evidence and continue another unblocked task; do not label shape reproduction as imported oracle evidence.
- A15.5 final command `for sample_round in 1 2 3; do cargo test --release -p keri-codec --test a15_baseline --all-features -- --ignored --nocapture --test-threads=1; done > docs/audits/2026-09-30-a15-final-release.txt 2>&1` **executed three full release runs**, each 15/15 ignored benchmark tests passed. The [final raw archive](audits/2026-09-30-a15-final-release.txt) has 44 distinct case rows each repeated three times (132 valid JSON rows), with p10≤median≤p90 and printed warmup/sample counts. Standard rows used 100/101; Argon2 rows 3/21, explicitly separate because the KDF is memory-hard. The [A15 report](audits/2026-09-30-a15-baseline.md) records hardware, release features, methodology, representative distributions/throughput/allocations/requested/retained/peak bytes, credential/TEL and custody boundaries, variance and optimization decisions. No production crypto policy, cache, architecture or public API changed by A15.
- `cargo clippy -p keri-codec --all-features --test a15_baseline -- -D warnings`, `cargo fmt --all --check` and `git diff --check` passed; the pre-existing test-only `clippy.toml` warning remained. Direct `cargo check -p keri-codec --no-default-features --features alloc` and `cargo check -p keri-rs --no-default-features` passed **compile-only**. Focused ACDC/TEL/registry tests executed 4/4, 4/4 and 45/45. The fresh `nix flake check -L --option max-jobs 1 > /tmp/cesr-a15-flake.log 2>&1` exited 0. Ten checks **rebuilt and passed**: doctest, deny, no_std, WASM, fmt, doc, Clippy, typos, Nextest and fuzz replay. Ten ancillary checks reported **previously built**: YAML, TOML fmt, nixfmt, audit, function-count ratchet, deadnix, version-owner, shellcheck, actionlint and KERI boundary. Release Nextest **executed** 2,564/2,564 passing tests with 24 skipped/ignored probes (including 15 A15 benchmarks executed separately); fuzz replay smoke targets **executed**. no_std and wasm32 (including the wire direct-mode example) **compiled only**. Other incompatible OS/architecture checks were omitted on this aarch64-darwin host. This satisfies the A15 acceptance criteria; A16–A30 remain open.

### 2026-09-30 — A15.4 complete; A15.5 gate next (commit de08a972, aarch64-darwin)

- **Exact next step: A15.5 final evidence/gate.** Verify the final release harness and raw archive counts/content, run focused feature/no_std/WASM target checks and a fresh `nix flake check` on the current tree, inspect every named result, then update the A15 report/TODO with command outcomes, skipped/compile-only distinctions, risks and optimization decisions. Mark A15 `[x]` only if all A15 acceptance criteria and the final gate pass; then continue A16 automatically. Preserve all existing worktree changes.
- A15.4 isolated actual `SaltyCustodian` Low-tier Argon2id13 custody: one-current/one-next `incept`, one-key `Salt::stretch`, `SaltyCustodian::sign` re-deriving its current key, and indexed Ed25519 signing with a pre-derived **test-only** key. Same fixed salt, Keripy path `000`, opslimit 2, 64 MiB and exact message were used, and the custodian signature was asserted byte-identical to the pre-derived control before timing. No key cache or secret-lifetime change was implemented; production custody policy remains A23. The Argon2 cases used explicitly reduced 3 warmups/21 samples per process because the KDF is memory-hard; the signing-only control retained 100/101. Generic input-byte throughput on KDF rows is not meaningful. Three process runs of the ignored custody case **executed and passed** with exact command `for sample_round in 1 2 3; do cargo test --release -p keri-codec --test a15_baseline --all-features salty_custody_argon2_and_signing_separated -- --ignored --nocapture --test-threads=1; done > docs/audits/2026-09-30-a15-custody-release.txt 2>&1`. [Raw output](audits/2026-09-30-a15-custody-release.txt) has p10/median/p90, allocations/requested/retained/peak; [report](audits/2026-09-30-a15-baseline.md) interprets the trust and memory boundaries. Median one-key stretch 40,707,209/40,736,959/40,779,917 ns with 67,108,864 requested and peak bytes; custodian re-deriving sign 41,720,917/41,175,917/40,939,125 ns and 67,109,424 requested bytes; two-key inception 82,210,500/82,302,167/82,404,208 ns and 134,218,700 requested bytes. Focused all-feature harness Clippy (`-D warnings`) passed with the existing test-only config warning. The A15 full Nix gate has **not** run after this addition.

### 2026-09-30 — A15.3 complete; A15.4 next (commit de08a972, aarch64-darwin)

- **Exact next step: A15.4 custody isolation.** Inspect `SaltyCustodian` API, Argon2 tier and signing path and the A24 custody/profile contracts. Add separate derivation and signing release cases with fixed documented tier/security settings, 100 warmups and 101 samples, three independent process rounds, and the same timing/throughput/allocation/retention methods. State any secret-lifetime/cache policy; do not add a key cache without explicit policy. Then A15.5 final focused target/feature checks, fresh `nix flake check`, archive report and accept A15 only after every criterion passes.
- A15.3 has executable ACDC and TEL lifecycle rows. Public `SadCodes::saidify` constructs nested/outer ACDC SADs; each accepted measured path runs `Acdc::deserialize`, binds the declared issuer to the verifying key, verifies a genuine Ed25519 signature and retains the owned credential. Payloads 1/64/512 KiB and 1/16/64 distinct credentials are measured. Rejected 64 KiB rows assert exact `CodecError::Said` after a byte change and exact cryptographic `VerificationError::Signature(SignatureError::Invalid)` after signing with another key. The large synthetic credentials are legal supported shapes, **not** imported keripy outputs; the ACDC parity corpus remains partial per the ledger.
- The TEL fixture prevalidates a genuinely signed issuer KEL, then the timed public route parses V1 `-G` TEL frames and checks accepted KEL source/seals to fold owned registry/credential states through `vcp → iss → rev`. Missing issue and revoke accepted-anchor cases reject; the latter preserves the issued state. A separate 1/16/64 distinct-credential TEL workload retains every issued head, with each event backed by its own prevalidated KEL anchor. No TEL issuer signature is required on the backerless branch; the accepted KEL anchor is the specified authorization. KEL persistence/lookup and host credential-index storage are outside the timed route and are not claimed as measured.
- Exact command `for sample_round in 1 2 3; do cargo test --release -p keri-codec --test a15_baseline --all-features -- --ignored --nocapture --test-threads=1; done > docs/audits/2026-09-30-a15-credential-tel-release.txt 2>&1` **executed three process rounds of all 14 ignored cases**, each 100 warmups + 101 samples, all passing. [Raw output](audits/2026-09-30-a15-credential-tel-release.txt) includes p10/median/p90, throughput and allocation/requested/retained/peak for every row; [report](audits/2026-09-30-a15-baseline.md) gives the method and selected comparisons. Median 512 KiB ACDC parse/verify/owned time was 1,794,500/1,936,833/1,822,125 ns, 29 allocations, 1,575,609 requested and 524,460 retained bytes. TEL `vcp→iss→rev` was 6,958/7,000/7,125 ns, 103 allocations, 7,225 requested and 193 retained bytes. These are local, isolated routes, not cross-stack speed claims.
- Focused `cargo test -p keri-codec --all-features --test keripy_acdc --test keripy_tel --test registry_fold` **executed and passed** ACDC 4/4, TEL 4/4 and registry lifecycle 45/45 tests. All-feature harness Clippy (`-D warnings`) passed with the existing test-only `clippy.toml` warning. Raw archive was marked intent-to-add for Nix. A15 full Nix gate remains pending until after A15.4/A15.5; keep A15 `[-]`.

### 2026-09-30 — A15.2 complete; A15.3 next (commit de08a972, aarch64-darwin)

- **Exact next step: A15.3 credential/lifecycle matrix.** Inspect public TEL/ACDC parse, issuer authentication, registry fold and owned-state routes and pinned fixtures. Add accepted and rejected issuance/revocation/anchor and large credential/credential-count rows to the ignored release harness, preserving equal crypto and explicit limits. Archive three independent process runs with p10/median/p90, throughput, allocations/requested bytes and retained/peak; then A15.4 custody and A15.5 final gate. A15 remains `[-]`.
- A15.2 now has signed recovery: a deterministic real Ed25519 `icp → ixn1 → ixn2` head, public `SameSnVerdict::Supersedes` for a genuine signed `rot` at sequence 1, host replay to the inception and validating recovery fold to an owned snapshot. Three executed process medians were 136,833/129,125/130,750 ns for 1,441 bytes; 116 allocations, 9,080 requested, 272 retained and 3,687 peak bytes. The host rewind/persistence itself is outside this route. No security/crypto policy is disabled.
- A deterministic signed inception fixture independently varied 1/4/8 controller keys with one signature, 1/4/8 signatures with eight keys, 4/8 witnesses with one receipt, 1/4/8 receipts with eight witnesses, 8/64 identical duplicate controller signatures, and 1/2/4/8 attachment groups holding the same eight real signatures. Another signed KEL varied 0/32/512/2,048 distinct digest anchors with two signatures and fixed group count, growing wire from 694 to 109,237 bytes. The prior one-shot/bytewise/64-byte chunk and batch16 rows complete those axes. Three independent all-case runs were **executed** after the scaling rows (nine ignored cases) and again after anchor rows (ten ignored cases), each with 100 warmups and 101 samples. Exact command: `for sample_round in 1 2 3; do cargo test --release -p keri-codec --test a15_baseline --all-features -- --ignored --nocapture --test-threads=1; done > OUTPUT 2>&1`, where `OUTPUT` was first [`2026-09-30-a15-kel-scale-release.txt`](audits/2026-09-30-a15-kel-scale-release.txt), then [`2026-09-30-a15-kel-anchors-release.txt`](audits/2026-09-30-a15-kel-anchors-release.txt). The [A15 report](audits/2026-09-30-a15-baseline.md) has distributions, selected comparisons, throughput/ownership interpretation and reproduction details; raw output has all rows. Eight signatures in one versus eight groups used 86/93 allocations and 8,848/11,180 requested bytes with the same 888 retained bytes. Sixty-four duplicate signatures increased allocation to 234 calls/52,038 requested bytes while retention stayed 272 bytes; exact identical signatures are deduplicated before cryptographic verification. The 2,048-anchor body used 4,176 allocations, 1,154,746 requested and 511,123 peak bytes, retaining the same 272-byte state as the empty-anchor case. These are local observations, not cross-stack claims.
- Focused release cases and all-feature harness Clippy (`-D warnings`) passed. `cargo fmt --all --check` and `git diff --check` passed after the final harness formatting. A15 full Nix gate has **not** run; it is required after A15.3/A15.4 before marking A15 complete. Raw archive files were marked intent-to-add for the Nix source filter.

### 2026-09-30 — A15.2 witnessed/rejected first matrix rows (commit de08a972, aarch64-darwin)

- **Exact next step: continue A15.2.** Add genuine signed recovery and independent key/witness/signature/duplicate/group-count scaling to the same integrated harness, preserving public parse → bind → verify → transition and returned owned-state/rejection semantics. Chunk size and batch size now have initial pinned rows; broaden any coupled axes only with an explicit workload explanation. Archive repeated process outputs and inspect latency, throughput, allocated and retained bytes. Then A15.3–A15.5; A15 remains `[-]`.
- The harness now executes the 715-byte pinned keripy witnessed inception with its two genuine witness receipts and a host-withheld variant that reaches exact `InsufficientWitnessReceipts { valid: 0, required: 2 }`. The accepted path returns owned `KeyStateSnapshot`; rejection returns no state and can stop earlier, so its lower time is not equivalent work. The exact command `for sample_round in 1 2 3; do cargo test --release -p keri-codec --test a15_baseline --all-features -- --ignored --nocapture --test-threads=1; done > docs/audits/2026-09-30-a15-kel-receipt-release.txt 2>&1` **executed three passes of all three ignored cases**, each with 100 warmups and 101 samples. [Raw output](audits/2026-09-30-a15-kel-receipt-release.txt) and [method/report](audits/2026-09-30-a15-baseline.md) record distributions and throughput. Median latency across processes: accepted KEL 161,042/155,834/159,416 ns; accepted witnessed 73,000/78,083/74,125 ns; rejected missing receipts 25,250/25,291/25,666 ns. Median allocation calls/requested/retained/peak bytes respectively: 122/13,061/448/5,816; 55/5,512/536/2,547; 44/4,576/0/2,547. Focused all-feature harness Clippy and `cargo fmt --all --check` passed with the pre-existing test-only config warning; `git diff --check` passed after trimming a raw-output trailing blank. A15 full gate is still pending.
- The same harness now executes the exact pinned KEL with 1-byte and 64-byte host chunks via `MessageFramer` + `BytesMut::split_to(...).freeze()`, then the same typed parse, real signature fold and owned snapshot; it also batches 16 independent folds while retaining 16 snapshots. The command `for sample_round in 1 2 3; do cargo test --release -p keri-codec --test a15_baseline --all-features -- --ignored --nocapture --test-threads=1; done > docs/audits/2026-09-30-a15-kel-chunk-batch-release.txt 2>&1` **executed three passes of six ignored cases** after the new rows. [Raw output](audits/2026-09-30-a15-kel-chunk-batch-release.txt) records p10/median/p90, throughput and allocator counts. Across processes, median one-shot latency was 158,000/159,375/159,125 ns, 64-byte chunks 158,500/160,166/159,000 ns, bytewise 198,625/170,291/170,167 ns, and 16 held folds 2,645,917/2,540,084/2,542,375 ns. One-shot/bytewise requested bytes 13,061/17,614; retained snapshots were 448 bytes in both. The batch requested 223,312 bytes and retained 15,360 bytes including its result vector. Focused all-feature harness Clippy and formatting passed after a lint-driven local variable rename; A15's full Nix gate has not run.

### 2026-09-30 — A15.1 measurement contract and pinned KEL baseline (commit de08a972, aarch64-darwin)

- **Exact next step: A15.2.** Extend [`a15_baseline.rs`](../crates/keri-codec/tests/a15_baseline.rs) with real signed KEL rejected, witnessed-receipt and recovery cases, varying the documented input/group/key/witness/signature/duplicate/chunk/batch axes. Reuse the same per-thread allocator and 100-warmup/101-sample release protocol; archive independent-process outputs. Then A15.3 credential/TEL, A15.4 custody and A15.5 gate. Keep A15 `[-]` until all matrix cells have evidence.
- A15.1 inventory and measurement method are in [the baseline report](audits/2026-09-30-a15-baseline.md), with pinned public-route fixtures and remaining axes. Platform: Apple M4 Pro MacBook Pro `Mac16,7`, 14 cores, 24 GB RAM, macOS 26.5.2, aarch64-darwin, rustc 1.95.0; Cargo release uses opt-level 3, LTO and one codegen unit. The ignored release harness measures parse → bind → real Ed25519 verify → KEL transition → owned `KeyStateSnapshot`, and records p10/median/p90, wire-byte throughput, allocation calls/requested bytes and retained/peak live bytes. It excludes network/persistence/durability; no cross-stack claim or key-cache change is made. New harness and raw result files were marked intent-to-add for later Nix source inclusion.
- The exact archived command was `for sample_round in 1 2 3; do cargo test --release -p keri-codec --test a15_baseline --all-features pinned_kel_parse_bind_verify_fold_owned_snapshot -- --ignored --nocapture --test-threads=1; done > docs/audits/2026-09-30-a15-kel-release.txt 2>&1`. It **executed three independent process runs**, each 100 warmups + 101 samples, all passed. Median latency 154,625/159,458/155,666 ns; p10–p90 143,125–163,500 / 145,000–178,125 / 144,833–162,750 ns; median allocation calls/requested bytes/retained/peak 122 / 13,061 / 448 / 5,816 per three-message fold. Raw output is [archived](audits/2026-09-30-a15-kel-release.txt). Two pilot five-warmup runs varied widely and are not used as baseline evidence. Focused all-feature Clippy on the harness passed with the existing test-only config warning; `cargo fmt --all --check` passed before the final warmup-count edit, so final formatting/check and A15's Nix gate remain pending.

### 2026-09-30 — A14 accepted; A15.1 started (commit de08a972, aarch64-darwin)

- **Exact next step: A15.1.** Inventory the public signed-fold, receipt, recovery, TEL and credential fixtures and existing microbenches. Define the integrated release measurement harness and its input axes, measurement counters and hardware/features. Then implement and execute the first reproducible baseline; continue A15.2–A15.5 without skipping acceptance dimensions. A14 is `[x]`; A16 remains after A15.
- `nix flake check -L --option max-jobs 1 > /tmp/cesr-a14-flake7.log 2>&1` **exited 0** on aarch64-darwin on the final A14 code. Release Nextest **executed 2,564/2,564 passed**, with nine ignored/skipped probes. Fuzz replay **executed**; no_std and `wasm32-unknown-unknown` checks, including the direct-mode wire example, **compiled only**. Twelve named checks rebuilt/passed (docs, WASM, doctests, deny, typos, no_std, Nextest, protected function ratchet, Clippy, fmt, version-owner and fuzz replay); eight named ancillary checks were **previously built** (YAML, TOML, nixfmt, audit, deadnix, shellcheck, actionlint, KERI boundary). Nix omitted aarch64-linux, x86_64-darwin and x86_64-linux. `cargo fmt --all --check` and `git diff --check` passed afterward. [A14 report](audits/2026-09-29-a14-framing.md) records the red-to-green cases, oracle and release work/memory probes; stream and codec changelogs record breaking API migration. A14's bounded V1 message and V1/V2 group framing contract is accepted; typed V2 bodies and optional capability decisions remain A24/A25 work.

### 2026-09-30 — A14 chunking, allocation, oracle and gate continuation (commit de08a972, aarch64-darwin)

- **Exact next step: finish A14.4 before A15.** Run a fresh full `nix flake check` after the final shorter-prefix guard, inspect its named results and A14 acceptance evidence, then mark A14 `[x]` only if all criteria are met and continue A15. Keep A24's V2/profile decisions open; the bounded group codec does not imply typed V2 messages.
- Pinned KEL/TEL/receipt/EXN/ACDC V1 bodies and frames now pass **all two-way split positions**, including a bare KEL attachment run terminated by the next body; KEL also passes bytewise delivery with exact signed body and remainder spans. `cargo test -p keri-codec --test a14_framing -q` **executed 8/8 passed**. `cargo test -p keri-codec --all-features -q` **executed** 391 unit cases and all non-ignored integration/doctests (nine ignored cases across suites). `cargo test -p cesr-stream --all-features -q` **executed** 389 unit cases, three allocation integration cases and one compile-fail doctest (three ignored release probes).
- New allocation evidence: `cargo test -p cesr-stream --test allocation bytewise_message_framing_allocates_no_input_copies -- --nocapture` **executed 1/1**. Framing 128- and 4096-byte padded caller-owned JSON bodies, delivered bytewise, made **zero allocations and requested zero bytes inside `MessageFramer::advance`**. The framer stores offsets/counters rather than retaining the input. An explicitly run ignored release probe, `cargo test --release -p cesr-stream --lib bench_bytewise_json_version_head -- --ignored --nocapture`, measured 21 samples of 20 bytewise passes through 1,049/4,121-byte hostile whitespace headers: repeat-run medians 136,000/539,416 ns (p10 135,208/532,458; p90 142,166/559,750), approximately 4.0× time for 3.9× input. The first run's larger-header median was 900,250 ns with p10 523,250 ns, indicating timing noise; neither run is a hard performance threshold.
- Pinned oracle: `scripts/keripy_spine_gen.py --keripy /tmp/cesr-a07-keripy-pin --out-dir /tmp/cesr-a14-oracle-spine` **executed** under Python 3.14 with pinned keripy, and `cmp` confirmed byte-identical 1,594-byte KEL fixture. The pinned imported-keripy A08 oracle **executed 7/7 exact EXN byte comparisons**; the A09 oracle **executed** six EXN and two ACDC canonical raw-body comparisons plus its rejection observations. The TEL/IPEX/ACDC corpus generators reproduced their checked-in happy JSONL files, and the receipt generator produced byte-identical receipt JSONL; only the spine, receipt and A08/A09 comparisons import the reference, while the other generators model pinned shapes.
- `cargo clippy --workspace --all-features --all-targets -- -D warnings`, `cargo fmt --all --check` and `git diff --check` passed after a test-local shadowed variable was renamed. The first A14 Nix attempt failed because flakes omitted untracked `framing.rs`; all previously untracked task files were marked **intent-to-add, not committed**, so Nix sees the worktree. The second attempt passed docs, doctests, deny, Clippy and fmt, then failed the protected `cesr-fn-ratchet`: a new free `pub(crate) fn` raised `cesr-stream` from zero to one. The version selector now lives on its existing `UnwrapGeneric` type instead; focused stream tests and workspace Clippy passed after that change. No corrected full Nix result has yet been recorded.
- The third Nix attempt exposed eight unmigrated `Deserialize` calls in the separate `fuzz-common` workspace. Its harness now uses an explicit `JsonLimits::new(4096, 64)` for first and second typed reads; `cargo test --manifest-path fuzz-common/Cargo.toml -q` **executed 1/1**, and its own `cargo fmt --manifest-path fuzz-common/Cargo.toml --check` passed after formatting. The corrected fourth invocation, `nix flake check -L --option max-jobs 1 > /tmp/cesr-a14-flake4.log 2>&1`, **exited 0** on aarch64-darwin. Release Nextest **executed 2,575/2,575 passed**, with nine ignored/skipped probes. Fuzz replay **executed**; no_std and WASM, including the `direct_mode` wire example, **compiled only**. Clippy, docs/doctests, deny, fmt, typos and version-owner rebuilt and passed; nine other named checks, including the protected function ratchet and KERI boundary, were **previously built** from the same corrected inputs. Nix omitted aarch64-linux, x86_64-darwin and x86_64-linux. This gate does not close the remaining bounded legacy group path review.
- A **red public compile regression** showed `CesrCodec::<V1>::new(policy)` was unavailable and the older async group decoder used unbounded `advance`. `CesrCodec<V>::new` now requires the shared `FrameLimits`, `Default` is removed, and V1/V2 declared element/byte limits reject before payload buffering. Completed enclosures use the same bounded nested walk as `MessageFramer` before emission; a pinned inner-signature regression rejects a zero-signature policy without consuming the input. The two mapping-only tests used invalid `AAAA` payloads for enclosing groups; those cases now use a valid zero-element nested group, retaining the exact variant mapping assertion. `cargo test -p cesr-stream --all-features -q` **executed 391 unit passes**, three allocation integration passes and one compile-fail doctest, with three ignored release probes. Workspace all-feature/all-target Clippy passed before final formatting. The stream changelog records the breaking constructor migration. The Nix gate above predates this group-codec change.
- The fifth full Nix gate, `/tmp/cesr-a14-flake5.log`, **exited 0** after the bounded `CesrCodec` change; it preceded the following consolidation. The old public `CesrMessage::parse` returned a body plus an attachment iterator over all remaining input, with no exact boundary or caller policy, and no production read caller remained. It was removed rather than wrapped. The internal first-field version cursor now solely serves `MessageFramer`; the fuzz target and frozen public-surface test use that framer. Two unique old version-head cases (reordered/wrong-kind/zero-size rejection and extended CBOR/MGPK lengths at every split) were ported to framer tests; old wrapper/debug tests were removed. `cargo test -p cesr-stream --all-features -q` **executed 376 unit passes**, three allocation integration passes and one doctest (three release probes ignored); `cargo test -p keri-codec --all-features -q` **executed** 391 unit cases and all non-ignored integration/doctests, including A14's eight cases. `cargo test --manifest-path fuzz-common/Cargo.toml -q` **executed 1/1**. Workspace all-feature/all-target Clippy passed after addressing the repo's private-module lint convention. The changelog, `CLAUDE.md`, public-surface test and fuzz harness record the breaking API migration. The fifth Nix gate does **not** cover this removal.
- Final A14 work probes: `cargo test -p cesr-stream --test allocation bytewise_variable_signature_group_keeps_no_input_copy -- --nocapture` **executed 1/1**; bytewise 64/256 nested signatures in a variable-length `-F` group requested **zero heap bytes** in the framer, complementing zero-allocation 128/4,096-byte JSON body cases. `cargo test --release -p cesr-stream --lib bench_bytewise_nested_signatures -- --ignored --nocapture` **executed** 5,772/22,668-byte `-F` groups in 344.333 µs/1.203917 ms per three bytewise passes (3.5× work for 3.9× bytes, one observation). The release JSON-header probe **executed** 21 samples of 20 bytewise passes over 1,049/4,121-byte whitespace heads: median 136,625/557,916 ns; p10 131,292/538,333; p90 139,708/558,417. No wall-clock assertion is used. These probes cover hostile variable elements, declared lengths, allocation and retained input ownership; the framer stores no input and made no heap allocation in either incremental case. The final full gate after these edits is pending.
- The sixth full Nix gate, `/tmp/cesr-a14-flake6.log`, **exited 0** after the public-surface removal. A final adversarial review then found that replacing a retained partial JSON version head with a shorter buffer could panic at an unchecked version offset; a second red assertion showed a shortened whitespace prefix incorrectly waited. The `JsonVersionHead` cursor now returns typed `Truncated` for both shorter-prefix states, and `event_size_at` slices via checked `get`. The focused regression **failed red twice** (panic, then wrong result) and **passed green**; `cargo test -p cesr-stream --all-features -q` **executed 377 unit passes**, four allocation integration passes and one doctest, with three ignored release probes. Workspace all-feature/all-target Clippy passed after the guard. The sixth gate predates this fix and is not final A14 acceptance.

### 2026-09-30 — A14 public bounded typed reads and opaque-probe rollback (commit de08a972, aarch64-darwin)

- **Exact next step: continue A14.2/A14.3.** Exercise bounded `Message::parse` and the sans-I/O framer across pinned bare/KEL/TEL/receipt/EXN/ACDC coalesced and fragmented inputs, exact remainders, incomplete attachment cases and hostile declared lengths/counts. Measure retained memory, allocations and hostile fragmented work; inspect all signature-bearing nested group paths. Then run A14.4 target/feature checks (including WASM), pinned oracle comparisons and a fresh full `nix flake check`. Keep A14 `[-]`; A15 follows only after every A14 criterion passes.
- A **red public compile regression** showed `Deserialize::deserialize` had no caller JSON policy. `JsonLimits` now flows through KEL/TEL/receipt/EXN/ACDC typed body parsers; `MessageLimits` combines it with `FrameLimits` at public `Message`/`EventMessage`/`TelMessage`/`ExnMessage`/`ReceiptMessage` reads. Those message parsers now use `MessageFramer` once to establish exact body, attachment and remainder spans before typed routing, removing their former `CesrMessage::parse` path. No old unlimited overload or bounded pass-through wrapper remains. `IpexMessage::parse` and the offer/grant embedded-body constructors now take the caller's JSON policy; public tests, examples and benches were migrated. One-shot EOF intentionally reports `Truncated` for incomplete input. [A14 report](audits/2026-09-29-a14-framing.md) and the [codec changelog](../crates/keri-codec/CHANGELOG.md) record the API decision and migration.
- A **red runtime regression** showed codex-seal probing consumed `JsonBudget` counters before opaque-anchor fallback while restoring only the byte offset; the fallback now restores both, and propagates real field/depth limit errors rather than trying another interpretation. Public pinned tests accept KEL/TEL/receipt/EXN/ACDC bodies under a generous policy and reject tight field/depth policies; a size-patched KEL opaque anchor demonstrates many-key and nested-object limits. Public `Message::parse` and `EventMessage::parse` also reject JSON and body-byte policy exceedance. Current public A14 integration suite **executed 6/6 passed**.
- `cargo test -p keri-codec --all-features -q` **executed** 391 unit passes, all non-ignored integration/doctests, and 9 ignored probe/integration cases across suites. `cargo clippy -p keri-codec --all-features --all-targets -- -D warnings` **passed** with the unchanged test-only `Matter::new_unchecked` config warning. `cargo check -p keri-rs --all-features --examples`, `cargo check --workspace --all-features --all-targets`, and `cargo check -p keri-codec --no-default-features --features alloc` were **compile-only passes**. The later opaque-anchor depth assertion and formatting edit need the final focused checks rerun. A14's full Nix gate has **not** run.

### 2026-09-30 — A14 JSON scanner work-budget primitives (commit de08a972, aarch64-darwin)

- **Exact next step: continue A14.2/A14.3.** Add failing **public** `Message`/typed-body field and depth regressions, then carry one explicit caller policy through the public typed read route and framer, with no unlimited compatibility wrapper. Include many-key opaque anchors and deeply nested SAD values in KEL/TEL/receipt/EXN/ACDC. The current scanner-owner tests are necessary but do **not** establish a public bound. Then finish A14's other chunking/oracle/adversarial/target/Nix criteria before marking it `[x]`; A15 remains next.
- Red scanner-owner tests first failed to compile because no budget or typed field/depth errors existed. `JsonBudget` now counts fields before key decoding and open containers before stack growth inside the existing canonical-value and opaque-anchor scanners. A further **red runtime** test showed fixed-field literals bypassing both limits; `Scanner::take_lit`/`expect` now charge matching fixed field and container tokens, including optional fields, on the same cursor. `OpaqueScan::object_len` requires the shared budget; the typed seal scanner passes its budget, while write validation and existing public read entries currently construct an unlimited budget. This is an **intermediate implementation**, not a claim that all public read paths have limits. It adds no preflight JSON grammar or pass-through bounded wrapper. [A14 report](audits/2026-09-29-a14-framing.md) records the scope.
- `cargo test -p keri-codec --lib work_budget_rejects --no-default-features --features alloc` **executed 2/2 passed** after the red compile failure; `cargo test -p keri-codec --lib canonical_value_charges_nested_fields_and_depth --no-default-features --features alloc` **executed 1/1 passed** after its red compile failure; `cargo test -p keri-codec --lib fixed_field_literals_charge_the_same_budget --no-default-features --features alloc` **executed 1/1 passed** after its red runtime failure. `cargo test -p keri-codec --all-features -q` **executed** 390 unit passes and all non-ignored integration/doctests; 9 integration/probe cases remained ignored across suites. `cargo clippy -p keri-codec --all-features --lib --tests -- -D warnings` **passed** with the pre-existing `Matter::new_unchecked` config warning. `cargo check -p keri-codec --no-default-features --features alloc` **compile-only passed after the fixed-literal change**. `cargo fmt --all --check` and `git diff --check` passed. No fresh A14 Nix gate yet.

### 2026-09-30 — A14 universal enclosure table switches (commit de08a972, aarch64-darwin)

- **Exact next step: continue A14.2/A14.3.** Add failing public `keri-codec` cases for JSON field/depth work limits, including nested arbitrary SAD values, opaque anchors and many-key objects. Put the counters in the existing scanner owners and pass an explicit policy through the public typed read path; do not add a separate JSON preflight grammar or a pass-through compatibility wrapper. Then complete bare/KEL/TEL/receipt/EXN/ACDC chunking/oracle cases, adversarial allocation/work measurements, no_std/WASM checks and a fresh `nix flake check`. A14 stays `[-]`; A15 remains next.
- The [CESR universal enclosure rule](https://trustoverip.github.io/kswg-cesr-specification/#universal-code-table-genus-version-codes-that-allow-genus-version-override) and current V1/V2 code tables identify `-T`/`-U`/`-V` as table-switching enclosing groups. **Red** V1 `-T` fixtures with a V2 genus selector plus two `-K` signatures, and with two standalone signature Matters, bypassed `max_signatures`; a complete enclosure with a partial selector wrongly returned `NeedBytes`. The bounded walk now traverses all three V1 enclosures with the existing `UnwrapGeneric` selector and `GroupFrameCursor` V1/V2 tables, counts direct Matter signatures, retains mixed Matter/group and embedded-body frames, and returns typed truncation for the complete partial selector. No V2 typed-message claim is made. [A14 report](audits/2026-09-29-a14-framing.md) has exact fixtures and limits.
- `cargo test -p cesr-stream --all-features -q` **executed** 389 unit passes, two ignored release probes, two integration passes and one compile-fail doctest. `cargo test -p keri-codec --test a14_framing -q` **executed** two pinned KEL tests. All-feature stream Clippy **passed** with the pre-existing test-only `Matter::new_unchecked` config warning; `cargo check -p cesr-stream --no-default-features --features alloc` was a **compile-only pass**. No fresh A14 Nix gate yet.

### 2026-09-30 — A14 nested signature cursor and scaling probe (commit de08a972, aarch64-darwin)

- **Exact next step: continue A14.2/A14.3.** The CESR Annex A override rule identifies V1 `-T`/`-U`/`-V` counterparts as table-switching enclosing groups; inspect the existing `UnwrapGeneric` selector logic and pin a red V1 generic/envelope fixture with a version switch. Extend the bounded walk to every admitted nested signature path without treating arbitrary opaque bytes as groups, recording the A24 profile decision for any V2 table requirement. Then bound JSON field/depth work in the existing body scanner and integrate policy into the public `keri-codec` read route. Add red cases before each fix. Complete bare/all-variant pinned oracle chunking, hostile coalesced/fragmented work and retained-memory measurements, no_std/WASM feature/target checks and a fresh `nix flake check`. Keep A14 `[-]` and A15 queued until all acceptance criteria pass.
- A release-only nested `-F` probe **executed** with `cargo test --release -p cesr-stream --lib bench_bytewise_nested_signatures -- --ignored --nocapture`: three bytewise passes over 64/256 nested signatures took 8.51/60.29 ms before and 0.232/0.746 ms after the change (about 36.6×/80.9× faster). One observation per size; no stability claim. `NestedSigCursor` now retains completed Matter, counter and signature offsets within `-F`/`-H`, and both one-shot `GroupKind::skip` and incremental framing use that grammar. An ordinary regression checks every two-way split, bytewise fragments, exact bare-group remainder and final-byte EOF for both families. [A14 report](audits/2026-09-29-a14-framing.md) has the measurement and limits.
- A separate **red** regression showed that `FrameLimits::max_group_elements` did not apply to the nested `-A` counter inside `-F`/`-H`: a declared two-signature list passed its one-element policy until payload arrived. The shared nested cursor now rejects at the counter with typed `GroupElements` limit evidence. Further **red** cases showed direct/nested/cumulative signatures and `-V`-enclosed signatures bypassed a one-signature policy; the cursor now counts `-A`/`-B`/`-C`/`-D` and nested `-F`/`-H` signatures, and an iterative V1 `-V` walk enforces signature, nested-group and envelope-depth bounds. The [A14 report](audits/2026-09-29-a14-framing.md) records the measured release probe after these checks (0.386/1.353 ms for 64/256 nested signatures, three bytewise passes). Generic/other opaque quadlet payload traversal is still open. `cargo test -p cesr-stream --all-features -q` **executed** 385 unit passes, two ignored release probes, two integration passes and one compile-fail doctest. `cargo test -p keri-codec --test a14_framing -q` **executed** two pinned tests. All-feature Clippy passed with the existing test-only `Matter::new_unchecked` config warning; `cargo check -p cesr-stream --no-default-features --features alloc` was **compile-only pass**. No fresh A14 Nix gate yet.

### 2026-09-30 — A14 partial framer, first-field binary correction and pinned V1 integration (commit de08a972, aarch64-darwin)

- **Exact next step: continue A14.2/A14.3.** Add and enforce explicit total signature, nested-group, JSON field and JSON depth budgets across the public `keri-codec` read route, then test bare attachments and all supported message variants through the bounded framer. Measure hostile variable-element and fragmented-header work/memory, run pinned oracle comparisons beyond KEL, no_std/WASM feature and target checks, then a fresh full `nix flake check` for A14. Do not mark A14 `[x]` until all acceptance criteria and migration evidence are satisfied; A15 remains next afterward.
- Red-to-green: JSON/CBOR/MGPK valid partial first fields now wait for bytes; a later `v` field and cold-start/version-kind mismatch reject; extended binary text-length heads are accepted. Zero-size body progress, incomplete counter at attachment-byte limit and typed EOF truncation regressions pass. The [A14 report](audits/2026-09-29-a14-framing.md) records each pre-fix failure and the [CESR first-field specification](https://trustoverip.github.io/kswg-cesr-specification/).
- `GroupFrameCursor` retains completed-element offsets and reuses `GroupKind::skip`; one-shot framing and async `CesrCodec<V>` share its counter table. `MessageFramer` holds body/attachment offsets and a JSON first-field cursor over caller-owned bytes; `MessageCodec` delegates to it and yields exact `Bytes`. `FrameLimits` currently cover body bytes, attachment bytes, top-level group count and per-group element count. Unframed attachment runs wait for next body/EOF; bare groups and complete `-V` envelopes emit immediately. Total signatures, JSON field/depth and nested-group limits are still open, as is fully bounded `keri-codec` integration. No profile-dependent V2 message capability is claimed before A24.
- Release group benchmark **executed**: `cargo test --release -p cesr-stream --features async --lib element_group_fragmentation_measurement -- --ignored --nocapture` (`/tmp/cesr-a14-group-after.log`), 256-signature bytewise median 19,834,750→335,334 ns, 59.2× faster; 64→256 signatures grows 3.6× on 4× input. This does not prove variable-element bounds. `cargo test -p cesr-stream --all-features` **executed** 380 unit passes, one ignored benchmark, two integration passes and one compile-fail doctest (`/tmp/cesr-a14-stream-tests4.log`). `cargo test -p keri-codec --test a14_framing -- --nocapture` **executed** 2 passes across all 1,595 two-way split positions and bytewise pinned KEL delivery (1,594 bytes, exact 577/630/387 frames). `cargo test -p keri-codec --lib message::tests` **executed** 30 passes (`/tmp/cesr-a14-keri-message-tests2.log`). All-feature Clippy on `cesr-stream` and on the KERI integration test **passed** with the existing test-only `Matter::new_unchecked` config warning. `cargo check -p cesr-stream --no-default-features --features alloc` was **compile-only pass**. The A13 Nix gate predates A14 changes; no fresh A14 gate yet.

### 2026-09-29 — A14.1 framing contract and baseline recorded (commit de08a972, aarch64-darwin)

- **Exact next step: A14.2.** Add red public regressions for short valid JSON `v` prefixes (`NeedBytes`, not `MissingVersionString`), malformed first-field heads, body-complete/partial-attachment and bare-attachment outcomes, exact consumed remainder and EOF. Then pin budget errors and a chunking-invariant decoder contract before implementing the cursor. A14 remains `[-]`; no A14 implementation is accepted yet.
- The [A14 report](audits/2026-09-29-a14-framing.md) records the [CESR cold-start/first-field specification](https://trustoverip.github.io/kswg-cesr-specification/) and issue [#193](https://github.com/devrandom-labs/cesr/issues/193)/[#208](https://github.com/devrandom-labs/cesr/issues/208)/[#210](https://github.com/devrandom-labs/cesr/issues/210) constraints. The current `CesrMessage::parse` is body-framing plus lazy attachments, not a complete-message boundary; `Message::parse` accepts a body at the end of current input even though unframed attachments can arrive later; the async `CesrCodec` frames groups only and reparses an element group's whole prefix on partial polls. The proposed sans-I/O cursor contract makes EOF/boundary explicit and keeps a caller-supplied work policy.
- An ignored **executed** release benchmark, `cargo test --release -p cesr-stream --features async --lib element_group_fragmentation_measurement -- --ignored --nocapture`, captured four warmups and 31 samples each for one element-count group of 1/16/64/256 signatures (`/tmp/cesr-a14-group-before.log`). The 64-signature bytewise median was 1,612,041 ns at 5,636 bytes; at 256 signatures it was 19,834,750 ns at 22,532 bytes (4× input, 12.3× time). Coalesced medians were 1,084 and 3,958 ns. No full Nix gate was run for A14; the A13 gate predates this test addition.

### 2026-09-29 — A13 accepted; A14 begins (commit de08a972, aarch64-darwin)

- **Exact next step: A14.1.** Verify current `cesr-stream` and `EventMessage::parse` partial-input, end-of-input, malformed-frame and consumed-remainder contracts against the CESR framing rules and existing issue/ADR contracts. Measure byte-by-byte/coalesced delivery and hostile length behavior before defining explicit budgets. A14 remains open until its own regressions, implementation and fresh gate pass.
- A13.1 confirmed the source finding against the [CESR right-alignment/zero-lead spec](https://trustoverip.github.io/kswg-cesr-specification/) and pinned keripy corpus. Baseline release measurements and current implementation measurements are in the [A13 report](audits/2026-09-29-a13-encoding.md): 31/31 executed samples each; Matter 10k median 552,667→310,375 ns, Indexer 10k 1,563,625→449,625 ns, representative inception JSON 1k 2,213,250→2,156,791 ns with overlapping timing distributions. JSON allocation count improved from 38 to 22. The allocation regression failed before the change at Matter 2 allocations and passes now at ≤1; append with preallocated capacity allocates 0. A separate 31-sample 1,024-key owned representation prototype found 56-byte `Matter` slots and 1,025 allocations/90,112 requested bytes versus 33-byte inline tuple slots and 1 allocation/33,792 requested bytes. The generic `Cow` carrier was not replaced: the prototype is Ed25519-only, and A24 has not settled the algorithm/profile matrix. Avoid a premature wrapper architecture.
- A13.2/A13.3 implemented a crate-private borrowed `ZeroLead` encoder method, direct `Matter`/`Indexer` append methods, and direct quoted CESR field writes in KERI/ACDC/EXN/IPEX JSON. No padded payload copy, intermediate index strings or extra JSON field String remains on these paths. Tests cover all 16 indexed code classes, zero/one/two lead-byte small and large variable Matter classes, prefix-buffer reuse, zero allocations with sufficient capacity, and typed rejection of nonzero lead bytes/pad bits. Existing 529 Matter and 277 Indexer release unit tests passed; pinned keripy `cesr-stream` replay passed 50 Matter and 53 Indexer vectors with zero skipped (six replay tests total); pinned KERI JSON parity passed 22 tests; the representative allocation ceiling tests passed. Targeted all-feature Clippy, rustfmt and `git diff --check` passed. Public append APIs and JSON writer change are described in both changelogs.
- The first full Nix attempt (`/tmp/cesr-a13-flake.log`) failed the protected `cesr-fn-ratchet` because a new `pub(crate) fn` raised the b64 free-function count from six to seven. The policy was preserved: the behavior moved to the borrowed `ZeroLead` value, returning the count to six. The subsequent `nix flake check -L --option max-jobs 1` **passed** (`/tmp/cesr-a13-flake2.log`), with Nextest executing 2,528/2,528 tests across 34 binaries and four skipped ignored benchmarks. Twelve final-run checks built/passed, including no_std/WASM **compile-only**, Clippy, docs/doctests, fuzz replay and ratchet. Eight other checks were `previously built` (YAML, TOML, nixfmt, audit, deadnix, shellcheck, actionlint, KERI boundary). The flake omitted aarch64-linux, x86_64-darwin and x86_64-linux. The three A13 ignored release benchmarks were explicitly executed 31/31 samples each. A13 is accepted; the A24 profile decision remains prerequisite to any algorithm-specific inline-key production representation.

### 2026-09-29 — A12 accepted; A13 begins (commit de08a972, aarch64-darwin)

- A12's final `nix flake check -L --option max-jobs 1` **passed** (`/tmp/cesr-a12-flake-final-pass.log`): Nextest executed 2,528/2,528 tests across 34 binaries with **3 skipped** explicitly ignored release benchmarks. The A12 `registry_cardinality_after` benchmark had been executed separately 31/31 times; the old A12 baseline had also executed 31/31 times before replacement. Nineteen other Darwin checks reported `previously built` in the final run, including no_std/WASM **compile-only**, Clippy, docs, doctests, fuzz replay and policy checks; those check derivations built or passed in preceding attempts or isolated runs, not falsely claimed as fresh executions in the last run. The flake omitted incompatible aarch64-linux, x86_64-darwin and x86_64-linux systems. `git diff --check` passed. The first Nix attempt hit the intermittent WASM `E0463`; an isolated WASM check passed. The next full attempt found the A09 property mismatch, which was corrected and stress-tested at 10,000 generated cases. The following run exhausted disk space in generated build directories; `cargo clean --profile dev` removed 12.2 GiB of generated artifacts while preserving source changes. A limited-job run passed other checks but again hit intermittent WASM `E0463`; an unchanged isolated WASM build passed, followed by the successful full gate. No such failed or cancelled attempt is counted as a passing full gate.
- A12 satisfies its recorded criteria: public TEL paths use independent owned management and credential heads; credential operations inspect no unrelated credential; the state has no source-history lifetime; current/historical issuer, registry, `ra`, sequence and prior bindings are checked; red-to-green retry/binding cases and all prior wire verdicts pass; the 16–1,024 cardinality report includes issuance/replay, indexed random lookup, retained memory and rejection costs; changelog describes the breaking API migration. The user explicitly ruled out compatibility facades; the old aggregate API and duplicate historical wrapper were removed from production. A map exists only in the integration test's host adapter. A09's corrected property and parity ledger are part of the same passing gate because the previous assertion contradicted A09's intended large-number grammar.
- **Exact next step: A13.1**, verify P02's encoding-allocation findings against current `Matter`/`Indexer`/JSON writer code and current spec, identify append/encode-into opportunities, then capture primitive and end-to-end release allocation/timing baselines. A13 remains `[-]` until its own regressions, implementation, targets/oracle and fresh Nix gate pass.


### 2026-09-29 — A12.3 split implemented; A12.4 final gate next (commit de08a972, aarch64-darwin)

- Production `RegistryState` now owns **only** the management head (`vcp`/`vrt`); `CredentialState` owns one credential head and validates `iss`/`bis` inception or `rev`/`brv` advancement against caller-supplied current registry and historical `ra` evidence. The owned values have no source-event lifetime. BackerAt now takes an accepted `&RegistryState` retained at its `(id,sn,SAID)` coordinate; the redundant `RegistryManagementEvidence` copy and unbounded `Cow<[CredentialChain]>` aggregate are gone. The old aggregate `ingest`/`vcstate`/`fold_optional` production APIs were removed, not wrapped for compatibility. `InconsistentCredential` is a new terminal typed error. The test-only host store in `registry_fold.rs` uses a map to preserve all existing 41 TEL verdict/wire cases while routing each event through the new public core; it is not a production dependency or prescribed host storage.
- Four A12 direct public regressions that were red on missing API/ownership now pass. They cover source-event drop, separate credential heads, rejected-delivery retry without partial mutation, historical `ra` after backer rotation, and wrong-registry/credential binding. The complete `registry_fold` suite executes **45/45 passed**. `cargo test -p keri-codec --all-features -q` and `cargo test -p keri-rs --all-features -q` passed all their suites; `cargo check -p keri-rs --no-default-features --features wire` passed compile-only. `cargo clippy -p keri-rs -p keri-codec --all-features --all-targets -- -D warnings` passed with only the pre-existing protected `clippy.toml` warning.
- The [A12 report](audits/2026-09-29-a12-baseline.md) now includes 31/31 **executed release-profile** post-split benchmark processes at each of 16/64/256/1,024 distinct accepted credentials. At 1,024, core validation plus test-host map insertion was 221,852 ns by sum of medians versus the old aggregate's 1,344,100 ns; 10,000 indexed random reads were 204,250 ns versus 12,838,792 ns. The accepted-issuance loop is a replay from an empty state over prepared events; duplicate-delivery occupancy and missing-anchor rejection costs were measured separately. Memory increased for this concrete owned `HashMap` host option (637,288 live bytes versus the old vector's 49,504-byte delta), but the old number excludes the 1,024 source event objects it required to remain live. The report states this limitation and A13's owned-representation follow-up. The release benchmark is intentionally skipped by ordinary test gates and was run explicitly. The pinned keripy Tevery/Tever A07 oracle executed successfully and emitted 13 structured rows covering six ilks, delayed anchors, out-of-order/re-drive, missing receipts, historical backers and wrong flavor (`/tmp/cesr-a12-tel-oracle.log`).
- **Exact next step: A12.4** run `git diff --check`, final relevant direct and full-feature checks after the latest historical issuer/config binding hardening, then `nix flake check -L`. Confirm no_std/WASM compile-only, fuzz replay, docs/policy and executed/skipped/cached Nextest outcomes; update changelog/API migration and evidence if anything changes. Mark A12 `[x]` only if all pass, then automatically start A13.

### 2026-09-29 — A12.4 Nix gate exposed an A09 property error; corrected, full rerun pending (commit de08a972, aarch64-darwin)

- First `nix flake check -L` attempt built/ran many Darwin checks but failed in WASM dependency compilation with intermittent `E0463: can't find crate core`. An unchanged isolated `nix build .#checks.aarch64-darwin.cesr-wasm -L` then **passed** (`/tmp/cesr-a12-wasm-retry.log`), as in A11. The next full Nix run passed its other reported checks, including cached WASM/no_std compile-only, then Nextest found a *real pre-existing A09 property-contract mismatch* after 2,109/2,528 tests (2,108 passed, 1 failed, 3 skipped; 419 not run because fail-fast). Proptest generated `{"k":-2.5e+1001}`: RFC-valid number grammar accepted by `OpaqueScan`, while `serde_json::Value` rejects magnitude with `number out of range`. The A09 intent and deterministic test already accepted large finite decimal syntax, but `opaque_scanner_accepts_subset_of_serde_json` falsely asserted a strict subset. Logs: `/tmp/cesr-a12-flake.log` and `/tmp/cesr-a12-flake-final.log`.
- Corrected the property to allow only `serde_json`'s explicit numeric-range rejection, renamed it `opaque_scanner_matches_serde_json_except_numeric_range`, and added the exact failing exponent to the deterministic grammar regression. Updated the stale claim in `docs/keripy-parity/ledger.md`. `cargo test -p keri-codec --lib opaque_scanner_matches_serde_json_except_numeric_range -- --nocapture` **executed 1/1 passed**; `PROPTEST_CASES=10000` on the same test **executed 1/1 passed** with 10,000 generated cases. An initial command accidentally used `--exact` with only the short name and ran **0** tests; it is not counted as evidence. **Exact next step:** rerun focused formatting/Clippy if needed and `nix flake check -L` after the property edit; keep A12 `[-]` until the full gate passes and exact outcomes are recorded.


### 2026-09-29 — A12.1 protocol contract and cardinality baseline; A12.2 next (commit de08a972, aarch64-darwin)

- Rechecked the [PTEL management/VC TEL distinction](https://trustoverip.github.io/tswg-ptel-specification/draft-pfeairheller-ptel.html), [KERI seal semantics](https://trustoverip.github.io/kswg-keri-specification/), pinned keripy routing, and repository [#98](https://github.com/devrandom-labs/cesr/issues/98), [#92](https://github.com/devrandom-labs/cesr/issues/92), and [#193](https://github.com/devrandom-labs/cesr/issues/193). The current `RegistryState` combines two separately sequenced TEL domains and retains a linearly searched credential vector plus references into every source event. The user clarified that compatibility is **not** a goal and that replacement APIs should remove redundant wrappers rather than preserve a poor base. A12 remains the explicitly authorized scoped registry correction, not the owner-driven general redesign of #193.
- Added and explicitly executed the release-only `registry_cardinality_baseline` 31/31 times on aarch64-darwin. Its [baseline report](audits/2026-09-29-a12-baseline.md) records 16/64/256/1,024 distinct issuance, 10,000 pseudorandom status lookups per level, live memory, replay and early rejected-delivery costs, with 27 post-warmup median/p10/p90 timings and allocation counts. At 1,024 heads the old aggregate retained +49,504 live bytes excluding required source fixtures, requested 98,112 bytes cumulatively for its vector, spent a median 1.344 ms on 1,024 issuance folds and 12.839 ms on 10,000 random status reads. The trends agree with the verified linear scans and O(N²) total distinct insertion work; no wall-clock threshold is asserted. The case is intentionally ignored in ordinary gates and was run explicitly.
- Chosen boundary: owned management state for `vcp`/`vrt`, owned independent credential head per `(registry, credential)` for `iss`/`rev`/`bis`/`brv`, host-supplied accepted KEL and historical management evidence, no core lookup/persistence. Remove the old aggregate API and redundant historical management snapshot once the new public-path tests and implementation pass. **Exact next step: A12.2** add and execute red public tests for issuance, revocation, backed historical `ra`, wrong registry/issuer, retry, owned reload and no cross-credential scan; then implement the split. A12 remains `[-]`.

### 2026-09-29 — A12.2 red replacement API paths; A12.3 in progress (commit de08a972, aarch64-darwin)

- Added four public integration cases to `registry_fold.rs`: owned management survives its `vcp` event dropping; two independent credential heads issue/revoke with retry on missing KEL anchor and one head unaffected; backed issuance/revocation use a cloned historical management head after rotation and reject contradictory current management; foreign-registry and wrong-credential binding reject without mutation. `cargo test -p keri-codec --test registry_fold a12_ --no-run` **failed before implementation as desired** (`/tmp/cesr-a12-red.log`): no `CredentialState`, borrowed `RegistryState` cannot outlive the inception event, `BackerAt` takes the old redundant evidence wrapper instead of management state, and no `InconsistentCredential` variant. One first-pass fixture arity error was corrected before recording this red proof. These are intended API/ownership failures, not retained defective expectations.
- **Exact next step: A12.3.** Implement the owned management/credential types and historical evidence boundary, migrate existing public TEL fold cases to exercise the new core without preserving a production aggregate wrapper, then make all targeted paths green. A12 remains `[-]`.


### 2026-09-29 — A11 accepted; A12 begins (commit de08a972, aarch64-darwin)

- A11's final `nix flake check -L` **passed**: Nextest executed 2,524/2,524 tests across 34 binaries; 2 explicitly ignored release benchmarks were skipped by the ordinary gate and were run separately for A10/A11 evidence. Nineteen other Darwin checks reported `previously built` in the final run, including no_std and WASM compile-only checks, Clippy, docs, fuzz replay, and policy ratchets. The check omitted incompatible aarch64-linux, x86_64-darwin, and x86_64-linux systems. The first full attempt failed in the Nix WASM build with `E0463: can't find crate core`; an unchanged isolated `nix build .#checks.aarch64-darwin.cesr-wasm -L` passed, followed by the passing full gate. The final log is `/tmp/cesr-a11-flake-final.log`; the first-attempt and isolated logs are `/tmp/cesr-a11-flake.log` and `/tmp/cesr-a11-wasm-retry.log`.
- Focused final checks also passed: `cargo test -p keri-codec --all-features -q`, `cargo test -p keri-rs --all-features -q`, `cargo check -p keri-rs --no-default-features --features wire`, `cargo clippy -p keri-rs -p keri-codec --all-features --all-targets -- -D warnings`, `cargo fmt --all`, and `git diff --check`. A11's retained-state API, red-to-green public retry regressions, allocation measurements, migration guidance, and target limits meet all recorded acceptance criteria. **Exact next step: A12.1**, verify registry cardinality and history ownership against code/spec/issue contracts, record sequential subtasks, and establish a distinct-issuance/status-lookup baseline before selecting the per-credential API. A12 remains `[-]`.

### 2026-09-29 — A11.3 mutable transitions and A11.4 allocation evidence; full gate next (commit de08a972, aarch64-darwin)

- Implemented `KeyState::ingest_mut`, `ingest_delegated_mut`, and `RegistryState::ingest_mut`; existing consuming methods now delegate to these and retain their original return shape. KEL rotation, delegated rotation and interaction validate all fallible chain, signature, commitment, witness and delegation checks before updating fields. TEL management rotation validates routing, anchor, backer algebra/threshold and receipts before updating; issue/revoke paths validate anchor and credential-chain position/prior before `Cow::to_mut` or head update. Registry Rustdoc now accurately says its consuming `ingest` loses custody on `Err`. The migration is in `keri/CHANGELOG.md`; `KeyStateSnapshot::view()` remains the cheap zero-copy option for snapshot-backed hosts.
- The three originally red retry-loop tests now **execute and pass**. Added a delegated late unsealed-anchor rejection before successful redrive, a TEL rotation late invalid-backer-receipt rejection before successful redrive, and converted an existing witness-rotation test from clone-to-survive-failure to retained mutable state. `cargo test -p keri-codec --test transitions --test delegation --test registry_fold -q` executed 58/58, 17/17 and 40/40 before the two latest adversarial assertions; their focused commands subsequently passed. `cargo test -p keri-rs --lib -q` executed 73/73. `cargo clippy -p keri-rs -p keri-codec --all-features --all-targets -- -D warnings` passed after scoped code cleanup, with only the pre-existing protected `clippy.toml` warning.
- The [A11 retry report](audits/2026-09-29-a11-retry.md) records 31/31 **executed release-profile** runs of the explicitly ignored `retained_retry_allocations` case. `KeyStateSnapshot::view()` and its rejected KEL view both allocated 0; accepted mutable KEL view allocated 2/48 for A10 crypto buffers. With one already-owned registry credential, clone-based rejected/accepted calls allocated 1/48 and 2/240, while retained mutable rejected/accepted calls allocated 0/0 in all 31 runs. Sub-microsecond TEL timings are below resolution; this is allocation evidence, not a large-cardinality performance claim (A12 owns that). The release-only benchmark is intentionally skipped by ordinary tests and was run explicitly.
- **Exact next step: A11.4** run final focused suite, no_std/WASM feature checks and `nix flake check -L`; record executed/cached/skipped outcomes, then mark A11 `[x]` only if they pass. A12 follows. A11 remains `[-]`.

### 2026-09-29 — A11.1 retry prototype and A11.2 red public paths (commit de08a972, aarch64-darwin)

- Confirmed P04 against current code: `KeyState::ingest(self, ...)`, `ingest_delegated(self, ...)`, and `RegistryState::ingest(self, ...)` discard their state on every `Err`; TEL `record_chain_event` calls `credentials.to_mut()` before validating sequence/prior, so a borrowed credential slice can be cloned even for a rejected event. The registry `ingest` Rustdoc incorrectly claims the caller keeps the old state. `KeyStateSnapshot::view()` already lends a cheap read/validate view and does not need an owned retry wrapper. For retained borrowed/owned states, chose `ingest_mut(&mut self, ...)` and delegated `ingest_delegated_mut`: validate all fallible rules before mutating in place, preserve the old consuming `ingest` methods as convenience wrappers. This avoids state clones on successful and rejected retry paths and gives the host a stable owner for redrive.
- Added executable host retry-loop prototypes/regressions to KEL transitions, delegated rotation, and TEL registry fold. Each uses the **same retained state** after a retryable rejection, supplies the missing signature or anchor, then accepts; KEL/TEL assert unchanged heads on failure, and TEL asserts a later duplicate rejection leaves an issued credential intact. All three focused pre-implementation commands **failed as expected at compile time** solely because `ingest_mut` / `ingest_delegated_mut` do not yet exist: `cargo test -p keri-codec --test transitions a11_kel_retries_missing_signature_on_the_same_state -- --exact`, `--test delegation a11_delegated_rotation_retries_after_anchor_arrives`, and `--test registry_fold a11_registry_retries_missing_anchor_on_the_same_owned_state`. This is an API-level red proof of the actual retry loop, not an audit expectation retained as a test.
- **Exact next step: A11.3.** Implement validated mutable KEL, delegated and TEL transitions with zero partial state mutation; refactor `record_chain_event` to inspect before `Cow::to_mut`, correct registry Rustdoc, rerun the red loops, then measure allocations and run the full A11 gate. A11 remains `[-]`.

### 2026-09-29 — A10 accepted; A11 begins (commit de08a972, aarch64-darwin)

- Final `nix flake check -L > /tmp/cesr-a10-flake.log 2>&1` **exited 0** on aarch64-darwin. All 14 reported Darwin checks passed. Its release nextest stage **executed 2,520/2,520 passed, 1 skipped**: the one skipped case is the intentionally ignored `a10_auth_work::authentication_paths` release measurement, separately **executed 31/31 times** after the final A10 verifier change and 31/31 times before it. Nix no_std and `wasm32-unknown-unknown` checks **compiled only**, including the `keri-rs` wire example; neither target was executed. Clippy, formatting, function ratchet, docs/doctests, deny, boundary, fuzz replay, typos and version-owner checks passed. The audit, YAML, Nix formatting, deadnix, shellcheck and actionlint checks were explicitly reported **previously built**; the other named check outputs were built in this invocation. Incompatible aarch64-linux, x86_64-darwin and x86_64-linux checks were omitted by Nix. `git diff --check` passed. No protected lint/config policy changed; item-specific `clippy::redundant_pub_crate` allows with reasons are confined to shared private-module helpers because `unreachable_pub` simultaneously forbids exposing those helpers publicly.
- A10's before/after allocations and 27-sample release timing distributions, pinned keripy oracle, public red-to-green regressions, API migration, no_std feature correction and exact platform limitations are recorded immediately below and in [the A10 report](audits/2026-09-29-a10-baseline.md). Every A10 acceptance criterion is met, so A10 is `[x]`. **Exact next step: A11**, verify the rejected-transition ownership finding against current `KeyState::ingest`, delegated ingestion and `RegistryState::ingest`, then record concrete subtasks and red tests before any implementation. Keep A11 `[-]` until its full criteria and fresh Nix gate pass.

### 2026-09-29 — A10.3 implemented and release comparisons captured; A10.4 gate next (commit de08a972, aarch64-darwin)

- KEL/TEL wire adapters now borrow parsed controller/witness/backer signature slices via `Cow`; host-asserted constructors still own vectors. Shared verifier resolves both controller keys and TEL backer prefixes by reference, deduplicates code/index/ondex/raw wire material before crypto, and passes an already sorted unique verified-index slice to threshold evaluation. Witness and transferable receipt paths share exact-material dedup and borrow keys; transferable receipts retain their group-wide out-of-range error check. A one-signature stack slot avoids a set allocation until a second distinct signature appears. `Verified::sigs()` now returns unique valid wire signatures, while distinct valid ondices at the same current index remain available to commitment opening. The four red public-path tests and the TEL pointer regression now pass; host retention, KEL witness borrowing, invalid-first/valid-later, out-of-range receipt, and weighted/simple sorted-unique threshold guards pass. Public API and migration details are in both `keri/CHANGELOG.md` and `keri-events/CHANGELOG.md`.
- Pinned keripy oracle `docs/audits/2026-09-29-a10-oracle.py` **executed 4/4 passed** under Python 3.14, pinned keripy `de59bc7d`: 256 exact duplicates verify once; invalid-first/valid-later at index 0 verifies; out-of-range index is skipped; three distinct current-only/dual-ondex encodings at current index 0 remain separate verified signatures. The Rust public tests cover the same behaviors and the conservative distinct-index threshold rule.
- The [before/after report](audits/2026-09-29-a10-baseline.md) records 31/31 **executed release-profile** runs before and after the final implementation (27 analyzed after four warmups), all four paths at 1/16/64/256 duplicates, exact allocation pairs, median and empirical p10/p90 timings. At 256, controller/witness/receipt/backer medians fell from 6,626/6,633/6,619/6,602 µs to 24/30/28/30 µs; allocation calls/bytes fell from 16/6,184, 9/2,120, 2/88, 18/6,272 to 2/48, 1/16, 0/0, 2/48. Parsed KEL `Signed::from` fell from 2/160 to 0/0 allocations. These inputs are identical repeats; all-unique scaling was not measured. One-signature timing differences are inside local noise.
- `cargo test -p keri-codec --test a10_auth_work --test registry_fold -q` **executed** 5/5 plus 39/39 passed (release-only measurement ignored by ordinary tests); `cargo test -p keri-rs --lib -q` **executed** 73/73; `cargo test -p keri-events --features internals --lib -q` **executed** 104/104. `cargo test -p keri-codec --all-features -q`, `cargo test -p keri-rs --all-features -q`, and `cargo test -p keri-events --features internals -q` passed their full suites; the codec run reports one intentionally ignored release benchmark. `cargo clippy -p keri-rs -p keri-events -p keri-codec --all-targets --all-features -- -D warnings` and `git diff --check` passed, with the pre-existing protected `clippy.toml` warning unchanged. A direct `cargo check -p keri-rs --no-default-features --features wire` **failed before the feature repair** because `wire` omitted `alloc` from `keri-codec`/`cesr-stream`; making `wire` include `alloc` fixed that feature graph, and the same exact check **compiled successfully** afterward. Plain no-default-features and explicit `alloc,wire` checks also compiled. The feature change and migration note are in `keri/CHANGELOG.md`.
- **Exact next step: A10.4** run `nix flake check -L` on aarch64-darwin, confirm target/feature and function-ratchet results, record executed/cached/ignored outcomes, then mark A10 `[x]` only if the full gate passes. A11 is next after A10.

### 2026-09-29 — A10.2 red regressions recorded; A10.3 implementation next (commit de08a972, aarch64-darwin)

- Added public-path regressions to `crates/keri-codec/tests/a10_auth_work.rs` and the existing framed TEL integration test. `cargo test -p keri-codec --test a10_auth_work` **executed and failed as expected before implementation**: parsed KEL `Signed` did not share signature storage; 256 identical controller signatures yielded 256 `Verified` entries rather than one; witness and TEL backer duplicate inputs took 9 and 18 allocations respectively, exceeding bounded-work assertions. The companion invalid-first/valid-later and same-current-index/distinct-ondex commitment test passed before the change and must stay green. `cargo test -p keri-codec --test registry_fold framed_backed_tel_chain_uses_historical_receipts -- --exact` **executed and failed as expected** because parsed TEL backer signatures were copied. Transferable receipts additionally have a passing invalid-first/valid-later and out-of-range-after-valid guard. These assertions describe desired behavior; no audit assertion of defective behavior was retained. The release-only before/after harness remains ignored by the ordinary gate but was explicitly executed 31 times for the baseline.
- **Exact next step: A10.3** implement borrowed KEL/TEL transient signatures, exact wire-material dedup before crypto, borrowed key resolution and reused distinct indices; then rerun the red tests. Keep A10 `[-]` until A10.4 comparisons, feature/target checks, full Nix gate, and changelog are complete.

### 2026-09-29 — A10.1 baseline and semantics captured; A10.2 red regressions next (commit de08a972, aarch64-darwin)

- Rechecked P02/P03 against current public code: `Signed::from(&EventMessage)` and `SignedTel::from(&TelMessage)` copy signature vectors; controller, witness and transferable-receipt paths clone key `Matter`s for `verify_indexed`; TEL backer auth additionally converts each `BasicPrefix` to an owned `VerifyingKey`. `Authority::verify` verifies duplicate signatures before sorting/deduping indices, then `SigningThreshold::satisfied_by` sorts/dedupes again. The pinned `verifySigs` reference removes duplicate full signature qb64 values before crypto; invalid and out-of-range signatures are skipped. `Commitment::opened_by` uses both index and ondex, so a pre-crypto dedup key must preserve their meaning.
- The [A10 baseline report](audits/2026-09-29-a10-baseline.md) records 31 **executed release-profile** samples of the original audit P02/P03 fixture and, separately, 31/31 executions of a durable ignored release-only harness at `crates/keri-codec/tests/a10_auth_work.rs` (`cargo test --release -p keri-codec --test a10_auth_work -- --ignored --nocapture`). The temporary copied audit probe was removed afterward. The durable harness covers parsed KEL conversion and public controller, witness, transferable-receipt, and anchored TEL-backer paths at 1/16/64/256 identical valid signatures. After four warmups, 27 timing samples per case show medians at 256 of 6,626/6,633/6,619/6,602 µs respectively; allocations are 16/9/2/18 calls, with exact bytes and p10/p90 in the report. `Signed::from` allocated 2 times/160 bytes. These are pre-change local measurements, not cross-machine promises.
- Semantic inventory checked against code and pinned keripy `verifySigs`: deduplicate **exact wire signature material** before crypto, not just index; invalid-first/valid-later at one index must pass; distinct `ondex` at one current index must remain available for commitment; threshold/TOAD count distinct valid indices; transferable receipt out-of-range is an error even if another signature verifies; host-owned constructors retain their vectors. The current `Siger` equality includes optional attached verfer and is unsuitable for wire-material dedup. Full details and source anchor are in the A10 report. **A10.1 complete. Exact next step: A10.2 red public-path regressions** for the above semantics, transient wire borrowing, and duplicate crypto-work/allocations before A10.3 implementation. A10 remains `[-]`.

### 2026-09-29 — A09 accepted; A10.1 baseline next (commit de08a972, aarch64-darwin)

- A09's actual imported keripy oracle command was `DYLD_LIBRARY_PATH=/nix/store/gd9s5r9njddmad7mf5rqs86xscbq7c2n-libsodium-1.0.20/lib PYTHONPATH=/tmp/cesr-a07-pydeps:/tmp/cesr-a07-keripy-pin/src:/tmp/cesr-a07-keripy-pin:/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages /Users/joel/.local/bin/python3.14 docs/audits/2026-09-29-a09-oracle.py`. It **executed and passed**, comparing six EXN and two ACDC checked-in raw bodies to actual pinned factories/readers, and observing five rejected alternate forms plus reference-only `NaN`/`Infinity`. The separate `--write` invocation generated the corpora initially; the acceptance run omitted `--write` and checked them. The V1 working profile and open A24 decisions are in [the versioned capability matrix](capability-matrix.md).
- Red `cargo test -p keri-codec --test keripy_json_payload --all-features -- --nocapture` failed 0/2 on escaped human text and apply attributes before repair. Later focused red tests showed opaque duplicate keys and a 400-digit integer failing the public signed-interaction path, plus a generic SAD escaped top-level key failing. The final implementation separates fixed CESR-token scans from generic JSON, decodes IPEX text via `Cow<str>` while retaining raw signed bodies, validates nested unique keys with bounded-by-input iterative walks, and keeps opaque anchors' broader RFC escape policy while removing their `f64` magnitude conversion. The public suite checks constructor→serialize→deserialize→typed/framed EXN, ACDC subjects, SAD exact bytes, malformed typed errors, duplicate aliases, 20,000-level nesting, tampered SAIDs and an RFC-valid non-writer exponent spelling signed over its actual bytes. The latter and pinned keripy's non-RFC nonfinite tokens are explicit, executed divergences in the parity ledger. Changelog records the non-const `Ipex*::message()` and removed `OpaqueScanError::NumberOutOfRange` migration.
- `cargo test -p keri-codec --all-features -q` **executed and passed** after the primary repair; the final `cargo test -p keri-codec --no-default-features --test keripy_json_payload --test sad -q` **executed 6/6 and 14/14 passed**; final `cargo clippy -p keri-codec --all-features --all-targets -- -D warnings`, `cargo fmt --all`, and `git diff --check` passed. The existing protected `clippy.toml` warning about the test-only unreachable method remains unchanged. The first Nix gate stopped at a typo in a new test string; after correction a second invocation hit a transient missing `core` target during the WASM build, while isolated `nix build .#checks.aarch64-darwin.cesr-wasm -L` **executed and passed unchanged**. The final `nix flake check -L` **passed** on aarch64-darwin: WASM/no_std compile checks, lint/docs/audit/fuzz-replay checks and **2,514/2,514 executed nextest cases, 0 skipped**. The final invocation rebuilt WASM and nextest; other successful check derivations were reused from earlier invocations. Nix omitted aarch64-linux and both x86_64 systems. A09 acceptance is satisfied.
- **Exact next step: A10.1.** Measure the current public authentication paths before changing ownership/crypto work, and pin duplicate-signature semantics against tests and the selected protocol contract.

### 2026-09-29 — A08 corrected oracle and gate accepted; A09.1 underway (commit de08a972, aarch64-darwin)

- The actual pinned keripy IPEX oracle `docs/audits/2026-09-29-a08-oracle.py` executed 7/7 exact raw-byte comparisons after regeneration. `cargo test -p keri-codec --test keripy_ipex --all-features -q` and `--no-default-features -q` each executed 7/7 passed; `cargo clippy -p keri-codec --all-features --all-targets -- -D warnings` and `git diff --check` passed. The previously recorded reference `pytest tests/vc/test_protocoling.py -q` executed 1/1 passed. `nix flake check -L` **passed** on aarch64-darwin with 12 named checks, including no_std/WASM compile checks, doctests and 2,502/2,502 executed nextest cases (0 skipped); other systems were explicitly omitted by Nix. The seven pinned byte comparisons cover the six public IPEX routes and both grant embed shapes; construction, typed parse and signed frame tests execute in Rust. A08 is now complete against the corrected V1 wire shape, including `e={}` on no-embed routes.
- **Exact next step: A09.1.** Pin canonical JSON/reference behavior and inventory all three scanner paths. Record A24's versioned capability matrix before a profile-dependent grammar choice; then add red public-path regressions.

### 2026-09-29 — A09.1 reference/profile contract done; A09.2 red matrix next (commit de08a972, aarch64-darwin)

- Created [versioned capability matrix](capability-matrix.md) before altering profile-sensitive JSON acceptance. It pins CESR/KERI/ACDC spec Git revisions, keripy `de59bc7d`, RFC 8259, an existing KERI 1.0 JSON/text-attachment working profile, partial/missing paths, owners and open release decisions. It records the conflict between the older parity ledger's “permanent” JSON-only wording and this queue's A24–A29 broader work without treating optional formats as excluded. A24 remains open until every required cell and owner decision has executable evidence.
- Executed `docs/audits/2026-09-29-a09-oracle.py --write` with Python 3.14 and pinned keripy on aarch64-darwin: six canonical EXN bodies passed exact writer/raw-reader comparison (quotes/backslashes, control escapes, raw UTF-8, negative/decimal/exponent numbers, nested containers and an escaped key); four alternate raw forms were rejected (surrogate-pair escape for raw emoji, duplicate nested key, top-level order, whitespace). The script generated `tests/corpus/json_payload/happy.jsonl` from actual `core.eventing.exchange`. A bare Unicode surrogate is not emitted by the reference writer. Pinned keripy accepts Python `NaN` and `Infinity` tokens despite RFC 8259 §6; the Rust profile will deliberately reject them and document an executable divergence. The oracle must be rerun without `--write` after regressions/fixes, so it checks rather than rewrites the corpus.
- Scanner inventory: `codec::scanner::Scanner::string` is a borrowed, escape-free CESR-token scan used for all fixed event/TEL/EXN fields and incorrectly for IPEX human `m`; `integer` is deliberately unsigned for structural threshold fields. Its `canonical_value` uses both for arbitrary nested payloads, rejecting valid reference escapes and signed/decimal/exponent numbers, and does not track nested duplicates. `said::scan_sad` reuses that walk; it checks duplicate top-level raw labels and preserves raw SAID spans but misses nested duplicates. `deserialize::opaque_scan` understands RFC-style escapes/surrogate pairs and number grammar, but accepts duplicate keys and caps numbers by an `f64` finiteness parse, rejecting finite huge integers the reference emits. The generic and fixed-token policies must be separated while signed raw bytes remain the verification input.
- **Exact next step: A09.2** add Rust regressions from the pinned six-body corpus, public constructor→serialize→deserialize→typed/frame paths for escaped `m`, ACDC/apply generic attribute values, malformed escapes/numbers/duplicates, and raw-byte SAID checks. Run them red before implementation.
- A09.2 red evidence: added `tests/keripy_json_payload.rs` with actual pinned six-body corpus through `Exn::deserialize`, exact reserialization, public IPEX agree construction/typed lift and signed framing, plus apply attributes with escaped text and RFC numbers and typed malformed/duplicate rejection. `cargo test -p keri-codec --test keripy_json_payload --all-features -- --nocapture` **failed red 0/2**: generic payload scan rejected the first escape at byte 229; public apply construction rejected the first escape at byte 11. The desired assertions remain in place for the fix.

### 2026-09-29 — A08 reopened on executing-reference `e={}` mismatch (commit de08a972, aarch64-darwin)

- While beginning A09's reference inventory, pinned keripy `core.eventing.exchange` and `tests/vc/test_protocoling.py` showed that V1 `exn` IPEX apply/agree/admit/spurn bodies include an empty `"e":{}` field. The earlier shape-reproduction corpus and our builders omit it. The previous A08 completion claim was premature: the suite executed the constructors against a reproduced shape, while `pytest` ran the reference independently without byte comparison. **A08 is reopened** and A09 is returned to queued state. The exact next step is a red Rust regression against pinned real IPEX constructor bytes, then update builders and corpus/compatibility expectations without erasing the original evidence. Rerun the full gate before marking A08 complete.
- Added `docs/audits/2026-09-29-a08-oracle.py` to reconstruct each checked-in happy body using **actual pinned** `core.eventing.exchange` or `peer.exchanging.specialExchange`. It **failed red** on apply: actual bytes include `e={}` (size `00017d`, SAID `EOfUQ...`), while the old corpus omitted it (size `000176`, SAID `EFqpc...`). Corrected the generator's V1 `SerderKERI` field-domain model, regenerated all seven happy and signed bodies (plus hardening records), and changed the four no-embed builders to use `ExnEmbeds::Empty`. The oracle then **executed 7/7 byte-identical comparisons** across all six routes and both grant shapes. `cargo test -p keri-codec --test keripy_ipex --all-features -q` **executed 7/7 passed** against the corrected corpus. The original PR #295 prose and generator omitted the `SerderKERI` completion of `e`, whereas the pinned implementation and its own `tests/vc/test_protocoling.py` expected bytes include it; the executable reference resolves that conflict.
- The decoder still accepts old EXN bodies with absent `e` as a legacy read form; this is a visible A09 canonical-read decision, not part of the public A08 builder output. **Next:** run Clippy and full Nix gate on the corrected corpus and migration docs; keep A08 incomplete until then.

### 2026-09-29 — A08 accepted; next A09 (commit de08a972, aarch64-darwin)

- The seven-record constructor matrix now exercises all six public `Exn::ipex_*` paths, with full and minimal grants, embedded SAID-verified ACDC, TEL issuance and KEL anchor bodies, empty human text, and both present and absent optional links. Each valid constructed envelope serializes byte-identically to its pinned-shape corpus counterpart, deserializes with a verified outer SAID, lifts through `IpexMessage::parse`, and survives signed `frame_v1` -> `Message::parse`. A separate adversarial case rejected invalid attribute maps and each typed embed before construction. The original placeholder failure and invalid-embed builder acceptance both failed red before their fixes.
- `cargo test -p keri-codec --test keripy_ipex --no-default-features -q` **executed 7/7 passed**; `cargo test -p keri-codec --all-features -q` **executed** 381/381 unit tests, 7/7 IPEX tests, 39/39 registry-fold tests, all other integration suites and 2/7 codec doctests (5 ignored). `cargo clippy -p keri-codec --all-features --all-targets -- -D warnings` and `git diff --check` passed; the pre-existing protected `clippy.toml` warning remains. The pinned keripy `tests/vc/test_protocoling.py -q` **executed 1/1 passed** under Python 3.14, invoking the six reference constructors. The original PR #295 contract was reviewed; its concrete typed route shape requires `acdc` for offer/grant, with grant `iss`/`anc` optional. Broader profile selection remains A24's work, not an implicit A08 exclusion.
- `nix flake check -L > /tmp/cesr-a08-flake.log 2>&1` exited 0 on aarch64-darwin. Release nextest **executed 2,502/2,502 passed, zero skipped**. Fuzz replay and doctests **executed**; no_std and `wasm32-unknown-unknown` **compiled only**, including `keri-rs`'s `wire` direct-mode example. Clippy, fmt, docs, deny, protected function ratchet, version-owner and typos passed; cached versus rebuilt status of individual ancillary checks was not recorded. Nix omitted incompatible systems. Its post-build `audit-tmpdir.sh` emitted a segmentation fault in a pipeline after nextest completed, but the flake command exited 0 and all named checks reported success; retain this as a gate limitation for final review rather than calling it a failed test.
- A08 acceptance is satisfied. **Exact next step: A09**, inventory the three JSON scanners, pin canonical forms against spec and an executing oracle, add failing public-path regressions for ordinary text/attributes while preserving signed bytes, then implement the grammar fix. Establish A24's versioned matrix before adding any profile-dependent forms beyond the currently selected V1 JSON route contract.

### 2026-09-29 — A08 constructor repair in progress (commit de08a972, aarch64-darwin)

- Checked the [merged EXN/IPEX contract](https://github.com/devrandom-labs/cesr/pull/295), local commit `6bd46c4a`, pinned `vc/protocoling.py`, and the A08 audit. The existing typed V1 JSON route contract requires `acdc` for offer/grant and permits optional grant `iss`/`anc`; `grant_minimal` omits both, and links are represented by optional `p`. The generic EXN codec can represent `e={}`, but the typed offer/grant lift requires its credential embed. No broader profile decision was made here; A24 still owns the versioned capability matrix before expanding that profile.
- Added a public constructor regression across all six routes and seven existing pinned-shape corpus records, including a full grant with real SAID-verified ACDC/TEL issuance/KEL anchor embeds and a minimal grant without `iss`/`anc`. It tests builder -> serialize -> deserialize -> typed IPEX parse -> signed `frame_v1` -> `Message::parse`, byte-identical to each corpus body; it also tests empty human messages for every route. **Red executed:** `cargo test -p keri-codec --test keripy_ipex public_ipex_constructors_round_trip_every_route_and_embed_shape -- --exact` failed in `Exn::ipex_apply` with `Deserialize(UnparseablePrimitive { field: "d", source: MalformedCode { part: Head, found: "35" } })` before the fix. Green: the full `keripy_ipex` suite executed 5/5, then 6/6 after embed validation.
- `Exn` now stores a pending digest code for newly built envelopes and a verified SAID for deserialized ones. `Exn::said()` returns `None` until the caller serializes and parses the body; `SerializedExn::said()` returns the computed value. This avoids decoding `#` as a qualified digest or misrepresenting a dummy digest as an authenticated identity. The EXN writer still derives the code from verified wire values and computes the SAID over the exact body. The public migration is in `keri-codec/CHANGELOG.md`.
- **Adversarial red executed:** a public offer builder accepted an invalid `{}` credential embed, yielding a frame its own reader would reject. The builder now validates typed `acdc`, `iss` and `anc` bodies before SAIDifying the embeds map; the same regression verifies rejection for all three labels. The assembled payload map is checked with the existing canonical scanner so caller-supplied apply attributes cannot produce an invalid output silently. `cargo clippy -p keri-codec --all-features --all-targets -- -D warnings` passed with the existing protected `clippy.toml` warning unchanged. Pinned keripy `tests/vc/test_protocoling.py -q` **executed 1/1 passed** under Python 3.14 and the locally archived pin; this test calls all six reference constructors.
- **Remaining:** optional `p` branch checks, all-feature/default/no_std focused test, full `nix flake check`, final A08 API/evidence review. Then mark A08 only if all acceptance criteria pass and continue to A09.

### 2026-09-29 — A07 accepted; next A08 (commit de08a972, aarch64-darwin)

- **Pinned oracle:** `DYLD_LIBRARY_PATH=/nix/store/gd9s5r9njddmad7mf5rqs86xscbq7c2n-libsodium-1.0.20/lib PYTHONPATH=/tmp/cesr-a07-pydeps:/tmp/cesr-a07-keripy-pin/src:/tmp/cesr-a07-keripy-pin:/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages /Users/joel/.local/bin/python3.14 docs/audits/2026-09-29-a07-oracle.py` **executed** against pinned Tevery/Tever and passed. It emitted 14 structured outcome rows: accepted six ilks, delayed KEL anchor, out-of-order `rev` and escrow re-drive, missing backed receipts, historical `ra` after backer rotation, and a terminal wrong-flavor case. The reference's KEL anchor fixture rotates the issuer KEL at each TEL event; Rust additionally executes a real key-state rotation with prior-next opening. Divergences are explicit: supplied contradictory accepted host evidence is terminal instead of indistinguishable from an absent lookup, and historical `ra` is checked by full registry/sn/SAID rather than only the reference's apparent SAID lookup. Both have executed adversarial Rust cases.
- **Rust execution:** `cargo test -p keri-codec --test registry_fold --no-default-features -q` **executed 39/39 passed**; `cargo test -p keri-codec --all-features -q` **executed** 381/381 unit tests, 39/39 registry-fold tests, all other integration suites, 2/7 codec doctests (5 ignored); `cargo test -p keri-rs --all-features -q` **executed** 73/73 unit and 3/3 compile-fail doctests (2 ignored). `cargo clippy -p keri-rs -p keri-codec --all-features --all-targets -- -D warnings` passed with the existing `clippy.toml` unreachable-method warning unchanged. The pinned keripy `tests/vdr/test_eventing.py -q` had previously executed 10/10 passed.
- **Full gate:** `nix flake check -L` exited 0 on aarch64-darwin. Its release nextest stage **executed 2,499/2,499, zero skipped**. Fuzz replay and doctests **executed**; no_std and `wasm32-unknown-unknown` targets, including `keri-rs --features wire` direct-mode example, **compiled** (WASM was not run). Clippy, fmt, docs, deny, protected function ratchet, version-owner, and typos checks passed; individual cached versus rebuilt status was not recorded for those checks. Other systems were omitted by Nix as incompatible with this host. The TEL wire/API changes and migration path are documented in `keri-codec/CHANGELOG.md` and `keri/CHANGELOG.md`. The later edit to two Rustdoc comments did not alter executable code.
- A07 acceptance is satisfied. **Exact next step: A08**, verify all public IPEX constructors against `ipex.rs`, the relevant issue/ADR contract and pinned keripy, then add red regressions for every defective path before fixing them.

### 2026-09-29 — A07.2/A07.3 completed; A07.4 matrix in progress (commit de08a972, aarch64-darwin)

- Framed `-V/-G` TEL traffic now enters `Message::parse` and the public
  `SignedTel::from` adapter for all six ilks. Backed `vcp`/`vrt`/`bis`/`brv`
  also carry genuine `-B` indexed receipts over exact TEL bytes. The
  backerless `vcp -> iss -> rev` and backed `vcp -> vrt -> bis -> brv`
  chains accept with successive exact issuer KEL coordinates, including
  historical `ra` after backer A rotates to B. Removing any accepted KEL
  event yields `Awaiting(KelAnchor)`; wrong issuer, KEL sn/SAID, sole-seal
  contents or cardinality, and wrong `ra` registry/sn/SAID reject terminally.
  Missing issuer and registry state re-drive. `-A` is not required for a
  KEL-anchored TEL body; `-B` is required when the governing TOAD is nonzero.
- Added an executed framed Rust case that first presents a revocation before
  issuance, then re-drives it after issuance and delayed KEL anchor evidence,
  with a real issuer KEL key rotation between registry inception and the
  credential events. The pinned Tevery script now exercises its out-of-order
  escrow and `processEscrows` re-drive, in addition to delayed KEL anchor and
  backed/historical receipt paths. It executed successfully with pinned
  keripy `de59bc7d834955c5b0273c62f6b8b6a0df150dc3` using
  `DYLD_LIBRARY_PATH=/nix/store/gd9s5r9njddmad7mf5rqs86xscbq7c2n-libsodium-1.0.20/lib
  PYTHONPATH=/tmp/cesr-a07-pydeps:/tmp/cesr-a07-keripy-pin/src:/tmp/cesr-a07-keripy-pin:/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages
  /Users/joel/.local/bin/python3.14 docs/audits/2026-09-29-a07-oracle.py`.
  Pinned Tevery's missing-anchor and incomplete-backers exceptions match
  the Rust awaiting classes; Rust distinguishes supplied contradictory
  accepted host evidence as terminal, and checks all three historical `ra`
  coordinates where pinned `getBackerState` appears to use the SAID alone.
  These are deliberate host-evidence hardening differences, with executable
  adversarial cases in `registry_fold.rs`.
- `cargo test -p keri-codec --test registry_fold --no-default-features -q`
  **executed 38/38 passed** before the key-rotation case; the focused new
  key-rotation test then **executed 1/1 passed**. `cargo clippy -p keri-rs -p
  keri-codec --all-features --all-targets -- -D warnings` passed after fixing
  test-only lint errors. The pre-existing unreachable disallowed-method
  warning from protected `clippy.toml` remains unchanged. No A07 Nix gate
  has run yet. **Next:** full post-matrix tests, explicit feature/target
  checks, `nix flake check`, then A07.5 evidence and A08.

### 2026-09-29 — A07.3 historical backer state and `-B` receipts in progress (commit de08a972, aarch64-darwin)

- Added and **executed red** a framed `bis` message from `Message::parse`
  through `SignedTel::from` into `RegistryState::ingest`: a real `-B`
  backer signature with no `-A` controller signature failed as
  `Signatures(MissingSignatures { verified: 0 })`. The fold now verifies
  only `backer_sigs` for backed events; this case passed green. It also
  verifies the *post-rotation* backer set on `vcp`/`vrt`, following pinned
  `Tever.valAnchorBigs`; a test for delayed `vcp` and `vrt` receipts failed
  red then passed after the guard. Incomplete receipts now await distinct
  `EvidenceKind::BackerReceipts` rather than becoming terminal at zero
  verified signatures. A forged/unrecognized receipt remains zero valid,
  and re-drive with the recognized backer succeeds.
- Added and **executed red** a historical `ra` case after `vrt`: the
  pre-fix API lacked `RegistryState::management_evidence` and
  `TelEvidence::BackerAt` (compile failure). The accepted management
  snapshot now retains registry id, sn, SAID, ordered backer set and TOAD.
  `bis` and `brv` resolve against the supplied historical snapshot, check
  its full coordinate, member uniqueness and threshold domain, then verify
  its old backer signatures even after current backers rotate. Supplying
  only current evidence yields `Awaiting(TelAnchor { sn: 0 })`; supplying
  a contradictory later snapshot is terminal `InconsistentManagement`;
  supplying the correct old snapshot accepts both issue and revoke.
- `cargo test -p keri-codec --test registry_fold --no-default-features`
  **executed 34/34 passed** after fixture migration. `cargo test -p
  keri-codec --all-features -q` **executed** all suites successfully
  (381 unit, 34 registry-fold, all other integration suites; 5 ignored
  doctests). `cargo test -p keri-rs --all-features -q` **executed 73/73
  unit and 3/3 compile-fail doctests** (2 ignored). `cargo fmt --all`
  and `git diff --check` passed. No A07 Nix gate yet.
- **Remaining before A07.2/A07.3 acceptance:** frame and fold all six
  ilks through their real source/receipt layouts; test wrong KEL issuer,
  sn, SAID, sole-seal cardinality and historical `ra` sn/SAID/registry
  individually; compare delayed receipt/anchor re-drive with pinned
  Tevery. Review whether host persistence needs an explicitly asserted
  historical-state rehydration API, while keeping source/accepted-state
  provenance explicit. Then A07.4's full end-to-end matrix and A07.5's
  Nix gate remain. Do not mark A07 complete before those checks.

### 2026-09-29 — A07.2 issuer KEL source and evidence taxonomy in progress (commit de08a972, aarch64-darwin)

- Public `TelMessage::parse` now accepts and retains pinned V1 TEL `-V/-G`
  source and `-B` indexed backer receipt groups, including the last `-G`
  couple as keripy's parser does. The `-G` sn is range checked as typed
  `EventMessageError::TelSourceSnOutOfRange`. Optional `wire` adapter lifts
  both groups into `SignedTel`; another codec/storage path can use
  `with_source` and `with_backer_sigs`. The framed regression failed red with
  `UnexpectedGroup(SealSourceCouples)` then passed green, preserving exact
  body, KEL coordinate and backer signature bytes.
- `SignedTel::with_host_accepted_anchor` now carries a host-asserted accepted
  KEL summary. The fold compares its issuer, sn and SAID to the TEL `-G`
  source, then requires its **sole** event seal to name the TEL `(i,s,d)`.
  This guard now runs on all six ilks. KEL anchoring, rather than issuer TEL
  signatures, authorizes the event, as the pinned oracle/spec require.
  `fold_optional` allows retryable missing registry/issuer state;
  `MissingAnchor`, `MissingIssuer`, `MissingRegistry` await their respective
  evidence, while supplied wrong issuer/registry/KEL event yields terminal
  `Inconsistent*`. The wire-to-fold vcp test exercises absent KEL, wrong
  accepted event and exact accepted event with the same parsed bytes.
- Migrated older fold fixtures from the blueprint's unanchored issuer
  signature assumption to explicit accepted KEL seals. Focused
  `cargo test -p keri-codec --test registry_fold --no-default-features`
  **executed 31/31 passed** after a prior 17-failure migration run.
  `cargo test -p keri-codec --all-features -q` **executed** all suites
  successfully (381 unit tests, 31 registry-fold tests, other integration
  suites; 5 existing ignored doctests), and
  `cargo test -p keri-rs --all-features -q` **executed 73/73 unit and 3/3
  compile-fail doctests** (2 other doctests ignored). `cargo fmt --all` and
  `git diff --check` passed. An initial all-features codec run uncovered
  `message_allocation`'s live-byte counter underflow when a thread frees
  pre-counter memory; signed test-only accounting fixed it, and its 5/5
  executed checks and the rerun full codec suite passed.
- A07.2 is **not yet complete**: add framed wire-to-fold cases for the
  remaining TEL ilks, source/issuer mismatch and delayed re-drive there,
  then enforce `-B` receipts and model historical management evidence in
  A07.3. Current backed fold tests still use legacy controller signature
  fixtures; do not claim backed wire acceptance. No A07 Nix gate has run
  yet. Public migration is noted in the crate changelogs; update as the
  backed path settles. **Next exact step:** add a red backed-wire test from
  parsed `-V/-G/-B` into the fold and a red historical `ra` test after
  `vrt`, then design host-supplied historical management evidence and backer
  threshold verification. Keep the A07.2/A07.3 boundary explicit as needed.

### 2026-09-29 — A07.1 pinned TEL semantic matrix underway (commit de08a972, aarch64-darwin)

- Preserved the sibling `/Users/joel/Code/keripy` worktree (its current
  `9161a705` checkout and untracked flake files were not modified). Archived
  the locally available pinned commit
  `de59bc7d834955c5b0273c62f6b8b6a0df150dc3` into
  `/tmp/cesr-a07-keripy-pin`; used Python 3.14.6, reused sibling venv
  packages and installed pytest/PyYAML only in `/tmp/cesr-a07-pydeps`.
  Pinned `tests/vdr/test_eventing.py -q` **executed 10/10 passed** (9.37s;
  one pysodium deprecation warning); the focused Tever/Tevery escrow
  selection **executed 3/3 passed** (5.26s). No reference test was skipped
  in the full run.
- Added `docs/audits/2026-09-29-a07-oracle.py` and **executed** it against
  pinned keripy (exit 0, 12 outcome rows, 2.57s). It sends accepted TEL
  messages through pinned `messagize` (`-V` frame, `-G` KEL source couple,
  then `-B` indexed backer signatures when backed), pinned `Parser`, then
  `Tevery.processEvent`; the `vcp` delayed-anchor case is re-driven through
  `processEscrows`. Direct `Tevery` calls assert rejection classes. Every
  accepted row checks the parsed KEL `(issuer i, sn, SAID)` coordinate and
  backer signature count. `vcp`, `vrt`, `iss`, `rev`, `bis`, `brv` all accepted
  with matching KEL seals. Missing `vcp` KEL event and a wrong `iss` KEL
  SAID yielded `MissingAnchorError`; an anchored backed `vcp` or `bis` with
  no receipt yielded `MissingWitnessSignatureError`. `bis` and `brv` after
  registry rotation accepted the **historical vcp** `ra=(registry,0,vcp SAID)`
  and old backer A signatures, although the current management head uses
  backer B. A simple `iss` under the backed registry produced terminal
  `ValidationError`. Event nonces make exact SAIDs vary per run; outcome/coordinate
  relations and frame groups are asserted by the script.
- Source contract: pinned `Tever.verifyAnchor` resolves the supplied `-G`
  `(sn, SAID)` in the issuer's *accepted KEL* and requires the KEL event's
  sole `a` seal to equal the TEL `(i,s,d)`; `valAnchorBigs` checks this for
  `vcp`/`vrt`/`bis`/`brv`, while `issue`/`revoke` do likewise for `iss`/`rev`.
  `getBackerState` loads historical backers and `bt` by `ra.d`. The official
  [PTEL draft](https://weboftrust.github.io/keridoc/docs/resources/mdfiles/draft-pfeairheller-ptel/)
  likewise describes KEL event seal anchoring and `-G` source attachments;
  TEL event bodies need no issuer signature. Pinned `getBackerState` appears
  to ignore `ra.s` after the digest lookup; the Rust fold should check the
  complete registry coordinate and record this as a justified divergence
  with an executable case.
- Existing Rust `TelMessage::parse` rejects `SealSourceCouples`/`-G` and
  `WitnessIdxSigs`/`-B`; it only retains `-A` controller signatures.
  `RegistryState::incept` admits a signed vcp without anchor, `iss`/`rev`
  authenticate issuer signatures without anchors, `vrt` checks an unproven
  anchor event, and `bis`/`brv` use current backers. `MissingAnchor`,
  `MissingIssuer`, and `MissingRegistry` are terminal even for absent facts.
  These are confirmed defects. Added three regressions in
  `crates/keri-codec/tests/registry_fold.rs` and **executed them red** with
  `cargo test -p keri-codec --test registry_fold --no-default-features`:
  `tel_public_wire_accepts_source_couple_and_backer_receipt` fails at the
  public `Message::parse` with `UnexpectedGroup(SealSourceCouples)`;
  `signed_vcp_without_accepted_kel_anchor_awaits_anchor` and
  `signed_iss_without_accepted_kel_anchor_awaits_anchor` both fail because
  unanchored events are accepted (one unrelated signed-TEL test passed in
  the latter filtered run). The first compile attempt exposed a nonexistent
  `EvidenceKind::KelAnchor`, then the red tests were corrected to compile
  and fail at runtime. **A07.1 complete. Next exact step (A07.2):** define
  the accepted KEL coordinate and source-couple wire model, implement
  issuer anchoring on every ilk, and classify absent versus inconsistent
  issuer/anchor/registry evidence; extend the red cases before each slice.

### 2026-09-29 — A06 input/proof boundary underway (commit de08a972, aarch64-darwin)

- A06.1 verified F05 in current `Signed`/`SignedTel`: each exposed `event`,
  `signed_bytes`, and signature fields independently, and the validating
  folds verified signatures over `signed_bytes` before applying `event`.
  This contradicts the old claim that mismatched bytes necessarily make
  verification fail: a signer of unrelated bytes can still authenticate
  those bytes. The adapter's `EventMessage`/`TelMessage` itself binds its
  parsed body; #128 and the K1 spine require default `keri` to remain sans-IO
  with no `keri-codec` runtime dependency. All external struct-literal
  construction and `Verified` proof consumers were inventoried. A compile-fail
  regression for direct `Signed` assembly failed before the fix under
  `nix develop --command cargo test -p keri-rs --doc` after confirming the
  example compiled normally. A second compile-fail regression showed public
  `Commitment::opened_by` accepted a `Verified` from another message/authority.
- A06.2/A06.3 implementation: `Signed` and `SignedTel` fields are now
  crate-private; wire adapters still pair the parser's event and exact body.
  Alternative codecs and accepted-record rehydration use the explicitly
  named `from_host_asserted_parts` constructors and own the event/body
  assertion; the fold cannot prove a host-loaded record's provenance.
  `Commitment::verify_opening` is the public operation that verifies a
  rotation's signatures and checks their exposure in one call;
  `opened_by` is crate-private. `Verified` remains inspectable but is no
  longer a public transferable opening token. The new accessors expose
  read-only event/body/signature views. Existing corpus and direct-event
  tests were migrated from struct literals to the asserted constructor;
  KEL/TEL wire tests check pointer-identical event/body pairing. The change
  is documented in `keri/CHANGELOG.md`. A10 will address signature-slice
  borrowing; A06 does not change the existing `Vec` ownership.
- Focused KEL/TEL corpus and transition test binaries passed after the
  migration; new parser-bound KEL/TEL adapter assertions passed in
  `nix develop --command cargo test -p keri-codec --test spine --test
  keripy_tel` (9/9 executed, zero ignored). `nix develop --command cargo
  test -p keri-rs --doc` passed three compile-fail boundary regressions;
  two historical doctests remain ignored. Workspace all-target/all-feature
  Clippy with `-D warnings` passed after preserving protected lint policy.
  `nix develop --command cargo tree -p keri-rs --no-default-features -e
  normal` showed no `keri-codec` normal dependency. An initial full
  `nix flake check -L` passed (nextest 2486/2486, zero skipped), but two
  stale comments about default wire-byte handling were corrected after its
  source snapshot. The next full gate on the corrected tree failed before
  tests in the Nix WASM builder with E0463 (`can't find crate for core`,
  reported target missing), cancelling other checks. The pinned Nix dev
  toolchain's sysroot does contain the wasm `libcore`, and
  `nix develop --command cargo build -p cesr-rs --target
  wasm32-unknown-unknown --no-default-features --features
  alloc,core,b64,crypto` passed independently (compile-only). The repeat
  final-tree `nix flake check -L` passed on aarch64-darwin: seven fresh checks
  (nextest 2486/2486 executed, zero skipped; release Clippy all features/all
  targets with warnings denied; doc; doctest; fuzz replay; no_std; WASM)
  plus 13 previously built checks (audit, YAML, nixfmt, KERI boundary,
  typos, deadnix, fmt, shellcheck, version owner, actionlint, deny,
  TOML fmt, function ratchet). no_std and WASM are compile-only, not target
  execution. Incompatible aarch64-linux, x86_64-darwin and x86_64-linux
  systems were omitted. `git diff --check` passed. The E0463 builder
  failure was not reproducible on the repeat; the successful final gate is
  the completion evidence. **A06 accepted. Next: A07**, start with Tevery/
  Tever reference behavior, issuer KEL anchors and escrow taxonomy.

### 2026-09-29 — A05 framing/ownership implementation underway (commit de08a972, aarch64-darwin)

- A05.1 confirmed P01 against the current `CesrGroup::parse` and async codec.
  New public-boundary allocation regressions failed before the fix under
  `nix develop --command cargo test --release -p keri-codec --test
  message_allocation -- --nocapture`: 94,507-byte / 1,024-bare-group input
  requested 49,120,238 bytes; 101,120-byte / 256-framed-message input
  requested 13,662,848 bytes. The latter differs slightly from the audit's
  13,531,776-byte baseline because the public `Message::parse` fixture and
  allocation accounting differ. Both 4× input increases exceeded the
  regression's 6× allocation-growth ceiling (about 15× and 14×).
- A05.2 now uses borrowed `GroupKind::skip` framing to determine one group
  span before copying. `CesrGroup::parse`/`parse_v2` and `Groups<V1/V2>` own
  only consumed group bytes, so retaining one parsed group does not retain
  later groups or messages. All KEL, receipt, TEL and EXN attachment walkers
  already call the common `CesrGroup::parse`; no routing fork was needed.
  The async codec frames element groups before `BytesMut::split_to`, leaving
  a complete buffered tail in place and partial/error bytes untouched.
  Public signatures, counter semantics, exact remainder and signed body
  slices are unchanged. `cesr-stream/CHANGELOG.md` records the ownership
  behavior change.
- A05.3 focused release regressions passed 5/5: bare and framed public
  allocation scaling, retained first group below 1 KiB with 1,024 groups
  present, exact two-group/body remainder plus truncated/malformed input,
  and a concatenated `Message::parse` tail with a truncated second message.
  `nix develop --command cargo test -p cesr-stream --features async --lib`
  passed 360/360 after replacing two old implementation-specific
  shared-allocation expectations with owned-frame byte assertions. Its new
  256-element-group codec regression checks the tail pointer stays at the
  original allocation plus the consumed frame length. These are executed
  native tests, not compile-only checks. First `nix flake check` failed the
  protected free-function ratchet, which counts `pub(crate)` free functions;
  the two helpers are now `CesrGroup` methods and that ratchet passed on the
  second run. The second gate failed release Clippy on a shadowed test
  variable; it is fixed. The third gate passed the policy ratchet, release
  Clippy, fmt, docs, deny, and feature builds, then nextest found two
  historical `cesr-stream/tests/allocation.rs` tests asserting invariant
  allocation *count* under the old shared-buffer ownership contract.
  They are now rewritten to assert linear requested-byte and allocation-count
  growth for V1/V2. `nix develop --command cargo test --release -p
  cesr-stream --test allocation` passed 2/2 executed, zero ignored. The
  fourth `nix flake check -L` passed on aarch64-darwin: 10 fresh checks
  (nextest 2486/2486 executed, zero skipped; Clippy release all features/all
  targets with warnings denied; fmt; doc; doctest; deny; fuzz replay; typos;
  no_std; WASM) and 10 previously built checks (audit, YAML, nixfmt,
  TOML fmt, deadnix, function ratchet, version owner, shellcheck,
  actionlint, KERI boundary). no_std and WASM were compile-only, not
  executed target tests. Incompatible aarch64-linux, x86_64-darwin and
  x86_64-linux systems were omitted. `git diff --check` passed. Public API
  signatures and wire behavior are unchanged; ownership of retained group
  storage now matches a single consumed frame. Failed gates cancelled other
  checks and are not completion evidence. **A05 accepted. Next: A06**,
  start with F05 provenance verification and trust-boundary inventory.

### 2026-09-29 — A04.1 transition prefix implemented (commit de08a972, aarch64-darwin)

- Confirmed F04 in current `KeyState::check_chains_onto`: it checked only
  sequence and prior SAID. The new public-wire regression
  `signed_wrong_identifier_interaction_cannot_advance_state` used B's
  self-addressing prefix, A's prior SAID, A's real Ed25519 signature, and a
  SAID-valid parsed message; it failed before the fix because A advanced.
  Pinned keripy `de59bc7d` `Kever.update` checks `serder.pre` against its
  state prefix before handling `rot`/`drt`/`ixn`.
- Added `StructuralError::IdentifierMismatch` (Terminal via existing
  `Rejection::Structural` disposition) and a prefix check in the common
  `check_chains_onto` path. `rotate` and `interact` now pass their event
  identifier to it, covering ordinary, delegated, and interaction folds.
  Signed-wire wrong-AID `ixn`, `rot`, and `drt` tests pass via
  `nix develop --command cargo test -p keri-codec --test transitions
  signed_wrong_identifier -- --nocapture` (2/2 executed) and the focused
  delegated test (1/1 executed). Full A04 gate has not run.
- Next: A04.2 inspect `judge_same_sn`, delegation contest chain, receipt and
  TEL anchor consumers for prefix/sn/SAID/event-kind/historical-binding
  mistakes. Add failing-before-fix regressions for confirmed gaps. Then
  distinguish same-sn classification from authenticated fork proof (A04.3)
  and complete A04.4 oracle/checks. A04 remains incomplete.
- A04.2 progress: `foreign_identifier_cannot_be_a_same_sn_contest` failed
  before the fix; the judge now returns typed
  `EvidenceError::IncomingIdentifierMismatch` or
  `RecordedIdentifierMismatch`. `recorded_event_at_state_head_must_match_state_said`
  also failed before its fix; a supplied recorded event at the head must match
  both the state's latest SAID and event kind (`RecordedHeadMismatch`). Valid
  basic-prefix same-AID competing inception fixture replaced a formerly
  invalid self-addressing cross-AID fixture; the antisymmetry property now
  allows a typed evidence error when its reverse ordering supplies an invented
  recorded head. `nix develop --command cargo test -p keri-codec --test
  duplicity` passed 28/28 executed, zero ignored.
- A04.2 TEL: `vrt_cannot_use_foreign_kel_anchor_as_issuer_evidence` failed
  before the fix and now passes. `RegistryState::rotate` checks that a
  host-supplied anchoring KEL event names the registry issuer before accepting
  its `(i,s,d)` seal. Existing receipt coordinate checks already compare
  prefix/sn/SAID; `DelegationEvidence::authorizes` already compares the
  delegator state, event prefix, and event seal. Still inspect delegation
  contest-chain ancestry and historical TEL/KEL acceptance limits. A04.3
  remains open, and no full A04 gate has run.
- A04.2 delegation cascade: the nearest delegating-event pair could be from
  a foreign AID while carrying valid-looking seals; its regression failed
  before the fix. The judge now checks pair identity at each level and binds
  level 0 to the delegate's recorded delegator, returning
  `DelegatingIdentifierMismatch { level }`. Rebuilt the positive cascade
  fixtures to use that actual delegator. `cargo test -p keri-codec --test
  duplicity` passed 29/29 after this correction. Higher-level ancestry and
  whether a supplied historical event was truly accepted remain host stream
  claims under the K3/K4 ADR: the pure state lacks the historical KEL to
  independently establish those facts. The owner-visible contract now
  distinguishes these claims from verified signed bytes.
- A04.3: `SameSnVerdict::Duplicitous` is documented as structural conflict
  classification, not authenticated fork proof. The signed-evidence regression
  `unsigned_conflict_classification_is_not_authenticated_fork_proof` shows an
  SAID-valid unsigned candidate can be classified but the validating fold
  rejects it as `MissingSignatures { verified: 0 }`; hosts must authenticate
  against historical authority before durable proof/reporting. No persistent
  proof is produced by this pure module. The existing K3 public verdict shape
  is retained, per its ADR; migration guidance is in `crates/keri/CHANGELOG.md`.
- A04.4: pinned keripy `de59bc7d` `Kever.update` comparison in
  `docs/audits/2026-09-29-a04-oracle.py` executed and rejected SAID-valid
  wrong-prefix `ixn`, `rot`, and `drt` before event-kind handling. `nix develop
  --command cargo fmt --all`, workspace all-target/all-feature Clippy with
  `-D warnings`, and `nix develop --command cargo nextest run -p keri-codec
  -p keri-rs -p keri-events --no-fail-fast` passed (753/753 executed, zero
  skipped). `git diff --check` passed. A later historical-binding change
  required a fresh final gate, recorded below.
- A04.2 historical correction after that gate started: regressions for an
  invented recorded last-establishment SAID and a purported post-establishment
  rotation both failed before implementation. `judge_same_sn` now requires the
  recorded event at `last_est.sn` to match its SAID and expected `icp`/`dip`/
  `rot`/`drt` kind, and requires later recorded events to be `ixn`.
  `EvidenceError::RecordedEstablishmentMismatch` and
  `RecordedPostEstablishmentKind` preserve those causes. The full duplicity
  test binary passed 32/32 executed, zero ignored. Final native aarch64-darwin
  `nix develop --command cargo nextest run -p keri-codec -p keri-rs
  -p keri-events --no-fail-fast` passed 755/755 executed, zero skipped;
  workspace all-target/all-feature Clippy with `-D warnings`, `cargo fmt
  --all`, and `git diff --check` passed. Final `nix flake check` passed all
  12 fresh checks plus 8 cached checks: workspace nextest 2480/2480
  executed, zero skipped; clippy, fmt, doc, doctest, deny, function ratchet,
  fuzz replay, typos and version owner passed. WASM and no_std checks built
  all five crates plus the WASM direct-mode example (compile-only, not
  executed); incompatible aarch64-linux, x86_64-darwin and x86_64-linux
  systems were omitted. No protected lint policy changed.
- Boundary decision: `KeyStateSnapshot::advance` remains the K1 ADR's total,
  crypto-free *trusted replay* of host-accepted events; it is not an
  untrusted-input validating fold. The host owns historical KEL acceptance
  for recorded events older than the state's last-establishment bookmark and
  for supplied TEL/delegation anchor events. The new checks reject all
  mismatches visible from the current state and keep those remaining claims
  explicit; A06 handles the separate signed-event/bytes coupling defect.
  Public API migration is documented in `crates/keri/CHANGELOG.md`.
  **A04 accepted. Next: A05**, start with P01 allocation reproduction on
  `EventMessage::parse` and `Message::parse` before changing group ownership.

### 2026-09-29 — A03 implementation and gate underway (commit de08a972, aarch64-darwin)

- A03.1–A03.3: verified F03 against the current wire parser, direct KEL/TEL
  folds, builders, the KERI backer/witness specification, and pinned keripy
  `de59bc7d`. The duplicate-witness signed-wire regression failed before the
  fix. Shared `keri_events::member_set::MemberSet` now owns static ordered-list
  laws: distinct KEL witnesses and TEL backers, distinct/disjoint deltas, and
  nontransferable KEL witness identity. Transferable TEL non-witness backers
  remain valid per the spec; no controller/witness overlap ban was found.
  Decoder, builder and direct fold invoke this owner. State folds retain
  prior-set membership and ordered post-rotation resolution. KEL rotation now
  rejects zero TOAD for a nonempty resolved set; TEL already had the domain
  check. A01 already covered nontransferable inception with witnesses, so an
  attempted duplicate fix was removed after verification.
- New executed regressions: signed duplicate witness wire and direct fold,
  transferable witness builder/wire/fold, overlapping witness rotation wire,
  nonempty KEL rotation with zero TOAD, valid survivor ordering and receipt
  indices, duplicate TEL vcp backers wire/fold, duplicate vrt cuts wire/fold,
  and vrt zero TOAD against resolved backers. Existing cut membership,
  addition membership, receipt and TEL positive-transition tests remain.
  Fixture corrections switched synthetic KEL witnesses to Ed25519N as the
  spec requires; event/controller keys remain transferable where appropriate.
- `nix develop --command cargo nextest run -p keri-codec -p keri-rs -p
  keri-events --no-fail-fast`: 744/744 executed, zero skipped before the final
  additional TEL threshold regression and the function-ratchet refactor;
  targeted TEL threshold test passed after addition. `nix develop --command
  cargo clippy --workspace --all-targets --all-features -- -D warnings` passed
  after fixing two exhaustive-pattern lints. `nix develop --command cargo fmt
  --all` and `git diff --check` passed. These are native aarch64-darwin
  checks; the first `nix flake check` failed the protected function ratchet
  because `keri-events` allowed zero free public functions. Moved all four
  checks onto `MemberSet` without changing the policy; the full gate is
  rerunning now and must pass before A03 is checked off.
- Executed `docs/audits/2026-09-29-a03-oracle.py` with Python 3.14,
  pinned keripy source and dependencies: 13 invalid KEL/TEL membership/TOAD
  cases rejected and both valid ordered rotations accepted. The oracle
  checks factory semantics; Rust signed-wire/fold tests check the actual
  public path. Public API changes and migration behavior are recorded in all
  three affected crate changelogs. After the `MemberSet` refactor,
  `nix develop --command cargo nextest run -p keri-codec -p keri-rs
  -p keri-events --no-fail-fast` passed 745/745 executed, zero skipped.
  Final `nix flake check` passed all 12 fresh checks plus 8 cached checks:
  workspace nextest 2470/2470 executed, zero skipped; clippy, fmt, doc,
  doctest, cargo-deny, function ratchet, fuzz replay, typos and version owner
  passed. WASM and no_std checks built all five crates (plus WASM direct-mode
  example) but did not execute those targets. Incompatible aarch64-linux,
  x86_64-darwin and x86_64-linux systems were omitted. `git diff --check`
  passed; no protected lint policy changed. **A03 accepted. Next: A04**, first
  verify F04 against current prefix and contest bindings, then add signed
  wrong-AID regressions before implementation.

### 2026-09-29 — A02 accepted; A03 underway (commit de08a972, aarch64-darwin)

- Verified F02 against `KeyState::ingest`, `ingest_delegated`,
  `judge_same_sn`, the K4 delegation ADR, and pinned keripy `de59bc7d`'s
  `Kever.update`/`rotate`. Added a genuine anchored `dip` → signed wire `rot`
  regression that first failed because the ordinary fold advanced the
  delegated state. Added anchored `drt` acceptance and recovery-over-`ixn`
  controls, nondelegated `drt` route checks, and typed recovery errors.
- The ordinary fold now rejects a plain `rot` on delegated state with
  `DelegationError::PlainRotationOnDelegatedState` (Terminal); a `drt` on a
  nondelegated state reports `DelegatorUnknown` (Terminal) from both entries.
  The same-sn judge returns `EvidenceError::IncompatibleEventKind` before
  offering an invalid rotation for recovery. Delegated `ixn` stays accepted.
  Valid `drt` still requires evidence and uses `ingest_delegated` after rewind.
- Corrected older tests that judged `drt` against an ordinary KEL or built a
  delegated snapshot without advancing its `dip`. Preserved the four recovery
  window positions with a signed delegated matrix. The pinned duplicity corpus
  passes. A receipt frame-order test exposed by the full gate searched random
  signature text for `-B`/`-C`; it now compares complete encoded groups.
- Evidence: initial `nix develop --command cargo test -p keri-codec --test
  delegation anchored_dip_rejects_plain_rotation_and_recovery -- --exact`
  failed at "wire rot advanced a delegated state". After the fix, `nix develop
  --command cargo test -p keri-codec --test delegation` ran 15/15;
  `--test duplicity --test delegation --test keripy_duplicity --test
  transitions` ran 93/93 after fixture corrections. `docs/audits/2026-09-29-a02-oracle.py`
  executed pinned keripy's `Kever.update` on a valid `rot` body with a delegated
  state skeleton and observed its `ValidationError` event-kind gate. Full
  pinned keripy integration tests were attempted but could not import
  `yaml` in the existing Python environment; this does not replace the
  executed Rust anchored integration tests. `nix develop --command cargo
  clippy --release --all-features --workspace --all-targets -- --deny warnings`
  passed. `nix flake check` passed on aarch64-darwin: fresh nextest 2,463/2,463
  executed, 0 skipped; WASM and no_std compile-only; fuzz replay, Clippy,
  formatting, docs and other check derivations passed; eight checks were
  matching-output cached. Incompatible Linux/x86_64 systems were omitted.
  `git diff --check` passed. No protected lint policy changed.
- Public API/migration: added `DelegationError::PlainRotationOnDelegatedState`
  and `EvidenceError::IncompatibleEventKind`, documented in
  `crates/keri/CHANGELOG.md`. Callers should route only eligible event kinds
  to recovery; after rewind, submit `drt` with delegation evidence. Signed
  bytes and valid wire formats are unchanged. Security details remain local.
- **Next: A03.** Read F03 and A03 criteria, inspect event/builder/TEL
  witness and backer invariants, reproduce the duplicate-witness public-wire
  attack as an expected-rejection regression before changing validation.
- A03.1 started: `transitions::duplicate_witness_wire_cannot_count_one_witness_twice`
  is an expected-rejection regression adapted from the audit probe. Command
  `nix develop --command cargo test -p keri-codec --test transitions
  duplicate_witness_wire_cannot_count_one_witness_twice -- --exact` failed
  on the unmodified A03 code at the public `EventMessage::parse` assertion,
  confirming the wire defect. Next implement shared static KEL membership
  validation and make both typed decode and direct fold reject it; continue
  through A03.2–A03.4 before marking the task complete.

### 2026-09-29 — A01 accepted; A02 underway (commit de08a972, aarch64-darwin)

- Verified the public-wire misbinding remains in `build_inception` and
  `KeyState::validate_inception`: SAID and controller signatures are checked,
  but a basic prefix is not compared with the sole declared key.
- Pinned keripy `de59bc7d` `SerderKERI._verify` requires every non-digestive
  inception prefix to have exactly one key, signing threshold `1`, and equal
  prefix/key qb64; non-transferable prefixes also forbid non-empty next keys,
  backers, and seals. It requires digestive prefixes for `dip`/`drt`.
- Added `tests/inception_identity.rs`: the initial attack regression failed on
  baseline typed decode, then passed after the fix. It asserts specific typed
  errors at typed decode, `KeriEvent::deserialize`, `EventMessage::parse` and
  direct signed fold, plus basic cardinality/threshold/non-transferable laws,
  digestive `dip`/`drt` and valid basic/self-addressing folding. The event
  model owns the shared inception identity rule; wire and fold both call it.
  Direct `InceptionEvent::new` remains explicitly unchecked, but cannot seed
  a state or pass typed wire decoding with an invalid identity.
- Corrected pre-existing test fixtures that paired unrelated basic prefixes
  and keys or emitted basic delegated events. The allocation fixture now uses
  a valid two-key self-addressing inception; remeasured exact allocations on
  aarch64-darwin: serialization 38, deserialization 41 (previous basic-shape
  fixture 36/35). The delegated rotation builder now rejects a basic prefix.
- Evidence, aarch64-darwin, pinned Rust 1.95.0: initial
  `nix develop --command cargo test -p keri-codec --test inception_identity`
  failed on the baseline at typed decode; after fix 4/4 executed. Focused
  `nix develop --command cargo nextest run -p keri-codec -p keri-rs --no-fail-fast`
  executed 630/630 at the first complete run before the expanded A01 tests.
  `nix develop --command cargo test -p keri-codec --lib keripy_parity::events::`
  executed 2/2 over the 43-event pinned factory corpus; `--test
  keripy_semantics` executed 3/3 signed semantic scenarios. The local Python
  3.14 oracle script `docs/audits/2026-09-29-a01-oracle.py`, run with pinned
  keripy source/dependencies, checked 2 valid controls and 4 SAID-valid
  attacks (unrelated key, two keys, threshold 2, basic `dip`).
- `nix flake check` passed after two failed attempts (first Clippy shadowing,
  then a transient WASM `core` lookup error; direct WASM build succeeded and
  the next gate passed). The passing aarch64-darwin gate freshly built
  `cesr-nextest` (2,457/2,457 executed, 0 skipped) and `cesr-wasm` (compile
  only); the other 18 checks were reused from matching build outputs.
  Incompatible aarch64-linux, x86_64-darwin and x86_64-linux systems were
  omitted by Nix. Default/wire test profiles are covered by nextest's Nix
  matrix; alloc-only/no_std and WASM were compile checks, not execution.
- Public API/migration: new `InceptionIdentityError`,
  `DeserializeError::InceptionIdentity`/`DelegatedPrefixNotDigestive`,
  `BuilderError::DelegatedPrefixNotDigestive`,
  `Rejection::InceptionIdentity` and
  `StructuralError::DelegatedPrefixNotDigestive` are documented in the three
  crate changelogs. Previously accepted malformed events must be rejected
  on ingestion; signed bytes and valid SAIDs are unchanged.
- **Next: A02.** Reproduce plain `rot` on a genuine anchored `dip`; inspect
  `state.rs` and `duplicity.rs` routing, then add failing tests for both
  delegated→plain and nondelegated→`drt` cases before the focused fix.

### 2026-09-29 — Initial foundation audit

- Reviewed the workspace and sibling integration boundary; retained the five-crate
  architecture as the starting point.
- Baseline `nix flake check` passed on aarch64-darwin using cached results.
- Nine standalone observation tests passed; release allocation probes measured
  quadratic copies, signature conversion allocations and repeated verification.
- Confirmed basic-prefix/key misbinding, delegation downgrade, duplicate witness
  counting, wrong-AID transitions, public input-provenance mismatch, IPEX builder
  failure, payload grammar restrictions and binary/incremental parser gaps.
- Source comparison identified TEL authorization/escrow divergence and limited
  oracle provenance. No live Tevery differential was run during this audit.
- Added this queue, detailed audit and reproducible probes. Production Rust,
  manifests, lint policies and runtime dependencies were not changed.
- **Next task: A01.** Original audit tests demonstrate acceptance of invalid
  input; translate the relevant test into an expected rejection before fixing it.

Future session entry template:

```text
Date / commit / task ID:
Changed:
Evidence and validation (commands, target/features, actual outcomes):
API/spec decisions:
Remaining acceptance criteria or blockers:
Next task and exact starting point:
```
