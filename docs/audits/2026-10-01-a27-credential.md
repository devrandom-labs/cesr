# A27 credential verification contract and evidence

Baseline: `de08a972` plus accepted A01–A26 worktree. A24 selects ACDC V1
JSON, Ed25519/BLAKE3 and a Selo client/agent route. ACDC V2, selective
disclosure and Signify/KERIA interoperability are later profiles.

## Pinned source and trust meaning

Pinned keripy `de59bc7d834955c5b0273c62f6b8b6a0df150dc3`
`vdr/verifying.py:Verifier.processCredential` requires registry and credential
TEL state, resolves the schema, checks Draft 7, and walks edges.
`core/scheming.py:JSONSchema.load` verifies schema `$id` SAID. The pinned
`verifyChain` executes `I2I` and `NI2I`, but raises `NotImplementedError`
for `DI2I`. The executable oracle runs that method with a minimal
accepted-state adapter and asserts all four outcomes, including wrong I2I
issuer. Keripy stores a revoked credential while logging revocation; the
Rust result is explicitly **currently valid** and rejects revoked root or
chain nodes. This is an intentional trust-meaning difference.

`scripts/keripy_credential_oracle.py` generates the checked-in
`crates/keri-codec/tests/corpus/credential/v1.jsonl` from the exact pin.
It executes `Schemer.verify`, `SerderACDC`, V1 KEL `incept`, TEL `vcp`,
`iss`, `rev`, and `Verifier.verifyChain`. The Rust test separately folds a
transferable issuer and holder KEL, anchors both registries and issuance
TEL events, verifies the holder's issuee field, then folds a revocation.
The adversarial bodies retain valid ACDC SAIDs: wrong Draft 7 type,
unrelated issuer, unrelated registry, wrong I2I issuee, unsupported DI2I,
nonempty rule, and aggregate/referenced attributes.

The result of `CredentialVerifier::verify` means: **the exact canonical V1
ACDC body fits a host-supplied, SAID-verified Draft 7 schema; its issuer,
registry and credential SAID match host-accepted KEL/TEL states; the current
credential TEL head is issued; and every selected chain node satisfies the
same checks and its I2I/NI2I edge relationship**. The host must obtain those
states from authenticated folds and commit them with exact event/body
provenance. The pure verifier does not query a network, run a database,
assess clock freshness or establish holder consent/possession.

## Selected forms and bounded failure semantics

- Schema bytes must be canonical, have a valid `$id` SAID and Draft 7 marker,
  and compile without a `$ref`. `jsonschema` is pinned at 0.49.7 with its
  default HTTP/file resolver features disabled. `$ref` is rejected before
  compilation. Schemas and credential bodies have a 1 MiB hard ceiling and
  JSON depth cannot exceed 128, in addition to caller field/depth limits.
- The `s` and `ri` references must be SAIDs. Attributes `a` must be inline.
  Aggregate `A` and referenced `a` return `UnsupportedDisclosure` before
  JSON Schema validation. The optional `u` nonce remains a body field; it
  does not imply path-signature or selective-disclosure support.
- `e` is an inline map with `d:""` and named `{n:<SAID>,o?:<operator>}`
  nodes. `I2I` binds the current issuer to the chain node's `a.i`; `NI2I`
  permits an independently issued node. An absent operator follows pinned
  keripy's issuee-sensitive default. `DI2I`, top-level `e.o`, referenced
  edge maps and other node shapes fail explicitly. Nonempty `r` and
  referenced rules are unsupported: human rules have no machine acceptance
  semantics in the selected foundation. Empty `r:{}` is accepted.
- The host supplies chain nodes under requested SAIDs. A missing node or
  schema is awaiting evidence. A supplied wrong body, unrelated state,
  revoked node, invalid operator, duplicate claim or unsupported form is
  terminal. `CredentialVerificationLimits` bounds each body, the number of
  supplied/visited nodes and depth; hard ceilings are 1 MiB, 1024 nodes and
  64 edges. An active-path SAID revisit is terminal `Cycle`. A canonical
  valid-SAID cycle would require a cryptographic fixed point or collision;
  the guard is unit-tested by seeding the active path.

The schema and status judgments remain separate APIs. `VerifiedSchema`
validates exact bytes and returns the parsed body; the no-std
`CredentialVerifier::status` binds an already parsed ACDC to accepted
states. The opt-in `credential-verification` adapter composes both and walks chains. A caller
must not treat `Acdc::deserialize` or a content SAID as a credential
validity decision.

## Gate record

Environment: aarch64-darwin, Nix development shell, Python 3.14.6 pinned
keripy checkout. The oracle reproduced its checked-in corpus. The focused
`a27_credential` suite and private active-path cycle unit passed;
`cargo clippy -p keri-codec -p keri-rs --all-targets --all-features -- -D warnings`
passed after fixes. Separate `keri-rs` alloc-only no-std and
`wasm32-unknown-unknown` `credential-verification` checks passed. The indexed
`nix flake check -L --option max-jobs 1` exited 0 on aarch64-darwin with
**2,587/2,587 release tests passed**, 24 skipped. All 19 isolated host and
WASM feature profiles, no-std, Clippy, formatting, docs/doctests, examples,
fuzz replay, audit, deny, typo, free-function ratchet, version-owner and
boundary checks passed. Incompatible aarch64-linux, x86_64-darwin and
x86_64-linux checks were omitted by Nix. `git diff --check` and
`git diff --cached --check` passed. `fuzz/Cargo.lock` was updated for the
independent fuzz workspace; `MIT-0` was added to `deny.toml` for the
new permissive `borrow-or-share` transitive dependency. The initial gate
failures exposed those integration requirements and a default-core codec
resolution regression; the dedicated `credential-verification` feature
restored the codec-free default, with matrix evidence.
