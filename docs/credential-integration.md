# V1 credential verification host contract

The selected A27 path accepts ACDC 1.0 JSON, a SAID-verified Draft 7 schema,
host-accepted issuer KEL and registry/credential TEL states, and optional
host-resolved chain nodes. The entry point is
`keri::CredentialVerifier::verify` with the `credential-verification` feature; the
no-std `CredentialVerifier::status` is the smaller issuer/TEL binding
decision. `Acdc::deserialize` and its SAID check do not assert validity.

For each credential, the host must:

1. Retain the exact ACDC body bytes and resolve its `s` schema SAID to
   exact schema bytes. Build `VerifiedSchema::from_bytes` with a JSON budget.
   Its local Draft 7 profile rejects `$ref` and never fetches a URL.
2. Resolve `ri` to an accepted `RegistryState`, the ACDC `d` to an accepted
   `CredentialState`, and `i` to a KEL state obtained by authenticated fold.
   The TEL fold must have validated the issuance/revocation event's accepted
   historical KEL anchor. Persist that acceptance with the event/body
   coordinates; rehydrating an arbitrary object under the same key is not
   evidence. A revoked head is a terminal invalid-current-status verdict.
3. Supply each `e.*.n` chain credential under its requested SAID with its
   own schema and accepted states. The verifier checks every supplied body
   against its lookup key and walks selected I2I/NI2I edges transitively.
   Use `CredentialVerificationLimits` for body bytes, nodes, depth and JSON
   work. Missing schema, registry, TEL, issuer or chain evidence returns
   `Disposition::Awaiting`; schedule retrieval/retry outside the core.
4. Commit any application decision against the same accepted evidence
   snapshot used for verification. A later revocation requires rechecking
   current validity. The host owns cache freshness, schema/credential
   retrieval, trust policy for issuers, storage, transport and retry clocks.

The selected verifier accepts inline attributes and empty or absent rules.
Aggregate or referenced attributes, selective disclosure, path signatures,
referenced schema/edge/rule blocks, nonempty human rules and DI2I edges
produce explicit unsupported errors. The result does not establish holder
consent, possession of an AID key, privacy, or a business policy decision.
IPEX conversation and attachment authorization is the separate A28 track.
