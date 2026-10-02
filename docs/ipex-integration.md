# Selected V1 IPEX host contract

Enable `keri-rs/credential-verification` and parse each exact EXN frame with
`ExnMessage::parse` under explicit `MessageLimits`. Supply a historical,
authenticated KEL `KeyState` for the EXN sender. Start with
`IpexConversation::begin` on a signed `/ipex/apply`; key its owned result by
`root()`, the opening EXN SAID. This first release profile requires an apply
before offer. It accepts the linear route
`apply → offer → agree → grant → admit`, or `spurn` after apply, offer, agree
or grant. Direct offer/grant starts and other route sequences are unsupported.

For every response, fetch the accepted conversation head by the EXN `p`
coordinate and call `ingest_mut` with `IpexEvidence` and `IpexLimits`. The
decision checks the exact outer signed body against the supplied sender KEL
state, alternating applicant/issuer, the prior SAID, and route law. An offer
must carry a schema-valid embedded ACDC issued by the requested issuer to the
applicant, with an `e.acdc` `-L` path carrying one valid `-A` indexed issuer
signature over the exact embedded ACDC bytes. The grant must carry the same
credential SAID and applicant recipient, currently issued registry/TEL state,
the exact accepted issuance TEL head, and an embedded KEL anchor at the
host-accepted historical issuer coordinate. The anchor must contain the sole
seal for that embedded issuance event. A grant needs the same pathed ACDC
proof. Only that one `e.acdc` indexed signature path is accepted for offers
and grants. Pathed `e.iss`/`e.anc` material, other path forms and non-`-A`
proofs have no selected verification semantics and are rejected. Other
routes must have no pathed material.

The host must atomically store the accepted head, its latest EXN SAID and a
replay marker, alongside its application effect. A failed `ingest_mut` does
not change the head. `Disposition::Awaiting` names a missing accepted fact;
load it and retry the same message. A terminal result must not be retried
under different participant or credential evidence. Multiple workers must
compare and swap the same persisted head so only one response to a prior SAID
commits. The host owns KEL/TEL history, schema and chain retrieval, sender
authentication provenance, transport, storage, delivery and notification.
It must recheck credential status when using a previously admitted credential
after a later TEL revocation. A successful IPEX decision establishes this
signed conversation and current credential status at the supplied evidence
snapshot; it is not issuer trust policy or proof of human consent.

The pinned two-party corpus and public test are
`scripts/keripy_ipex_flow_oracle.py` and
`crates/keri-codec/tests/a28_ipex.rs`. They include valid signed issuer and
holder messages and signed SAID-valid substitutions for sender, prior,
credential, recipient and anchor, plus missing or wrong proof signatures.
