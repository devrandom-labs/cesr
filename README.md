# cesr workspace

Current foundation review: [audit and evidence](docs/audits/2026-09-29-foundation.md).
Implementation priorities and session restart guide: [work queue](docs/TODO.md).
Supported and open protocol profiles: [capability matrix](docs/capability-matrix.md).

A five-crate Cargo workspace providing CESR (Composable Event Streaming
Representation) and KERI (Key Event Receipt Infrastructure) primitives. Every
crate supports `no_std` with allocation and compiles for
`wasm32-unknown-unknown` under the documented feature profiles. The
[isolated feature matrix](docs/audits/2026-09-30-a17-matrix.md) records which
profiles are compile-only versus exercised at runtime.

| Crate | Import as | Contents |
|-------|-----------|----------|
| [`cesr-rs`](crates/cesr) | `cesr` | the CESR primitive substrate: alphabet, code tables, version grammar, key math (`b64` + `core` + `crypto`) |
| [`cesr-stream`](crates/cesr-stream) | `cesr_stream` | stream framing: counters, text groups, cold-start detection and qb2 conversion; typed binary messages remain open |
| [`keri-events`](crates/keri-events) | `keri_events` | the KERI vocabulary: events, seals, thresholds, identifiers (pure data, no serialization) |
| [`keri-codec`](crates/keri-codec) | `keri_codec` | events ↔ canonical JSON with SAID; the read/write spine `EventMessage::parse` / `frame_v1` |
| [`keri-rs`](crates/keri) | `keri` | the sans-io KERI core: key-state fold, escrow dispositions, delegation, duplicity, custody |

The crates version independently and remain pre-1.0, with intentional public
API changes recorded in their changelogs. All are gated by `nix flake check`.

## KERI without a database

`keri-rs` is a pure sans-io core: it stores nothing, looks nothing up, and
does no I/O. The supported KEL validation, escrow judgment, delegation,
duplicity and custody paths are functions over values the caller supplies. The example
[`crates/keri/examples/direct_mode.rs`](crates/keri/examples/direct_mode.rs)
shows a selected direct-mode KEL flow: two in-memory parties exchange framed
wire bytes and assert the verdicts in that flow:

1. **Inception** — self-addressing AIDs; the K1 fold (`KeyState::incept`)
   seeds key state straight off the wire.
2. **Exchange** — direct mode needs zero witnesses; each side's view of the
   other is just a folded transcript.
3. **Rotation** — pre-rotation opens the prior next-key commitment; the old
   keys stop verifying (the stale-key wedge).
4. **Delegation** — Alice delegates an Agent AID; the dip is accepted only
   against the anchoring seal already folded into Alice's KEL (K4).
5. **Signing** — the Agent signs an application message; Bob verifies it
   against the folded authority alone.
6. **Abandonment** — rotating with an empty next-key commitment closes further
   KEL rotation. The example rejects signatures from old keys against the
   *current* authority and its custodian refuses to rotate again. Historical
   signatures still have cryptographic meaning; a host decides whether an
   application action is authorized under its chosen time and state policy.
7. **Detours** — out-of-order delivery classifies as escrow dispositions
   (awaiting prior events vs. contested, K2); a forged fork at an occupied
   sequence number judges as duplicity (K3).

Run it with:

```text
cargo run -p keri-rs --example direct_mode --features wire
```

CI compiles this example for `wasm32-unknown-unknown` — the protocol core
runs anywhere Rust does, with no database, runtime, or OS services.

Licensed under MIT OR Apache-2.0.
