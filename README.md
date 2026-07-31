# cesr workspace

A five-crate Cargo workspace providing CESR (Composable Event Streaming
Representation) and KERI (Key Event Receipt Infrastructure) primitives. Every
crate is no_std/WASM-capable: each compiles for `wasm32-unknown-unknown`, and
for bare-metal no_std targets with the right features.

| Crate | Import as | Contents |
|-------|-----------|----------|
| [`cesr-rs`](crates/cesr) | `cesr` | the CESR primitive substrate: alphabet, code tables, version grammar, key math (`b64` + `core` + `crypto`) |
| [`cesr-stream`](crates/cesr-stream) | `cesr_stream` | stream framing: counters, groups, cold-start detection, text/binary stream parsing |
| [`keri-events`](crates/keri-events) | `keri_events` | the KERI vocabulary: events, seals, thresholds, identifiers (pure data, no serialization) |
| [`keri-codec`](crates/keri-codec) | `keri_codec` | events ↔ canonical JSON with SAID; the read/write spine `EventMessage::parse` / `frame_v1` |
| [`keri-rs`](crates/keri) | `keri` | the sans-io KERI core: key-state fold, escrow dispositions, delegation, duplicity, custody |

The crates version independently: `cesr-rs` holds a stable surface while the
KERI crates iterate. All are gated by a single `nix flake check`.

## KERI without a database

`keri-rs` is a pure sans-io core: it stores nothing, looks nothing up, and
does no I/O. Everything the KERI protocol needs — validation, escrow
judgment, delegation, duplicity detection, custody — is a function over
values the caller supplies. The flagship example
[`crates/keri/examples/direct_mode.rs`](crates/keri/examples/direct_mode.rs)
proves it: two in-memory parties run the full protocol exchanging nothing but
framed wire bytes, asserting every protocol verdict along the way:

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
6. **Revocation** — rotating with an empty next-key commitment abandons the
   delegated AID: its old signatures verify against nothing, its KEL admits
   no more events, and custody refuses to rotate — the wedge is pure
   verification, no revocation registry.
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
