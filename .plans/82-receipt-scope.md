# #82 — Message-ilk scope for 1.0: typed Rct in, Qry/Rpy/Exn documented out

Decisions made with Joel (2026-07-31): **separate `Receipt` type** (not a `KeriEvent`
variant) + **`Message` sum parse entry** for mixed streams. Rust-native design; keripy
is the semantics oracle only (pin `de59bc7d`), improved where its behavior is sloppy.

## Oracle facts (keripy @ de59bc7d)

- `receipt()` `eventing.py:957`: body fields **`v,t,d,i,s`** — `d` = SAID of the
  *receipted* event (not self-SAID), `i` = receipted KEL's prefix, `s` = hex sn, no
  leading zeros. JSON, size-patched version string; **no SAID splice** (`d` given).
- Dead check: comment "sn must be >= 1" but code tests `< 0` — inceptions (sn 0) are
  receiptable and witnesses receipt them. We accept sn 0; no dead check replicated.
- Parser rct branch `parsing.py:1434`: attachments accepted = **cigars** (`-C`
  NonTransReceiptCouples), **wigers** (`-B` WitnessIdxSigs), **tsgs** (`-F`
  TransIdxSigGroups: (pre, sn, said) + nested `-A`). **≥1 required** else
  ValidationError. `-D` TransReceiptQuadruples are an *event-replay* attachment,
  not an rct attachment — out of scope here.
- `processReceipt` `eventing.py:4481+`: silently *skips* transferable prefixes in
  couples. **Divergence (improvement):** our parser rejects a transferable prefix in a
  `-C` couple as a typed error — a couple's prefix IS the verification key; a
  transferable one is unverifiable nonsense. keripy-generated valid streams unaffected.

## Scope decision (the issue's ask)

- **Rct: IN** — typed `Receipt` + codec + differential vectors (this plan).
- **Qry / Rpy / Exn: OUT for 1.0** — routing/protocol messages, the layer above.
  Recorded in `MessageType` rustdoc per variant ("typed support: here / layer above"),
  still rejected by `from_code`. No silent stubs.

## Design

### keri-events (ratchet: 0 free fns — methods only)

- `MessageType::Rct` — `code() = "rct"`, `from_code` accepts, `is_establishment() =
  false`. Rustdoc scope table on the enum; dead-codes test drops `rct`, keeps
  `qry/rpy/exn`.
- `src/receipt.rs`: `Receipt<'a> { prefix: Identifier<'a>, sn: Number, said: Said<'a> }`
  — the coordinate of the receipted event. **Public `new`** (no self-SAID to forge —
  unlike events, no `internals` gate needed), accessors, `into_static`,
  `const MESSAGE_TYPE: MessageType = MessageType::Rct`. NOT in `KeriEvent`.

### cesr-stream (ratchet: 0 — methods only)

Write-side constructors (read side already typed):
- `NonTransReceiptCouples::from_couples(&[(Prefixer, Cigar)])`
- `TransIdxSigGroups::from_groups(...)` (elements carry nested `ControllerIdxSigs`)
Mirror `from_indexed_signatures` shape: encode elements → `Self::new(raw, count, V1)`.

### keri-codec write path (ratchet: 32/32 full — methods only)

- Render rct body `v,t,d,i,s` via existing `write_head`/`JsonWriter` machinery;
  size backpatch only, **no SAID computation/splice**.
- Inherent `Receipt::serialize(&self) -> Result<SerializedReceipt, CodecError>` — NOT
  the `Serialize` trait (its `SerializedEvent` contract means "self-SAID computed";
  receipt has none — honest types over trait uniformity).
- `SerializedReceipt { raw, size }` + `frame_v1(couples, wigs, trans_groups)` mirroring
  `SerializedEvent::frame_v1`: `-V` quadlet counter, groups in keripy messagize order,
  empty groups omitted, **all-empty → typed error** (`MissingEndorsement`-style, the
  ≥1 rule at write time too).

### keri-codec read path

- `ParsedRct` strict view (head + `t == "rct"` + fields `d,i,s`, no trailing).
- New top-level sum:
  ```rust
  pub enum Message<'a> { Event(EventMessage<'a>), Receipt(ReceiptMessage<'a>) }
  impl<'a> Message<'a> { pub fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), ...> }
  ```
  Dispatch on parsed `t`; `EventMessage::parse` unchanged for KEL-only callers.
- `ReceiptMessage<'a>`:
  ```rust
  pub struct ReceiptMessage<'a> {
      receipt: Receipt<'a>, body: &'a [u8],
      couples: Vec<ReceiptCouple<'a>>,      // { receiptor: BasicPrefix, signature: Cigar }
      wigs: Vec<Siger<'a>>,
      trans_receipts: Vec<TransferableReceipt<'a>>,
      // { receiptor: Identifier, sn: Number, said: Said, signatures: Vec<Siger> }
  }
  ```
  Named structs over tuples; attachment lifts via existing `Field`/`FromWire` layer.
  **≥1 attachment group enforced at parse** (oracle `parsing.py:1434`), typed error.
- `KeriEvent`/`EventMessage` parse on an rct body → distinct typed error
  (`NotKeyEvent`-style variant, not `UnknownMessageType`).

## Tests

1. **Round-trip**: `Receipt::serialize` → `Message::parse` → re-serialize
   byte-identical; framed with each attachment combination.
2. **Defensive**: truncated body/attachments, zero attachment groups, transferable
   prefix in couple (typed reject — divergence probe), bad hex `s`, wrong `t`,
   rct through `EventMessage::parse` (typed `NotKeyEvent`).
3. **Proptest**: sn ∈ {0, 1, arbitrary, MAX-1, MAX}; prefix both derivations;
   round-trip stability.
4. **Differential (keripy)**: new `scripts/keripy_receipts_gen.py` → 
   `crates/keri-codec/tests/corpus/keripy/parity/receipts.jsonl`
   (receipt bodies byte-compare) + framed streams (messagize with cigars / wigers /
   tsgs / combinations) parsed end-to-end. Harness module `keripy_parity/receipts.rs`
   (name contains `keripy` → nightly filter). Add generator line to
   `.github/workflows/keripy-diff.yml`.
5. Mixed-stream test: icp + rct interleaved through `Message::parse`.
6. no_std + wasm: via `nix flake check` (the only gate).

## Breaking changes (call out in PR + CHANGELOG)

- `MessageType` gains `Rct` (exhaustive matches downstream break).
- New public types: `Receipt` (keri-events); `Message`, `ReceiptMessage`,
  `ReceiptCouple`, `TransferableReceipt`, `SerializedReceipt` (keri-codec);
  new error variants.

## Issue closure

`rct` typed IN with byte-for-byte keripy vectors; `qry/rpy/exn` documented OUT on the
enum; every ilk code has a stated home. Unblocks K5 (#91).
