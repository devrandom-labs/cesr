# K7 · Custody: `Custodian` trait + Salty derivation (#93)

**Date:** 2026-07-31
**Issue:** #93 (K7 — milestone "KERI · sans-io core")
**Status:** Approved by Joel (sections 1–2, this session)

## Goal

Key custody with keripy/signify-compatible derivation, split across the layer
boundary: the pure argon2id stretch primitive in `cesr::crypto`, the custody
trait and its deterministic reference impl in `keri-rs`. Hardware backends
(Secure Enclave, Android Keystore, HSM) plug in above via the trait; they are
bombay M4 scope, not this repo.

## Scope decision

**SaltyCustodian only.** `RandyCustodian` (random keys, x25519-wrapped params)
is blocked on #84 (x25519 + sealed box) and is deferred with a tracker card.
Encrypted-salt export (signify `sxlt`-style params) is likewise #84-blocked and
deferred with a card.

## Fact corrections vs issue text

The issue body claims keripy path format `"{pidx:x}.{ridx:x}.{kidx:x}"`.
Current keripy source (v2.0.0.dev5-1245-g9161a705, `app/keeping.py:542-544`)
disagrees:

```python
stem = self.stem if self.stem else "{:x}".format(pidx)  # if not stem use pidx
path = "{}{:x}{:x}".format(stem, ridx, kidx + i)
```

No dots. signify-ts (`core/manager.ts`) builds the same shape with stem
`"signify:aid"` (`core/keeping.ts:312`). This design follows source;
differential vectors are the referee.

## Part 1 — `cesr::crypto::salt` (pure substrate)

New module behind the existing `crypto` feature.

### `Salt`

- Wraps 16 raw bytes (Matter code `0A` / Salt128); secret bytes in
  `Zeroizing` per house convention.
- Constructors: `generate()` (OS RNG; gated like `KeyPair::generate`),
  from raw bytes, from qb64.

### `Tier` + stretch

`Tier { Low, Med, High }` maps to libsodium-exact argon2id13 parameters,
parallelism p=1 (libsodium fixes lanes=1):

| Tier | t_cost (opslimit) | m_cost (memlimit) |
|------|-------------------|--------------------|
| Low  | 2 | 64 MiB (65536 KiB) |
| Med  | 3 | 256 MiB (262144 KiB) |
| High | 4 | 1 GiB (1048576 KiB) |
| temp (test-only) | 1 | 8 KiB |

- `stretch(path, tier) -> Zeroizing<[u8; 32]>` via RustCrypto `argon2`
  (no_std + alloc; verified in the flake matrix). Path bytes are the argon2
  password; the 16 salt bytes are the argon2 salt. Byte-identical to keripy
  `Salter.stretch` (`core/signing.py:418-455`).
- `signer(path, tier, transferable) -> KeyPair<Ed25519>` — seed from stretch,
  reuses the existing `KeyPair` from-seed constructor.
- keripy's `temp=True` params (t=1, m=8 KiB) exposed **only** behind the
  `test-utils` feature — differential vectors need it; production never sees it.

## Part 2 — `keri-rs::custody`

New module `custody.rs` in `crates/keri`. cesr's `crypto` feature is already a
keri-rs dependency.

### `Custodian` trait (object-safe)

```rust
pub trait Custodian {
    type Error;
    fn incept(&mut self, spec: KeySpec) -> Result<KeyCommitment, Self::Error>;
    fn rotate(&mut self, spec: KeySpec) -> Result<KeyCommitment, Self::Error>;
    fn sign(&self, ser: &[u8], indices: Option<&[u32]>) -> Result<Vec<Siger<'static>>, Self::Error>;
}
```

`Siger<'static>` is cesr's existing indexed-signature type (what
`KeyPair::sign_indexed` returns today); it gets renamed under #193, not here.

- `KeySpec { count, ncount, transferable }` — struct argument, not bare
  `usize` twins (kills positional-swap bugs).
- `KeyCommitment { verkeys: Vec<VerifyingKey>, next_digests: Vec<Digest> }` —
  keri-events newtypes; exactly what the keri-codec `incept()`/`rotate()`
  builders consume.
- **No `params()` on the trait.** Custody-state persistence is per-impl
  (hardware backends have no serializable state). Each impl exposes an
  inherent `params()`. Trait stays minimal and object-safe.

Naming: "Keeper" is keripy's noun; trait is named for the domain (key
custody). Methods keep KERI spec verbs (incept/rotate/sign).

### `SaltyCustodian` (deterministic; phone/IoT default)

- State: `Salt` + `Tier` + path convention + `(pidx, ridx, kidx)` counters +
  transferability.
- `PathConvention { Keripy, Signify, Custom(String) }` — Keripy stem =
  `hex(pidx)`, Signify stem = `"signify:aid"`.
- `incept`: current keys derived at `(ridx, kidx)`; next keys at
  `(ridx+1, kidx+count)` — keripy `keeping.py:1019-1030` semantics.
  Next-key digests = Blake3-256 over verkey qb64 (existing cesr digest path).
- `rotate`: promote next indices, derive the new next set, same offset rule.
- `params() -> SaltyParams { stem, tier, pidx, ridx, kidx, transferable }` —
  **no salt material**. Caller re-supplies the salt/passcode at
  reconstruction (signify bran model). Documented loudly: params exist for
  LOCAL persistence; transmitting them is the key-light trade-off, never the
  default.

## Deferred → tracker cards

1. `RandyCustodian` — blocked on #84 (x25519 wrap for key export).
2. Encrypted-salt export (`sxlt`-style params) — blocked on #84 (sealed box).
3. miri zeroize scope note: miri runs the drop/zeroize path with temp-tier
   argon2 only; full-tier argon2 under miri is impractically slow.

## Testing

- **Differential vectors** generated from the local keripy checkout (python3.14
  env per house memory) for both path conventions — signify's stretch is the
  same libsodium `crypto_pwhash` call; the path string is the only delta.
  Same passcode → same derived verkeys, byte-identical qb64.
- **Round-trip / sequence**: full icp→rot chain driven through
  `SaltyCustodian` into keri-codec builders; re-derivation from `params()` +
  salt reproduces identical keys.
- **Defensive boundaries**: bad salt lengths, invalid qb64, count/ncount
  zero-and-max, index-out-of-range in `sign`.
- **Proptest**: counters and counts at 0 / 1 / MAX-1 / MAX; path strings
  empty / long.
- **Zeroize**: miri-checked drop of `Salt` and stretched seeds (temp tier).
- no_std + wasm32 stay green via `nix flake check`.
