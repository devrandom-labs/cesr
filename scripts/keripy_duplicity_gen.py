#!/usr/bin/env python3
"""Generate the keripy duplicity differential vectors (JSONL) for the K3 judge.

keripy is the oracle. Each scenario folds a base KEL through a real
``keri.core.eventing.Kevery.processEvent``, then feeds a CONTEST event at an
already-occupied sn and records keripy's own verdict:

  * ``supersedes``   — keripy accepted the contest (its head moved to it).
  * ``duplicate``    — same SAID as recorded; idempotent log, head unmoved.
  * ``duplicitous``  — keripy raised ``LikelyDuplicitousError`` (`.ldes`).
  * ``yields``       — drt-over-drt cascade loss (B2): keripy raised a bare
                       ``ValidationError`` (eventing.py:3467-3475 at the pin);
                       translated from ``error:ValidationError`` for the
                       delegated scenarios only.

One JSONL record per scenario:
``{"name", "events": [b64…], "sigs": [[qb64…]…],
   "contest": {"raw": b64, "sigs": [qb64…]}, "expected": …}`` — delegated
scenarios additionally carry ``"chain": [{"incumbent": b64,
"challenger": b64}]``, the delegating-event pair(s) for the cascade.

Gate scenarios (1-5) anchor keripy eventing.py:4396-4478 (pin below);
cascade scenarios (6-7) port the db-level construction of keripy's own
``tests/core/test_delegating.py::test_delegation_supersede`` (no Habery) and
anchor ``Kever.validateDelegation`` (eventing.py:3413-3492).

Deterministic: fixed salt, no wall-clock, no OS randomness. DO NOT check in a
corpus whose ``expected`` is ``error:*`` — that means the scenario
construction is wrong; fix the script.

Pin: keripy v2.0.0.dev5-1030-gde59bc7d (oracle main 9161a705), KERI/CESR V1
JSON (``KERI10JSON``).
"""
import argparse
import base64
import json
import sys
from pathlib import Path

KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"

# Deterministic signers: fixed 16-byte salt -> Ed25519 key sequence.
SALT = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"


def b64(raw):
    return base64.standard_b64encode(raw).decode("ascii")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is prepended "
                         "to sys.path); omit if keripy is already importable")
    ap.add_argument("--out", required=True, type=Path, help="output JSONL file")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    from keri.core.coring import Diger, Kinds, Number
    from keri.core.eventing import Kevery, delcept, deltate, incept, interact, rotate
    from keri.core.signing import Salter
    from keri.core.structing import SealEvent
    from keri.db.basing import openDB
    from keri.kering import LikelyDuplicitousError, Vrsn_1_0

    def stub_ld_escrow(kvy):
        """keripy bug at the pin: ``escrowLDEvent`` calls ``db.addLde``, which
        ``Baser`` no longer has (eventing.py:5868), crashing BEFORE the
        ``LikelyDuplicitousError`` raise at eventing.py:4475-4478. Stub the
        broken escrow write — the classification raise (our oracle signal)
        is unaffected."""
        kvy.escrowLDEvent = lambda **kwa: None

    def outcome(kvy, serder, sigers, delsner=None, delsger=None, delegated=False):
        """Feed one contest event; classify keripy's reaction as a verdict."""
        pre_state = kvy.kevers[serder.pre].serder.said if serder.pre in kvy.kevers else None
        try:
            kvy.processEvent(serder=serder, sigers=sigers,
                             delsner=delsner, delsger=delsger)
        except LikelyDuplicitousError:
            return "duplicitous"
        except Exception as ex:  # noqa: BLE001 — record verbatim for triage
            got = f"error:{type(ex).__name__}"
            # B2 cascade loss is a bare ValidationError drop, not duplicity
            # escrow (eventing.py:3467-3475) — translate, delegated only.
            if delegated and got == "error:ValidationError":
                return "yields"
            return got
        post = kvy.kevers[serder.pre].serder.said
        if post == serder.said:
            return "supersedes" if pre_state is not None else "accepted"
        return "duplicate"

    signers = Salter(raw=SALT).signers(count=8, transferable=True, temp=True)
    k = [s.verfer.qb64 for s in signers]
    # Pre-rotation commitments: Blake3-256 digest of the next key's qb64b.
    nxt = [Diger(ser=s.verfer.qb64b).qb64 for s in signers]

    records = []

    def emit(name, events, sigs, contest, contest_sigs, expected, chain=None):
        assert expected in ("supersedes", "duplicate", "duplicitous", "yields"), (
            f"{name}: keripy outcome {expected!r} — scenario construction is wrong")
        rec = {
            "name": name,
            "events": [b64(s.raw) for s in events],
            "sigs": [[sg.qb64 for sg in ss] for ss in sigs],
            "contest": {"raw": b64(contest.raw),
                        "sigs": [sg.qb64 for sg in contest_sigs]},
            "expected": expected,
        }
        if chain is not None:
            rec["chain"] = chain
        records.append(rec)

    def feed(kvy, serder, sigers, **kwa):
        kvy.processEvent(serder=serder, sigers=sigers, **kwa)

    # ── Gate scenarios (eventing.py:4396-4478) ──────────────────────────────

    def base_ixn_chain(kvy):
        """icp -> ixn1 -> ixn2, all single-sig. Returns (pre, icp, ixn1, ixn2, sig lists)."""
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], version=Vrsn_1_0, kind=Kinds.json)
        pre = icp.ked["i"]
        s0 = [signers[0].sign(icp.raw, index=0)]
        feed(kvy, icp, s0)
        ixn1 = interact(pre=pre, dig=icp.said, sn=1, version=Vrsn_1_0, kind=Kinds.json)
        s1 = [signers[0].sign(ixn1.raw, index=0)]
        feed(kvy, ixn1, s1)
        ixn2 = interact(pre=pre, dig=ixn1.said, sn=2, version=Vrsn_1_0, kind=Kinds.json)
        s2 = [signers[0].sign(ixn2.raw, index=0)]
        feed(kvy, ixn2, s2)
        return pre, icp, ixn1, ixn2, s0, s1, s2

    # 1. rot_recovers_ixn — a rot at sn 1 inside the recovery window
    #    (lastEst.s = 0 < 1 <= sno) supersedes the recorded ixn1.
    with openDB(name="dup-rot-recovers") as db:
        kvy = Kevery(db=db)
        stub_ld_escrow(kvy)
        pre, icp, ixn1, ixn2, s0, s1, s2 = base_ixn_chain(kvy)
        rot = rotate(pre=pre, keys=[k[1]], dig=icp.said, ndigs=[nxt[2]], sn=1,
                     version=Vrsn_1_0, kind=Kinds.json)
        sr = [signers[1].sign(rot.raw, index=0)]
        expected = outcome(kvy, rot, sr)
        emit("rot_recovers_ixn", [icp, ixn1, ixn2], [s0, s1, s2], rot, sr, expected)

    # 2. duplicate_resend — resending the recorded ixn1 (head stays at ixn2).
    with openDB(name="dup-duplicate") as db:
        kvy = Kevery(db=db)
        stub_ld_escrow(kvy)
        pre, icp, ixn1, ixn2, s0, s1, s2 = base_ixn_chain(kvy)
        expected = outcome(kvy, ixn1, s1)
        emit("duplicate_resend", [icp, ixn1, ixn2], [s0, s1, s2], ixn1, s1, expected)

    # 3. duplicitous_ixn — a different ixn at sn 1 (digest anchor changes the SAID).
    with openDB(name="dup-ixn") as db:
        kvy = Kevery(db=db)
        stub_ld_escrow(kvy)
        pre, icp, ixn1, ixn2, s0, s1, s2 = base_ixn_chain(kvy)
        ixn1b = interact(pre=pre, dig=icp.said, sn=1,
                         data=[{"d": Diger(ser=b"duplicitous anchor").qb64}],
                         version=Vrsn_1_0, kind=Kinds.json)
        s1b = [signers[0].sign(ixn1b.raw, index=0)]
        expected = outcome(kvy, ixn1b, s1b)
        emit("duplicitous_ixn", [icp, ixn1, ixn2], [s0, s1, s2], ixn1b, s1b, expected)

    # 4. rot_vs_rot — a rot at the establishment sn never supersedes (A1);
    #    different SAID -> likely duplicitous.
    with openDB(name="dup-rot-vs-rot") as db:
        kvy = Kevery(db=db)
        stub_ld_escrow(kvy)
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], version=Vrsn_1_0, kind=Kinds.json)
        pre = icp.ked["i"]
        s0 = [signers[0].sign(icp.raw, index=0)]
        feed(kvy, icp, s0)
        rot1 = rotate(pre=pre, keys=[k[1]], dig=icp.said, ndigs=[nxt[2]], sn=1,
                      version=Vrsn_1_0, kind=Kinds.json)
        sr1 = [signers[1].sign(rot1.raw, index=0)]
        feed(kvy, rot1, sr1)
        rot1b = rotate(pre=pre, keys=[k[1]], dig=icp.said, ndigs=[nxt[3]], sn=1,
                       version=Vrsn_1_0, kind=Kinds.json)
        sr1b = [signers[1].sign(rot1b.raw, index=0)]
        expected = outcome(kvy, rot1b, sr1b)
        emit("rot_vs_rot", [icp, rot1], [s0, sr1], rot1b, sr1b, expected)

    # 5. duplicitous_icp — a second, different inception for the same pre.
    with openDB(name="dup-icp") as db:
        kvy = Kevery(db=db)
        stub_ld_escrow(kvy)
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], version=Vrsn_1_0, kind=Kinds.json)
        s0 = [signers[0].sign(icp.raw, index=0)]
        feed(kvy, icp, s0)
        icp2 = incept(keys=[k[0]], ndigs=[nxt[2]], version=Vrsn_1_0, kind=Kinds.json)
        s02 = [signers[0].sign(icp2.raw, index=0)]
        expected = outcome(kvy, icp2, s02)
        emit("duplicitous_icp", [icp], [s0], icp2, s02, expected)

    # ── Cascade scenarios (eventing.py:3413-3492) ───────────────────────────
    # Port of the db-level half of keripy's test_delegation_supersede: bob is
    # the delegator, del the delegate; one Kevery holds both KELs. Delegated
    # events are fed with their source couple (delsner/delsger) exactly as the
    # parser supplies them from SealSourceCouples attachments.

    def delegation_setup(kvy):
        """bob icp; bob ixn1 approving del's dip; del dip accepted.
        Returns (bobPre, bobIcp, bobIxn1, delPre, delDip, delDipSigs)."""
        bobIcp = incept(keys=[k[0]], ndigs=[nxt[1]], version=Vrsn_1_0, kind=Kinds.json)
        bobPre = bobIcp.ked["i"]
        feed(kvy, bobIcp, [signers[0].sign(bobIcp.raw, index=0)])
        delDip = delcept(keys=[k[3]], delpre=bobPre, ndigs=[nxt[4]],
                         version=Vrsn_1_0, kind=Kinds.json)
        delPre = delDip.ked["i"]
        seal = SealEvent(i=delPre, s=delDip.snh, d=delDip.said)
        bobIxn1 = interact(pre=bobPre, dig=bobIcp.said, sn=1, data=[seal._asdict()],
                           version=Vrsn_1_0, kind=Kinds.json)
        feed(kvy, bobIxn1, [signers[0].sign(bobIxn1.raw, index=0)])
        dip_sigs = [signers[3].sign(delDip.raw, index=0)]
        feed(kvy, delDip, dip_sigs,
             delsner=Number(num=1), delsger=Diger(qb64=bobIxn1.said))
        assert delPre in kvy.kevers
        return bobPre, bobIcp, bobIxn1, delPre, delDip, dip_sigs

    def make_drts(delPre, delDip):
        """The incumbent drt at sn 1 (reveals k4, opening the dip's next
        commitment) and a challenger drt' revealing k5. keripy quirk at the
        pin: ``valSigsWigsDel`` (eventing.py:2885) checks a superseding drt's
        prior-next exposure against the CURRENT head state's commitment (the
        incumbent's ``n`` = digest(k5)), not the dip's — so the challenger
        must reveal k5 to get past the signature gate and reach
        ``validateDelegation``'s cascade, which is the verdict under test.
        The K3 judge routes on (sn, ilk, chain) only; signature semantics
        stay in the fold, so the verdict comparison is unaffected."""
        drt = deltate(pre=delPre, keys=[k[4]], dig=delDip.said, sn=1, ndigs=[nxt[5]],
                      version=Vrsn_1_0, kind=Kinds.json)
        drt_b = deltate(pre=delPre, keys=[k[5]], dig=delDip.said, sn=1, ndigs=[nxt[6]],
                        version=Vrsn_1_0, kind=Kinds.json)
        assert drt.said != drt_b.said
        return drt, drt_b

    # 6. drt_cascade_b1 — the challenger drt is approved by a LATER delegator
    #    event (bob ixn3 vs incumbent's bob ixn2): B1 supersedes.
    with openDB(name="dup-cascade-b1") as db:
        kvy = Kevery(db=db)
        stub_ld_escrow(kvy)
        bobPre, _, bobIxn1, delPre, delDip, dip_sigs = delegation_setup(kvy)
        drt, drt_b = make_drts(delPre, delDip)
        seal = SealEvent(i=delPre, s=drt.snh, d=drt.said)
        bobIxn2 = interact(pre=bobPre, dig=bobIxn1.said, sn=2, data=[seal._asdict()],
                           version=Vrsn_1_0, kind=Kinds.json)
        feed(kvy, bobIxn2, [signers[0].sign(bobIxn2.raw, index=0)])
        drt_sigs = [signers[4].sign(drt.raw, index=0)]
        feed(kvy, drt, drt_sigs,
             delsner=Number(num=2), delsger=Diger(qb64=bobIxn2.said))
        seal_b = SealEvent(i=delPre, s=drt_b.snh, d=drt_b.said)
        bobIxn3 = interact(pre=bobPre, dig=bobIxn2.said, sn=3, data=[seal_b._asdict()],
                           version=Vrsn_1_0, kind=Kinds.json)
        feed(kvy, bobIxn3, [signers[0].sign(bobIxn3.raw, index=0)])
        drt_b_sigs = [signers[5].sign(drt_b.raw, index=0)]
        expected = outcome(kvy, drt_b, drt_b_sigs,
                           delsner=Number(num=3), delsger=Diger(qb64=bobIxn3.said),
                           delegated=True)
        emit("drt_cascade_b1", [delDip, drt], [dip_sigs, drt_sigs], drt_b, drt_b_sigs,
             expected,
             chain=[{"incumbent": b64(bobIxn2.raw), "challenger": b64(bobIxn3.raw)}])

    # 7. drt_cascade_b2_loss — WITHHELD at this pin. keripy's cascade beyond
    # B1 is dead at runtime: ``validateDelegation`` reads ``bossn.Ilk``
    # (capital I — eventing.py:3446); ``SerderKERI`` only has ``.ilk``, so the
    # moment the B1 sn-comparison is False (same-sn delegating events — the
    # B3/B2/C paths) keripy raises AttributeError, not a verdict. Their own
    # supersede test is a stub ("This needs to be fixedup", test_delegating.py:489).
    # B2/B3/C conformance is therefore to keripy's SOURCE-TEXT rules
    # (eventing.py:3444-3475), covered by the in-repo cascade unit tests;
    # regenerate this vector when upstream fixes the typo. Recorded in
    # docs/keripy-parity/ledger.md.

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        fh.write(f"# keripy-GENERATED (not synthesized from cesr/keri-rs) — "
                 f"keripy {KERIPY_VERSION}, oracle main 9161a705, KERI10JSON. "
                 f"events/contest/chain are keripy serder.raw bytes (base64); "
                 f"expected is keripy Kevery's own verdict.\n")
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")

    print(f"wrote {len(records)} duplicity vectors -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
