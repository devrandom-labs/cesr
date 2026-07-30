#!/usr/bin/env python3
"""Generate the keripy delegation differential vectors (JSONL) for the K4
delegation-validation fold (#90).

keripy is the oracle. Each scenario folds a DELEGATOR KEL through a real
``keri.core.eventing.Kevery.processEvent`` on a bare, validator-role Kevery
(no local habs — ``locallyOwned``/``locallyMembered``/``locallyWitnessed``
are all False, so ``validateDelegation`` runs the full seal path,
eventing.py:3009-3416), then feeds the delegate's dip/drt and records
keripy's own verdict:

  * ``accepted`` — the delegate's kever accepted the event.
  * ``awaiting`` — keripy escrowed with ``MissingDelegationError``
                   (``.pdes``): no source couple, or the purported
                   delegating event carries no matching seal.
  * ``denied``   — keripy raised a bare ``ValidationError``: the delegator
                   carries the do-not-delegate trait.

Accepted scenarios feed the delegate event with its source seal couple
(``delsner``/``delsger``) exactly as the parser supplies it from
SealSourceCouples attachments — without a couple keripy escrows
unconditionally (``eager`` is False in ``processEvent``), which is scenario
``dip_missing_anchor``.

One JSONL record per scenario:
``{"name", "delegator_events": [b64…], "delegator_sigs": [[qb64…]…],
   "delegate_events": [b64…], "delegate_sigs": [[qb64…]…],
   "anchor_indices": [usize|null, …], "expected": …}`` — one anchor index
per delegate event: the index into ``delegator_events`` of the anchoring
event, or null when no evidence exists (the host drives the plain entry).

Deterministic: fixed salt, no wall-clock, no OS randomness. DO NOT check in
a corpus whose ``expected`` is ``error:*`` — that means the scenario
construction is wrong; fix the script.

Pin: the loaded keripy checkout's ``git describe --tags``, computed at
generation time (oracle main 9161a705), KERI/CESR V1 JSON (``KERI10JSON``).
"""
import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path

# Fallback when `git describe` is unavailable: the oracle pin (main 9161a705).
KERIPY_VERSION_FALLBACK = "v2.0.0.dev5-1245-g9161a705"


def keripy_version():
    """``git describe --tags`` of the LOADED keripy checkout (located via the
    imported package's ``__file__`` — the venv's editable pth resolves there),
    falling back to the known pin when git or the checkout is unavailable."""
    import keri

    root = Path(keri.__file__).resolve().parents[2]
    try:
        return subprocess.run(
            ["git", "-C", str(root), "describe", "--tags"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return KERIPY_VERSION_FALLBACK

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
    from keri.core.eventing import Kevery, delcept, deltate, incept, interact
    from keri.core.signing import Salter
    from keri.core.structing import SealEvent
    from keri.db.basing import openDB
    from keri.kering import (MissingDelegationError, TraitCodex, ValidationError,
                             Vrsn_1_0)

    def outcome(kvy, serder, sigers, **kwa):
        """Feed one delegate event; classify keripy's reaction as a verdict."""
        try:
            kvy.processEvent(serder=serder, sigers=sigers, **kwa)
        except MissingDelegationError:  # subclass of ValidationError — first
            return "awaiting"
        except ValidationError:
            return "denied"
        except Exception as ex:  # noqa: BLE001 — record verbatim for triage
            return f"error:{type(ex).__name__}"
        if serder.pre in kvy.kevers and kvy.kevers[serder.pre].serder.said == serder.said:
            return "accepted"
        return "error:not-accepted"

    signers = Salter(raw=SALT).signers(count=8, transferable=True, temp=True)
    k = [s.verfer.qb64 for s in signers]
    # Pre-rotation commitments: Blake3-256 digest of the next key's qb64b.
    nxt = [Diger(ser=s.verfer.qb64b).qb64 for s in signers]

    records = []
    version = keripy_version()

    def emit(name, delegator_events, delegator_sigs, delegate_events,
             delegate_sigs, anchor_indices, expected):
        assert expected in ("accepted", "awaiting", "denied"), (
            f"{name}: keripy outcome {expected!r} — scenario construction is wrong")
        records.append({
            "name": name,
            "delegator_events": [b64(s.raw) for s in delegator_events],
            "delegator_sigs": [[sg.qb64 for sg in ss] for ss in delegator_sigs],
            "delegate_events": [b64(s.raw) for s in delegate_events],
            "delegate_sigs": [[sg.qb64 for sg in ss] for ss in delegate_sigs],
            "anchor_indices": anchor_indices,
            "expected": expected,
        })

    def feed(kvy, serder, sigers, **kwa):
        kvy.processEvent(serder=serder, sigers=sigers, **kwa)

    def delegator_icp(cnfg=None):
        """bob's genesis: single-sig k0 committing to k1."""
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], cnfg=cnfg,
                     version=Vrsn_1_0, kind=Kinds.json)
        return icp, icp.ked["i"], [signers[0].sign(icp.raw, index=0)]

    def delegate_dip(bob_pre):
        """del's dip: single-sig k3 committing to k4, delegated by bob."""
        dip = delcept(keys=[k[3]], delpre=bob_pre, ndigs=[nxt[4]],
                      version=Vrsn_1_0, kind=Kinds.json)
        return dip, dip.ked["i"], [signers[3].sign(dip.raw, index=0)]

    def anchoring_ixn(bob_pre, prior, sn, seals):
        """bob's interaction at sn anchoring `seals` (empty = plain)."""
        ixn = interact(pre=bob_pre, dig=prior.said, sn=sn,
                       data=[s._asdict() for s in seals],
                       version=Vrsn_1_0, kind=Kinds.json)
        return ixn, [signers[0].sign(ixn.raw, index=0)]

    # 1. dip_anchored_ixn — bob's ixn1 anchors the dip's (i, s, d); the dip,
    #    fed with its source couple, is accepted.
    with openDB(name="del-dip-anchored") as db:
        kvy = Kevery(db=db)
        icp, bob_pre, s_icp = delegator_icp()
        feed(kvy, icp, s_icp)
        dip, del_pre, s_dip = delegate_dip(bob_pre)
        seal = SealEvent(i=del_pre, s=dip.snh, d=dip.said)
        ixn1, s_ixn1 = anchoring_ixn(bob_pre, icp, 1, [seal])
        feed(kvy, ixn1, s_ixn1)
        expected = outcome(kvy, dip, s_dip,
                           delsner=Number(num=1), delsger=Diger(qb64=ixn1.said))
        emit("dip_anchored_ixn", [icp, ixn1], [s_icp, s_ixn1], [dip], [s_dip],
             [1], expected)

    # 2. drt_anchored_ixn — extend 1: del's drt at sn 1, anchored by bob's
    #    ixn2; both delegate events accepted.
    with openDB(name="del-drt-anchored") as db:
        kvy = Kevery(db=db)
        icp, bob_pre, s_icp = delegator_icp()
        feed(kvy, icp, s_icp)
        dip, del_pre, s_dip = delegate_dip(bob_pre)
        seal = SealEvent(i=del_pre, s=dip.snh, d=dip.said)
        ixn1, s_ixn1 = anchoring_ixn(bob_pre, icp, 1, [seal])
        feed(kvy, ixn1, s_ixn1)
        feed(kvy, dip, s_dip,
             delsner=Number(num=1), delsger=Diger(qb64=ixn1.said))
        drt = deltate(pre=del_pre, keys=[k[4]], dig=dip.said, sn=1,
                      ndigs=[nxt[5]], version=Vrsn_1_0, kind=Kinds.json)
        s_drt = [signers[4].sign(drt.raw, index=0)]
        seal2 = SealEvent(i=del_pre, s=drt.snh, d=drt.said)
        ixn2, s_ixn2 = anchoring_ixn(bob_pre, ixn1, 2, [seal2])
        feed(kvy, ixn2, s_ixn2)
        expected = outcome(kvy, drt, s_drt,
                           delsner=Number(num=2), delsger=Diger(qb64=ixn2.said))
        emit("drt_anchored_ixn", [icp, ixn1, ixn2], [s_icp, s_ixn1, s_ixn2],
             [dip, drt], [s_dip, s_drt], [1, 2], expected)

    # 3. dip_missing_anchor — the delegator KEL carries no anchoring event
    #    and no source couple arrives: keripy escrows (.pdes) → awaiting.
    with openDB(name="del-dip-missing") as db:
        kvy = Kevery(db=db)
        icp, bob_pre, s_icp = delegator_icp()
        feed(kvy, icp, s_icp)
        dip, _, s_dip = delegate_dip(bob_pre)
        expected = outcome(kvy, dip, s_dip)
        emit("dip_missing_anchor", [icp], [s_icp], [dip], [s_dip],
             [None], expected)

    # 4. dip_dnd_delegator — bob's genesis carries the do-not-delegate
    #    trait: validateDelegation drops with ValidationError → denied.
    with openDB(name="del-dip-dnd") as db:
        kvy = Kevery(db=db)
        icp, bob_pre, s_icp = delegator_icp(cnfg=[TraitCodex.DoNotDelegate])
        feed(kvy, icp, s_icp)
        dip, del_pre, s_dip = delegate_dip(bob_pre)
        seal = SealEvent(i=del_pre, s=dip.snh, d=dip.said)
        ixn1, s_ixn1 = anchoring_ixn(bob_pre, icp, 1, [seal])
        feed(kvy, ixn1, s_ixn1)
        expected = outcome(kvy, dip, s_dip,
                           delsner=Number(num=1), delsger=Diger(qb64=ixn1.said))
        emit("dip_dnd_delegator", [icp, ixn1], [s_icp, s_ixn1], [dip], [s_dip],
             [1], expected)

    # 5. dip_tampered_seal — bob's ixn1 seals the dip's (i, s) with the
    #    WRONG digest (bob's icp said): the seal search fails → awaiting.
    with openDB(name="del-dip-tampered") as db:
        kvy = Kevery(db=db)
        icp, bob_pre, s_icp = delegator_icp()
        feed(kvy, icp, s_icp)
        dip, del_pre, s_dip = delegate_dip(bob_pre)
        seal = SealEvent(i=del_pre, s=dip.snh, d=icp.said)
        ixn1, s_ixn1 = anchoring_ixn(bob_pre, icp, 1, [seal])
        feed(kvy, ixn1, s_ixn1)
        expected = outcome(kvy, dip, s_dip,
                           delsner=Number(num=1), delsger=Diger(qb64=ixn1.said))
        emit("dip_tampered_seal", [icp, ixn1], [s_icp, s_ixn1], [dip], [s_dip],
             [1], expected)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        fh.write(f"# keripy-GENERATED (not synthesized from cesr/keri-rs) — "
                 f"keripy {version}, oracle main 9161a705, KERI10JSON. "
                 f"delegator/delegate events are keripy serder.raw bytes (base64); "
                 f"anchor_indices indexes delegator_events per delegate event; "
                 f"expected is keripy Kevery's own verdict.\n")
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")

    print(f"wrote {len(records)} delegation vectors -> {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
