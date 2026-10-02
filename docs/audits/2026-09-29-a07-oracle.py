"""Executable TEL acceptance matrix for keripy de59bc7d834955c5b0273c62f6b8b6a0df150dc3.

Run with that pinned tree on PYTHONPATH, plus its dependencies. This script
exercises Tevery/Tever, not merely the event factories. It prints JSON lines
so Rust cases can compare outcome, KEL anchor coordinate, and TEL `ra`.
"""

import json

from keri.app import openKS
from keri.core import (Diger, Parser, SealEvent, SealSource, Seqner,
                       SerderKERI, Signer, messagize)
from keri.db import openDB
from keri import (MissingAnchorError, MissingWitnessSignatureError,
                  OutOfOrderError, ValidationError, Vrsn_1_0)
from keri.vdr import (
    Tevery, backerIssue, backerRevoke, incept, issue, openReger, revoke, rotate
)
from tests.vdr import buildHab


VC_A = "EEBp64Aw2rsjdJpAR0e2qCq3jX7q7gLld3LjAwZgaLXU"
VC_B = "EBpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"
DATE = "2021-01-01T00:00:00.000000+00:00"


def row(event, anchor, outcome, **extra):
    print(json.dumps({
        "ilk": event.ked["t"], "said": event.said,
        "kel_anchor": {"i": anchor[0], "s": anchor[1].sn,
                       "d": anchor[2].qb64},
        "tel_ra": event.ked.get("ra"), "outcome": outcome, **extra,
    }, sort_keys=True))


def wire_check(tvy, event, coordinate, bigers):
    """Route a real framed TEL message into Tevery through the CESR parser."""
    class Capture:
        def __init__(self, target):
            self.target = target
            self.extracted = None
            self.accepted = False

        def processEvent(self, **kwargs):
            self.extracted = kwargs
            self.target.processEvent(**kwargs)
            self.accepted = True

    _, seqner, saider = coordinate
    source = SealSource(s=f"{seqner.sn:x}", d=saider.qb64)
    frame = messagize(event, bonds=source, wigers=bigers,
                      framed=False, gvrsn=Vrsn_1_0)
    assert frame[len(event.raw):].startswith(b"-V")
    capture = Capture(tvy)
    Parser(ims=frame, framed=False, tvy=capture,
           version=Vrsn_1_0).parse()
    extracted = capture.extracted
    assert extracted is not None
    assert extracted["serder"].raw == event.raw
    assert extracted["seqner"].sn == seqner.sn
    assert extracted["saider"].qb64 == saider.qb64
    assert len(extracted["wigers"]) == len(bigers or [])
    assert capture.accepted
    return ["-V", "-G"] + (["-B"] if bigers else [])


def anchor(hab, event):
    seal = SealEvent(event.ked["i"], event.ked["s"], event.said)
    kel = SerderKERI(raw=hab.rotate(data=[seal._asdict()], framed=True))
    return (hab.pre, Seqner(sn=int(kel.ked["s"], 16)), Diger(qb64=kel.said))


def deliver(tvy, event, coordinate, bigers=None):
    groups = wire_check(tvy, event, coordinate, bigers)
    row(event, coordinate, "accepted", frame_groups=groups)


def expect(tvy, event, coordinate, error, bigers=None):
    _, seqner, saider = coordinate
    try:
        tvy.processEvent(serder=event, seqner=seqner, saider=saider, wigers=bigers)
    except error:
        row(event, coordinate, error.__name__)
    else:
        raise AssertionError(f"{event.ked['t']} accepted without {error.__name__}")


def backerless():
    with openDB() as db, openKS() as ks, openReger() as reger:
        _, hab = buildHab(db, ks, name="a07-nb")
        tvy = Tevery(reger=reger, db=db)
        vcp = incept(hab.pre, baks=[], toad=0, cnfg=["NB"])
        # The coordinate is supplied in the -G source couple before its KEL
        # event arrives. Re-drive after the anchor becomes accepted.
        vcp_anchor = anchor(hab, vcp)
        _, seqner, saider = vcp_anchor
        accepted_kel = db.evts.get(keys=(hab.pre, saider.qb64b))
        db.kels.rem(keys=hab.pre, on=seqner.sn)
        db.evts.rem(keys=(hab.pre, saider.qb64b))
        expect(tvy, vcp, vcp_anchor, MissingAnchorError)
        db.kels.add(keys=hab.pre, on=seqner.sn, val=saider.qb64b)
        db.evts.put(keys=(hab.pre, saider.qb64b), val=accepted_kel)
        tvy.processEscrows()
        assert vcp.pre in tvy.tevers
        row(vcp, vcp_anchor, "accepted_after_anchor")

        iss = issue(VC_A, vcp.pre, dt=DATE)
        iss_anchor = anchor(hab, iss)
        wrong = (hab.pre, iss_anchor[1], Diger(qb64="E" + "A" * 43))
        expect(tvy, iss, wrong, MissingAnchorError)
        rev = revoke(VC_A, vcp.pre, iss.said, dt=DATE)
        rev_anchor = anchor(hab, rev)
        expect(tvy, rev, rev_anchor, OutOfOrderError)
        deliver(tvy, iss, iss_anchor)
        tvy.processEscrows()
        row(rev, rev_anchor, "accepted_after_prior")
        assert tvy.tevers[vcp.pre].vcState(VC_A).et == "rev"


def backed():
    with openDB() as db, openKS() as ks, openReger() as reger:
        _, hab = buildHab(db, ks, name="a07-bak")
        tvy = Tevery(reger=reger, db=db)
        a = Signer(qb64="ABjD4nRlycmM5cPcAkfOATAp8wVldRsnc9f1tiwctXlw",
                   transferable=False)
        b = Signer(qb64="AKUotEE0eAheKdDJh9QvNmSEmO_bjIav8V_GmctGpuCQ",
                   transferable=False)
        a_pre, b_pre = a.verfer.qb64, b.verfer.qb64

        vcp = incept(hab.pre, baks=[a_pre], toad=1)
        vcp_anchor = anchor(hab, vcp)
        expect(tvy, vcp, vcp_anchor, MissingWitnessSignatureError)
        deliver(tvy, vcp, vcp_anchor, [a.sign(ser=vcp.raw, index=0)])

        # A simple issue is structurally invalid for a backed registry;
        # adding KEL evidence cannot turn this verdict into acceptance.
        wrong_flavor = issue(VC_A, vcp.pre, dt=DATE)
        expect(tvy, wrong_flavor, vcp_anchor, ValidationError)

        vrt = rotate(vcp.pre, dig=vcp.said, baks=[a_pre],
                     cuts=[a_pre], adds=[b_pre], toad=1)
        vrt_anchor = anchor(hab, vrt)
        deliver(tvy, vrt, vrt_anchor, [b.sign(ser=vrt.raw, index=0)])

        # Both credential events cite historical vcp (sn=0, backer A), while
        # the current registry head is vrt (sn=1, backer B).
        bis = backerIssue(VC_B, vcp.pre, regsn=0, regd=vcp.said, dt=DATE)
        bis_anchor = anchor(hab, bis)
        expect(tvy, bis, bis_anchor, MissingWitnessSignatureError)
        deliver(tvy, bis, bis_anchor, [a.sign(ser=bis.raw, index=0)])

        # A SAID-valid, correctly signed brv with a credential-event digest
        # in ra cannot name the registry management event at (regk, 0).
        wrong_ra = backerRevoke(VC_B, vcp.pre, regsn=0, regd=bis.said,
                                dig=bis.said, dt=DATE)
        wrong_ra_anchor = anchor(hab, wrong_ra)
        expect(tvy, wrong_ra, wrong_ra_anchor, ValidationError,
               [a.sign(ser=wrong_ra.raw, index=0)])

        brv = backerRevoke(VC_B, vcp.pre, regsn=0, regd=vcp.said,
                           dig=bis.said, dt=DATE)
        brv_anchor = anchor(hab, brv)
        deliver(tvy, brv, brv_anchor, [a.sign(ser=brv.raw, index=0)])
        assert tvy.tevers[vcp.pre].vcState(VC_B).et == "brv"


if __name__ == "__main__":
    backerless()
    backed()
