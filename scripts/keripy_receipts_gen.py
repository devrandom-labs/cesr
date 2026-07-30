#!/usr/bin/env python3
"""Generate the keripy receipt (`rct`) differential corpus (issue #82).

keripy is the oracle. Two row kinds, one JSON object per line:

- ``kind="body"``: bare receipt bodies from keripy's ``receipt()``
  (``eventing.py:957`` at the pin) over sequence-number and prefix-derivation
  boundaries. cesr must (1) parse every body cleanly into the same
  ``(pre, sn, said)`` coordinate and (2) re-serialize it byte-identically.

- ``kind="framed"``: full receipt messages from keripy's ``messagize()``
  (V1, ``framed=False`` so the ``-V`` attachment counter is present) with
  every endorsement family it attaches to an rct: non-transferable couples
  (``-C`` cigars), witness indexed sigs (``-B`` wigers), transferable
  indexed-sig groups (``-F`` sigers + SealEvent source), and a combination.
  cesr must parse each stream, route the groups to the same counts, verify
  every signature over the receipted event's bytes, and re-frame the parse
  result byte-identically.

No DB: receipts are pure message construction plus detached signatures.
Deterministic: fixed salts, no wall-clock, no OS randomness.
Pin: keripy v2.0.0.dev5-1030-gde59bc7d, KERI/CESR V1 JSON (KERI10JSON).
"""
import argparse
import json
import sys
from pathlib import Path

KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"


def emit(fh, obj):
    fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is prepended "
                         "to sys.path); omit if keripy is already importable")
    ap.add_argument("--out", required=True, type=Path,
                    help="output directory (receipts.jsonl is written here)")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    from keri.core.coring import Kinds, MtrDex
    from keri.core.counting import Vrsn_1_0
    from keri.core.eventing import incept, messagize, receipt
    from keri.core.signing import Salter
    from keri.core.structing import SealEvent

    salt = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"
    signers = Salter(raw=salt).signers(count=4, transferable=True, temp=True)
    wsigners = Salter(raw=salt).signers(count=3, transferable=False, temp=True)
    J = dict(kind=Kinds.json, version=Vrsn_1_0)

    # The receipted event: a real basic-derivation inception, and a
    # self-addressing sibling — receipts name coordinates in BOTH styles.
    basic_icp = incept(keys=[signers[0].verfer.qb64], **J)
    said_icp = incept(keys=[signers[1].verfer.qb64], code=MtrDex.Blake3_256, **J)

    rows = []

    # ── body rows: sn / derivation boundary sweep ────────────────────────
    body_cases = [
        ("body_basic_sn0", basic_icp.pre, 0, basic_icp.said),
        ("body_self_addressing_sn0", said_icp.pre, 0, said_icp.said),
        ("body_sn_26", basic_icp.pre, 26, basic_icp.said),
        ("body_sn_large", basic_icp.pre, 0xDEADBEEF, basic_icp.said),
        ("body_sn_u64_max", basic_icp.pre, 2**64 - 1, basic_icp.said),
    ]
    for case, pre, sn, said in body_cases:
        serder = receipt(pre=pre, sn=sn, said=said, kind=Kinds.json, version=Vrsn_1_0)
        rows.append({
            "kind": "body",
            "case": case,
            "pre": pre,
            "sn": f"{sn:x}",
            "said": said,
            "raw": serder.raw.decode(),
        })

    # ── framed rows: every endorsement family messagize attaches ─────────
    rserder = receipt(pre=basic_icp.pre, sn=0, said=basic_icp.said,
                      kind=Kinds.json, version=Vrsn_1_0)

    cigars = [wsigners[0].sign(ser=basic_icp.raw)]
    wigers = [wsigners[i].sign(ser=basic_icp.raw, index=i) for i in range(2)]
    endorser = signers[2]
    endorser_icp = incept(keys=[endorser.verfer.qb64], code=MtrDex.Blake3_256, **J)
    tsg_sigers = [endorser.sign(ser=basic_icp.raw, index=0)]
    seal = SealEvent(i=endorser_icp.pre, s=endorser_icp.snh, d=endorser_icp.said)

    framed_cases = [
        ("framed_couples", dict(cigars=cigars), dict(couples=1, wigs=0, trans=0)),
        ("framed_wigers", dict(wigers=wigers), dict(couples=0, wigs=2, trans=0)),
        ("framed_tsg", dict(sigers=tsg_sigers, source=seal),
         dict(couples=0, wigs=0, trans=1)),
        ("framed_couples_and_wigers", dict(cigars=cigars, wigers=wigers),
         dict(couples=1, wigs=2, trans=0)),
        ("framed_all_three",
         dict(sigers=tsg_sigers, source=seal, cigars=cigars, wigers=wigers),
         dict(couples=1, wigs=2, trans=1)),
    ]
    for case, attachments, counts in framed_cases:
        stream = messagize(rserder, framed=False, **attachments)
        rows.append({
            "kind": "framed",
            "case": case,
            "pre": rserder.pre,
            "sn": rserder.snh,
            "said": rserder.said,
            "event_raw": basic_icp.raw.decode(),
            "witnesses": [w.verfer.qb64 for w in wsigners[:2]],
            "endorser_pre": endorser_icp.pre if counts["trans"] else None,
            "endorser_sn": endorser_icp.snh if counts["trans"] else None,
            "endorser_said": endorser_icp.said if counts["trans"] else None,
            "endorser_key": endorser.verfer.qb64 if counts["trans"] else None,
            "counts": counts,
            "stream": stream.decode(),
        })

    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / "receipts.jsonl"
    with out.open("w") as fh:
        for row in rows:
            emit(fh, row)
    print(f"wrote {len(rows)} rows to {out} (keripy {KERIPY_VERSION})")


if __name__ == "__main__":
    main()
