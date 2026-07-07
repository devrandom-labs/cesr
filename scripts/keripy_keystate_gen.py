#!/usr/bin/env python3
"""Generate the keripy key-state differential vector (JSONL) for the K1 fold.

keripy is the oracle. This builds a single-sig **transferable** KEL —
inception -> rotation -> interaction — signs each event with real Ed25519
signers, folds them through keripy's ``keri.core.eventing.Kever``, and emits ONE
JSON object to the output file capturing:

  * ``events``:      the ordered event bytes (base64 of ``serder.raw``) plus the
                     controller signature indices (single-sig => ``[0]``).
  * ``final_state``: keripy's ``Kever`` state AFTER folding all events
                     (prefix / sn / current keys / next-key digests / witnesses /
                     TOAD). This is keripy's authoritative fold output — the cesr
                     ``keri-rs`` fold is asserted against it, NOT the other way
                     round (that would be circular).

Deterministic: fixed salt, no wall-clock, no OS randomness.

Pin: keripy v2.0.0.dev5-1030-gde59bc7d, KERI/CESR V1 JSON (``KERI10JSON``).
"""
import argparse
import base64
import json
import sys
from pathlib import Path

KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"


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

    from keri.core.coring import Diger, Kinds
    from keri.core.eventing import Kever, incept, interact, rotate
    from keri.core.signing import Salter
    from keri.core.counting import Vrsn_1_0
    from keri.db.basing import openDB

    # Deterministic signers: fixed 16-byte salt -> Ed25519 key sequence.
    salt = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"
    signers = Salter(raw=salt).signers(count=4, transferable=True, temp=True)

    k0 = [signers[0].verfer.qb64]
    k1 = [signers[1].verfer.qb64]
    k2 = [signers[2].verfer.qb64]

    # Pre-rotation commitments: Blake3-256 digest of the next key's qb64b.
    nxt1 = [Diger(ser=signers[1].verfer.qb64b).qb64]  # commits to k1
    nxt2 = [Diger(ser=signers[2].verfer.qb64b).qb64]  # commits to k2

    events = []  # (serder, [siger]) pairs — the event and its controller signatures

    with openDB(name="k1-keystate") as db:
        # Event 0: inception (current k0, commit k1). Signed by k0.
        icp = incept(keys=k0, ndigs=nxt1, version=Vrsn_1_0, kind=Kinds.json)
        pre = icp.ked["i"]
        sig0 = signers[0].sign(icp.raw, index=0)
        kever = Kever(serder=icp, sigers=[sig0], db=db)
        events.append((icp, [sig0]))

        # Event 1: rotation (reveal k1, commit k2), sn 1. Signed by k1.
        rot = rotate(pre=pre, keys=k1, dig=icp.said, ndigs=nxt2, sn=1,
                     version=Vrsn_1_0, kind=Kinds.json)
        sig1 = signers[1].sign(rot.raw, index=0)
        kever.update(serder=rot, sigers=[sig1])
        events.append((rot, [sig1]))

        # Event 2: interaction, sn 2. Signed by current key k1.
        ixn = interact(pre=pre, dig=rot.said, sn=2, version=Vrsn_1_0, kind=Kinds.json)
        sig2 = signers[1].sign(ixn.raw, index=0)
        kever.update(serder=ixn, sigers=[sig2])
        events.append((ixn, [sig2]))

        # keripy's authoritative folded state after all three events.
        final_state = {
            "prefix_qb64": kever.prefixer.qb64,
            "sn": kever.sner.num,
            "keys_qb64": [v.qb64 for v in kever.verfers],
            "threshold_sith": kever.tholder.sith,
            "next_keys_qb64": [d.qb64 for d in kever.ndigers],
            "next_threshold_sith": kever.ntholder.sith,
            "witness_threshold": kever.toader.num,
            "witnesses_qb64": list(kever.wits),
        }

    # Sanity: keripy's own fold must land where this KEL says it should.
    assert final_state["sn"] == 2, final_state["sn"]
    assert final_state["keys_qb64"] == k1, final_state["keys_qb64"]
    assert final_state["next_keys_qb64"] == nxt2, final_state["next_keys_qb64"]

    record = {
        "keripy_version": KERIPY_VERSION,
        "note": ("keripy-GENERATED (not synthesized from cesr/keri-rs). events are "
                 "keripy serder.raw bytes; final_state is keripy Kever's fold output."),
        "events": [
            {"raw_b64": base64.standard_b64encode(serder.raw).decode("ascii"),
             "signer_indices": [sg.index for sg in sigers],
             "sigs_qb64": [sg.qb64 for sg in sigers]}
            for serder, sigers in events
        ],
        "final_state": final_state,
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        fh.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")

    print(f"wrote {len(events)} events -> {args.out} "
          f"(prefix={final_state['prefix_qb64']}, sn={final_state['sn']})",
          file=sys.stderr)


if __name__ == "__main__":
    main()
