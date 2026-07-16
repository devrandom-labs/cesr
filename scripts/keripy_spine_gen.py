#!/usr/bin/env python3
"""Generate keripy-signed WIRE fixtures for the read-spine acceptance tests
(spine spec §4 Test A, `keri/tests/spine.rs`).

keripy is the oracle. Unlike the JSONL corpora (which carry `serder.raw` plus
signatures as separate fields), these fixtures are raw ``messagize`` output —
the exact bytes keripy puts on the wire: JSON body + framed ``-V``
AttachmentGroup counter + ``-A`` ControllerIdxSigs + indexed signatures.

  * ``keripy_icp_signed.cesr`` — ONE signed transferable inception
    (2 keys, kt=2, 2 next-key digests, nt=2, no witnesses).
  * ``keripy_kel_signed.cesr`` — a 3-message stream icp -> rot -> ixn,
    each signed and messagized, concatenated.

The KEL is folded through keripy's ``Kever`` so the printed expectations are
keripy's authoritative state, not this script's arithmetic. The JSON printed
to stdout is pinned VERBATIM in ``keri/tests/spine.rs``.

Deterministic: fixed salt, no wall-clock, no OS randomness.

Pin: keripy v2.0.0.dev5-1030-gde59bc7d (scripts/KERIPY_PIN), KERI/CESR V1
JSON (``KERI10JSON``), V1 attachment counters (``gvrsn=Vrsn_1_0``).
"""
import argparse
import json
import sys
from pathlib import Path

KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is prepended "
                         "to sys.path); omit if keripy is already importable")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="directory for the .cesr fixtures (keri/tests/fixtures)")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    from keri.core.coring import Diger, Kinds
    from keri.core.counting import Vrsn_1_0
    from keri.core.eventing import Kever, incept, interact, messagize, rotate
    from keri.core.signing import Salter
    from keri.db.basing import openDB

    # Deterministic signers: fixed 16-byte salt -> Ed25519 key sequence.
    # 0,1 = current keys; 2,3 = first rotation reveal; 4,5 = next commitment.
    salt = b"spine-fixture-01"
    signers = Salter(raw=salt).signers(count=6, transferable=True, temp=True)

    keys0 = [signers[0].verfer.qb64, signers[1].verfer.qb64]
    keys1 = [signers[2].verfer.qb64, signers[3].verfer.qb64]
    nxt1 = [Diger(ser=signers[2].verfer.qb64b).qb64,
            Diger(ser=signers[3].verfer.qb64b).qb64]
    nxt2 = [Diger(ser=signers[4].verfer.qb64b).qb64,
            Diger(ser=signers[5].verfer.qb64b).qb64]

    with openDB(name="spine-gen") as db:
        # Event 0: inception (2 current keys, kt=2, commit keys1, nt=2).
        icp = incept(keys=keys0, isith="2", ndigs=nxt1, nsith="2",
                     version=Vrsn_1_0, kind=Kinds.json)
        pre = icp.ked["i"]
        icp_sigs = [signers[i].sign(icp.raw, index=i) for i in range(2)]
        kever = Kever(serder=icp, sigers=icp_sigs, db=db)
        icp_msg = bytes(messagize(icp, sigers=icp_sigs, gvrsn=Vrsn_1_0))

        # Event 1: rotation (reveal keys1, commit nxt2), sn 1. Signed by keys1.
        rot = rotate(pre=pre, keys=keys1, dig=icp.said, isith="2",
                     ndigs=nxt2, nsith="2", sn=1,
                     version=Vrsn_1_0, kind=Kinds.json)
        rot_sigs = [signers[2 + i].sign(rot.raw, index=i) for i in range(2)]
        kever.update(serder=rot, sigers=rot_sigs)
        rot_msg = bytes(messagize(rot, sigers=rot_sigs, gvrsn=Vrsn_1_0))

        # Event 2: interaction, sn 2. Signed by the current keys (keys1).
        ixn = interact(pre=pre, dig=rot.said, sn=2,
                       version=Vrsn_1_0, kind=Kinds.json)
        ixn_sigs = [signers[2 + i].sign(ixn.raw, index=i) for i in range(2)]
        kever.update(serder=ixn, sigers=ixn_sigs)
        ixn_msg = bytes(messagize(ixn, sigers=ixn_sigs, gvrsn=Vrsn_1_0))

        # keripy's authoritative folded state after all three events.
        final_state = {
            "prefix_qb64": kever.prefixer.qb64,
            "sn": kever.sner.num,
            "latest_said_qb64": kever.serder.said,
            "keys_qb64": [v.qb64 for v in kever.verfers],
            "threshold_sith": kever.tholder.sith,
            "next_keys_qb64": [d.qb64 for d in kever.ndigers],
            "next_threshold_sith": kever.ntholder.sith,
            "witness_threshold": kever.toader.num,
            "witnesses_qb64": list(kever.wits),
        }

    # Sanity: each message is body + framed V1 attachment group (-V counter).
    for serder, msg in ((icp, icp_msg), (rot, rot_msg), (ixn, ixn_msg)):
        assert msg.startswith(serder.raw), "message must start with the body"
        attachment = msg[len(serder.raw):]
        assert attachment.startswith(b"-V"), attachment[:4]
    # Sanity: keripy's own fold must land where this KEL says it should.
    assert final_state["sn"] == 2, final_state["sn"]
    assert final_state["latest_said_qb64"] == ixn.said, final_state
    assert final_state["keys_qb64"] == keys1, final_state["keys_qb64"]
    assert final_state["next_keys_qb64"] == nxt2, final_state["next_keys_qb64"]

    args.out_dir.mkdir(parents=True, exist_ok=True)
    icp_path = args.out_dir / "keripy_icp_signed.cesr"
    kel_path = args.out_dir / "keripy_kel_signed.cesr"
    icp_path.write_bytes(icp_msg)
    kel_path.write_bytes(icp_msg + rot_msg + ixn_msg)

    pinned = {
        "keripy_version": KERIPY_VERSION,
        "note": ("keripy-GENERATED wire streams (messagize output: body + framed "
                 "-V attachment). Pin these values verbatim in keri/tests/spine.rs."),
        "icp": {
            "prefix_qb64": pre,
            "said_qb64": icp.said,
            "keys_qb64": keys0,
            "kt_sith": icp.ked["kt"],
            "nt_sith": icp.ked["nt"],
            "toad": int(icp.ked["bt"], 16),
            "witness_count": len(icp.ked["b"]),
            "message_len": len(icp_msg),
            "body_len": len(icp.raw),
        },
        "kel_final": final_state,
    }
    print(json.dumps(pinned, indent=2, sort_keys=True))

    print(f"wrote {icp_path} ({len(icp_msg)} bytes) and {kel_path} "
          f"({len(icp_msg) + len(rot_msg) + len(ixn_msg)} bytes, 3 messages)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
