#!/usr/bin/env python3
"""Regenerate/check pinned keripy V1 query, reply and discovery fixtures."""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path

import keri
from keri.core import SerderKERI, Signer, eventing
from keri.core.structing import SealEvent, StateEstEvent
from keri.kering import Kinds, Vrsn_1_0


ROOT = Path(__file__).resolve().parents[1]
PIN = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3"
CORPUS = ROOT / "crates/keri-codec/tests/corpus/discovery/v1.jsonl"
STAMP = "2026-10-01T00:00:00.000000+00:00"


def fixtures():
    signer = Signer(raw=bytes([0x24]) * 32, transferable=True)
    nontrans = Signer(raw=bytes([0x25]) * 32, transferable=False)
    inception = eventing.incept(
        keys=[signer.verfer.qb64], ndigs=[], nsith="0", toad="0", wits=[],
        kind=Kinds.json, pvrsn=Vrsn_1_0, code="E",
    )
    aid = inception.pre
    source = SealEvent(i=aid, s="0", d=inception.said)
    state = eventing.state(
        pre=aid, sn=0, pig="", dig=inception.said, fn=0, eilk="icp",
        keys=[signer.verfer.qb64],
        eevt=StateEstEvent(s="0", d=inception.said, br=[], ba=[]),
        stamp=STAMP, ndigs=[], nsith="0", toad="0", wits=[],
        version=Vrsn_1_0, kind=Kinds.json,
    )
    data = [
        (
            "qry_kel",
            eventing.query(
                pre=aid, route="/logs", replyRoute="/reply",
                query={"i": aid, "s": "0"}, stamp=STAMP,
                pvrsn=Vrsn_1_0,
            ),
            True,
        ),
        (
            "rpy_end_add",
            eventing.reply(
                pre=aid, route="/end/role/add",
                data={"cid": aid, "role": "witness", "eid": aid},
                stamp="2026-10-01T00:00:01.000000+00:00",
                pvrsn=Vrsn_1_0,
            ),
            True,
        ),
        (
            "rpy_end_cut",
            eventing.reply(
                pre=aid, route="/end/role/cut",
                data={"cid": aid, "role": "witness", "eid": aid},
                stamp="2026-10-01T00:00:02.000000+00:00",
                pvrsn=Vrsn_1_0,
            ),
            True,
        ),
        (
            "rpy_loc_scheme",
            eventing.reply(
                pre=aid, route="/loc/scheme",
                data={"eid": aid, "scheme": "https", "url": "https://example.com/witness"},
                stamp="2026-10-01T00:00:03.000000+00:00",
                pvrsn=Vrsn_1_0,
            ),
            True,
        ),
        (
            "rpy_loc_nontrans",
            eventing.reply(
                pre=nontrans.verfer.qb64, route="/loc/scheme",
                data={"eid": nontrans.verfer.qb64, "scheme": "https",
                      "url": "https://example.com/nontrans"},
                stamp="2026-10-01T00:00:03.500000+00:00",
                pvrsn=Vrsn_1_0,
            ),
            True,
        ),
        (
            "rpy_ksn",
            eventing.reply(
                pre=aid, route=f"/ksn/{aid}", data=asdict(state),
                stamp="2026-10-01T00:00:04.000000+00:00",
                pvrsn=Vrsn_1_0,
            ),
            True,
        ),
        (
            "rpy_oobi_untrusted",
            eventing.reply(
                pre=aid, route="/oobi/witness",
                data={"cid": aid, "urls": ["https://example.com/oobi"]},
                stamp="2026-10-01T00:00:05.000000+00:00",
                pvrsn=Vrsn_1_0,
            ),
            False,
        ),
    ]

    rows = []
    for name, serder, signed in data:
        parsed = SerderKERI(raw=serder.raw)
        assert parsed.ked == serder.ked and parsed.said == serder.said, name
        assert "i" not in parsed.ked, f"V1 {name} gained a V2 sender field"
        if signed:
            if name == "rpy_loc_nontrans":
                cigar = nontrans.sign(ser=serder.raw)
                assert nontrans.verfer.verify(cigar.raw, serder.raw), name
                message = bytes(eventing.messagize(serder, cigars=[cigar]))
            else:
                sig = signer.sign(ser=serder.raw, index=0)
                assert signer.verfer.verify(sig.raw, serder.raw), name
                message = bytes(eventing.messagize(serder, sigers=[sig], source=source))
            assert message.startswith(serder.raw), name
        else:
            message = serder.raw
        rows.append(dict(
            case=name,
            ilk=serder.ked["t"],
            route=serder.ked["r"],
            raw=serder.raw.decode(),
            signed=message.decode(),
            authorizer=(nontrans.verfer.qb64 if name == "rpy_loc_nontrans"
                        else aid if signed else None),
            signer_est_sn="0" if signed and name != "rpy_loc_nontrans" else None,
            signer_est_said=inception.said if signed and name != "rpy_loc_nontrans" else None,
            signer_est_raw=inception.raw.decode() if signed and name != "rpy_loc_nontrans" else None,
        ))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    assert (ROOT / "scripts/KERIPY_PIN").read_text().strip() == PIN
    checkout = Path(os.environ["KERIPY_CHECKOUT"]).resolve()
    assert Path(keri.__file__).resolve().is_relative_to(checkout), keri.__file__
    rows = fixtures()
    encoded = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)
    if args.write:
        CORPUS.parent.mkdir(parents=True, exist_ok=True)
        CORPUS.write_text(encoded)
    else:
        assert CORPUS.read_text() == encoded, "discovery oracle corpus drift"
    print(json.dumps({"pin": PIN, "cases": [row["case"] for row in rows]}))


if __name__ == "__main__":
    main()
