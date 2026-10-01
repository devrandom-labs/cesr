"""Pinned keripy factory oracle for A03 witness/backer membership and TOAD.

Run against keripy de59bc7d with its Python 3.14 dependencies. The factory
checks set algebra and thresholds; the Rust integration tests additionally
exercise signed wire parsing, state folds, and indexed receipt verification.
"""

import json
from pathlib import Path

from keri.core import eventing
from keri.kering import Kinds
from keri.vdr import eventing as vdr_eventing


def reject(label, expected, build):
    try:
        build()
    except ValueError as error:
        assert expected in str(error), (label, str(error))
        print(f"reject {label}: {error}")
    else:
        raise AssertionError(f"keripy accepted {label}")


corpus = Path("crates/keri-codec/tests/corpus/keripy/parity/events.jsonl")
rows = {row["case"]: json.loads(row["raw"])
        for row in map(json.loads, corpus.read_text().splitlines())}
icp_row = rows["icp_witnessed"]
keys, ndigs, wits = icp_row["k"], icp_row["n"], icp_row["b"]
added = rows["icp_witnessed_salt2"]["b"][0]
unknown = rows["icp_witnessed_salt2"]["b"][1]

icp = eventing.incept(keys=keys, ndigs=ndigs, wits=wits, toad=2, kind=Kinds.json)
assert icp.ked["b"] == wits
reject("KEL duplicate witness", "duplicates", lambda: eventing.incept(
    keys=keys, ndigs=ndigs, wits=[wits[0], wits[0]], toad=2, kind=Kinds.json))
reject("KEL zero TOAD", "Invalid toad", lambda: eventing.incept(
    keys=keys, ndigs=ndigs, wits=[wits[0]], toad=0, kind=Kinds.json))


def rotate(**kwargs):
    return eventing.rotate(icp.pre, keys, icp.said, ndigs=ndigs,
                           wits=wits, toad=2, kind=Kinds.json, **kwargs)


reject("KEL duplicate cut", "duplicates", lambda: rotate(cuts=[wits[1], wits[1]]))
reject("KEL unknown cut", "not all members", lambda: rotate(cuts=[unknown]))
reject("KEL existing addition", "Intersecting", lambda: rotate(adds=[wits[0]]))
reject("KEL cut/add overlap", "Intersecting", lambda: rotate(
    cuts=[wits[1]], adds=[wits[1]]))
reject("KEL zero post-rotation TOAD", "Invalid toad", lambda: eventing.rotate(
    icp.pre, keys, icp.said, ndigs=ndigs, wits=wits, cuts=[wits[1]],
    adds=[added], toad=0, kind=Kinds.json))
valid_rot = rotate(cuts=[wits[1]], adds=[added])
assert valid_rot.ked["br"] == [wits[1]]
assert valid_rot.ked["ba"] == [added]
print("accept KEL ordered cut/add rotation")

vcp = vdr_eventing.incept(pre=icp.pre, baks=wits, toad=2)
assert vcp.ked["b"] == wits
reject("TEL duplicate backer", "duplicates", lambda: vdr_eventing.incept(
    pre=icp.pre, baks=[wits[0], wits[0]], toad=2))
reject("TEL zero TOAD", "Invalid toad", lambda: vdr_eventing.incept(
    pre=icp.pre, baks=[wits[0]], toad=0))


def vrt(**kwargs):
    return vdr_eventing.rotate(vcp.pre, vcp.said, baks=wits, toad=2, **kwargs)


reject("TEL duplicate cut", "duplicates", lambda: vrt(cuts=[wits[1], wits[1]]))
reject("TEL unknown cut", "not all members", lambda: vrt(cuts=[unknown]))
reject("TEL existing addition", "Intersecting", lambda: vrt(adds=[wits[0]]))
reject("TEL cut/add overlap", "Intersecting", lambda: vrt(
    cuts=[wits[1]], adds=[wits[1]]))
valid_vrt = vrt(cuts=[wits[1]], adds=[added])
assert valid_vrt.ked["br"] == [wits[1]]
assert valid_vrt.ked["ba"] == [added]
print("accept TEL ordered cut/add rotation")
