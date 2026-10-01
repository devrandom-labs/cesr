#!/usr/bin/env python3
"""Check the checked-in TEL corpus against imported keripy at KERIPY_PIN.

This is a factory/reader/signature oracle, independent of the shape generator.
It also checks the registry-event coordinate carried by backed events.
"""

import base64
import hashlib
import json
import os
from pathlib import Path

import keri
from keri.core import SerderKERI, Signer
from keri.vdr import backerIssue, backerRevoke, incept, issue, revoke, rotate


ROOT = Path(__file__).resolve().parents[1]
PIN = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3"
CASES = (
    "vcp_two_backers", "vcp_no_backers", "vrt_cuts_adds",
    "iss_basic", "rev_basic", "bis_backed", "brv_backed",
)
CORPUS = ROOT / "crates/keri-codec/tests/corpus/tel"


def rows(filename):
    parsed = [json.loads(line) for line in (CORPUS / filename).read_text().splitlines()]
    assert tuple(row["case"] for row in parsed) == CASES, filename
    assert all(row["raw"] and row["ilk"] for row in parsed), filename
    return {row["case"]: row for row in parsed}


def main():
    assert (ROOT / "scripts/KERIPY_PIN").read_text().strip() == PIN
    checkout = Path(os.environ["KERIPY_CHECKOUT"]).resolve()
    assert Path(keri.__file__).resolve().is_relative_to(checkout), keri.__file__
    print(json.dumps({"pin": PIN, "imported_keri": str(Path(keri.__file__).resolve())},
                     sort_keys=True))
    happy = rows("happy.jsonl")
    signed = rows("signed.jsonl")
    body = {name: json.loads(happy[name]["raw"]) for name in CASES}
    first = body["vcp_two_backers"]
    second = body["vcp_no_backers"]
    rotation = body["vrt_cuts_adds"]
    issuance = body["iss_basic"]
    revocation = body["rev_basic"]
    backed_issue = body["bis_backed"]
    backed_revoke = body["brv_backed"]

    # These are the registry-event coordinates required by the backed TEL
    # chain, not just arbitrary data accepted by a body factory.
    assert backed_issue["ra"] == {"i": first["i"], "s": "0", "d": first["d"]}
    assert backed_revoke["ra"] == {"i": first["i"], "s": "0", "d": first["d"]}
    assert backed_revoke["p"] == backed_issue["d"]

    actual = {
        "vcp_two_backers": incept(
            pre=first["ii"], toad=int(first["bt"], 16), baks=first["b"],
            nonce=first["n"], cnfg=first["c"]),
        "vcp_no_backers": incept(
            pre=second["ii"], toad=int(second["bt"], 16), baks=second["b"],
            nonce=second["n"], cnfg=second["c"]),
        "vrt_cuts_adds": rotate(
            regk=rotation["i"], dig=rotation["p"],
            sn=int(rotation["s"], 16), toad=int(rotation["bt"], 16),
            baks=first["b"], cuts=rotation["br"], adds=rotation["ba"]),
        "iss_basic": issue(
            vcdig=issuance["i"], regk=issuance["ri"], dt=issuance["dt"]),
        "rev_basic": revoke(
            vcdig=revocation["i"], regk=revocation["ri"],
            dig=revocation["p"], dt=revocation["dt"]),
        "bis_backed": backerIssue(
            vcdig=backed_issue["i"], regk=backed_issue["ii"],
            regsn=int(backed_issue["ra"]["s"], 16),
            regd=first["d"], dt=backed_issue["dt"]),
        "brv_backed": backerRevoke(
            vcdig=backed_revoke["i"], regk=backed_revoke["ra"]["i"],
            regsn=int(backed_revoke["ra"]["s"], 16),
            regd=first["d"], dig=backed_revoke["p"],
            dt=backed_revoke["dt"]),
    }
    signer = Signer(raw=hashlib.sha256(b"keripy-tel-parity:issuer").digest())
    for name in CASES:
        expected = happy[name]["raw"].encode()
        event = actual[name]
        assert event.raw == expected, (name, event.raw, expected)
        reader = SerderKERI(raw=expected)
        assert reader.raw == expected and reader.said == event.said, name
        sig = signer.sign(ser=expected, index=0)
        row = signed[name]
        assert row["raw"].encode() == expected, name
        assert row["sig_qb64"] == sig.qb64, name
        assert base64.b64decode(row["vk_b64"]) == signer.verfer.raw, name
        assert signer.verfer.verify(sig.raw, expected), name
        print(json.dumps({"case": name, "ilk": row["ilk"], "said": event.said,
                          "factory_bytes": "match", "reader": "match",
                          "signature": "match"}, sort_keys=True))
    semantic = [json.loads(line) for line in (CORPUS / "semantic.jsonl").read_text().splitlines()]
    assert len(semantic) == 1 and semantic[0]["case"] == "brv_wrong_registry_anchor"
    row = semantic[0]
    raw = row["raw"].encode()
    sad = json.loads(raw)
    assert sad["ra"] == {"i": first["i"], "s": "0", "d": sad["p"]}
    assert sad["ra"]["d"] != first["d"]
    assert row["registry_vcp_said"] == first["d"]
    wrong = backerRevoke(vcdig=sad["i"], regk=sad["ra"]["i"],
                         regsn=0, regd=sad["p"], dig=sad["p"], dt=sad["dt"])
    assert wrong.raw == raw and SerderKERI(raw=raw).said == wrong.said
    assert row["sig_qb64"] == signer.sign(ser=raw, index=0).qb64
    assert base64.b64decode(row["vk_b64"]) == signer.verfer.raw
    assert row["keripy_verdict"] == "ValidationError"
    assert row["rust_verdict"] == "InconsistentManagement"
    print(json.dumps({"case": row["case"], "said": wrong.said,
                      "factory_bytes": "match", "signature": "match",
                      "semantic": "wrong management ra"}, sort_keys=True))


if __name__ == "__main__":
    main()
