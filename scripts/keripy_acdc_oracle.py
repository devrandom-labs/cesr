#!/usr/bin/env python3
"""Check ACDC v1 corpus bytes, nested SAIDs and signatures with pinned keripy."""

import base64
import hashlib
import json
import os
from pathlib import Path

import keri
from keri.core import Saider, SerderACDC, Signer
from keri.kering import ValidationError


ROOT = Path(__file__).resolve().parents[1]
PIN = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3"
CASES = ("compact_minimal", "compact_issuance", "expanded_issuance",
         "aggregate_reference")
CORPUS = ROOT / "crates/keri-codec/tests/corpus/acdc"
NEGATIVE = {
    "missing_issuer": "MissingFieldError",
    "unallowed_prior": "ExtraFieldError",
    "both_attribute_forms": "AlternateFieldError",
    "unallowed_aggregate_edge": "ExtraFieldError",
    "unallowed_aggregate_rule": "ExtraFieldError",
}


def rows(name):
    found = [json.loads(line) for line in (CORPUS / name).read_text().splitlines()]
    assert tuple(row["case"] for row in found) == CASES, name
    assert all(row["raw"] for row in found), name
    return {row["case"]: row for row in found}


def main():
    assert (ROOT / "scripts/KERIPY_PIN").read_text().strip() == PIN
    checkout = Path(os.environ["KERIPY_CHECKOUT"]).resolve()
    assert Path(keri.__file__).resolve().is_relative_to(checkout), keri.__file__
    print(json.dumps({"pin": PIN, "imported_keri": str(Path(keri.__file__).resolve())},
                     sort_keys=True))
    happy = rows("happy.jsonl")
    signed = rows("signed.jsonl")
    signer = Signer(raw=hashlib.sha256(b"keripy-acdc-parity:issuer").digest())
    for name in CASES:
        expected = happy[name]["raw"].encode()
        sad = json.loads(expected)
        # A raw reader enforces the pinned v1 field domain, including required
        # issuer and the absence of fields from unrelated KEL/ACDC versions.
        reader = SerderACDC(raw=expected)
        assert reader.raw == expected and reader.verify(), name
        made = SerderACDC(sad=sad, makify=True)
        assert made.raw == expected and made.said == reader.said, name
        for label in ("s", "a", "e", "r"):
            block = sad.get(label)
            if isinstance(block, dict) and "d" in block:
                assert Saider(qb64=block["d"]).verify(
                    block, prefixed=True, versioned=False), (name, label)
                _, rebuilt = Saider.saidify(sad=block)
                assert rebuilt == block, (name, label)
        row = signed[name]
        sig = signer.sign(ser=expected, index=0)
        assert row["raw"].encode() == expected, name
        assert row["sig_qb64"] == sig.qb64, name
        assert base64.b64decode(row["vk_b64"]) == signer.verfer.raw, name
        assert signer.verfer.verify(sig.raw, expected), name
        print(json.dumps({"case": name, "said": reader.said,
                          "reader": "match", "factory_bytes": "match",
                          "nested_said": "match", "signature": "match"},
                         sort_keys=True))
    harden = [json.loads(line) for line in (CORPUS / "harden.jsonl").read_text().splitlines()]
    observed = set()
    for row in harden:
        name = row["case"]
        if name not in NEGATIVE:
            continue
        observed.add(name)
        sad = json.loads(row["raw"])
        assert Saider(qb64=sad["d"]).verify(sad, prefixed=True), name
        try:
            SerderACDC(raw=row["raw"].encode())
        except ValidationError as error:
            cause = type(error.__cause__).__name__
            assert cause == NEGATIVE[name], (name, cause)
            print(json.dumps({"case": name, "said": sad["d"],
                              "reader_rejection": cause}, sort_keys=True))
        else:
            raise AssertionError(f"pinned ACDC reader accepted {name}")
    assert observed == set(NEGATIVE), observed


if __name__ == "__main__":
    main()
