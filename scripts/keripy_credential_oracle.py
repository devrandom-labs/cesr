#!/usr/bin/env python3
"""Generate/check pinned keripy V1 schema and credential evidence cases."""

import argparse
import json
import os
from pathlib import Path
from types import SimpleNamespace

import keri
from keri.core import Diger, JSONSchema, Salter, Schemer, SerderACDC, Signer, eventing
from keri.kering import Kinds, Vrsn_1_0
from keri.vc import proving
from keri.vdr import eventing as vdr_eventing
from keri.vdr.verifying import Verifier


ROOT = Path(__file__).resolve().parents[1]
PIN = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3"
CORPUS = ROOT / "crates/keri-codec/tests/corpus/credential/v1.jsonl"
STAMP = "2026-10-01T00:00:00.000000+00:00"


def fixtures():
    issuer_key = Signer(raw=bytes([0x34]) * 32, transferable=True)
    issuer_next = Signer(raw=bytes([0x36]) * 32, transferable=True)
    other_key = Signer(raw=bytes([0x35]) * 32, transferable=True)
    other_next = Signer(raw=bytes([0x37]) * 32, transferable=True)
    issuer_icp = eventing.incept(
        keys=[issuer_key.verfer.qb64],
        ndigs=[Diger(ser=issuer_next.verfer.qb64b).qb64], nsith="1", toad="0",
        wits=[], kind=Kinds.json, pvrsn=Vrsn_1_0, code="E",
    )
    other_icp = eventing.incept(
        keys=[other_key.verfer.qb64],
        ndigs=[Diger(ser=other_next.verfer.qb64b).qb64], nsith="1", toad="0",
        wits=[], kind=Kinds.json, pvrsn=Vrsn_1_0, code="E",
    )
    registry = vdr_eventing.incept(
        pre=issuer_icp.pre, nonce=Salter(raw=bytes([0x46]) * 16).qb64,
        cnfg=["NB"], baks=[], toad=0, version=Vrsn_1_0,
    )
    other_registry = vdr_eventing.incept(
        pre=other_icp.pre, nonce=Salter(raw=bytes([0x47]) * 16).qb64,
        cnfg=["NB"], baks=[], toad=0, version=Vrsn_1_0,
    )
    schema = Schemer(sed={
        "$id": "",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["v", "d", "i", "ri", "s", "a"],
        "properties": {
            "v": {"type": "string"},
            "d": {"type": "string"},
            "i": {"type": "string"},
            "ri": {"type": "string"},
            "s": {"type": "string"},
            "a": {
                "type": "object",
                "required": ["d", "i", "dt", "title"],
                "properties": {
                    "d": {"type": "string"},
                    "i": {"type": "string"},
                    "dt": {"type": "string", "format": "date-time"},
                    "title": {"type": "string"},
                },
            },
        },
    }, typ=JSONSchema())

    def cred(*, issuer=issuer_icp.pre, status=registry.pre, title="Engineer",
             source=None, rules=None):
        return proving.credential(
            schema=schema.said, issuer=issuer, status=status,
            recipient=other_icp.pre, data={"dt": STAMP, "title": title},
            source=source, rules=rules, version=Vrsn_1_0, kind=Kinds.json,
        )

    valid = cred()
    class Lookup:
        def __init__(self, values):
            self.values = values

        def get(self, keys):
            return self.values.get(keys)

    accepted_state = SimpleNamespace(et="iss", dt=STAMP)
    verifier = SimpleNamespace(
        reger=SimpleNamespace(
            saved=Lookup({valid.said: valid.said}),
            creds=Lookup({valid.said: valid}),
            subjs=Lookup({other_icp.pre: other_icp.pre}),
        ),
        tevers={registry.pre: SimpleNamespace(vcState=lambda said: accepted_state)},
    )
    assert Verifier.verifyChain(verifier, valid.said, "I2I", other_icp.pre) is accepted_state
    assert Verifier.verifyChain(verifier, valid.said, "I2I", issuer_icp.pre) is None
    assert Verifier.verifyChain(verifier, valid.said, "NI2I", issuer_icp.pre) is accepted_state
    try:
        Verifier.verifyChain(verifier, valid.said, "DI2I", other_icp.pre)
    except NotImplementedError:
        pass
    else:
        raise AssertionError("DI2I unexpectedly gained reference semantics")
    bad_schema = cred(title=42)
    wrong_issuer = cred(issuer=other_icp.pre)
    wrong_registry = cred(status=other_registry.pre)
    chain = {"d": "", "qualification": {"n": valid.said, "o": "I2I"}}
    chained = cred(issuer=other_icp.pre, status=other_registry.pre, source=chain)
    wrong_issuee = cred(source=chain)
    ni2i = cred(source={"d": "", "qualification": {"n": valid.said, "o": "NI2I"}})
    di2i = cred(source={"d": "", "qualification": {"n": valid.said, "o": "DI2I"}})
    rule_credential = cred(rules={"usageDisclaimer": "Use carefully."})
    aggregate_sad = dict(valid.sad)
    aggregate_sad["A"] = aggregate_sad.pop("a")["d"]
    aggregate_credential = SerderACDC(sad=aggregate_sad, makify=True)
    referenced_sad = dict(valid.sad)
    referenced_sad["a"] = referenced_sad["a"]["d"]
    referenced_credential = SerderACDC(sad=referenced_sad, makify=True)
    for item in [chained, wrong_issuee, ni2i, di2i, rule_credential]:
        assert SerderACDC(raw=item.raw).said == item.said
        schema.verify(item.raw)
    for name, value, expected in [
        ("issued", valid, True),
        ("schema_type_mismatch", bad_schema, False),
        ("unrelated_issuer", wrong_issuer, True),
        ("unrelated_registry", wrong_registry, True),
    ]:
        parsed = SerderACDC(raw=value.raw)
        assert parsed.said == value.said, name
        try:
            schema.verify(value.raw)
            schema_valid = True
        except Exception:
            schema_valid = False
        assert schema_valid is expected, name

    issue = vdr_eventing.issue(
        vcdig=valid.said, regk=registry.pre, version=Vrsn_1_0, dt=STAMP,
    )
    revoke = vdr_eventing.revoke(
        vcdig=valid.said, regk=registry.pre, dig=issue.said,
        version=Vrsn_1_0, dt="2026-10-01T00:00:01.000000+00:00",
    )
    chained_issue = vdr_eventing.issue(
        vcdig=chained.said, regk=other_registry.pre, version=Vrsn_1_0, dt=STAMP,
    )
    wrong_issuee_issue = vdr_eventing.issue(
        vcdig=wrong_issuee.said, regk=registry.pre, version=Vrsn_1_0, dt=STAMP,
    )
    ni2i_issue = vdr_eventing.issue(
        vcdig=ni2i.said, regk=registry.pre, version=Vrsn_1_0, dt=STAMP,
    )
    di2i_issue = vdr_eventing.issue(
        vcdig=di2i.said, regk=registry.pre, version=Vrsn_1_0, dt=STAMP,
    )
    rows = []
    for name, value in [
        ("issued", valid),
        ("schema_type_mismatch", bad_schema),
        ("unrelated_issuer", wrong_issuer),
        ("unrelated_registry", wrong_registry),
    ]:
        rows.append(dict(
            case=name,
            schema=schema.raw.decode(),
            schema_said=schema.said,
            credential=value.raw.decode(),
            credential_said=value.said,
            issuer_icp=issuer_icp.raw.decode(),
            registry_vcp=registry.raw.decode(),
            issue_iss=issue.raw.decode(),
            revoke_rev=revoke.raw.decode(),
            other_issuer_icp=other_icp.raw.decode(),
            other_registry_vcp=other_registry.raw.decode(),
        ))
    rows[0].update(dict(
        chained_credential=chained.raw.decode(),
        chained_said=chained.said,
        chained_issue_iss=chained_issue.raw.decode(),
        wrong_issuee_credential=wrong_issuee.raw.decode(),
        wrong_issuee_issue_iss=wrong_issuee_issue.raw.decode(),
        ni2i_credential=ni2i.raw.decode(),
        ni2i_issue_iss=ni2i_issue.raw.decode(),
        di2i_credential=di2i.raw.decode(),
        di2i_issue_iss=di2i_issue.raw.decode(),
        rule_credential=rule_credential.raw.decode(),
        aggregate_credential=aggregate_credential.raw.decode(),
        referenced_attributes_credential=referenced_credential.raw.decode(),
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
        assert CORPUS.read_text() == encoded, "credential oracle corpus drift"
    print(json.dumps({"pin": PIN, "cases": [row["case"] for row in rows]}))


if __name__ == "__main__":
    main()
