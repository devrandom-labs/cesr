#!/usr/bin/env python3
"""Pinned two-party V1 IPEX factory, signature and pathed-proof transcript."""

import argparse
import json
import os
from pathlib import Path

import keri
from keri.core import Codens, Counter, Pather, SerderACDC, SerderKERI, Signer, eventing
from keri.help import helping
from keri.kering import Kinds, Vrsn_1_0
from keri.vc import protocoling


ROOT = Path(__file__).resolve().parents[1]
PIN = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3"
SOURCE = ROOT / "crates/keri-codec/tests/corpus/credential/v1.jsonl"
CORPUS = ROOT / "crates/keri-codec/tests/corpus/ipex/flow.jsonl"
STAMP = "2026-10-01T00:00:00.000000+00:00"


class Hab:
    """Only pinned protocoling's endorsement host edge, with real signatures."""

    def __init__(self, pre, signer):
        self.pre = pre
        self.signer = signer

    def endorse(self, serder, **_):
        signature = self.signer.sign(ser=serder.raw, index=0)
        return bytearray(
            serder.raw
            + Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0).qb64b
            + signature.qb64b
        )


def fixtures():
    credential = json.loads(SOURCE.read_text().splitlines()[0])
    issuer_key = Signer(raw=bytes([0x34]) * 32, transferable=True)
    holder_key = Signer(raw=bytes([0x35]) * 32, transferable=True)
    issuer_icp = SerderKERI(raw=credential["issuer_icp"].encode())
    holder_icp = SerderKERI(raw=credential["other_issuer_icp"].encode())
    assert issuer_icp.ked["k"] == [issuer_key.verfer.qb64]
    assert holder_icp.ked["k"] == [holder_key.verfer.qb64]
    issuer = Hab(issuer_icp.pre, issuer_key)
    holder = Hab(holder_icp.pre, holder_key)

    vcp = SerderKERI(raw=credential["registry_vcp"].encode())
    iss = SerderKERI(raw=credential["issue_iss"].encode())
    vcp_anchor = eventing.interact(
        pre=issuer.pre, dig=issuer_icp.said, sn=1,
        data=[dict(i=vcp.said, s="0", d=vcp.said)],
        version=Vrsn_1_0, kind=Kinds.json,
    )
    issue_anchor = eventing.interact(
        pre=issuer.pre, dig=vcp_anchor.said, sn=2,
        data=[dict(i=iss.ked["i"], s=iss.ked["s"], d=iss.said)],
        version=Vrsn_1_0, kind=Kinds.json,
    )
    acdc = SerderACDC(raw=credential["credential"].encode())
    acdc_proof = (
        acdc.raw
        + Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0).qb64b
        + issuer_key.sign(ser=acdc.raw, index=0).qb64b
    )
    original_now = helping.nowIso8601
    helping.nowIso8601 = lambda: STAMP
    try:
        apply, apply_atc = protocoling.ipexApplyExn(
            holder, issuer.pre, "Please issue", acdc.sad["s"], {},
        )
        offer, offer_atc = protocoling.ipexOfferExn(
            issuer, "Can issue", acdc_proof, apply=apply,
        )
        agree, agree_atc = protocoling.ipexAgreeExn(
            holder, "I agree", offer,
        )
        grant, grant_atc = protocoling.ipexGrantExn(
            issuer, holder.pre, "Issued", acdc_proof,
            iss=iss.raw, anc=issue_anchor.raw, agree=agree, dt=STAMP,
        )
        admit, admit_atc = protocoling.ipexAdmitExn(
            holder, "Received", grant, dt=STAMP,
        )
        spurn, spurn_atc = protocoling.ipexSpurnExn(
            holder, "Declined", offer,
        )
        wrong_sender_offer, wrong_sender_offer_atc = protocoling.ipexOfferExn(
            holder, "Impersonated issuer", acdc_proof, apply=apply,
        )
        wrong_issuee = SerderACDC(raw=credential["wrong_issuee_credential"].encode())
        wrong_issuee_proof = (
            wrong_issuee.raw
            + Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0).qb64b
            + issuer_key.sign(ser=wrong_issuee.raw, index=0).qb64b
        )
        cross_credential_grant, cross_credential_grant_atc = protocoling.ipexGrantExn(
            issuer, holder.pre, "Different credential", wrong_issuee_proof,
            iss=iss.raw, anc=issue_anchor.raw, agree=agree, dt=STAMP,
        )
        wrong_recipient_grant, wrong_recipient_grant_atc = protocoling.ipexGrantExn(
            issuer, issuer.pre, "Wrong recipient", acdc_proof,
            iss=iss.raw, anc=issue_anchor.raw, agree=agree, dt=STAMP,
        )
        wrong_anchor_grant, wrong_anchor_grant_atc = protocoling.ipexGrantExn(
            issuer, holder.pre, "Wrong anchor", acdc_proof,
            iss=iss.raw, anc=vcp_anchor.raw, agree=agree, dt=STAMP,
        )
        other_apply, _ = protocoling.ipexApplyExn(
            holder, issuer.pre, "Another application", acdc.sad["s"], {},
        )
        cross_conversation_offer, cross_conversation_offer_atc = protocoling.ipexOfferExn(
            issuer, "Other conversation", acdc_proof, apply=other_apply,
        )
        missing_proof_offer, missing_proof_offer_atc = protocoling.ipexOfferExn(
            issuer, "No proof", acdc.raw, apply=apply,
        )
        bad_proof = (
            acdc.raw
            + Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0).qb64b
            + holder_key.sign(ser=acdc.raw, index=0).qb64b
        )
        bad_proof_offer, bad_proof_offer_atc = protocoling.ipexOfferExn(
            issuer, "Wrong proof signer", bad_proof, apply=apply,
        )
    finally:
        helping.nowIso8601 = original_now

    transcript = [
        ("apply", apply, apply_atc, holder),
        ("offer", offer, offer_atc, issuer),
        ("agree", agree, agree_atc, holder),
        ("grant", grant, grant_atc, issuer),
        ("admit", admit, admit_atc, holder),
        ("spurn", spurn, spurn_atc, holder),
        ("wrong_sender_offer", wrong_sender_offer, wrong_sender_offer_atc, holder),
        ("cross_credential_grant", cross_credential_grant, cross_credential_grant_atc, issuer),
        ("wrong_recipient_grant", wrong_recipient_grant, wrong_recipient_grant_atc, issuer),
        ("wrong_anchor_grant", wrong_anchor_grant, wrong_anchor_grant_atc, issuer),
        ("cross_conversation_offer", cross_conversation_offer, cross_conversation_offer_atc, issuer),
        ("missing_proof_offer", missing_proof_offer, missing_proof_offer_atc, issuer),
        ("bad_proof_offer", bad_proof_offer, bad_proof_offer_atc, issuer),
    ]
    rows = []
    for name, exn, attachments, sender in transcript:
        parsed = SerderKERI(raw=exn.raw)
        assert parsed.said == exn.said and parsed.verify(), name
        assert sender.signer.verfer.verify(
            sender.signer.sign(ser=exn.raw, index=0).raw, exn.raw,
        ), name
        rows.append(dict(
            case=name, raw=exn.raw.decode(), wire=(exn.raw + attachments).decode(),
            said=exn.said, sender=sender.pre,
            prior=exn.ked["p"], route=exn.ked["r"],
        ))
    assert rows[1]["prior"] == rows[0]["said"]
    assert rows[2]["prior"] == rows[1]["said"]
    assert rows[3]["prior"] == rows[2]["said"]
    assert rows[4]["prior"] == rows[3]["said"]
    assert rows[5]["prior"] == rows[1]["said"]
    assert Pather(parts=["e", "acdc"]).qb64b in offer_atc
    assert Pather(parts=["e", "acdc"]).qb64b in grant_atc
    rows[0]["issuer_icp"] = issuer_icp.raw.decode()
    rows[0]["holder_icp"] = holder_icp.raw.decode()
    rows[0]["registry_vcp"] = vcp.raw.decode()
    rows[0]["issue_iss"] = iss.raw.decode()
    rows[0]["registry_anchor_ixn"] = vcp_anchor.raw.decode()
    rows[0]["issue_anchor_ixn"] = issue_anchor.raw.decode()
    rows[0]["credential"] = acdc.raw.decode()
    rows[0]["schema"] = credential["schema"]
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
        CORPUS.write_text(encoded)
    else:
        assert CORPUS.read_text() == encoded, "IPEX flow corpus drift"
    print(json.dumps({"pin": PIN, "cases": [row["case"] for row in rows]}))


if __name__ == "__main__":
    main()
