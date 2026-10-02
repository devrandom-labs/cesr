#!/usr/bin/env python3
"""Check IPEX corpus against pinned exchange and protocoling behavior."""

import base64
import hashlib
import json
import os
from pathlib import Path

import keri
from keri.core import Saider, SerderACDC, SerderKERI, Signer
from keri.core.eventing import exchange
from keri.help import helping
from keri.peer.exchanging import specialExchange
from keri.vc import protocoling


ROOT = Path(__file__).resolve().parents[1]
PIN = "de59bc7d834955c5b0273c62f6b8b6a0df150dc3"
CASES = ("apply", "offer", "agree", "grant", "grant_minimal", "admit", "spurn")
CORPUS = ROOT / "crates/keri-codec/tests/corpus/ipex"


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def rows(name):
    found = [json.loads(line) for line in (CORPUS / name).read_text().splitlines()]
    assert tuple(row["case"] for row in found) == CASES, name
    assert all(row["raw"] and row["route"] for row in found), name
    return {row["case"]: row for row in found}


class Hab:
    """Only the host endorsement boundary needed by protocoling factories."""

    def __init__(self, pre):
        self.pre = pre

    def endorse(self, serder, **_):
        return bytearray(serder.raw)


class ReplyIndex:
    def get(self, keys):
        return None


class Host:
    def __init__(self):
        self.db = type("DB", (), {"erpy": ReplyIndex()})()


def protocoling_bodies(sad):
    hab = Hab(sad["apply"]["i"])
    stamp = sad["apply"]["dt"]
    original_now = helping.nowIso8601
    helping.nowIso8601 = lambda: stamp
    try:
        apply, _ = protocoling.ipexApplyExn(
            hab, sad["apply"]["a"]["i"], sad["apply"]["a"]["m"],
            sad["apply"]["a"]["s"], sad["apply"]["a"]["a"])
        offer, _ = protocoling.ipexOfferExn(
            hab, sad["offer"]["a"]["m"], compact(sad["offer"]["e"]["acdc"]))
        agree, _ = protocoling.ipexAgreeExn(hab, sad["agree"]["a"]["m"], offer)
        grant, _ = protocoling.ipexGrantExn(
            hab, sad["grant"]["a"]["i"], sad["grant"]["a"]["m"],
            compact(sad["grant"]["e"]["acdc"]),
            iss=compact(sad["grant"]["e"]["iss"]),
            anc=compact(sad["grant"]["e"]["anc"]), agree=agree,
            dt=sad["grant"]["dt"])
        minimal, _ = protocoling.ipexGrantExn(
            hab, sad["grant_minimal"]["a"]["i"],
            sad["grant_minimal"]["a"]["m"],
            compact(sad["grant_minimal"]["e"]["acdc"]), agree=agree,
            dt=sad["grant_minimal"]["dt"])
        admit, _ = protocoling.ipexAdmitExn(
            hab, sad["admit"]["a"]["m"], grant, dt=sad["admit"]["dt"])
        spurn, _ = protocoling.ipexSpurnExn(
            hab, sad["spurn"]["a"]["m"], offer)
    finally:
        helping.nowIso8601 = original_now
    return dict(zip(CASES, (apply, offer, agree, grant, minimal, admit, spurn)))


def main():
    assert (ROOT / "scripts/KERIPY_PIN").read_text().strip() == PIN
    checkout = Path(os.environ["KERIPY_CHECKOUT"]).resolve()
    assert Path(keri.__file__).resolve().is_relative_to(checkout), keri.__file__
    print(json.dumps({"pin": PIN, "imported_keri": str(Path(keri.__file__).resolve())},
                     sort_keys=True))
    happy = rows("happy.jsonl")
    signed = rows("signed.jsonl")
    sad = {name: json.loads(happy[name]["raw"]) for name in CASES}
    made = protocoling_bodies(sad)
    signer = Signer(raw=hashlib.sha256(b"keripy-ipex-parity:sender").digest())
    for name in CASES:
        expected = happy[name]["raw"].encode()
        body = sad[name]
        args = dict(sender=body["i"], prior=body["p"], route=body["r"],
                    attributes=body["a"], stamp=body["dt"])
        if name in ("offer", "grant", "grant_minimal"):
            embeds = {key: compact(value) for key, value in body["e"].items()
                      if key != "d"}
            factory, _ = specialExchange(**args, embeds=embeds)
        else:
            factory = exchange(**args)
        assert factory.raw == expected, (name, "exchange")
        assert made[name].raw == expected, (name, "protocoling")
        reader = SerderKERI(raw=expected)
        assert reader.raw == expected and reader.verify(), name
        embedded = body["e"]
        if "d" in embedded:
            assert Saider(qb64=embedded["d"]).verify(
                embedded, prefixed=True, versioned=False), name
        for label, block in embedded.items():
            if label == "d":
                continue
            embedded_raw = compact(block)
            (SerderACDC if label == "acdc" else SerderKERI)(raw=embedded_raw)
        row = signed[name]
        sig = signer.sign(ser=expected, index=0)
        assert row["raw"].encode() == expected, name
        assert row["sig_qb64"] == sig.qb64, name
        assert base64.b64decode(row["vk_b64"]) == signer.verfer.raw, name
        assert signer.verfer.verify(sig.raw, expected), name
        print(json.dumps({"case": name, "route": body["r"], "said": reader.said,
                          "factory_bytes": "match", "protocoling_bytes": "match",
                          "embedded_reader": "match", "signature": "match"},
                         sort_keys=True))

    # Exercise actual protocoling route gates with only the host lookup
    # boundary supplied. Conversation persistence/authorization remains A28.
    prior = {event.said: event for event in made.values()}
    host = Host()
    original_clone = protocoling.cloneMessage
    protocoling.cloneMessage = lambda _hby, said=None: (prior.get(said), None)
    try:
        for name in CASES:
            handler = protocoling.IpexHandler(sad[name]["r"], host, None)
            assert handler.verify(made[name]), (name, "route rejected")
        wrong_prior = exchange(
            sender=sad["agree"]["i"], prior=made["apply"].said,
            route="/ipex/agree", attributes=sad["agree"]["a"],
            stamp=sad["agree"]["dt"])
        assert not protocoling.IpexHandler("/ipex/agree", host, None).verify(wrong_prior)
        missing_prior = exchange(
            sender=sad["admit"]["i"], prior="", route="/ipex/admit",
            attributes=sad["admit"]["a"], stamp=sad["admit"]["dt"])
        assert not protocoling.IpexHandler("/ipex/admit", host, None).verify(missing_prior)
    finally:
        protocoling.cloneMessage = original_clone
    print(json.dumps({"protocoling_verdicts": "7 accepted, 2 rejected"}))


if __name__ == "__main__":
    main()
