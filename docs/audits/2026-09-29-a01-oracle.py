"""A01 negative semantic probes against pinned keripy SerderKERI.

Run with the keripy `de59bc7d` source and its Python 3.14 dependencies on
PYTHONPATH. This keeps the generated attack bodies SAID-valid before checking
the identifier rules.
"""

import json
from pathlib import Path

from keri.core.coring import Saider
from keri.core.serdering import SerderKERI
from keri.kering import ValidationError


corpus = Path("crates/keri-codec/tests/corpus/keripy/parity/events.jsonl")
rows = {row["case"]: row for row in map(json.loads, corpus.read_text().splitlines())}


def reseal(sad):
    _, updated = Saider.saidify(sad=sad)
    assert Saider(qb64=updated["d"]).verify(sad=updated)
    raw = json.dumps(updated, separators=(",", ":")).encode()
    assert len(raw) == int(updated["v"][10:16], 16)
    return raw


def rejects(raw, phrase):
    try:
        SerderKERI(raw=raw, verify=False)._verify()
    except ValidationError as error:
        assert phrase in str(error), str(error)
    else:
        raise AssertionError(f"keripy accepted {phrase}")


basic = json.loads(rows["icp_basic_single"]["raw"])
self_addressing = json.loads(rows["icp_multisig_simple"]["raw"])
dip = json.loads(rows["dip_basic"]["raw"])
assert SerderKERI(raw=rows["icp_basic_single"]["raw"].encode()).verify()
assert SerderKERI(raw=rows["icp_multisig_simple"]["raw"].encode()).verify()

unrelated_key = dict(basic, k=[self_addressing["k"][1]])
rejects(reseal(unrelated_key), "Mismatch prefix")

two_keys = dict(basic, k=[basic["k"][0], self_addressing["k"][1]])
rejects(reseal(two_keys), "Invalid keys")

wrong_threshold = dict(basic, kt="2")
rejects(reseal(wrong_threshold), "Invalid signing threshold")

basic_dip = dict(dip, i=basic["i"])
rejects(reseal(basic_dip), "Invalid identifier prefix code")

print("keripy de59bc7d: 2 valid controls and 4 SAID-valid attacks checked")
