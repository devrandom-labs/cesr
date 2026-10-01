"""Compare the IPEX happy corpus to the pinned keripy EXN factories.

Run with keripy de59bc7d834955c5b0273c62f6b8b6a0df150dc3 on PYTHONPATH.
The deterministic inputs come from the checked-in Rust corpus; the expected
bytes are recomputed by actual keripy exchange/specialExchange functions.
"""

import json
from pathlib import Path

from keri.core.eventing import exchange
from keri.peer.exchanging import specialExchange


CORPUS = Path(__file__).resolve().parents[2] / "crates/keri-codec/tests/corpus/ipex/happy.jsonl"


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


for line in CORPUS.read_text().splitlines():
    row = json.loads(line)
    expected = row["raw"].encode("utf-8")
    sad = json.loads(expected)
    args = dict(
        sender=sad["i"],
        prior=sad["p"],
        route=sad["r"],
        attributes=sad["a"],
        stamp=sad["dt"],
    )
    if row["case"] in ("offer", "grant", "grant_minimal"):
        embeds = {key: compact(value) for key, value in sad["e"].items() if key != "d"}
        actual, _ = specialExchange(**args, embeds=embeds)
    else:
        actual = exchange(**args)
    assert actual.raw == expected, (
        row["case"],
        actual.raw.decode("utf-8"),
        expected.decode("utf-8"),
    )
    print(json.dumps({"case": row["case"], "said": actual.said, "matched": True}))
