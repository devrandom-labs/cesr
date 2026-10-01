"""Pinned keripy de59bc7d Kever.update AID-binding oracle for A04.

Use the pinned Python 3.14 source/dependency environment. The skeletal Kever
reaches only the prefix gate; Rust integration tests exercise full signed-wire
parsing, transition state, contests, and TEL anchors.
"""

import json
from pathlib import Path
from types import SimpleNamespace

from keri.core.eventing import Kever
from keri.core.serdering import SerderKERI
from keri.kering import ValidationError


corpus = Path("crates/keri-codec/tests/corpus/keripy/parity/events.jsonl")
rows = {row["case"]: row["raw"]
        for row in map(json.loads, corpus.read_text().splitlines())}
foreign_pre = json.loads(rows["icp_witnessed"])["i"]

for case in ("ixn_empty", "rot_simple", "drt_simple"):
    event = SerderKERI(raw=rows[case].encode())
    assert event.verify()
    assert event.pre != foreign_pre
    state = Kever.__new__(Kever)
    state.ndigers = [object()]
    state.prefixer = SimpleNamespace(transferable=True, qb64=foreign_pre)
    try:
        state.update(event, sigers=[])
    except ValidationError as error:
        assert "Mismatch event aid prefix" in str(error), (case, str(error))
    else:
        raise AssertionError(f"keripy accepted wrong-identifier {case}")
    print(f"keripy rejects wrong-identifier {case} before event-kind handling")
