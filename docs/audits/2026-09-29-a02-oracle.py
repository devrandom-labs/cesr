"""Execute pinned keripy's Kever.update event-kind gate for a real rot body.

Use the pinned de59bc7d source and Python 3.14 dependency environment in
PYTHONPATH. The skeletal Kever has only the fields read before this gate;
the Rust integration tests cover full anchored state and signed wire replay.
"""

import json
from pathlib import Path
from types import SimpleNamespace

from keri.core.eventing import Kever
from keri.core.serdering import SerderKERI
from keri.kering import ValidationError

corpus = Path("crates/keri-codec/tests/corpus/keripy/parity/events.jsonl")
row = next(row for row in map(json.loads, corpus.read_text().splitlines())
           if row["case"] == "rot_simple")
rot = SerderKERI(raw=row["raw"].encode())
assert rot.verify()

state = Kever.__new__(Kever)
state.ndigers = [object()]
state.prefixer = SimpleNamespace(transferable=True, qb64=rot.pre)
state.delegated = True

try:
    state.update(rot, sigers=[])
except ValidationError as error:
    assert "Attempted non delegated rotation" in str(error), str(error)
else:
    raise AssertionError("keripy accepted a plain rot on delegated state")

print("keripy de59bc7d: delegated Kever.update rejects a valid plain rot body")
