"""Execute the A09 JSON wire grammar probes against pinned keripy.

Run with keripy de59bc7d834955c5b0273c62f6b8b6a0df150dc3 on PYTHONPATH.
These are canonical writer/reader observations, not a substitute for the Rust
public-path regressions or a claim that all of RFC 8259 is canonical KERI.
"""

import json
import sys
from pathlib import Path

from keri.core.eventing import exchange
from keri.core.serdering import SerderKERI
from keri.vc.proving import credential


CORPUS = Path(__file__).resolve().parents[2] / "crates/keri-codec/tests/corpus/ipex/happy.jsonl"
PAYLOAD_CORPUS = Path(__file__).resolve().parents[2] / "crates/keri-codec/tests/corpus/json_payload/happy.jsonl"
ACDC_SOURCE = Path(__file__).resolve().parents[2] / "crates/keri-codec/tests/corpus/acdc/happy.jsonl"
ACDC_CORPUS = Path(__file__).resolve().parents[2] / "crates/keri-codec/tests/corpus/json_payload/acdc.jsonl"
seed = json.loads(json.loads(CORPUS.read_text().splitlines()[0])["raw"])


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def version_size(raw):
    """Patch only the V1 version's size to isolate grammar from size errors."""
    old = raw[16:22]
    assert len(old) == 6 and all(c in b"0123456789abcdef" for c in old)
    return raw[:16] + f"{len(raw):06x}".encode() + raw[22:]


cases = {
    "escaped_quote_backslash": {"m": 'A "quote" and \\ slash'},
    "escaped_controls": {"m": "line\nfeed\tend"},
    "raw_utf8": {"m": "snowman ☃ and 🎵"},
    "negative_decimal_exponent": {"m": "number", "neg": -7, "decimal": 1.25, "exp": 1e-7},
    "nested": {"m": "nested", "child": {"x": [True, None, -1.5]}},
    "escaped_key": {"m": "key", 'quote"key': "value"},
}

raws = {}
rows = []
for name, attributes in cases.items():
    exn = exchange(
        sender=seed["i"],
        prior="",
        route="/ipex/agree",
        attributes=attributes,
        stamp=seed["dt"],
    )
    raw = exn.raw
    assert raw == compact(exn.sad), name
    assert SerderKERI(raw=raw).said == exn.said, name
    raws[name] = raw
    rows.append({"case": name, "raw": raw.decode("utf-8"), "message": attributes["m"],
                 "typed_ipex": len(attributes) == 1})
    print(json.dumps({"case": name, "accepted": True, "raw": raw.decode("utf-8")}, ensure_ascii=False))

acdc_seed = json.loads(json.loads(ACDC_SOURCE.read_text().splitlines()[1])["raw"])
acdc_rows = []
for name, data in {
    "acdc_escaped_text": {"dt": seed["dt"], "title": 'A "quote" and \\ slash\nnext'},
    "acdc_numbers_utf8": {"dt": seed["dt"], "title": "snowman ☃ and 🎵",
                          "negative": -7, "decimal": 1.25, "exponent": 1e-7},
}.items():
    acdc = credential(schema=acdc_seed["s"], issuer=acdc_seed["i"], data=data,
                      recipient=acdc_seed["a"]["i"])
    assert acdc.raw == compact(acdc.sad), name
    assert acdc.verify(), name
    acdc_rows.append({"case": name, "raw": acdc.raw.decode("utf-8")})
    print(json.dumps({"case": name, "accepted": True, "raw": acdc.raw.decode("utf-8")}, ensure_ascii=False))

payload_expected = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
acdc_expected = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in acdc_rows)
if "--write" in sys.argv:
    PAYLOAD_CORPUS.parent.mkdir(parents=True, exist_ok=True)
    PAYLOAD_CORPUS.write_text(payload_expected)
    ACDC_CORPUS.write_text(acdc_expected)
else:
    assert PAYLOAD_CORPUS.read_text() == payload_expected, "checked-in EXN payload corpus differs from pinned keripy"
    assert ACDC_CORPUS.read_text() == acdc_expected, "checked-in ACDC payload corpus differs from pinned keripy"

# A JSON parser can decode these spellings, but the pinned KERI writer never
# emits them. The KERI raw reader recomputes the canonical bytes and rejects.
raw = raws["raw_utf8"]
mutations = {
    "escaped_surrogate_pair": raw.replace("🎵".encode(), b"\\ud83c\\udfb5"),
    "duplicate_nested_key": raws["nested"].replace(b'"child":', b'"m":"duplicate","child":'),
    "top_level_order": compact({"v": json.loads(raw)["v"], **{
        key: value for key, value in sorted(json.loads(raw).items()) if key != "v"
    }}),
    "whitespace": raw.replace(b',"e":{}', b', "e":{}'),
    "nonwriter_exponent": raws["negative_decimal_exponent"].replace(b"1e-07", b"1e-7"),
}
for name, mutated in mutations.items():
    mutated = version_size(mutated)
    if name != "top_level_order":
        assert compact(json.loads(mutated)) != mutated, name
    try:
        SerderKERI(raw=mutated)
    except Exception as error:
        print(json.dumps({"case": name, "accepted": False, "error": type(error).__name__}))
    else:
        raise AssertionError(f"pinned raw reader accepted {name}")

# Python's JSON encoder/parser accepts these non-RFC constants and the pinned
# keripy Serder accepts its own output. RFC 8259 section 6 excludes them; Rust
# intentionally rejects them, with an executable case in the A09 suite.
for name, value in (("NaN", float("nan")), ("Infinity", float("inf"))):
    exn = exchange(sender=seed["i"], prior="", route="/ipex/agree",
                   attributes={"m": "non-finite", "n": value}, stamp=seed["dt"])
    assert SerderKERI(raw=exn.raw).said == exn.said
    print(json.dumps({"case": name, "accepted_by_keripy": True,
                      "rfc8259_valid": False}))
