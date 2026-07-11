#!/usr/bin/env python3
"""Generate the keripy parity corpus: codex / formulas / validation (issue #151).

The "missing middle" between primitive byte-diffing (keripy_diff) and the
event-wire corpus (#145). keripy is the oracle:

- codex.jsonl      — every entry of TraitDex, DigDex, PreDex, Ilks, and the
                     seal shapes in structing.py, introspected (not hardcoded),
                     with a constructible qb64/sample per entry.
- formulas.jsonl   — ample(n, weak) for n in 0..=256, plus Tholder.satisfy
                     verdicts for a curated sith/indices case list.
- validation.jsonl — factory rejection matrix: each case is EXECUTED against
                     the keripy factory at generation time and must raise
                     (control_valid rows must not), so every row is a verified
                     keripy fact, not a source-reading guess.

Rows cesr deliberately does not implement carry a `divergence` marker here
(permanent knowledge lives in the corpus); temporarily-open gaps (#149, #150)
are tracked on the Rust side so they burn down without regenerating vectors.

Deterministic given --seed. Pin: the commit recorded in scripts/KERIPY_PIN.
"""
import argparse
import json
import random
import sys
from pathlib import Path


def emit(fh, obj):
    fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


def rand_raw(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def codes(dex):
    """Yield (name, code) for every public string member of a keripy codex."""
    for name, code in sorted(vars(dex).items()):
        if not name.startswith("_") and isinstance(code, str):
            yield name, code


# --- divergence maps: permanent, deliberate non-goals (ledger-backed) --------

# cesr scope is the KERI KEL core; registry (TEL), ACDC, and exchange/disclosure
# ilks are out of scope.
KEL_CORE_ILKS = {"icp", "rot", "ixn", "dip", "drt", "rct", "qry", "rpy", "exn"}
ILK_DIVERGENCE = "non-KEL-core ilk (TEL/ACDC/exchange) — out of cesr scope (KERI KEL core only); see docs/keripy-parity/ledger.md"

# PreDex codes whose curve crates are deliberately deferred (RustCrypto
# stable-generation policy). Populate from the first sweep run's triage
# (Task B5) — start empty so gaps are DISCOVERED, not presumed.
PRE_DIVERGENCE = {}


def gen_codex(rng, out):
    from keri.kering import TraitDex, Ilks
    from keri.core.coring import DigDex, PreDex, Matter, Diger
    from keri.core import structing

    sample_pre = Matter(raw=bytes(32), code=PreDex.Ed25519N).qb64
    sample_dig = Diger(ser=b"keripy-parity-seal", code=DigDex.Blake3_256).qb64
    seal_field_samples = {
        "d": sample_dig, "rd": sample_dig, "i": sample_pre,
        "bi": sample_pre, "s": "0", "t": "icp",
    }

    written = 0
    with (out / "codex.jsonl").open("w") as fh:
        for name, code in codes(TraitDex):
            emit(fh, {"kind": "codex", "family": "trait", "name": name, "code": code})
            written += 1
        for name, code in codes(DigDex):
            qb64 = Diger(ser=rand_raw(rng, 16), code=code).qb64
            emit(fh, {"kind": "codex", "family": "dig", "name": name,
                      "code": code, "qb64": qb64})
            written += 1
        for name, code in codes(PreDex):
            qb64 = Matter(raw=bytes(Matter._rawSize(code)), code=code).qb64
            row = {"kind": "codex", "family": "pre", "name": name,
                   "code": code, "qb64": qb64}
            if name in PRE_DIVERGENCE:
                row["divergence"] = PRE_DIVERGENCE[name]
            emit(fh, row)
            written += 1
        for name in Ilks._fields:
            code = getattr(Ilks, name)
            row = {"kind": "codex", "family": "ilk", "name": name, "code": code}
            if code not in KEL_CORE_ILKS:
                row["divergence"] = ILK_DIVERGENCE
            emit(fh, row)
            written += 1
        for name in sorted(dir(structing)):
            obj = getattr(structing, name)
            if (isinstance(obj, type) and issubclass(obj, tuple)
                    and hasattr(obj, "_fields") and name.startswith("Seal")):
                sample = {f: seal_field_samples[f] for f in obj._fields}
                emit(fh, {"kind": "codex", "family": "seal", "name": name,
                          "fields": list(obj._fields), "sample": sample})
                written += 1
    return written


# Curated satisfy cases: (sith-as-JSON-value, indices). Includes duplicate
# indices on purpose — keripy vs cesr dedup semantics is exactly the class of
# divergence this gate exists to surface.
THOLDER_CASES = [
    (1, []), (1, [0]), (2, [0]), (2, [0, 1]), (2, [0, 0]),
    (3, [0, 1, 2]), (3, [0, 1]), ("2", [0, 1]), ("2", [5, 9]),
    (["1/2", "1/2", "1/4"], [0, 1]), (["1/2", "1/2", "1/4"], [0]),
    (["1/2", "1/2", "1/4"], [0, 2]), (["1/2", "1/2", "1/4"], [0, 1, 2]),
    (["1"], [0]), (["1"], []),
    ([["1/2", "1/2"], ["1"]], [0, 1]), ([["1/2", "1/2"], ["1"]], [0, 1, 2]),
    ([["1/2", "1/2"], ["1"]], [2]), ([["1/2", "1/2"], ["1"]], [0, 2]),
]


def gen_formulas(out):
    from keri.core.eventing import ample
    from keri.core.coring import Tholder

    written = 0
    with (out / "formulas.jsonl").open("w") as fh:
        for n in range(257):
            for weak in (True, False):
                row = {"kind": "formula", "formula": "ample", "n": n, "weak": weak}
                try:
                    row["m"] = ample(n, weak=weak)
                except Exception as e:
                    row["m"] = None
                    row["error"] = type(e).__name__
                emit(fh, row)
                written += 1
        for sith, indices in THOLDER_CASES:
            t = Tholder(sith=sith)
            emit(fh, {"kind": "formula", "formula": "tholder_satisfy",
                      "sith": sith, "indices": indices,
                      "satisfies": bool(t.satisfy(indices=indices))})
            written += 1
    return written


def gen_validation(rng, out):
    from keri.core import eventing
    from keri.core.coring import MtrDex, Matter, Diger
    from keri.kering import Kinds

    def vkey():
        return Matter(raw=rand_raw(rng, 32), code=MtrDex.Ed25519).qb64

    def wit():
        return Matter(raw=rand_raw(rng, 32), code=MtrDex.Ed25519N).qb64

    def dig():
        return Diger(ser=rand_raw(rng, 16), code=MtrDex.Blake3_256).qb64

    k1, k2 = vkey(), vkey()
    w1, w2, w3 = wit(), wit(), wit()
    n1 = dig()
    # pre/delpre must be TRANSFERABLE: SerderKERI._verify rejects rot with
    # non-empty `n` from a non-transferable prefix code, and a KERI delegator
    # must itself be able to rotate. A delegatee prefix (dip/drt) must further
    # be DIGESTIVE (code in DigDex) per SerderKERI._verify, hence digpre.
    pre, delpre, prior = vkey(), vkey(), dig()
    digpre = dig()

    # (factory, case, kwargs, rust_static). kwargs use the kwarg names verified
    # against the pin (Step B2.1). rust_static marks cases unrepresentable in
    # cesr's typed builder API (permanent — ledger-backed); None means
    # representable. Note: at the pin, deltate is rotate(ilk=drt) and takes NO
    # delpre kwarg — drt events carry no delegator field (it binds at dip).
    CASES = [
        ("incept", "control_valid",
         dict(keys=[k1, k2], ndigs=[n1], wits=[w1, w2], toad=2), None),
        ("incept", "sith_zero", dict(keys=[k1], isith="0"), None),
        ("incept", "sith_exceeds_keys", dict(keys=[k1], isith="2"), None),
        ("incept", "nsith_exceeds_ndigs",
         dict(keys=[k1], ndigs=[n1], nsith="2"), None),
        ("incept", "dup_wits", dict(keys=[k1], wits=[w1, w1], toad=1), None),
        ("incept", "toad_gt_wits", dict(keys=[k1], wits=[w1, w2], toad=3), None),
        ("incept", "toad_zero_with_wits", dict(keys=[k1], wits=[w1], toad=0), None),
        ("incept", "toad_nonzero_no_wits", dict(keys=[k1], wits=[], toad=1), None),
        ("incept", "cnfg_not_list", dict(keys=[k1], cnfg="EO"),
         "config is Vec<ConfigTrait>; a non-list is unrepresentable"),
        ("incept", "data_not_list", dict(keys=[k1], data={"d": "x"}),
         "anchors is Vec<Seal>; a non-list is unrepresentable"),
        ("rotate", "control_valid",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, ndigs=[n1]), None),
        ("rotate", "sn_zero", dict(pre=pre, keys=[k1], dig=prior, sn=0), None),
        ("rotate", "sith_exceeds_keys",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, isith="2"), None),
        ("rotate", "dup_wits_prior",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, wits=[w1, w1], toad=1), None),
        ("rotate", "dup_cuts",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, wits=[w1, w2],
              cuts=[w1, w1], toad=1), None),
        ("rotate", "dup_adds",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, adds=[w3, w3], toad=1), None),
        ("rotate", "cut_not_in_wits",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, wits=[w1], cuts=[w2], toad=0),
         None),
        ("rotate", "add_already_in_wits",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, wits=[w1], adds=[w1], toad=2),
         None),
        ("rotate", "cut_add_intersect",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, wits=[w1, w2], cuts=[w1],
              adds=[w1], toad=1), None),
        ("rotate", "toad_gt_new_wits",
         dict(pre=pre, keys=[k1], dig=prior, sn=1, wits=[w1], toad=5), None),
        ("interact", "control_valid", dict(pre=pre, dig=prior, sn=1), None),
        ("interact", "sn_zero", dict(pre=pre, dig=prior, sn=0), None),
        ("interact", "data_not_list",
         dict(pre=pre, dig=prior, sn=1, data={"x": 1}),
         "anchors is Vec<Seal>; a non-list is unrepresentable"),
        ("delcept", "control_valid",
         dict(keys=[k1], delpre=delpre, ndigs=[n1]), None),
        ("delcept", "dup_wits",
         dict(keys=[k1], delpre=delpre, wits=[w1, w1], toad=1), None),
        ("deltate", "control_valid",
         dict(pre=digpre, keys=[k1], dig=prior, sn=1, ndigs=[n1]), None),
        ("deltate", "sn_zero",
         dict(pre=digpre, keys=[k1], dig=prior, sn=0), None),
    ]

    # Normalize keripy kwargs → the canonical params schema the Rust replay
    # reads: list fields always present, scalars nullable.
    def normalize(kw):
        return {
            "keys": kw.get("keys", []),
            "sith": kw.get("isith"),
            "ndigs": kw.get("ndigs", []),
            "nsith": kw.get("nsith"),
            "wits": kw.get("wits", []) if isinstance(kw.get("wits", []), list) else [],
            "toad": kw.get("toad"),
            "cuts": kw.get("cuts", []),
            "adds": kw.get("adds", []),
            "sn": kw.get("sn"),
            "delpre": kw.get("delpre"),
        }

    written = 0
    with (out / "validation.jsonl").open("w") as fh:
        for factory_name, case, kwargs, static in CASES:
            factory = getattr(eventing, factory_name)
            err = None
            try:
                # kind is pinned to JSON: keripy's default kind='CESR' raises
                # KindError for protocol v1 before any field validation runs.
                factory(kind=Kinds.json, **kwargs)
            except Exception as e:
                err = e
            if case.startswith("control"):
                assert err is None, f"{factory_name}/{case} raised: {err!r}"
            else:
                assert err is not None, f"{factory_name}/{case} did not raise"
            row = {"kind": "validation", "factory": factory_name, "case": case,
                   "params": normalize(kwargs),
                   "raises": type(err).__name__ if err else None,
                   "message": str(err) if err else ""}
            if static:
                row["rust_static"] = static
            emit(fh, row)
            written += 1
    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is "
                         "prepended to sys.path); omit if importable")
    ap.add_argument("--out", required=True, type=Path,
                    help="corpus output directory (…/corpus/keripy/parity)")
    ap.add_argument("--seed", type=int, default=42, help="PRNG seed")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    args.out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)

    n = {
        "codex": gen_codex(rng, args.out),
        "formulas": gen_formulas(args.out),
        "validation": gen_validation(rng, args.out),
    }
    for kind, count in n.items():
        print(f"{kind}: {count} vectors", file=sys.stderr)


if __name__ == "__main__":
    main()
