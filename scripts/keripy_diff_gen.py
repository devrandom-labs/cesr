#!/usr/bin/env python3
"""Generate the keripy differential-test corpus (JSONL) from keripy.

Tier-2 of the P0.3 differential-testing harness (issue #27). keripy is the
oracle: for every code table it enumerates codes, constructs primitives with a
deterministic-random raw payload (and a boundary sweep for counter counts /
indexer indices), and emits one JSON object per line capturing the structured
fields plus keripy's exact ``qb64`` / ``qb2`` bytes. The cesr side replays this
corpus hermetically in ``src/keripy_diff/`` and asserts byte-for-byte agreement.

Deterministic given ``--seed``: no wall-clock, no OS randomness. keripy is
imported from the environment (pip-installed) or from ``--keripy <checkout>/src``.

Pin: keripy v2.0.0.dev5.
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


def gen_matter(rng, Matter, MtrDex, out):
    written = 0
    with (out / "matter.jsonl").open("w") as fh:
        for _name, code in codes(MtrDex):
            sizes = Matter.Sizes.get(code)
            if sizes is None or sizes.fs is None:
                continue  # variable-size codes are out of scope for the seed sweep
            try:
                raw = rand_raw(rng, Matter._rawSize(code))
                m = Matter(raw=raw, code=code)
                row = {
                    "kind": "matter",
                    "code": code,
                    "raw": m.raw.hex(),
                    "soft": getattr(m, "soft", "") or "",
                    "qb64": m.qb64,
                    "qb2": m.qb2.hex(),
                }
            except Exception:
                continue  # placeholder / non-constructible code — skip
            emit(fh, row)
            written += 1
    return written


def gen_counter(rng, Counter, dex, version, fname, out):
    written = 0
    sweep = [0, 1, 4094, 4095, 4096, 100000, rng.randrange(1, 4096)]
    with (out / fname).open("w") as fh:
        for _name, code in codes(dex):
            for count in sweep:
                try:
                    c = Counter(code=code, count=count, version=version)
                    row = {
                        "kind": "counter",
                        "code": code,
                        "count": count,
                        "qb64": c.qb64,
                        "qb2": c.qb2.hex(),
                    }
                except Exception:
                    continue
                emit(fh, row)
                written += 1
    return written


def gen_indexer(rng, Indexer, IdrDex, out):
    written = 0
    with (out / "indexer.jsonl").open("w") as fh:
        for _name, code in codes(IdrDex):
            sizes = Indexer.Sizes.get(code)
            if sizes is None or sizes.fs is None:
                continue
            try:
                raw = rand_raw(rng, Indexer._rawSize(code))
            except Exception:
                continue
            # index sweep; for dual-index ("Both", os > 0) codes also a distinct ondex.
            trials = [(0, None), (1, None), (63, None)]
            if sizes.os > 0:
                trials.append((1, 2))
            for index, ondex in trials:
                try:
                    ix = Indexer(raw=raw, code=code, index=index, ondex=ondex)
                    row = {
                        "kind": "indexer",
                        "code": code,
                        "raw": ix.raw.hex(),
                        "index": ix.index,
                        "ondex": ix.ondex,
                        "qb64": ix.qb64,
                        "qb2": ix.qb2.hex(),
                    }
                except Exception:
                    continue
                emit(fh, row)
                written += 1
    return written


def gen_stream(rng, Counter, Indexer, IdrDex, version, out):
    """A V1 ControllerIdxSigs group: a ``-A`` counter frame over N Ed25519 sigs.

    ``-A`` counts elements, so ``count`` == number of signatures, which the cesr
    replay asserts directly.
    """
    code = IdrDex.Ed25519_Sig
    raw_size = Indexer._rawSize(code)
    sigs = [Indexer(raw=rand_raw(rng, raw_size), code=code, index=i) for i in range(2)]
    ctr = Counter(code="-A", count=len(sigs), version=version)
    qb64 = ctr.qb64 + "".join(s.qb64 for s in sigs)
    qb2 = ctr.qb2 + b"".join(s.qb2 for s in sigs)
    with (out / "stream.jsonl").open("w") as fh:
        emit(fh, {
            "kind": "stream",
            "code": ctr.code,
            "count": len(sigs),
            "qb64": qb64,
            "qb2": qb2.hex(),
            "elements": [{
                "kind": "indexer",
                "code": code,
                "raw": s.raw.hex(),
                "index": s.index,
                "ondex": s.ondex,
                "qb64": s.qb64,
                "qb2": s.qb2.hex(),
            } for s in sigs],
        })
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is prepended to "
                         "sys.path); omit if keripy is already importable")
    ap.add_argument("--out", required=True, type=Path, help="corpus output directory")
    ap.add_argument("--seed", type=int, default=42, help="PRNG seed (deterministic corpus)")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    from keri.core.coring import Matter, MtrDex
    from keri.core import counting
    from keri.core.indexing import Indexer, IdrDex

    args.out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)

    n = {
        "matter": gen_matter(rng, Matter, MtrDex, args.out),
        "counter_v1": gen_counter(rng, counting.Counter, counting.CtrDex_1_0,
                                  counting.Vrsn_1_0, "counter_v1.jsonl", args.out),
        "counter_v2": gen_counter(rng, counting.Counter, counting.CtrDex_2_0,
                                  counting.Vrsn_2_0, "counter_v2.jsonl", args.out),
        "indexer": gen_indexer(rng, Indexer, IdrDex, args.out),
        "stream": gen_stream(rng, counting.Counter, Indexer, IdrDex, counting.Vrsn_1_0, args.out),
    }
    for kind, count in n.items():
        print(f"{kind}: {count} vectors", file=sys.stderr)


if __name__ == "__main__":
    main()
