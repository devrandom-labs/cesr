#!/usr/bin/env python3
"""Generate keripy custody differential vectors (issue #93, K7).

keripy is the oracle. One JSON object with:
    {"oracle": "manager"|"salter-formula", "salt_qb64", "tier": "low",
     "steps": [{"op": "incept"|"rotate", "count", "ncount",
                "verkeys": [qb64...], "digers": [qb64...]}]}

Sequence: incept(1,1) -> rotate(1,2) -> rotate(2,1) at tier low,
temp=False, stem default (pidx 0). Deterministic: fixed salt.

Oracle preference: keripy Manager (real custody stack, temp LMDB via
keeping.openKS()); falls back to Salter + the source-cited path formula
(keeping.py:542-544, 1019-1030) if the Manager path is broken at the pin.
Pin: scripts/KERIPY_PIN.
"""
import json
import sys
from pathlib import Path

from keri.core.signing import Salter

RAW = b"0123456789abcdef"
SEQUENCE = [("incept", 1, 1), ("rotate", 1, 2), ("rotate", 2, 1)]


def via_manager():
    from keri.app import keeping

    with keeping.openKS() as ks:
        salter = Salter(raw=RAW)
        mgr = keeping.Manager(ks=ks, salt=salter.qb64)
        steps = []
        verfers, digers = mgr.incept(
            icount=1, ncount=1, salt=salter.qb64, tier="low", temp=False,
            transferable=True,
        )
        pre = verfers[0].qb64
        steps.append({
            "op": "incept", "count": 1, "ncount": 1,
            "verkeys": [v.qb64 for v in verfers],
            "digers": [d.qb64 for d in digers],
        })
        for _, count, ncount in SEQUENCE[1:]:
            verfers, digers = mgr.rotate(pre=pre, ncount=ncount, temp=False)
            steps.append({
                "op": "rotate", "count": count, "ncount": ncount,
                "verkeys": [v.qb64 for v in verfers],
                "digers": [d.qb64 for d in digers],
            })
        return {
            "oracle": "manager", "salt_qb64": salter.qb64,
            "tier": "low", "steps": steps,
        }


def via_salter_formula():
    """Path math from keeping.py:542-544 / 1019-1030 at the pin."""
    from keri.core.coring import Diger

    salter = Salter(raw=RAW)
    pidx = 0
    ridx, kidx, count = 0, 0, 0
    steps = []
    for op, ccount, ncount_new in SEQUENCE:
        if op == "incept":
            ridx, kidx, count = 0, 0, ccount
        else:
            ridx, kidx = ridx + 1, kidx + count
            count = ccount
        stem = f"{pidx:x}"
        signers = [
            salter.signer(path=f"{stem}{ridx:x}{kidx + i:x}",
                          tier="low", temp=False, transferable=True)
            for i in range(count)
        ]
        nsigners = [
            salter.signer(path=f"{stem}{ridx + 1:x}{kidx + count + i:x}",
                          tier="low", temp=False, transferable=True)
            for i in range(ncount_new)
        ]
        steps.append({
            "op": op, "count": count, "ncount": ncount_new,
            "verkeys": [s.verfer.qb64 for s in signers],
            "digers": [Diger(ser=s.verfer.qb64b).qb64 for s in nsigners],
        })
    return {
        "oracle": "salter-formula", "salt_qb64": salter.qb64,
        "tier": "low", "steps": steps,
    }


def main():
    out = Path(sys.argv[1])
    try:
        data = via_manager()
    except Exception as ex:  # pin breakage — fall back, but say so loudly
        print(f"manager oracle unavailable ({ex!r}); using salter formula",
              file=sys.stderr)
        data = via_salter_formula()
    out.write_text(json.dumps(data, indent=1) + "\n")
    print(f"oracle={data['oracle']} steps={len(data['steps'])} -> {out}")


if __name__ == "__main__":
    main()
