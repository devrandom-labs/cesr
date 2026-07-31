#!/usr/bin/env python3
"""Generate keripy salt-stretch differential vectors (issue #93, K7).

keripy is the oracle. One JSON object per line:
    {"salt_qb64", "path", "cost" ("temp"|"low"), "seed_hex",
     "verkey_qb64", "verkey_nt_qb64"}

Rows cover: empty path, single-hex paths, keripy Manager-style paths
(stem+ridx+kidx per keeping.py:542-544), signify-style paths
("signify:aid" stem per signify-ts keeping.ts:312), and a long path.
`temp` rows exercise the vector-speed cost (opslimit 1, memlimit 8 KiB);
two `low` rows pin the real libsodium interactive parameters
(opslimit 2, memlimit 64 MiB).

Deterministic: fixed salt raw, no OS randomness.
Pin: scripts/KERIPY_PIN.
"""
import json
import sys
from pathlib import Path

from keri.core.signing import Salter

RAW = b"0123456789abcdef"
PATHS = [
    "",
    "0",
    "00",
    "000",
    "001",
    "01f",
    "signify:aid00",
    "signify:aid12",
    "a-very-long-derivation-path-for-boundary-coverage-0123456789",
]


def row(salter, path, cost):
    temp = cost == "temp"
    tier = None if temp else "low"
    seed = salter.stretch(size=32, path=path, tier=tier, temp=temp)
    signer = salter.signer(path=path, tier=tier, temp=temp, transferable=True)
    signer_nt = salter.signer(path=path, tier=tier, temp=temp, transferable=False)
    return {
        "salt_qb64": salter.qb64,
        "path": path,
        "cost": cost,
        "seed_hex": seed.hex(),
        "verkey_qb64": signer.verfer.qb64,
        "verkey_nt_qb64": signer_nt.verfer.qb64,
    }


def main():
    out = Path(sys.argv[1])
    salter = Salter(raw=RAW)
    rows = [row(salter, p, "temp") for p in PATHS]
    rows += [row(salter, p, "low") for p in ["", "000"]]
    out.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    print(f"wrote {len(rows)} vectors to {out}")


if __name__ == "__main__":
    main()
