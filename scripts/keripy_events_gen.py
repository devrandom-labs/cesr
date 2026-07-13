#!/usr/bin/env python3
"""Generate the keripy event-wire corpus: full-breadth scenario matrix (issue #145).

keripy is the oracle. This builds every KEL event shape keripy emits at the
pin — all 5 ilks, basic AND self-addressing derivations, simple/weighted/
multi-clause thresholds, intive on and off, witnesses with br/ba and toad at
boundaries, every TraitDex config trait, and seal anchors — and emits ONE JSON
object per scenario capturing the raw wire bytes (as a JSON string, like
seal_events.jsonl). cesr must (1) deserialize every record cleanly and
(2) re-serialize it byte-identically, except rows marked reserialize="blocked"
(the intive integer-threshold write gap, tracked in events.rs).

No signing, no DB: read + byte-identity are pure serializer facts. Prior
events for rot/ixn/drt reuse a genesis icp's pre/said so chaining fields are
real keripy values, not synthetic.

Deterministic: fixed salt, no wall-clock, no OS randomness.
Pin: keripy v2.0.0.dev5-1030-gde59bc7d, KERI/CESR V1 JSON (KERI10JSON).
"""
import argparse
import json
import sys
from pathlib import Path

KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"


def emit(fh, obj):
    fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is prepended "
                         "to sys.path); omit if keripy is already importable")
    ap.add_argument("--out", required=True, type=Path,
                    help="output directory (events.jsonl is written here)")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    from keri.core.coring import Diger, Kinds
    from keri.core.eventing import incept, interact, rotate
    from keri.core.signing import Salter
    from keri.core.counting import Vrsn_1_0
    from keri.kering import Ilks, TraitDex

    salt = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"
    signers = Salter(raw=salt).signers(count=6, transferable=True, temp=True)
    wsigners = Salter(raw=salt).signers(count=3, transferable=False, temp=True)

    def keys(a, b):
        return [s.verfer.qb64 for s in signers[a:b]]

    def ndigs(a, b):
        return [Diger(ser=s.verfer.qb64b).qb64 for s in signers[a:b]]

    wits = [w.verfer.qb64 for w in wsigners]
    J = dict(kind=Kinds.json, version=Vrsn_1_0)

    seal = {"i": signers[0].verfer.qb64,
            "s": "0",
            "d": Diger(ser=b"anchor").qb64}

    # A self-addressing genesis to source pre/dig for rot/ixn/drt scenarios.
    base = incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), nsith="2", **J)
    pre, dig = base.pre, base.said

    # A delegator prefix for dip/drt.
    delg = incept(keys=keys(0, 1), **J)

    rows = []  # (case, ilk, derivation, serder, blocked)

    def add(case, ilk, derivation, serder, blocked=False):
        rows.append((case, ilk, derivation, serder, blocked))

    # --- icp ---------------------------------------------------------------
    add("icp_basic_single", "icp", "basic",
        incept(keys=keys(0, 1), ndigs=ndigs(1, 2), **J))
    add("icp_multisig_simple", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), nsith="2", **J))
    add("icp_weighted", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=["1/2", "1/2", "1"], ndigs=ndigs(3, 6),
               nsith=["1/2", "1/2", "1"], **J))
    add("icp_weighted_multiclause", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=[["1/2", "1/2"], ["1"]], ndigs=ndigs(3, 6),
               nsith=[["1/2", "1/2"], ["1"]], **J))
    add("icp_witnessed", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits, toad=2, **J))
    add("icp_witnessed_toad_max", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits, toad=3, **J))
    add("icp_config_estonly", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               cnfg=[TraitDex.EstOnly], **J))
    add("icp_config_dnd_nb", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               cnfg=[TraitDex.DoNotDelegate, TraitDex.NoBackers], **J))
    add("icp_config_rb", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               cnfg=[TraitDex.RegistrarBackers], **J))
    add("icp_config_nrb", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               cnfg=[TraitDex.NoRegistrarBackers], **J))
    add("icp_config_did", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               cnfg=[TraitDex.DelegateIsDelegator], **J))
    add("icp_seal_anchored", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), data=[seal], **J))
    add("icp_intive", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=2, ndigs=ndigs(3, 6), nsith=2,
               wits=wits, toad=1, intive=True, **J), blocked=True)

    # --- rot ---------------------------------------------------------------
    add("rot_simple", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
               ndigs=ndigs(0, 3), **J))
    add("rot_weighted", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1,
               isith=["1/2", "1/2", "1"], ndigs=ndigs(0, 3), **J))
    add("rot_witness_cuts_adds", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
               ndigs=ndigs(0, 3), wits=[], cuts=[], adds=wits, toad=2, **J))
    add("rot_seal_anchored", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
               ndigs=ndigs(0, 3), data=[seal], **J))
    add("rot_intive", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith=2,
               ndigs=ndigs(0, 3), intive=True, **J), blocked=True)

    # --- ixn ---------------------------------------------------------------
    add("ixn_empty", "ixn", "self_addressing",
        interact(pre=pre, dig=dig, sn=1, **J))
    add("ixn_seal", "ixn", "self_addressing",
        interact(pre=pre, dig=dig, sn=1, data=[seal], **J))
    add("ixn_multi_seal", "ixn", "self_addressing",
        interact(pre=pre, dig=dig, sn=1, data=[seal, seal], **J))

    # --- dip (delegated inception; read + byte-identity only) --------------
    add("dip_basic", "dip", "self_addressing",
        incept(keys=keys(0, 1), ndigs=ndigs(1, 2), delpre=delg.pre, **J))
    add("dip_multisig", "dip", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               delpre=delg.pre, **J))
    add("dip_witnessed", "dip", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits,
               toad=2, delpre=delg.pre, **J))

    # --- drt (delegated rotation; read + byte-identity only) ---------------
    add("drt_simple", "drt", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, ilk=Ilks.drt,
               isith="2", ndigs=ndigs(0, 3), **J))
    add("drt_weighted", "drt", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, ilk=Ilks.drt,
               isith=["1/2", "1/2", "1"], ndigs=ndigs(0, 3), **J))

    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / "events.jsonl"
    with out.open("w") as fh:
        for case, ilk, derivation, serder, blocked in rows:
            rec = {
                "kind": "event",
                "case": case,
                "ilk": ilk,
                "derivation": derivation,
                "raw": serder.raw.decode("utf-8"),
                "reserialize": "blocked" if blocked else "identical",
            }
            if blocked:
                rec["blocked_by"] = "#168"  # intive write gap
            emit(fh, rec)

    print(f"wrote {len(rows)} event vectors -> {out} "
          f"(keripy {KERIPY_VERSION})", file=sys.stderr)


if __name__ == "__main__":
    main()
