#!/usr/bin/env python3
"""Generate the keripy event-wire corpus: full-breadth scenario matrix (issue #145).

keripy is the oracle. This builds every KEL event shape keripy emits at the
pin — all 5 ilks, basic AND self-addressing derivations, simple/weighted/
multi-clause thresholds, intive on and off, witnesses with br/ba and toad at
boundaries, every TraitDex config trait, and seal anchors — plus the #170
legal-but-unusual families: reserve/partial rotations (revealing fewer keys
than previously committed), asymmetric kt/nt structures (weighted-vs-simple
both directions, differing clause counts, zero-weight members), scale
boundaries (12 keys, 8 witnesses, 4-clause nesting), and a second-salt sweep
hardening against fixture coupling — and emits ONE JSON object per scenario
capturing the raw wire bytes (as a JSON string, like seal_events.jsonl). cesr must (1) deserialize every record cleanly and
(2) re-serialize it byte-identically — every row round-trips, including the
intive integer-threshold rows (closed by `ThresholdForm`, #168 / rung 3 of
#171).

No signing, no DB: read + byte-identity are pure serializer facts. Prior
events for rot/ixn/drt reuse a genesis icp's pre/said so chaining fields are
real keripy values, not synthetic.

Deterministic: fixed salts, no wall-clock, no OS randomness.
Pin: keripy v2.0.0.dev5-1030-gde59bc7d, KERI/CESR V1 JSON (KERI10JSON).

Optionally, with ``--kels-out``, also builds a signed 3-event weighted-multisig
KEL (icp -> rot -> ixn) and folds it through keripy's ``Kever`` to emit one
JSONL fold vector capturing the authoritative final key state.
"""
import argparse
import base64
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
    ap.add_argument("--kels-out", type=Path, default=None,
                    help="output JSONL file for signed complete-KEL fold vectors")
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
    signers = Salter(raw=salt).signers(count=24, transferable=True, temp=True)
    wsigners = Salter(raw=salt).signers(count=8, transferable=False, temp=True)

    def keys(a, b):
        return [s.verfer.qb64 for s in signers[a:b]]

    def ndigs(a, b):
        return [Diger(ser=s.verfer.qb64b).qb64 for s in signers[a:b]]

    # Existing witnessed rows keep using only the FIRST 3 witnesses; new #170
    # scale rows use the full 8-strong bank.
    wits = [w.verfer.qb64 for w in wsigners[:3]]
    wits8 = [w.verfer.qb64 for w in wsigners]
    J = dict(kind=Kinds.json, version=Vrsn_1_0)

    seal = {"i": signers[0].verfer.qb64,
            "s": "0",
            "d": Diger(ser=b"anchor").qb64}

    # A self-addressing genesis to source pre/dig for rot/ixn/drt scenarios.
    base = incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), nsith="2", **J)
    pre, dig = base.pre, base.said

    # A delegator prefix for dip/drt.
    delg = incept(keys=keys(0, 1), **J)

    # --- #170: second-salt bank + helpers + base2 (fixture-coupling sweep) --
    salt2 = b"0123456789abcdef"
    signers2 = Salter(raw=salt2).signers(count=6, transferable=True, temp=True)
    wsigners2 = Salter(raw=salt2).signers(count=3, transferable=False, temp=True)

    def keys2(a, b):
        return [s.verfer.qb64 for s in signers2[a:b]]

    def ndigs2(a, b):
        return [Diger(ser=s.verfer.qb64b).qb64 for s in signers2[a:b]]

    wits2 = [w.verfer.qb64 for w in wsigners2]

    base2 = incept(keys=keys2(0, 3), isith="2", ndigs=ndigs2(3, 6), nsith="2", **J)

    rows = []  # (case, ilk, derivation, serder)

    def add(case, ilk, derivation, serder):
        rows.append((case, ilk, derivation, serder))

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
               wits=wits, toad=1, intive=True, **J))

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
               ndigs=ndigs(0, 3), intive=True, **J))

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

    # --- #170: reserve / partial rotation (pairs with #132 ondex exposure) ----
    add("rot_partial_reveal", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 5), dig=dig, sn=1, isith="2",
               ndigs=ndigs(6, 9), **J))
    add("rot_partial_weighted", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 5), dig=dig, sn=1, isith=["1/2", "1/2"],
               ndigs=ndigs(6, 9), **J))
    add("drt_partial_reveal", "drt", "self_addressing",
        rotate(pre=pre, keys=keys(3, 5), dig=dig, sn=1, ilk=Ilks.drt, isith="2",
               ndigs=ndigs(6, 9), **J))

    # --- #170: asymmetric threshold structures ------------------------------
    add("icp_weighted_kt_simple_nt", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=["1/2", "1/2", "1"], ndigs=ndigs(3, 6),
               nsith="2", **J))
    add("icp_simple_kt_weighted_nt", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6),
               nsith=["1/2", "1/2", "1"], **J))
    add("icp_clause_count_asym", "icp", "self_addressing",
        incept(keys=keys(0, 4), isith=[["1/2", "1/2"], ["1", "1"]],
               ndigs=ndigs(4, 10),
               nsith=[["1/2", "1/2"], ["1"], ["1", "1/2", "1/2"]], **J))
    add("icp_zero_weight", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith=["1/2", "1/2", "0"], ndigs=ndigs(3, 6),
               nsith=["1/2", "1/2", "0"], **J))
    add("icp_multiclause_zero_member", "icp", "self_addressing",
        incept(keys=keys(0, 4), isith=[["1/2", "1/2", "0"], ["1"]],
               ndigs=ndigs(4, 8),
               nsith=[["1/2", "1/2", "0"], ["1"]], **J))
    add("rot_weighted_kt_simple_nt", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1,
               isith=["1/2", "1/2", "1"], ndigs=ndigs(0, 3), nsith="2", **J))

    # --- #170: scale boundaries ---------------------------------------------
    add("icp_12_keys", "icp", "self_addressing",
        incept(keys=keys(0, 12), isith="8", ndigs=ndigs(12, 24), nsith="8", **J))
    add("icp_8_witnesses", "icp", "self_addressing",
        incept(keys=keys(0, 3), isith="2", ndigs=ndigs(3, 6), wits=wits8,
               toad=6, **J))
    add("icp_4_clauses", "icp", "self_addressing",
        incept(keys=keys(0, 8),
               isith=[["1/2", "1/2"], ["1"], ["1/2", "1/2", "1/2"], ["1", "1"]],
               ndigs=ndigs(8, 16),
               nsith=[["1/2", "1/2"], ["1"], ["1/2", "1/2", "1/2"], ["1", "1"]],
               **J))
    add("rot_12_keys", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 15), dig=dig, sn=1, isith="8",
               ndigs=ndigs(0, 3), **J))
    add("rot_witness_mixed_cuts_adds", "rot", "self_addressing",
        rotate(pre=pre, keys=keys(3, 6), dig=dig, sn=1, isith="2",
               ndigs=ndigs(0, 3), wits=wits8[0:4], cuts=wits8[0:2],
               adds=wits8[4:7], toad=3, **J))

    # --- #170: second-salt sweep (fixture-coupling hardening) ----------------
    add("icp_multisig_simple_salt2", "icp", "self_addressing", base2)
    add("rot_weighted_salt2", "rot", "self_addressing",
        rotate(pre=base2.pre, keys=keys2(3, 6), dig=base2.said, sn=1,
               isith=["1/2", "1/2", "1"], ndigs=ndigs2(0, 3), **J))
    add("icp_witnessed_salt2", "icp", "self_addressing",
        incept(keys=keys2(0, 3), isith="2", ndigs=ndigs2(3, 6), wits=wits2,
               toad=2, **J))

    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out / "events.jsonl"
    with out.open("w") as fh:
        for case, ilk, derivation, serder in rows:
            rec = {
                "kind": "event",
                "case": case,
                "ilk": ilk,
                "derivation": derivation,
                "raw": serder.raw.decode("utf-8"),
                "reserialize": "identical",
            }
            emit(fh, rec)

    if args.kels_out is not None:
        from keri.core.eventing import Kever
        from keri.db.basing import openDB

        def diger_qb64(i):
            return Diger(ser=signers[i].verfer.qb64b).qb64

        kel = []  # (serder, [siger])
        with openDB(name="k145-weighted") as db:
            # icp: 3 keys, weighted kt, committing to keys 3..6.
            icp = incept(keys=keys(0, 3), isith=["1/2", "1/2", "1"],
                         ndigs=[diger_qb64(3), diger_qb64(4), diger_qb64(5)],
                         nsith=["1/2", "1/2", "1"], **J)
            wpre = icp.ked["i"]
            isigs = [signers[i].sign(icp.raw, index=i) for i in range(3)]
            kever = Kever(serder=icp, sigers=isigs, db=db)
            kel.append((icp, isigs))

            # rot: reveal keys 3..6, commit back to 0..3, sn 1.
            rot = rotate(pre=wpre, keys=keys(3, 6), dig=icp.said, sn=1,
                         isith=["1/2", "1/2", "1"],
                         ndigs=[diger_qb64(0), diger_qb64(1), diger_qb64(2)],
                         nsith=["1/2", "1/2", "1"], **J)
            rsigs = [signers[i].sign(rot.raw, index=i - 3) for i in range(3, 6)]
            kever.update(serder=rot, sigers=rsigs)
            kel.append((rot, rsigs))

            # ixn: sn 2, signed by current keys 3..6.
            ixn = interact(pre=wpre, dig=rot.said, sn=2, **J)
            xsigs = [signers[i].sign(ixn.raw, index=i - 3) for i in range(3, 6)]
            kever.update(serder=ixn, sigers=xsigs)
            kel.append((ixn, xsigs))

            final_state = {
                "prefix_qb64": kever.prefixer.qb64,
                "sn": kever.sner.num,
                "keys_qb64": [v.qb64 for v in kever.verfers],
                "threshold_sith": kever.tholder.sith,
                "next_keys_qb64": [d.qb64 for d in kever.ndigers],
                "next_threshold_sith": kever.ntholder.sith,
                "witness_threshold": kever.toader.num,
                "witnesses_qb64": list(kever.wits),
            }

        rec = {
            "keripy_version": KERIPY_VERSION,
            "case": "weighted_multisig_icp_rot_ixn",
            "note": ("keripy-GENERATED (not synthesized from cesr/keri-rs). events are "
                     "keripy serder.raw bytes; final_state is keripy Kever's fold output."),
            "events": [
                {"raw_b64": base64.standard_b64encode(s.raw).decode("ascii"),
                 "signer_indices": [sg.index for sg in sigs],
                 "sigs_qb64": [sg.qb64 for sg in sigs]}
                for s, sigs in kel
            ],
            "final_state": final_state,
        }
        args.kels_out.parent.mkdir(parents=True, exist_ok=True)
        with args.kels_out.open("w") as fh:
            emit(fh, rec)
        print(f"wrote 1 fold KEL -> {args.kels_out}", file=sys.stderr)

    print(f"wrote {len(rows)} event vectors -> {out} "
          f"(keripy {KERIPY_VERSION})", file=sys.stderr)


if __name__ == "__main__":
    main()
