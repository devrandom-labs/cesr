#!/usr/bin/env python3
"""Generate the keripy semantic differential corpus (JSONL) for the K9 (#95)
fold-verdict parity harness.

keripy is the SEMANTIC oracle. Each scenario drives one bare, validator-role
``keri.core.eventing.Kevery`` (no local habs, so every escrow path runs) with
an event sequence in a fixed DELIVERY order and records keripy's own verdict
per delivery step:

  * ``accepted``  — no exception; the kever accepted the event.
  * ``escrowed``  — ``OutOfOrderError`` (``.ooes``), ``MissingSignatureError``
                    (``.pses``), ``MissingWitnessSignatureError`` (``.pwes``),
                    or ``MissingDelegationError`` (``.pdes``/``.udes``); the
                    exception class name is recorded verbatim, plus the cesr
                    ``EvidenceKind`` the escrow maps to.
  * ``rejected``  — a bare ``ValidationError`` (drop).
  * ``contested`` — ``LikelyDuplicitousError``: keripy routes the event to
                    the duplicate/duplicitous branch.

Re-drives run through the matching escrow processor — verified to exist at
the pin: ``processEscrowOutOfOrders`` (eventing.py:5891),
``processEscrowPartialSigs`` (:6019), ``processEscrowPartialWigs`` (:6174),
``processEscrowPartialDels`` (:6325). The processors are silently idempotent
(a still-unprocessable escrow is re-parked without signal), so the re-drive
verdict is derived from whether the kever advanced (``kvy.kevers[pre].sner``).

Pin defect workaround: the stale-sn scenario reaches ``escrowLDEvent``, which
calls ``db.addLde`` — a method the pin's ``Baser`` no longer has, crashing
with ``AttributeError`` BEFORE the classifying ``LikelyDuplicitousError``
raise (pin defect #1 in ``docs/keripy-parity/ledger.md``). The
``stub_ld_escrow`` monkeypatch from ``keripy_duplicity_gen.py`` is reused on
every Kevery that can hit the duplicitous branch; the classification raise
(the oracle signal) is unaffected.

One JSONL record per scenario, families split across two files:
``happy.jsonl`` (in-order accepted folds) and ``escrow.jsonl`` (escrow /
reject / contested delivery-verdict scenarios). ``final_state`` is keripy's
``Kever`` state after all deliveries AND escrow re-processing — the same
fields ``keripy_keystate_gen.py`` emits, plus ``said_qb64``
(``kever.serder.said``) — or null for scenarios whose subject KEL never
accepts an inception.

Deterministic: fixed salt, no wall-clock, no OS randomness. DO NOT check in a
corpus whose verdicts contain ``error:*`` — that means the scenario
construction is wrong; every scenario below asserts its intended verdicts at
generation time, so such a corpus cannot be produced silently.

Pin: keripy v2.0.0.dev5-1030-gde59bc7d (KERIPY_PIN de59bc7d), KERI/CESR V1
JSON (``KERI10JSON``).

Regenerate (exactly):

    DYLD_LIBRARY_PATH=/nix/store/4cip8y1ab6xcpr0vynm242h202m6a874-libsodium-1.0.22-unstable-2026-04-16/lib \\
    PYTHONPATH=/Users/joel/Code/keripy/.venv/lib/python3.14/site-packages \\
    /Users/joel/.local/bin/python3.14 scripts/keripy_semantics_gen.py \\
      --keripy /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/7bc70638-c9f8-4ceb-a375-0f85c47c2748/scratchpad/keripy-pin \\
      --out-dir crates/keri-codec/tests/corpus/semantics
"""
import argparse
import base64
import json
import sys
from pathlib import Path

KERIPY_VERSION = "v2.0.0.dev5-1030-gde59bc7d"

# Deterministic signers: fixed 16-byte salt -> Ed25519 key sequence.
SALT = b"g\x15\x89\x1a@\xa4\xa47\x07\xb9Q\xb8\x18\xcdJW"
# Distinct salts for the witness bank and the non-transferable signer so no
# witness/ephemeral key shares key material with the controller sequence.
WIT_SALT = b"semantics-wit-01"
NT_SALT = b"semantics-nt-001"

# keripy escrow exception -> cesr EvidenceKind name the consumer must match.
EVIDENCE = {
    "OutOfOrderError": "prior_events",
    "MissingSignatureError": "signatures",
    "MissingWitnessSignatureError": "witness_receipts",
    "MissingDelegationError": "delegation",
}


def b64(raw):
    return base64.standard_b64encode(raw).decode("ascii")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", type=Path, default=None,
                    help="path to a keripy checkout (its <checkout>/src is prepended "
                         "to sys.path); omit if keripy is already importable")
    ap.add_argument("--out-dir", required=True, type=Path,
                    help="output directory for happy.jsonl and escrow.jsonl")
    args = ap.parse_args()

    if args.keripy is not None:
        src = (args.keripy / "src").resolve()
        sys.path.insert(0, str(src if src.is_dir() else args.keripy.resolve()))

    from keri.core.coring import Diger, Kinds
    from keri.core.eventing import Kevery, delcept, incept, interact, rotate
    from keri.core.signing import Salter
    from keri.db.basing import openDB
    from keri.kering import (LikelyDuplicitousError, MissingDelegationError,
                             MissingSignatureError, MissingWitnessSignatureError,
                             OutOfOrderError, ValidationError, Vrsn_1_0)

    J = {"version": Vrsn_1_0, "kind": Kinds.json}

    def stub_ld_escrow(kvy):
        """keripy bug at the pin: ``escrowLDEvent`` calls ``db.addLde``, which
        ``Baser`` no longer has, crashing BEFORE the
        ``LikelyDuplicitousError`` raise. Stub the broken escrow write — the
        classification raise (our oracle signal) is unaffected."""
        kvy.escrowLDEvent = lambda **kwa: None

    def deliver(kvy, serder, sigers, wigers=None):
        """Feed one event; classify keripy's reaction as a verdict tuple."""
        try:
            kvy.processEvent(serder=serder, sigers=sigers, wigers=wigers)
        except (OutOfOrderError, MissingSignatureError,
                MissingWitnessSignatureError, MissingDelegationError) as ex:
            return ("escrowed", type(ex).__name__)
        except LikelyDuplicitousError as ex:
            return ("contested", type(ex).__name__)
        except ValidationError as ex:
            return ("rejected", type(ex).__name__)
        except Exception as ex:  # noqa: BLE001 — record verbatim for triage
            return (f"error:{type(ex).__name__}",)
        if serder.pre in kvy.kevers and \
                kvy.kevers[serder.pre].serder.said == serder.said:
            return ("accepted",)
        return ("error:not-accepted",)

    def exp(event, verdict, keripy_error=None, redrive=False):
        """One expected-delivery entry; escrowed carries the evidence kind."""
        e = {"event": event, "verdict": verdict}
        if keripy_error is not None:
            e["keripy_error"] = keripy_error
        if verdict == "escrowed":
            e["evidence"] = EVIDENCE[keripy_error]
        if redrive:
            e["redrive"] = True
        return e

    def state_of(kvy, pre):
        """keripy's Kever state for `pre`, or None if no inception accepted."""
        if pre not in kvy.kevers:
            return None
        kever = kvy.kevers[pre]
        return {
            "prefix_qb64": kever.prefixer.qb64,
            "sn": kever.sner.num,
            "keys_qb64": [v.qb64 for v in kever.verfers],
            "threshold_sith": kever.tholder.sith,
            "next_keys_qb64": [d.qb64 for d in kever.ndigers],
            "next_threshold_sith": kever.ntholder.sith,
            "witness_threshold": kever.toader.num,
            "witnesses_qb64": list(kever.wits),
            "said_qb64": kever.serder.said,
        }

    records = {"happy": [], "escrow": []}

    def emit(scenario, family, events, delivery, expected, final_state, note):
        """One corpus line. `events` is a list of (serder, sigers, wigers)."""
        for step in expected:
            assert not step["verdict"].startswith("error"), (
                f"{scenario}: {step!r} — scenario construction is wrong")
        records["happy" if family == "happy" else "escrow"].append({
            "scenario": scenario,
            "family": family,
            "events": [{"raw": b64(s.raw),
                        "sigs_qb64": [sg.qb64 for sg in sigs],
                        "wigs_qb64": [wg.qb64 for wg in (wigs or [])]}
                       for s, sigs, wigs in events],
            "delivery": delivery,
            "expected": expected,
            "final_state": final_state,
            "keripy_version": KERIPY_VERSION,
            "note": note,
        })

    signers = Salter(raw=SALT).signers(count=12, transferable=True, temp=True)
    k = [s.verfer.qb64 for s in signers]
    # Pre-rotation commitments: Blake3-256 digest of the next key's qb64b.
    nxt = [Diger(ser=s.verfer.qb64b).qb64 for s in signers]

    # ── 1. happy_single_sig_ladder ─────────────────────────────────────────
    with openDB(name="sem-happy-ladder") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], **J)
        pre = icp.ked["i"]
        s0 = [signers[0].sign(icp.raw, index=0)]
        ixn1 = interact(pre=pre, dig=icp.said, sn=1, **J)
        s1 = [signers[0].sign(ixn1.raw, index=0)]
        rot1 = rotate(pre=pre, keys=[k[1]], dig=ixn1.said, sn=2, ndigs=[nxt[2]], **J)
        sr1 = [signers[1].sign(rot1.raw, index=0, ondex=0)]
        ixn2 = interact(pre=pre, dig=rot1.said, sn=3, **J)
        s3 = [signers[1].sign(ixn2.raw, index=0)]
        rot2 = rotate(pre=pre, keys=[k[2]], dig=ixn2.said, sn=4, ndigs=[nxt[3]], **J)
        sr2 = [signers[2].sign(rot2.raw, index=0, ondex=0)]
        events = [(icp, s0, None), (ixn1, s1, None), (rot1, sr1, None),
                  (ixn2, s3, None), (rot2, sr2, None)]
        expected = []
        for i, (ser, sigs, _) in enumerate(events):
            got = deliver(kvy, ser, sigs)
            assert got == ("accepted",), f"happy_single_sig_ladder step {i}: {got!r}"
            expected.append(exp(i, "accepted"))
        emit("happy_single_sig_ladder", "happy", events, [0, 1, 2, 3, 4], expected,
             state_of(kvy, pre),
             "icp -> ixn -> rot -> ixn -> rot, single-sig, in-order; all accepted")

    # ── 2. happy_multisig_weighted ─────────────────────────────────────────
    with openDB(name="sem-happy-weighted") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=k[0:3], isith=["1/2", "1/2", "1/2"],
                     ndigs=nxt[3:6], nsith="2", **J)
        pre = icp.ked["i"]
        s0 = [signers[i].sign(icp.raw, index=i) for i in range(3)]
        ixn1 = interact(pre=pre, dig=icp.said, sn=1, **J)
        s1 = [signers[i].sign(ixn1.raw, index=i) for i in range(3)]
        rot1 = rotate(pre=pre, keys=k[3:5], isith="2", dig=ixn1.said, sn=2,
                      ndigs=[nxt[6]], **J)
        sr1 = [signers[3].sign(rot1.raw, index=0, ondex=0),
               signers[4].sign(rot1.raw, index=1, ondex=1)]
        events = [(icp, s0, None), (ixn1, s1, None), (rot1, sr1, None)]
        expected = []
        for i, (ser, sigs, _) in enumerate(events):
            got = deliver(kvy, ser, sigs)
            assert got == ("accepted",), f"happy_multisig_weighted step {i}: {got!r}"
            expected.append(exp(i, "accepted"))
        emit("happy_multisig_weighted", "happy", events, [0, 1, 2], expected,
             state_of(kvy, pre),
             "3-key weighted threshold [1/2,1/2,1/2] icp -> ixn -> rot, all sigs")

    # ── 3. happy_partial_rotation ──────────────────────────────────────────
    # The icp commits to FIVE next keys; the rotation reveals a non-contiguous
    # subset (k3 at commitment position 0, k5 at position 2 — k4/k6/k7 are
    # burned), so the rotation sigs carry ondex != index (the #170 partial /
    # reserve rotation semantics, paired with #132 ondex exposure).
    with openDB(name="sem-happy-partial") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=k[0:3], isith="2", ndigs=nxt[3:8], nsith="2", **J)
        pre = icp.ked["i"]
        s0 = [signers[0].sign(icp.raw, index=0), signers[1].sign(icp.raw, index=1)]
        rot1 = rotate(pre=pre, keys=[k[3], k[5]], isith="2", dig=icp.said, sn=1,
                      ndigs=[nxt[8], nxt[9]], **J)
        sr1 = [signers[3].sign(rot1.raw, index=0, ondex=0),
               signers[5].sign(rot1.raw, index=1, ondex=2)]
        ixn1 = interact(pre=pre, dig=rot1.said, sn=2, **J)
        s2 = [signers[3].sign(ixn1.raw, index=0), signers[5].sign(ixn1.raw, index=1)]
        events = [(icp, s0, None), (rot1, sr1, None), (ixn1, s2, None)]
        expected = []
        for i, (ser, sigs, _) in enumerate(events):
            got = deliver(kvy, ser, sigs)
            assert got == ("accepted",), f"happy_partial_rotation step {i}: {got!r}"
            expected.append(exp(i, "accepted"))
        emit("happy_partial_rotation", "happy", events, [0, 1, 2], expected,
             state_of(kvy, pre),
             "5-key commitment, rotation reveals a non-contiguous subset "
             "(ondex != index), then ixn; all accepted")

    # ── 4. escrow_out_of_order_gap ─────────────────────────────────────────
    with openDB(name="sem-esc-ooo") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], **J)
        pre = icp.ked["i"]
        s0 = [signers[0].sign(icp.raw, index=0)]
        ixn1 = interact(pre=pre, dig=icp.said, sn=1, **J)
        s1 = [signers[0].sign(ixn1.raw, index=0)]
        ixn2 = interact(pre=pre, dig=ixn1.said, sn=2, **J)
        s2 = [signers[0].sign(ixn2.raw, index=0)]
        got0 = deliver(kvy, icp, s0)
        assert got0 == ("accepted",), got0
        got2 = deliver(kvy, ixn2, s2)
        assert got2 == ("escrowed", "OutOfOrderError"), got2
        got1 = deliver(kvy, ixn1, s1)
        assert got1 == ("accepted",), got1
        # Escrow re-drive: the processor is silently idempotent, so kever
        # sn-advance is the acceptance signal.
        kvy.processEscrowOutOfOrders()
        assert kvy.kevers[pre].sner.num == 2, kvy.kevers[pre].sner.num
        events = [(icp, s0, None), (ixn1, s1, None), (ixn2, s2, None)]
        expected = [exp(0, "accepted"),
                    exp(2, "escrowed", "OutOfOrderError"),
                    exp(1, "accepted"),
                    exp(2, "accepted", redrive=True)]
        emit("escrow_out_of_order_gap", "escrow", events, [0, 2, 1, 2], expected,
             state_of(kvy, pre),
             "sn-2 delivered before sn-1 escrows (.ooes); re-drive after the "
             "gap closes is accepted")

    # ── 5. escrow_partial_signatures ───────────────────────────────────────
    with openDB(name="sem-esc-psig") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=k[0:3], isith="2", ndigs=[nxt[3]], **J)
        pre = icp.ked["i"]
        sparse = [signers[0].sign(icp.raw, index=0)]
        full = [sparse[0], signers[1].sign(icp.raw, index=1),
                signers[2].sign(icp.raw, index=2)]
        got0 = deliver(kvy, icp, sparse)
        assert got0 == ("escrowed", "MissingSignatureError"), got0
        got1 = deliver(kvy, icp, full)
        assert got1 == ("accepted",), got1
        # Same raw twice: the cure is a fuller signature set on the same event.
        events = [(icp, sparse, None), (icp, full, None)]
        expected = [exp(0, "escrowed", "MissingSignatureError"),
                    exp(1, "accepted", redrive=True)]
        emit("escrow_partial_signatures", "escrow", events, [0, 1], expected,
             state_of(kvy, pre),
             "3-key sith=2 icp with 1 of 3 sigs escrows (.pses); redelivery "
             "with all sigs is accepted")

    # ── 6. escrow_partial_witness ──────────────────────────────────────────
    wwits = Salter(raw=WIT_SALT).signers(count=2, transferable=False, temp=True)
    wit_pres = [w.verfer.qb64 for w in wwits]
    with openDB(name="sem-esc-pwit") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], wits=wit_pres, toad=2, **J)
        s0 = [signers[0].sign(icp.raw, index=0)]
        # No witness receipts (wigers) delivered: bare validator-role Kevery,
        # so the TOAD check runs and escrows (.pwes).
        got = deliver(kvy, icp, s0)
        assert got == ("escrowed", "MissingWitnessSignatureError"), got
        events = [(icp, s0, None)]
        expected = [exp(0, "escrowed", "MissingWitnessSignatureError")]
        emit("escrow_partial_witness", "escrow", events, [0], expected, None,
             "icp with 2 witnesses toad=2 and no receipts escrows (.pwes); "
             "receipt re-drive is K5's suite")

    # ── 7. escrow_missing_delegation ───────────────────────────────────────
    with openDB(name="sem-esc-pdel") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], **J)
        bob = icp.ked["i"]
        sb = [signers[0].sign(icp.raw, index=0)]
        dip = delcept(keys=[k[3]], delpre=bob, ndigs=[nxt[4]], **J)
        sd = [signers[3].sign(dip.raw, index=0)]
        got0 = deliver(kvy, icp, sb)
        assert got0 == ("accepted",), got0
        # Delegator KEL present but no anchor seal and no source couple.
        got1 = deliver(kvy, dip, sd)
        assert got1 == ("escrowed", "MissingDelegationError"), got1
        events = [(icp, sb, None), (dip, sd, None)]
        expected = [exp(0, "accepted"),
                    exp(1, "escrowed", "MissingDelegationError")]
        # The delegate KEL never accepts an inception: no delegate final state.
        emit("escrow_missing_delegation", "escrow", events, [0, 1], expected, None,
             "dip without a delegator anchor seal escrows (.pdes); the cure "
             "path is K4's suite")

    # ── 8. reject_unverifiable_sigs ────────────────────────────────────────
    with openDB(name="sem-rej-sig") as db:
        kvy = Kevery(db=db)
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], **J)
        # The only attached sig is over DIFFERENT bytes: verifySigs filters it,
        # zero verified indices remain, and keripy drops with a bare
        # ValidationError ("No verified signatures", eventing.py:2703-2705) —
        # never escrowed (DDoS guard).
        forged = [signers[0].sign(b"forged: not the inception bytes", index=0)]
        got = deliver(kvy, icp, forged)
        assert got == ("rejected", "ValidationError"), got
        events = [(icp, forged, None)]
        expected = [exp(0, "rejected", "ValidationError")]
        emit("reject_unverifiable_sigs", "reject", events, [0], expected, None,
             "icp whose only sig is forged is dropped (bare ValidationError); "
             "cesr MissingSignatures{verified: 0} -> Terminal")

    # ── 9. reject_stale_sn ─────────────────────────────────────────────────
    with openDB(name="sem-rej-stale") as db:
        kvy = Kevery(db=db)
        stub_ld_escrow(kvy)  # pin defect #1: escrowLDEvent crashes pre-raise
        icp = incept(keys=[k[0]], ndigs=[nxt[1]], **J)
        pre = icp.ked["i"]
        s0 = [signers[0].sign(icp.raw, index=0)]
        ixn1 = interact(pre=pre, dig=icp.said, sn=1, **J)
        s1 = [signers[0].sign(ixn1.raw, index=0)]
        # A NEW distinct event at the already-occupied sn 1 (the seal anchor
        # changes the SAID): keripy routes it to the duplicitous branch.
        ixn1b = interact(pre=pre, dig=icp.said, sn=1,
                         data=[{"d": Diger(ser=b"stale sn variant").qb64}], **J)
        s1b = [signers[0].sign(ixn1b.raw, index=0)]
        got0 = deliver(kvy, icp, s0)
        assert got0 == ("accepted",), got0
        got1 = deliver(kvy, ixn1, s1)
        assert got1 == ("accepted",), got1
        got2 = deliver(kvy, ixn1b, s1b)
        assert got2 == ("contested", "LikelyDuplicitousError"), got2
        events = [(icp, s0, None), (ixn1, s1, None), (ixn1b, s1b, None)]
        expected = [exp(0, "accepted"),
                    exp(1, "accepted"),
                    exp(2, "contested", "LikelyDuplicitousError")]
        emit("reject_stale_sn", "reject", events, [0, 1, 2], expected,
             state_of(kvy, pre),
             "a distinct event at an occupied sn goes to the duplicitous "
             "branch; cesr OutOfOrder{actual <= expected} -> Contested")

    # ── 10. reject_nontransferable_state ───────────────────────────────────
    nts = Salter(raw=NT_SALT).signers(count=1, transferable=False, temp=True)
    with openDB(name="sem-rej-nt") as db:
        kvy = Kevery(db=db)
        # Basic Ed25519N prefix (single key, no `code` override -> i = key)
        # with an empty next-key commitment: non-transferable at birth.
        icp = incept(keys=[nts[0].verfer.qb64], **J)
        pre = icp.ked["i"]
        s0 = [nts[0].sign(icp.raw, index=0)]
        ixn1 = interact(pre=pre, dig=icp.said, sn=1, **J)
        s1 = [nts[0].sign(ixn1.raw, index=0)]
        got0 = deliver(kvy, icp, s0)
        assert got0 == ("accepted",), got0
        got1 = deliver(kvy, ixn1, s1)
        assert got1 == ("rejected", "ValidationError"), got1
        events = [(icp, s0, None), (ixn1, s1, None)]
        expected = [exp(0, "accepted"),
                    exp(1, "rejected", "ValidationError")]
        emit("reject_nontransferable_state", "reject", events, [0, 1], expected,
             state_of(kvy, pre),
             "any event on a non-transferable state is dropped "
             "(eventing.py:2357-2359); cesr NonTransferableState -> Terminal")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for family in ("happy", "escrow"):
        out = args.out_dir / f"{family}.jsonl"
        with out.open("w") as fh:
            for rec in records[family]:
                fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
        print(f"wrote {len(records[family])} semantic vectors -> {out}",
                  file=sys.stderr)


if __name__ == "__main__":
    main()
