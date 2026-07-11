# keripy Oracle Repin (#156) + Parity Gate (#151) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repin the keripy differential oracle from `v2.0.0.dev5` to `de59bc7d` (#156), then build the deterministic codex/formula/validation parity gate on top of the corrected pin (#151).

**Architecture:** Two phases, one PR each. Phase A moves the pin to a single source of truth (`scripts/KERIPY_PIN`), regenerates the primitive corpus from keripy `de59bc7d`, and triages drift. Phase B adds `scripts/keripy_parity_gen.py` (introspects keripy codex tables, evaluates formulas, executes factory rejections), three checked-in JSONL families under `cesr/tests/corpus/keripy/parity/`, and a hermetic `cesr/src/keripy_parity/` sweep module mirroring the `keripy_diff` embedded-corpus pattern. Known gaps (#149 witness validation, #150 seal codex) become `#[ignore]`d bug-probe tests that FAIL while the gap exists; deliberate non-goals get `divergence` markers in vectors plus a ledger entry.

**Tech Stack:** Python 3.14+ (generator, keripy as oracle), Rust (test-only sweep module, `include_str!` embedded corpus, serde_json), GitHub Actions (nightly regen + drift PR), Nix flake gate.

**Porting doctrine (user directive, non-negotiable):** parity means *observable agreement with keripy*, never structural transliteration. The gate asserts behavior; it must never pressure implementation shape. Fix-work this gate drives (#149, #150, any discovered red) is designed like the keystate port: identify the domain (witness configuration, seal codex, thresholds), give it its own type that makes invalid states unrepresentable, and let builders consume domain types. Consequence for the sweeps: a corpus rejection row that becomes **unconstructable in Rust's type system counts as satisfied** — it is strictly stronger than keripy's runtime `ValueError`. When a tracked row is fixed type-level, it moves to the type-enforced skip class (same treatment as `rust_static`, with the marker naming the enforcing type), not to a runtime-`Err` assertion.

**Key repo facts (verified 2026-07-11):**
- keripy checkout: `/Users/joel/Code/keripy`, HEAD = `de59bc7d834955c5b0273c62f6b8b6a0df150dc3` — this is the pin target. All cesr port citations (`ample.rs:9-11`, `icp.rs:72-73`) already reference it.
- Existing harness: `cesr/src/keripy_diff/{mod,matter,counter,indexer,stream}.rs`, gated `#[cfg(all(test, feature = "serder", feature = "std"))]` in `cesr/src/lib.rs:101-103`, corpus embedded via `include_str!`.
- `pub(crate)` replay surface (reachable from an in-crate test module): `serder::deserialize::reference::{tholder_from_json, seal_from_json, parse_seal_array, parse_config_array, parse_qb64_verfer_array, parse_qb64_prefixer_array, parse_qb64_diger_array, parse_witness_threshold}`; `serder::builder::icp::{dummy_saider, dummy_prefixer}`.
- Public replay surface: `serder::ample::ample(n: usize) -> Result<u32, SerderError>`, `core::primitives::Tholder::{satisfy, check_well_formed}`, `keri::{ConfigTrait::from_code, Ilk::from_code, Seal}`, builders re-exported at `serder::builder::{InceptionBuilder, RotationBuilder, InteractionBuilder, DelegatedInceptionBuilder, DelegatedRotationBuilder}`.
- Builder expressibility limits (drive tracked/static markers): `RotationBuilder`/`DelegatedRotationBuilder` have `witness_removals`/`witness_additions` but **no prior-wits parameter** (#149 explicitly leaves "carry prior wits or document not to" open); `config`/`anchors` are typed `Vec<_>` so keripy's "not a list" rejections are unrepresentable; `witness_threshold` is `u32` so negative toad is unrepresentable.
- Local generation env (from memory + atuin): keripy `de59bc7d` needs Python ≥ 3.14.2 and nix libsodium via `DYLD_LIBRARY_PATH`. Run `atuin search keripy_diff_gen` to recall the exact previously-working invocation before inventing one.

---

## Phase A — #156: repin the oracle to `de59bc7d`

### Task A1: Branch + pinned keripy worktree

**Files:** none (setup)

- [ ] **Step A1.1: Branch off latest main**

```bash
cd /Users/joel/Code/devrandom/cesr
git fetch origin
git switch -c chore/156-repin-keripy-oracle origin/main
```

- [ ] **Step A1.2: Create a worktree of keripy at the pin** (does not disturb the user's checkout — it already IS at `de59bc7d`, but a worktree makes the pin explicit and survives the user moving their HEAD)

```bash
git -C /Users/joel/Code/keripy worktree add \
  /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin \
  de59bc7d834955c5b0273c62f6b8b6a0df150dc3
```

- [ ] **Step A1.3: Verify the generator environment works** — recall the working invocation first:

```bash
atuin search keripy_diff_gen
```

Expected: a previous command showing the python + `DYLD_LIBRARY_PATH` pattern used for keripy. Reuse it verbatim in A3. If nothing is found, the pattern from memory is: python ≥ 3.14.2 with keripy pip-installed (or `--keripy <checkout>`), `DYLD_LIBRARY_PATH` pointing at the nix libsodium `lib/` directory.

### Task A2: Single pin source

**Files:**
- Create: `scripts/KERIPY_PIN`
- Modify: `scripts/keripy_diff_gen.py:14-15` (docstring pin)
- Modify: `.github/workflows/keripy-diff.yml` (env + clone step)

- [ ] **Step A2.1: Write the pin file** (sha + trailing newline, nothing else)

```bash
printf 'de59bc7d834955c5b0273c62f6b8b6a0df150dc3\n' > scripts/KERIPY_PIN
```

- [ ] **Step A2.2: Point the generator docstring at the pin file.** In `scripts/keripy_diff_gen.py` replace:

```python
Pin: keripy v2.0.0.dev5.
```

with:

```python
Pin: the commit recorded in scripts/KERIPY_PIN (single source of truth).
```

- [ ] **Step A2.3: Rework the workflow to read the pin file and clone a commit.** In `.github/workflows/keripy-diff.yml`, delete the `env:` block (lines 23-26) and replace the clone step (lines 36-39) with:

```yaml
      - name: Resolve keripy pin
        run: echo "KERIPY_REF=$(cat scripts/KERIPY_PIN)" >> "$GITHUB_ENV"

      - name: Clone keripy at the pinned commit
        run: |
          git init /tmp/keripy
          git -C /tmp/keripy remote add origin https://github.com/WebOfTrust/keripy
          git -C /tmp/keripy fetch --depth 1 origin "${KERIPY_REF}"
          git -C /tmp/keripy checkout FETCH_HEAD
```

Keep the `${{ env.KERIPY_REF }}` reference in the PR body (line 85) — it now renders the sha. Update the stale comment at lines 24-25 (the reference to the superpowers spec doc) to point at `scripts/KERIPY_PIN`.

- [ ] **Step A2.4: Check Python requirement at the pin** (the tag needed ≥ 3.14.2; verify the pin didn't move it):

```bash
rg -n "requires-python|python_requires" /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin/setup.py /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin/pyproject.toml 2>/dev/null
```

If the requirement moved past what `actions/setup-python@v5` `python-version: "3.14"` provides, bump that line in the workflow to match.

### Task A3: Regenerate primitive corpus + triage drift

**Files:**
- Modify (regenerated): `cesr/tests/corpus/keripy/{matter,counter_v1,counter_v2,indexer,stream}.jsonl`

- [ ] **Step A3.1: Regenerate** (substitute the exact env prefix recalled in A1.3):

```bash
python scripts/keripy_diff_gen.py \
  --keripy /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin \
  --out cesr/tests/corpus/keripy
git --no-pager diff --stat -- cesr/tests/corpus/keripy
```

- [ ] **Step A3.2: Triage the diff row-by-row.** Rules: **new rows** (new keripy codes) are fine — the Rust harness logs them as skips if unimplemented; **removed rows** mean keripy dropped a code — note it for the PR body; **changed qb64/qb2 bytes for the same (code, inputs)** is a red flag — a byte-level semantic change in keripy between dev5 and `de59bc7d`; investigate against keripy git log before accepting, and record the finding in the PR body. Do not rubber-stamp.

```bash
git --no-pager diff -- cesr/tests/corpus/keripy | rg '^[+-]\{' | head -50
```

- [ ] **Step A3.3: Run the diff harness against the fresh corpus:**

```bash
nix develop --command cargo test --all-features keripy_diff -- --nocapture
```

Expected: PASS, with `SKIP` stderr lines for any newly-added keripy codes cesr doesn't implement yet. A hard FAIL is a real divergence: stop, diagnose (superpowers:systematic-debugging), fix cesr or file an issue + `#[ignore]` with the issue ref.

- [ ] **Step A3.4: Update `docs/keripy-parity/report.md`** header reference from `v2.0.0.dev5` to `de59bc7d` (the report itself is regenerated by keripy-sync; just fix the stale pin citation if present).

### Task A4: Commit, gate, PR (Phase A)

- [ ] **Step A4.1: Commit** (the flake gate only sees committed state — commit BEFORE checking):

```bash
git add scripts/KERIPY_PIN scripts/keripy_diff_gen.py .github/workflows/keripy-diff.yml \
        cesr/tests/corpus/keripy docs/keripy-parity
git commit -m "chore(diff): #156 repin keripy oracle to de59bc7d — single pin source + corpus regen"
```

- [ ] **Step A4.2: Full gate:**

```bash
nix flake check
```

Expected: all checks green. On failure: fix, `git commit --amend` or follow-up commit, re-run.

- [ ] **Step A4.3: PR** (verify `gh auth status` shows `joeldsouzax` active):

```bash
git push -u origin chore/156-repin-keripy-oracle
gh pr create --repo devrandom-labs/cesr \
  --title "chore(diff): repin keripy oracle to de59bc7d — single pin source, corpus regen (#156)" \
  --body "$(cat <<'EOF'
Closes #156. Blocks-resolution for #151 (parity gate must generate from the corrected pin).

- Pin now lives in `scripts/KERIPY_PIN` (single source); workflow resolves it at runtime and clones the commit (not a tag).
- Primitive corpus regenerated from keripy `de59bc7d`; drift triage: <summarize row-level findings here — new codes / removed codes / byte changes>.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Fill in the actual triage summary from A3.2 — never leave the placeholder text.

**Phase B does not start until this PR is merged and `main` is re-fetched** (memory: never build on a stale branch).

---

## Phase B — #151: codex/formula/validation parity gate

### File structure (Phase B)

| File | Responsibility |
|---|---|
| `scripts/keripy_parity_gen.py` | Create. Introspects pinned keripy → emits 3 JSONL families. Deterministic (`--seed`). |
| `cesr/tests/corpus/keripy/parity/codex.jsonl` | Checked-in. TraitDex/DigDex/PreDex/Ilks/seal-shape rows. |
| `cesr/tests/corpus/keripy/parity/formulas.jsonl` | Checked-in. `ample` table (weak+strong) + Tholder.satisfy samples. |
| `cesr/tests/corpus/keripy/parity/validation.jsonl` | Checked-in. Factory rejection matrix + per-factory `control_valid` rows. |
| `cesr/src/keripy_parity/mod.rs` | Vector structs + `include_str!` loaders (mirrors `keripy_diff/mod.rs`). |
| `cesr/src/keripy_parity/codex.rs` | Codex sweeps + `#[ignore]` seal bug-probe (#150). |
| `cesr/src/keripy_parity/formulas.rs` | ample + tholder_satisfy sweeps. |
| `cesr/src/keripy_parity/validation.rs` | Builder rejection sweeps + `#[ignore]` bug-probe (#149). |
| `cesr/src/lib.rs` | Modify: declare `mod keripy_parity` beside `keripy_diff`. |
| `docs/keripy-parity/ledger.md` | Create. Divergence ledger. |
| `.github/workflows/keripy-diff.yml` | Modify: regen + run parity families nightly. |

### Task B1: Branch

- [ ] **Step B1.1:**

```bash
cd /Users/joel/Code/devrandom/cesr
git fetch origin
git switch -c feat/151-keripy-parity-gate origin/main
```

### Task B2: Generator — `scripts/keripy_parity_gen.py`

**Files:**
- Create: `scripts/keripy_parity_gen.py`

- [ ] **Step B2.1: Verify keripy factory kwarg names at the pin before writing cases** (facts-only — do not trust remembered signatures):

```bash
python - <<'EOF'
import sys; sys.path.insert(0, "/private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin/src")
import inspect
from keri.core import eventing
for f in ("incept", "rotate", "interact", "delcept", "deltate", "ample"):
    print(f, inspect.signature(getattr(eventing, f)))
from keri.core.coring import Tholder
print("Tholder.satisfy", inspect.signature(Tholder.satisfy))
EOF
```

Adjust the kwarg names in Step B2.2's `CASES` to the printed signatures (the code below uses `isith`/`nsith`/`ndigs`/`wits`/`cuts`/`adds`/`toad`/`sn`/`pre`/`dig`/`delpre`/`cnfg`/`data` — correct any that differ, and correct the JSONL `params` mapping comments accordingly).

- [ ] **Step B2.2: Write the generator.** Same conventions as `keripy_diff_gen.py`: `emit()` compact-sorted JSON, `--keripy/--out/--seed` CLI, deterministic, stderr counts.

```python
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

Deterministic given --seed. Pin: the commit in scripts/KERIPY_PIN.
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

# cesr scope is the KERI KEL core; registry (TEL) and ACDC ilks are out of scope.
KEL_CORE_ILKS = {"icp", "rot", "ixn", "dip", "drt", "rct", "qry", "rpy", "exn"}
ILK_DIVERGENCE = "TEL/ACDC ilk — out of cesr scope (KERI KEL core only); see docs/keripy-parity/ledger.md"

# PreDex codes whose curve crates are deliberately deferred (RustCrypto
# stable-generation policy). Populate from the first sweep run's triage —
# see Task B5 step 4; start empty so gaps are DISCOVERED, not presumed.
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

    def vkey():
        return Matter(raw=rand_raw(rng, 32), code=MtrDex.Ed25519).qb64

    def wit():
        return Matter(raw=rand_raw(rng, 32), code=MtrDex.Ed25519N).qb64

    def dig():
        return Diger(ser=rand_raw(rng, 16), code=MtrDex.Blake3_256).qb64

    k1, k2 = vkey(), vkey()
    w1, w2, w3 = wit(), wit(), wit()
    n1 = dig()
    pre, delpre, prior = wit(), wit(), dig()

    # (factory, case, kwargs, rust_static). kwargs use the kwarg names verified
    # in Step B2.1. rust_static marks cases unrepresentable in cesr's typed
    # builder API (permanent — ledger-backed); None means representable.
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
         dict(pre=pre, keys=[k1], dig=prior, sn=1, delpre=delpre, ndigs=[n1]),
         None),
        ("deltate", "sn_zero",
         dict(pre=pre, keys=[k1], dig=prior, sn=0, delpre=delpre), None),
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
                factory(**kwargs)
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
```

- [ ] **Step B2.3: Generate + determinism check** (same env prefix as A3.1):

```bash
python scripts/keripy_parity_gen.py \
  --keripy /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin \
  --out cesr/tests/corpus/keripy/parity
cp -r cesr/tests/corpus/keripy/parity /tmp/parity-run1
python scripts/keripy_parity_gen.py \
  --keripy /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin \
  --out cesr/tests/corpus/keripy/parity
diff -r /tmp/parity-run1 cesr/tests/corpus/keripy/parity && echo DETERMINISTIC
```

Expected: `DETERMINISTIC`. Also eyeball one row per family: `head -1 cesr/tests/corpus/keripy/parity/*.jsonl`.

If any generator `assert` fires (a case didn't raise / control raised), the CASES entry disagrees with keripy at the pin — fix the case to match keripy's actual behavior (keripy is the oracle; the corpus records facts, not wishes).

### Task B3: Rust scaffold — `cesr/src/keripy_parity/mod.rs`

**Files:**
- Create: `cesr/src/keripy_parity/mod.rs`
- Modify: `cesr/src/lib.rs` (beside the `keripy_diff` declaration at ~101-103)

- [ ] **Step B3.1: Write `mod.rs`** (mirrors `keripy_diff/mod.rs`: embedded corpus, panic-on-malformed loader):

```rust
//! Parity-gate harness vs keripy (issue #151).
//!
//! The "missing middle" between primitive byte-diffing (`keripy_diff`) and the
//! event-wire corpus (#145): replays checked-in, keripy-generated codex /
//! formula / validation vectors and asserts cesr agrees. Vectors carrying a
//! `divergence` marker are deliberate non-goals recorded in
//! `docs/keripy-parity/ledger.md`; temporarily-open gaps (#149, #150) live in
//! Rust-side tracked tables next to `#[ignore]`d bug-probe tests that FAIL
//! while the gap exists.

use serde::Deserialize;
use serde_json::Value;
use std::string::String;
use std::vec::Vec;

mod codex;
mod formulas;
mod validation;

#[derive(Debug, Deserialize)]
struct CodexVector {
    pub kind: String,
    pub family: String,
    pub name: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub qb64: String,
    #[serde(default)]
    pub fields: Vec<String>,
    pub sample: Option<Value>,
    pub divergence: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FormulaVector {
    pub kind: String,
    pub formula: String,
    pub n: Option<u64>,
    pub weak: Option<bool>,
    pub m: Option<u64>,
    pub sith: Option<Value>,
    #[serde(default)]
    pub indices: Vec<u32>,
    pub satisfies: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ValidationVector {
    pub kind: String,
    pub factory: String,
    pub case: String,
    pub params: Value,
    pub raises: Option<String>,
    #[serde(default)]
    pub message: String,
    pub rust_static: Option<String>,
}

// Embedded at compile time (`include_str!`) for the same reason as
// `keripy_diff`: the nix gate builds and runs tests in separate hermetic
// phases, so runtime manifest-relative paths do not survive to nextest.
#[allow(
    clippy::panic,
    reason = "test-only corpus loader: panics on malformed corpus fixtures"
)]
fn parse_lines<T: serde::de::DeserializeOwned>(text: &str) -> Vec<T> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<T>(l).unwrap_or_else(|e| panic!("parse `{l}`: {e}")))
        .collect()
}

fn load_codex() -> Vec<CodexVector> {
    parse_lines(include_str!("../../tests/corpus/keripy/parity/codex.jsonl"))
}

fn load_formulas() -> Vec<FormulaVector> {
    parse_lines(include_str!("../../tests/corpus/keripy/parity/formulas.jsonl"))
}

fn load_validation() -> Vec<ValidationVector> {
    parse_lines(include_str!("../../tests/corpus/keripy/parity/validation.jsonl"))
}

#[cfg(test)]
mod scaffold_tests {
    use super::*;

    #[test]
    fn corpus_families_load_and_are_nonempty() {
        assert!(!load_codex().is_empty(), "codex corpus is empty");
        assert!(!load_formulas().is_empty(), "formulas corpus is empty");
        assert!(!load_validation().is_empty(), "validation corpus is empty");
    }

    #[test]
    fn kinds_are_homogeneous() {
        assert!(load_codex().iter().all(|v| v.kind == "codex"));
        assert!(load_formulas().iter().all(|v| v.kind == "formula"));
        assert!(load_validation().iter().all(|v| v.kind == "validation"));
    }
}
```

- [ ] **Step B3.2: Declare the module in `lib.rs`.** Find the existing block (~lines 101-103):

```rust
#[cfg(all(test, feature = "serder", feature = "std"))]
mod keripy_diff;
```

and add directly below it:

```rust
#[cfg(all(test, feature = "serder", feature = "std"))]
mod keripy_parity;
```

- [ ] **Step B3.3: Create empty `codex.rs`, `formulas.rs`, `validation.rs`** (just the module doc comment each, so the scaffold compiles), then run the scaffold test — it must pass (the corpus from B2.3 is already on disk):

```bash
nix develop --command cargo test --all-features keripy_parity -- --nocapture
```

Expected: `corpus_families_load_and_are_nonempty` + `kinds_are_homogeneous` PASS.

- [ ] **Step B3.4: Commit scaffold:**

```bash
git add scripts/keripy_parity_gen.py cesr/tests/corpus/keripy/parity cesr/src/keripy_parity cesr/src/lib.rs
git commit -m "test(parity): #151 generator + corpus + embedded-corpus scaffold"
```

### Task B4: Formula sweeps — `cesr/src/keripy_parity/formulas.rs`

**Files:**
- Modify: `cesr/src/keripy_parity/formulas.rs`

- [ ] **Step B4.1: Write both sweep tests** (they are the failing-test step AND the assertion; the implementation under test already exists — this is conformance TDD: red here means cesr diverges):

```rust
//! Formula parity sweeps — `formulas.jsonl` (issue #151).
//!
//! Reintroducing the #147 `ample(3)` bug turns `ample_matches_keripy_table`
//! red at n=3 (mutation-proven in the PR).

use std::eprintln;

use crate::serder::ample::ample;
use crate::serder::deserialize::reference::tholder_from_json;

use super::load_formulas;

#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: malformed corpus rows panic with context"
)]
fn ample_matches_keripy_table() {
    let vectors = load_formulas();
    let mut weak = 0usize;
    let mut strong = 0usize;
    for v in vectors.iter().filter(|v| v.formula == "ample") {
        let n = usize::try_from(v.n.unwrap_or_else(|| panic!("ample row missing n")))
            .unwrap_or_else(|_| panic!("ample n exceeds usize"));
        if v.weak == Some(false) {
            // No cesr consumer for strong-majority ample; carried in the
            // corpus for the day one exists. Ledger: docs/keripy-parity/ledger.md.
            strong += 1;
            continue;
        }
        let m = v.m.unwrap_or_else(|| panic!("weak ample row missing m (n={n})"));
        assert_eq!(u64::from(ample(n).unwrap()), m, "ample({n})");
        weak += 1;
    }
    assert!(weak >= 257, "expected the full 0..=256 weak sweep, got {weak}");
    eprintln!("ample: {weak} weak rows asserted, {strong} strong rows skipped (ledger)");
}

#[test]
#[allow(
    clippy::panic,
    reason = "test-only sweep: malformed corpus rows panic with context"
)]
fn tholder_satisfy_matches_keripy() {
    let vectors = load_formulas();
    let mut rows = 0usize;
    for v in vectors.iter().filter(|v| v.formula == "tholder_satisfy") {
        let sith = v
            .sith
            .as_ref()
            .unwrap_or_else(|| panic!("satisfy row missing sith"));
        let tholder =
            tholder_from_json(sith).unwrap_or_else(|e| panic!("sith {sith}: {e}"));
        let want = v
            .satisfies
            .unwrap_or_else(|| panic!("satisfy row missing verdict"));
        assert_eq!(
            tholder.satisfy(v.indices.iter().copied()),
            want,
            "satisfy(sith={sith}, indices={:?})",
            v.indices
        );
        rows += 1;
    }
    assert!(rows > 0, "no tholder_satisfy rows in corpus");
    eprintln!("tholder_satisfy: {rows} rows asserted");
}
```

- [ ] **Step B4.2: Run and triage:**

```bash
nix develop --command cargo test --all-features keripy_parity::formulas -- --nocapture
```

Expected: `ample_matches_keripy_table` PASS (the #152 port matched `de59bc7d`). `tholder_satisfy_matches_keripy` MAY fail on duplicate-index rows — cesr dedups (fail-closed), keripy may not. If it fails: that is the gate working. Triage per the decision rule: cesr's dedup is a deliberate fail-closed choice → keep cesr behavior, move those rows to `divergence`-marked (add a `SATISFY_DIVERGENCE` map in the generator marking the specific `(sith, indices)` rows, regenerate, skip-with-counter in the sweep, ledger entry) **and** flag it in the PR description — semantic satisfy divergence is significant enough that the user must see it. If instead keripy also dedups, the sweep just passes.

- [ ] **Step B4.3: Commit:**

```bash
git add cesr/src/keripy_parity/formulas.rs cesr/tests/corpus/keripy/parity scripts/keripy_parity_gen.py
git commit -m "test(parity): #151 formula sweeps — ample table + tholder satisfy"
```

### Task B5: Codex sweeps — `cesr/src/keripy_parity/codex.rs`

**Files:**
- Modify: `cesr/src/keripy_parity/codex.rs`

- [ ] **Step B5.1: Write the sweeps.** Trait/ilk sweep by `from_code` + roundtrip; dig/pre by replaying the qb64 example through the same `pub(crate)` array parsers the serder read path uses; seals through `parse_seal_array`. `SealBack`/`SealKind` are Rust-side tracked (#150) with an `#[ignore]` bug-probe:

```rust
//! Codex parity sweeps — `codex.jsonl` (issue #151).
//!
//! Deleting a `ConfigTrait`/`Ilk` arm or a `Seal` variant turns these red
//! (mutation-proven in the PR). A codex entry keripy adds in a future pin
//! lands as a red diff via the nightly regen.

use serde_json::{Value, json};
use std::eprintln;
use std::vec::Vec;

use crate::keri::{ConfigTrait, Ilk, Seal};
use crate::serder::deserialize::reference::{
    parse_qb64_diger_array, parse_qb64_prefixer_array, parse_seal_array,
};

use super::{CodexVector, load_codex};

/// Seal shapes that exist in keripy's codex but not yet in cesr's `Seal`.
/// Burn-down: remove entries as #150 lands; the bug-probe below fails-red
/// while any entry remains and the gap is real.
const TRACKED_SEALS: &[(&str, &str)] = &[("SealBack", "#150"), ("SealKind", "#150")];

fn tracked_seal(name: &str) -> Option<&'static str> {
    TRACKED_SEALS
        .iter()
        .find(|(seal, _)| *seal == name)
        .map(|(_, issue)| *issue)
}

fn seal_variant_matches(name: &str, seal: &Seal) -> bool {
    matches!(
        (name, seal),
        ("SealDigest", Seal::Digest { .. })
            | ("SealRoot", Seal::Root { .. })
            | ("SealSource", Seal::Source { .. })
            | ("SealEvent", Seal::Event { .. })
            | ("SealLast", Seal::Last { .. })
    )
}

#[allow(
    clippy::panic,
    reason = "test-only sweep: malformed corpus rows panic with context"
)]
fn parse_sample_seal(v: &CodexVector) -> Result<Vec<Seal>, crate::serder::error::SerderError> {
    let sample = v
        .sample
        .as_ref()
        .unwrap_or_else(|| panic!("seal row {} missing sample", v.name));
    parse_seal_array(&json!([sample]))
}

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: skip logging + context panics"
)]
fn codex_tables_match_keripy() {
    let vectors = load_codex();
    let mut asserted = 0usize;
    let mut diverged = 0usize;
    let mut tracked = 0usize;

    for v in &vectors {
        if let Some(reason) = &v.divergence {
            eprintln!("DIVERGENCE {}/{}: {reason}", v.family, v.name);
            diverged += 1;
            continue;
        }
        match v.family.as_str() {
            "trait" => {
                let parsed = ConfigTrait::from_code(&v.code)
                    .unwrap_or_else(|e| panic!("trait {} ({}): {e}", v.name, v.code));
                assert_eq!(parsed.code(), v.code, "trait roundtrip {}", v.name);
            }
            "ilk" => {
                let parsed = Ilk::from_code(&v.code)
                    .unwrap_or_else(|e| panic!("ilk {} ({}): {e}", v.name, v.code));
                assert_eq!(parsed.code(), v.code, "ilk roundtrip {}", v.name);
            }
            "dig" => {
                parse_qb64_diger_array(&json!([v.qb64]))
                    .unwrap_or_else(|e| panic!("dig {} ({}): {e}", v.name, v.code));
            }
            "pre" => {
                parse_qb64_prefixer_array(&json!([v.qb64]))
                    .unwrap_or_else(|e| panic!("pre {} ({}): {e}", v.name, v.code));
            }
            "seal" => {
                if tracked_seal(&v.name).is_some() {
                    tracked += 1;
                    continue;
                }
                let seals = parse_sample_seal(v)
                    .unwrap_or_else(|e| panic!("seal {}: {e}", v.name));
                let [seal] = seals.as_slice() else {
                    panic!("seal {}: expected exactly one parsed seal", v.name);
                };
                assert!(
                    seal_variant_matches(&v.name, seal),
                    "seal {} parsed to the wrong variant",
                    v.name
                );
            }
            other => panic!("unknown codex family {other:?}"),
        }
        asserted += 1;
    }
    assert!(asserted > 0, "codex corpus asserted nothing");
    eprintln!(
        "codex: {asserted} asserted, {diverged} divergence-skipped (ledger), {tracked} tracked (#150)"
    );
}

/// Bug-probe for #150: keripy seal shapes cesr cannot read yet. FAILS while
/// the gap exists (run with `--ignored` to see it red); flips green when #150
/// lands, at which point remove the `TRACKED_SEALS` entries and this test
/// becomes part of the main sweep.
#[test]
#[ignore = "#150: SealBack/SealKind not yet in cesr's Seal — this probe fails while the gap is open"]
#[allow(
    clippy::panic,
    reason = "test-only bug-probe: context panics on malformed corpus"
)]
fn tracked_seal_shapes_parse_150() {
    let vectors = load_codex();
    for v in vectors.iter().filter(|v| v.family == "seal") {
        let Some(issue) = tracked_seal(&v.name) else {
            continue;
        };
        let parsed = parse_sample_seal(v);
        assert!(
            parsed.is_ok(),
            "{issue} still open: seal {} rejected: {:?}",
            v.name,
            parsed.err()
        );
    }
}

#[test]
fn tracked_seals_still_exist_in_corpus() {
    // Guard: if a regen drops a tracked seal row, the probe above would
    // vacuously pass — fail here instead so the tracked table gets pruned
    // deliberately, not silently.
    let vectors = load_codex();
    for (name, issue) in TRACKED_SEALS {
        assert!(
            vectors.iter().any(|v| v.family == "seal" && v.name == *name),
            "tracked seal {name} ({issue}) no longer in corpus — prune TRACKED_SEALS"
        );
    }
}
```

- [ ] **Step B5.2: Run:**

```bash
nix develop --command cargo test --all-features keripy_parity::codex -- --nocapture
```

Expected: `codex_tables_match_keripy` may FAIL on `pre` rows for codes cesr's prefixer path doesn't accept (Ed448 family, ECDSA variants — the RustCrypto stable-generation deferral). Triage each failing code:
  - **Deliberate deferral** (curve crate not on stable generation): add the entry to `PRE_DIVERGENCE` in the generator with reason `"<curve> deferred — RustCrypto stable-generation policy; see ledger"`, regenerate (B2.3 command), ledger entry in Task B7.
  - **Genuine miss** (a code cesr should accept today): file a new issue, add a Rust-side tracked table + `#[ignore]` probe exactly like the seal pattern.

- [ ] **Step B5.3: Verify the bug-probe is red** (proof it has teeth while #150 is open):

```bash
nix develop --command cargo test --all-features keripy_parity::codex -- --ignored --nocapture
```

Expected: `tracked_seal_shapes_parse_150` FAILS with "SealBack rejected". If it passes, #150 is already fixed — delete the `TRACKED_SEALS` entries instead.

- [ ] **Step B5.4: Commit:**

```bash
git add cesr/src/keripy_parity/codex.rs cesr/tests/corpus/keripy/parity scripts/keripy_parity_gen.py
git commit -m "test(parity): #151 codex sweeps — traits, ilks, digs, pres, seals (tracked #150)"
```

### Task B6: Validation sweeps — `cesr/src/keripy_parity/validation.rs`

**Files:**
- Modify: `cesr/src/keripy_parity/validation.rs`

- [ ] **Step B6.1: Write the replay + sweeps:**

```rust
//! Factory-validation parity sweeps — `validation.jsonl` (issue #151).
//!
//! Each row is a parameter combination keripy's factory rejects (executed and
//! verified at generation time) or a `control_valid` row it accepts. The
//! sweep replays each representable row against the matching cesr builder.

use serde_json::Value;
use std::eprintln;
use std::string::String;
use std::vec::Vec;

use crate::core::primitives::{Prefixer, Tholder, Verfer};
use crate::serder::builder::icp::{dummy_prefixer, dummy_saider};
use crate::serder::builder::{
    DelegatedInceptionBuilder, DelegatedRotationBuilder, InceptionBuilder, InteractionBuilder,
    RotationBuilder,
};
use crate::serder::deserialize::reference::{
    parse_qb64_prefixer_array, parse_qb64_verfer_array, tholder_from_json,
};
use crate::serder::deserialize::reference::parse_qb64_diger_array;
use crate::serder::error::SerderError;

use super::{ValidationVector, load_validation};

/// Rows cesr's builders accept today but keripy rejects — the #149 burn-down.
/// The main sweep skips these; the `#[ignore]` probe below FAILS while any
/// remains unenforced. Remove entries as #149 lands.
const TRACKED: &[(&str, &str, &str)] = &[
    ("incept", "dup_wits", "#149"),
    ("incept", "toad_gt_wits", "#149"),
    ("incept", "toad_zero_with_wits", "#149"),
    ("incept", "toad_nonzero_no_wits", "#149"),
    ("rotate", "dup_cuts", "#149"),
    ("rotate", "dup_adds", "#149"),
    ("rotate", "cut_add_intersect", "#149"),
    ("delcept", "dup_wits", "#149"),
];

/// Rows whose keripy parameters cannot be expressed through cesr's builder
/// API at all: rot/drt builders carry cuts/adds but no prior-wits list, so
/// wits-relative checks have no builder-level equivalent. #149 explicitly
/// owns the decision (add the parameter or document not to).
const INEXPRESSIBLE: &[(&str, &str, &str)] = &[
    ("rotate", "dup_wits_prior", "#149: no prior-wits parameter on RotationBuilder"),
    ("rotate", "cut_not_in_wits", "#149: no prior-wits parameter on RotationBuilder"),
    ("rotate", "add_already_in_wits", "#149: no prior-wits parameter on RotationBuilder"),
    ("rotate", "toad_gt_new_wits", "#149: new-wit-set bound needs prior wits"),
];

fn lookup<'a>(table: &'a [(&str, &str, &str)], factory: &str, case: &str) -> Option<&'a str> {
    table
        .iter()
        .find(|(f, c, _)| *f == factory && *c == case)
        .map(|(_, _, why)| *why)
}

#[allow(
    clippy::panic,
    reason = "test-only replay: malformed corpus rows panic with context"
)]
fn verfers(params: &Value) -> Vec<Verfer<'static>> {
    parse_qb64_verfer_array(&params["keys"]).unwrap_or_else(|e| panic!("keys: {e}"))
}

#[allow(
    clippy::panic,
    reason = "test-only replay: malformed corpus rows panic with context"
)]
fn prefixers(params: &Value, field: &str) -> Vec<Prefixer<'static>> {
    parse_qb64_prefixer_array(&params[field]).unwrap_or_else(|e| panic!("{field}: {e}"))
}

fn threshold(params: &Value, field: &str) -> Option<Tholder> {
    let v = &params[field];
    (!v.is_null()).then(|| {
        tholder_from_json(v).unwrap_or_else(|e| panic!("{field} {v}: {e}"))
    })
}

#[allow(
    clippy::panic,
    reason = "test-only replay: malformed corpus rows panic with context"
)]
fn toad(params: &Value) -> Option<u32> {
    let v = &params["toad"];
    (!v.is_null()).then(|| {
        u32::try_from(v.as_u64().unwrap_or_else(|| panic!("toad {v} not u64")))
            .unwrap_or_else(|_| panic!("toad {v} exceeds u32"))
    })
}

fn sn(params: &Value) -> Option<u128> {
    params["sn"].as_u64().map(u128::from)
}

/// Replays one corpus row against the matching cesr builder. `Ok(())` means
/// the builder accepted; `Err` means it rejected.
#[allow(
    clippy::panic,
    reason = "test-only replay: malformed corpus rows panic with context"
)]
fn replay(v: &ValidationVector) -> Result<(), SerderError> {
    let p = &v.params;
    match v.factory.as_str() {
        "incept" => {
            let mut b = InceptionBuilder::new().keys(verfers(p));
            if let Some(t) = threshold(p, "sith") {
                b = b.threshold(t);
            }
            let ndigs = parse_qb64_diger_array(&p["ndigs"])
                .unwrap_or_else(|e| panic!("ndigs: {e}"));
            if !ndigs.is_empty() {
                b = b.next_keys(ndigs);
            }
            if let Some(t) = threshold(p, "nsith") {
                b = b.next_threshold(t);
            }
            b = b.witnesses(prefixers(p, "wits"));
            if let Some(t) = toad(p) {
                b = b.witness_threshold(t);
            }
            b.build().map(|_| ())
        }
        "rotate" => {
            let mut b = RotationBuilder::new()
                .prefix(dummy_prefixer()?)
                .prior_event_said(dummy_saider()?)
                .keys(verfers(p));
            if let Some(s) = sn(p) {
                b = b.sn(s);
            }
            if let Some(t) = threshold(p, "sith") {
                b = b.threshold(t);
            }
            b = b
                .witness_removals(prefixers(p, "cuts"))
                .witness_additions(prefixers(p, "adds"));
            if let Some(t) = toad(p) {
                b = b.witness_threshold(t);
            }
            b.build().map(|_| ())
        }
        "interact" => {
            let mut b = InteractionBuilder::new()
                .prefix(dummy_prefixer()?)
                .prior_event_said(dummy_saider()?);
            if let Some(s) = sn(p) {
                b = b.sn(s);
            }
            b.build().map(|_| ())
        }
        "delcept" => {
            let mut b = DelegatedInceptionBuilder::new()
                .keys(verfers(p))
                .delegator(dummy_prefixer()?);
            let ndigs = parse_qb64_diger_array(&p["ndigs"])
                .unwrap_or_else(|e| panic!("ndigs: {e}"));
            if !ndigs.is_empty() {
                b = b.next_keys(ndigs);
            }
            b = b.witnesses(prefixers(p, "wits"));
            if let Some(t) = toad(p) {
                b = b.witness_threshold(t);
            }
            b.build().map(|_| ())
        }
        "deltate" => {
            let mut b = DelegatedRotationBuilder::new()
                .prefix(dummy_prefixer()?)
                .prior_event_said(dummy_saider()?)
                .keys(verfers(p));
            if let Some(s) = sn(p) {
                b = b.sn(s);
            }
            let ndigs = parse_qb64_diger_array(&p["ndigs"])
                .unwrap_or_else(|e| panic!("ndigs: {e}"));
            if !ndigs.is_empty() {
                b = b.next_keys(ndigs);
            }
            b.build().map(|_| ())
        }
        other => panic!("unknown factory {other:?}"),
    }
}

#[test]
#[allow(
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only sweep: skip logging + context panics"
)]
fn builder_validation_matches_keripy() {
    let vectors = load_validation();
    let mut asserted = 0usize;
    let mut skipped_static = 0usize;
    let mut skipped_tracked = 0usize;

    for v in &vectors {
        if let Some(reason) = &v.rust_static {
            eprintln!("STATIC {}/{}: {reason}", v.factory, v.case);
            skipped_static += 1;
            continue;
        }
        if let Some(why) = lookup(INEXPRESSIBLE, &v.factory, &v.case)
            .or_else(|| lookup(TRACKED, &v.factory, &v.case))
        {
            eprintln!("TRACKED {}/{}: {why}", v.factory, v.case);
            skipped_tracked += 1;
            continue;
        }
        let result = replay(v);
        if v.raises.is_some() {
            assert!(
                result.is_err(),
                "{}/{}: keripy raises {} ({}) but cesr accepted",
                v.factory,
                v.case,
                v.raises.as_deref().unwrap_or(""),
                v.message
            );
        } else {
            assert!(
                result.is_ok(),
                "{}/{}: keripy accepts but cesr rejected: {:?}",
                v.factory,
                v.case,
                result.err()
            );
        }
        asserted += 1;
    }
    assert!(asserted > 0, "validation corpus asserted nothing");
    eprintln!(
        "validation: {asserted} asserted, {skipped_static} static-skipped, {skipped_tracked} tracked (#149)"
    );
}

/// Bug-probe for #149: expressible rejection rows cesr's builders still
/// accept. FAILS while the gap exists; flips green when #149 lands — then
/// prune `TRACKED` so the rows join the main sweep.
#[test]
#[ignore = "#149: witness-validation gaps — this probe fails while any TRACKED row is unenforced"]
fn tracked_validation_rows_reject_149() {
    let vectors = load_validation();
    for v in &vectors {
        if lookup(TRACKED, &v.factory, &v.case).is_none() {
            continue;
        }
        let result = replay(v);
        assert!(
            result.is_err(),
            "#149 still open: {}/{} accepted (keripy: {})",
            v.factory,
            v.case,
            v.message
        );
    }
}

#[test]
fn tracked_tables_match_corpus() {
    // Guard against silent rot in both directions: every tracked/inexpressible
    // entry must still exist in the corpus, and no entry may be marked static.
    let vectors = load_validation();
    for (factory, case, why) in TRACKED.iter().chain(INEXPRESSIBLE) {
        let row = vectors
            .iter()
            .find(|v| v.factory == *factory && v.case == *case);
        let Some(row) = row else {
            panic!("tracked row {factory}/{case} ({why}) no longer in corpus — prune the table");
        };
        assert!(
            row.rust_static.is_none(),
            "{factory}/{case} is both tracked and rust_static — pick one"
        );
    }
}
```

- [ ] **Step B6.2: Run + verify both directions:**

```bash
nix develop --command cargo test --all-features keripy_parity::validation -- --nocapture
nix develop --command cargo test --all-features keripy_parity::validation -- --ignored --nocapture
```

Expected: main sweep PASS (enforced rows reject: `sith_zero`, `sith_exceeds_keys`, `nsith_exceeds_ndigs`, `sn_zero`; control rows build Ok). Ignored probe FAILS listing the #149 rows — that red is the acceptance evidence, quote it in the PR. If a supposedly-TRACKED row already rejects, remove it from `TRACKED` (the gap closed under us); if a supposedly-enforced row is accepted, that's a NEW finding — file an issue and move it to `TRACKED` with the new ref.

- [ ] **Step B6.3: Commit:**

```bash
git add cesr/src/keripy_parity/validation.rs
git commit -m "test(parity): #151 validation matrix sweep — builders vs keripy factories (tracked #149)"
```

### Task B7: Divergence ledger — `docs/keripy-parity/ledger.md`

**Files:**
- Create: `docs/keripy-parity/ledger.md`

- [ ] **Step B7.1: Write the ledger.** One section per deliberate divergence; every `divergence` marker and skipped-row class in the corpus must have an entry here, and vice versa. Content (extend with whatever B4.2/B5.2 triage produced):

```markdown
# keripy Parity — Divergence Ledger

Deliberate, documented divergences between cesr and the pinned keripy
(`scripts/KERIPY_PIN`). Every `divergence`-marked corpus row and every
skipped-row class in `cesr/src/keripy_parity/` maps to an entry here.
**Documented divergence ≠ discovered divergence** — anything not listed here
that the sweeps surface is a bug.

Temporarily-open gaps are NOT listed here — they live in Rust-side tracked
tables (`TRACKED_SEALS` → #150, `TRACKED`/`INEXPRESSIBLE` → #149) beside
`#[ignore]`d bug-probes that fail while the gap exists.

## Ilks: TEL / ACDC message types

cesr implements the KERI KEL core ilks (`icp rot ixn dip drt rct qry rpy exn`).
keripy's `Ilks` additionally carries registry (TEL: `vcp vrt iss rev bis brv`)
and ACDC/v2 types (`xip pro bar rip bup upd acm act acg ace sch att agg edg
rul`). These are out of cesr's scope (primitives crate for the KEL layer);
corpus rows carry the divergence marker.

## Strong-majority `ample`

keripy's `ample(n, weak=False)` maximizes `m`; no cesr call site consumes it
(the witness-threshold default uses the weak form, matching keripy's own
factory defaults). The corpus carries strong rows for the day a consumer
exists; the sweep counts and skips them.

## PreDex: deferred key-type codes

<filled during Task B5 triage: each deferred code (expected: Ed448 family,
ECDSA variants not on the RustCrypto stable generation), its keripy codex
name/code, and the deferral rationale.>

## Type-system-enforced factory rejections

keripy validates `cnfg`/`data` are lists at runtime; cesr's builders take
`Vec<ConfigTrait>` / `Vec<Seal>`, so the malformed inputs are unrepresentable.
Corpus rows carry `rust_static` markers; the sweep counts and skips them.

## Arbitrary anchor dicts

keripy accepts fully arbitrary dicts as anchors (`data` validated only as a
list). cesr's strict reader parses only the seal codex shapes. Policy decision
tracked in #150; once decided, this entry records the outcome.
```

- [ ] **Step B7.2: Commit:**

```bash
git add docs/keripy-parity/ledger.md
git commit -m "docs(parity): #151 divergence ledger"
```

### Task B8: Proof of teeth (mutation checks — NOT committed)

Acceptance items from #151. Each mutation is applied, the red is observed and captured for the PR body, then reverted.

- [ ] **Step B8.1: ample mutation (reintroduces the exact #147 bug).** In `cesr/src/serder/ample.rs:23` change `let f_floor = (faultable / 3).max(1);` to `let f_floor = faultable / 3;` — then:

```bash
nix develop --command cargo test --all-features keripy_parity::formulas::ample_matches_keripy_table -- --nocapture
```

Expected: FAIL at `ample(3)` (left: 2, right: 3) — the historic #147 value. Capture the output, then:

```bash
git checkout -- cesr/src/serder/ample.rs
```

- [ ] **Step B8.2: Codex mutation.** In `cesr/src/keri/config.rs:51` delete the line `"NRB" => Ok(Self::NoRegistrarBackers),` — then:

```bash
nix develop --command cargo test --all-features keripy_parity::codex::codex_tables_match_keripy -- --nocapture
```

Expected: FAIL (panic `trait NoRegistrarBackers (NRB): unknown config trait`). Capture, then:

```bash
git checkout -- cesr/src/keri/config.rs
```

- [ ] **Step B8.3: Seal mutation.** In `cesr/src/serder/deserialize/reference.rs:529-534` delete the `Root` arm (`} else if has("rd") && n == 1 { ... }`) — then run the codex sweep as in B8.2. Expected: FAIL on `SealRoot`. Capture, then:

```bash
git checkout -- cesr/src/serder/deserialize/reference.rs
git status   # must be clean of mutations before proceeding
```

### Task B9: Nightly regen wiring — `.github/workflows/keripy-diff.yml`

**Files:**
- Modify: `.github/workflows/keripy-diff.yml`

- [ ] **Step B9.1: Extend the regen step** (after Phase A the file already resolves `KERIPY_REF` from `scripts/KERIPY_PIN`). Replace:

```yaml
      - name: Regenerate corpus
        run: |
          python scripts/keripy_diff_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy
          git --no-pager diff --stat -- cesr/tests/corpus/keripy || true
```

with:

```yaml
      - name: Regenerate corpus
        run: |
          python scripts/keripy_diff_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy
          python scripts/keripy_parity_gen.py --keripy /tmp/keripy --out cesr/tests/corpus/keripy/parity
          git --no-pager diff --stat -- cesr/tests/corpus/keripy || true
```

- [ ] **Step B9.2: Widen the harness filter.** Replace:

```yaml
      - name: Run differential harness against the fresh corpus
        run: nix develop --command cargo test --all-features keripy_diff -- --nocapture
```

with:

```yaml
      - name: Run differential harness against the fresh corpus
        run: nix develop --command cargo test --all-features keripy -- --nocapture
```

(the substring filter `keripy` matches both `keripy_diff::` and `keripy_parity::` test paths).

- [ ] **Step B9.3: Update the PR body text** (lines 84-90) to mention all corpus families:

```yaml
          body: |
            Nightly **keripy-diff** regenerated the primitive + parity corpus from
            keripy `${{ env.KERIPY_REF }}` (pin: `scripts/KERIPY_PIN`).

            A non-empty diff means keripy's output moved or the generator surfaced
            new coverage — review the vector delta before merging (a new codex
            entry, changed formula row, or new validation rule is a visible diff,
            not silent rot). If the harness step failed, a real cesr↔keripy
            disagreement exists: do **not** merge; file a bug and fix cesr (or
            `#[ignore]` the case with a tracking issue).
```

- [ ] **Step B9.4: Lint the workflow + commit:**

```bash
nix develop --command actionlint .github/workflows/keripy-diff.yml
git add .github/workflows/keripy-diff.yml
git commit -m "ci(parity): #151 nightly regen + drift-PR covers parity corpus families"
```

### Task B10: Full gate + PR (Phase B)

- [ ] **Step B10.1: Full gate on committed state:**

```bash
git status   # must be clean — everything committed
nix flake check
```

Expected: green (clippy at god-level over the new module included — fix code, never `#[allow]` without a load-bearing reason).

- [ ] **Step B10.2: PR** with the teeth evidence:

```bash
git push -u origin feat/151-keripy-parity-gate
gh pr create --repo devrandom-labs/cesr \
  --title "test(parity): #151 keripy parity gate — codex/formula/validation vectors" \
  --body "$(cat <<'EOF'
Closes #151. Built on the #156 repin (`scripts/KERIPY_PIN` = de59bc7d).

Three deterministic vector families generated from pinned keripy, checked in,
swept hermetically in `nix flake check` (no python at check time):

- `codex.jsonl` — TraitDex/DigDex/PreDex/Ilks/seal shapes; SealBack/SealKind
  tracked red via `#[ignore]` probe (#150)
- `formulas.jsonl` — ample 0..=256 weak+strong, Tholder.satisfy samples
- `validation.jsonl` — executed factory rejection matrix + control rows;
  witness-validation gaps tracked red via `#[ignore]` probe (#149)

**Proof of teeth (mutations applied → red → reverted):**
- ample `f_floor` mutation reintroducing #147 → formula sweep red at n=3: <paste B8.1 output>
- `ConfigTrait` NRB arm deleted → codex sweep red: <paste B8.2 output>
- Seal `Root` reader arm deleted → codex sweep red: <paste B8.3 output>

Divergence ledger: `docs/keripy-parity/ledger.md` (TEL/ACDC ilks, strong ample,
deferred PreDex codes, type-enforced rejections, arbitrary anchors pending #150).

Nightly `keripy-diff.yml` now regenerates all families; keripy drift opens a PR.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Paste the actual captured mutation outputs — never leave the angle-bracket placeholders.

- [ ] **Step B10.3: Clean up the keripy worktree:**

```bash
git -C /Users/joel/Code/keripy worktree remove \
  /private/tmp/claude-501/-Users-joel-Code-devrandom-cesr/0bdb48ce-299f-4bc4-a643-b85b5e2b2df5/scratchpad/keripy-pin
```

---

## Self-review notes

- **Spec coverage:** #156 fix list → A2 (single pin source), A2.3 (commit clone), A3 (regen + triage), A3.4/A2.3 (docs/workflow refs), A2.4 (python req). #151 acceptance → B8 (mutation-proven ample + codex teeth), B2-B6 (three families generated/checked-in/swept, tracked reds referencing #149/#150), B9 (nightly regen), B7 (ledger with intive/v2 divergences — intive is write-emission territory recorded under the ilk/TEL entry if it surfaces, else out of this card's families).
- **Type consistency:** `load_codex/load_formulas/load_validation` names match between mod.rs and the three sweep files; `CodexVector.sample` is `Option<Value>`; `ValidationVector.raises` is `Option<String>` (control rows emit `null`); generator emits list params always-present per `normalize()`, which the Rust `replay()` relies on.
- **Known judgment points the executor must NOT decide silently:** (1) any `tholder_satisfy` red (B4.2) — semantic divergence, surface to the user in the PR; (2) any changed primitive-corpus bytes in A3.2 — investigate, never rubber-stamp; (3) new PreDex gaps beyond the RustCrypto deferral set (B5.2) — file issues.
