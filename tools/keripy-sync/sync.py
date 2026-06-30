#!/usr/bin/env python3
"""keripy-sync — deterministic CESR code-table parity report generator.

Parses the CESR code tables on both sides — keripy's Python `*Codex` dataclasses
and cesr's Rust code enums — and renders a markdown parity report listing the
codes keripy defines that cesr does not yet implement (the "gap"), plus codes
cesr has that keripy doesn't (for awareness).

Deterministic and stdlib-only: no network (caller provides a keripy checkout),
no LLM, output sorted by code. The only field that changes between runs is the
keripy commit the report was generated against — so the report's diff in a PR is
exactly "what changed in keripy's tables since last time".

Codes are compared by their canonical Base64 value (e.g. `A`, `-A`, `--A`), not
by name, because the two projects spell names differently (keripy `Ed25519_Seed`
vs cesr `Ed25519Seed`) while the code value is the stable CESR identifier.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

KERIPY_REPO = "WebOfTrust/keripy"

# One entry per CESR code table we track. `cesr_mode` selects how a code value is
# extracted from the Rust source, because each table encodes it differently:
#   strum       -> #[strum(serialize = "A")]
#   doc_lead    -> /// `-A` — ...        (counter codes, leading backtick token)
#   doc_quoted  -> /// ... — `"A"`       (indexer codes, backtick-quoted token)
TABLES = [
    {
        "title": "Matter — primitives",
        "keripy_file": "src/keri/core/coring.py",
        "keripy_class": "MatterCodex",
        "keripy_test": "tests/core/test_coring.py",
        "cesr_files": ["src/core/matter/code/matter_code.rs"],
        "cesr_mode": "strum",
    },
    {
        "title": "Counter v1 — CESR 1.0 groups",
        "keripy_file": "src/keri/core/counting.py",
        "keripy_class": "CounterCodex_1_0",
        "keripy_test": "tests/core/test_counting.py",
        "cesr_files": ["src/core/counter/code.rs"],
        "cesr_mode": "doc_lead",
    },
    {
        "title": "Counter v2 — CESR 2.0 groups",
        "keripy_file": "src/keri/core/counting.py",
        "keripy_class": "CounterCodex_2_0",
        "keripy_test": "tests/core/test_counting.py",
        "cesr_files": ["src/core/counter/v2.rs"],
        "cesr_mode": "doc_lead",
    },
    {
        "title": "Indexer — indexed signatures",
        "keripy_file": "src/keri/core/indexing.py",
        "keripy_class": "IndexerCodex",
        "keripy_test": "tests/core/test_indexing.py",
        "cesr_files": ["src/core/indexer/code.rs"],
        "cesr_mode": "doc_quoted",
    },
]

# A keripy codex entry:  Name: str = 'CODE'  # optional description
KERIPY_ENTRY = re.compile(
    r"""^\s+(?P<name>\w+)\s*:\s*str\s*=\s*["'](?P<code>[^"']+)["']\s*(?:\#\s*(?P<desc>.*))?$"""
)
# Anchored to the start of the line so a `#[strum(...)]` mentioned inside a doc
# comment (`/// ... via #[strum(serialize = "...")]`) is not parsed as a real code.
CESR_STRUM = re.compile(r"""^\s*#\[strum\(serialize\s*=\s*"(?P<code>[^"]+)"\)\]""")
CESR_DOC_LEAD = re.compile(r"""^\s*///\s*`(?P<code>-{1,2}[A-Za-z0-9_]+)`""")
CESR_DOC_QUOTED = re.compile(r"""`"(?P<code>[^"]+)"`""")


@dataclass(frozen=True)
class Entry:
    code: str
    name: str
    desc: str
    line: int


def is_placeholder(e: Entry) -> bool:
    """keripy reserves `TBD*` / 'Test of ...' codex slots as future placeholders;
    they are not real codes to implement, so they are excluded from the gap."""
    return e.name.upper().startswith("TBD") or e.desc.lower().startswith("test of")


def parse_keripy_class(path: Path, class_name: str) -> list[Entry]:
    """Extract the codex entries of a single `class <class_name>:` block."""
    entries: list[Entry] = []
    in_class = False
    class_re = re.compile(rf"^class\s+{re.escape(class_name)}\b")
    for lineno, raw in enumerate(path.read_text().splitlines(), start=1):
        if not in_class:
            if class_re.match(raw):
                in_class = True
            continue
        # A new top-level `class ` (column 0) ends the block.
        if raw.startswith("class "):
            break
        m = KERIPY_ENTRY.match(raw)
        if m:
            entries.append(
                Entry(
                    code=m.group("code"),
                    name=m.group("name"),
                    desc=(m.group("desc") or "").strip(),
                    line=lineno,
                )
            )
    return entries


def parse_cesr_codes(files: list[Path], mode: str) -> set[str]:
    """Extract the set of code values cesr implements for one table."""
    pat = {"strum": CESR_STRUM, "doc_lead": CESR_DOC_LEAD, "doc_quoted": CESR_DOC_QUOTED}[mode]
    codes: set[str] = set()
    for path in files:
        if not path.exists():
            continue
        for raw in path.read_text().splitlines():
            m = pat.search(raw)
            if m:
                codes.add(m.group("code"))
    return codes


def keripy_ref(keripy_root: Path, override: str | None) -> str:
    """The keripy ref to pin permalinks to. Prefer an explicit tag (stable
    between releases, so the report doesn't churn on every keripy commit); fall
    back to the checkout's HEAD sha for local runs."""
    if override:
        return override
    try:
        return subprocess.check_output(
            ["git", "-C", str(keripy_root), "rev-parse", "HEAD"], text=True
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "main"


def permalink(ref: str, file: str, line: int) -> str:
    return f"https://github.com/{KERIPY_REPO}/blob/{ref}/{file}#L{line}"


def render(keripy_root: Path, cesr_root: Path, ref: str) -> str:
    out: list[str] = []
    out.append("# keripy parity report")
    out.append("")
    out.append(
        "> **Generated by `tools/keripy-sync/sync.py` — do not edit by hand.** "
        "Lists CESR code-table entries keripy defines that cesr does not yet "
        "implement. Work it by turning gap rows into `keripy-sync` issues."
    )
    out.append("")
    out.append(f"- keripy ref: [`{ref}`](https://github.com/{KERIPY_REPO}/tree/{ref})")
    out.append("")

    tables_rendered = []
    total_gap = 0
    summary_rows = []

    for spec in TABLES:
        kp = parse_keripy_class(keripy_root / spec["keripy_file"], spec["keripy_class"])
        cesr_codes = parse_cesr_codes(
            [cesr_root / f for f in spec["cesr_files"]], spec["cesr_mode"]
        )
        kp_codes = {e.code for e in kp}
        missing = [e for e in kp if e.code not in cesr_codes]
        gap = sorted((e for e in missing if not is_placeholder(e)), key=lambda e: e.code)
        placeholders = sorted((e for e in missing if is_placeholder(e)), key=lambda e: e.code)
        extra = sorted(cesr_codes - kp_codes)
        total_gap += len(gap)
        summary_rows.append(
            (spec["title"], len(kp), len(cesr_codes), len(gap), len(extra))
        )

        section: list[str] = []
        section.append(f"## {spec['title']}")
        section.append("")
        section.append(
            f"keripy `{spec['keripy_class']}`: {len(kp)} codes · "
            f"cesr: {len(cesr_codes)} codes · **gap: {len(gap)}**"
        )
        section.append("")
        if gap:
            section.append("### Gap — in keripy, not in cesr")
            section.append("")
            section.append("| code | keripy name | description | source |")
            section.append("|------|-------------|-------------|--------|")
            for e in gap:
                src = permalink(ref, spec["keripy_file"], e.line)
                desc = e.desc.replace("|", "\\|")
                section.append(
                    f"| `{e.code}` | `{e.name}` | {desc} | [coring]({src}) |"
                )
            section.append("")
            section.append(
                f"Test vectors for these live in keripy "
                f"[`{spec['keripy_test']}`](https://github.com/{KERIPY_REPO}/blob/{ref}/{spec['keripy_test']})."
            )
            section.append("")
        else:
            section.append("_No gap — cesr implements every keripy code in this table._")
            section.append("")
        if placeholders:
            section.append(
                f"_Skipped {len(placeholders)} keripy placeholder/TBD slot(s): "
                + ", ".join(f"`{e.code}` ({e.name})" for e in placeholders)
                + "._"
            )
            section.append("")
        if extra:
            section.append(
                "<details><summary>cesr has "
                f"{len(extra)} code(s) keripy lacks (awareness): "
                + ", ".join(f"`{c}`" for c in extra)
                + "</summary></details>"
            )
            section.append("")
        tables_rendered.append("\n".join(section))

    # Summary table goes first (after the header), built once totals are known.
    summary: list[str] = []
    summary.append(f"**Total gap: {total_gap} codes** across {len(TABLES)} tables.")
    summary.append("")
    summary.append("| table | keripy | cesr | gap | cesr-extra |")
    summary.append("|-------|-------:|-----:|----:|-----------:|")
    for title, k, c, g, x in summary_rows:
        summary.append(f"| {title} | {k} | {c} | {g} | {x} |")
    summary.append("")

    return "\n".join(out + summary + tables_rendered) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--keripy", required=True, type=Path, help="path to a keripy checkout")
    ap.add_argument("--cesr", default=Path.cwd(), type=Path, help="path to the cesr repo root")
    ap.add_argument(
        "--out",
        default=Path("docs/keripy-parity/report.md"),
        type=Path,
        help="report output path (relative to --cesr)",
    )
    ap.add_argument(
        "--ref",
        default=None,
        help="keripy ref (tag/branch/sha) to pin permalinks to; defaults to the checkout HEAD",
    )
    args = ap.parse_args()

    report = render(args.keripy, args.cesr, keripy_ref(args.keripy, args.ref))
    out_path = args.cesr / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report)
    sys.stderr.write(f"keripy-sync: wrote {out_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
