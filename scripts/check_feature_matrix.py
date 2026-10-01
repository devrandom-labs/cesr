#!/usr/bin/env python3
"""Compile published feature profiles as independent downstream consumers.

Each manifest has one path dependency, so workspace dev dependencies and Cargo's
feature unification cannot make a broken standalone feature look healthy.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
PROFILES = (
    ("cesr-rs", "", "empty"),
    ("cesr-rs", "", "default"),
    ("cesr-rs", "b64", "b64"),
    ("cesr-rs", "core", "core"),
    ("cesr-rs", "crypto", "crypto"),
    ("cesr-rs", "std,core", "std-core"),
    ("cesr-stream", "alloc", "alloc"),
    ("cesr-stream", "", "default"),
    ("cesr-stream", "async", "async"),
    ("cesr-stream", "std,async", "std-async"),
    ("keri-events", "alloc", "alloc"),
    ("keri-events", "", "default"),
    ("keri-codec", "alloc", "alloc"),
    ("keri-codec", "", "default"),
    ("keri-rs", "", "core"),
    ("keri-rs", "", "default"),
    ("keri-rs", "wire", "wire"),
    ("keri-rs", "std,wire", "std-wire"),
    ("keri-rs", "credential-verification", "credential"),
)


def crate_path(package):
    directory = {"cesr-rs": "cesr", "keri-rs": "keri"}.get(package, package)
    return ROOT / "crates" / directory


def check_resolution(project, package, label, features):
    command = [
        "cargo", "metadata", "--offline", "--format-version", "1",
        "--manifest-path", str(project / "Cargo.toml"),
    ]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        return False
    metadata = json.loads(result.stdout)
    names = {item["id"]: item["name"] for item in metadata["packages"]}
    resolved = {
        names[node["id"]]: set(node["features"])
        for node in metadata["resolve"]["nodes"]
        if names[node["id"]] in {"cesr-rs", "cesr-stream", "keri-events", "keri-codec", "keri-rs"}
    }
    errors = []
    if "test-utils" in resolved.get("cesr-rs", set()):
        errors.append("production consumer enabled cesr-rs/test-utils")
    if package == "keri-rs" and label in {"core", "default"}:
        if "keri-codec" in resolved:
            errors.append("core-only keri-rs pulled wire codec")
    if package == "cesr-rs" and label == "b64":
        if resolved["cesr-rs"] & {"core", "crypto"}:
            errors.append("b64-only cesr-rs pulled core or crypto")
    if package == "cesr-stream" and label == "alloc":
        if "crypto" in resolved.get("cesr-rs", set()):
            errors.append("alloc-only cesr-stream pulled crypto")
    if label != "default" and "std" not in features.split(",") and "async" not in features.split(",") and "credential-verification" not in features.split(","):
        for dependency, enabled in resolved.items():
            if "std" in enabled:
                errors.append(f"{dependency} enabled std in a no-std profile")
    if errors:
        print("; ".join(errors), file=sys.stderr, flush=True)
    return not errors


def check_profile(directory, package, features, label, target):
    project = directory / f"{package}-{label}"
    (project / "src").mkdir(parents=True)
    (project / "src" / "lib.rs").write_text("pub use subject::*;\n")
    selected = ", ".join(f'"{feature}"' for feature in features.split(",") if feature)
    defaults = "true" if label == "default" else "false"
    (project / "Cargo.toml").write_text(
        f'[package]\nname = "matrix-{package}-{label}"\nversion = "0.0.0"\n'
        f'edition = "2024"\n[dependencies]\n'
        f'subject = {{ package = "{package}", path = "{crate_path(package)}", '
        f'default-features = {defaults}, features = [{selected}] }}\n'
    )
    command = ["cargo", "check", "--offline", "--manifest-path", str(project / "Cargo.toml")]
    if target:
        command.extend(("--target", target))
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    resolution_ok = check_resolution(project, package, label, features)
    status = "PASS" if result.returncode == 0 and resolution_ok else "FAIL"
    print(f"{package:12} {label:20} {target or 'host':26} {status}", flush=True)
    if result.returncode:
        print("\n".join(result.stderr.splitlines()[-24:]), file=sys.stderr, flush=True)
    return result.returncode == 0 and resolution_ok


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="Cargo target triple; default is the host")
    args = parser.parse_args()
    packages = {package for package, _, label in PROFILES if label == "default"}
    unique_profiles = {(package, label) for package, _, label in PROFILES}
    if len(PROFILES) != 19 or len(unique_profiles) != 19 or len(packages) != 5:
        raise SystemExit("expected 19 unique profiles and one default for each of five crates")
    os.environ.setdefault("CARGO_TARGET_DIR", str(ROOT / "target" / "feature-matrix"))
    with tempfile.TemporaryDirectory(prefix="cesr-feature-matrix-") as temp:
        directory = Path(temp)
        results = [
            check_profile(directory, package, features, label, args.target)
            for package, features, label in PROFILES
        ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
