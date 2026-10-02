#!/usr/bin/env python3
"""Measure linked WASM probes and resolved dependencies for CESR feature costs."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
TARGET = "wasm32-unknown-unknown"
SOURCE = {
    "core": """
use subject::core::matter::builder::MatterBuilder;
use subject::core::matter::code::DigestCode;
#[unsafe(no_mangle)]
pub extern "C" fn probe() -> usize {
    let value = MatterBuilder::new().with_code(DigestCode::Blake3_256)
        .with_raw(&[7u8; 32][..]).unwrap().build().unwrap();
    value.to_qb64().len()
}
""",
    "ed25519": """
use subject::{Ed25519, KeyPair};
#[unsafe(no_mangle)]
pub extern "C" fn probe() -> usize {
    let key = KeyPair::<Ed25519>::from_seed_bytes(&[7u8; 32]);
    let signature = key.sign(b"measure").unwrap();
    usize::from(key.verify(b"measure", &signature).is_ok())
}
""",
    "argon2": """
use subject::crypto::salt::{Salt, Tier};
#[unsafe(no_mangle)]
pub extern "C" fn probe() -> usize {
    let salt = Salt::from_raw(&[7u8; 16]).unwrap();
    let key = salt.key_pair("measure", Tier::Low).unwrap();
    let signature = key.sign(b"measure").unwrap();
    usize::from(key.verify(b"measure", &signature).is_ok())
}
""",
}
GRAPH_PROFILES = (("keri-core", []), ("keri-wire", ["wire"]))


def run(command, env):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def main():
    target_dir = ROOT / "target" / "a17-size"
    environment = {**os.environ, "CARGO_TARGET_DIR": str(target_dir)}
    with tempfile.TemporaryDirectory(prefix="cesr-size-") as temp:
        root = Path(temp)
        for label, source in SOURCE.items():
            project = root / label
            (project / "src").mkdir(parents=True)
            (project / "src" / "lib.rs").write_text(source)
            features = "core" if label == "core" else "crypto"
            (project / "Cargo.toml").write_text(
                f'[package]\nname = "size-{label}"\nversion = "0.0.0"\nedition = "2024"\n'
                '[lib]\ncrate-type = ["cdylib"]\n'
                f'[dependencies]\nsubject = {{ package = "cesr-rs", path = "{ROOT / "crates/cesr"}", '
                f'default-features = false, features = ["{features}"] }}\n'
                '[profile.release]\nopt-level = 3\nlto = true\ncodegen-units = 1\n'
                'strip = "symbols"\npanic = "abort"\n'
            )
            manifest = str(project / "Cargo.toml")
            metadata = json.loads(run([
                "cargo", "metadata", "--offline", "--format-version", "1",
                "--filter-platform", TARGET, "--manifest-path", manifest,
            ], environment))
            names = {item["id"]: item["name"] for item in metadata["packages"]}
            dependencies = {names[node["id"]] for node in metadata["resolve"]["nodes"]}
            run([
                "cargo", "build", "--offline", "--release", "--target", TARGET,
                "--manifest-path", manifest,
            ], environment)
            artifact = target_dir / TARGET / "release" / f"size_{label}.wasm"
            print(json.dumps({
                "probe": label,
                "target": TARGET,
                "release": "opt=3,lto,codegen-units=1,strip,panic=abort",
                "resolved_packages": len(dependencies),
                "argon2_resolved": "argon2" in dependencies,
                "wasm_bytes": artifact.stat().st_size,
            }, sort_keys=True), flush=True)
        for label, features in GRAPH_PROFILES:
            project = root / label
            (project / "src").mkdir(parents=True)
            (project / "src" / "lib.rs").write_text("pub use subject::*;\n")
            selected = ", ".join(f'"{feature}"' for feature in features)
            (project / "Cargo.toml").write_text(
                f'[package]\nname = "size-{label}"\nversion = "0.0.0"\nedition = "2024"\n'
                f'[dependencies]\nsubject = {{ package = "keri-rs", path = "{ROOT / "crates/keri"}", '
                f'default-features = false, features = [{selected}] }}\n'
            )
            metadata = json.loads(run([
                "cargo", "metadata", "--offline", "--format-version", "1",
                "--filter-platform", TARGET, "--manifest-path", str(project / "Cargo.toml"),
            ], environment))
            names = {item["id"]: item["name"] for item in metadata["packages"]}
            dependencies = {names[node["id"]] for node in metadata["resolve"]["nodes"]}
            print(json.dumps({
                "probe": label,
                "target": TARGET,
                "resolved_packages": len(dependencies),
                "argon2_resolved": "argon2" in dependencies,
                "codec_resolved": "keri-codec" in dependencies,
                "wasm_bytes": None,
            }, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
