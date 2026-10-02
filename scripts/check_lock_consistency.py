"""Require every Cargo workspace lock to use its local path crates' versions."""

from pathlib import Path
import sys
import tomllib


MANIFESTS = {
    "cesr-rs": "crates/cesr/Cargo.toml",
    "cesr-stream": "crates/cesr-stream/Cargo.toml",
    "keri-events": "crates/keri-events/Cargo.toml",
    "keri-codec": "crates/keri-codec/Cargo.toml",
    "keri-rs": "crates/keri/Cargo.toml",
    "fuzz-common": "fuzz-common/Cargo.toml",
    "cesr-fuzz": "fuzz/Cargo.toml",
    "cesr-fuzz-afl": "fuzz-afl/Cargo.toml",
}

LOCKS = {
    "Cargo.lock": ("cesr-rs", "cesr-stream", "keri-events", "keri-codec", "keri-rs"),
    "fuzz-common/Cargo.lock": (
        "cesr-rs", "cesr-stream", "keri-events", "keri-codec", "fuzz-common"
    ),
    "fuzz/Cargo.lock": (
        "cesr-rs", "cesr-stream", "keri-events", "keri-codec", "fuzz-common", "cesr-fuzz"
    ),
    "fuzz-afl/Cargo.lock": (
        "cesr-rs", "cesr-stream", "keri-events", "keri-codec", "fuzz-common", "cesr-fuzz-afl"
    ),
}


def read_toml(path: Path) -> dict:
    with path.open("rb") as file:
        return tomllib.load(file)


def check(root: Path) -> list[str]:
    versions = {
        name: read_toml(root / manifest)["package"]["version"]
        for name, manifest in MANIFESTS.items()
    }
    errors = []
    for lock, required in LOCKS.items():
        entries = read_toml(root / lock)["package"]
        for name in required:
            matching = [entry for entry in entries if entry["name"] == name]
            if len(matching) != 1:
                errors.append(f"{lock}: expected one {name} entry, found {len(matching)}")
                continue
            actual = matching[0]
            if actual.get("source") is not None:
                errors.append(f"{lock}: {name} must resolve from the local path")
            if actual["version"] != versions[name]:
                errors.append(
                    f"{lock}: {name} is {actual['version']}, "
                    f"but {MANIFESTS[name]} is {versions[name]}"
                )
    return errors


if __name__ == "__main__":
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    problems = check(root)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        sys.exit(1)
    print("all four Cargo locks match their local path-crate manifests")
