#!/usr/bin/env python3
"""Build candidate binaries without embedding local workspace or home paths."""
import os
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    def output(*args):
        return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    revision = output("git", "rev-parse", "--verify", "HEAD")
    status = output("git", "status", "--porcelain", "--untracked-files=all")
    source_epoch = output("git", "show", "-s", "--format=%ct", revision)
    if not source_epoch.isascii() or not source_epoch.isdecimal() or len(source_epoch) > 16:
        raise SystemExit("commit timestamp is invalid for SOURCE_DATE_EPOCH")
    env = os.environ.copy()
    if env.get("RUSTFLAGS") or env.get("CARGO_ENCODED_RUSTFLAGS") or env.get("CARGO_TARGET_DIR"):
        raise SystemExit("unset RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS and CARGO_TARGET_DIR for a candidate build")
    if any("=" in str(path) or "\x1f" in str(path) for path in (Path.home(), ROOT)):
        raise SystemExit("home and workspace paths must not contain '=' or the unit-separator character")
    # The encoded form preserves spaces in paths on all supported hosts.
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
        "--remap-path-prefix", f"{Path.home()}=/build-home",
        "--remap-path-prefix", f"{ROOT}=/src/agentswapper",
    ])
    # Independent builders use the same source timestamp, regardless of the
    # host clock or a caller-provided SOURCE_DATE_EPOCH.
    env["SOURCE_DATE_EPOCH"] = source_epoch
    subprocess.run(["cargo", "+1.98.0", "build", "--locked", "--release", "-p", "agentswapper-cli", "--bins"],
                   cwd=ROOT, env=env, check=True)
    if revision != output("git", "rev-parse", "--verify", "HEAD") or status != output("git", "status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("source revision or working-tree state changed during build")
    suffix = ".exe" if os.name == "nt" else ""
    release = ROOT / "target/release"
    marker = {
        "schema": 1,
        "revision": revision,
        "dirty": bool(status),
        "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(),
        "binaries": {name + suffix: hashlib.sha256((release / (name + suffix)).read_bytes()).hexdigest()
                     for name in ("aswp", "agentswapper")},
    }
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=release, delete=False) as file:
            temporary = Path(file.name)
            json.dump(marker, file, sort_keys=True)
            file.write("\n")
        os.replace(temporary, release / "agentswapper-build.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
