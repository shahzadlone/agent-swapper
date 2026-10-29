#!/usr/bin/env python3
"""Build candidate binaries without embedding local workspace or home paths."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
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
    subprocess.run(["cargo", "+1.98.0", "build", "--locked", "--release", "-p", "agentswapper-cli", "--bins"],
                   cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    main()
