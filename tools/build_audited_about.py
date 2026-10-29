#!/usr/bin/env python3
"""Build the reviewed attribution tool and check cached binary consistency."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import audit_attribution_tool as audit


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_installed(binary=None):
    binary = Path(binary or shutil.which("cargo-about") or "")
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("audited cargo-about binary is missing")
    marker = binary.parent / "cargo-about-build.json"
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("audited cargo-about build marker is missing")
    expected = {"schema": 1, "source_sha256": audit.PINS["cargo-about-0.9.3"],
                "lock_sha256": audit.AUDITED["cargo-about-0.9.3/Cargo.lock"],
                "binary_sha256": digest(binary.read_bytes())}
    if json.loads(marker.read_text(encoding="utf-8")) != expected:
        raise ValueError("audited cargo-about build marker does not match")
    version = subprocess.run([str(binary), "--version"], check=True, capture_output=True,
                             text=True, timeout=30).stdout.strip()
    if version != "cargo-about 0.9.3":
        raise ValueError("unexpected cargo-about version")


def build(root):
    # The audit checks pinned archive and extracted source before cargo builds.
    audit.main()
    command = ["cargo", "+1.98.0", "install", "cargo-about", "--version", "0.9.3", "--locked", "--features", "cli", "--force"]
    if root is not None:
        command += ["--root", str(root)]
    subprocess.run(command, cwd=audit.ROOT, check=True, timeout=1800)
    bin_dir = (root or Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))) / "bin"
    binary = bin_dir / ("cargo-about.exe" if os.name == "nt" else "cargo-about")
    marker = {"schema": 1, "source_sha256": audit.PINS["cargo-about-0.9.3"],
              "lock_sha256": audit.AUDITED["cargo-about-0.9.3/Cargo.lock"],
              "binary_sha256": digest(binary.read_bytes())}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=bin_dir, delete=False) as file:
            temporary = Path(file.name)
            json.dump(marker, file, sort_keys=True)
            file.write("\n")
        os.replace(temporary, bin_dir / "cargo-about-build.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    verify_installed(binary)
    print("Reviewed attribution tool built and verified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        if args.root is not None:
            parser.error("--root cannot be used with --verify-only")
        verify_installed()
        print("Reviewed attribution tool marker verified")
    else:
        build(args.root)


if __name__ == "__main__":
    main()
