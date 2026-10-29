#!/usr/bin/env python3
"""Build the pinned dependency checker with its reviewed runtime lockfile."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

from audit_attribution_tool import ROOT, PINS, verify_crate

LOCK_SHA = "e95a13724b1146d18121ea19c28a7015d67b651ed32ea764f001513f6ffcb88c"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_installed(binary=None):
    if digest((ROOT / "tools/cargo-deny-tool.lock").read_bytes()) != LOCK_SHA:
        raise ValueError("reviewed cargo-deny lockfile changed")
    binary = Path(binary or shutil.which("cargo-deny") or "")
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("audited cargo-deny binary is missing")
    marker = binary.parent / "cargo-deny-attestation.json"
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("audited cargo-deny build marker is missing")
    data = json.loads(marker.read_text(encoding="utf-8"))
    expected = {"schema": 1, "source_sha256": PINS["cargo-deny-0.20.2"],
                "lock_sha256": LOCK_SHA, "binary_sha256": digest(binary.read_bytes())}
    if data != expected:
        raise ValueError("audited cargo-deny build marker does not match")
    version = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    if version != "cargo-deny 0.20.2":
        raise ValueError("unexpected cargo-deny version")


def build(root):
    lock = (ROOT / "tools/cargo-deny-tool.lock").read_bytes()
    if digest(lock) != LOCK_SHA:
        raise ValueError("reviewed cargo-deny lockfile changed")
    subprocess.run(["cargo", "info", "cargo-deny@0.20.2"], check=True, cwd=ROOT, timeout=180)
    source = verify_crate("cargo-deny-0.20.2")
    archive = source.parent.parent.parent / "cache" / source.parent.name / "cargo-deny-0.20.2.crate"
    with tempfile.TemporaryDirectory(prefix="aswp-deny-build-") as directory:
        dest = Path(directory)
        with tarfile.open(archive, "r:gz") as tar:
            seen = set()
            for member in tar.getmembers():
                name = PurePosixPath(member.name)
                if name.is_absolute() or "\\" in member.name or any(p in ("", ".", "..") for p in member.name.split("/")) or not member.name.startswith("cargo-deny-0.20.2/"):
                    raise ValueError("invalid checker source path")
                if member.isdir():
                    continue
                if not member.isfile() or member.name in seen:
                    raise ValueError("invalid checker source entry")
                seen.add(member.name)
                target = dest.joinpath(*name.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = tar.extractfile(member)
                if stream is None:
                    raise ValueError("missing checker source")
                target.write_bytes(stream.read())
                target.chmod(member.mode & 0o777)
        tool = dest / "cargo-deny-0.20.2"
        (tool / "Cargo.lock").write_bytes(lock)
        manifest = str(tool / "Cargo.toml")
        subprocess.run(["cargo", "metadata", "--manifest-path", manifest, "--locked", "--format-version", "1"], cwd=ROOT, check=True, stdout=subprocess.DEVNULL, timeout=180)
        verify_crate("spdx-0.13.6")
        subprocess.run(["cargo", "deny", "--manifest-path", manifest, "--config", str(ROOT / "tools/build-tools-deny.toml"), "--locked", "--exclude-dev", "check", "advisories"], cwd=ROOT, check=True, timeout=180)
        command = ["cargo", "install", "--path", str(tool), "--locked", "--force"]
        if root is not None:
            command += ["--root", str(root)]
        subprocess.run(command, cwd=ROOT, check=True, timeout=1800)
    bin_dir = (root or Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))) / "bin"
    binary = bin_dir / ("cargo-deny.exe" if os.name == "nt" else "cargo-deny")
    marker = {"schema": 1, "source_sha256": PINS["cargo-deny-0.20.2"],
              "lock_sha256": LOCK_SHA, "binary_sha256": digest(binary.read_bytes())}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=bin_dir, delete=False) as file:
            temporary = Path(file.name)
            json.dump(marker, file, sort_keys=True)
            file.write("\n")
        os.replace(temporary, bin_dir / "cargo-deny-attestation.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    verify_installed(binary)
    print("Reviewed dependency checker built and verified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        if args.root is not None:
            parser.error("--root cannot be used with --verify-only")
        verify_installed()
        print("Reviewed dependency checker marker verified")
    else:
        build(args.root)


if __name__ == "__main__":
    main()
