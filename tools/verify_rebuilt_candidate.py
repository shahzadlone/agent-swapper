#!/usr/bin/env python3
"""Compare independently built binaries to a verified preview candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

from verify_candidate_set import RebuildMismatch, read_bounded, verify_one
from release_candidate import verify_build_marker


def verify_rebuild(directory, target, revision, lock, version, source_files, binaries):
    suffix = ".exe" if "windows" in target else ""
    local = {}
    for name in ("aswp" + suffix, "agentswapper" + suffix):
        path = binaries / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
            raise ValueError(f"rebuilt {name} is missing or invalid")
        local[name] = read_bounded(path, 256 * 1024 * 1024)
    marker = binaries / "agentswapper-build.json"
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 65536:
        raise ValueError("rebuilt candidate marker is missing or invalid")
    verify_build_marker(json.loads(read_bounded(marker, 65536).decode("utf-8")), revision, False, lock, local)
    binary_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in local.items()}
    verify_one(directory, target, revision, lock, version, source_files, binary_hashes)
    for name, value in binary_hashes.items():
        print(f"{name}: {value}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, help="directory containing one candidate and checksum")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    revision = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=root,
                              check=True, capture_output=True, text=True).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root,
                            check=True, capture_output=True, text=True).stdout
    if status:
        raise ValueError("rebuilt candidate requires a clean working tree")
    rust = subprocess.run(["rustc", "+1.98.0", "-vV"], cwd=root,
                          check=True, capture_output=True, text=True).stdout
    target = next(line.removeprefix("host: ") for line in rust.splitlines() if line.startswith("host: "))
    lock = hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest()
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    source_files = {name: (root / name).read_bytes() for name in
                    ("LICENSE", "NOTICE", "assets/brand/THIRD_PARTY_NOTICES.txt")}
    verify_rebuild(args.candidate, target, revision, lock, version, source_files,
                   root / "target" / "release")


def diagnostic(error):
    if (isinstance(error, RebuildMismatch)
            and error.name in {"aswp", "agentswapper", "aswp.exe", "agentswapper.exe"}
            and re.fullmatch(r"[0-9a-f]{64}", error.candidate)
            and re.fullmatch(r"[0-9a-f]{64}", error.rebuilt)):
        return f"{error.name} differs: candidate SHA-256 {error.candidate}; rebuilt SHA-256 {error.rebuilt}"
    known = {
        "candidate directory is missing or linked": "candidate directory invalid",
        "candidate must contain exactly one archive and checksum": "candidate inventory invalid",
        "candidate checksum mismatch": "candidate checksum mismatch",
        "candidate build information does not match this run": "candidate source binding mismatch",
        "candidate binaries do not match the current build marker; rebuild them": "rebuild marker mismatch",
        "rebuilt candidate requires a clean working tree": "rebuild checkout is dirty",
        "rebuilt candidate marker is missing or invalid": "rebuild marker missing or invalid",
    }
    category = known.get(str(error))
    if category:
        return category
    name = type(error).__name__
    return "verification failed (" + (name if name.isalnum() else "error") + ")"


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print(f"::error title=Candidate rebuild::{diagnostic(error)}", flush=True)
        raise
