#!/usr/bin/env python3
"""Compare independently built binaries to a verified preview candidate."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib
import zipfile

from verify_candidate_set import verify_one
from release_candidate import verify_build_marker


def compare(archive, target, binaries):
    suffix = ".exe" if "windows" in target else ""
    with zipfile.ZipFile(archive) as candidate:
        for name in ("aswp" + suffix, "agentswapper" + suffix):
            path = binaries / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
                raise ValueError(f"rebuilt {name} is missing or invalid")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            expected = hashlib.sha256(candidate.read(name)).hexdigest()
            if actual != expected:
                raise ValueError(f"rebuilt {name} does not match candidate")
            print(f"{name}: {actual}")


def verify_rebuild(directory, target, revision, lock, version, source_files, binaries):
    archive = verify_one(directory, target, revision, lock, version, source_files)
    suffix = ".exe" if "windows" in target else ""
    local = {}
    for name in ("aswp" + suffix, "agentswapper" + suffix):
        path = binaries / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
            raise ValueError(f"rebuilt {name} is missing or invalid")
        local[name] = path.read_bytes()
    marker = binaries / "agentswapper-build.json"
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 65536:
        raise ValueError("rebuilt candidate marker is missing or invalid")
    verify_build_marker(json.loads(marker.read_text(encoding="utf-8")), revision, False, lock, local)
    compare(archive, target, binaries)


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


if __name__ == "__main__":
    main()
