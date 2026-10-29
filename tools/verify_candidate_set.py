#!/usr/bin/env python3
"""Validate preview archives before the separate provenance-signing job."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

TARGETS = {
    "unsigned-candidate-Linux-X64": "x86_64-unknown-linux-gnu",
    "unsigned-candidate-macOS-ARM64": "aarch64-apple-darwin",
    "unsigned-candidate-Windows-X64": "x86_64-pc-windows-msvc",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_archive_name(name):
    path = PurePosixPath(name)
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if not name or path.is_absolute() or "\\" in name:
        return False
    for part in name.split("/"):
        if (part in ("", ".", "..") or part.endswith((" ", "."))
                or part.split(".", 1)[0].upper() in reserved
                or any(c in '<>:"|?*' or ord(c) < 32 or ord(c) == 127 for c in part)):
            return False
    return True


def verify_one(directory, target, revision, lock_hash):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("candidate directory is missing or linked")
    entries = list(directory.iterdir())
    archives = [p for p in entries if p.name.endswith(".zip")]
    if len(archives) != 1 or len(entries) != 2:
        raise ValueError("candidate must contain exactly one archive and checksum")
    archive = archives[0]
    if not re.fullmatch(r"agentswapper-[A-Za-z0-9_.+\-]+-" + re.escape(target) + r"\.zip", archive.name):
        raise ValueError("unexpected candidate archive name")
    checksum = directory / (archive.name + ".sha256")
    if archive.is_symlink() or checksum.is_symlink() or not archive.is_file() or not checksum.is_file():
        raise ValueError("candidate files must be regular and unlinked")
    if archive.stat().st_size > 256 * 1024 * 1024 or checksum.stat().st_size > 1024:
        raise ValueError("candidate exceeds size limits")
    data = archive.read_bytes()
    if checksum.read_text(encoding="utf-8") != f"{digest(data)}  {archive.name}\n":
        raise ValueError("candidate checksum mismatch")
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > 4096 or len(names) != len(set(names)) or sum(e.file_size for e in entries) > 512 * 1024 * 1024:
            raise ValueError("candidate entries exceed bounds or are duplicated")
        for entry in entries:
            name = entry.filename
            mode = entry.external_attr >> 16
            if not safe_archive_name(name) or stat.S_IFMT(mode) != stat.S_IFREG:
                raise ValueError("candidate contains an unsafe entry")
        info = bundle.getinfo("BUILD-INFO.json")
        if info.file_size > 1024 * 1024:
            raise ValueError("candidate build information exceeds bounds")
        manifest = json.loads(bundle.read(info))
        if (manifest.get("schema") != 1 or manifest.get("source_revision") != revision
                or manifest.get("source_dirty") is not False or manifest.get("target") != target
                or manifest.get("cargo_lock_sha256") != lock_hash):
            raise ValueError("candidate build information does not match this run")
        version = manifest.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_.+\-]+", version) or archive.name != f"agentswapper-{version}-{target}.zip":
            raise ValueError("candidate version does not match its archive name")
        suffix = ".exe" if "windows" in target else ""
        if not {"aswp" + suffix, "agentswapper" + suffix, "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt", "PREVIEW.txt"}.issubset(names):
            raise ValueError("candidate is missing required files")
        if any((bundle.getinfo(name + suffix).external_attr >> 16) & 0o777 != 0o755 for name in ("aswp", "agentswapper")):
            raise ValueError("candidate executable modes do not match")
        preview = bundle.getinfo("PREVIEW.txt")
        if preview.file_size > 4096 or not bundle.read(preview).startswith(b"Internal developer preview; not a signed or published release.\n"):
            raise ValueError("candidate preview label is missing")
        hashes = manifest.get("files")
        if not isinstance(hashes, dict) or set(hashes) != set(names) - {"BUILD-INFO.json"}:
            raise ValueError("candidate file inventory does not match")
        for name, expected in hashes.items():
            if not isinstance(expected, str) or digest(bundle.read(name)) != expected:
                raise ValueError("candidate file hash mismatch")
    return archive


def verify_set(root, revision, lock_hash):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("invalid source revision")
    if not re.fullmatch(r"[0-9a-f]{64}", lock_hash):
        raise ValueError("invalid lockfile hash")
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != set(TARGETS):
        raise ValueError("candidate platform set is incomplete or unexpected")
    return [verify_one(root / name, target, revision, lock_hash) for name, target in TARGETS.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("revision")
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    args = parser.parse_args()
    archives = verify_set(args.root, args.revision, digest(args.lockfile.read_bytes()))
    print(f"Verified {len(archives)} candidate archives for this source revision")


if __name__ == "__main__":
    main()
