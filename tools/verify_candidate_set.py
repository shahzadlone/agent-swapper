#!/usr/bin/env python3
"""Validate preview archives before the separate provenance-signing job."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import tomllib
import zipfile
from portable_archive import ensure_portable_names, safe_path

TARGETS = {
    "unsigned-candidate-Linux-X64": "x86_64-unknown-linux-gnu",
    "unsigned-candidate-macOS-ARM64": "aarch64-apple-darwin",
    "unsigned-candidate-Windows-X64": "x86_64-pc-windows-msvc",
}


class RebuildMismatch(ValueError):
    def __init__(self, name, candidate, rebuilt, detail=None):
        super().__init__("rebuilt executables do not match candidate")
        self.name = name
        self.candidate = candidate
        self.rebuilt = rebuilt
        self.detail = detail


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_bounded(path, limit):
    with path.open("rb") as file:
        data = file.read(limit + 1)
    if len(data) > limit:
        raise ValueError("candidate exceeds size limits")
    return data


def safe_archive_name(name):
    try:
        safe_path(name)
        return True
    except ValueError:
        return False


def verify_one(directory, target, revision, lock_hash, version, source_files, expected_binaries=None,
               rebuilt_contents=None):
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
    data = read_bounded(archive, 256 * 1024 * 1024)
    checksum_text = read_bounded(checksum, 1024).decode("utf-8")
    if checksum_text != f"{digest(data)}  {archive.name}\n":
        raise ValueError("candidate checksum mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        entries = bundle.infolist()
        names = [entry.filename for entry in entries]
        if len(entries) > 4096 or len(names) != len(set(names)) or sum(e.file_size for e in entries) > 512 * 1024 * 1024:
            raise ValueError("candidate entries exceed bounds or are duplicated")
        ensure_portable_names(names)
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
        if manifest.get("version") != version or archive.name != f"agentswapper-{version}-{target}.zip":
            raise ValueError("candidate version does not match checked-out source and archive name")
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
        for name, expected in source_files.items():
            if name not in hashes or hashes[name] != digest(expected):
                raise ValueError("candidate project notice does not match checked-out source")
        if expected_binaries is not None:
            names = {"aswp" + suffix, "agentswapper" + suffix}
            if set(expected_binaries) != names:
                raise ValueError("rebuilt executables do not match candidate")
            for name in sorted(names):
                if hashes[name] != expected_binaries[name]:
                    detail = None
                    if rebuilt_contents is not None and name in rebuilt_contents:
                        candidate = bundle.read(name)
                        rebuilt = rebuilt_contents[name]
                        if digest(rebuilt) == expected_binaries[name]:
                            detail = binary_difference(candidate, rebuilt)
                    raise RebuildMismatch(name, hashes[name], expected_binaries[name], detail)
    return archive


def pe_timestamp(data):
    """Read only the PE COFF timestamp, without trusting offsets from the file."""
    if len(data) < 64 or data[:2] != b"MZ":
        return None
    offset = int.from_bytes(data[60:64], "little")
    if offset > len(data) - 12 or data[offset:offset + 4] != b"PE\0\0":
        return None
    return int.from_bytes(data[offset + 8:offset + 12], "little")


def binary_difference(candidate, rebuilt):
    common = min(len(candidate), len(rebuilt))
    first = next((i for i in range(common) if candidate[i] != rebuilt[i]), common)
    return (len(candidate), len(rebuilt), first, pe_timestamp(candidate), pe_timestamp(rebuilt))


def verify_set(root, revision, lock_hash, version, source_files):
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("invalid source revision")
    if not re.fullmatch(r"[0-9a-f]{64}", lock_hash):
        raise ValueError("invalid lockfile hash")
    if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9_.+\-]+", version):
        raise ValueError("invalid checked-out workspace version")
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()} != set(TARGETS):
        raise ValueError("candidate platform set is incomplete or unexpected")
    return [verify_one(root / name, target, revision, lock_hash, version, source_files) for name, target in TARGETS.items()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("revision")
    parser.add_argument("--lockfile", type=Path, default=Path("Cargo.lock"))
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    version = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    source_files = {name: (source / name).read_bytes() for name in
                    ("LICENSE", "NOTICE", "assets/brand/THIRD_PARTY_NOTICES.txt")}
    archives = verify_set(args.root, args.revision, digest(args.lockfile.read_bytes()), version, source_files)
    print(f"Verified {len(archives)} candidate archives for this source revision")


if __name__ == "__main__":
    main()
