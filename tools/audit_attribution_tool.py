#!/usr/bin/env python3
"""Audit the exact cargo-about build-tool graph before using its binary."""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
CARGO_ROOT = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
PINS = {
    "cargo-deny-0.20.2": "e528dfcbe739af7ce37a77d3d6df1b29dd6887b1c701d888820c0f16b864f737",
    "cargo-about-0.9.3": "f2309e4e7cd6fbb25c4c8d68e69c728936dec58a0cb7940dcb382d5be32aa52b",
    "spdx-0.13.6": "646c5a367da914e3babcb9cd8e91c37ccaac42325b8f86f036513ad103f2a716",
}
AUDITED = {
    "cargo-deny-0.20.2/Cargo.lock": "72524836b04cb973cbd61485b4c11a15c2e67073b3fbd93246563a0e899e7772",
    "cargo-deny-0.20.2/src/licenses/gather.rs": "b69bb8d69826f6e8d52db11eb0bc77c53326dbc1a41dfd6130e2bfa21d6410bf",
    "cargo-about-0.9.3/Cargo.lock": "49f19333a375e6034ab204cedb503fb58f217eadf822beae0d790ba146f1b6bf",
    "cargo-about-0.9.3/src/licenses.rs": "8b5b722219ce42949dbeea341282ab82ab903a27e515a3ab95c816c66cfbaec1",
    "spdx-0.13.6/src/detection/cache.rs": "e29f2edd16efe275ecb630d76621bf38ce52eaa95890e9b688ea7b75be80eada",
    "spdx-0.13.6/src/detection/inline_cache.rs": "3c7625c8ca56d83bfcb3858f8ac00ea70aeb82c02fd7160a948245f4311dd37e",
    "spdx-0.13.6/src/detection/cache.bin.zstd": "713d60670871815f14878c52c7044b6fe3b28e8a65161c7fd4a86f2d6d3aceec",
}


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def run(args):
    subprocess.run(args, cwd=ROOT, check=True, timeout=180)


def verify_crate(name):
    sources = list((CARGO_ROOT / "registry" / "src").glob(f"*/{name}"))
    if len(sources) != 1 or sources[0].is_symlink():
        raise ValueError(f"expected one registry source for {name}")
    source = sources[0]
    archive = CARGO_ROOT / "registry" / "cache" / source.parent.name / f"{name}.crate"
    if archive.is_symlink() or not archive.is_file():
        raise ValueError(f"missing registry archive for {name}")
    data = archive.read_bytes()
    if checksum(data) != PINS[name]:
        raise ValueError(f"registry archive checksum mismatch for {name}")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > 2000 or sum(member.size for member in members) > 16 * 1024 * 1024:
            raise ValueError(f"registry archive exceeds bounds for {name}")
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or "\\" in member.name or "\x00" in member.name or any(p in ("", ".", "..") for p in member.name.split("/")) or not member.name.startswith(name + "/"):
                raise ValueError(f"invalid registry archive path for {name}")
            if member.isdir():
                continue
            if not member.isfile() or member.name in seen:
                raise ValueError(f"invalid registry archive entry for {name}")
            seen.add(member.name)
            relative = path.relative_to(name)
            local = source
            for part in relative.parts:
                local = local / part
                if local.is_symlink():
                    raise ValueError(f"linked registry source for {name}")
            if not local.is_file():
                raise ValueError(f"missing or linked registry source for {name}")
            stream = tar.extractfile(member)
            if stream is None or checksum(stream.read()) != checksum(local.read_bytes()):
                raise ValueError(f"registry source mismatch for {name}")
            audited = AUDITED.get(member.name)
            if audited is not None and checksum(local.read_bytes()) != audited:
                raise ValueError(f"audited source changed for {name}")
    for audited in (key for key in AUDITED if key.startswith(name + "/")):
        if audited not in seen:
            raise ValueError(f"audited source missing for {name}")
    return source


def main():
    from build_audited_deny import verify_installed
    verify_installed()
    # cargo info fetches the crate without running its build scripts.
    run(["cargo", "info", "cargo-about@0.9.3"])
    about = verify_crate("cargo-about-0.9.3")
    manifest = about / "Cargo.toml"
    # Resolve/download the exact locked graph before checking the pinned SPDX source.
    subprocess.run(["cargo", "metadata", "--manifest-path", str(manifest), "--locked", "--features", "cli", "--format-version", "1"],
                   cwd=ROOT, check=True, stdout=subprocess.DEVNULL, timeout=180)
    verify_crate("spdx-0.13.6")
    run(["cargo", "deny", "--manifest-path", str(manifest), "--config", str(ROOT / "tools/build-tools-deny.toml"),
         "--locked", "--features", "cli", "check", "advisories"])
    print("Pinned attribution tool graph and scoped advisory policy verified")


if __name__ == "__main__":
    main()
