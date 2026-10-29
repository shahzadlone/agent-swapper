#!/usr/bin/env python3
"""Build and verify an unsigned CI candidate; this never publishes a release."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from build_audited_deny import verify_installed
from build_audited_about import verify_installed as verify_about

ROOT = Path(__file__).resolve().parents[1]
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.+\-]+$")


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, timeout=180, **kwargs).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")) or "\\" in name or "\x00" in name:
        raise ValueError(f"unsafe archive entry: {name!r}")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    for part in name.split("/"):
        if part.endswith((" ", ".")) or part.split(".", 1)[0].upper() in reserved or any(c in '<>:"|?*' or ord(c) < 32 or ord(c) == 127 for c in part):
            raise ValueError(f"nonportable archive entry: {name!r}")
    return str(path)


def add(files, name, path, mode=0o644):
    name = safe_path(name)
    if name in files or path.is_symlink() or not path.is_file():
        raise ValueError(f"invalid or duplicate input: {name}")
    files[name] = (path.read_bytes(), mode)


def reject_build_paths(binary, paths, windows):
    for path in paths:
        variants = {str(path), str(path).replace("\\", "/")}
        for variant in variants:
            needle = os.fsencode(variant)
            if len(needle) < 5:
                raise ValueError("build path too short to verify")
            if needle.lower() in binary.lower() if windows else needle in binary:
                raise ValueError("local build path found; use build_candidate_binaries.py")


def verify_build_marker(marker, revision, dirty, lock_hash, binaries):
    expected = {"schema": 1, "revision": revision, "dirty": dirty,
                "lock_sha256": lock_hash,
                "binaries": {name: digest(data) for name, data in binaries.items()}}
    if marker != expected:
        raise ValueError("candidate binaries do not match the current build marker; rebuild them")


def add_locked_source(files, crate_bytes, expected_checksum):
    if digest(crate_bytes) != expected_checksum:
        raise ValueError("option-ext crate checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(crate_bytes), mode="r:gz") as original:
        members = original.getmembers()
        if len(members) > 1000 or sum(m.size for m in members) > 5 * 1024 * 1024:
            raise ValueError("option-ext crate exceeds source bounds")
        for member in members:
            name = safe_path(member.name)
            if not name.startswith("option-ext-0.2.0/"):
                raise ValueError("unexpected option-ext crate root")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("link or special file in option-ext crate")
            stream = original.extractfile(member)
            if stream is None:
                raise ValueError("missing option-ext source content")
            destination = safe_path("source/" + name)
            if destination in files:
                raise ValueError("duplicate option-ext source entry")
            files[destination] = (stream.read(), 0o644)


def write_candidate(output, filename, payload):
    if safe_path(filename) != filename or "/" in filename:
        raise ValueError("invalid candidate filename")
    output.mkdir(parents=True, exist_ok=True)
    archive_path = output / filename
    checksum_path = output / (filename + ".sha256")
    # Refuse to replace existing artifacts, including symlinks. Remove only
    # files this invocation created if either write or close fails.
    archive_created = False
    checksum_created = False
    try:
        with archive_path.open("xb") as destination:
            archive_created = True
            destination.write(payload)
        with checksum_path.open("x", encoding="utf-8", newline="\n") as destination:
            checksum_created = True
            destination.write(f"{digest(payload)}  {filename}\n")
    except BaseException:
        if checksum_created:
            checksum_path.unlink()
        if archive_created:
            archive_path.unlink()
        raise
    return archive_path


def candidate(output, allow_dirty):
    revision = run(["git", "rev-parse", "--verify", "HEAD"], text=True).strip()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("invalid source revision")
    dirty = bool(run(["git", "status", "--porcelain", "--untracked-files=all"], text=True).strip())
    if dirty and not allow_dirty:
        raise ValueError("working tree is dirty; use --allow-dirty only for local testing")
    verify_installed()
    run(["cargo", "deny", "--locked", "check"])
    rust = run(["rustc", "-vV"], text=True).strip()
    if not rust.startswith("rustc 1.98.0 "):
        raise ValueError("candidate must use the pinned Rust 1.98.0 toolchain")
    host = next(line.split(": ", 1)[1] for line in rust.splitlines() if line.startswith("host: "))
    if not SAFE_NAME.fullmatch(host):
        raise ValueError("invalid Rust host triple")
    metadata = json.loads(run(["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", host]))
    package = next(p for p in metadata["packages"] if p["name"] == "agentswapper-cli" and p["source"] is None)
    version = package["version"]
    if not SAFE_NAME.fullmatch(version):
        raise ValueError("invalid workspace version")
    suffix = ".exe" if "windows" in host else ""
    files = {}
    for name in ("aswp", "agentswapper"):
        add(files, name + suffix, ROOT / "target" / "release" / (name + suffix), 0o755)
        reject_build_paths(files[name + suffix][0], (ROOT, Path.home()), os.name == "nt")
    marker_path = ROOT / "target/release/agentswapper-build.json"
    if marker_path.is_symlink() or not marker_path.is_file():
        raise ValueError("candidate build marker is missing; rebuild the binaries")
    verify_build_marker(json.loads(marker_path.read_text(encoding="utf-8")), revision, dirty,
                        digest((ROOT / "Cargo.lock").read_bytes()),
                        {name + suffix: files[name + suffix][0] for name in ("aswp", "agentswapper")})
    for name in ("LICENSE", "NOTICE"):
        add(files, name, ROOT / name)
    add(files, "assets/brand/THIRD_PARTY_NOTICES.txt", ROOT / "assets/brand/THIRD_PARTY_NOTICES.txt")
    verify_about()
    licenses = run(["cargo", "about", "generate", "--locked", "--workspace", "--fail", "tools/licenses.hbs"])
    if not licenses.strip() or b"option-ext" not in licenses:
        raise ValueError("dependency attribution is incomplete")
    files["THIRD_PARTY_LICENSES.txt"] = (licenses, 0o644)
    # Preserve actual NOTICE files as well as the generated license texts.
    for dependency in metadata["packages"]:
        if dependency["source"] is None:
            continue
        name, ver = dependency["name"], dependency["version"]
        if not SAFE_NAME.fullmatch(name) or not SAFE_NAME.fullmatch(ver):
            raise ValueError("invalid dependency identity")
        directory = Path(dependency["manifest_path"]).parent
        for path in sorted(directory.iterdir()):
            if path.name.upper().startswith("NOTICE") and path.is_file():
                add(files, f"notices/{name}-{ver}/{path.name}", path)
    # option-ext is unmodified MPL-2.0 code. Verify the original published crate
    # against Cargo.lock and carry its complete source with the binary.
    matches = [p for p in metadata["packages"] if p["name"] == "option-ext"]
    if len(matches) != 1 or matches[0]["version"] != "0.2.0" or not (matches[0]["source"] or "").startswith("registry+"):
        raise ValueError("expected registry option-ext 0.2.0 source")
    source = Path(matches[0]["manifest_path"]).parent
    registry = source.parent.parent.parent
    crate = registry / "cache" / source.parent.name / "option-ext-0.2.0.crate"
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    lock_entries = [p for p in lock["package"] if p["name"] == "option-ext" and p["version"] == "0.2.0" and p.get("source", "").startswith("registry+")]
    if len(lock_entries) != 1 or crate.is_symlink() or not crate.is_file():
        raise ValueError("missing locked option-ext crate")
    crate_bytes = crate.read_bytes()
    add_locked_source(files, crate_bytes, lock_entries[0]["checksum"])
    files["PREVIEW.txt"] = (b"Internal developer preview; not a signed or published release.\nProvider isolation and automatic switching are unverified or incomplete.\nSee https://github.com/shahzadlone/agent-swapper for documentation.\n", 0o644)
    manifest = {
        "schema": 1, "version": version, "target": host, "source_revision": revision,
        "source_dirty": dirty, "rustc": rust, "cargo_lock_sha256": digest((ROOT / "Cargo.lock").read_bytes()),
        "files": {name: digest(data) for name, (data, _) in sorted(files.items())},
    }
    files["BUILD-INFO.json"] = ((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), 0o644)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name, (data, mode) in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, data)
    payload = archive.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload)) as bundle, tempfile.TemporaryDirectory(prefix="aswp-release-check-") as temp:
        if bundle.testzip() is not None or len(bundle.namelist()) != len(set(bundle.namelist())):
            raise ValueError("corrupt or duplicate archive entry")
        if set(bundle.namelist()) != set(files) or json.loads(bundle.read("BUILD-INFO.json")) != manifest:
            raise ValueError("archive contents or build manifest changed")
        for name, expected in manifest["files"].items():
            if digest(bundle.read(name)) != expected:
                raise ValueError(f"archive hash mismatch: {name}")
        for name in ("aswp" + suffix, "agentswapper" + suffix):
            if (bundle.getinfo(name).external_attr >> 16) & 0o777 != 0o755:
                raise ValueError(f"executable mode missing: {name}")
            dest = Path(temp) / name
            dest.write_bytes(bundle.read(name))
            dest.chmod(0o755)
            env = {"HOME": temp, "USERPROFILE": temp}
            for key in ("SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"):
                if key in os.environ:
                    env[key] = os.environ[key]
            state = Path(temp) / "state"
            result = subprocess.run([str(dest), "--state-dir", str(state), "--help"], cwd=temp, env=env,
                                    capture_output=True, timeout=20, check=True)
            if b"Usage:" not in result.stdout or state.exists():
                raise ValueError(f"archive smoke check failed: {name}")
    filename = f"agentswapper-{version}-{host}.zip"
    archive_path = write_candidate(output, filename, payload)
    print(f"Verified unsigned candidate: {archive_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-dirty", action="store_true", help="mark dirty local builds; never use for publication")
    args = parser.parse_args()
    try:
        candidate(args.output, args.allow_dirty)
    except Exception as error:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            # The candidate environment contains no real provider credentials.
            # Do not include captured subprocess output, which can contain
            # arbitrary package-provided text; include only the exception.
            detail = f"{type(error).__name__}: {error}"[-3000:]
            detail = detail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=Candidate packaging::{detail}", flush=True)
        raise


if __name__ == "__main__":
    main()
