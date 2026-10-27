#!/usr/bin/env python3
"""Run isolated, provider-free consumer contracts against an audited gents checkout."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


PINS = {
    "89f1b6760e2297b3d8a09d347c43eaf6978a8b31": "reviewed-main",
    "b4755abe7b737c91b386908fffeb045333d73eb1": "unmerged-replay-fix",
}
RIG_REV = "b12a51c9c544e1b0f5b3961e0293cf8868868730"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--case", choices=("minimal", "replay"), required=True)
    parser.add_argument("--target-dir", required=True, type=Path)
    parser.add_argument("--check-target", help="Cross-typecheck tests instead of executing them")
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision not in PINS:
        parser.error("source must be one of the two audited revisions in run.py")
    dirty = subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"],
        text=True,
    )
    if dirty:
        parser.error("source has tracked modifications; use a clean detached worktree")

    def dependency(name, extra=""):
        return f'{name} = {{ path = {json.dumps(str(source / "crates" / name))}{extra} }}\n'

    name = "aswp-gents-consumer-spike" if args.case == "minimal" else "aswp-gents-loop-spike"
    manifest = (
        f'[package]\nname = "{name}"\nversion = "0.0.0"\nedition = "2024"\n'
        'publish = false\nlicense = "Apache-2.0"\n[workspace]\n[dependencies]\n'
        + dependency("gents-protocol", ", default-features = false")
        + 'serde_json = "1"\n'
    )
    if args.case == "minimal":
        manifest += dependency("gents-codex-protocol") + dependency("gents-fs-runner")
        manifest += 'tempfile = "3"\n'
    else:
        manifest += dependency("gents-loop", ', features = ["native"]')
        manifest += 'rig-core = { version = "0.35.0", default-features = false }\nchrono = "0.4"\n'
        manifest += (
            '[patch.crates-io]\nrig-core = { git = "https://github.com/jackzampolin/rig", '
            f'rev = "{RIG_REV}" }}\n'
        )

    fixtures = Path(__file__).resolve().parent
    env = os.environ.copy()
    env["RUSTUP_TOOLCHAIN"] = "1.98.0"
    env["CARGO_TARGET_DIR"] = str(args.target_dir.resolve())
    env["CARGO_NET_GIT_FETCH_WITH_CLI"] = "true"
    with tempfile.TemporaryDirectory(prefix="aswp-gents-contract-") as tmp:
        consumer = Path(tmp)
        (consumer / "src").mkdir()
        (consumer / "Cargo.toml").write_text(manifest)
        shutil.copyfile(fixtures / f"{args.case}.rs", consumer / "src/lib.rs")
        shutil.copyfile(fixtures / f"{args.case}.lock", consumer / "Cargo.lock")
        command = ["cargo", "check" if args.check_target else "test", "--locked", "--tests", "-j2"]
        if args.check_target:
            command.extend(["--target", args.check_target])
        print(json.dumps({"revision": revision, "label": PINS[revision], "case": args.case}), flush=True)
        result = subprocess.run(command, cwd=consumer, env=env, check=False)
        print(json.dumps({"exit_code": result.returncode}), flush=True)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
