#!/usr/bin/env python3
"""Run the Linux fixture inside an already delegated cgroup; never set one up."""

import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


def main():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise SystemExit("The fixture requires an unprivileged Linux process")
    if len(sys.argv) != 2:
        raise SystemExit("Usage: run_delegated_custody_probe.py PATH_TO_PROBE")
    binary = Path(sys.argv[1]).resolve(strict=True)
    entries = [
        line.removeprefix("0::")
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    ]
    if len(entries) != 1:
        raise SystemExit("No unique cgroup v2 membership")
    if not re.fullmatch(r"/system\.slice/aswp-custody-\d+-\d+\.service", entries[0]):
        raise SystemExit("Run only inside the dedicated CI systemd service; no automatic local setup")
    relative = PurePosixPath(entries[0])
    if not relative.is_absolute() or ".." in relative.parts or relative == PurePosixPath("/"):
        raise SystemExit("Refusing an ambiguous or root cgroup")
    parent = Path("/sys/fs/cgroup").joinpath(*relative.parts[1:])
    # The Rust probe validates filesystem type, links, owner, permissions,
    # membership and writable control files before creating unique child groups.
    return subprocess.run([str(binary), str(parent)], check=False, timeout=90).returncode


if __name__ == "__main__":
    raise SystemExit(main())
