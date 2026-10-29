#!/usr/bin/env python3
"""Record non-secret platform facts for versioned custody verification."""

import json
import os
import platform
import subprocess
from pathlib import Path


def main():
    rust = subprocess.run(
        ["rustc", "+1.98.0", "-Vv"], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    ).stdout.strip()
    try:
        compiler = subprocess.run(
            ["cc", "--version"], check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        ).stdout.splitlines()[0]
    except (OSError, subprocess.SubprocessError, IndexError):
        compiler = "unavailable"
    evidence = {
        "os": platform.system(),
        "release": platform.release(),
        "build": platform.version(),
        "architecture": platform.machine(),
        "macos": platform.mac_ver()[0],
        "rust": rust,
        "cc_on_path": compiler,
        "libc": platform.libc_ver(),
        "runner_image": os.environ.get("ImageOS", "unknown"),
        "runner_image_version": os.environ.get("ImageVersion", "unknown"),
    }
    encoded = json.dumps(evidence, sort_keys=True)
    destination = Path("target/platform-evidence.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(encoded + "\n", encoding="utf-8")
    # Keep evidence available in public check annotations as well as runner logs.
    escaped = encoded.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::notice title=Platform evidence::{escaped}")


if __name__ == "__main__":
    main()
