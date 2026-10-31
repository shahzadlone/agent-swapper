#!/usr/bin/env python3
"""Record non-secret platform facts for versioned custody verification."""

import json
import os
import platform
import subprocess
from pathlib import Path


def windows_update_build_revision():
    if os.name != "nt":
        return None
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            value, kind = winreg.QueryValueEx(key, "UBR")
        return value if kind == winreg.REG_DWORD and isinstance(value, int) else None
    except OSError:
        return None


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
        "windows_update_build_revision": windows_update_build_revision(),
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
