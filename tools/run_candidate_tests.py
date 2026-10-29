#!/usr/bin/env python3
"""Run candidate safety tests and expose failures in CI annotations."""
import os
import subprocess
import sys


def main():
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tools", "-p", "test_release_candidate.py", "-v"],
        env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode and env.get("GITHUB_ACTIONS") == "true":
        detail = (result.stdout + result.stderr)[-6000:]
        escaped = detail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Candidate safety tests::{escaped}", flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
