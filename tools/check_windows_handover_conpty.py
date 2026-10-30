#!/usr/bin/env python3
"""Exercise hidden passphrases through ConPTY using only fictional task data."""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from check_windows_dashboard_conpty import Session


PASSWORD = b"fictional-handover-secret-canary"
NOTE = "# Fixture task\nKeep fictional-context-canary private.\n"


def check(binary, fixture, case):
    with tempfile.TemporaryDirectory(prefix="aswp-secret-conpty-") as directory:
        root = Path(directory).resolve()
        (root / "workspace").mkdir()
        (root / "bin").mkdir()
        note = root / "workspace" / "HANDOVER.md"
        note.write_text(NOTE, encoding="utf-8")
        env = {key: value for key, value in os.environ.items()
               if key.upper() in {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}}
        env.update({key: str(root) for key in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"]})
        env.update({"PATH": str(root / "bin"), "TERM": "xterm-256color", "ASWP_CONPTY_FIXTURE": "1"})
        command = [str(binary), "--state-dir", str(root / "state")]

        def cli(*args, input=None):
            return subprocess.run(command + list(args), cwd=root / "workspace", env=env,
                                  input=input, check=True, capture_output=True, timeout=30)

        cli("profile", "add", "claude", "--alias", "fixture")
        pack = root / "task.age"
        pickup = root / "PICKUP_CONTEXT.md"
        arguments = ["handover", "pack", "--from", "fixture", "--input", str(note), "--output", str(pack)]
        if case in {"inspect", "wrong-password", "pickup-file"}:
            cli(*arguments, "--passphrase-stdin", input=PASSWORD + b"\n")
            arguments = ["handover", "inspect", str(pack)]
            if case == "pickup-file":
                arguments = ["handover", "pickup", str(pack), "--target", "codex", "--output", str(pickup)]
        expected = 130 if case in {"escape", "ctrl-c", "confirm-cancel"} else 125 if case in {
            "mismatch", "unsupported-key", "wrong-password"} else 0
        (root / "fixture-command.json").write_text(json.dumps([arguments, expected]), encoding="utf-8")
        session = Session([str(fixture), "__handover_host", str(binary), str(root)], env, root / "workspace")
        try:
            session.wait_output(b"Handover passphrase: ")
            if case in {"escape", "ctrl-c", "unsupported-key"}:
                session.send(PASSWORD + {"escape": b"\x1b", "ctrl-c": b"\x03", "unsupported-key": b"\t"}[case])
            else:
                session.send((b"fictional-wrong-secret-canary" if case == "wrong-password" else PASSWORD) + b"\r")
                if case in {"pack", "mismatch", "confirm-cancel"}:
                    session.wait_output(b"Confirm passphrase: ")
                    session.send(PASSWORD + (b"-different\r" if case == "mismatch" else b"\x1b" if case == "confirm-cancel" else b"\r"))
            deadline = time.monotonic() + 30
            while session.alive():
                if session.error is not None:
                    raise session.error
                if time.monotonic() >= deadline:
                    raise AssertionError(f"{case}: hidden entry did not exit")
                time.sleep(0.02)
            code = w.DWORD()
            session.api.require(session.api.GetExitCodeProcess(session.process, c.byref(code)))
            result = json.loads((root / "console-result.json").read_bytes())
            assert result["exitCode"] == expected, (case, result)
            assert result["inputBefore"] & 7 == 6, (case, result)
            assert result["inputBefore"] == result["inputAfter"], (case, result)
            assert result["outputBefore"] == result["outputAfter"], (case, result)
            assert code.value == 0, (case, code.value)
        finally:
            session.close()
        # Include bytes drained during ClosePseudoConsole in the leak check.
        output = bytes(session.output)
        for canary in [PASSWORD, b"fictional-wrong-secret-canary", b"fictional-context-canary"]:
            assert canary not in output, f"{case}: secret/context was echoed"
        if case == "pack":
            assert pack.read_bytes().startswith(b"age-encryption.org/v1")
            assert PASSWORD not in pack.read_bytes()
        elif case == "pickup-file":
            assert "fictional-context-canary" in pickup.read_text(encoding="utf-8")
        elif case not in {"inspect", "wrong-password"}:
            assert not pack.exists(), case
        print(f"Windows handover ConPTY: {case} passed", flush=True)


def main():
    if os.name != "nt" or len(sys.argv) != 3:
        raise SystemExit("Usage on Windows: check_windows_handover_conpty.py PATH_TO_ASWP PATH_TO_WINDOWS_DASHBOARD_PROBE")
    binary, fixture = [Path(value).resolve(strict=True) for value in sys.argv[1:]]
    for case in ["escape", "ctrl-c", "confirm-cancel", "mismatch", "unsupported-key", "pack", "inspect", "wrong-password", "pickup-file"]:
        check(binary, fixture, case)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Windows handover ConPTY::{message}", flush=True)
        raise
