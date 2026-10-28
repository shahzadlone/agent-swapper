#!/usr/bin/env python3
"""Exercise bare-command dashboard entry in an isolated POSIX pseudoterminal."""

import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time


def drain(master, process, output, until=None):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if until is not None and until in output:
            return
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            output.extend(data)
        elif process.poll() is not None:
            break
    if until is not None:
        raise AssertionError(f"dashboard did not render expected fixture text: {until!r}")
    if process.poll() is None:
        raise AssertionError("dashboard did not exit before deadline")


def check(binary, quit_key):
    with tempfile.TemporaryDirectory(prefix="aswp-dashboard-") as directory:
        root = Path(directory)
        state = root / "state"
        env = {"HOME": str(root), "TERM": "xterm-256color", "LANG": "C.UTF-8"}
        command = [str(binary), "--state-dir", str(state)]
        subprocess.run(command + ["profile", "add", "claude", "--alias", "private-canary"],
                       env=env, check=True, capture_output=True, timeout=10)
        subprocess.run(command + ["config", "set", "ui.mask", "true"],
                       env=env, check=True, capture_output=True, timeout=10)
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        process = None
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                       cwd=root, env=env)
            output = bytearray()
            drain(master, process, output, b"profile-1")
            assert b"\x1b[?1049h" in output, "bare command did not enter dashboard"
            assert not termios.tcgetattr(slave)[3] & termios.ICANON, "raw mode was not enabled"
            assert b"private-canary" not in output, "saved masking leaked account label"
            os.write(master, b"e")
            # Ratatui emits cell differences, not complete sentences. Verify the
            # actual mutation rather than searching its incremental ANSI stream.
            deadline = time.monotonic() + 10
            while True:
                recorded = subprocess.run(command + ["profile", "show", "private-canary", "--json"],
                                          env=env, check=True, capture_output=True, timeout=10)
                if json.loads(recorded.stdout)["data"]["profile"]["enabled"] is False:
                    break
                assert time.monotonic() < deadline, "keyboard action was not persisted"
                time.sleep(0.05)
            os.write(master, b"/private-canary")
            drain(master, process, output, b"[hidden]")
            assert b"private-canary" not in output, "search bypassed privacy"
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 17, 44, 0, 0))
            # Leave search, expose help after a resize, then exercise the exit key.
            os.write(master, b"\r?")
            drain(master, process, output, b"Navigation:")
            os.write(master, quit_key)
            drain(master, process, output)
            assert process.wait(timeout=2) == 0
            assert b"\x1b[?1049l" in output, "alternate screen was not restored"
            assert termios.tcgetattr(slave) == before, "terminal attributes were not restored"
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            os.close(master)
            os.close(slave)

        # Explicit JSON remains noninteractive even when attached to a terminal.
        json_state = root / "json-state"
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen([str(binary), "--state-dir", str(json_state), "--json"],
                                       stdin=slave, stdout=slave, stderr=slave, env=env)
            output = bytearray()
            drain(master, process, output)
            assert process.wait(timeout=2) == 0
            assert b"\x1b[?1049h" not in output
            assert json.loads(output)["data"]["status"] == "developer_preview"
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            os.close(master)
            os.close(slave)
        assert not json_state.exists()


def main():
    if os.name != "posix" or len(sys.argv) != 3:
        raise SystemExit("Usage on POSIX: check_dashboard_pty.py PATH_TO_ASWP PATH_TO_AGENTSWAPPER")
    check(Path(sys.argv[1]).resolve(strict=True), b"q")
    check(Path(sys.argv[2]).resolve(strict=True), b"\x03")
    print("Bare dashboard, privacy, persisted availability, resize, q/Ctrl-C and terminal restoration: pass")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Dashboard PTY check::{message}")
        raise
