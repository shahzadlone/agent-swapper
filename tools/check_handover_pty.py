#!/usr/bin/env python3
"""Check hidden handover entry, cancellation and signal cleanup using fictional data."""

import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import tty

from check_dashboard_pty import drain, read_available, wait_for_consumed_input
from terminal_fixture import same_terminal_configuration


PASSPHRASE = b"fixture-only-passphrase-canary"
PARTIAL = b"partial-secret-canary"


class Sandbox:
    def __init__(self, binary, root):
        self.binary = binary
        self.root = root
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.note = self.workspace / "HANDOVER.md"
        self.note.write_text("# Fictional handover\nPreserve a fixture task.\n")
        self.env = {"HOME": str(root), "PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "C.UTF-8"}
        self.base = [str(binary), "--state-dir", str(root / "state")]
        subprocess.run(self.base + ["profile", "add", "claude", "--alias", "fixture"],
                       env=self.env, check=True, capture_output=True, timeout=10)

    def disconnect(self, confirmation, partial):
        """A non-controlling PTY sends no SIGHUP when its peer disappears."""
        destination = self.root / "disconnected.age"
        command = self.base + ["handover", "pack", "--from", "fixture", "--input", str(self.note),
                               "--output", str(destination)]
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                       cwd=self.workspace, env=self.env, start_new_session=True)
            output = bytearray()
            drain(master, process, output, b"Handover passphrase:")
            if confirmation:
                os.write(master, PASSPHRASE + b"\r")
                drain(master, process, output, b"Confirm passphrase:")
            if partial:
                os.write(master, PARTIAL + partial)
                wait_for_consumed_input(slave, master, process, output)
            os.close(master)
            master = None
            assert process.wait(timeout=3) == 125, "disconnected prompt did not fail cleanly"
            assert not destination.exists(), "disconnected entry published ciphertext"
            assert PASSPHRASE not in output and PARTIAL not in output
            print(f"peer-disconnect confirm={confirmation} partial={partial!r}: pass", flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            if master is not None:
                os.close(master)
            os.close(slave)

    def check(self, name, action, confirmation=False, passphrase=PASSPHRASE):
        output_path = self.root / f"{name}.age"
        command = self.base + ["handover", "pack", "--from", "fixture", "--input", str(self.note),
                               "--output", str(output_path), "--workspace", str(self.workspace)]
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        process = None
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                       cwd=self.workspace, env=self.env)
            output = bytearray()
            drain(master, process, output, b"Handover passphrase:")
            assert not termios.tcgetattr(slave)[3] & (termios.ICANON | termios.ECHO)
            if confirmation:
                os.write(master, passphrase + b"\r")
                drain(master, process, output, b"Confirm passphrase:")
            expected_signal = None
            if isinstance(action, int):
                os.write(master, PARTIAL)
                process.send_signal(action)
                expected_signal = action
            elif action in ("partial-utf8", "partial-csi"):
                os.write(master, PARTIAL + (b"\xc3" if action == "partial-utf8" else b"\x1b["))
                wait_for_consumed_input(slave, master, process, output)
                process.send_signal(signal.SIGTERM)
                expected_signal = signal.SIGTERM
            elif action == "spill":
                process.send_signal(signal.SIGSTOP)
                await_stopped(process)
                # Queue secret bytes while the reader is stopped. Never block
                # on a full PTY input buffer; its capacity differs across OSes.
                os.set_blocking(master, False)
                try:
                    os.write(master, PARTIAL * 120)
                except BlockingIOError:
                    pass
                finally:
                    os.set_blocking(master, True)
                process.send_signal(signal.SIGTERM)
                process.send_signal(signal.SIGCONT)
                expected_signal = signal.SIGTERM
            elif action == "cancel":
                os.write(master, PARTIAL + b"\x03")
            elif action == "mismatch":
                os.write(master, b"different-fixture-passphrase\r")
            elif action in ("success", "slow-unicode", "crypto-signal"):
                if action == "slow-unicode":
                    # Split a multibyte character across multiple poll/read
                    # deadlines. It must survive rather than being discarded.
                    os.write(master, passphrase[:-1])
                    wait_for_consumed_input(slave, master, process, output)
                    time.sleep(0.3)
                    os.write(master, passphrase[-1:] + b"\r")
                else:
                    os.write(master, passphrase + b"\r")
                drain(master, process, output, b"Confirm passphrase:")
                os.write(master, passphrase + b"\r")
                if action == "crypto-signal":
                    # Observe the real boundary after hidden entry has restored
                    # the terminal, while the fixed-cost KDF is still running.
                    deadline = time.monotonic() + 10
                    while not termios.tcgetattr(slave)[3] & termios.ICANON:
                        assert time.monotonic() < deadline, "hidden entry did not finish"
                        read_available(master, output)
                        time.sleep(0.001)
                    # Move past prompt teardown into the fixed log-18 KDF;
                    # signal handling must still be active at this point.
                    time.sleep(0.01)
                    assert process.poll() is None, "pack completed before the crypto interrupt fixture"
                    process.send_signal(signal.SIGTERM)
                    expected_signal = signal.SIGTERM
            else:
                raise AssertionError(f"unknown action: {action}")
            drain(master, process, output)
            result = process.wait(timeout=2)
            if expected_signal is not None:
                assert result == -expected_signal, "original signal termination was lost"
            elif action in ("success", "slow-unicode"):
                assert result == 0, f"interactive pack failed: {bytes(output[-800:])!r}"
            else:
                assert result != 0
                assert (b"did not match" if action == "mismatch" else b"cancelled") in output
            after = termios.tcgetattr(slave)
            assert same_terminal_configuration(before, after), f"hidden entry left terminal settings modified: before={before!r}; after={after!r}"
            assert PASSPHRASE not in output and PARTIAL not in output, "hidden entry echoed secret input"
            if action == "spill":
                tty.setraw(slave)
                try:
                    assert not select.select([slave], [], [], 0)[0], "unread secret bytes remained for the shell"
                finally:
                    termios.tcsetattr(slave, termios.TCSANOW, before)
            if action in ("success", "slow-unicode"):
                assert output_path.is_file()
                inspected = subprocess.run(self.base + ["handover", "inspect", str(output_path),
                                                        "--passphrase-stdin", "--json"],
                                           input=passphrase + b"\n", env=self.env, capture_output=True,
                                           check=True, timeout=30)
                assert PASSPHRASE not in inspected.stdout + inspected.stderr
                assert json.loads(inspected.stdout)["data"]["documentBytes"] == len(self.note.read_bytes())
            else:
                assert not output_path.exists(), "cancelled entry published ciphertext"
            print(f"{name}: pass", flush=True)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            os.close(master)
            os.close(slave)


def await_stopped(process):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        pid, status = os.waitpid(process.pid, os.WUNTRACED | os.WNOHANG)
        if pid:
            if os.WIFSTOPPED(status):
                assert os.WSTOPSIG(status) == signal.SIGSTOP
                return
            # Reaping an unexpected exit must update Popen before failure
            # cleanup, so it cannot signal a recycled PID.
            process.returncode = os.waitstatus_to_exitcode(status)
            raise AssertionError("hidden entry exited before the stop fixture")
        time.sleep(0.01)
    raise AssertionError("hidden entry did not stop")


def main():
    if os.name != "posix" or len(sys.argv) != 2:
        raise SystemExit("Usage on POSIX: check_handover_pty.py PATH_TO_ASWP")
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="aswp-handover-pty-") as directory:
        sandbox = Sandbox(binary, Path(directory))
        for confirmation in [False, True]:
            for partial in [b"", b"\xc3", b"\x1b["]:
                sandbox.disconnect(confirmation, partial)
            phase = "confirm" if confirmation else "first"
            for quit_signal in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
                sandbox.check(f"{phase}-{quit_signal.name}", quit_signal, confirmation)
            sandbox.check(f"{phase}-keyboard-cancel", "cancel", confirmation)
            sandbox.check(f"{phase}-partial-utf8-SIGTERM", "partial-utf8", confirmation)
            sandbox.check(f"{phase}-partial-csi-SIGTERM", "partial-csi", confirmation)
        sandbox.check("queued-secret-spill", "spill")
        sandbox.check("mismatch", "mismatch", confirmation=True)
        sandbox.check("post-prompt-crypto-SIGTERM", "crypto-signal")
        sandbox.check("pack-and-inspect", "success")
        sandbox.check("slow-unicode-pack-and-inspect", "slow-unicode", passphrase=PASSPHRASE + b"-\xc3\xa9")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Handover PTY check::{message}", flush=True)
        raise
