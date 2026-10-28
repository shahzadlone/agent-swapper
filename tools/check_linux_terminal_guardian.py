#!/usr/bin/env python3
"""Exercise the provider-free guardian topology under a real interactive bash/PTY."""

import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import sys
import tempfile
import termios
import time


class Shell:
    def __init__(self, root):
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            os.chdir(root)
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"],
                      {"HOME": str(root), "PATH": "/usr/bin:/bin", "TERM": "xterm-256color",
                       "LANG": "C.UTF-8", "HISTFILE": "/dev/null", "PS1": "__ASWP_READY__ "})
        self.output = bytearray()
        self.status = None
        try:
            self.wait_for(lambda: b"__ASWP_READY__ " in self.output)
        except BaseException:
            self.close()
            raise

    def pump(self):
        if self.master is not None and select.select([self.master], [], [], 0.02)[0]:
            try:
                self.output.extend(os.read(self.master, 65536))
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
        assert len(self.output) <= 256 * 1024, "fixture exceeded terminal output budget"

    def wait_for(self, condition, seconds=10):
        deadline = time.monotonic() + seconds
        while not condition():
            assert time.monotonic() < deadline, f"terminal deadline expired: {bytes(self.output[-1500:])!r}"
            self.pump()
            time.sleep(0.01)

    def send(self, data):
        os.write(self.master, data)

    def prompt(self, offset):
        self.wait_for(lambda: b"__ASWP_READY__ " in self.output[offset:])

    def poll(self):
        if self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = status
        return self.status

    def hangup(self):
        os.close(self.master)
        self.master = None

    def close(self):
        if self.master is not None:
            self.hangup()
        deadline = time.monotonic() + 3
        while self.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if self.status is None:
            # Only signal the unreaped child returned by pty.fork. Its PID cannot
            # have been recycled. No PID from fixture metadata is signalled here.
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)


def marker(shell, root, name):
    path = root / name

    def ready():
        failure = root / "failure"
        assert not failure.exists(), f"Rust fixture failed: {failure.read_text() if failure.exists() else ''}"
        return path.exists()

    shell.wait_for(ready)
    return json.loads(path.read_text())


def foreground(shell, group):
    shell.wait_for(lambda: os.tcgetpgrp(shell.master) == group)


def run_case(binary, mode):
    with tempfile.TemporaryDirectory(prefix="aswp-terminal-guardian-") as directory:
        root = Path(directory)
        shell = Shell(root)
        try:
            command = f"{shlex.quote(str(binary))} parent {shlex.quote(str(root))}"
            if mode == "ignored-signals":
                command = "trap '' INT HUP; " + command + "; rc=$?; trap - INT HUP; (exit $rc)"
            shell.send((command + "\n").encode())
            target = marker(shell, root, "target")
            parent = marker(shell, root, "parent")
            guardian = marker(shell, root, "guardian")
            assert target["group"] == parent["group"] == parent["pid"]
            assert guardian["group"] == guardian["pid"] != parent["group"]
            assert os.tcgetpgrp(shell.master) == target["group"]
            active_settings = termios.tcgetattr(shell.master)

            if mode in ("suspend-resize", "group-kill"):
                offset = len(shell.output)
                shell.send(b"\x1a")
                shell.prompt(offset)
                assert os.tcgetpgrp(shell.master) != parent["group"]
                assert b"Stopped" in shell.output[offset:]
                if mode == "group-kill":
                    # bash resolves its own job, rather than this controller
                    # signalling a possibly stale group number from metadata.
                    shell.send(b"kill -KILL %1\n")
                else:
                    shell.send(b"fg\n")
                    foreground(shell, parent["group"])
                    assert termios.tcgetattr(shell.master) == active_settings
                    fcntl.ioctl(shell.master, termios.TIOCSWINSZ, struct.pack("HHHH", 31, 99, 0, 0))
                    marker(shell, root, "resize")
                    shell.wait_for(lambda: json.loads((root / "resize").read_text()) == {"rows": 31, "cols": 99})
                    shell.send(b"exit\n")
            elif mode == "interrupt":
                shell.send(b"\x03")
            elif mode == "ignored-signals":
                assert target["ignored"] & 3 == 3, "exec lost ignored HUP/INT dispositions"
                shell.send(b"\x03")
                # Confirm ignored interrupt does not finish the target, while
                # still draining output. Actual input must remain usable.
                until = time.monotonic() + 0.15
                while time.monotonic() < until:
                    shell.pump()
                assert not (root / "finished").exists()
                shell.send(b"exit\n")
            elif mode == "terminal-close":
                shell.hangup()
            elif mode == "parent-kill":
                (root / "kill-parent").touch()
            else:
                raise AssertionError(f"unknown mode: {mode}")

            finished = marker(shell, root, "finished")
            if mode == "interrupt":
                # The guardian may observe channel EOF before target SIGINT;
                # a targeted kill on that path is still a fixture cleanup.
                assert finished["signal"] in (signal.SIGINT, signal.SIGKILL)
                assert finished["exit"] is None
            elif mode == "group-kill":
                assert finished["signal"] == signal.SIGKILL
            elif mode == "parent-kill":
                assert finished["parentEof"] is True
                assert finished["signal"] == signal.SIGKILL
            elif mode == "terminal-close":
                if finished["signal"] is None:
                    assert finished["exit"] == 0
                    closed = marker(shell, root, "input")
                    assert closed in ({"closed": "eof"}, {"closed": "eio"})
                else:
                    assert finished["signal"] in (signal.SIGHUP, signal.SIGKILL)
            else:
                assert finished["exit"] == 0 and finished["signal"] is None
                assert marker(shell, root, "input") == {"line": "exit\n"}

            if shell.master is not None:
                foreground(shell, shell.pid)
                shell.send(b"printf '__ASWP_RC=%s__\\n' \"$?\"\n")
                # After group-kill, $? belongs to the successful kill builtin;
                # the guardian's target SIGKILL is asserted independently above.
                expected = 130 if mode == "interrupt" else (137 if mode == "parent-kill" else 0)
                shell.wait_for(lambda: f"__ASWP_RC={expected}__".encode() in shell.output)
            print(f"{mode}: pass", flush=True)
        finally:
            shell.close()


def main():
    if sys.platform != "linux" or len(sys.argv) != 2:
        raise SystemExit("Usage on Linux: check_linux_terminal_guardian.py PATH_TO_FIXTURE")
    binary = Path(sys.argv[1]).resolve(strict=True)
    for mode in ["suspend-resize", "interrupt", "ignored-signals", "group-kill", "parent-kill", "terminal-close"]:
        run_case(binary, mode)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Linux terminal guardian::{message}", flush=True)
        raise
