#!/usr/bin/env python3
"""Exercise the provider-free guardian topology under a real interactive bash/PTY."""

import errno
import argparse
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
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
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


def lease_available(root):
    with (root / "lease").open("rb") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(lease, fcntl.LOCK_UN)
        return True


def hold_live_session(shell, root):
    # Exceed the old 30-second total lifetime limit; continually check that
    # neither the guardian nor target has finished and the lease remains held.
    deadline = time.monotonic() + 31
    while time.monotonic() < deadline:
        shell.pump()
        assert not (root / "failure").exists(), "fixture failed during live session"
        assert not (root / "cleanup-ready").exists(), "cleanup began during live session"
        assert not (root / "finished").exists(), "fixture ended during live session"
        assert not lease_available(root), "lease lost during live session"
        time.sleep(0.05)


def run_case(binary, mode, delegated=None):
    with tempfile.TemporaryDirectory(prefix="aswp-terminal-guardian-") as directory:
        root = Path(directory)
        shell = Shell(root)
        try:
            shell_settings = termios.tcgetattr(shell.master)
            raw = mode in ("raw-exit", "raw-parent-kill")
            if raw:
                (root / "with-raw-terminal").touch()
            detached = mode in ("detached-writer", "detached-parent-kill", "detached-guardian-kill")
            if detached:
                assert delegated is not None, "detached fixture requires an explicit scope"
                (root / "with-writer").touch()
            if mode == "detached-guardian-kill":
                (root / "with-guardian-loss").touch()
            command = f"{shlex.quote(str(binary))} parent {shlex.quote(str(root))}"
            if delegated is not None:
                command += f" {shlex.quote(str(delegated))}"
            if mode == "ignored-signals":
                command = "trap '' INT HUP; " + command + "; rc=$?; trap - INT HUP; (exit $rc)"
            if mode == "redirected-stderr":
                command += f" 2>{shlex.quote(str(root / 'stderr.txt'))}"
            shell.send((command + "\n").encode())
            target = marker(shell, root, "target")
            if raw:
                assert marker(shell, root, "raw-entered") == {"raw": True}
                flags = termios.tcgetattr(shell.master)[3]
                assert not flags & (termios.ICANON | termios.ECHO | termios.ISIG)
            parent = marker(shell, root, "parent")
            guardian = marker(shell, root, "guardian")
            assert not lease_available(root), "guardian failed to retain transferred lease"
            assert target["group"] == parent["group"] == parent["pid"]
            assert guardian["group"] == guardian["pid"] != parent["group"]
            assert target["terminals"] == [True, True, mode != "redirected-stderr"]
            assert os.tcgetpgrp(shell.master) == target["group"]
            scope_path = None
            if delegated is not None:
                scope = marker(shell, root, "scope")
                assert Path(os.fsdecode(bytes(scope["parentBytes"]))) == delegated
                scope_path = Path(os.fsdecode(bytes(scope["pathBytes"])))
                assert scope_path.parent == delegated and scope_path.name.startswith("aswp-probe-")
                assert marker(shell, root, "admitted")["pid"] == target["pid"]
                members = (scope_path / "cgroup.procs").read_text().splitlines()
                assert str(target["pid"]) in members
                assert str(parent["pid"]) not in members and str(guardian["pid"]) not in members
                if detached:
                    writer = marker(shell, root, "writer-heartbeat")
                    assert writer["group"] != parent["group"]
                    assert str(writer["pid"]) in (scope_path / "cgroup.procs").read_text().splitlines()
                    shell.wait_for(lambda: json.loads((root / "writer-heartbeat").read_text())["tick"] > writer["tick"] + 3)
            active_settings = termios.tcgetattr(shell.master)
            prompt_offset = len(shell.output)

            if mode in ("suspend-resize", "group-kill", "long-session"):
                if mode == "long-session":
                    hold_live_session(shell, root)
                offset = len(shell.output)
                shell.send(b"\x1a")
                shell.prompt(offset)
                assert os.tcgetpgrp(shell.master) != parent["group"]
                assert b"Stopped" in shell.output[offset:]
                if mode == "long-session":
                    hold_live_session(shell, root)
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
            elif mode in ("parent-kill", "detached-parent-kill", "raw-parent-kill"):
                (root / "kill-parent").touch()
            elif mode == "detached-guardian-kill":
                (root / "kill-guardian").touch()
                assert marker(shell, root, "parent-empty") == {"guardianSignal": 9}
                assert not lease_available(root), "surviving parent lost its lease"
                assert "populated 0" in (scope_path / "cgroup.events").read_text().splitlines()
                assert not (root / "writer-exited").exists()
                (root / "retire-scope").touch()
            elif mode in ("redirected-stderr", "detached-writer", "raw-exit"):
                shell.send(b"exit\n")
            else:
                raise AssertionError(f"unknown mode: {mode}")

            assert marker(shell, root, "cleanup-ready") == {"leaseHeld": True}
            assert not lease_available(root), "lease released before cleanup observation"
            if scope_path is not None:
                assert marker(shell, root, "scope-finished") == {"retired": True}
                assert not scope_path.exists(), "terminal scope was not retired"
                if detached and mode != "detached-guardian-kill":
                    assert marker(shell, root, "writer-stopped") == {"signal": 9}
                    assert not (root / "writer-exited").exists()
            (root / "release-lease").touch()
            finished = marker(shell, root, "finished")
            shell.wait_for(lambda: lease_available(root))
            if mode == "detached-guardian-kill":
                assert finished == {"guardianSignal": 9}
            elif mode == "interrupt":
                # The guardian may observe channel EOF before target SIGINT;
                # a targeted kill on that path is still a fixture cleanup.
                assert finished["signal"] in (signal.SIGINT, signal.SIGKILL)
                assert finished["exit"] is None
            elif mode == "group-kill":
                assert finished["signal"] == signal.SIGKILL
            elif mode in ("parent-kill", "detached-parent-kill", "raw-parent-kill"):
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
            if mode == "redirected-stderr":
                diagnostic = b"target diagnostic stays on stderr\n"
                assert (root / "stderr.txt").read_bytes() == diagnostic
                assert diagnostic.rstrip() not in shell.output

            if shell.master is not None:
                foreground(shell, shell.pid)
                if raw:
                    shell.prompt(prompt_offset)
                    restored = termios.tcgetattr(shell.master) == shell_settings
                    if mode == "raw-exit":
                        assert marker(shell, root, "terminal-restored") == {"foreground": True}
                        assert restored, "terminal attributes were not restored on normal exit"
                    else:
                        print(f"raw-parent-kill: shell restored terminal={restored}; crash recovery remains unqualified", flush=True)
                shell.send(b"printf '__ASWP_RC=%s__\\n' \"$?\"\n")
                # After group-kill, $? belongs to the successful kill builtin;
                # the guardian's target SIGKILL is asserted independently above.
                expected = 130 if mode == "interrupt" else (137 if mode in ("parent-kill", "detached-parent-kill", "raw-parent-kill") else 0)
                shell.wait_for(lambda: f"__ASWP_RC={expected}__".encode() in shell.output)
            print(f"{mode}: pass", flush=True)
        finally:
            (root / "retire-scope").touch()
            (root / "release-lease").touch()
            shell.close()


def main():
    if sys.platform != "linux":
        raise SystemExit("This fixture requires Linux")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--cgroup-root", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    delegated = args.cgroup_root.absolute() if args.cgroup_root is not None else None
    modes = ["suspend-resize", "interrupt", "ignored-signals", "group-kill", "parent-kill", "terminal-close", "redirected-stderr", "raw-exit", "raw-parent-kill"]
    if delegated is not None:
        modes += ["detached-writer", "detached-parent-kill", "detached-guardian-kill"]
    else:
        modes.append("long-session")
    for mode in modes:
        run_case(binary, mode, delegated)
    if delegated is not None:
        print("::notice title=Linux terminal cgroup::twelve terminal cases: normal raw-mode restoration, crash restoration observation, and detached-writer cleanup with retained lease", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Linux terminal guardian::{message}", flush=True)
        raise
