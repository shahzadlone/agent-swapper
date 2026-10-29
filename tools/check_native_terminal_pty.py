#!/usr/bin/env python3
"""Check native-launch terminal restoration with an isolated fixture agent."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import termios
import time


def check(binary, mode):
    with tempfile.TemporaryDirectory(prefix="aswp-native-terminal-") as directory:
        root = Path(directory)
        env = {"HOME": str(root), "PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "C.UTF-8"}
        command = [str(binary), "--state-dir", str(root / "state")]
        subprocess.run(command + ["profile", "add", "claude", "--alias", "fixture"],
                       cwd=root, env=env, check=True, capture_output=True, timeout=10)
        agent = root / "fake-agent"
        if mode == "foreground-change":
            helper = root / "move-foreground.py"
            helper.write_text("import os, signal\nos.setpgid(0, 0)\nsignal.signal(signal.SIGTTOU, signal.SIG_IGN)\nos.tcsetpgrp(0, os.getpgrp())\n")
            suffix = f"{shlex.quote(sys.executable)} {shlex.quote(str(helper))} || exit 91\nexit 42\n"
        else:
            suffix = "exec sleep 10\n" if mode == "interrupt" else "exit 42\n"
        agent.write_text("#!/bin/sh\nstty raw -echo || exit 90\nprintf fixture-ready\n" + suffix)
        agent.chmod(0o700)
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        process = None
        output = bytearray()
        try:
            def controlling_terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            process = subprocess.Popen(command + ["run", "fixture", "--experimental-native", "--executable", str(agent)],
                                       cwd=root, env=env, stdin=slave, stdout=slave, stderr=slave,
                                       preexec_fn=None if mode == "detached" else controlling_terminal)
            deadline = time.monotonic() + 10
            sent_interrupt = False
            while process.poll() is None:
                assert time.monotonic() < deadline, "fixture did not exit"
                if select.select([master], [], [], 0.05)[0]:
                    output.extend(os.read(master, 65536))
                if mode == "interrupt" and b"fixture-ready" in output and not sent_interrupt:
                    # The supervisor is our owned, unreaped process-group leader.
                    os.killpg(process.pid, signal.SIGINT)
                    sent_interrupt = True
            while select.select([master], [], [], 0)[0]:
                output.extend(os.read(master, 65536))
            expected = 130 if mode == "interrupt" else (125 if mode == "foreground-change" else 42)
            assert process.returncode == expected, f"unexpected exit: {process.returncode}: {bytes(output)!r}"
            assert b"fixture-ready" in output
            if mode not in ("detached", "foreground-change"):
                assert termios.tcgetattr(slave) == before, "native agent left terminal attributes changed"
            if mode == "foreground-change":
                assert b"terminal settings could not be restored" in output
            result = subprocess.run(command + ["runs", "--json"], cwd=root, env=env,
                                    check=True, capture_output=True, timeout=10)
            run = json.loads(result.stdout)["data"][0]
            recorded_exit = 42 if mode == "foreground-change" else expected
            assert run["exitCode"] == recorded_exit and run["custody"] == "exited_uncontained"
        finally:
            if process is not None and process.poll() is None:
                if mode == "detached":
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            os.close(master)
            os.close(slave)
    print(f"Native terminal {mode}: pass")


def main():
    if os.name != "posix" or len(sys.argv) != 2:
        raise SystemExit("Usage on POSIX: check_native_terminal_pty.py PATH_TO_ASWP")
    binary = Path(sys.argv[1]).resolve(strict=True)
    for mode in ("exit", "interrupt", "detached", "foreground-change"):
        check(binary, mode)


if __name__ == "__main__":
    main()
