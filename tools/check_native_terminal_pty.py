#!/usr/bin/env python3
"""Check native-launch terminal restoration with an isolated fixture agent."""
import fcntl
import errno
import json
import os
from pathlib import Path
import pty
import re
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
        process = None
        output = bytearray()
        stop = root / "shell-stop"
        start = root / "shell-start"
        env["ASWP_FIXTURE_STOP"] = str(stop)
        env["ASWP_FIXTURE_START"] = str(start)
        try:
            def controlling_terminal():
                try:
                    os.setsid()
                    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                except BaseException as error:
                    os.write(2, f"terminal setup: {type(error).__name__}: {error}\n".encode())
                    raise
            try:
                # Keep the session leader alive while observing terminal state.
                # Some systems revoke a PTY when its session leader exits, even
                # if the controller still holds the slave open.
                shell = 'trap ":" INT; printf "__ASWP_SHELL_READY__\\n"; while [ ! -f "$ASWP_FIXTURE_START" ]; do sleep 0.05; done; "$@"; status=$?; printf "\\n__ASWP_EXIT=%s__\\n" "$status"; while [ ! -f "$ASWP_FIXTURE_STOP" ]; do sleep 0.05; done; exit "$status"'
                args = ["/bin/sh", "-c", shell, "fixture-shell"] + command + ["run", "fixture", "--experimental-native", "--executable", str(agent)]
                process = subprocess.Popen(args,
                                           cwd=root, env=env, stdin=slave, stdout=slave, stderr=slave,
                                           preexec_fn=None if mode == "detached" else controlling_terminal)
            except subprocess.SubprocessError as error:
                detail = os.read(master, 4096) if select.select([master], [], [], 0.5)[0] else b""
                raise RuntimeError(f"could not start PTY fixture: {error}; {detail!r}") from error
            deadline = time.monotonic() + 10
            while b"__ASWP_SHELL_READY__" not in output:
                assert time.monotonic() < deadline and process.poll() is None, "fixture shell did not become ready"
                if select.select([master], [], [], 0.05)[0]:
                    data = os.read(master, 65536)
                    if data:
                        output.extend(data)
            # Acquisition of the controlling terminal can itself change driver
            # settings on some systems; measure the launcher's actual baseline.
            before = termios.tcgetattr(slave)
            start.touch()
            sent_interrupt = False
            marker = None
            while marker is None:
                assert time.monotonic() < deadline, "fixture did not exit"
                assert process.poll() is None, "fixture shell exited before reporting status"
                if select.select([master], [], [], 0.05)[0]:
                    try:
                        data = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        data = b""
                    if data:
                        output.extend(data)
                if mode == "interrupt" and b"fixture-ready" in output and not sent_interrupt:
                    # The supervisor is our owned, unreaped process-group leader.
                    os.killpg(process.pid, signal.SIGINT)
                    sent_interrupt = True
                marker = re.search(rb"__ASWP_EXIT=(\d+)__", output)
            expected = 130 if mode == "interrupt" else (125 if mode == "foreground-change" else 42)
            assert int(marker.group(1)) == expected, f"unexpected exit: {bytes(output)!r}"
            assert b"fixture-ready" in output
            if mode not in ("detached", "foreground-change"):
                after = termios.tcgetattr(slave)
                assert after == before, f"native agent left terminal attributes changed; before={before!r}; after={after!r}"
            if mode == "foreground-change":
                assert b"terminal settings could not be restored" in output
            result = subprocess.run(command + ["runs", "--json"], cwd=root, env=env,
                                    check=True, capture_output=True, timeout=10)
            run = json.loads(result.stdout)["data"][0]
            recorded_exit = 42 if mode == "foreground-change" else expected
            assert run["exitCode"] == recorded_exit and run["custody"] == "exited_uncontained"
            stop.touch()
            assert process.wait(timeout=3) == expected
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
        print(f"::notice title=Native terminal fixture::starting {mode}", flush=True)
        try:
            check(binary, mode)
        except Exception as error:
            detail = f"{mode}: {type(error).__name__}: {error}"[:2000]
            detail = detail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=Native terminal fixture::{detail}", flush=True)
            raise
        print(f"::notice title=Native terminal fixture::completed {mode}", flush=True)


if __name__ == "__main__":
    main()
