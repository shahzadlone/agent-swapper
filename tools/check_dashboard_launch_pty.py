#!/usr/bin/env python3
"""Exercise reviewed dashboard launches with local, provider-free agent fixtures."""
import fcntl
import json
import os
from pathlib import Path
import pty
import signal
import struct
import subprocess
import sys
import tempfile
import termios

from check_dashboard_pty import drain
from check_native_terminal_pty import same_terminal_configuration


AGENT = r'''
import json, os, signal, sys, termios, tty
from pathlib import Path
root = Path(os.environ["HOME"])
sequence = root / "sequence"
number = int(sequence.read_text()) + 1 if sequence.exists() else 1
sequence.write_text(str(number))
agent = Path(sys.argv[0]).name
attrs = termios.tcgetattr(0)
home = (sys.argv[sys.argv.index("--home") + 1] if agent == "gents"
        else os.environ[{"claude": "CLAUDE_CONFIG_DIR", "codex": "CODEX_HOME", "kimi": "KIMI_CODE_HOME"}[agent]])
record = {"agent": agent, "args": sys.argv[1:], "home": home,
          "cwd": str(Path.cwd()), "canonical": bool(attrs[3] & termios.ICANON),
          "echo": bool(attrs[3] & termios.ECHO)}
(root / f"launch-{number}.json").write_text(json.dumps(record))
tty.setraw(0)
# Keep terminal-generated Ctrl-C while deliberately changing every other raw
# input setting. The launcher must restore its own baseline before returning.
attrs = termios.tcgetattr(0)
attrs[3] |= termios.ISIG
termios.tcsetattr(0, termios.TCSANOW, attrs)
print(f"__ASWP_AGENT_{number}_READY__", flush=True)
if agent == "codex":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    os.read(0, 1)
    sys.exit(91)
os.read(0, 1)
sys.exit(42 if agent == "claude" and not sys.argv[1:] else 0)
'''


def check(binary):
    with tempfile.TemporaryDirectory(prefix="aswp-dashboard-launch-") as directory:
        root = Path(directory)
        programs = root / "bin"
        programs.mkdir()
        for agent in ["claude", "codex", "kimi", "gents"]:
            path = programs / agent
            path.write_text(f"#!{sys.executable}\n" + AGENT)
            path.chmod(0o700)
        env = {"HOME": str(root), "PATH": str(programs) + ":/usr/bin:/bin",
               "TERM": "xterm-256color", "LANG": "C.UTF-8"}
        command = [str(binary), "--state-dir", str(root / "state")]

        def cli(*args):
            return subprocess.run(command + list(args), cwd=root, env=env,
                                  check=True, capture_output=True, timeout=10)

        cli("profile", "add", "claude", "--alias", "alpha-canary")
        cli("profile", "add", "codex", "--alias", "beta-canary")
        cli("profile", "add", "kimi", "--alias", "gamma-canary")
        cli("profile", "add", "gents", "--alias", "relay-canary",
            "--agent", "agent-canary", "--address", "127.0.0.1:9191")
        cli("config", "set", "ui.mask", "true")
        profiles = json.loads(cli("list", "--json").stdout)["data"]
        homes = {entry["profile"]["harness"]: root / "state" / "profiles" / entry["profile"]["id"]
                 for entry in profiles}
        runtime = homes["gents"] / "runtime.json"
        runtime.write_text(json.dumps({"home": str(homes["gents"].resolve()),
                                       "graphql": "http://127.0.0.1:9191/api/v0/graphql"}))
        runtime.chmod(0o600)
        master, slave = pty.openpty()
        process = None
        stop = root / "shell-stop"
        start = root / "shell-start"
        env["ASWP_FIXTURE_STOP"] = str(stop)
        env["ASWP_FIXTURE_START"] = str(start)

        def read_until(marker):
            output = bytearray()
            try:
                drain(master, process, output, marker)
            except AssertionError as error:
                raise AssertionError(f"{error}; output tail={bytes(output[-2500:])!r}") from error
            return bytes(output)

        def history():
            return json.loads(cli("runs", "--json").stdout)["data"]

        def accept(number, key=b"\r"):
            # Input events are processed in order. Do not search incremental
            # ANSI draws for full review sentences: unchanged spaces/cells may
            # be represented by cursor moves instead of repeated characters.
            os.write(master, key + b" \r")
            output = read_until(f"__ASWP_AGENT_{number}_READY__".encode())
            assert b"\x1b[?1049l" in output, "agent started before leaving alternate screen"
            record = json.loads((root / f"launch-{number}.json").read_text())
            assert record["canonical"] and record["echo"], "agent inherited dashboard raw mode"
            return record

        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 100, 0, 0))

            def controlling_terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)

            # Keep the session leader alive to inspect the post-exit terminal
            # on macOS, where closing that leader can revoke the slave.
            shell = ('trap ":" INT; printf "__ASWP_SHELL_READY__\\n"; '
                     'while [ ! -f "$ASWP_FIXTURE_START" ]; do sleep 0.05; done; '
                     '"$@"; status=$?; printf "\\n__ASWP_EXIT=%s__\\n" "$status"; '
                     'while [ ! -f "$ASWP_FIXTURE_STOP" ]; do sleep 0.05; done; exit "$status"')
            process = subprocess.Popen(["/bin/sh", "-c", shell, "fixture-shell"] + command,
                                       cwd=root, env=env, stdin=slave, stdout=slave, stderr=slave,
                                       preexec_fn=controlling_terminal)
            read_until(b"__ASWP_SHELL_READY__")
            before = termios.tcgetattr(slave)
            start.touch()
            initial = read_until(b"q quit")
            assert b"alpha-canary" not in initial

            # Bare Enter and an extra Enter cannot authorize an experimental
            # launch. Masking also prevents Space from granting acceptance.
            os.write(master, b"\r")
            private = read_until(b"Unmask with Ctrl-P")
            for canary in [b"alpha-canary", str(root).encode()]:
                assert canary not in private, "masked review leaked identifying metadata"
            os.write(master, b" \r")
            assert history() == []
            os.write(master, b"\x07")
            assert not (root / "sequence").exists()
            os.write(master, b"\r\x10 \r")
            output = read_until(b"__ASWP_AGENT_1_READY__")
            assert b"\x1b[?1049l" in output
            os.write(master, b"x")
            read_until(b"Agent returned with exit 42")
            first = json.loads((root / "launch-1.json").read_text())
            assert first["agent"] == "claude" and first["args"] == []
            assert first["canonical"] and first["echo"]
            assert Path(first["home"]).resolve() == homes["claude"].resolve()
            assert Path(first["cwd"]).resolve() == root.resolve()
            assert history()[0]["custody"] == "exited_uncontained"

            # Login is also reviewed, uses the same registered home, and comes
            # back to the dashboard rather than requiring a shell round trip.
            login = accept(2, b"l")
            assert login["agent"] == "claude" and login["args"] == ["auth", "login"]
            assert login["home"] == first["home"]
            os.write(master, b"x")
            read_until(b"Agent returned with exit 0")
            assert history()[0]["kind"] == "login"

            # A second native brand receives the terminal in canonical mode.
            # Ctrl-C targets the foreground agent and still allows the launcher
            # to re-enter its dashboard with the interrupted exit recorded.
            codex = accept(3, b"j\r")
            assert codex["agent"] == "codex" and codex["args"] == []
            assert Path(codex["home"]).resolve() == homes["codex"].resolve()
            os.write(master, b"\x03")
            read_until(b"Agent returned with exit 130")
            assert history()[0]["exitCode"] == 130

            kimi = accept(4, b"j\r")
            assert kimi["agent"] == "kimi" and kimi["args"] == []
            assert Path(kimi["home"]).resolve() == homes["kimi"].resolve()
            os.write(master, b"x")
            read_until(b"Agent returned with exit 0")

            gents = accept(5, b"j\r")
            assert gents["agent"] == "gents" and gents["args"][0] == "chat"
            assert Path(gents["home"]).resolve() == homes["gents"].resolve()
            os.write(master, b"x")
            read_until(b"Gents client returned with exit 0")
            source = history()[0]
            assert source["custody"] == "external_runtime_unknown"
            resumed = accept(6, b"c")
            assert resumed["args"] == gents["args"]
            os.write(master, b"x")
            read_until(b"Gents client returned with exit 0")
            latest = history()[0]
            assert latest["gentsSession"]["id"] == source["gentsSession"]["id"]
            assert latest["gentsSession"]["resumedFrom"] == source["id"]
            assert len(history()) == 6

            os.write(master, b"q")
            read_until(b"__ASWP_EXIT=0__")
            assert len(history()) == 6 and (root / "sequence").read_text() == "6"
            assert same_terminal_configuration(before, termios.tcgetattr(slave))
            cli("registry", "verify")
            stop.touch()
            assert process.wait(timeout=3) == 0
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
            os.close(master)
            os.close(slave)
    print("Dashboard reviewed native/login/gents launch, manual brand change, resume, Ctrl-C and terminal restoration: pass")


def main():
    if os.name != "posix" or len(sys.argv) != 2:
        raise SystemExit("Usage on POSIX: check_dashboard_launch_pty.py PATH_TO_ASWP")
    check(Path(sys.argv[1]).resolve(strict=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = str(error).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Dashboard launch PTY check::{message}", flush=True)
        raise
