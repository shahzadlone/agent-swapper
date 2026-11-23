"""Interactive launch-pty control: the client gets a real controlling-free
pty for its outer terminal, a resize is applied mid-flight through the
master, input flows to the target through the full production channel, and
the target's output plus its view of the forwarded window size must reach
the control. Read-only evidence; no provider command is ever accepted.
"""
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def main():
    args = sys.argv[1:]
    require(
        len(args) >= 4 and args[0] == "--client",
        "expects --client CLIENT [ARGS...] --target TARGET [ARGS...]",
    )
    separator = args.index("--target")
    command = [args[1], *args[2:separator]]
    target = args[separator + 1:]
    require(bool(command) and bool(target), "both the client command and the target are required")
    client = command[0]
    # Some client interfaces carry the numeric user id (the disposable
    # client); others derive it from the process identity (the CLI's
    # managed launch). The control never uses it itself.
    user = next(
        (argument for argument in command[1:] if argument.isdigit()),
        None,
    )

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    def foreground_session():
        # The client becomes the session leader with the pty as its
        # controlling terminal and its own group as the foreground group, so
        # its terminal reads and mode changes cannot be stopped by SIGTTIN
        # or SIGTTOU.
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(
        [*command, *target],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        preexec_fn=foreground_session,
        close_fds=True,
    )
    os.close(slave)
    try:
        # Resize the outer pty mid-flight: the client's feeder must forward
        # the change to the inner master before the target reads its size.
        time.sleep(0.5)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 33, 111, 0, 0))
        time.sleep(1.0)
        os.write(master, b"ping\n")
        seen = b""
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and process.poll() is None:
            ready, _, _ = select.select([master], [], [], 1.0)
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
            if b"got:ping" in seen and b"111 33" in seen:
                break
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            state = []
            for probe in (
                f"/proc/{process.pid}/status",
                f"/proc/{process.pid}/wchan",
                f"/proc/{process.pid}/syscall",
                f"/proc/{process.pid}/task",
            ):
                try:
                    result = subprocess.run(["sudo", "-n", "cat", probe],
                                            capture_output=True, text=True, timeout=10)
                    state.append(f"{probe}: {result.stdout[-400:]!r}")
                except Exception as probe_error:
                    state.append(f"{probe}: {probe_error!r}")
            raise RuntimeError(
                "the launch client never exited; "
                + " | ".join(state)
                + f"; saw {seen[-400:]!r}"
            )
        # Drain whatever the client wrote last (its diagnostics land on the
        # pty and may arrive after the exit).
        drain_deadline = time.monotonic() + 2
        while time.monotonic() < drain_deadline:
            ready, _, _ = select.select([master], [], [], 0.3)
            if not ready:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
        require(
            code == 0,
            f"the launch client did not succeed: {code}; saw {seen[-800:]!r}",
        )
        require(
            b"got:ping" in seen,
            f"the target did not receive the input through the relay; saw {seen[-600:]!r}",
        )
        require(
            b"33 111" in seen,
            f"the window-size change was not forwarded to the target; saw {seen[-600:]!r}",
        )
        require(
            b"target exited" not in seen or b"Code" in seen or b"code" in seen,
            "unexpected launch outcome",
        )
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            state = []
            for probe in (
                f"/proc/{process.pid}/status",
                f"/proc/{process.pid}/wchan",
                f"/proc/{process.pid}/syscall",
                f"/proc/{process.pid}/task",
            ):
                try:
                    result = subprocess.run(["sudo", "-n", "cat", probe],
                                            capture_output=True, text=True, timeout=10)
                    state.append(f"{probe}: {result.stdout[-400:]!r}")
                except Exception as probe_error:
                    state.append(f"{probe}: {probe_error!r}")
            raise RuntimeError(
                "the launch client never exited; "
                + " | ".join(state)
                + f"; saw {seen[-400:]!r}"
            )
        # Drain whatever the client wrote last (its diagnostics land on the
        # pty and may arrive after the exit).
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.3)
            if not ready:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            seen += chunk
        require(code == 0, f"the launch client did not succeed: {code}; saw {seen[-800:]!r}")
        print("interactive launch pty: input, resize backhaul and output verified")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        os.close(master)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = repr(error)[:1500].replace("%", "%25")
        print(f"::error title=launch pty control::{message}", flush=True)
        sys.exit(1)
