"""Interactive launch-pty control: the client gets a real controlling-free
pty for its outer terminal, a resize is applied mid-flight through the
master, input flows to the target through the full production channel, and
the target's output plus its view of the forwarded window size must reach
the control. Read-only evidence; no provider command is ever accepted.
"""
import fcntl
import os
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
        len(args) >= 5 and args[0] == "--client",
        "expects --client CLIENT USER JOURNAL -- TARGET [ARGS...]",
    )
    client = args[1]
    user = args[2]
    journal = args[3]
    require(args[4] == "--", "expected -- before the target")
    target = args[5:]

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    process = subprocess.Popen(
        [client, user, "launch", journal, *target],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
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
        require(b"got:ping" in seen, "the target did not receive the input through the relay")
        require(b"111 33" in seen, "the window-size change was not forwarded to the target")
        require(
            b"target exited" not in seen or b"Code" in seen or b"code" in seen,
            "unexpected launch outcome",
        )
        code = process.wait(timeout=20)
        require(code == 0, f"the launch client did not succeed: {code}")
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
