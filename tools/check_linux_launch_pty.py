"""Interactive launch-pty control: the client runs inside a real
session-owning outer shell topology, receives input and resizes through the
full production channel, and shows the suspension protocol end to end.

The control plays the terminal owner: an anchoring session-leader process
(setsid + controlling tty) spawns the launch client in its own process
group, hands it the foreground, and performs the shell's own fg resumption
when the client legitimately suspends itself on the target's job-control
stop. Read-only evidence; no provider command is ever accepted.

Scenarios (--scenario NAME, default basic):
  basic        mid-flight resize, input relay, forwarded window size
  hidden-input a target-side echo-off read: the token must never echo
  raw-bytes     sixty-four deliberate bytes byte-for-byte through the relay
  nested-jobs   an interactive bash suspends its own foreground job; the
                client itself must never stop
  job-control   the direct target stops on ^Z, the client suspends, and the
                anchor's fg resumption drives the full notice/grant/CONT path
  long-active   a target that stays active well past every admission window
  long-stopped  a target held stopped for seventy seconds before resumption
"""
import fcntl
import hashlib
import json
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time

# The deliberately hostile byte stream for the raw-bytes scenario: control
# bytes, ISIG triggers, flow-control triggers, high bytes and an EOF marker
# are all just data once both line disciplines are honest.
RAW_BLOB = bytes(
    list(range(0, 40))
    + [0x1A, 0x03, 0x11, 0x13, 0x7F, 0xFF, 0x80, 0x9B, 0xC2, 0xA9]
    + list(b"rawbytes-probe")
)

# The anchoring session leader: a fresh fork, so setsid always succeeds. It
# owns the controlling terminal, spawns the client in its own process group
# (the production shape: the client is a session member, not a leader),
# reports the client's state transitions to the control, and performs the
# shell's own fg resumption only on the control's explicit command. The
# child's exec is held behind a pipe until the control acknowledges its
# terminal-mode baseline capture: neither the group/foreground races nor a
# fast client can touch the driver state before the baseline exists.
SESSION_ANCHOR = r"""
import json, os, signal, sys, time
command = json.loads(sys.argv[1])
commands_fd = int(sys.argv[2])
events_fd = int(sys.argv[3])
events = os.fdopen(events_fd, "wb", buffering=0)
def tell(message):
    events.write((message + "\n").encode())
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
hold_read, hold_release = os.pipe()
pid = os.fork()
if pid == 0:
    os.setpgid(0, 0)
    os.close(commands_fd)
    os.close(events_fd)
    os.close(hold_release)
    os.read(hold_read, 1)
    os.close(hold_read)
    try:
        os.execv(command[0], command)
    except BaseException as error:
        os.write(2, ("anchor exec failed: " + repr(error) + "\n").encode())
        os._exit(71)
os.close(hold_read)
try:
    os.setpgid(pid, pid)
except OSError:
    # The child's own pre-exec setpgid won the race; the group already
    # exists because the child holds its exec behind the pipe.
    pass
os.tcsetpgrp(0, pid)
tell("PID " + str(pid))
# The control captures its terminal-mode baseline now, then orders the
# start: the client's first instruction runs strictly after the baseline.
order = os.read(commands_fd, 64).decode().strip()
if order != "start":
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass
    tell("BADORDER " + order)
    sys.exit(70)
os.write(hold_release, b"x")
os.close(hold_release)
while True:
    _, status = os.waitpid(pid, os.WUNTRACED)
    if not os.WIFSTOPPED(status):
        break
    tell("STOPPED")
    order = os.read(commands_fd, 64).decode().strip()
    if order == "resume":
        # The shell's fg: both processes agree the pgrp is the client's
        # own before the signal lets it continue.
        os.killpg(pid, 0)
        os.tcsetpgrp(0, pid)
        os.killpg(pid, signal.SIGCONT)
        tell("RESUMED")
    elif order == "kill":
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass
        tell("KILLED")
    else:
        tell("BADORDER " + order)
        sys.exit(70)
if os.WIFEXITED(status):
    code = os.WEXITSTATUS(status)
else:
    code = 128 + os.WTERMSIG(status)
tell("EXIT " + str(code))
# Stay a live session leader briefly so the master can still deliver the
# client's last bytes to the control.
time.sleep(1)
sys.exit(code if 0 <= code <= 255 else 1)
"""


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


class Session:
    """One anchored client run: the pty master, the narration and command
    pipes, and the accumulated master output."""

    def __init__(self, client_argv):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        command_read, command_write = os.pipe()
        event_read, event_write = os.pipe()

        def anchor_session():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                SESSION_ANCHOR,
                json.dumps(client_argv),
                str(command_read),
                str(event_write),
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            pass_fds=(command_read, event_write),
            preexec_fn=anchor_session,
            close_fds=True,
        )
        os.close(slave)
        os.close(command_read)
        os.close(event_write)
        self.events = event_read
        self.orders = command_write
        self.seen = b""
        self.event_buffer = b""
        self.client_pid = None
        self.baseline = None

    def capture_baseline(self):
        """The terminal-mode baseline, captured before the client's first
        instruction runs: the anchor holds the client's exec until the
        start order that follows this capture."""
        self.baseline = self.attrs()

    def start_client(self):
        """Release the held exec; every client state from here on is the
        client's own doing."""
        os.write(self.orders, b"start\n")

    def write(self, data):
        os.write(self.master, data)

    def attrs(self):
        """The pty's current driver state, seen from the master."""
        return termios.tcgetattr(self.master)

    def mode_flags(self):
        """The canonical-mode flags ISIG and ECHO: set for the cooked baseline,
        cleared while the relay holds the terminal in raw mode."""
        return self.attrs()[3] & (termios.ISIG | termios.ECHO)

    def resize(self, rows, columns):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))

    def read_pending(self, timeout):
        """Drain the master for up to the timeout; accumulate the output."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], min(0.2, deadline - time.monotonic()))
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 4096)
            except OSError:
                return
            if not chunk:
                return
            self.seen += chunk

    def wait_for(self, needle, timeout, what):
        deadline = time.monotonic() + timeout
        while needle not in self.seen:
            require(time.monotonic() < deadline, f"timed out waiting for {what}; saw {self.seen[-800:]!r}")
            self.read_pending(0.3)
        return True

    def pump_events(self, timeout=0.0):
        """Accumulate anchor narration lines into the event buffer."""
        ready, _, _ = select.select([self.events], [], [], timeout)
        if not ready:
            return
        try:
            chunk = os.read(self.events, 4096)
        except OSError:
            return
        if chunk:
            self.event_buffer += chunk

    def next_event(self, timeout, what):
        """Read one complete anchor narration line."""
        deadline = time.monotonic() + timeout
        while True:
            if b"\n" in self.event_buffer:
                line, _, self.event_buffer = self.event_buffer.partition(b"\n")
                return line.decode()
            require(time.monotonic() < deadline, f"timed out waiting for the anchor's {what}")
            self.pump_events(0.3)

    def expect_event(self, prefix, timeout, what):
        line = self.next_event(timeout, what)
        require(line == prefix or line.startswith(prefix + " "),
                f"unexpected anchor narration while waiting for {what}: {line}")
        return line

    def assert_no_stop(self, seconds, what):
        """The anchor must narrate no client stop inside the window."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.pump_events(0.1)
            while b"\n" in self.event_buffer:
                line, _, self.event_buffer = self.event_buffer.partition(b"\n")
                require(not line.startswith(b"STOPPED"),
                        f"the client stopped itself during {what}: {line.decode()}")
        return True

    def assert_stopped_state(self, what):
        with open(f"/proc/{self.client_pid}/status") as status:
            state = status.read().split("State:")[1].split("\n")[0].strip()
        require(state.startswith("T "), f"the client is not really stopped during {what}: {state}")
        return True

    def resume(self):
        os.write(self.orders, b"resume\n")

    def finish(self, expected_code, required):
        line = self.next_event(60, "exit narration")
        require(line.startswith("EXIT "), f"expected an exit narration, got: {line}")
        code = int(line.split()[1])
        self.read_pending(3)
        for needle in required:
            require(needle in self.seen, f"missing {needle!r}; saw {self.seen[-800:]!r}")
        anchor_code = self.process.wait(timeout=10)
        require(code == expected_code,
                f"the launch client exited with {code}, expected {expected_code}; saw {self.seen[-800:]!r}")
        require(anchor_code == code, f"the anchor exited with {anchor_code}, expected the client's {code}")
        return code

    def close(self):
        if self.process.poll() is None:
            # Kill the client's own group first: a still-running client is
            # the anchor's child, not ours, and must not leak as an orphan.
            if self.client_pid:
                for signum in (signal.SIGKILL, signal.SIGCONT):
                    try:
                        os.killpg(self.client_pid, signum)
                    except OSError:
                        pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for fd in (self.master, self.events, self.orders):
            try:
                os.close(fd)
            except OSError:
                pass


def parse_args(args):
    require(len(args) >= 4, "expects [--scenario NAME] --client CLIENT [ARGS...] --target TARGET [ARGS...]")
    scenario = "basic"
    if args[0] == "--scenario":
        scenario = args[1]
        args = args[2:]
    require(args[0] == "--client", "expects --client CLIENT [ARGS...] --target TARGET [ARGS...]")
    separator = args.index("--target")
    command = [args[1], *args[2:separator]]
    target = args[separator + 1:]
    require(bool(command) and bool(target), "both the client command and the target are required")
    return scenario, [*command, *target]


def scenario_basic(session):
    # Resize the outer pty mid-flight: the client's feeder must forward the
    # change to the inner master before the target reads its size.
    time.sleep(0.5)
    session.resize(33, 111)
    time.sleep(1.0)
    session.write(b"ping\n")
    session.wait_for(b"got:ping", 45, "the input relayed to the target")
    session.wait_for(b"33 111", 45, "the resized window forwarded to the target")
    session.finish(0, [b"got:ping", b"33 111"])
    print("interactive launch pty: input, resize backhaul and output verified")


def scenario_hidden_input(session):
    # The target announces the moment its echo is off; only its own answer
    # may ever speak the token back through the relay.
    session.wait_for(b"hidden-ready", 30, "the target's echo-off readiness")
    session.write(b"secret-token-9\n")
    session.wait_for(b"got:secret-token-9", 30, "the echo-off target's answer")
    session.read_pending(1)
    require(session.seen.count(b"secret-token-9") == 1,
            f"the token echoed through some line discipline: {session.seen[-600:]!r}")
    session.finish(0, [])
    print("interactive launch pty: hidden input stayed hidden through the relay")


def scenario_raw_bytes(session):
    session.wait_for(b"raw-ready", 45, "the target entering raw mode")
    require(len(RAW_BLOB) == 64, "the raw-bytes probe must be exactly 64 bytes")
    session.write(RAW_BLOB)
    digest = hashlib.sha256(RAW_BLOB).hexdigest().encode()
    session.wait_for(digest, 30, "the exact 64-byte digest")
    session.wait_for(b"raw-certified", 30, "the raw relay's completion marker")
    session.finish(0, [digest, b"raw-certified"])
    print("interactive launch pty: raw bytes traveled byte-for-byte")


def scenario_nested_jobs(session):
    time.sleep(2.0)
    session.write(b"sleep 30\n")
    time.sleep(0.7)
    # An interactive bash's own job control handles ^Z: the inner sleep
    # stops, bash keeps running, and the launch client must not suspend.
    session.write(b"\x1a")
    session.wait_for(b"Stopped", 20, "bash's own job stop announcement")
    session.assert_no_stop(3, "the nested job termination")
    session.write(b"echo rc:$?\n")
    session.wait_for(b"rc:148", 20, "bash's stopped-job status report")
    # A client that never stopped still owns the raw terminal.
    require(session.mode_flags() == 0,
            f"the relay lost its raw modes during the nested job control: {session.attrs()}")
    session.write(b"kill -9 %1\n")
    session.write(b"exit\n")
    session.write(b"exit\n")
    session.finish(0, [b"Stopped", b"rc:148"])
    print("interactive launch pty: nested job control stopped the inner job only")


def scenario_job_control(session, hold_seconds):
    name = "job-control" if hold_seconds < 10 else "long-stopped"
    # The baseline was captured while the anchor still held the client's
    # exec: the pure post-acquisition state the client finds and must
    # faithfully restore at every suspension and at the end.
    baseline = session.baseline
    require(baseline[3] & termios.ISIG and baseline[3] & termios.ECHO,
            f"the pty baseline is unexpectedly not canonical: {baseline}")
    session.wait_for(b"target-ready", 45, "the target starting")
    # The direct target stops on ^Z; the guardian must notice, the client
    # must restore its modes and suspend itself for real.
    session.write(b"\x1a")
    session.wait_for(b"launch: target stopped by signal", 30, "the client's stop notice line")
    session.expect_event("STOPPED", 30, "client suspension narration")
    session.assert_stopped_state(name)
    require(session.attrs() == baseline,
            f"a suspended client left foreign modes on the terminal: {session.attrs()}")
    time.sleep(hold_seconds)
    session.assert_stopped_state(f"{name} after the hold")
    require(session.attrs() == baseline,
            f"the stopped hold drifted the terminal modes: {session.attrs()}")
    # The anchor's fg: foreground back to the client group, then SIGCONT;
    # the reawakened client re-enters raw mode and the guardian resumes the
    # target only through its resume grant.
    session.resume()
    session.expect_event("RESUMED", 30, "the anchor's foreground resumption")
    session.wait_for(b"launch: foreground returned; resuming the target", 30,
                     "the client's resume acknowledgement")
    require(session.mode_flags() == 0,
            f"the resumed client did not re-enter raw mode: {session.attrs()}")
    time.sleep(1.0)
    session.write(b"\x03")
    session.wait_for(b"target exited", 30, "the authenticated target exit report")
    require(session.attrs() == baseline,
            f"the relay's terminal modes were not restored for the shell: {session.attrs()}")
    session.finish(0, [b"launch: target stopped by signal", b"target exited"])


def scenario_long_active(session):
    # Seventy-five seconds of live target: every admission deadline is long
    # gone and only the active phase's own patience may carry the relay.
    session.wait_for(b"long-active-done", 200, "the long-active target completion")
    session.finish(0, [b"long-active-done"])
    print("interactive launch pty: a 75-second active target completed through the relay")


SCENARIOS = {
    "basic": scenario_basic,
    "hidden-input": scenario_hidden_input,
    "raw-bytes": scenario_raw_bytes,
    "nested-jobs": scenario_nested_jobs,
    "job-control": lambda session: scenario_job_control(session, 5),
    "long-active": scenario_long_active,
    "long-stopped": lambda session: scenario_job_control(session, 70),
}


def main():
    scenario, client_argv = parse_args(sys.argv[1:])
    require(scenario in SCENARIOS, f"unknown scenario {scenario}")
    runner = SCENARIOS[scenario]
    # The launch client's pid is what the anchor suspends and resumes; read
    # it up front so the stopped-state evidence names the real process.
    session = Session(client_argv)
    line = session.next_event(60, "client pid narration")
    require(line.startswith("PID "), f"expected a client pid narration, got: {line}")
    session.client_pid = int(line.split()[1])
    # The anchor holds the client's exec until the start order: capture the
    # terminal-mode baseline first so every later driver state is the
    # client's own doing.
    session.capture_baseline()
    session.start_client()
    try:
        runner(session)
    finally:
        session.close()
    if scenario == "job-control":
        print("interactive launch pty: direct stop, client suspension and fg resumption verified")
    if scenario == "long-stopped":
        print("interactive launch pty: a 70-second hold verified across the stop and resume path")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = repr(error)[:1500].replace("%", "%25")
        print(f"::error title=launch pty control::{message}", flush=True)
        sys.exit(1)
