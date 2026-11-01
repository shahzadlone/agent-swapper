# Managed two-terminal relay qualification

Status: implementation and local source checks; hosted execution pending.
This fixed-target experiment connects the already qualified guardian-session
inner PTY to a newly created outer PTY. The Python harness owns both the outer
terminal and its shell. It never attaches to the terminal running the harness.

The first hosted run (`bf8db03`, run `41273807410`) exposed two harness errors:
the relay's foreground/resume-request marker was incorrectly treated as an
acknowledgement of kernel continuation, and a Python signal enum's string
format differed between runner versions. The harness now waits for the original
child to leave its stopped state and then verifies working input. It compares
the numeric signal value explicitly. Neither correction weakens the protocol
or permits a resume-request marker to stand in for observed target execution.

The relay passes bytes unchanged in both directions, with separate 16 KiB
queues. Initial dimensions and resize events reach the inner PTY. Typed signal
and flow-control bytes remain subject to the inner terminal's current mode.
The outer terminal stays raw during interaction, including when the target
temporarily disables echo or enters raw mode itself.

An authenticated direct-child stop makes the relay restore its saved outer
mode and suspend. A shell `bg` leaves the inner child stopped and performs no
outer-terminal I/O. After `fg`, the relay updates size, re-enters raw mode, and
sends the existing nonce/sequence-bound resume grant to the guardian. An
orphaned outer group whose SIGTSTP is discarded resumes useful interaction.
Nested foreground jobs handled by the target do not suspend the relay.

Control EOF starts a bounded output drain. Inner PTY EIO and control EOF are
transport observations, never target exit receipts or containment receipts.
Cancellation discards pending output deliberately, restores the outer terminal,
closes the control channel, and independently observes the original scope's
retirement before preserving the cancellation signal's exit status. Full
output queues cannot prevent control and signal processing.

Nine hosted scenarios cover byte preservation, hidden input, resizing, final
output, orphaned suspension, target-managed nested jobs, actual output
backpressure with SIGTERM, and shell stop/background/foreground transitions
from canonical Ctrl-Z and a raw-mode self-stop. Added faults close the outer
master, kill the client, or kill the guardian while final output is blocked.
Those faults retain original process/cgroup handles and observe the death of
a descendant that blocks SIGHUP. They check scope removal, released leases
and a stopped heartbeat independently of the relay's cleanup markers.
The existing independent outer
probe keeps its nine restoration, input, signal and shell tests.

This component creates a private locked fixture file and syncs a small fixture
intent before GO. The separate real Store suite exercises SQLite journal
failure, retained leases and unresolved run policy using the same client API.
The combined relay does not claim to integrate a production Store or complete
its journal. The guardian accepts only its protected fixed executable.

After outer master loss, restoration is explicitly unavailable; the relay still
attempts independent scope retirement and preserves delivered SIGHUP. SIGKILL
cannot run client cleanup and leaves the test terminal raw. This is a measured
restoration limit, not a terminal-restoration pass. A bounded drain timeout
restores modes and retires the scope, then reports failure without a blocking
stderr write into the same full terminal. Hosted results remain pending.

Open gates include external suspension requests while the inner target runs,
restoration by a surviving owner after uncatchable client death,
long sessions, already multithreaded CLI composition, arbitrary provider
execution, final-exec/exit receipts, and production manager installation.
The shared signal/terminal component requires a fresh process; it blocks
signals before creating the client runtime so new threads inherit that mask.
No existing CLI thread's signal policy is changed.
