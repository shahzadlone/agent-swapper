# Managed two-terminal relay qualification

Status: all 19 managed cases passed on Ubuntu 22.04 and 24.04 at `150dd2c`
in [run 41275848735](https://github.com/shahzadlone/agent-swapper/actions/runs/41275848735).
The complete platform, candidate-package and reproducible-build pipeline passed.
The earlier nine direct cases passed their full pipeline at `f79f800` in
[run 41274299505](https://github.com/shahzadlone/agent-swapper/actions/runs/41274299505).
Independent source review and production integration remain separate gates.

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
The follow-up run (`8c6d683`, `41274062393`) passed through shell stop, background,
foreground and matching before/after `stty` snapshots, then exposed an invalid
extra assertion comparing bash's live readline mode to pre-shell attributes.
Shell cases now consistently compare complete command-time snapshots; direct
cases still compare every original termios field and control character.

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
stderr write into the same full terminal. These fault cases passed on both
Ubuntu images as part of the complete checkpoint above.

The surviving-owner variant uses the same managed relay as a fixed child of the surviving
[terminal owner](linux-terminal-owner.md). Parent and child share the outer
foreground group. The parent performs no relay I/O and holds no copy of the
activation socket or inner master. It waits exclusively for its child and
restores outer modes after observing child exit. Its metadata record identifies
the original child; it does not replace the child's authenticated manager
binding or provide a retirement receipt.

All nine direct cases are repeated with this parent, including normal and raw
inner stops through shell `bg`/`fg`. The SIGKILL case now kills the relay child
through its retained pidfd: the parent must restore every saved terminal
attribute, while independent original cgroup/process handles must prove scope
removal and descendant death. The killed child cannot publish restoration or
retirement markers. Outer-terminal loss remains explicitly unrestorable.
The fixed CI activation burst cap increases from 40 to 56 to cover the nine
additional sequential activations; concurrency remains bounded at four.

A nineteenth hosted case kills the owner while its relay, inner target and
descendant are stopped. A same-session subreaper shell prevents an implicit
orphan-group continuation. Parent-death SIGKILL must close the stopped relay's
control descriptor, after which independent original process/cgroup handles
must show full scope retirement. No client or owner exit-cleanup marker may
exist. The shell keeps the modes restored before the loss. This case and the
subreaper's negative control are described in the terminal-owner report.

Open gates include external suspension requests while the inner target runs,
active parent and whole-group loss,
long sessions, already multithreaded CLI composition, arbitrary provider
execution, final-exec/exit receipts, and production manager installation.
The shared signal/terminal component requires a fresh process; it blocks
signals before creating the client runtime so new threads inherit that mask.
No existing CLI thread's signal policy is changed.

The next composition adds ten surviving-owner cases using `PTY3`: exec is held
until a separate synced fixture spawn observation succeeds, then the normal
relay receives authenticated target-exit reports. The harness requires the
exec-hold and durable-observation markers to name the same bound target, and
the running target must report no tracer. Final-output success also requires
the authenticated exit-zero observation. Bytes, hidden/raw input, resize,
nested jobs, orphaned stops, shell `bg`/`fg`, backpressure cancellation, outer
loss, relay SIGKILL, blocked drain and stopped-parent loss are exercised with
the composed protocol. All 29 cases passed on Ubuntu 22.04 and 24.04 at `bde5303`; the complete
[run 41278328369](https://github.com/shahzadlone/agent-swapper/actions/runs/41278328369)
also passed platform tests, candidate packaging and independent rebuilds. The real Store exec/exit suites remain separate
from this relay's synced fixture records. Neither record completes a journal.

A further lifetime regression separates the absolute startup budget from active
observation budgets. The client previously reused its 12-second admission
deadline for later stop/resume rechecks. Active sessions now get an eight-second
manager-observation window per recheck while preserving the original binding.
The admission deadline still covers prepared GO and the entire held-exec journal
and release phase; no startup failure receives an active-session extension.

The hosted long case stays active for 15 seconds, stops through the shell,
remains in the background with the inner target stopped until at least 38
seconds, then resumes and checks working input, authenticated final exit,
complete terminal restoration and original-scope retirement. It deliberately
crosses the former 25/30/35-second relay/target/guardian fixture lifetimes.
Those component fixture limits are now 55 seconds, below the unchanged
60-second root-manager lifetime; cleanup and external harness bounds remain.
This fixed-duration regression passed both Ubuntu versions at `edb07b2`; the
complete [run 41278778150](https://github.com/shahzadlone/agent-swapper/actions/runs/41278778150)
also passed all platform, packaging and rebuild jobs. It does not claim an
unbounded production session or qualify arbitrary provider runtimes.

The exec-gated relay now returns an authenticated target code to its caller,
using the existing native CLI convention `128 + signal` for target termination.
The surviving owner preserves its child's complete eight-bit exit code instead
of collapsing nonzero codes to 125. Explicit outer cancellation retains its
original signal behavior. These results are returned only after terminal cleanup
and independent scope retirement. Missing target status yields failure 125 and
an unresolved-outcome marker, even if the terminal drained and scope retired.
The legacy fixed relay keeps its earlier component-only exit convention.

Three new hosted cases require exact exit 7, real-time signal status through the
retained target pidfd, and failure after guardian loss without a target report.
The exec-gated Ctrl-C cases now require 130, including the actual shell status
after stop/background/foreground transitions. The total becomes 32 ordinary
cases plus the separate long-session case. All passed on Ubuntu 22.04 and 24.04
at `5be7b7f`, and the complete
[run 41279456494](https://github.com/shahzadlone/agent-swapper/actions/runs/41279456494)
passed all platform, packaging and rebuild jobs. All nine local surviving-owner
cases also pass with code preservation.
