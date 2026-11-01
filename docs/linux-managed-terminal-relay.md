# Managed two-terminal relay qualification

Status: implementation and local source checks; hosted execution pending.
This fixed-target experiment connects the already qualified guardian-session
inner PTY to a newly created outer PTY. The Python harness owns both the outer
terminal and its shell. It never attaches to the terminal running the harness.

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

Six hosted scenarios cover byte preservation, hidden input, resizing, final
output, orphaned suspension, target-managed nested jobs, actual output
backpressure with SIGTERM, and shell stop/background/foreground transitions
from canonical Ctrl-Z and a raw-mode self-stop. The existing independent outer
probe keeps its nine restoration, input, signal and shell tests.

This component creates a private locked fixture file and syncs a small fixture
intent before GO. The separate real Store suite exercises SQLite journal
failure, retained leases and unresolved run policy using the same client API.
The combined relay does not claim to integrate a production Store or complete
its journal. The guardian accepts only its protected fixed executable.

Open gates include external suspension requests while the inner target runs,
outer master loss and uncatchable client death, output-drain failure policy,
long sessions, already multithreaded CLI composition, arbitrary provider
execution, final-exec/exit receipts, and production manager installation.
The shared signal/terminal component requires a fresh process; it blocks
signals before creating the client runtime so new threads inherit that mask.
No existing CLI thread's signal policy is changed.
