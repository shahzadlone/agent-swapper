# Cooked admission: source review and corrections

Opus 5.5 reviewed supplied source at `c6f1863` on 2026-11-01 with xhigh
reasoning. It ran no tools or tests. The review covered the retained-kernel
extraction, Store terminal adapter and cooked startup suspension. It found three
job-control defects; it did not review the later manager transport or protected
image extraction.

| Finding | Correction | Regression evidence |
| --- | --- | --- |
| Stopping admission again after `bg` made the surviving owner try to restore another foreground job's terminal, aborting the session | Restore only when the original group owns the foreground; a background stop changes no terminal modes | Native file-journal and real-Store cases stop, background, stop again, compare complete snapshots and resume to exit 0 |
| Ctrl-Z between the final cancellation check and raw entry was mistaken for an unsupported active external stop | The final permit enters raw mode and drains pending signals before granting execution; a cooked stop restores, suspends and retries under the original deadline | Native final-entry cases cover foreground/background continuation and both exec-held and direct Job admission |
| Unblocking before raising SIGTSTP could stop twice when a second copy arrived after the last drain | Queue the local stop while blocked, then unmask; process/thread copies share the same stop/continue cycle | A fresh-process regression using the exact private primitive failed the old order with a second stopped state and passes the new order after one continuation |

The shared runtime now owns the foreground admission wait and final raw entry.
It preserves the first cancellation signal, restores before cancellation or
suspension, and never extends the original deadline. A distinct stop queued
after continuation is processed rather than discarded. Exec-held admission
stays cooked at GO; only the later release permit enters raw mode. Direct Job
admission enters raw mode in its GO permit. Signals queued during synchronous
journal writes are handled by the mandatory final permit after the write and
manager recheck; a write failure still reaches cleanup and final signal draining.

Disabling ISIG closes the terminal-generated Ctrl-Z window. Signal delivery and
foreground changes after the final check are not atomic with sending a grant.
The existing explicit refusal of an external SIGTSTP during active execution
remains. Failure never converts a free lease, marker or diagnostic observation
into a Store completion receipt.

The native matrix now expects 68 file-journal cases and 30 real-Store cases,
plus a long-session case and four stopped/background expiry cases. New background
re-stop cases retain the original owner pidfd, check it before reading process
state, and require no target execution or retirement while admission is stopped.
Native results for this correction are pending.

Local validation passes 26 runtime tests and three compile-fail doctests,
54 isolated evaluation tests, strict runtime/evaluation Clippy, 14 activation
harness tests, the dependency-boundary check, nine outer-terminal cases and
13 surviving-owner cases. One ignored runtime receiver role is invoked by its
passing cross-process test. Real-manager cases run only in disposable hosted CI;
no installation or provider login was performed on the user's machine.

Strict core Clippy with the Store qualification feature also passes. Its local
Store suite passes 67 tests; 33 privileged roles remain deliberately gated for
the hosted runner. The three cleanup-signal cases, queued-stop regression and
all eleven advisory/termination exec cases pass using the corrected shared code.
