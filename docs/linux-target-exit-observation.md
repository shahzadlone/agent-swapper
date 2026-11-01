# Authenticated target exit after exec confirmation

Status: the initial report implementation at `dadd15c` passed the complete
[run 41278117899](https://github.com/shahzadlone/agent-swapper/actions/runs/41278117899).
The raw real-time outcome extension at `36884d4` passed the complete
[run 41278633679](https://github.com/shahzadlone/agent-swapper/actions/runs/41278633679),
including both native manager jobs, all platform tests, packaging and rebuilds.
No production custody receipt or journal completion is introduced.

The guardian can distinguish an executed target's exit from a shim failure only
after the exact exec event and release described in the
[exec-gate experiment](linux-exec-gated-terminal.md). In that fixture mode, its
exclusive child waiter now sends one final report after observing `Exited` or
`Signaled`. The report binds the original invocation, child, nonce and last
stop sequence. Exit codes and terminating signals have separate tagged forms;
125 is a valid target exit code after confirmed exec. The signal form preserves
the kernel's core-dump bit. These are the distinct states defined by
[waitpid(2)](https://man7.org/linux/man-pages/man2/waitpid.2.html).

The client requires the packet's kernel sender credentials to match the bound
guardian and the complete launch binding to match its session. It accepts the
report only after exec confirmation and release, only once, and only when the
original retained target pidfd independently reports death. A queued report may
arrive after the guardian and service have gone, so it does not require a live
guardian at that point. Ordinary stop notices still require live identity
checks. Neither terminal EOF nor control-channel EOF creates an exit report.

Sending a report does not wait for acknowledgement or grant the client authority
to delay manager cleanup. Send failure leaves the client without a known exit;
the guardian still returns and the manager retires its remaining processes.
No numeric process operation follows reaping. Target exit, all-writer scope
retirement, lease release and durable journal completion remain separate facts.

The hosted real-Store test runs a target with a descendant that blocks SIGHUP.
It covers exits 0 and 125, Ctrl-C, real-time termination, and guardian SIGKILL. It deliberately waits
for independently observed original-scope retirement before reading control:
the first four cases must preserve their queued target status, while guardian
loss must yield EOF with no invented status. The original descendant pidfd must
report death, its heartbeat must stop without voluntary exit, and the real
journal must remain unresolved after reopening. A separate job-control case
checks the final report after a complete stop/resume sequence.

Parser tests reject substituted senders, stale launch/sequence data, missing or
extra fields, mixed code/signal forms, negative or overflowing codes and invalid
signals. These tests do not qualify provider behavior, production installation,
exit receipts after client restart or durable recovery. Independent review of
the exec-gate and report composition remains open.

The guardian now processes raw terminal status before named-signal decoding,
preserving real-time signal numbers and the core-dump bit. The exclusive owner
still revokes numeric PID authority first, as required by the
[wait-ownership fix](linux-wait-ownership.md). A fixed sender receives the
original target pidfd as stdin and sends SIGRTMIN through that capability only;
the target creates no extra process for the fault. The report must preserve the
actual signal number after guardian retirement and descendant cleanup. Local
raw-wait regression checks separately require both exact real-time status and
refusal of any later numeric operation. This extension passed both Ubuntu 22.04 and 24.04 in the run above.
