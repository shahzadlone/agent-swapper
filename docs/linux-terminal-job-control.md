# Linux inner-session job control

Status: provider-free topology experiment. It does not enable a production
launch backend, install a service, change the caller's terminal, or complete a
launch journal. The separately qualified `PTY1` activation fixture still gives
the target its own session; its parent guardian is outside that session. That
layout does not supply the non-orphaned foreground group needed for ordinary
terminal suspend/resume.

The [fixed example](../tools/linux-manager-evaluation/examples/terminal_job_control.rs)
instead gives the guardian an owned inner terminal and session. Its directly
spawned child has a separate process group in the same session. Only after the
controller's GO does the guardian make that group foreground and transfer the
slave to its fixed shim. The shim keeps its PID and group when executing the
fixed target. No arbitrary executable, external PID, provider account or outer
terminal descriptor is accepted.

The fresh single-threaded guardian blocks job-control signals, including those
that could stop it during a background `tcsetpgrp`. Its shim explicitly clears
the inherited signal mask after the foreground grant and before final exec.
Rust 1.98.0's Unix `CommandExt::exec` preserves the inherited mask; an implicit
reset must not be assumed. The fixed roles refuse inherited ignored or caught
job-control dispositions. The final target checks its mask, session, foreground
group and standard-stream-only descriptor set.

The local experiment passes these observations:

| Action | Required evidence |
| --- | --- |
| Ctrl+C and Ctrl+Z before GO | Both signals are pending in the blocked guardian; target marker absent |
| Ctrl+Z after target readiness | Exact owned child reports `SIGTSTP` stop, then continuation and working input |
| Read while target group is background | A real terminal read produces `SIGTTIN`; foreground resume completes the read |
| Write while background with `TOSTOP` | A real write produces `SIGTTOU`; foreground resume completes output |
| Ctrl+C after resume | Exact child exits from `SIGINT`; further group operations are refused |
| Guardian exits, controller retains master | Master reaches EIO and no controlling session remains |

One non-Send owner handles all exact-child waits, including stop, continue and
exit events. It never mixes those events with `std::Child`'s exit-status cache.
Group signalling is limited to the fixed direct child, which never changes its
group; its unreaped PID reserves that group ID. This restriction is not a policy
for arbitrary provider descendants or shells. Each stage has a deadline and
checked normal cleanup, with bounded fallback cleanup. Parent-death signals
limit orphaning of these fixed children; they are not descendant containment.

The pre-GO control-character test explicitly flushes its owned PTY after both
signals have been witnessed. That is a fixture cleanup step, not a production
typeahead rule. Both native Ubuntu jobs passed at `82ecbbf` in
[run 41270270251](https://github.com/shahzadlone/agent-swapper/actions/runs/41270270251).
Its complete platform/package pipeline subsequently passed.

Opus 5.5 xhigh reviewed the topology and supported a guardian-owned session,
while identifying hangup, signal normalization and child-wait ownership as
important integration concerns. Some recommendations assumed that std clears
signal masks during spawn; inspection of both Unix spawn paths in the pinned
Rust 1.98.0 source shows that they preserve the mask. The fixed shim also checks
the inherited blocked mask on both hosted kernels. The guardian never unblocks
its terminal signals, and group operations reject a reaped child. The review's
generic early-reap concern therefore does not establish a reused-PID operation
in this restricted owner. A stronger non-reaping lifecycle may still be useful
for a future arbitrary-target API. The requested focused follow-up hit the
Claude session quota and is not counted as a completed review.

## Manager-backed integration

The next `PTY2` mode uses the actual protected, fixed-user activation service,
real profile lease and durable Store callback. `PTY1` stays separately tested.
The guardian acquires its inner terminal before spawning a separate child
group, and checks that it did not already have a controlling terminal. The
shim verifies the controlling session, foreground group and inherited mask
before final exec at the journaled PID. Its final target verifies that job
signals are unblocked. No parent-death signal is installed in this hosted mode.

Stop notices carry the kernel sender credentials, guardian invocation, child
PID, launch nonce and a monotonic bounded sequence. A resume is accepted only
for the pending stop and must carry its nonce and sequence in the exact
versioned frame. Unknown fields, foreign identities, replayed sequences,
extra descriptors and truncated frames are refused. The same single-threaded
owner handles all child wait events and refuses group operations after reap
or after the fixed child changes group. No callback receives a raw PID to
signal independently.

The hosted test covers canonical Ctrl+Z and raw-mode self-suspension, working
input and Ctrl+C after resume, disconnect while stopped, guardian SIGKILL while
stopped, terminal hangup while running or stopped, and a real SQLite write
conflict that withholds GO. Hangup is observed through the retained slave's
POLLHUP, not attributed from an arbitrary SIGHUP. Its cases retain the control
connection until an independent witness observes retirement. Other retirement
cases keep an independent PTY master open. Original and reopened Stores must
still retain unresolved journal policy after the raw lease lock is released.
These checks do not claim that terminal hangup alone proves scope retirement.

Local validation passes 39 library tests, 27 binary tests, 12 coordinator guard
tests, the extracted shared job-control example and strict Clippy. New tests
cover stop identity/sequence validation and resume withdrawal, replay, rights
cleanup and timeout restoration. The initial PTY2 revision at `10bd84c` passed
both Ubuntu manager jobs in
[run 41270937633](https://github.com/shahzadlone/agent-swapper/actions/runs/41270937633).
Its full platform/package pipeline and an independent implementation review
remain separately tracked.

### Nested foreground job

The fixed target can additionally create one child in a separate foreground
group within the same inner session. When Ctrl+Z stops that child, its parent
target observes the stop, restores its own foreground group and handles the
resume locally. Its temporary SIGTTOU mask is restored on success and error;
neither the guardian nor the outer caller's terminal is modified by this handoff.

The hosted case requires the nested child's stopped state while the direct
target remains running. The guardian's stop-notice wait must expire for its
specific no-packet reason, and the other descendant must continue writing.
The target then foregrounds/resumes its nested child, waits for normal exit,
restores its own group and returns to the existing direct-target stop/resume
checks. This prevents a nested stop from being mistaken for an outer-session
suspend request. All roles and commands are fixed; this is not a generic shell.

Local compilation, strict Clippy and the existing 39 library/27 binary tests
pass. The nested foreground case requires its own hosted execution and remains
pending at this checkpoint.

### Descendant cleanup and stop scope

The follow-up target can spawn one fixed descendant in its foreground group.
That descendant verifies its inherited terminal and session, checks that it
has no parent-death signal, then blocks SIGHUP before declaring readiness. It
writes a bounded heartbeat and keeps its terminal descriptors open. The target
never signals or reaps it after readiness. This removes terminal hangup and
parent-death signalling as explanations for descendant death in the disconnect,
guardian-crash and hangup cases. The final Ctrl+C case can legitimately signal
both target and descendant and is not used to isolate manager cleanup.

The test observes the descendant's PID, parent, session, group, cgroup and
blocked SIGHUP, retains a pidfd before any fault, and requires pidfd exit and
heartbeat quiescence after observed scope retirement. The descendant must not
reach its voluntary deadline. These are fixed-fixture observations, not an
arbitrary-descendant binding API or new authority to complete a journal.

Canonical Ctrl+Z must stop both group members and freeze the descendant's
heartbeat; foreground resume must restart it. In contrast, raw-mode self-
suspension stops only the target, and the descendant must keep writing while
the target is stopped. Thus a stop notice is not evidence that all writers are
quiescent. The profile lease and unresolved journal policy continue to block
reuse throughout this state. Strict Clippy passes locally; the strengthened
hosted descendant checks remain pending.

Remaining integration work includes the actual manager-owned guardian,
authenticated stop/resume framing, durable launch ordering, arbitrary target
signal policy, stopped or regrouped descendants, terminal-mode restoration,
outer-shell foreground handoff, redirected streams and bounded relay
backpressure. An EIO observation alone does not establish retirement of every
writer or safe subscription reuse.

```sh
cargo +1.98.0 run --locked --manifest-path tools/linux-manager-evaluation/Cargo.toml --example terminal_job_control
```
