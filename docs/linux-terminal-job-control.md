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
typeahead rule. Native Ubuntu 22.04/24.04 results and the focused Opus design
review remain pending.

Remaining integration work includes the actual manager-owned guardian,
authenticated stop/resume framing, durable launch ordering, arbitrary target
signal policy, stopped or regrouped descendants, terminal-mode restoration,
outer-shell foreground handoff, redirected streams and bounded relay
backpressure. An EIO observation alone does not establish retirement of every
writer or safe subscription reuse.

```sh
cargo +1.98.0 run --locked --manifest-path tools/linux-manager-evaluation/Cargo.toml --example terminal_job_control
```
