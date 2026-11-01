# Linux final-exec observation experiment

Status: isolated provider-free spike; no production launch or journal transition
uses it. The [managed-launch evaluation](linux-managed-launch.md) separately
qualifies guardian identity, real leases, journal ordering and inner terminals.

A close-on-exec pipe is useful for reporting explicit exec errors, but EOF can
also follow a shim's death before exec. Likewise, exit 125 can come from either
a shim failure or an executed target. Neither observation alone establishes
that the final target image executed.

The new [exec_event example](../tools/linux-manager-evaluation/examples/exec_event.rs)
tests a narrower kernel observation. A fresh, single-threaded shim asks its
direct parent to trace it and stops. The parent selects `PTRACE_O_TRACEEXEC`
and `PTRACE_O_EXITKILL`, then continues it to a private GO gate. Only the exact
owned child's `PTRACE_EVENT_EXEC` is accepted as an exec event. The target is
still stopped at that observation; detach resumes it without tracing. These
semantics are documented in the [Linux ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html).

The local spike passes six cases:

| Case | Required result |
| --- | --- |
| Successful exec, target exits 125 | Exec event before any target marker; after detach, target reports no tracer and only standard streams, then exits 125 |
| Missing executable | ENOENT and exit 125; no exec event or target marker |
| Shim exits 125 before exec | Same numeric exit status, but no exec event or target marker |
| Shim receives SIGKILL before GO | SIGKILL status, no exec event or target marker |
| Shim raises ordinary SIGTRAP | A signal stop, never accepted as an exec event |
| GO withheld | Bounded wait expires; owned child is killed and reaped without executing the target |

The experiment accepts no target command or external PID. All trace operations
address the directly spawned, unreaped child; waits and signals stop after
reaping. An `ECHILD` error also revokes numeric-PID operations. The fresh parent
refuses inherited ignored SIGCHLD, which would undermine its child ownership.
Cleanup is explicit and checked in successful trials, with a bounded Drop
fallback. It does not inspect target memory or registers.

This is not yet an architecture choice. Native Ubuntu results and the Opus
design review are pending. Later evidence must cover tracer loss, permission
refusals, externally delivered signals, exec/detach/disconnect races, and
combination with the actual guardian and journal. Provider-specific sandbox,
dumpability, credential and tracing compatibility remains unmeasured. An exec
event establishes an image transition, not target initialization, successful
login, application readiness or retirement of all writers.

Run the fixed local experiment with:

```sh
cargo +1.98.0 run --locked --manifest-path tools/linux-manager-evaluation/Cargo.toml --example exec_event
```
