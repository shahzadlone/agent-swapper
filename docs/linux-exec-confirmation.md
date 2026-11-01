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

The six base cases at `5904d50` passed on Ubuntu 22.04 and 24.04 in
[run 41267572192](https://github.com/shahzadlone/agent-swapper/actions/runs/41267572192).
Its remaining platform/packaging checks and Opus design review are pending.

Two additional local cases now kill an owned tracer with SIGKILL: after its
child reaches the GO gate, and after the kernel exec stop but before detach.
The tracer transfers its original child pidfd to the controller, which confirms
the child is live immediately before killing only its own unreaped tracer.
The child pidfd must then report exit and the target marker must remain absent.
No tracer destructor can run. At the exec stop there is no target-side input
loop that could mistake channel EOF for this shutdown. Failed observations
use the received pidfd only for cleanup and never count that fallback as a
passing fault result. Both cases passed on Ubuntu 22.04 and 24.04 at `fc666e0`
in [run 41267901868](https://github.com/shahzadlone/agent-swapper/actions/runs/41267901868).
The later thread-affinity and wait-ownership revision remains separately
qualified. The six-case base pipeline at `5904d50` subsequently passed all
platform tests, package builds and reproducible rebuilds.

This is not yet an architecture choice. Later evidence must cover permission
refusals, externally delivered signals, exec/detach/disconnect races, and
combination with the actual guardian and journal. Provider-specific sandbox,
dumpability, credential and tracing compatibility remains unmeasured. An exec
event establishes an image transition, not target initialization, successful
login, application readiness or retirement of all writers.

The Opus 5.5 xhigh design review supports a narrow spike and stresses one
tracing thread, exclusive child-wait ownership and no operation after reap.
The owner is now non-Send and its explicit cleanup and Drop fallback both use
the same typed nix wait path. An absent exec event after a general GO race
remains **unresolved**; it must never become proof that no exec occurred. The
fixed fault cases above deliberately put their kills before GO or at a known
exec stop, where their narrower assertions can be tested.

The review also proposes comparing a read-only executable-identity check after
status-pipe EOF. A changed image can offer positive evidence without tracing,
but a fast exit, an inaccessible image or re-exec of the same image leaves it
unresolved, and the process is not held before target instructions. The
comparison below is implemented as a separate experiment. Further choices include
whether to journal exec observation before detach and whether a later guardian
uses TRACEME or SEIZE. The present example is not a generic launch API.

## Read-only comparison

The separate [exec_identity example](../tools/linux-manager-evaluation/examples/exec_identity.rs)
waits for the fixed shim's private descriptor to close, then opens the owned,
unreaped child's executable through procfs with `O_PATH`. It compares device
and inode with the gated shim's original image. Closure alone is never a
positive result. Unchanged identity and expected unavailable/inaccessible-image
errors remain unresolved; other errors fail the experiment.

One live target uses a private copy of the same fixed executable, giving it a
different inode; another re-execs the original file. The live targets wait at
a bounded fixture barrier until the observer finishes. Separate controls exit
before exec, receive SIGKILL before GO, or attempt a missing image. No arbitrary
provider program, external PID or account data is accepted.

Locally, the distinct live image was observed; same-image exec and all three
negative controls remained unresolved. All 25 fast-target trials also remained
unresolved. Fast results are reported as counts rather than asserting a timing-
dependent success rate. They characterize this observer's availability in the
controlled fixture, not its general soundness under adversarial scheduling.
Native Ubuntu comparison results remain pending. This pathname-based observer
is not the production retained-procfs binding and supplies no custody receipt,
journal transition, readiness guarantee or fallback policy.

Run the fixed local experiment with:

```sh
cargo +1.98.0 run --locked --manifest-path tools/linux-manager-evaluation/Cargo.toml --example exec_event
```
