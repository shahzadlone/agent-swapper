# Reaping precedes fallible wait-status decoding

Status: the local negative control reproduced the bug. The correction at
`75f3f61` passed both Ubuntu manager jobs in
[run 41277981298](https://github.com/shahzadlone/agent-swapper/actions/runs/41277981298),
including the regression, standalone exec-event cases and managed terminal
suite. The complete exec-gate composition at `58b5696` subsequently passed all platform,
package and rebuild checks in
[run 41277990876](https://github.com/shahzadlone/agent-swapper/actions/runs/41277990876).
This affects
qualification helpers; no production process-launch implementation uses their
waiter.

The pinned nix 0.31.3 `waitpid` wrapper first performs the wait syscall, then
converts the raw result into `WaitStatus`. Its `Signal` enum cannot represent
Linux real-time signals. A child terminated by SIGRTMIN is therefore reaped
successfully, but the conversion returns EINVAL. Our two exclusive wait owners
previously treated this like a failed syscall and left their numeric-PID
authority enabled. A later cleanup could attempt a signal after reaping.

Both now use rustix's safe raw-status wait operation. They record terminal
status and revoke PID authority before asking nix to decode it. Actual syscall
errors remain distinguishable from decoding errors, and ECHILD still revokes
ownership. Unknown decoded results remain failures; they never become an
invented exit status. The cleanup path cannot signal or wait again after that
reaping observation.

A fixed Python child sends SIGRTMIN only to itself. The shared job owner test
requires the expected decoding error, revoked ownership, and refusal of later
resume/wait operations. The standalone exec-event experiment exercises the same
case in its separate tracing owner and refuses later kill/wait operations.
The regression failed against the old shared waiter with “decoder failure left
a reaped numeric PID owned,” then passed after the ordering correction. The
negative-control harness explicitly revokes ownership before a failing assertion
so its own unwind cannot signal an already-reaped PID.

This correction establishes cleanup ownership. The subsequent
[exit-report implementation](linux-target-exit-observation.md) preserves raw
real-time signal outcomes and passed the complete pipeline at `36884d4`. No numeric PID is used as a retained process identity.
The underlying distinction between waiting and inspecting its returned status
is described by [waitpid(2)](https://man7.org/linux/man-pages/man2/waitpid.2.html).

The shared job-control consumer now delegates its raw wait and cleanup to
`agentswapper-linux-runtime::child_waiter::ChildWaiter`. Ptrace and fixed-group
resume remain in the fixture wrapper. The raw real-time test moved to the runtime;
the higher-level decode-failure test still verifies that its wrapper refuses
later numeric operations. New raw-wait tests cover lost ownership and actual
cleanup of the original child. See the [runtime boundary](linux-runtime.md#exclusive-direct-child-waiting)
for pending native extraction evidence and the sole-waiter contract.
