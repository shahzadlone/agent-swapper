# Reaping precedes fallible wait-status decoding

Status: the local negative control reproduced the bug and the corrected
regression passes. Hosted validation is pending. This affects qualification
helpers; no production process-launch implementation uses their waiter.

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

This correction establishes cleanup ownership; full real-time signal reporting
is a separate follow-up. No numeric PID is used as a retained process identity.
The underlying distinction between waiting and inspecting its returned status
is described by [waitpid(2)](https://man7.org/linux/man-pages/man2/waitpid.2.html).
