# Linux managed launch: next design checkpoint

Status: design candidate, not an installed or shipped backend. Normal Linux
launches remain uncontained. The read-only manager observer is qualified
separately in [the evaluation notes](../tools/linux-manager-evaluation/README.md).

The next problem is launch authority. The system manager can keep a service's
cgroup controls outside the target user's ownership, but AgentSwapper must get
the target into that service before it executes. Passing a writable delegated
cgroup to the target is insufficient, as the [escape measurements](linux-supervision.md)
already demonstrate. A broad polkit or sudo grant is not an acceptable shortcut.

## Candidate to prototype

Evaluate **fixed-user socket activation** before adding a custom root broker.
An administrator would install root-owned socket/template units and a reviewed
guardian executable. Each connection starts a separate service whose `User=`
and `Group=` are fixed at installation. Client messages cannot choose a root
identity, systemd properties or a root command. Only the unprivileged guardian
parses the launch request and starts the native CLI.

This proposal builds on documented systemd behavior: `Accept=yes` creates a
service instance for each connection and supplies its connected socket; socket
ownership/mode and connection limits are configurable. These are useful
primitives, not evidence that our complete protocol is secure.
[systemd.socket](https://www.freedesktop.org/software/systemd/man/255/systemd.socket.html)

The installation would be specific to an ordinary local UID, with its socket
under root-owned ancestry and accessible only to that UID. Root would own the
unit files and guardian executable. The root manager would retain the scope;
the service would use `Delegate=no`, `KillMode=control-group` and bounded stop
handling. It would not enable PAM session migration: systemd documents that
`PAMName=` can move the main process and its children to another session scope.
[systemd.exec](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#PAMName=)

| Launch mechanism | Benefit | Cost or unresolved issue |
| --- | --- | --- |
| Fixed-user socket/template units | No new root request parser; one manager-owned service per accepted connection | Administrator installation per UID; activation identity, terminal relay and lifecycle still need proof |
| Narrow root broker | Flexible one-shot transient services and explicit request policy | New privileged parser, authentication boundary, installation and sustained security maintenance |
| Per-launch administrator authorization | No permanently installed broker | Repeated prompts; authorization caching and transient-property authority need review |
| User-manager delegation | Easy setup | Measured migration escape; cannot qualify descendant custody |

The socket design is a hypothesis to test, not a general recommendation to
grant service-management permission. There is no proposed `manage-units`
polkit rule, unrestricted sudo command or automatic host installation.

## Required protocol and lifecycle evidence

1. Authenticate both ends of activation and bind the accepted connection to
   its exact manager invocation. A claimed PID, unit name, environment value
   or socket filename is insufficient. Recheck the root-owned template and
   fixed user, and test replay or substitution by another connection.
2. Validate a bounded request and inherited descriptors. Preserve the current
   profile lease, environment policy and durable intent before allowing target
   execution. Uncertain admission must remain unresolved after cleanup.
3. Keep a guardian in the service while the target runs. Test client loss,
   guardian loss, target exit, startup timeout and connection half-close.
   Only authenticated observation of the original retained scope can establish
   that local scope's retirement. It says nothing about external services.
4. Qualify interactive behavior. A service launched by PID 1 does not inherit
   the caller's controlling terminal relationship. Evaluate an inner PTY with
   a client relay; test resize, raw mode, password entry, Ctrl-C, suspend/resume,
   shell foreground restoration, disconnects and long-running sessions.
5. Test permission compatibility before selecting hardening directives. A
   filesystem sandbox, native CLI sandbox, browser login flow and process
   containment have different contracts. Do not claim one from another.
6. Measure profile isolation and provider behavior separately. The service's
   fixed UID does not isolate mutually hostile programs running as that same
   user, prevent all delegated work, or qualify vendor credential stores.

The first prototype should use only bounded fixture programs in temporary
root-owned units on disposable hosted CI. It must verify an ordinary user's
activation, a different user's refusal, independent connections/scopes,
detached-worker cleanup and complete fixture removal. No installed provider,
real account or local service is needed for that experiment.

That provider-free prototype is now implemented in
[`check_linux_socket_activation.py`](../tools/check_linux_socket_activation.py),
as a qualification-only program. It creates exclusive runtime unit files and a
protected root ownership marker on opted-in hosted runners. Cleanup requires
the matching marker and original unit contents before controlling any service.
Targets run as the fixed ordinary UID; two connections must receive different
invocations, a different UID must be denied, and fresh writer heartbeats must
precede disconnect. Both original scope descriptors must observe removal,
while the sibling continues. Unit lifetimes and privileged fixture commands
are bounded. These cooperative fixture observations do not yet authenticate
a production launch request, integrate the Rust observer with template
instances, or qualify a terminal relay.

The initial stream-socket prototype at `eec7afc` passed these checks on both
Ubuntu 22.04 and 24.04 in
[run 41166901044](https://github.com/shahzadlone/agent-swapper/actions/runs/41166901044).
The subsequent revision uses `ListenSequentialPacket=` so the existing Rust
sequenced-packet/descriptor transport can be reused rather than inventing
stream framing. At `574eaba`, the sequenced-packet activation, oversized-packet
refusal, separate-user refusal, independent scopes and cleanup passed on both
images in [run 41167663744](https://github.com/shahzadlone/agent-swapper/actions/runs/41167663744).
An added control sends an otherwise valid packet with an unexpected harmless
descriptor. At `e957bd0`, that refusal and the complete branch pipeline passed in
[run 41167963827](https://github.com/shahzadlone/agent-swapper/actions/runs/41167963827).
This experiment does not yet use the Rust guardian or carry real launch data.

The next isolated Rust probe enables `SO_PASSCRED` before connecting, checks the
root-manager listener, and receives a bounded offer with the actual message
sender's kernel credentials. It requires that sender to match the manager's
`MainPID`, ordinary user and invocation, with the expected protected template,
no drop-ins, and retained process/cgroup handles. It then disconnects and waits
for authenticated retirement of that original scope. It sends no GO, launch
envelope or descriptor and must create no worker. This passed on Ubuntu 22.04
at `6d8747d` in [run 41169249761](https://github.com/shahzadlone/agent-swapper/actions/runs/41169249761).
Ubuntu 24.04 stopped in the preceding retirement trial: an invocation was
collected between lookup and a property read. The observer now recognizes the
authenticated `NoUnitForInvocationID` property error as a reason to perform a
fresh lookup, never as retirement evidence by itself. This matches
[systemd's invocation-path resolver](https://github.com/systemd/systemd/blob/v255/src/core/manager.c#L3013).
Regression tests refuse an error from another sender or an unrelated error;
At `08a5fd1`, both images passed the corrected retirement, name-reuse and
activation-binding trials in
[run 41169464915](https://github.com/shahzadlone/agent-swapper/actions/runs/41169464915).
The complete pipeline passed, as did the later hosted-fixture opt-in gate at
`4ccd252` in [run 41170491804](https://github.com/shahzadlone/agent-swapper/actions/runs/41170491804).
Local tests cover truncated, empty, late and uncredentialed packets, and prove
that an unexpected transferred descriptor is closed on refusal. The distinction
between connection-time peer credentials and message credentials is described
in the [Linux UNIX socket manual](https://man7.org/linux/man-pages/man7/unix.7.html).
This measures fixture identity only; it does not validate an installed guardian
binary, authorize a journal transition or qualify production execution.

## Source review and follow-up

Opus 5.5 reviewed the `e957bd0` fixture and shared Rust transport on
2026-10-31. It supported fixed-user activation as the next candidate for
launches under the invoking user's own UID. That review predates the Rust
binding probe above and does not approve its implementation or production use.

The review requested proof that truncated ancillary data closes transferred
descriptors. Inspection of pinned rustix's buffer destructor and a new shared
transport regression test establish cleanup on both early-return paths: sixteen
transferred file locks overflow the control buffer, and a separate oversized
payload truncates data. Every independent lock can be reacquired after refusal.
No descriptor leak was found in that existing implementation; the missing
evidence was a regression test. This shared guardian protocol is not yet used
by normal production launches.

The fixture now requires an invocation-specific clean-EOF marker written by
the cooperative guardian before its exit. A negative control deliberately
causes a guardian protocol error: even though the writer stops and scope is
removed, it must be refused as clean-disconnect evidence. The service/writer
deadline is 60 seconds, guardian receive deadline 40 seconds, and the live
pre-disconnect check must occur within 25 seconds. Cleanup waits up to five
seconds for asynchronous scope removal. These review changes passed on both
Ubuntu versions at `c8979bf` in
[run 41169986563](https://github.com/shahzadlone/agent-swapper/actions/runs/41169986563).

The Python fixture continues to trust the CI checkout and its local helper
imports. Adding Python isolated mode while explicitly reintroducing that
same import path would not remove this trust. Production must instead use a
reviewed, root-owned Rust guardian executable and validated installation.

Separate controlled bus listeners now test an authentication handshake that
never replies and one that disconnects. They run only inside opted-in hosted
mount namespaces. The stalled listener must observe EOF after the observer's
deadline; both cases require exit 125 and no observation. Both passed on the
same two native jobs at `c8979bf`. A failed earlier attempt at `33fefe0` exposed
a fixture ordering error: its procfs overlay could hide namespace metadata
before the probe child validated it. An explicit ready byte now proves the
child checked its real namespace before the parent installs any overlay.
These are availability/refusal checks, not simulated manager-owner
replacement or successful manager authentication.

### Credential and disconnect follow-up

The separate Opus activation-binding review of `33fefe0` required a clean-EOF
marker on the BIND path too and verification of PID-zero decoding. The observer
owner/authentication review of `4ccd252` requested a second `MainPID` and
`ActiveState` read after kernel binding, inside the invocation bracket. Those
checks are implemented. They do not establish an atomic manager snapshot or
eliminate every numeric-PID reuse possibility.

Pinned rustix 1.1.6 represents credential PIDs with `NonZeroI32`, while Linux
can return zero for an unconnected peer or a packet queued before `SO_PASSCRED`
was enabled. Reading those bytes into that type is unsound; the earlier passing
late-enable test is withdrawn as evidence. The existing
[upstream issue](https://github.com/bytecodealliance/rustix/issues/1698) describes
the same representation problem. The isolated observer now uses integer-bearing
credential decoders, with source-review scope and dependency pins recorded in
[dependency decisions](dependencies.md#linux-activation-credential-decoding).
New tests exercise both actual kernel PID-zero paths and explicitly refuse a
zero message-sender PID after safe decoding.

Offer validation also binds the manager-authenticated unit name to the client's
PID and UID, using systemd's AF_UNIX instance format, verified in
[v249](https://github.com/systemd/systemd/blob/v249/src/core/socket.c#L822) and
[v255](https://github.com/systemd/systemd/blob/v255/src/core/socket.c#L797).
It checks sender GID and matching real/effective identities. Tests use different
client and guardian PIDs and mutate both kernel credentials and text claims.

Linux permits a zero-length sequenced packet while its peer remains open.
Both Rust guardian transport and Python fixture now require kernel-reported
read-side shutdown before accepting EOF; unexpected descriptors are discarded
and refused. BIND and GO negative controls send an actual empty record and an
unexpected command while retaining the peer. Neither may write a clean-EOF
marker, even if systemd subsequently removes the failed scope.

Local validation passed 16 observer tests, six shared transport tests, 18 Python
fixture tests, strict Clippy and the locked dependency audit. The guardian lease
fixture passed parent descriptor closure and parent-group SIGKILL. Both native
manager jobs passed these changes at `8c46be6` in
[run 41260763189](https://github.com/shahzadlone/agent-swapper/actions/runs/41260763189).
The full pipeline is still being followed. The replacement-decoder review
completed with no must-fix receive-path finding. Its hardening follow-up limits
the control buffer to one credentials message, so extra control types cannot
be silently discarded and accepted.

That review also found that read-side shutdown alone still accepts an empty
record queued before trailing data. The shared Rust EOF helper and Python
fixture now temporarily enable `SO_PASSCRED` with zero control capacity: every
record, including a late-credential empty record, produces `MSG_CTRUNC`, whereas
EOF carries no credentials. No credential bytes are decoded. The original
socket option is restored before returning; shutdown must also have no poll
error. Seven shared transport tests now cover queued-empty and trailing-data
cases, descriptor release, and restoration before later control messages.
Native fault controls include shutdown after an empty record and after trailing
data. The focused Opus follow-up found the stricter EOF discrimination correct
for the single-reader Linux protocol. A double-error diagnostic now preserves
both the read and socket-option restoration failures. The implementation relies
on the kernel attaching credentials to every queued record but not to EOF;
this was checked against the Linux 6.8
[UNIX receive path](https://github.com/torvalds/linux/blob/v6.8/net/unix/af_unix.c)
and [ancillary delivery](https://github.com/torvalds/linux/blob/v6.8/include/net/scm.h).

Parallel execution of the new Rust fixture's tests exposed a test timing
assumption: the lock-release regression passed 30/30 alone but failed 7/30
with process-spawning tests. An in-flight fork can briefly share CLOEXEC open
file descriptions until exec. Descriptor-release tests now use a bounded
one-second wait for those independent holders too; a retained receiver
descriptor still fails. Source inspection, rather than instantaneous lock
reacquisition, establishes the receiver's destructor timing.

The focused Opus kernel review completed with two low-severity and two
informational findings, with no high/medium finding in its stated scope. The
observer now restricts the authenticated service to `Type=exec`, no PID file,
`NotifyAccess=none` and `RemainAfterExit=no`, rechecks migration controls on each
live observation, and enforces the namespace precondition inside binding itself.
These follow-up checks await their own native run. Directory device/inode facts
identify only the retained directory: a failed invocation's directory may be
reused by a later start. They never replace the manager invocation ID or prove
freshness. Kernel retirement alone likewise never proves manager retirement.
The reviewed model trusts the kernel/root and excludes hostile same-UID code;
it is not production or arbitrary-service qualification.

Root-owned launch installation on a user's machine comes later, after the
exact files, removal procedure, platform evidence and source review are ready
for review. The next implementation gates are a Rust activated guardian,
lease/journal/GO ordering, inherited descriptor hygiene and the service's inner
PTY plus client relay. Neither this design nor successful read-only observation
enables automatic switching.
