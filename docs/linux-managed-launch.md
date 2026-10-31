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
descriptor; its native result is pending. This experiment does not yet use the
Rust guardian or carry real launch data.

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
both native image results for the correction remain pending.
Local tests cover truncated, empty, late and uncredentialed packets, and prove
that an unexpected transferred descriptor is closed on refusal. The distinction
between connection-time peer credentials and message credentials is described
in the [Linux UNIX socket manual](https://man7.org/linux/man-pages/man7/unix.7.html).
This measures fixture identity only; it does not validate an installed guardian
binary, authorize a journal transition or qualify production execution.

Root-owned launch installation on a user's machine comes later, after the
exact files, removal procedure, platform evidence and source review are ready
for review. Opus implementation review is also outstanding while the current
subscription session limit applies. Neither this design nor successful
read-only observation enables automatic switching.
