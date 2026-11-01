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
At that revision the service was Python and carried no real launch data.

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

The Python coordinator continues to trust the CI checkout and its local helper
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

A separate socketpair check reproduced a diagnostic race: closing with unread
trailing records can reset the peer and discard an already queued error reply.
BIND fault trials now require an invocation-specific refusal marker written at
the intended error path; reset alone never passes. A regression accepts only
the exact marker and refuses both a missing marker and an unrelated error.

The focused Opus kernel review completed with two low-severity and two
informational findings, with no high/medium finding in its stated scope. The
observer now restricts the authenticated service to `Type=exec`, no PID file,
`NotifyAccess=none` and `RemainAfterExit=no`, rechecks migration controls on each
live observation, and enforces the namespace precondition inside binding itself.
These follow-up checks passed both native manager jobs at `4cda3ed` in
[run 41262752539](https://github.com/shahzadlone/agent-swapper/actions/runs/41262752539). Directory device/inode facts
identify only the retained directory: a failed invocation's directory may be
reused by a later start. They never replace the manager invocation ID or prove
freshness. Kernel retirement alone likewise never proves manager retirement.
The reviewed model trusts the kernel/root and excludes hostile same-UID code;
it is not production or arbitrary-service qualification.

### Rust activated service checkpoint

The service and fixed writer now run from
[`activated_guardian.rs`](../tools/linux-manager-evaluation/src/activated_guardian.rs).
The Python coordinator exclusively creates a temporary root-owned executable
under `/run`, records its SHA-256 alongside exact unit contents, and verifies
ownership, mode and hash before startup and cleanup. A changed image refuses
cleanup commands. This is disposable CI setup, not a host installer.

The service checks its image, fixed identity, client peer, invocation and
root-managed cgroup. It accepts only BIND or GO for its own bounded fixture
writer. The shared Rust transport supplies strict EOF discrimination. A private
five-second barrier makes fault trials deterministic: all empty/trailing records
and half-close are queued before the guardian reads them.

Before spawning, the single-threaded service applies the same reviewed fuxix
CLOEXEC operation used by the core shim. The fixed writer replaces standard
streams with null devices, starts a separate session, and refuses any surviving
nonstandard descriptor before writing a heartbeat. This checks the fixture's
actual inherited descriptors; it does not qualify future arbitrary providers.

The initial Rust service passed both native manager jobs at `e10a564` in
[run 41262114805](https://github.com/shahzadlone/agent-swapper/actions/runs/41262114805).
After correcting the concurrent-fork timing assumption, its 24-test parallel
suite passed 30/30 stress runs. Its focused Opus service/image review is now
complete. The subsequent follow-up passes 25 Rust tests, eight core transport
tests and 11 Python guard tests locally, plus strict Clippy. Both Ubuntu
manager jobs passed the revised service at `4cda3ed` in
[run 41262752539](https://github.com/shahzadlone/agent-swapper/actions/runs/41262752539).

The review's `/run` noexec concern did not occur on either qualified native
runner. This disposable fixture keeps its existing runtime path but now refuses
a noexec mount explicitly before writing files or controlling units. It never
changes mount options. Effective socket/template configuration must match the
runtime fragments, have no drop-ins and need no reload; preexisting manager
units are refused. Group identity, root-peer refusal and retained-directory
membership are checked too. Cleanup verifies socket stop instead of ignoring
failures, and rolls back exclusively created inodes if file creation fails
before reload. Error diagnostics retain earlier failures.

Queued-record refusal is now a distinct error type. Transport, poll and
socket-option failures cannot produce the expected fault-control attribution.
Guardian diagnostics use one bounded socket record, and writer startup reports
early child failure. These address the review's substantive findings; both native manager jobs
exercised the complete revised configuration and lifecycle.

This initial service checkpoint did not include real profile lease transfer,
durable journal-before-GO ordering or an inner PTY. The later journal checkpoint
below covers the first two with a cooperating gated writer. No normal launch
path uses this service.

Root-owned launch installation on a user's machine comes later, after the
exact files, removal procedure, platform evidence and source review are ready
for review. The next implementation gates are qualifying the Rust activated
guardian, lease/journal/GO ordering, inherited descriptor hygiene and the service's inner
PTY plus client relay. Neither this design nor successful read-only observation
enables automatic switching.

### Next integration seam

The journal checkpoint exposes the observer's client side as an isolated
library used only by Linux core development tests, with a thin observer binary.
The service and writer remain binary roles. This keeps the real `Store`
lifecycle APIs private and avoids an extra subprocess/JSON authentication
boundary. Opus independently recommended this direction over public core
testing hooks or a sidecar observer.

Owned bound/prepared/running/closed states will make the GO sequence explicit:
acquire a disposable profile lease, bind the guardian, persist a fresh logical
run scope, transfer a duplicate lease, receive and verify the gated writer's
identity, persist its spawn observation, then release GO. Errors retain the
original scope witnesses for explicit bounded retirement; drop only closes
resources and never grants a journal completion. Observations have no conversion
to a Linux custody receipt. The library must stay absent from the core's normal
dependency graph and resolve the same pinned versions through the root lock.

New tests combine those real boundaries: journaling failure withholds GO,
the guardian's duplicate alone retains the lease, and the durable unresolved
run continues to block reuse after cleanup and reopening. They will use a
cooperating gated writer, not claim provider exec confirmation. Existing
operator-attestation behavior need not change to complete this checkpoint.

### Integrated Rust activation evidence

The complete `4cda3ed` checkpoint passed
[run 41262752539](https://github.com/shahzadlone/agent-swapper/actions/runs/41262752539):
Linux, macOS and Windows tests; both Ubuntu manager suites; namespace evidence;
dependency policies; candidate builds and independent reproducibility on all
three platforms. Branch provenance attestation was skipped by policy. The
checkpoint is integrated into main; main's provenance run is a separate gate.
No provider login, normal managed launch, public release or signing was enabled.
The subsequent real lease/journal work remains under qualification separately.

### Activated journal checkpoint under qualification

The client library now owns bound, prepared, running and closed states. Its
development-only synchronous boundary refuses nested runtimes, retains the
original manager/cgroup/process witnesses, and shuts down the control socket
on drop even if an in-flight fork still holds a duplicate. Drop never waits for
retirement or clears a journal record. Explicit retirement uses the original
manager invocation and retained kernel objects, including the writer pidfd.

The fixed service's ADMIT mode receives a duplicate real profile lease and
starts a cooperating writer that waits for a separate versioned GO record.
The client independently checks its PID, UID, cgroup and guardian parent before
the test journals the spawn. A fresh 16-byte nonce sent only after that durable
write appears in the first heartbeat. The writer has already executed the
fixture image while gated: this is not a provider pre-exec barrier or exec
confirmation. Lease release on guardian exit alone is not scope retirement.

Two explicitly opted-in hosted tests exercise the real Store: sibling
activations retire independently while the remaining guardian retains its
lock; an actual SQLite BUSY error withholds GO and leaves no heartbeat. Both
reopen the store after retirement and require the durable unresolved run to
block launch even though a raw lock can be acquired. No completion receipt,
operator attestation or production launch enablement is added.

Local protocol, wrong-parent/group, duplicate-socket and runtime-boundary
regressions pass. Both native manager jobs passed the initial activated journal
checkpoint at `9ca328e` in
[run 41263488760](https://github.com/shahzadlone/agent-swapper/actions/runs/41263488760).
Focused Opus review and the remaining platform/packaging checks are pending.
The library is a Linux-only core dev dependency; CI checks matching audited transport/runtime pins in both lockfiles
and excludes the evaluation library, zbus and Tokio from normal/build graphs.

### Next: abrupt loss, then terminal integration

The current journal fixture closes its client channel cooperatively. Before
connecting this backend to normal launches, add independent client-SIGKILL and
guardian-SIGKILL trials. The controller must retain its own authenticated
manager/cgroup/process witnesses before killing its owned fixture child. A
marker containing a PID or invocation is only input to independent binding,
never retirement evidence. Guardian fault injection must target the retained
pidfd, not a newly looked-up numeric PID. In both cases, verify a live writer
before the fault, its original scope's retirement afterwards, raw lease release
and the unresolved journal's continued refusal after reopening. Keep these
cases separate from cooperative EOF attribution.

The next terminal checkpoint needs a genuine pre-exec shim plus an inner PTY;
the current gated writer has already executed and has null output streams.
Keep the service's control channel separate from target stdin, stdout and
stderr, and preserve descriptor hygiene across the final exec. First measure
a fixed target's controlling terminal, nonce-bound execution barrier, resize,
interrupt, raw-mode input and disconnect. Then qualify shell suspend/resume,
redirection, foreground restoration, client/guardian loss and sessions beyond
startup timeouts. Do not infer these properties from the earlier delegated
fixture: a root-manager service starts with a different terminal relationship.

### Journal review follow-up under qualification

The focused Opus review of `9ca328e` found no ADMIT execution path preceding the
separate start grant, but identified gaps in the assertions and failure APIs.
The follow-up centralizes recheck → synchronous journal callback → recheck → GO
in `Prepared::start_after`; the callback runs outside an entered async runtime.
A failed write records whether the prepared writer was still live before the
channel closes. The only public start method uses this ordering. A later
transport error means GO might have been delivered; intent remains unresolved.

The test now observes a live, ready writer without a heartbeat across ten
writer intervals before GO, repeats that check after journaling, and requires
PID plus nonce in heartbeats. Lock transitions are checked in the still-open
store as well as after reopening, where the successful spawn PID must persist.
Invalid lease metadata and a separately held file lock must refuse before
writer creation, with exact fixture-only fault attribution.

Retirement observation errors retain the original witnesses for retry.
Connection-close errors after successful observation are separate diagnostic
results, not a lost observation. Connection destruction runs under the owned
runtime context before nonblocking shutdown. Prepared packets now carry an
explicit version tag and have independent malformed/sender regression cases.
The writer authenticates its gate's peer and null outputs; the guardian drops
its extra child-stdin descriptor and checks atomically published readiness.

Withdrawal before GO has distinct attribution only after strict EOF. A
credential-requesting peek with zero ancillary capacity distinguishes even an
empty queued record from closure, without decoding credentials. The flags may
include `MSG_CMSG_CLOEXEC` at EOF, so only data/control truncation participates
in that distinction. Modes and timeout restoration are explicit and tested,
including delayed delivery, expiry, queued-empty-plus-shutdown and discarded
rights. The blocking receiver refuses a nonblocking or credential-enabled
channel. Client sends remain bounded nonblocking attempts and can fail without
waiting for queue space.

The review's failed-unit lifecycle concern was already covered by
`CollectMode=inactive-or-failed`, the watcher's explicit failed-state handling
and both native jobs. Stderr already goes to the journal; stdout must remain
the protocol socket. Tests already run individually with one test thread, and
the runner now also requires exactly one passing test and publishes its own
annotation. The single twelve-second client startup budget remains intentional
and conservative relative to the guardian's fifteen-second window; it is not
reset around a slow journal callback. The legacy GO mode remains a separate
fixed-writer control; journal-order claims apply to ADMIT only.

This follow-up passes local protocol tests and strict Clippy. Its revised
native tests and focused withdrawal/ordering follow-up review remain pending.

### Abrupt-loss checkpoint under qualification

The next hosted trials kill the original guardian through its retained pidfd,
and kill an independently spawned client with SIGKILL. The latter controller
never receives a copy of the activation socket. It authenticates its own
read-only manager/cgroup/process witnesses before the fault, rejecting wrong
invocation, directory identity and child claims. Each trial verifies a live
writer before the fault, original-scope retirement and lease release afterwards,
and continued journal refusal after reopening. Guardian-loss must lack a clean
EOF marker; client-loss requires guardian EOF handling without any client
cleanup. Both native manager jobs passed all four journal tests at `45cd72b` in
[run 41264264431](https://github.com/shahzadlone/agent-swapper/actions/runs/41264264431).
The coordinator requires exactly one passed test for each requested case.
Focused review and the remaining platform/packaging checks are pending. No production custody receipt is added.

### Abrupt-loss review follow-up

The focused Opus review of `45cd72b` confirmed retained-pidfd signalling, owned
unreaped-child signalling and independent witnesses without a socket copy.
The follow-up checks lock release in the original open store, requires the EOF
marker to be absent immediately before client SIGKILL, matches specific
identity-refusal errors and adds the guardian-as-writer case to isolate the
PPid check. Reports now live beside the store, and failed fault injection
explicitly attempts retirement before reporting the original failure.

A runtime owner now uses nonblocking shutdown from construction onward;
post-admission claim validation runs only after the Session owns the connection
and witnesses. A local test drops it from inside another runtime while blocking
work is held. This covers failed independent binding as well as normal teardown.

The test harness starts a new session for each fixed cargo/test/client group.
A ninety-second outer timeout kills that owned group and preserves partial
output; manager-owned workers remain separately bounded and are stopped by
fixture teardown. A local grandchild/pidfd regression verifies the timeout's
process and diagnostic behavior. This is fixture orchestration, not a general
process-containment claim.

Exit attribution remains deliberately limited. The template already collects
failed instances, and retirement requires disappearance of the original scope
plus pidfd exit and authenticated manager retirement. A collected service does
not retain an authoritative `ExecMainStatus` for later observation. The test
therefore reports a SIGKILL request through the retained pidfd followed by
observed retirement; it does not claim a recovered manager exit status or prove
that no concurrent error could have preceded the signal. The EOF marker means
the guardian reached that protocol path, not that systemd recorded exit zero.
The fixed writer sets no parent-death signal. No `SuccessExitStatus=KILL` or
weaker retirement policy is introduced to make the tests pass.

Local verification passes 33 client tests, 22 binary tests, 12 Python guards and
strict Clippy. Native validation of these later changes remains pending.

### Scoped withdrawal review and wake-up checks

Opus's follow-up review of `2f87dc8` returned no must-fix finding for the supplied
withdrawal peek, callback ordering and retryable-retirement mechanisms. The
runtime entry check and admission deadline already run through `recheck`;
the follow-up also checks the deadline immediately before the journal callback
and obtains the runtime before taking the connection for final close.

New local tests cover delayed full closure, the actual Control destructor
waking the GO wait, GO queued immediately before full close, and timeout/socket
policy restoration on refusal paths. They pass with the existing framing,
empty-record and transferred-capability tests: 35 client tests and 23 binary
tests, plus strict Clippy. Retirement still never resolves the journal, and a
send-stage error remains possibly delivered because socket-option restoration
can fail after the packet was queued.

Both Ubuntu manager jobs passed the reviewed journal follow-up at `2f87dc8`
([run 41265192617](https://github.com/shahzadlone/agent-swapper/actions/runs/41265192617))
and the subsequent crash/harness follow-up at `60d67bb`
([run 41265660485](https://github.com/shahzadlone/agent-swapper/actions/runs/41265660485)).
Their remaining platform/packaging results, and the latest small wake-up
follow-up, are tracked separately before integration.

### Inner terminal and final-exec checkpoint

The full journal follow-up pipeline at `2f87dc8` passed in
[run 41265192617](https://github.com/shahzadlone/agent-swapper/actions/runs/41265192617),
including all platform suites, dependency policies, candidate packaging and
reproducible rebuilds. It was integrated into main as `d19371d`. The later
crash/wake-up checkpoint remains separately tracked.

The next isolated `PTY1` fixture adds an inner PTY. Terminal bytes travel on its
master descriptor; the credential-bearing control connection remains separate.
The prepared response requires exactly one close-on-exec, nonblocking PTY
master and the bound guardian's credentials. Wrong descriptors, excess rights,
missing rights and truncated controls are refused; received capabilities close
on every refusal. Validation opens the peer with `NOCTTY`, so it cannot acquire
a controlling terminal for the client.

The guardian starts a fixed shim behind the existing gate and transfers the
terminal slave only after the real Store callback commits the observed PID.
The shim creates its session, acquires the controlling terminal without stealing
one, sets the foreground group and execs the fixed target at that same PID.
Only standard streams survive exec; no lease, control socket or manager witness
is inherited. No arbitrary target, environment or provider data is accepted.

The new hosted case tests three endings: control disconnect, terminal Ctrl-C
and an actual SQLite write conflict. It keeps an independent master open
through retirement to exclude PTY hangup as an alternative cleanup cause.
Before GO and during the successful journal callback the target's final-exec
marker must be absent; afterwards the target reports the journaled PID and
nonce. Checks cover controlling session/foreground group, resize dimensions,
echo-off fake password input, UTF-8/escape bytes and raw-mode Ctrl-C bytes,
then normal Ctrl-C signal termination after restoring terminal modes. The
write-conflict case must retire without final exec. Every case retains an
unresolved journal record after lease release and Store reopening.

Local validation passes 37 library and 25 binary tests plus strict Clippy;
the existing 12 coordinator guard/timeout tests also pass. Hosted terminal
execution and the focused Opus source review are pending at this checkpoint.
These checks do not qualify a caller-terminal relay, SIGWINCH handling,
suspend/resume, shell foreground restoration, long sessions, arbitrary exec
failure reporting or provider login/refresh behavior. Normal Linux launches
remain uncontained.

### Terminal source-review follow-up

The complete base terminal pipeline at `720372b` passed in
[run 41266991013](https://github.com/shahzadlone/agent-swapper/actions/runs/41266991013).
Opus 5.5 xhigh then found a possible torn read of the exit marker and several
tests that did not fully establish their stated terminal behavior. The marker
now uses atomic rename. The received capability stays local until sender,
invocation, descriptor and kernel child checks pass; it is never inspected as
a terminal before message authentication or retained on a refused prepare.

Master-negative tests now reach the actual ioctl with valid descriptor flags.
Slave checks require a devpts character TTY that refuses the master-only
TIOCGPTN operation; all standard streams must identify the same slave inode.
This avoids relying on an assumed device-major range. A mode guard restores
the inner terminal on prompt-write failure, read timeout and oversized input;
these failure paths now have local tests.

The hosted test independently observes no controlling session, a shim argv,
no controlling device and no terminal output during the successful journal
callback. After GO it observes the new session and foreground group through
kernel/procfs data and binds a separate manager/process witness. Echo must be
present before hiding input and after both hidden and raw input. The raw
payload includes line-editing, signal, newline-translation and flow-control
bytes. One case queues typeahead before GO, observes its line-discipline echo
while the shim remains gated, and requires the command response only after
the target starts. No implicit flush is added that could lose input racing GO.

A fourth ending kills the original guardian through its retained pidfd while
the target is in raw mode. All endings require master EIO after retirement;
that is evidence of no remaining slave holder, not by itself evidence that
the target never executed. Scope and child retirement still leave the journal
unresolved. Normal target writes can block until the guardian's bounded
lifetime and manager cleanup; this fixed fixture is not a general relay.

The strengthened revision passes 37 library tests, 26 binary tests and strict
Clippy locally. Its revised hosted terminal case remains pending. Separately,
the prior crash/wake-up checkpoint `9fb76b0` passed the full platform/package
pipeline in [run 41266261801](https://github.com/shahzadlone/agent-swapper/actions/runs/41266261801)
and was integrated into main as `2e90693`.
