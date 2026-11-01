# Shared Linux helper transport

The first runtime extraction moves the existing sequenced-packet transport and
bounded launch envelope into `agentswapper-linux-runtime`. Core helpers and the
isolated manager experiments now consume the same library. The crate has no
database, CLI, manager client, activation installer or process-custody receipt.
Linux production managed execution remains disabled.

This is an implementation boundary, not a new protocol. The transport retains
its descriptor truncation/refusal checks, record-versus-EOF distinction,
absolute transfer deadlines and private socket requirements. The envelope keeps
its byte/item bounds, OS-string handling, environment validation, zeroizing
buffers and cross-process argv-canary test. Its fields remain private and it has
no Debug or serialization implementation. Encoding and decoding are private;
consumers use validated capture and bounded transfer operations.

The initial transport slice uses only rustix and zeroize, already used by the core.
Dependencies are Linux-targeted; other platforms compile an empty library and
the core does not depend on it there. The dependency-boundary check rejects
database, CLI, encryption application, or manager dependencies in this first
helper slice. The isolated observer lock now also pins the same zeroize version
as the root lock. No existing registry dependency version changes.

The implementation and its 17 tests moved together. One ignored receiver role
is invoked by the passing cross-process test; it is not an untested gate. The
Linux-only temporary-path test uses standard canonicalization directly instead
of the platform portability wrapper. Core compatibility imports preserve older
helper consumers; qualification consumers import the library directly.

Local validation passed 16 runtime tests (plus the receiver role they invoke),
20 remaining core supervision tests, the cross-process admission probe,
60 isolated-manager tests, strict Clippy for the runtime/core and all isolated
targets, both locked dependency audits and the dependency-boundary check.
Hosted platform, terminal, packaging and rebuild qualification passed in
[run 41279851409](https://github.com/shahzadlone/agent-swapper/actions/runs/41279851409).
The [production integration sequence](linux-production-integration.md) describes
the remaining installation, fresh helper, exec/journal and retirement work.

## Fresh-process signal ownership

The next extraction moves the existing terminal helpers' signalfd event loop
into the runtime. All three terminal examples and the surviving parent now use
that shared implementation. Fixture terminal admission and marker files stay
outside the runtime. This adds the already pinned nix 0.31.3 signal feature as
a normal Linux dependency; it does not enable ptrace in the production graph.

The owner is explicitly neither Send nor Sync. Its signal mask therefore cannot
be restored on another thread by moving or sharing the owner; compile-fail tests
check both constraints. Descriptor access uses AsFd and keeps the signalfd field
private. Construction still requires a fresh single-threaded process with the
relevant signals at their default unblocked dispositions. Procfs enumeration
errors now propagate instead of being counted as threads. An actual concurrent
thread test verifies refusal without changing the calling thread's mask.

This does not change the running CLI's signal policy. The fresh helper still
owns signal setup, and each consumer restores its terminal and completes cleanup
before restoring the saved mask. Terminal and manager composition are validated
by their existing owned-PTY tests; the shared owner itself grants no process
custody or permission to reuse a profile.

Local checks for the signal extraction passed 17 runtime tests, two compile-fail
doctests, all nine outer-terminal cases and all nine surviving-owner cases,
strict runtime and qualification Clippy, both dependency audits and the boundary
check. The stopped-parent case required its companion shell executable to be
built before running; it then passed. Hosted managed-terminal and full packaging
qualification passed in [run 41280349161](https://github.com/shahzadlone/agent-swapper/actions/runs/41280349161).

## Terminal guard and cleanup order

The shared terminal guard borrows the fresh signal owner. Rust therefore refuses
ordinary code that restores the signal mask while the terminal guard is still
alive; a compile-fail doctest checks that ordering. Descriptor access uses AsFd,
and the saved attributes, foreground group and raw-mode tracking remain private.

The runtime admits matching terminal standard streams, reopens verified stdin
into a separate nonblocking open-file description, and rechecks identity and
the original caller's flags. It changes neither flags shared with the shell nor
the foreground group. Entering raw mode and restoring saved attributes both
require ownership of the current foreground group. Fixture-only directory,
environment and terminal-record checks remain in the qualification wrapper.

Before any foreground query, the runtime refuses PTY masters, including locked
masters. A private PTY test checks both master states and the accepted slave.
Foreground queries use nix's signed PID representation, so a zero result cannot
enter rustix's nonzero PID type or count as foreground ownership. The added term
feature uses the existing nix pin; no registry version changes.

These helpers still require the calling process or its direct parent to lead
the foreground group. Launching them beneath an arbitrary existing TUI does not
establish that topology or make shell job control work automatically. Fresh
process entry, journal ownership and the CLI/TUI return path remain explicit
production integration work. The shared guard supplies neither exec evidence
nor a process-scope retirement receipt.

Terminal extraction validation passed 18 runtime tests, three compile-fail
doctests, all 18 local owned-terminal/owner cases, strict runtime and isolated
Clippy, both locked dependency audits and the dependency-boundary check. The terminal guard and subsequent fresh-entry composition passed hosted
managed-terminal, cross-platform packaging and rebuild qualification in
[run 41281405713](https://github.com/shahzadlone/agent-swapper/actions/runs/41281405713).
An earlier terminal-only attempt refused installation on a runner with noexec
`/run`; alternate fixture placement is being qualified separately.


## Retained kernel observations

The next extraction moves the existing procfs, pidfd and cgroup checks into
`scope_observation`. Both the client and ordinary-user guardian consume the same
runtime implementation. The fixture wrapper retains its exact accepted name
policy, diagnostic serialization and fault injection. The shared code adds no
registry dependency, manager client, signal send, installer or migration write.
The default production dependency graph is unchanged.

The shared binder accepts only a bounded ASCII service leaf beneath the retained
system slice; callers must independently authenticate their installation, manager
and invocation. The fixture still applies its stricter namespace first. A valid
leaf does not authorize a launch. The binder retains the original cgroup directory,
guardian pidfd/proc directory and each target witness; it preserves same-mount,
identity, direct-child and protected migration-control checks. Scope disappearance
still requires a fresh ENOENT relative to the retained directory and the original
guardian pidfd to have exited. ENODEV remains unresolved and retryable.

Live/retirement structs are diagnostic facts, with no serialization implementation
in the runtime. They do not prove manager retirement and are never accepted by
Store as completion receipts. The caller must still observe the same authenticated
manager invocation independently. The borrowed original guardian pidfd supports
the existing fixture's fault injection without moving that operation into the
runtime or replacing it with a numeric-PID lookup.

The six kernel regressions and namespace-map test moved with the implementation;
a service-leaf traversal/control-character/length regression was added. No kernel
coverage was removed: duplicate copies formerly compiled in both evaluation
library and binary are now one runtime suite. Local runtime validation passed
26 tests plus three compile-fail doctests, with one receiver role invoked by its
cross-process test. Strict runtime and qualification Clippy pass. The extraction passed both native Linux runners and the complete cross-platform
pipeline in [run 41286269736](https://github.com/shahzadlone/agent-swapper/actions/runs/41286269736).
This is a shared observation building block, not production managed execution.

The reduced evaluation suite passes all 54 tests after moving the duplicated
kernel cases. Strict core Clippy also passes with the Store qualification feature,
and the dependency-boundary check confirms identical pinned graphs.

Cooked foreground admission and final raw entry now share this runtime too.
The [suspension review](linux-suspension-review.md) records the three corrected
job-control defects, actual negative control and completed native/pipeline evidence.

## Exclusive direct-child waiting

`child_waiter::ChildWaiter` now owns the existing raw wait loop used by the fixed
guardian and surviving terminal owner. It consumes the standard `Child`, keeps
its fields private and is neither Send nor Sync. Stops, continuations and raw
terminal outcomes use one waiter. Terminal status and ECHILD revoke ownership
before any caller converts the status through nix's finite signal enum. Drop
only kills an unreaped direct child and makes a bounded reaping attempt; it
never supplies evidence that an entire process scope has retired.

The qualification wrapper retains all process-group and ptrace policy. No trace
feature or dependency enters the normal runtime, and no general process-group
signal method is exposed by the shared waiter. Callers must still exclude any
competing waiter or SIGCHLD auto-reaper in their trusted process. Rust's ownership
of this handle cannot prevent unrelated code from making a separate wait syscall.

The real-time raw-status regression moved with the loop. The fixture retains
its finite-decoder failure regression, checking that resume/wait are refused
after the syscall has reaped. New tests observe ECHILD after an intentional
competing wait and observe the original child pidfd plus ECHILD after cleanup.
Two compile-fail doctests enforce the thread-ownership restrictions. Local
runtime validation passes 29 tests and five compile-fail doctests; the one
ignored receiver role is invoked by a passing cross-process test. All 52 remaining
evaluation tests and strict runtime/evaluation Clippy pass. Native composition
qualification remains pending.

The shared waiter also passes all nine outer-terminal and 13 surviving-owner
cases, eleven pre-exec signal cases, three cleanup-signal cases, and the queued
stop regression. Strict core Clippy with the Store qualification feature passes.


## Separate authenticated manager transport

`agentswapper-linux-manager` now contains the existing fixed system-bus path
checks, root listener authentication, root PID-1 manager credentials, unique-owner
reply checks and bounded read queries. The qualification client consumes it.
The production core/CLI and the small helper runtime still do not depend on it;
a dependency check enforces both boundaries. Other operating systems compile an
empty library. No root installer, activation request, target launch, Store or
retirement receipt is exposed by this crate.

Connection admission revalidates protected paths and the initial namespace,
checks that the socket identity did not change during connect, and authenticates
the same unique manager before returning. Its own eight-second bound fits inside
the consumer's existing whole-admission bound. Every property query still validates
the reply sender and post-receive decoding size. The bound manager handle and explicit colon-prefixed destination check reject
well-known destination aliases, including zbus's special bus-driver exception. GetUnit and GetUnitByInvocationID
are explicit read operations; no arbitrary manager-method entry point is public.
The caller retains responsibility for installation policy, service properties,
original kernel handles and manager rechecks throughout the run.

Path and transport diagnostics remain serializable measurement data. A successful
connection is not a custody receipt. The existing report schema is unchanged;
private fixture names, service template checks, launch messages and failure hooks
remain in the evaluation workspace. The sender/framing/type regression moved into
the new crate; a path-escaping case was added. Lockfile changes introduce only the
local workspace package and its path edges; no registry package version changes.
Native qualification of this extraction remains pending.

Local manager extraction checks pass: both manager tests, all 53 remaining
evaluation tests, strict manager/evaluation/core-feature Clippy, formatting,
dependency boundaries and both locked license/advisory audits. No new registry
package was introduced. Hosted authentication, scope/terminal composition and
candidate rebuild results are still required for this revision.

The first native transport run reached the stalled-authentication refusal but
its harness accepted only the enclosing observer's timeout wording. The harness
now accepts either specific eight-second timeout, while still requiring code
125, empty stdout, a real authentication byte, EOF from the observer and the
existing twelve-second process bound. This does not broaden successful manager
admission. Native rerun evidence remains pending.

## Protected installed image

`installed_image::ProtectedImage` retains an open executable below root-owned,
non-writable ancestry. Each path component is opened relative to its already
checked parent with no symlink following; the leaf must be a root-owned regular
file with exact mode 0755 on an executable mount. Nonblocking open prevents a
FIFO substitution from hanging before the file-type check. The handle is private,
read-only and CLOEXEC, with no Debug or serialization implementation. Its current
process check compares the retained image's device/inode with an open
`/proc/self/exe`; the caller must establish a trusted procfs/namespace separately.

The fixed guardian now consumes this check while preserving its exact installed
path and protected-unit checks. Root remains trusted. This is not a manifest,
version check, installer, general launch permission or immutability claim against
root; production installation remains a separate gate. No new dependency is added.

Local validation passes 29 runtime tests and three compile-fail doctests, plus
strict runtime and existing-consumer Clippy. Tests open the system's protected
coreutils image read-only, reject a different running image, malformed/staging
paths, special files and directories. They neither execute that image nor install
files. Hosted guardian qualification of this change remains pending.

The first Ubuntu-latest run exposed a test portability assumption: its coreutils
`true` path is a symlink. The test now resolves that test asset before checking
its protected target, and separately requires refusal of the original symlink.
Production image admission keeps its no-symlink policy. The corrected pipeline
is pending; the earlier test failure is not an image-admission bypass.

## Manager invocation retirement query

The existing authenticated `GetUnitByInvocationID` retirement query now lives
in `agentswapper-linux-manager` and is consumed by the same bounded watcher.
It accepts only a unique bus destination and validates bounded unit/invocation
inputs before decoding. An authenticated exact-invocation absence or matching
inactive/failed observation is the manager half of retirement. A property
collection race still requires a new authenticated lookup; access denial,
service absence, timeout and wrong-sender errors never become successful absence.

The outer consumer retains its original 20-second limit, manager-owner checks
before and after, and original cgroup/guardian handles. The shared query's boolean
is expressly not a scope receipt, target outcome or permission for Store to
finish a run. This extraction adds no dependencies and does not expose manager
mutations. Its two reply/error regressions moved with the code; a new input test
rejects malformed, zero, Unicode and oversized invocation values before indexing.
All five manager tests, strict manager/consumer Clippy and the dependency-boundary
check pass locally. Native composition evidence remains pending.

All 51 remaining evaluation tests and strict core Clippy with the Store
qualification feature also pass after moving the retirement-query tests.

## Bound manager handle

The authenticated transport now returns a `Manager` handle that keeps the raw
D-Bus connection paired with its original unique owner. Its fields are private
outside the library, and it exposes neither a raw connection nor arbitrary
method calls. Read helpers reject a different sender before issuing a query;
observing a replacement well-known-name owner does not silently retarget the
handle. Explicit close preserves the existing bounded consumer cleanup path.

The snapshot, journal recheck and retirement consumers now use this handle.
Construction still requires the same protected bus path, root peer, root PID 1
manager credentials and stable owner. This narrows the reusable API; it is not
installation authorization or a Store completion receipt. No dependencies or
wire behavior change. Native qualification of this API boundary remains pending.

The bound-handle change passes five manager tests, all 51 existing consumer tests,
strict manager/consumer/core Clippy and the dependency-boundary check locally.

The [manager/image source review](linux-manager-image-review.md) records the
subsequent destination, label-encoding, mount-policy, file-capability and test
corrections, including the independent deadline negative control. Combined revision `4fb4abf` passed the complete pipeline in
[41290326745](https://github.com/shahzadlone/agent-swapper/actions/runs/41290326745),
including all seven original mount controls on Ubuntu 22.04 and 24.04.

Individual extraction checkpoints passed complete pipelines: manager transport
`16277f9` in [41288395690](https://github.com/shahzadlone/agent-swapper/actions/runs/41288395690),
protected images before the new mount/capability checks at `1787a26` in
[41288859678](https://github.com/shahzadlone/agent-swapper/actions/runs/41288859678),
and the child waiter at `a719604` in
[41288872078](https://github.com/shahzadlone/agent-swapper/actions/runs/41288872078).
These close their earlier pending extraction results. The combined manager-handle and review-correction run above also passed.

## Client corroboration of the guardian image

The activation snapshot now opens its exact fixed installed guardian image and
corroborates it through the original kernel binding. `require_main_image` opens
the kernel's `exe` magic link relative to the retained proc directory, compares
device/inode with the protected image handle, and checks the original pidfd is
still live. It never reconstructs a numeric `/proc/PID/exe` path. UID and cgroup
observations precede this check; the existing manager rechecks still follow it.
The guardian's own image check remains an additional check.

The caller must supply a policy-approved image in a trusted namespace. This
comparison needs procfs read permission and a dumpable guardian; unavailable
access refuses admission. It does not authenticate argv, establish target exec,
prove immutable state after observation or replace the remaining installation
manifest/version checks. Transient measurement fixtures keep their existing
policy; the new check applies to fixed socket-activated guardian snapshots.

A real owned child test accepts its protected system image, rejects a different
image, then rejects the original retained process after its pidfd has exited.
Canonical test assets accommodate multicall coreutils; the different image is
Python, not another applet that might share the same inode. Local runtime tests
pass 33 cases plus five compile-fail doctests, with the receiver role exercised
by its cross-process test. Strict runtime and consumer Clippy pass. Native
activation and the complete pipeline passed at `7ca3650` in
[41290629942](https://github.com/shahzadlone/agent-swapper/actions/runs/41290629942).

All 49 evaluation tests, strict core Clippy with the Store qualification feature
and the dependency-boundary check also pass for the client image comparison.

## Retained installed configuration

`ProtectedConfig` and `ProtectedImage` now share the same descriptor-relative,
no-symlink path walk. The private shared opener requires root-owned protected
ancestry and a root-owned non-writable regular leaf. Each public constructor
then requires its own exact mode: 0644 data or 0755 executable. Image mount and
capability restrictions remain separate. Configuration data can live on nosuid
and noexec filesystems, including the fixed `/run/systemd/system` template path.
A trusted namespace and fixed installation location remain prerequisites;
root UID/mode metadata is not a general filesystem-author identity guarantee.

The fixed service-template consumer now opens and reads that retained config
handle instead of checking pathname metadata alone. It requires nonempty UTF-8
text without NUL bytes, bounded to 16 KiB. Manager properties and drop-in checks
still establish the separate service policy. This does not parse arbitrary unit
files, authenticate a production manifest or change the installed unit contents.

Positional reads ignore shared file offsets and read one extra byte to detect
oversized input. Tests cover an exact-limit file, a changed shared offset,
one-byte overflow, empty data, and a real protected system configuration file;
an executable is refused as configuration. Data is never executed or logged.
The native asset matrix now has eleven cases, adding configuration on nosuid/noexec
mounts, executable-mode refusal, oversized data and a nonblocking FIFO refusal
to the seven image controls. The FIFO has protected ancestry, so the actual leaf
open must refuse promptly rather than stopping at an earlier directory check.
Privileged cases remain confined to disposable hosted CI.

Local validation passes 35 runtime tests, five compile-fail doctests, 49 existing
consumer tests, strict runtime/consumer/core-feature Clippy, the two harness
refusal tests, 14 activation harness tests and the dependency-boundary check.
One ignored runtime receiver role is invoked by its passing process test.
Native template and asset qualification of this revision remain pending.

## Active invocation rechecks

The real journal/terminal client's live recheck now uses the shared manager
crate's `require_active_invocation`. It validates bounded identity inputs, looks
up the original invocation through the bound unique manager, and checks unit ID,
invocation before and after the read, MainPID and active state. It no longer
addresses a reusable unit-name object during a live recheck. Missing or collected
invocations refuse admission/resume; they do not silently bind a replacement.

The caller retains its absolute admission deadline or bounded active-observation
window, original kernel handles, and current-owner checks around the whole
observation. A successful manager recheck remains separate from installation
policy, kernel custody, exec confirmation and Store completion. There is no
new dependency or production launch permission.

Local checks pass ten manager tests and 49 consumer tests with strict Clippy.
The new refusal tests cover invalid identity bounds and every observed identity
component, including a consistent replacement invocation. The complete native
terminal/admission matrix must qualify the changed query path; that run is pending.

## Loaded service lifecycle policy

The shared manager crate now checks the loaded service lifecycle through the
already bound invocation path. The snapshot consumer requires Type=exec, an
empty PIDFile, NotifyAccess=none, RemainAfterExit=false and an empty PAMName.
The first four checks preserve the existing policy; the explicit PAM read closes
a gap between the fixed template's intended policy and the observer's checks.
UID, cgroup, delegation, kill mode, installed assets and original kernel handles
remain separately required by the surrounding snapshot.

PAM sessions can move child processes into another session scope, as documented
by [systemd.exec](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#PAMName=).
The property is present in the older qualified manager generation too; see
[systemd v249's property declaration](https://github.com/systemd/systemd/blob/v249/src/core/dbus-execute.c#L1079).
The test rejects indirect PID ownership, notification ownership, retained-active
state and PAM sessions, including a nonempty whitespace value. No PAM service
is installed or activated for these local controls.

Local validation passes eleven manager tests and 49 evaluation tests, strict
manager/consumer Clippy and the dependency-boundary check. Native qualification
of the new property read remains pending. The shared check grants no production
launch or Store completion authority.

## Opaque activated-service binding

`agentswapper-linux-manager::BoundService` now owns the original invocation path,
retained process/cgroup binding and protected configuration/image handles. It is
neither cloneable nor serializable. A private connection identity ties it to the
exact authenticated `Manager` instance; equal unique-name text on another
connection is insufficient. Identity copies and kernel observations remain
non-authoritative diagnostics.

The caller supplies fixed trusted installation paths and an ordinary UID through
`ServicePolicy`. The activation client opens and retains that policy **before
connecting**, and carries the same handles into binding. The independent witness
uses the same paired-path constructor. The normal library contains no fixture
prefix, environment bypass, fault command or root installation procedure.

Binding reads the original invocation object, validates unit/UID/PID/cgroup,
non-transient status, exact template path, absent drop-ins, direct lifecycle,
delegation and kill mode, and rejects `NeedDaemonReload`. That last check refuses
manager-reported stale configuration; it is not proof of byte-identical loaded
content or an atomic snapshot against root. Kernel binding and guardian-image
comparison precede a final active recheck. Subsequent rechecks retain the
invocation path, check the same connection and owner, and corroborate the original
process/image again. Existing caller deadlines and child checks remain in place.

The qualification client and witness consume this shared binding. The transient
measurement observer remains in the evaluation crate. Retirement still requires
original kernel removal plus the authenticated original invocation's retirement;
the watch checks the exact connection before starting. No Store receipt or
production managed launcher is introduced.

Local checks pass twelve manager tests, a non-cloneability compile-fail doctest,
49 evaluation tests and strict manager/consumer Clippy. A policy refusal matrix
covers fourteen mismatches. Native CI additionally checks that a second valid
manager connection with the same owner cannot substitute, and temporarily changes
only its owned template to mode 0664 to require the shared policy's precise
refusal before connecting. That control drops root before executing the observer,
restores mode 0644 in `finally`, and requires no worker or marker. Existing
qualification suites cover the new composition; native results remain pending.

Completed predecessor pipelines: retained-config/FIFO revision `6d2f727` in
[41291656552](https://github.com/shahzadlone/agent-swapper/actions/runs/41291656552),
review corrections `e8cc4e8` in
[41292133837](https://github.com/shahzadlone/agent-swapper/actions/runs/41292133837),
and active invocation rechecks `279cc96` in
[41292389909](https://github.com/shahzadlone/agent-swapper/actions/runs/41292389909).
These do not qualify the subsequent lifecycle, NOCTTY or bound-service revisions.

The first bound-service native run
[41293930402](https://github.com/shahzadlone/agent-swapper/actions/runs/41293930402)
passed connection substitution, the mutable-template refusal, ordinary
activation and initial journal cases on both Ubuntu versions. Both stopped at
a stale assertion in the forged-invocation witness control: direct invocation
lookup now refused absence before the former unit-name comparison. Binding now
uses the existing authenticated absence decoder and exposes a stable NotFound
error; the test requires both that kind and the precise absence message. It does
not accept arbitrary manager errors. The rest of the composition requires a rerun.

The source-only Opus 5.5 review of `86f6c72` found no authority bypass and
identified evidence, policy-retention and API-surface gaps. The first corrections
make both subprocess-role tests require one executed passing test; an actual
misspelled-role negative control fails, and restoring the name passes. The
mutable-template control now checks the socket's accepted-connection count and
idle state before and after refusal, verifies mode restoration, and rechecks the
loaded unit. Mocked timeout, unexpected success and unexpected connection cases
all fail while restoring mode 0644. Admission and connection substitution share
one ten-second deadline, including the bounded offer read. Local runtime and
evaluation tests, strict evaluation Clippy and 15 activation-harness tests pass.
Native qualification of these corrections remains pending.

The second review correction records configuration device/inode, link count,
size, modification/change timestamps, mode and ownership at open. Reads check
the retained stamp before and after reading; binding and later active rechecks
also reopen the protected path and require the original stamp. Identical-content
replacement, in-place edits and mode changes refuse. These are change detectors
under a trusted root, not proof of an atomic manager load or protection against
root. Independent witnesses cover only their own observation window.

The hosted private-mount harness now holds an ordinary observer after retaining
the file, then tests an unchanged file, identical-byte replacement, content
change and mode change. Local tests cover every stamp field and real owned-file
replacement/edit/chmod. Native results for the added controls remain pending.

`BoundService` no longer exposes its inner kernel binding. Child observations
require its original guardian parent; retirement observations pair both halves
using its private identity and exact manager connection. Returned observations
remain diagnostics, not Store completion authority. The guardian signal handle
requires an explicit `qualification` feature in both shared crates, enabled only
by the evaluation consumer. Dependency checks assert that ordinary application,
runtime and manager graphs leave that feature disabled. Positive and negative
doctests check type availability, non-cloneability, hidden inner binding and the
disabled signal method. Owner/transport replacement leaves retirement unresolved.

Local validation: 38 runtime tests plus five doctests, twelve manager tests plus
four doctests, 49 evaluation tests, strict runtime/manager/evaluation/core-feature
Clippy, the dependency boundary, and the Python fixture checks pass. This still
does not enable a production managed launcher, install local services or consume
real provider accounts.

## Ordinary guardian credentials and loaded-policy rechecks

The activation policy now binds the primary GID as well as the UID. The original
guardian's retained proc directory must report matching real/effective/saved/
filesystem IDs, supplementary groups contained in the caller's existing group
set, empty inheritable/permitted/effective/bounding/ambient capabilities, and
`NoNewPrivs: 1`. Original pidfd liveness brackets this read. The fixture template
explicitly clears the capability bounding and ambient sets and sets `Restart=no`.

Supplementary groups cannot simply be assumed empty: systemd initializes them
from the user's group database, and `SupplementaryGroups=` extends that list.
The policy therefore permits a subset of the ordinary caller's groups, including
its primary group, and refuses group expansion or root group membership. See
[systemd's group semantics](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#SupplementaryGroups=)
and the [kernel's process-status fields](https://docs.kernel.org/filesystems/proc.html).

Admission and every active recheck now read the complete loaded-policy snapshot,
including primary group, drop-ins, reload state, delegation and kill mode, plus
direct lifecycle and `Restart=no`. The claimed unit must be a nonempty instance
of the retained template's own stem. Existing connection/owner, invocation,
configuration-stamp, executable, cgroup and original-process checks remain
required. This does not add delegated-work custody or crash-recovery authority.

Local checks pass 39 runtime tests, thirteen manager tests, nine combined
doctests, 49 evaluation tests, strict runtime/manager/evaluation/core-feature
Clippy, dependency boundaries and 15 activation-harness checks. Native results
for this new credential policy remain pending. The requested follow-up Opus
review of predecessor `3ae40ee` could not run because the CLI reported its session
quota exhausted; it supplies no additional review evidence.

## One-use retirement value

`BoundService::observe_retirement` now returns a private, non-cloneable
`RetiredService` only after both original-kernel removal and authenticated
original-invocation retirement agree on the exact retained manager connection.
It uses the binding's existing paired observer. Success revokes further issuance
before returning; errors, deadline expiry and cancellation retain the binding
for retry. The mutable-borrow API avoids dropping the original witnesses when
a caller cancels an owned asynchronous transition.

An opaque `ServiceKey` identifies this particular binding in memory. Copies
select an expected binding but prove nothing by themselves. Even an independent
valid witness of the same invocation has another key, so it cannot replace a
lost original witness after a crash. The receipt still says nothing about a
Store run/profile, a target's exit status, or delegated work. It is not yet used
to authorize profile reuse.

The real BIND fixture now checks an expired deadline while live, successful
retirement against the original key, rejection against a fresh witness's key,
and rejection of a second issuance. Its binding and substitution work share the
existing admission deadline. Local manager tests, positive/negative doctests,
49 consumer tests and strict manager/consumer Clippy pass; native qualification
and a real Store consumer are the next gates.
