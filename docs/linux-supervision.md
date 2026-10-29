# Linux supervision experiment

Linux native launches remain uncontained. These provider-free experiments are
gates toward an opt-in backend, not a cleanup guarantee for current launches.

## Proposed ownership

The interactive supervisor keeps the foreground process group. A guardian runs
in a separate process group, outside the target cgroup, with no terminal I/O.
It owns a duplicate of the profile lease and a private control channel. Closing
the parent channel triggers cleanup; the guardian retains the lease until that
cleanup finishes. The target joins the supervisor's foreground group only after
private admission and a durable spawn observation.

A terminal's group-directed signal must not kill both supervisors. Separating
the guardian group addresses that particular failure, without preventing a
same-user process from killing both or a service manager from killing their
entire containing scope. Simultaneous supervisor loss remains unknown custody.

The existing durable unfinished run already blocks another launch after a
supervisor loses its lease. The guardian-held lease additionally blocks manual
attestation while cleanup is still active; it is not a replacement for the
journal. A cleanup observation and a root exit status are separate evidence.

The delegated cgroup parent must contain the supervisor and permit child-group
creation and admission. No privileged setup or process-group fallback will run
automatically. Trusted helpers must start with a neutral environment: target
environment and input are restored only after admission. Preserve inherited
ignored signal dispositions; do not blindly reset them. See Linux
[cgroup delegation](https://docs.kernel.org/admin-guide/cgroup-v2.html),
[exec signal semantics](https://man7.org/linux/man-pages/man2/execve.2.html) and
[shared file-lock ownership](https://man7.org/linux/man-pages/man2/flock.2.html).

## Executable evidence

`linux_admission_transport_probe` checks descriptor transfer, original stdin
semantics, close-on-exec and malformed admission. Its independent-stream case
transfers stdin, stdout and stderr separately, verifies shared offsets and
distinct output contents, and rejects a partial handoff before target execution.
The descriptor and control-packet transport now lives in the core's private
`src/supervision/linux_admission_transport.rs` module, shared with the journal
and terminal fixtures. Control messages reject empty expectations, malformed
packets and unexpected descriptors; a local test checks that rejecting a
transferred lock closes the received descriptor. This does not connect the
transport to production launches or establish a cleanup receipt.
An internal, bounded launch envelope separately encodes the original Unix
argument and environment bytes without requiring UTF-8. It rejects NULs,
ambiguous environment keys, excess lengths, truncation and trailing data, and
reconstructs a command with an explicit environment; a local subprocess test
checks byte preservation and directory selection. Envelope buffers are
zeroized on drop, but process-environment snapshots, `Command` and operating
system copies are outside that guarantee. The envelope is not yet transferred
by production launch. A provider-free subprocess test transfers it over an
unnamed stream whose descriptor travels on the guardian channel, and confirms
the helper's initial command line and environment do not contain the test
canaries. The receiver checks stream type, length and EOF; malformed and
truncated transfers fail, and the stream operations use one absolute deadline.
The delegated journal fixture now also transfers the envelope to a guardian
started with a minimal environment; its target receives a generated canary
only after GO. The guardian's initial command line and environment are checked
for that canary. This combined case passed the delegated Linux step in
[CI run 40829325192](https://github.com/shahzadlone/agent-swapper/actions/runs/40829325192/job/123299633910)
at `de1cc1c`. The actual
production guardian/shim lifecycle and authentication boundary remain to be
integrated and tested. The fixture now starts a trusted shim, moves it into the
scope, and records its PID before acknowledging admission. The shim validates
the parent/leaf identity and its own membership before accepting the envelope
and again after GO, then execs the target with the transferred streams. Its
receives share one deadline. A local subprocess test supplies ordinary
directories and confirms that a fully queued command cannot run. The shimmed
journal and supervisor-loss cases passed the delegated Linux step in
[CI run 40829689354](https://github.com/shahzadlone/agent-swapper/actions/runs/40829689354/job/123300777995)
at `ed1e2aa`, using the test-harness shim. Both
CLI executables now include an internal shim entry, which refuses launch without
the private admission protocol and a validated scope. Ordinary launches do not
call it, and it does not issue a stop receipt. The delegated journal fixture
is configured to use the actual `aswp` binary on CI; this new path requires a
successful hosted run before it is evidence. The actual `aswp` shim passed
both delegated journal cases in
[CI run 40830277723](https://github.com/shahzadlone/agent-swapper/actions/runs/40830277723/job/123302647991)
at `a6e07aa`.
The delegated terminal fixture also routes the target through this shared
shim and transfers all three original streams. Its non-delegated path remains
the earlier terminal-only control case. The revised delegated terminal cases
require their own hosted CI run; prior terminal results used the older shim.
The revised terminal cases passed the delegated Linux step in
[CI run 40829968967](https://github.com/shahzadlone/agent-swapper/actions/runs/40829968967/job/123301672399)
at `b98df73`; they use the shared shim source in the fixture executable, not
the `aswp` entry point.

An internal CLI guardian role now receives a scope, actual lease, launch
envelope and three streams through its private channel. It starts the CLI shim
in the supervisor's process group, admits it to the cgroup, reports its PID,
and waits for GO before supplying the target launch. It requests scope cleanup
when the channel closes or the target exits, retaining the lease through that
attempt. On normal exit it reports an empty scope, waits for the supervisor's
retirement authorization, then reports retirement. The supervisor fixture
independently checks emptiness and lease exclusion before authorizing removal;
loss of the channel at that point triggers guardian cleanup. These messages
are not a journal stop receipt. Dedicated normal-exit and channel-loss tests use the actual CLI guardian and the real
journal; they require a successful delegated CI run at this change before they
provide evidence. Ordinary launches still do not invoke this guardian.
The earlier single-step guardian protocol passed its normal-exit and
channel-loss delegated tests in
[CI run 40831703990](https://github.com/shahzadlone/agent-swapper/actions/runs/40831703990/job/123307176584)
at `50992ba`: the driver requires both test result markers and a successful
exit. That run predates the two-step retirement handshake, which remains to be
validated separately.
`linux_custody_probe` combines
that transport with actual delegated cgroup admission and cleanup. Their CI
results are recorded in [supervision validation](supervision-validation.md).

Cgroup creation now opens the unique child relative to the validated parent
descriptor with beneath/no-symlink/no-cross-mount resolution. It acquires its
parent copy before creating anything, then acquires a child descriptor before
attempting rollback. If that descriptor cannot be acquired, the error reports
that the child may remain; it does not delete by name. Validation failure after
acquisition attempts rollback only when the name still identifies that child.
A local regression renames/replaces the parent's path and verifies that
cleanup affects the original directory, while a same-name replacement survives.
Further provider-free tests replace the child after its descriptor is acquired:
the removal function used by retirement and the rollback guard refuse the
replacement. These tests use ordinary temporary directories; the actual cgroup
retirement path passed the existing delegated custody and terminal cases at
`b9ee5e6`, but no adversarial replacement case ran on cgroupfs. The identity
check and name-based removal are separate operations, so this does not prove
safety against a same-user actor racing between them. A failed check can leave
an empty original child behind; cleanup remains unresolved.
The delegated probe also injects validation failure three times and checks for
leftover children; those kernel-specific results require CI at the change's commit.
That delegated rollback checkpoint passed all four CI jobs at `4b500ed`.
These primitives and their rollback regressions now live in the core's private
`src/supervision/linux_cgroup.rs` module, shared with the existing probes.
Domain/group fields stay private;
consumers borrow the validated descriptors and retire the owned child through
the shared implementation. This is preparation for testing terminal admission
against the same cgroup code, not a production backend.
Received capabilities now explicitly require directory descriptors before
filesystem and ownership validation. A provider-free regression rejects both
ordinary files and, when available, a real cgroup control-file descriptor.

An open cgroup directory's link count cannot yet be used as portable proof
that the original scope was removed. For example, Linux
[`v6.8`](https://github.com/torvalds/linux/blob/v6.8/fs/kernfs/inode.c) and
[`v7.0`](https://github.com/torvalds/linux/blob/v7.0/fs/kernfs/inode.c)
recompute a kernfs directory's link count in their inode refresh path. This
source review rules out assuming that a removed directory always reports zero;
it does not establish the behavior of every supported distribution kernel.
The race between checking a named child and removing it remains a stop-receipt
gate, even when the supervisor observed the scope empty beforehand.
The fixture now also probes `cgroup.events` relative to the original open leaf
descriptor before and after retirement, and compares it with a newly created
same-name cgroup. These observations passed the delegated Linux job at `e527350`
in [CI run 40832463049](https://github.com/shahzadlone/agent-swapper/actions/runs/40832463049/job/123309571171).
They remain observations under evaluation, not a receipt. A further fixture
now attempts retirement using the original descriptor after replacement and
requires the replacement to survive; that added check awaits hosted CI.
In Linux [`v7.0` cgroup destruction](https://github.com/torvalds/linux/blob/v7.0/kernel/cgroup/cgroup.c),
the kernel checks population, disables migration and removes the cgroup's
visible files during destruction; those implementation details need qualification
on supported kernels and against the complete failure model before relying on
the missing file as proof.

The actual CLI guardian's two-step empty-observation and retirement handshake
passed the delegated Linux job at `b827509` in
[CI run 40831925937](https://github.com/shahzadlone/agent-swapper/actions/runs/40831925937/job/123307869893).
That run predates the missing-events and same-name replacement observations;
it does not qualify them or the production launcher. An additional delegated
case now interrupts startup after transferring the scope and lease but before
launch data, and requires cleanup while the journal remains unresolved. Its
kernel-dependent result must be established by hosted CI.

`linux_guardian_probe` uses only temporary files and cooperating fixtures. The
parent transfers its locked open file description over the anonymous socket;
the guardian has a different process group and no terminal standard streams.
The controller separately verifies that:

- Closing the parent's lease and channel while it stays alive produces EOF
  at the guardian and does not release the lock.
- Killing the owned parent's process group with SIGKILL leaves the guardian
  alive, observing EOF, and holding the lock.
- A separate open cannot acquire the lease until the guardian is explicitly
  allowed to finish simulated cleanup. It can acquire it afterwards.

The controller is a subreaper for these fixtures. Waits and reads are bounded;
cleanup never signals a PID read from a fixture file. This experiment does not
kill target processes, use a cgroup, test shell job control or issue a production
scope receipt. No providers, user credentials or host services are involved.

The guardian probe passed 25 local iterations (50 scenarios), then the Linux CI
probe at `d88d7cb`; all four CI jobs passed. This validates the separate-group
and lease behavior, not the remaining terminal and cgroup integrations.

`linux_terminal_guardian_probe` and `check_linux_terminal_guardian.py` exercise
the topology under an isolated interactive bash with its own controlling PTY.
The Rust parent starts the guardian in a different process group; the guardian
starts the target in the parent's foreground group. A transferred read/write
PTY supplies the target's three independently transferred standard streams,
while the guardian's own standard
streams remain detached from the terminal. The tests check:

- Ctrl-Z returns control to bash; `fg` restores the target group and terminal
  settings. A subsequent SIGWINCH records the new 99-column, 31-row geometry,
  and canonical input still reaches the target unchanged.
- Ctrl-C leaves bash with status 130. The guardian records target termination;
  parent EOF may trigger a targeted SIGKILL before target SIGINT is observed.
- Explicit inherited SIG_IGN for HUP and INT survives both exec boundaries.
  Ctrl-C leaves that target running and ordinary input still completes it.
- Bash's group-directed `kill -KILL %1` kills the stopped foreground job while
  the guardian survives long enough to observe and report target SIGKILL.
- Killing only the parent fixture produces EOF at the guardian, which stops
  its still-running target and records SIGKILL. Bash sees parent status 137.
- Closing the PTY terminates the target through HUP, guardian cleanup, or an
  explicitly recorded input EOF/EIO. Ordinary completion separately requires
  proof that the target received the exact typed `exit` line.
- A real bash `2>` redirection preserves stderr's non-terminal identity and
  writes the target's exact diagnostic only to its separate file.

The original six scenarios passed 50 local iterations (300 scenarios).
Independent three-stream forwarding then passed 25 more iterations of the six
cases (150 scenarios). Fixture waits,
socket reads and target lifetime are bounded. The controller signals only its
unreaped shell child during failure cleanup; it never signals metadata PIDs.
The expanded seven-case suite, including stderr redirection from an 80 x 24
terminal, passed 25 iterations (175 scenarios).
The default mode does not use a cgroup or journal, contain descendants, forward target
exit codes through a production protocol, or test shell pipelines.
Signal handling and terminal topology still need combined testing
with admission, leases, detached writers and the real supervisor state machine.

The combined case is in the delegated cgroup probe's private
`linux_probe/guardian_cgroup.rs` module. A surrogate foreground supervisor
transfers parent-directory, child-directory and locked-lease descriptors to a
guardian in another process group. Before using `cgroup.kill`, the guardian
verifies that the supplied parent contains itself and that a direct child with
the generated scope name has the same device/inode as the supplied leaf. The
delegated parent itself and traversal names are refused as kill capabilities.

The guardian admits a trusted shim, restores its input, and observes its root
exit while a detached writer continues. The controller then kills the owned
supervisor's process group. Parent-channel EOF must make the guardian kill the
writer and observe zero kernel population. The controller checks that empty
state before invoking any cleanup backstop, verifies that the lease is still
busy and an outside writer is still advancing, then retires the scope. Only
after that independent retirement may the guardian release the lease. The
controller verifies writer SIGKILL, guardian success and renewed lock acquisition.

The combined case executes in the explicitly delegated Linux CI service; local
checks compile it without creating a delegation. It does not combine interactive PTY behavior
with cgroup admission, integrate the journal, or qualify
real providers. Its controller is an observation and failure-cleanup backstop;
production will require its own measured reconciliation paths.

The terminal fixture now has an explicit `--cgroup-root` mode. Its guardian
creates a scope through the same shared primitive, starts a trusted shim in the
foreground process group, verifies kernel admission, and only then transfers
the target's original standard streams and permits exec. The shim independently
checks membership before starting the target. The controller checks the
admission PID against the actual target and confirms that both supervisors stay
outside that scope. Completion requires scope retirement before the helper
reports its result; the observer checks that the directory is gone.

CI runs the seven shell cases in this mode inside the existing explicitly
delegated service, after the detached-writer/lease cases. No local privileged
setup is introduced. Ordinary-directory refusal and the uncontained shell suite
pass locally; the seven combined cases passed all four CI jobs at `06bee8e`.
The temporary admission marker models ordering only, with no production
journal callback or scope receipt. Profile leases are measured in the separate
combined loss-direction cases, rather than in this terminal fixture.

Two additional delegated-only cases now start a heartbeat writer from the target
and detach it with `setsid`. The observer verifies that it is still advancing
inside the target cgroup before allowing either normal root exit or parent-only
SIGKILL. The guardian is a subreaper; after its owned root Child is reaped and the
scope is retired, it waits for that adopted writer and requires SIGKILL. The
observer requires that evidence and refuses a voluntary writer exit. These two
combined terminal/descendant cases passed at `d1d2afb` in [CI 40691671337](https://github.com/shahzadlone/agent-swapper/actions/runs/40691671337);
they are never selected by the uncontained controller mode.

The terminal fixture also transfers a locked temporary lease descriptor to the
guardian after handing over the three standard streams. The parent drops its
copy before the target starts. An independent opener verifies exclusion while
the target runs, including after parent-only SIGKILL, and again after the
guardian reports cleanup. Only after the observer checks scope retirement and
detached-writer termination does it release the guardian to close the lease;
the observer then confirms it can acquire the lock. This is fixture evidence,
not integration with the production profile lease or journal. The delegated
cases require CI at the change's exact commit.

A separate Linux test now passes a duplicate of the actual `ProfileLease` to a
guardian fixture after recording a real run intent. It kills the owned supervisor,
checks that the guardian's descriptor keeps manual recovery blocked, and then
checks that the unfinished intent continues to block reuse after the descriptor
is released. This validates the lease/journal boundary only: that fixture does
not start an agent, manage a cgroup, or issue a cleanup receipt, and production
launches do not yet transfer their lease to a guardian.

An additional delegated CI fixture combines those pieces: it records an actual
run intent, transfers the actual profile lease, admits a gated fixture target
to a dedicated cgroup, records its PID before acknowledging the launch, kills
the supervisor, and independently checks the empty scope and held lease before
retirement and release. The target changes session after admission; a separate
outside-scope heartbeat must continue through cleanup. The pending journal
intent remains unresolved until manual attestation. This is still fixture-only;
no production stop receipt is implied. The delegated step passed at `b81ab2b`
in [CI run 40825373742](https://github.com/shahzadlone/agent-swapper/actions/runs/40825373742/job/123287079787),
including the journal/lease and outside-heartbeat assertions. That run's macOS
job failed in a separate temporary-path test, so this is evidence for the Linux
step rather than a passing whole-workflow result.

The same delegated fixture now also kills the supervisor after the target PID
is durably recorded but before GO. The guardian observes the closed channel,
kills and retires the scope, and releases its duplicate lease. The observer
checks that the target never crossed its gate, the PID remains in the journal,
and the unresolved intent blocks reuse even after the lease can be reacquired.
This case and the original journal guardian case passed the Linux job in
[CI run 40826152704](https://github.com/shahzadlone/agent-swapper/actions/runs/40826152704/job/123289538202)
at `ce4379d`. It does not qualify production admission or simultaneous loss.

A further delegated-only case injects guardian SIGKILL through the parent's
owned child handle. Before the target starts, the guardian transfers the parent
and leaf directory descriptors to the foreground supervisor, which validates
their filesystem, ownership, membership, direct-child name and inode identity.
The surviving parent retains the lease, kills the leaf and waits for kernel
population zero. An independent observer checks empty state and lock exclusion
before permitting retirement, then verifies removal and only permits lease
release afterwards. The guardian's death leaves no owned target status in the
parent; the fixture records guardian loss rather than inventing a target exit
status or a production custody receipt. A bounded drop cleanup is a fixture
backstop, not a guarantee after simultaneous supervisor loss. All four CI jobs
passed at `afa45a2`, including the ten-case delegated terminal suite in
[CI 40813187840](https://github.com/shahzadlone/agent-swapper/actions/runs/40813187840).

The parent-loss case passed the delegated Linux CI job at `3f541db`, including
the explicit kernel-empty, lock-exclusion and outside-writer observations.
The reverse case requests failure injection through the surviving parent's
owned Child handle. After observing helper SIGKILL, that parent uses the same
validated leaf capability to stop the writer, retains its own lease through
independent scope retirement, and only then exits. The observer again checks
emptiness before any controller cleanup. Both loss directions passed the
delegated Linux CI job at `97ca8af`; that successful fixture result does not classify a production
guardian failure as a normal run completion. Simultaneous supervisor loss and
journal reconciliation remain open gates.

Two additional provider-free cases put the target in actual terminal raw mode.
On normal exit, the fixture supervisor restores the exact saved attributes while
it still owns the foreground; the observer checks them after the shell resumes.
On parent SIGKILL, the observer records whether the shell restored attributes,
without treating that observation as a crash-recovery guarantee. The native
launcher now separately snapshots and restores a foreground terminal after its
direct child exits; that implementation does not integrate the cgroup guardian
or guarantee recovery after supervisor failure. See the native terminal fixture
in CI for its platform-specific evidence.

## Remaining gates

Integrate the combined terminal/cgroup fixture with the actual journal, after
the remaining transport, signal and lifetime gates pass.
The terminal guardian fixture no longer imposes a total deadline on a live or
suspended session. Its admission transport retains bounded receive operations,
and its cleanup phases retain explicit deadlines. A long-session PTY case
without cgroup delegation exercises an active session and suspension beyond
the old 30-second limit;
this fixture behavior does not establish production deadline handling. A
complete startup-phase deadline and failure reconciliation are still needed;
per-operation transport bounds alone do not establish that guarantee. The
terminal fixture now requires a bounded READY/GO exchange before it hands the
original streams to the admitted shim. A delayed-guardian case verifies that a
parent timeout prevents target execution and that the guardian holds the lease
through cleanup. That handshake has no journal commit and is not a production
receipt: failure or simultaneous supervisor loss still needs reconciliation.
The guardian also bounds its wait for the parent's GO after READY. A local PTY
fixture holds the parent alive without sending GO and checks that the target
never executes and the lease becomes available after guardian cleanup. This
tests that phase without a delegated cgroup; it does not prove a total startup
deadline or production cleanup behavior.
Spawn trusted helpers before changing inherited interrupt dispositions in the
frontend. The fixture's inherited-signal results do not qualify the current
native-launch interrupt wrapper.
Extend failure injection for group removal and cleanup before promoting the
fixture code. Integrate admission and receipts with the journal only once those
gates pass; every ambiguous result must remain unresolved. macOS needs its own
measured backend rather than inheriting Linux claims.

Claude Opus 5.5 at xhigh reviewed the proposed architecture. Its process-group,
signal-disposition and lease-retention observations informed these experiments.
The review did not qualify the implementation or real-provider behavior.
A later terminal-fixture source review timed out without returning feedback;
it provides no implementation approval.
