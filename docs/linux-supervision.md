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
`linux_custody_probe` combines
that transport with actual delegated cgroup admission and cleanup. Their CI
results are recorded in [supervision validation](supervision-validation.md).

Cgroup creation now opens the unique child relative to the validated parent
descriptor with beneath/no-symlink/no-cross-mount resolution. It acquires its
parent copy before creating anything, then rolls back the empty child if opening
or validation fails. The rollback guard never acquires a name that already
exists. A local regression renames/replaces the parent's path and verifies that
cleanup affects the original directory, while a same-name replacement survives.
The delegated probe also injects validation failure three times and checks for
leftover children; those kernel-specific results require CI at the change's commit.
That delegated rollback checkpoint passed all four CI jobs at `4b500ed`.
These primitives and their rollback regressions now live in the private
`examples/support/linux_cgroup.rs` module. Domain/group fields stay private;
consumers borrow the validated descriptors and retire the owned child through
the shared implementation. This is preparation for testing terminal admission
against the same cgroup code, not a production backend.
Received capabilities now explicitly require directory descriptors before
filesystem and ownership validation. A provider-free regression rejects both
ordinary files and, when available, a real cgroup control-file descriptor.

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
without treating that observation as a crash-recovery guarantee. The fixture
restoration is not yet integrated with native launches. Both cases need the
delegated CI run at their own commit.

## Remaining gates

Integrate the combined terminal/cgroup fixture with the actual journal, after
the remaining transport, signal and lifetime gates pass.
Replace fixture lifetime limits with phase-specific startup/cleanup deadlines
before production use; normal live sessions and suspension must not expire.
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
