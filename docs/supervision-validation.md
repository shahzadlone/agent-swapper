# Native supervision validation

This record covers cooperating fixture processes, not real providers, credential
isolation or external work. Automatic switching remains disabled.

## Recorded checkpoints

| Commit | Evidence | Result |
| --- | --- | --- |
| `ef6e973` | [CI 40638824387](https://github.com/shahzadlone/agent-swapper/actions/runs/40638824387) | All four jobs passed; per-run backend probe before launch integration |
| `533c355` | [CI 40640405391](https://github.com/shahzadlone/agent-swapper/actions/runs/40640405391) | All four jobs passed; opt-in CLI, schema 6, scoped history and migration backup/rollback |
| `6d0e394` | [CI 40640736012](https://github.com/shahzadlone/agent-swapper/actions/runs/40640736012) | All four jobs passed; admission/wrapping/query/timeout fault injection and receipt ownership doctests |
| `a835b29` | [CI 40641607779](https://github.com/shahzadlone/agent-swapper/actions/runs/40641607779) | All four jobs passed; review fix and incomplete-supervision diagnostics |
| `cb44045` | [CI 40642895082](https://github.com/shahzadlone/agent-swapper/actions/runs/40642895082) | All four jobs passed; provider-free Linux stdin/PTY transport experiment |
| `ba9495d` | [CI 40643621025](https://github.com/shahzadlone/agent-swapper/actions/runs/40643621025) | All four jobs passed; descriptor transport combined with delegated cgroup admission, cleanup and missing-membership refusal |
| `fa20cda` | [CI 40645886037](https://github.com/shahzadlone/agent-swapper/actions/runs/40645886037) | All four jobs passed; bare dashboard entry, masked search and actual POSIX terminal restoration |
| `d88d7cb` | [CI 40647286964](https://github.com/shahzadlone/agent-swapper/actions/runs/40647286964) | All four jobs passed; Linux guardian survives parent-group SIGKILL and retains transferred lease through simulated cleanup |
| `10bee79` | [CI 40668801991](https://github.com/shahzadlone/agent-swapper/actions/runs/40668801991) | All four jobs passed; responsive profile details, stable selection/availability actions, alias-reuse refusal, and POSIX keyboard persistence with output draining |
| `b593bb6` | [CI 40670584230](https://github.com/shahzadlone/agent-swapper/actions/runs/40670584230) | All four jobs passed; six actual bash/PTY guardian cases, including parent-only loss and terminal-close input outcomes |
| `4b500ed` | [CI 40671213375](https://github.com/shahzadlone/agent-swapper/actions/runs/40671213375) | All four jobs passed; pinned-parent cgroup initialization, three real delegated rollback injections, and path-replacement/collision regression |

At `6d0e394`, platform annotations recorded Rust 1.98.0 and:

- Windows Server 2025, build 10.0.26100, AMD64.
- Ubuntu Linux 7.0.0-1017-azure, x86_64.
- macOS 26.6.2, Darwin 25.6.0, arm64.

Windows executed the actual Job backend and integrated native-launch fixtures.
Linux and macOS tested unsupported-backend refusal and portable registry behavior;
they did not execute Windows containment. CI also passed 25 preference-concurrency
iterations on every platform, ten Windows journal-lifecycle iterations, the older
Windows custody probe, the delegated Linux cgroup probe and doctests.

Local Linux validation passed 130 tests plus the intentional Unix fixture entry
skip, Clippy with warnings denied, formatting, doctests and dependency policy.
A full Windows-target Clippy check covered all targets without linking/running
Windows binaries; the SQLite build was bypassed for this metadata-only check.
Actual Windows builds used bundled SQLite in CI.

## Assertions exercised

Admission is suspended before assignment and a deliberately delayed callback.
Rejected or unwinding callbacks and a wrapper failure after successful admission
leave no executing target. An independent kernel Job observer checks cleanup on
those injected failure paths. Membership-query errors and expired cleanup return
no receipt and still retire the owned processes.

A root exits while its descendant remains alive. Targeted stop returns only after
an empty membership observation, preserves sibling Jobs and unrelated children,
and rejects breakaway creation with access-denied while a normal child succeeds.
Drop and hard supervisor termination release fixture lifetime locks. A naturally
empty Job can also finish. Receipts cannot be constructed or cloned by callers,
and stop consumes the running scope.

Integrated CLI tests preserve root exit code 42, kill background descendants,
record the matching local scope, and allow a subsequent completed run. A killed
supervisor leaves an unresolved journal intent and blocks reuse even after its
local processes have stopped. Manual recovery stays `attested_stopped`. The
journal rejects missing, mismatched, reused and relabelled scope receipts.
Schema-5 migrations preserve gents sessions and pending runs, back up the original
database, and roll back on altered projections or DDL.

## Review and limits

Claude Opus 5.5 at xhigh reviewed the initial design. A broader implementation
review timed out without a result; a subsequent focused source review completed
and found no concrete ownership or cleanup defect in the supplied paths. It
identified a validation-order inconsistency: the supervised branch bypassed the
shared session/binding check. That check was moved before the branch. Public plan
builders already refused the incompatible metadata, but the shared invariant is
now explicit. A review is supporting evidence, not runtime qualification.

The supervisor-crash window before first Job assignment can leak a suspended
process. Dependency failure cleanup may wait without a timeout. Membership-list
overflow was source-audited as an error path, not stress-tested with thousands of
processes. Same-user malicious interference, external services, filesystem and
credential isolation, actual provider versions and account refresh remain outside
this evidence. See [custody](custody.md) and the [support matrix](support-matrix.md).

The next Linux guardian design and its separately bounded fixture checks are
documented in [Linux supervision](linux-supervision.md). They do not promote the
production Linux custody state.
